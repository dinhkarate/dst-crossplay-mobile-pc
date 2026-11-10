#!/usr/bin/env python3
"""Put the crossplay server on Klei's online server lists.

Each platform reads its own list (https://lobby-v2-cdn.klei.com/<region>-<Platform>.json.gz)
and the lobby files a row by its `platform` field, so a PC server token can list the PC port
on the Steam list and the phone bridge port on the Mobile list. A token holds one row
(a second write answers E_ROWID_EXIST), so each row needs its own token.

    lobby_announce.py --name "my server" --row 1:762172:11001:pc_token.txt --row 64:64020301:11002:mobile_token.txt

Protocol read from the dedicated server binary: POST /lobby/write, then /lobby/keepAlive
every 300 s, /lobby/delete at the end. The lobby takes the row's address from the source IP
of the request, so run this on the host that owns the public UDP ports.

A row's `guid` is the RakNet GUID the port answers a ping with (checked against live rows),
so each port is pinged every PROBE_S seconds: the row is written while the port answers,
rewritten when the GUID changes (server restart) and removed when it stops answering."""
import argparse, json, os, re, signal, socket, struct, sys, time, urllib.error, urllib.request

KEEPALIVE_S = 300
PROBE_S = 60
MISSES_BEFORE_DELETE = 3
RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")


def post(region, path, body, token):
    req = urllib.request.Request(f"https://lobby-v2-{region}.klei.com{path}",
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            status, text = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode()
    except OSError as e:
        status, text = 0, str(e)
    print(f"[lobby] {path} -> {status} {text.replace(token, '<token>')[:400]}", flush=True)
    try:
        return status, json.loads(text)
    except ValueError:
        return status, {}


def raknet_probe(host, port):
    """(GUID, session) from the port's answer to an unconnected ping.

    The session is the 16-hex RakString the pong carries (b"\\x00\\x10" marker, the
    same layout the bridge writes with build_payload). The listing row must carry the
    SAME session as the pong, or a client that joins from the online list bounces in
    its WAIT_TOKEN loop forever."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(b"\x01" + struct.pack(">Q", int(time.time() * 1000)) + RAKNET_MAGIC + os.urandom(8), (host, port))
        pong = s.recv(4096)
    except OSError:
        return None, None
    finally:
        s.close()
    if len(pong) < 17 or pong[0] != 0x1c:
        return None, None
    guid = str(struct.unpack(">Q", pong[9:17])[0])
    i = pong.rfind(b"\x00\x10")
    while i >= 0 and not all(chr(c) in "0123456789ABCDEF" for c in pong[i + 2:i + 18]):
        i = pong.rfind(b"\x00\x10", 0, i)
    session = pong[i + 2:i + 18].decode("ascii") if i >= 0 else None
    return guid, session


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="ap-southeast-1")
    ap.add_argument("--name", required=True)
    ap.add_argument("--row", action="append", required=True, metavar="PLATFORM:VERSION:PORT:TOKENFILE[:p]",
                    help="one list entry: 1 = Steam, 64 = Mobile; PORT is the public UDP port; "
                         "a trailing :p marks only this row as password protected")
    ap.add_argument("--probe-host", default="127.0.0.1", help="where the listed ports are pinged")
    ap.add_argument("--eos-host", default="", metavar="PUID",
                    help="list this EOS ProductUserId as the host of the Mobile row, so the phone "
                         "joins it over EOS P2P instead of dialing the address directly")
    ap.add_argument("--password", action="store_true", help="mark every row as password protected")
    ap.add_argument("--description", default="",
                    help="server description shown in the client details panel; \\n becomes a newline")
    ap.add_argument("--max-players", type=int, default=6)
    ap.add_argument("--season", default="autumn")
    ap.add_argument("--mode", default="survival", help="game mode shown in the row (survival, endless, wilderness)")
    ap.add_argument("--tags", default="", help="extra comma-separated tags shown in the row, after english and the mode")
    ap.add_argument("--secondary", action="append", default=[], metavar="SHARD_ID:PORT:PUIDFILE",
                    help="list a shard in the Mobile row's `secondaries`, reached over EOS at the relay whose "
                         "ProductUserId is in PUIDFILE. A phone changing shard on an online cluster looks the "
                         "target up there by shard id (cShardBroadcast::OnDestinationInfoResponse). List the "
                         "Master (id 1) too, so the way back resolves. Needs --public-host.")
    ap.add_argument("--public-host", default="",
                    help="address given as __addr of each secondary; the phone only uses it as a label for "
                         "the EOS connection, but a LAN address would make it dial UDP instead")
    ap.add_argument("--row-file", default="",
                    help="write {rowId, region} of the Mobile row here, for lan_bridge --migrate-lobby")
    a = ap.parse_args()
    if a.secondary and not a.public_host:
        ap.error("--secondary needs --public-host")
    tags = ",".join(["english", a.mode] + [t.strip() for t in a.tags.split(",") if t.strip()])

    description = a.description.replace("\\n", "\n")

    rows = []
    for spec in a.row:
        parts = spec.split(":")
        platform, version, port, token_file = parts[:4]
        row_password = a.password or (len(parts) > 4 and parts[4] == "p")
        puid = a.eos_host
        if puid and os.path.isfile(puid):
            puid = open(puid).read().strip()
        eos_host = f"E:{puid}" if puid and int(platform) == 64 else ""
        rows.append({"platform": int(platform), "version": int(version), "port": int(port),
                     "password": row_password, "steamid": eos_host,
                     "token": open(token_file).read().strip(), "id": None, "guid": None,
                     "session": os.urandom(8).hex().upper(), "misses": 0})

    def read_puid(path):
        try:
            puid = open(path).read().strip()
        except OSError:
            return ""
        return puid[2:] if puid.startswith("E:") else puid

    def secondaries():
        out = {}
        for spec in a.secondary:
            shard, port, puid_file = spec.split(":", 2)
            puid = read_puid(puid_file)
            if puid:
                out[shard] = {"__addr": a.public_host, "id": shard, "steamid": f"E:{puid}", "port": int(port)}
        return out

    def save_row_file(row):
        if not a.row_file or row["platform"] != 64:
            return
        tmp = a.row_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"rowId": row["id"], "region": a.region}, f)
        os.replace(tmp, a.row_file)

    def get_row_id(row):
        if row["id"]:
            return row["id"]
        parts = row["token"].split("^")
        if len(parts) >= 4:
            return f"{parts[1]}^{parts[3]}"
        return None

    def remove(row):
        rid = get_row_id(row)
        if rid:
            post(a.region, "/lobby/delete", {"__token": row["token"], "__rowId": rid}, row["token"])
        row["id"] = row["guid"] = None

    def write(row, guid):
        puid = a.eos_host
        if puid and os.path.isfile(puid):
            puid = open(puid).read().strip()
        if puid and row["platform"] == 64:
            row["steamid"] = f"E:{puid}"

        body = {
            "__token": row["token"], "masterversion": 1,
            "host": row["token"].split("^")[1], "name": a.name, "platform": row["platform"],
            "v": row["version"], "port": row["port"], "session": row["session"], "guid": guid,
            # A dedicated server keeps clienthosted false even with an EOS id; that is what the
            # other mobile dedicated rows publish and what gives the row its dedicated icon.
            "dedicated": True, "clienthosted": False, "password": row["password"],
            "lanonly": False,
            "clanonly": False, "fo": False, "pvp": False, "mods": False,
            "maxconnections": a.max_players, "connected": 0,
            "mode": a.mode, "intent": a.mode, "season": a.season,
            "tags": tags, "allownewplayers": True, "serverpaused": False,
            "steamid": row["steamid"], "steamroom": "0", "nat": 5, "tick": 15, "clientmodsoff": False,
            # The details panel reads the description from `desc`; `data` only carries the day.
            "desc": description,
            "data": "return { day=1, dayselapsedinseason=0, daysleftinseason=20 }",
            "players": "return {  }",
        }
        if row["platform"] == 64 and a.secondary:
            row["secondaries"] = secondaries()
            body["secondaries"] = row["secondaries"]
        status, answer = post(a.region, "/lobby/write", body, row["token"])
        if status == 200:
            row["id"], row["guid"] = answer["POST"]["__rowId"], guid
            save_row_file(row)
            print(f"[lobby] platform {row['platform']} listed as {row['id']} at "
                  f"{answer['POST'].get('__addr')}:{row['port']} guid {guid}", flush=True)
        elif answer.get("Error", {}).get("Code") == "E_ROWID_EXIST":
            print(f"[lobby] row exists, clearing and rewriting...", flush=True)
            rid = get_row_id(row)
            if rid:
                post(a.region, "/lobby/delete", {"__token": row["token"], "__rowId": rid}, row["token"])
            status2, answer2 = post(a.region, "/lobby/write", body, row["token"])
            if status2 == 200:
                row["id"], row["guid"] = answer2["POST"]["__rowId"], guid
                save_row_file(row)
                print(f"[lobby] platform {row['platform']} listed as {row['id']} at "
                      f"{answer2['POST'].get('__addr')}:{row['port']} guid {guid}", flush=True)

    def leave(*_):
        for row in rows:
            remove(row)
        sys.exit(0)
    signal.signal(signal.SIGTERM, leave)
    signal.signal(signal.SIGINT, leave)

    last_keepalive = time.time()
    while True:
        for row in rows:
            guid, session = raknet_probe(a.probe_host, row["port"])
            if guid is None:
                row["misses"] += 1
                if row["misses"] == MISSES_BEFORE_DELETE:
                    print(f"[lobby] port {row['port']} stopped answering", flush=True)
                    remove(row)
                continue
            row["misses"] = 0
            changed = guid != row["guid"]
            if session is not None and session != row["session"]:
                row["session"] = session
                changed = True
            # The EOS device-id login hands out a NEW ProductUserId every time the relay
            # restarts, so the puid file can change under us. The row must then be rewritten,
            # or the phone keeps dialing the dead old peer. (The bridge pong self-heals because
            # build_payload re-reads the file on every ping.)
            if a.eos_host and row["platform"] == 64 and os.path.isfile(a.eos_host):
                want = f"E:{open(a.eos_host).read().strip()}"
                if want and want != row["steamid"]:
                    print(f"[lobby] host PUID changed {row['steamid']} -> {want}, rewriting row", flush=True)
                    row["steamid"] = want
                    changed = True
            # A relay restart gives its shard a new id too; the secondaries must follow.
            if row["platform"] == 64 and a.secondary and secondaries() != row.get("secondaries"):
                print("[lobby] secondary shard ids changed, rewriting row", flush=True)
                changed = True
            if changed:
                remove(row)
                write(row, guid)
        if time.time() - last_keepalive >= KEEPALIVE_S:
            last_keepalive = time.time()
            for row in rows:
                if row["id"]:
                    status, answer = post(a.region, "/lobby/keepAlive",
                                          {"__token": row["token"], "__rowId": row["id"]}, row["token"])
                    # The lobby drops rows on its own (E_NOT_IN_DB); forget the id so the
                    # next probe writes the row again instead of keepAlive-ing a corpse.
                    if answer.get("Error", {}).get("Code") == "E_NOT_IN_DB":
                        print(f"[lobby] row {row['id']} is gone from DB, rewriting on the next probe", flush=True)
                        row["id"] = row["guid"] = None
        time.sleep(PROBE_S)


if __name__ == "__main__":
    main()
