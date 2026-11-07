#!/usr/bin/env python3
"""
proxy-bridge/lan_bridge.py

Bridge LAN thử nghiệm giữa client DST Mobile và server PC Dedicated.

1. Nghe broadcast tìm server LAN (RakNet ID_UNCONNECTED_PING) của client mobile và trả lời
   bằng offline ping response theo định dạng mobile (phiên bản/nền tảng mobile), để server PC
   hiện trong tab LAN của điện thoại.
2. Mọi gói khác từ client được chuyển tiếp tới server PC (mỗi client một socket riêng),
   gói trả lời được gửi ngược lại. Header từng gói được ghi log để phân tích bắt tay.

--rewrite-listing sửa gói 0x86. --geyser sửa network id 24→18 trong khung 0x87
(construction và đuôi serialize) và trong khung 0x88. Mọi gói khác đi nguyên vẹn.

Cách dùng:
    python3 lan_bridge.py --listen-port 11000 --server 127.0.0.1:10999 \
        --template pong_mobile.hex --name PC-Bridge-761239 --log bridge.log
"""

import argparse
import json
import os
import select
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from listing_rewrite import rewrite_listing, rewrite_listing_payload
except Exception:
    rewrite_listing = rewrite_listing_payload = None
try:
    from geyser.translator import GeyserTranslator, TranslatorConfig
    from geyser.raknet import ack_datagram, ack_numbers, datagram_number
except Exception:
    GeyserTranslator = None
    TranslatorConfig = None
    ack_datagram = None
    ack_numbers = None
    datagram_number = None

RAKNET_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
ID_UNCONNECTED_PING = 0x01
ID_UNCONNECTED_PING_OPEN = 0x02
ID_UNCONNECTED_PONG = 0x1C

PROBE_EVERY_S = 2.0
SERVER_SILENT_S = 7.0   # three missed probes


class ServerWatch:
    """Whether the server behind the bridge is up.

    The pong comes from a template, so the bridge would list a dead or still loading
    server. A dedicated server answers a bare unconnected ping, even while paused.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.probe_at = None
        self.seen = None

    def probe_due(self, now: float) -> bool:
        if not self.enabled or (self.probe_at is not None and now - self.probe_at < PROBE_EVERY_S):
            return False
        self.probe_at = now
        return True

    def pong(self, now: float) -> None:
        self.seen = now

    def alive(self, now: float) -> bool:
        return not self.enabled or (self.seen is not None and now - self.seen < SERVER_SILENT_S)

RTT_REPORT_S = 30.0
RTT_PENDING_S = 10.0    # a datagram not ACKed by then was lost or resent under a new number


class RttLeg:
    """Round trip of one leg (bridge to client, or bridge to server) for one client.

    Time from forwarding a data datagram to seeing the ACK that names it. A resend
    gets a new datagram number, so a sample never mixes two transmissions. The peer
    ACKs on its own update tick, so the minimum is the closest to the path itself.
    """

    def __init__(self):
        self.sent = {}
        self.samples = []

    def forwarded(self, number: int, now: float) -> None:
        self.sent[number] = now

    def acked(self, numbers, now: float) -> None:
        for number in numbers:
            at = self.sent.pop(number, None)
            if at is not None:
                self.samples.append(now - at)

    def report(self, now: float):
        """(count, min, median, p95) in ms since the last report, or None."""
        self.sent = {n: t for n, t in self.sent.items() if now - t < RTT_PENDING_S}
        if not self.samples:
            return None
        s, self.samples = sorted(self.samples), []
        return len(s), s[0] * 1000, s[len(s) // 2] * 1000, s[min(len(s) - 1, len(s) * 95 // 100)] * 1000


def set_lan_only(flags: bytes, on: bool) -> bytes:
    """Bật/tắt cờ LAN-only (listing 0x286) trong 8 byte cờ ngay sau session của pong.

    Cờ này quyết định điện thoại nối UDP thẳng (bật) hay qua EOS (tắt) tới IP không cùng LAN
    (cPendingConnection::IsEosNetworkConnection, mobile VA 0x899234). Sau session là 3 trường
    string-num dạng index (1 bit + 4 bit), 2 bit 0x284/0x285, net id rỗng (3 bit 0), rồi tới 0x286:
    bit thứ 20, tức byte 2 mask 0x08.
    """
    bits = int.from_bytes(flags[:3], "big")
    if any(not (bits >> (23 - 5 * k)) & 1 for k in range(3)) or (bits >> 4) & 0b111:
        raise ValueError("Pong mẫu không có layout quen thuộc; không bật được LAN-only")
    b = bytearray(flags)
    b[2] = (b[2] | 0x08) if on else (b[2] & ~0x08)
    return bytes(b)


def build_payload(template: bytes, name: str, session: str, eos_host: str = "",
                  lan_only: bool | None = None) -> bytes:
    """Thay session, tên và (nếu có) ProductUserId trong payload mẫu của server mobile.

    lan_only=True/False ghi đè cờ LAN-only của mẫu; None giữ nguyên."""
    i = template.rfind(b"\x00\x10")
    while i >= 0 and not all(chr(c) in "0123456789ABCDEF" for c in template[i + 2:i + 18]):
        i = template.rfind(b"\x00\x10", 0, i)
    if i < 0:
        raise ValueError("Không tìm thấy session trong payload mẫu")
    head, rest = template[:i], template[i + 18:]
    if eos_host:
        puid = open(eos_host).read().strip() if os.path.isfile(eos_host) else eos_host.strip()
        if puid.startswith("E:"):
            puid = puid[2:]
        if len(puid) == 32:
            import re
            m = re.search(rb"0002[0-9a-fA-F]{28}", head)
            if m:
                head = head[:m.start()] + puid.encode("ascii") + head[m.end():]
    flags, region = rest[:8], rest[8:10]
    if lan_only is not None:
        flags = set_lan_only(flags, lan_only)
    name_b = name.encode()
    return head + b"\x00\x10" + session.encode() + flags + region + struct.pack(">H", len(name_b)) + name_b

def read_row_file(path: str):
    """(rowId, region) of the Mobile row, or None while the announcer has not listed it."""
    try:
        with open(path) as f:
            row = json.load(f)
        return row["rowId"], row["region"]
    except (OSError, ValueError, KeyError):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-port", type=int, default=11000)
    ap.add_argument("--server", default="127.0.0.1:10999")
    ap.add_argument("--template", required=True, help="File hex chứa payload pong của server mobile")
    ap.add_argument("--name", default="PC-Bridge")
    ap.add_argument("--log", default="bridge.log")
    ap.add_argument("--duration", type=int, default=1800)
    ap.add_argument("--rewrite-listing", action="store_true",
                    help="Ghi lại gói handshake listing (0x86) sang format mobile")
    ap.add_argument("--geyser", action="store_true",
                    help="Dịch network id 0x87 và 0x88 từ 24 bit xuống 18 bit. Gói không parse được thì đi nguyên.")
    ap.add_argument("--netvars", action="store_true",
                    help="Cùng --geyser: mã hóa lại netvar entity từ schema PC sang schema mobile (geyser/schema), "
                         "và đổi mã RPC/action của điện thoại sang mã PC.")
    ap.add_argument("--announce", metavar="HOST[:PORT]",
                    help="Gửi pong không cần ping tới HOST:PORT (không có PORT thì quét mọi cổng) cho tới khi HOST "
                         "kết nối. Dùng khi điện thoại phát hotspot: broadcast của nó đi ra mạng di động, không tới bridge.")
    ap.add_argument("--migrate", metavar="PORT=BRIDGE_PORT", action="append", default=[],
                    help="Cùng --geyser: khi server chuyển điện thoại sang shard ở PORT (vào/ra hang), "
                         "đổi thành cổng của bridge đứng trước shard đó. Lặp lại cho từng shard.")
    ap.add_argument("--migrate-host", default="",
                    help="Cluster online: server gửi gói chuyển shard dạng online (0x97, không có địa chỉ). Bridge đổi "
                         "thành gói LAN trỏ về HOST này (IP/tên miền điện thoại quay số tới) và cổng của bridge duy "
                         "nhất trong --migrate. Bỏ trống = để nguyên gói.")
    ap.add_argument("--migrate-lobby", default="", metavar="ROW_FILE",
                    help="Cluster online, điện thoại vào qua EOS: gửi gói chuyển shard dạng online (điện thoại tra row "
                         "Mobile trên lobby rồi nối EOS tới secondaries[--migrate-shard]). ROW_FILE là file "
                         "lobby_announce --row-file ghi. Được ưu tiên hơn --migrate/--migrate-host khi file có.")
    ap.add_argument("--migrate-shard", type=int, default=0, metavar="ID",
                    help="Cùng --migrate-lobby: id của shard đích trong secondaries (Master = 1).")
    ap.add_argument("--lan-only-pong", action="store_true",
                    help="Bật cờ LAN-only trong pong. Dùng cho bridge Caves trên cluster online: điện thoại chuyển "
                         "shard sang đây sẽ nối UDP thẳng tới --migrate-host thay vì qua EOS. Đừng bật trên bridge "
                         "Master đứng sau relay EOS: điện thoại vào từ danh sách Online sẽ kẹt ở Connecting.")
    ap.add_argument("--unlisted", action="store_true",
                    help="Bridge của shard phụ: không trả lời dò LAN nên không hiện thành một server riêng. Vẫn trả lời "
                         "ping mà client gửi ngay trước khi kết nối, ping này kèm user id.")
    ap.add_argument("--server-password", default=None,
                    help="Mật khẩu cluster của server PC. Điện thoại không có ô nhập mật khẩu trong handshake "
                         "nên bridge tự điền vào slot password (giữa net id và tên) khi chuyển handshake lên server. "
                         "Bỏ trống = server không đặt cluster_password.")
    ap.add_argument("--always-pong", action="store_true",
                    help="Trả pong kể cả khi server không trả lời. Mặc định bridge tự ping server và chỉ trả pong "
                         "khi server còn sống, để server chết hoặc đang load không hiện trong tab LAN.")
    ap.add_argument("--eos-host", default="",
                    help="File or string of adapter EOS ProductUserId; if provided, updates the host PUID in the pong payload")
    args = ap.parse_args()

    host, port = args.server.rsplit(":", 1)
    server = (host, int(port))
    template = bytes.fromhex(open(args.template).read().strip())
    payload_session = os.urandom(8).hex().upper()
    payload = build_payload(template, args.name, payload_session, eos_host=args.eos_host,
                            lan_only=True if args.lan_only_pong else None)
    guid = os.urandom(8)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    lsock.bind(("0.0.0.0", args.listen_port))

    # Dò server: socket riêng, không lẫn với gói của client.
    watch = ServerWatch(enabled=not args.always_pong)
    hsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hsock.bind(("0.0.0.0", 0))
    probe = bytes([ID_UNCONNECTED_PING]) + bytes(8) + RAKNET_MAGIC + guid
    was_alive, started = None, time.monotonic()

    upstream = {}   # địa chỉ client -> socket tới server
    reverse = {}    # socket -> địa chỉ client
    log = open(args.log, "a", buffering=1)

    geyser = None
    if args.geyser and GeyserTranslator is not None:
        def _glog(msg, _log=log):
            print(msg, flush=True)
            _log.write(f"{time.time():.3f} {msg}\n")
        mapper = rpc = None
        if args.netvars:
            from geyser.netvars import NetvarMapper
            from geyser.rpc import RpcMapper
            mapper = NetvarMapper.from_dir()
            rpc = RpcMapper.from_dir(password=args.server_password.encode() if args.server_password else None)
            print(f"[+] Netvars: {len(mapper.pc)} prefab PC, {len(mapper.mob)} prefab mobile; RPC {len(rpc.code_map)} mã")
        geyser = GeyserTranslator(TranslatorConfig(
            enabled=True, translate_construction=True, translate_serialize=True, netvars=mapper, rpc=rpc,
            migrate_ports=dict(tuple(map(int, m.split("="))) for m in args.migrate),
            migrate_host=args.migrate_host,
            migrate_password=(args.server_password or "").encode(),
            listing=rewrite_listing_payload if args.rewrite_listing else None,
            migrate_lobby=(lambda path=args.migrate_lobby: read_row_file(path)) if args.migrate_lobby else None,
            migrate_shard=args.migrate_shard,
            log=_glog))
        print("[+] Geyser: rewrite 0x87 and 0x88 network id 24→18, including 0x88/0x8c splits. ACK/NAK và message khác đi nguyên.")
    elif args.geyser:
        print("[!] --geyser được bật nhưng không import được geyser; passthrough")

    def record(direction, addr, data):
        log.write(f"{time.time():.3f} {direction} {addr[0]}:{addr[1]} len={len(data)} id=0x{data[0]:02x} {data[:512].hex()}\n")

    rtt = {}        # (leg, địa chỉ client) -> RttLeg
    rtt_last = time.monotonic()

    def rtt_leg(leg, peer):
        return rtt.setdefault((leg, peer), RttLeg())

    def rtt_report(now):
        for (leg, peer), stats in list(rtt.items()):
            r = stats.report(now)
            if r is None:
                if not stats.sent:
                    del rtt[(leg, peer)]
                continue
            log.write(f"{time.time():.3f} rtt {leg} {peer[0]}:{peer[1]} n={r[0]} "
                      f"min={r[1]:.1f} p50={r[2]:.1f} p95={r[3]:.1f} ms\n")

    def emit(direction, peer, datagrams):
        for dgram in datagrams:
            number = datagram_number(dgram) if datagram_number is not None else None
            if number is not None:
                rtt_leg("server" if direction == "c2s" else "client", peer).forwarded(number, time.monotonic())
            if direction == "c2s":
                sock = upstream.get(peer)
                if sock is None:
                    log.write(f"{time.time():.3f} drop c2s no-socket {peer}\n")
                    continue
                sock.sendto(dgram, server)
            else:
                lsock.sendto(dgram, peer)

    def flush_geyser():
        if geyser is None:
            return
        for direction, peer, dgram in geyser.flush(time.monotonic()):
            emit(direction, peer, [dgram])

    # Pong cho --announce. sendPingTime tối đa: RakNet tính ping = now - sendPingTime, ra 0 hoặc số nhỏ.
    announce_pong = bytes([ID_UNCONNECTED_PONG]) + b"\xff" * 8 + guid + RAKNET_MAGIC + payload
    announce_host, announce_fixed, announce_port, announce_last = None, None, 1024, 0.0
    if args.announce:
        announce_host, _, p = args.announce.partition(":")
        announce_fixed = int(p) if p else None

    def announce():
        nonlocal announce_port, announce_last
        if announce_fixed is not None:
            if time.time() - announce_last >= 0.5:
                announce_last = time.time()
                lsock.sendto(announce_pong, (announce_host, announce_fixed))
            return
        for _ in range(2048):
            try:
                lsock.sendto(announce_pong, (announce_host, announce_port))
            except OSError:
                pass
            announce_port = announce_port + 1 if announce_port < 65535 else 1024

    print(f"[+] Bridge nghe UDP {args.listen_port}, chuyển tới {server}, tên '{args.name}'")
    if args.announce:
        print(f"[+] Announce: gửi pong tới {args.announce} cho tới khi nó kết nối")
    end = time.time() + args.duration
    while time.time() < end:
        flush_geyser()
        now = time.monotonic()
        if now - rtt_last >= RTT_REPORT_S:
            rtt_last = now
            rtt_report(now)
        if watch.probe_due(now):
            try:
                hsock.sendto(probe, server)
            except OSError:
                pass
        alive = watch.alive(now)
        # Lúc mới chạy chưa có pong nào: chờ hết SERVER_SILENT_S rồi mới báo server chết.
        if watch.enabled and alive != was_alive and (alive or was_alive or now - started >= SERVER_SILENT_S):
            msg = "server-up" if alive else "server-down: không trả pong cho tới khi server trả lời"
            print(f"[{'+' if alive else '!'}] {msg}", flush=True)
            log.write(f"{time.time():.3f} {msg}\n")
            was_alive = alive
        announcing = (alive and announce_host is not None
                      and not any(a[0] == announce_host for a in upstream))
        if announcing:
            announce()
        ready, _, _ = select.select([lsock, hsock, *reverse.keys()], [], [], 0.05 if announcing else 0.5)
        for s in ready:
            try:
                data, addr = s.recvfrom(65535)
            except OSError:
                # ICMP port unreachable của server đã chết báo về socket đã gửi tới nó.
                continue
            if not data:
                continue
            if s is hsock:
                if data[0] == ID_UNCONNECTED_PONG:
                    watch.pong(time.monotonic())
                continue
            if s is lsock:
                if data[0] in (ID_UNCONNECTED_PING, ID_UNCONNECTED_PING_OPEN) and data[9:25] == RAKNET_MAGIC:
                    # After the magic and client guid the phone writes a user id string: empty in a
                    # LAN browse, set in the ping it sends to a server it is about to connect to.
                    if args.unlisted and data[33:35] in (b"", b"\x00\x00"):
                        continue
                    if not watch.alive(time.monotonic()):
                        continue
                    cur_payload = build_payload(template, args.name, payload_session, eos_host=args.eos_host,
                            lan_only=True if args.lan_only_pong else None) if args.eos_host else payload
                    pong = bytes([ID_UNCONNECTED_PONG]) + data[1:9] + guid + RAKNET_MAGIC + cur_payload
                    lsock.sendto(pong, addr)
                    # Không ghi phần sau guid: ping trước khi kết nối kèm user id.
                    record("ping", addr, data[:33])
                    continue
                if addr not in upstream:
                    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    u.bind(("0.0.0.0", 0))
                    upstream[addr], reverse[u] = u, addr
                    log.write(f"{time.time():.3f} new-client {addr[0]}:{addr[1]}\n")
                record("c->s", addr, data)
                if ack_numbers is not None and data[0] & 0xC0 == 0xC0:
                    rtt_leg("client", addr).acked(ack_numbers(data), time.monotonic())
                if geyser is not None:
                    outs = geyser.translate_datagram("c2s", data, peer=addr, now=time.monotonic())
                else:
                    outs = [data]
                emit("c2s", addr, outs)
            else:
                client = reverse[s]
                record("s->c", client, data)
                if ack_numbers is not None and data[0] & 0xC0 == 0xC0:
                    rtt_leg("server", client).acked(ack_numbers(data), time.monotonic())
                out = data
                if args.rewrite_listing and rewrite_listing is not None:
                    try:
                        rw = rewrite_listing(data)
                    except Exception as e:
                        rw = None
                        log.write(f"{time.time():.3f} rewrite-error {e}\n")
                    if rw is not None:
                        log.write(f"{time.time():.3f} rewrote-listing in={len(data)} out={len(rw)} "
                                  f"newbits=0x{rw[5]:02x}{rw[6]:02x}\n")
                        out = rw
                if geyser is not None:
                    outs = geyser.translate_datagram("s2c", out, peer=client, now=time.monotonic())
                    if not outs:
                        log.write(f"{time.time():.3f} geyser-held {client[0]}:{client[1]} len={len(out)}\n")
                        # The client has not seen this datagram, so it will not ACK it.
                        # ACK the server now or its resend timer stalls the rest of the split.
                        if ack_datagram is not None and datagram_number is not None:
                            number = datagram_number(out)
                            if number is not None:
                                s.sendto(ack_datagram(number), server)
                    elif outs != [out]:
                        log.write(f"{time.time():.3f} geyser-out n={len(outs)} "
                                  f"lens={','.join(str(len(d)) for d in outs)}\n")
                        # A repacked split reuses the numbers of its first pieces; the
                        # datagram that completed it is never sent, so ACK it here.
                        if ack_datagram is not None and datagram_number is not None:
                            number = datagram_number(out)
                            if number is not None and number not in {datagram_number(d) for d in outs}:
                                s.sendto(ack_datagram(number), server)
                else:
                    outs = [out]
                emit("s2c", client, outs)
        flush_geyser()

if __name__ == "__main__":
    main()
