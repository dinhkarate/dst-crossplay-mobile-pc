# DST Crossplay (Docker)

Host one Don't Starve Together dedicated server that **phones can join from the mobile Online
list**. One folder, one `.env`, one command. This is the stack that runs the public servers
".DST Crossplay PC Mobile #1-#3".

> **Verified live.** A retail phone (Samsung, `com.playdigious.dst` 2.3.1) joins this Linux stack
> from the Mobile Online list and plays on server build 762172, goes down a sinkhole into the
> Caves and comes back up. Last confirmed 2026-11-18 on three servers.

## How it works

A phone never dials a server's IP. It reads a row from Klei's Mobile lobby list and connects to
the Epic Online Services (EOS) id in that row. A PC dedicated server has no EOS id and speaks a
slightly different wire dialect, so the stack adds three small services around it:

```
 phone ──EOS P2P (Epic)──▶ relay ──UDP──▶ bridge ──UDP──▶ server
   ▲                                                        (patched PC dedicated server)
   └── reads the row ◀── announcer (Klei Mobile lobby list)
```

| Service | What it does |
|---|---|
| `server` | The Master shard (surface) of the PC dedicated server, build 762172, with six small binary patches (`server/patch_server.py`). Offline unless `vendor/cluster_token_steam.txt` exists (see "Tokens"). |
| `caves` | The Caves shard: same image, same world volume, linked to the Master over loopback. Profile `caves`. |
| `bridge` | Translates the mobile and PC dialects in both directions and answers the list ping. |
| `bridge-caves` | The same for the Caves shard. Unlisted: it only answers the ping a phone sends right before it moves to the caves. Profile `caves`. |
| `relay` | Logs in to EOS and carries phone traffic between Epic's network and the bridge. Its id is kept in the `eos-cache` volume, so it survives restarts. |
| `relay-caves` | A second EOS id in front of `bridge-caves`, for phones changing shard (`eos-cache-caves` volume). Profile `caves`. |
| `announcer` | Writes the lobby row (dedicated, password protected) that points at the relay's id, with both shards' relays under `secondaries`. |

Everything runs on one machine. A home connection behind an ordinary router works without any
port forward for a phone to play: EOS starts through Epic's relays and upgrades to a direct
connection. A PC that joins the self-registered Steam row connects straight to the server port,
so an online server needs UDP `SERVER_PORT` forwarded to this machine, plus `CAVES_PORT` for
going down a sinkhole (and `CAVES_BRIDGE_PORT` for phones that join over the LAN).

### Caves

A sinkhole moves the player to the other shard: the server sends the client the Caves port and
the client reconnects there. PC clients need nothing more. For a phone, `bridge` rewrites that
port to `bridge-caves`, which translates for the Caves shard, and `bridge-caves` sends it back
on the stairs. **What works today:**

| Who | Offline / LAN world | Online world |
|---|---|---|
| PC (Steam) | ✅ | ✅ (forward `CAVES_PORT`) |
| Phone on the same LAN (direct UDP) | ✅ tested: down, play, up, twice | 🧪 not yet tested live |
| Phone from the Mobile Online list (EOS) | — | ✅ via `relay-caves`: down, play, up (2026-11-18) |

A phone from the Mobile Online list is connected over EOS and has to change shard over EOS
as well. The `caves` profile adds `relay-caves`, a second EOS identity in front of
`bridge-caves`; the announcer lists both relays in the Mobile row's `secondaries` (Master = 1,
Caves = `CAVES_SHARD_ID`), and the bridges send the phone the online move message, which makes
it look the target up there. Both relays need the same EOS credentials; the Caves relay
gets its own id on first start. Drop `caves` from `COMPOSE_PROFILES` for a surface-only world.

## What you need

- Linux x86_64 with Docker and Docker Compose, about 5 GB of disk and 2 GB of RAM.
- The four things listed in [`vendor/README.md`](vendor/README.md): the EOS SDK, a pong
  template, a Klei cluster token, and the EOS credentials of the DST mobile deployment.

### Tokens

One Klei cluster token makes one lobby row, so an online server uses two
(accounts.klei.com → Game Servers, one token per row):

| File | Row |
|---|---|
| `vendor/cluster_token.txt` | Mobile list (written by `announcer`) |
| `vendor/cluster_token_steam.txt` | Steam list (the server lists itself; also turns the world online) |

Without `cluster_token_steam.txt` the world stays offline (LAN): PC players then only find it
under LAN. `OFFLINE_CLUSTER=true/false` in `.env` overrides that choice.

> The EOS credentials are the ones embedded in the mobile game. Using them from your own
> server is a gray area under Epic's and Klei's terms. Run this for yourself and your friends.

### Getting the five `DST_EOS_*` values

These are **not** per-player and **not** something you register yourself: they are the single set
of credentials of Klei's retail DST Mobile EOS deployment, identical for everyone. A retail phone
can only do EOS P2P inside Klei's product, so your server must present the same credentials — there
is no "use your own Epic app" substitute. The repo ships none of them; extract them once, from a
copy of the game **you own**, as an interoperability measure (DMCA §1201(f) / EU Software Directive
Art. 6). Do not redistribute them.

On the APK of DST Mobile you own (from your device or your own backup). On a Play install the native
library is in the arm64 **split** APK, not `base.apk` — unzip whichever split contains
`lib/arm64-v8a/libDontStarve.so`:

```bash
unzip -o split_config.arm64_v8a.apk 'lib/arm64-v8a/libDontStarve.so' -d dst-apk   # or base.apk for a universal APK
cd dst-apk/lib/arm64-v8a

# The five values are stored as five ADJACENT strings, in this order:
#   ProductId, SandboxId, DeploymentId  — each exactly 32 lowercase hex chars
#   ClientId                            — 32 chars, but starts with non-hex letters (e.g. "xy...")
#   ClientSecret                        — longer (~43 chars)
# Find the three 32-hex ids with their offsets; the next two strings right after them are the
# ClientId and ClientSecret:
strings -t x libDontStarve.so | grep -E ' [0-9a-f]{32}$'    # prints exactly 3 lines (the ids) + offsets
strings -t x libDontStarve.so | sort                        # or inspect around those offsets for the
                                                            # two tokens that immediately follow
```

Verified against DST Mobile 2.3.1: the five fields are five consecutive strings. The ClientId is
the string immediately after the third 32-hex id; the ClientSecret is the one after that. Exact
offsets shift between builds, so locate them by the 32-hex anchor rather than by address. Copy the five into your `.env` (`DST_EOS_PRODUCT_ID`, `_SANDBOX_ID`,
`_DEPLOYMENT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET`). The runtime PUID your server uses is generated
automatically on first start (an anonymous EOS DeviceID login) and cached in the `eos-cache`
volume — you do not supply it.

Sanity-check your `.env` before starting (confirms the shape without printing the secret):

```bash
set -a; . ./.env; set +a
for v in DST_EOS_PRODUCT_ID DST_EOS_SANDBOX_ID DST_EOS_DEPLOYMENT_ID; do
  printf '%s: ' "$v"; [ "${#v}" ] && echo "${!v}" | grep -qE '^[0-9a-f]{32}$' && echo "ok (32-hex)" || echo "BAD — want 32 lowercase hex"
done
[ -n "$DST_EOS_CLIENT_ID" ]     && echo "DST_EOS_CLIENT_ID: set (${#DST_EOS_CLIENT_ID} chars)"     || echo "DST_EOS_CLIENT_ID: MISSING"
[ -n "$DST_EOS_CLIENT_SECRET" ] && echo "DST_EOS_CLIENT_SECRET: set (${#DST_EOS_CLIENT_SECRET} chars)" || echo "DST_EOS_CLIENT_SECRET: MISSING"
```

If the three ids are `ok (32-hex)` and both client fields are set, the relay will reach Klei's EOS
on first start. Watch `docker compose logs -f relay`: a line `==== ADAPTER PUID: 0002... ====`
means the credentials were accepted and the relay logged in; `login failed: <reason>` means one of
the five values is wrong.

## Install

```bash
cd deploy/crossplay-docker

cp .env.example .env        # fill in the EOS credentials, the name and the password
#                             then put the vendor files in place (vendor/README.md)

./setup.sh up               # downloads + patches the server the first time (3.5 GB), checks, builds, starts
```

`./setup.sh check` tells you exactly what is still missing. The download stops with a
clear message if Steam now ships a build other than 762172: the patches and the bridge's
translation tables only fit that build.

## Check that it works

```bash
docker compose ps                                   # seven services (four without caves), all "running"
docker compose logs caves | grep -iE "connected to master|shard"   # the Caves shard joined the Master
docker compose logs relay | grep -E "ADAPTER PUID|Listening"
docker compose logs announcer | grep "listed as"
```

On the phone: **Browse Games**, search for your server name, **Join**, enter the password. The
row shows the dedicated-server icon. The first seconds of a session go through Epic's relays
(about 80 ms); it then switches to a direct connection.

## Everyday use

| Task | Command |
|---|---|
| Stop / start | `docker compose down` / `docker compose up -d` |
| Change name, password, description | edit `.env`, delete `cluster.ini` in the `dst-data` volume (or edit it there), `docker compose up -d --force-recreate` |
| Server console | `docker attach dst-crossplay-server-1` (Caves: `dst-crossplay-caves-1`; detach with Ctrl-P Ctrl-Q) |
| Back up the world | copy the `dst-crossplay_dst-data` volume |
| Measure latency | set `BRIDGE_LOG=/logs/bridge.log`, recreate the bridge, `grep " rtt " logs/bridge.log` |

## Other layouts

Set `COMPOSE_PROFILES` in `.env`:

- `server,caves,announcer` (default): everything here.
- `server,announcer`: surface only, no caves.
- `announcer`: the game server runs somewhere else; set `BRIDGE_SERVER=host:port`.
- `server`: another machine announces the row. Copy the relay's id to it once:
  `docker run --rm -v dst-crossplay_eos-cache:/c:ro debian:bookworm-slim cat /c/adapter_puid.txt`

**The ping number in the list.** Phones ping the address that wrote the row, on `BRIDGE_PORT`.
Other servers in the list show `???` there and can still be joined, so a row without a
reachable UDP port should behave the same; this layout has not been tested. To show a number, forward UDP `BRIDGE_PORT` to this machine on your router, or announce
from a VPS and forward that port from there (`tools/udp_relay.py`).

## Good to know

- **Two servers behind one public IP** (two machines on the same home line) must use different
  `BRIDGE_PORT` values: the lobby keys a row by address and port.
- Machines that cannot reach Steam: copy `vendor/dst-server` from one that can, then run
  `python3 server/patch_server.py vendor/dst-server`.

- **Survival resets the world** when every player is dead, and an idle character dies at night.
  Use `GAME_MODE=endless` for a world that should last.
- Keep the default tick rate. 30 Hz was tried and makes the phone's character stutter.
- Players join with default cosmetics; skins are not carried over.
- **No server mods.** Every enabled mod that is not `client_only_mod` adds a network variable to
  each entity, and the phone cannot load mods, so it fails to read the world and stays on a blank
  beige screen. A mod that only adds browser tags (`server_filter_tags`) works when its
  `modinfo.lua` says `client_only_mod = true`: the tags still reach the Steam row.
- Two stacks on one machine also need their own `SHARD_PORT` and Steam ports
  (`MASTER_STEAM_PORT`, `MASTER_AUTH_PORT`, `CAVES_STEAM_PORT`, `CAVES_AUTH_PORT`).
- Adding caves to an existing world: the entrypoint switches the shard link on in the old
  `cluster.ini` and the Caves shard generates its level on first start.
- A session's worth of loading (join) sends 100-300 kB in one burst; the phone acknowledges it
  1-2 s late. That is the loading screen, not lag.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Relay restarts with `deviceid failed: EOS_InvalidState` | The `eos-cache` volume holds a keychain copied from another machine. Empty the volume; the relay creates a new id. |
| Relay exits with `GLIBC_2.38 not found` | The relay image must stay on `debian:trixie`. |
| Relay log has no "connected to Stomp" | The `nofile` limit was removed from the compose file. |
| Phone says "incompatible version" after authenticating | The server binary is not patched: `python3 server/patch_server.py --check vendor/dst-server`. |
| Row missing from the list | `docker compose logs announcer`; the token in `vendor/cluster_token.txt` is wrong or already used by another row. |
| Row lists but shows `???` | See "The ping number in the list". |
