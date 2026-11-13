# vendor/: what you must provide

These files are licensed, large or bound to an account, so they are not in the repository.
Everything in this folder except this file is ignored by git. `../setup.sh check` verifies them.

| Path | What it is | Where it comes from |
|---|---|---|
| `eos-sdk/include/` | EOS SDK C headers (`eos_sdk.h`, ...) | The EOS SDK for Linux, from Epic's developer portal |
| `eos-sdk/lib/x86_64-linux/libEOSSDK-Linux-Shipping.so` | EOS SDK shared library (needs GLIBC 2.38 or newer) | Same SDK |
| `pong_mobile.hex` | Hex dump of the ping reply a phone expects (`tServerListing`, flag byte `80`: dedicated). The bridge swaps in your name, session and relay id. | Generated for you by `python3 vendor/gen_pong_template.py` (also run automatically by `../setup.sh check`). No capture or account id needed. |
| `cluster_token.txt` | A Klei cluster token; it owns the lobby row. Only for the `announcer` profile. | accounts.klei.com, Game Servers |
| `cluster_token_steam.txt` | Optional, a second Klei cluster token for the Steam row. Present = the world runs online. | accounts.klei.com, Game Servers |
| `dst-server/` | The dedicated server, build 762172, patched. Only for the `server` profile. | `../setup.sh server` |

The EOS credentials (`DST_EOS_*`) go in `../.env`, not here. They are the single, shared set of
credentials of Klei's retail mobile deployment (not per-player, not one you register yourself);
extract them from a copy of the game you own — see **Getting the five `DST_EOS_*` values** in
[`../README.md`](../README.md).
