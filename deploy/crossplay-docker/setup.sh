#!/bin/bash
# One-stop helper for the crossplay stack.
#
#   ./setup.sh server   download the DST dedicated server into vendor/dst-server and patch it
#   ./setup.sh check    verify that everything the stack needs is in place
#   ./setup.sh up       download the server if missing, check, build and start
set -euo pipefail
cd "$(dirname "$0")"

fail=0
ok()   { echo "  ok       $1"; }
miss() { echo "  MISSING  $1"; fail=1; }

server() {
    mkdir -p vendor/dst-server
    # Anonymous Steam download of app 343050 (DST dedicated server), about 3.5 GB.
    # steamcmd sometimes ends with "Missing configuration" on a first run; a retry gets through.
    for attempt in 1 2 3; do
        docker run --rm --platform linux/amd64 --network host -v "$PWD/vendor/dst-server:/dst" steamcmd/steamcmd:latest \
            +force_install_dir /dst +login anonymous +app_update 343050 validate +quit || true
        [ -x vendor/dst-server/bin64/dontstarve_dedicated_server_nullrenderer_x64 ] && break
        echo "download incomplete (attempt $attempt of 3), retrying"
    done
    python3 server/patch_server.py vendor/dst-server
}

check() {
    echo "Checking $(pwd)"
    if [ -f .env ]; then ok ".env"; else miss ".env (cp .env.example .env, then fill it in)"; fi
    for v in DST_EOS_PRODUCT_ID DST_EOS_SANDBOX_ID DST_EOS_DEPLOYMENT_ID DST_EOS_CLIENT_ID DST_EOS_CLIENT_SECRET SERVER_PASSWORD; do
        if [ -f .env ] && grep -Eq "^$v=.+" .env; then ok "$v is set"; else miss "$v in .env"; fi
    done
    # The pong template carries no secret, so we synthesize it from the known wire
    # format instead of asking for a captured file (vendor/gen_pong_template.py).
    if [ ! -e vendor/pong_mobile.hex ] && [ -f vendor/gen_pong_template.py ]; then
        name=$(grep -E '^SERVER_NAME=' .env 2>/dev/null | cut -d= -f2- | tr -d '"' || true)
        if [ -n "$name" ]; then
            python3 vendor/gen_pong_template.py -o vendor/pong_mobile.hex --name "$name" >/dev/null
        else
            python3 vendor/gen_pong_template.py -o vendor/pong_mobile.hex >/dev/null
        fi
        echo "  made     vendor/pong_mobile.hex (synthesized, no capture needed)"
    fi
    for f in vendor/eos-sdk/include/eos_sdk.h vendor/eos-sdk/lib/x86_64-linux/libEOSSDK-Linux-Shipping.so vendor/pong_mobile.hex; do
        if [ -e "$f" ]; then ok "$f"; else miss "$f (see vendor/README.md)"; fi
    done
    profiles=$(grep -E '^COMPOSE_PROFILES=' .env 2>/dev/null | cut -d= -f2 || true)
    case ",$profiles," in *,announcer,*)
        if [ -s vendor/cluster_token.txt ]; then ok "vendor/cluster_token.txt"; else miss "vendor/cluster_token.txt (Klei cluster token for the Mobile row)"; fi;;
    esac
    offline=$(grep -E '^OFFLINE_CLUSTER=' .env 2>/dev/null | cut -d= -f2 || true)
    if [ -s vendor/cluster_token_steam.txt ]; then
        [ "$offline" = true ] && echo "  note     OFFLINE_CLUSTER=true: vendor/cluster_token_steam.txt is ignored" \
                              || ok "vendor/cluster_token_steam.txt (online: Steam row)"
    elif [ "$offline" = false ]; then
        miss "vendor/cluster_token_steam.txt (OFFLINE_CLUSTER=false needs the Steam-row token)"
    else
        echo "  note     no vendor/cluster_token_steam.txt: offline LAN world, no Steam row"
    fi
    case ",$profiles," in *,server,*)
        dir=$(grep -E '^DST_SERVER_DIR=' .env 2>/dev/null | cut -d= -f2 || true); dir=${dir:-./vendor/dst-server}
        if [ -x "$dir/bin64/dontstarve_dedicated_server_nullrenderer_x64" ]; then
            state=$(python3 server/patch_server.py --check "$dir" 2>&1) || true
            if [ "$state" = patched ]; then ok "$dir (build 762172, patched)"; else miss "$dir: $state (run ./setup.sh server)"; fi
        else
            miss "$dir (run ./setup.sh server)"
        fi;;
    esac
    if docker compose version >/dev/null 2>&1; then ok "docker compose"; else miss "docker compose"; fi
    [ "$fail" = 0 ] && echo "All good." || { echo "Fix the MISSING items above."; return 1; }
}

case "${1:-}" in
    server) server ;;
    check)  check ;;
    up)
        profiles=$(grep -E '^COMPOSE_PROFILES=' .env 2>/dev/null | cut -d= -f2 || true)
        dir=$(grep -E '^DST_SERVER_DIR=' .env 2>/dev/null | cut -d= -f2 || true); dir=${dir:-./vendor/dst-server}
        case ",$profiles," in *,server,*|*,caves,*)
            [ "$dir" = ./vendor/dst-server ] && [ ! -x "$dir/bin64/dontstarve_dedicated_server_nullrenderer_x64" ] && server;;
        esac
        check && docker compose up -d --build && docker compose ps ;;
    *)      sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
