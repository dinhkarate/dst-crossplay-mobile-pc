#!/bin/bash
# Writes the cluster config from the environment on first start, then runs one shard in
# the foreground: SHARD=Master (the surface, default) or SHARD=Caves. Both shards share the
# data volume and talk over the shard link on loopback. Existing files in the data volume
# are left alone, so edits there survive restarts; delete a file to have it written again.
# Two settings are kept in sync on every start: the [SHARD] link is switched on in a
# cluster.ini written before Caves existed, and the online/offline keys follow OFFLINE_CLUSTER.
#
# Online (Steam + Mobile lobbies): put the Steam-row cluster token in
# vendor/cluster_token_steam.txt. OFFLINE_CLUSTER=auto (the default) goes online when that
# file is there and stays a LAN/offline demo when it is not.
set -euo pipefail
NAME="${CLUSTER_NAME:-Crossplay}"
SHARD="${SHARD:-Master}"
CLUSTER="/data/DoNotStarveTogether/$NAME"
STEAM_TOKEN=/vendor/cluster_token_steam.txt
# The lobby description uses \n for a line break; cluster.ini wants one line.
DESC="${SERVER_DESCRIPTION:-}"
DESC="${DESC//\\n/ | }"

OFFLINE="${OFFLINE_CLUSTER:-auto}"
if [ "$OFFLINE" = auto ]; then
    if [ -s "$STEAM_TOKEN" ]; then OFFLINE=false; else OFFLINE=true; fi
fi

# The shards only listen on loopback, so the key guards nothing outside the host.
SHARD_BLOCK="[SHARD]
shard_enabled = true
bind_ip = 127.0.0.1
master_ip = 127.0.0.1
master_port = ${SHARD_PORT:-10888}
cluster_key = ${CLUSTER_KEY:-crossplay}"

mkdir -p "$CLUSTER/$SHARD"
# Both shards may start at once: write to a temp file and rename, so neither reads half a file.
if [ ! -f "$CLUSTER/cluster.ini" ]; then
    cat > "$CLUSTER/cluster.ini.$SHARD" <<INI
[GAMEPLAY]
game_mode = ${GAME_MODE:-survival}
max_players = ${MAX_PLAYERS:-6}
pvp = false
pause_when_empty = true

[NETWORK]
cluster_name = ${SERVER_NAME:-DST Crossplay}
cluster_description = $DESC
cluster_password = ${SERVER_PASSWORD:-}
lan_only_cluster = $OFFLINE
offline_cluster = $OFFLINE

[MISC]
console_enabled = true

$SHARD_BLOCK
INI
    mv "$CLUSTER/cluster.ini.$SHARD" "$CLUSTER/cluster.ini"
elif grep -Eq '^shard_enabled *= *false' "$CLUSTER/cluster.ini"; then
    echo "[entrypoint] enabling the shard link in an existing cluster.ini"
    SHARD_BLOCK="$SHARD_BLOCK" awk '/^\[SHARD\]/ { print ENVIRON["SHARD_BLOCK"]; skip = 1; next }
                                    /^\[/ { skip = 0 }
                                    !skip' "$CLUSTER/cluster.ini" > "$CLUSTER/cluster.ini.$SHARD"
    mv "$CLUSTER/cluster.ini.$SHARD" "$CLUSTER/cluster.ini"
fi
sed -i -E "s/^(lan_only_cluster|offline_cluster) *=.*/\1 = $OFFLINE/" "$CLUSTER/cluster.ini"

if [ "$OFFLINE" = false ]; then
    if [ -s "$STEAM_TOKEN" ]; then
        cp "$STEAM_TOKEN" "$CLUSTER/cluster_token.txt"
    elif [ ! -s "$CLUSTER/cluster_token.txt" ]; then
        echo "[entrypoint] OFFLINE_CLUSTER=false needs vendor/cluster_token_steam.txt" >&2
        exit 1
    fi
fi

if [ "$SHARD" = Caves ]; then
    PORT="${CAVES_PORT:-11013}" STEAM_PORT="${CAVES_STEAM_PORT:-27017}" AUTH_PORT="${CAVES_AUTH_PORT:-8767}" MASTER=false
    if [ ! -f "$CLUSTER/Caves/worldgenoverride.lua" ]; then
        cat > "$CLUSTER/Caves/worldgenoverride.lua" <<'LUA'
return {
    override_enabled = true,
    preset = "DST_CAVE",
    overrides = {
        specialevent = "none",
    },
}
LUA
    fi
else
    PORT="${SERVER_PORT:-11011}" STEAM_PORT="${MASTER_STEAM_PORT:-27016}" AUTH_PORT="${MASTER_AUTH_PORT:-8766}" MASTER=true
fi
if [ ! -f "$CLUSTER/$SHARD/server.ini" ]; then
    cat > "$CLUSTER/$SHARD/server.ini" <<INI
[NETWORK]
server_port = $PORT

[STEAM]
master_server_port = $STEAM_PORT
authentication_port = $AUTH_PORT

[SHARD]
is_master = $MASTER
name = $SHARD
INI
fi

cd /dst/bin64
exec ./dontstarve_dedicated_server_nullrenderer_x64 -console \
    -persistent_storage_root /data -conf_dir DoNotStarveTogether -cluster "$NAME" -shard "$SHARD"
