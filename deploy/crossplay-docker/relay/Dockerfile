# EOS P2P <-> UDP relay: the piece that lets a phone on the Online tab reach the server.
# The EOS SDK binary needs GLIBC >= 2.38, so we build and run on debian:trixie (NOT bookworm 2.36).
# Build context is deploy/crossplay-docker/ ; the EOS SDK is vendored under vendor/eos-sdk/.
FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY vendor/eos-sdk/include /src/include
COPY vendor/eos-sdk/lib/x86_64-linux/libEOSSDK-Linux-Shipping.so /src/
COPY relay/eos_p2p_relay.c /src/
RUN g++ -O2 -std=c++17 -Iinclude eos_p2p_relay.c -L. -lEOSSDK-Linux-Shipping \
    -o eos_p2p_relay -Wl,-rpath,'$ORIGIN'

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/eos_p2p_relay /app/
COPY --from=build /src/libEOSSDK-Linux-Shipping.so /app/
# The relay writes its ProductUserId here; the bridge/announcer read it from the shared volume.
ENV DST_EOS_PUID_FILE=/eos-cache/adapter_puid.txt
ENV DST_EOS_CACHE_DIR=/eos-cache
ENTRYPOINT ["/app/eos_p2p_relay"]
