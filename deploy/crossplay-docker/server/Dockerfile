# Runtime for the DST dedicated server. The game files are NOT in the image: they are
# mounted read-only from vendor/dst-server (see setup.sh), so the image stays small and
# carries nothing licensed. The server binary is Linux x86_64 only.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libcurl3-gnutls libstdc++6 \
 && rm -rf /var/lib/apt/lists/*
COPY server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
