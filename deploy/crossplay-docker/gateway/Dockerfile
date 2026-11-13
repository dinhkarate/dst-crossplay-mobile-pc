# The Python gateway: the LAN bridge (phone <-> PC server protocol translation) and the
# lobby announcer (puts the server on Klei's Online lists). Pure stdlib, no pip deps.
# Build context is the REPO ROOT so we can copy proxy-bridge/ into the image.
FROM python:3.12-slim
WORKDIR /gateway
COPY proxy-bridge/ /gateway/
# lan_bridge.py and lobby_announce.py are selected per-service by the compose command.
ENTRYPOINT ["python3", "-u"]
