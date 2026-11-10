#!/usr/bin/env python3
"""Public UDP front for the crossplay server: forwards each listed port to the same port on
the host that runs the server (reached over the VPN), and the replies back.

Each client address gets its own upstream socket, so the server sees one source port per
client, as it would without the relay. Idle clients are dropped after IDLE_S seconds.

    udp_relay.py --target 192.0.2.10 11001 11002 11003 11004"""
import argparse, selectors, socket, time

IDLE_S = 120


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="address of the host that runs the server")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("ports", type=int, nargs="+")
    a = ap.parse_args()

    sel = selectors.DefaultSelector()
    flows = {}  # (listen socket, client address) -> [upstream socket, last seen]
    for port in a.ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((a.bind, port))
        sel.register(s, selectors.EVENT_READ, ("listen", port))
    print(f"relaying {a.ports} -> {a.target}", flush=True)

    swept = time.time()
    while True:
        for key, _ in sel.select(timeout=5):
            kind, info = key.data
            try:
                data, addr = key.fileobj.recvfrom(65535)
            except ConnectionRefusedError:
                # An ICMP port-unreachable pending on the socket (e.g. the upstream
                # just went down) must not kill the whole relay: drop that flow.
                if kind == "up":
                    listen, client = info
                    flow = flows.pop(info, None)
                    if flow is not None:
                        sel.unregister(flow[0])
                        flow[0].close()
                    print(f"- {client[0]}:{client[1]} upstream refused, flow dropped", flush=True)
                continue
            except OSError:
                continue
            if kind == "listen":
                flow = flows.get((key.fileobj, addr))
                if flow is None:
                    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    up.connect((a.target, info))
                    sel.register(up, selectors.EVENT_READ, ("up", (key.fileobj, addr)))
                    flow = flows[(key.fileobj, addr)] = [up, 0]
                    print(f"+ {addr[0]}:{addr[1]} -> {info} ({len(flows)} flows)", flush=True)
                flow[1] = time.time()
                flow[0].send(data)
            else:
                listen, client = info
                flows[info][1] = time.time()
                listen.sendto(data, client)
        now = time.time()
        if now - swept > 10:
            swept = now
            for k, (up, seen) in list(flows.items()):
                if now - seen > IDLE_S:
                    sel.unregister(up)
                    up.close()
                    del flows[k]


if __name__ == "__main__":
    main()
