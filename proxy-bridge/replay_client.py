#!/usr/bin/env python3
"""Minimal RakNet+DST replay client: drives the live bridge+server through a real
mobile handshake (captured packets) up to the 0x86 server-listing, then validates the
listing the bridge returned (should be rewritten to mobile format, ~821B).

Not a full client — just enough to trigger + capture the listing without a phone."""
import socket, sys, time, json, struct

TARGET = (sys.argv[1] if len(sys.argv)>1 else "192.168.1.18", 11000)
SEQ = [bytes.fromhex(h) for h in json.load(open(sys.argv[2] if len(sys.argv)>2 else "/tmp/replay_seq.json"))]

def dgram_num(pkt):
    return pkt[1] | (pkt[2]<<8) | (pkt[3]<<16)

def make_ack(n):
    return b"\xc0\x00\x01\x01" + bytes([n & 0xff, (n>>8)&0xff, (n>>16)&0xff])

def inner_id(pkt):
    if pkt[:1]!=b"\x84" or len(pkt)<11: return None
    rb=pkt[4]; hdr=14 if rb==0x60 else (10 if rb==0x40 else 7)
    return pkt[hdr] if len(pkt)>hdr else None

s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("0.0.0.0",0)); s.settimeout(2.0)
print(f"[*] replay client {s.getsockname()} -> {TARGET}")

def drain(label,ack=True):
    got=[]
    while True:
        try: d,_=s.recvfrom(65535)
        except socket.timeout: break
        iid=inner_id(d)
        print(f"    <- len={len(d)} id=0x{d[0]:02x}" + (f" inner=0x{iid:02x}" if iid is not None else ""))
        got.append(d)
        if ack and d[:1]==b"\x84":
            s.sendto(make_ack(dgram_num(d)),TARGET)
        if len(d) in range(760,900) and (inner_id(d)==0x86):
            return got,d
    return got,None

listing=None
# indices in SEQ: 1=OpenConnReq1(0x05) 2=OpenConnReq2(0x07) 3=ConnReq(0x09) 5=NewIncoming(0x13) 6=0x00 7=0x91
plan=[("0x05 OpenConnReq1",1),("0x07 OpenConnReq2",2),("0x09 ConnReq",3),
      ("0x13 NewIncoming",5),("aux 0x00",6),("0x91 DST-handshake",7)]
for label,idx in plan:
    print(f"[>] send {label} ({len(SEQ[idx])}B)")
    s.sendto(SEQ[idx],TARGET)
    time.sleep(0.15)
    _,lst=drain(label)
    if lst is not None:
        listing=lst; print(f"[+] GOT LISTING len={len(lst)}"); break

# a couple extra drains in case listing lags after 0x91
for _ in range(3):
    if listing: break
    _,lst=drain("post")
    if lst: listing=lst

if listing is None:
    print("[-] no 0x86 listing received"); sys.exit(2)

open("/tmp/live_listing.bin","wb").write(listing)
print(f"[+] saved /tmp/live_listing.bin ({len(listing)}B)")
# quick checks: is it the REWRITTEN (mobile) form?
p=listing[14:]  # payload after reliability header (0x60 -> 14B)
print(f"    payload[0]=0x{p[0]:02x} (expect 0x86)")
print(f"    platform 64 (03d0df4d00000040): {bytes.fromhex('03d0df4d00000040') in listing}")
print(f"    platform  1 (03d0df4d00000001): {bytes.fromhex('03d0df4d00000001') in listing}")
print(f"    mobile owner OU_ present: {b'OU_' in listing}")
print(f"    bitLength field=0x{listing[5]:02x}{listing[6]:02x} = {(listing[5]<<8)|listing[6]} bits = {((listing[5]<<8)|listing[6])//8}B ; actual payload={len(listing)-14}B")
