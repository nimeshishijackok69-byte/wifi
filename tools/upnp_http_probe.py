import os
import socket
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard.netinfo import active_interface

iface = active_interface()
gw = iface.gateway
print("gw", gw)

sts = ["upnp:rootdevice", "urn:schemas-upnp-org:service:WANIPConnection:1", "ssdp:all"]
for st in sts:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    msg = f'M-SEARCH * HTTP/1.1\r\nHOST: {gw}:1900\r\nMAN: "ns=01"\r\nMX: 2\r\nST: {st}\r\n\r\n'.encode()
    try:
        s.sendto(msg, (gw, 1900))
        print("sent", st)
        while True:
            data, addr = s.recvfrom(8192)
            print("resp", addr, data.decode(errors="ignore")[:500])
    except Exception as e:
        print("fail", st, e)
    s.close()

paths = [
    "/rootDesc.xml", "/rootdesc.xml", "/des/root.xml", "/desc/root.xml",
    "/UDAP/dev.xml", "/upnp/desc/root.xml", "/upnp/rootDesc.xml",
    "/:1900/rootDesc.xml", "/rootDesc.xml?123", "/SSDP/rootDesc.xml",
    "/upnp/IGD.xml", "/etc/udhcpd_upnp.xml", "/gena/rootDesc.xml",
    "/media/rpc.xml", "/serviceDesc.xml", "/description.xml",
    "/pnp/rootDesc.xml", "/root.xml", "/upnp.xml",
]
for p in paths:
    for port in ("", ":1900", ":5000", ":8080", ":80"):
        url = f"http://{gw}{port}{p}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuard/1.0"})
            with urllib.request.urlopen(req, timeout=2) as r:
                body = r.read().decode(errors="ignore")
                if "upnp" in body.lower() or "wanipconnection" in body.lower() or "device" in body.lower() or "<" in body[:20]:
                    print(url, r.status, body[:400])
        except Exception:
            pass
