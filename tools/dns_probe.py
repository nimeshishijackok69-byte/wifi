import socket
import struct

def ptr_query(server, name):
    qid = 0x1234
    flags = 0x0100
    hdr = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    q = b""
    for part in name.rstrip(".").split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack("!HH", 12, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    try:
        s.sendto(hdr + q, (server, 53))
        data, _ = s.recvfrom(4096)
        return data
    except Exception as e:
        return None
    finally:
        s.close()

def parse(data):
    if not data or len(data) < 12:
        return None
    _, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    return qd, an, ns, ar, data[12:]

for ip in ["192.168.1.33","192.168.1.34","192.168.1.38","192.168.1.42","192.168.1.43","192.168.1.36"]:
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    data = ptr_query("192.168.1.1", rev)
    print(ip, parse(data))

# Also broadcast? try gateway as direct DNS server for .local names
for name in ["DESKTOP-IG27U9C.local", "unknown.local"]:
    data = ptr_query("192.168.1.1", name)
    print(name, parse(data))
