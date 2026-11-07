"""Checks for the gateway PTR (reverse-DNS) name lookup."""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import netinfo  # noqa: E402

FAILS = []


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label + (f"  [{detail}]" if detail and not condition else ""))
    if not condition:
        FAILS.append(label)


def sample_packet(target: str) -> bytes:
    """One-question DNS reply naming the host (no compression tricks)."""
    def labels(name: str) -> bytes:
        out = b""
        for part in name.rstrip(".").split("."):
            out += bytes([len(part)]) + part.encode()
        return out + b"\x00"

    header = struct.pack("!HHHHHH", 0x1234, 0x8500, 1, 1, 0, 0)
    question = labels("33.1.168.192.in-addr.arpa") + struct.pack("!HH", 12, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 0, 0) + labels(target)
    return header + question + answer


def main() -> int:
    packet = sample_packet("OPPO-A15.hgu_lan")
    name, _ = netinfo._dns_name(packet, 12)
    check("DNS name decode", name == "33.1.168.192.in-addr.arpa", name)

    # Fix 7: non-English ipconfig labels still parse (values are universal).
    german = (
        "Drahtloser LAN-Adapter Wi-Fi:\n"
        "   IPv4-Adresse  . . . : 192.168.1.36\n"
        "   Subnetzmaske  . . . : 255.255.255.0\n"
        "   Standardgateway . . : 192.168.1.1\n"
        "   Physische Adresse . : C4-13-75-93-DD-29\n"
    )
    ifaces = netinfo.list_interfaces(german)
    check("locale-free parse finds iface", len(ifaces) == 1 and ifaces[0].ip == "192.168.1.36", str(ifaces))
    check("locale-free parse finds gateway+mac", bool(ifaces) and ifaces[0].gateway == "192.168.1.1" and "C4" in ifaces[0].mac, str(ifaces[0] if ifaces else ""))
    # prefer-by-MAC beats the Wi-Fi heuristic
    two = german + (
        "\nEthernet-Adapter Ethernet:\n"
        "   IPv4 Address. . . : 10.0.0.5\n"
        "   Subnet Mask . . . : 255.255.255.0\n"
        "   Default Gateway . : 10.0.0.1\n"
        "   Physical Address. : AA-BB-CC-DD-EE-FF\n"
    )
    picked = netinfo.active_interface(prefer="AA:BB:CC:DD:EE:FF", text=two)
    check("prefer wins over heuristic", picked is not None and picked.ip == "10.0.0.5", str(picked))
    check("iface_key is MAC", netinfo.iface_key(picked) == "AA:BB:CC:DD:EE:FF")

    # Live check: the router answers PTR queries for its own DHCP clients.
    iface = netinfo.active_interface()
    if iface:
        names = netinfo.gateway_reverse_dns_many(["192.168.1.33", "192.168.1.34"], iface.gateway)
        check("gateway PTR names", set(names) == {"192.168.1.33", "192.168.1.34"}, str(names))
        for ip, name in names.items():
            print(f"  {ip}: {name}")

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL NETWORK-NAME TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
