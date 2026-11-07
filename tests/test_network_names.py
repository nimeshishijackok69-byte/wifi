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
