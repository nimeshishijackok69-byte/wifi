"""Harmless check that NetGuard can send raw frames on this PC.

Run it as administrator (that is what NetGuard needs).  It only
- asks the router to identify itself with a normal ARP request, and
- sends two forged replies about an unused address.

No real device is touched.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import arpblock, netinfo  # noqa: E402


def main() -> int:
    iface = netinfo.active_interface()
    print("adapter :", iface)
    print("admin   :", arpblock.is_admin())
    print("npcap   :", arpblock.npcap_installed())
    print("scapy   :", arpblock.scapy_available())
    if not iface:
        print("FAIL no adapter")
        return 1

    from scapy.all import ARP, Ether, conf, sendp, srp

    conf.use_pcap = True
    device = conf.route.route(iface.gateway or iface.ip)[0]
    print("device  :", device)

    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=iface.gateway),
            iface=device, timeout=3, verbose=False,
        )
    except Exception as exc:
        print("FAIL send/receive:", exc)
        return 1

    if not answered:
        print("FAIL the router did not answer an ARP request")
        return 1
    reply = answered[0][1]
    print("router replied:", reply.psrc, reply.hwsrc)

    # One gratuitous ARP about a reserved TEST-NET address (RFC 5737).
    # No device in this LAN can be affected by it.
    my_mac = iface.mac.replace("-", ":").upper()
    try:
        sendp(
            Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac)
            / ARP(op=2, hwsrc=my_mac, psrc="198.51.100.250",
                  hwdst="ff:ff:ff:ff:ff:ff", pdst="198.51.100.250"),
            iface=device, verbose=False,
        )
    except Exception as exc:
        print("FAIL forged send:", exc)
        return 1

    print("SEND OK", time.strftime("%H:%M:%S"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
