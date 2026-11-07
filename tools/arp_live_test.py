"""Live check of the ARP blocker against an unused address.

Run as administrator.  Targets 192.168.1.254 (normally outside the DHCP pool)
with a fake MAC, so no real device is affected.  Proves the send loop,
the persistent socket and the restore path all work.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import arpblock, netinfo  # noqa: E402


def main() -> int:
    iface = netinfo.active_interface()
    gateway_mac = netinfo.gateway_mac(iface.gateway) if iface else ""
    print("iface:", iface)
    print("gateway mac:", gateway_mac)
    ok, message = arpblock.readiness(iface)
    print("ready:", ok, message)
    if not ok:
        return 1

    blocker = arpblock.ArpBlocker()
    ok, message = blocker.add("02:00:00:00:00:99", "192.168.1.254", iface, gateway_mac)
    print("add:", ok, message)
    if not ok:
        return 1

    time.sleep(4)
    print("running:", blocker.running)
    print("targets:", blocker.targets)
    print("last error:", blocker.last_error or "none")

    blocker.stop()
    time.sleep(1)
    print("stopped:", not blocker.running, "targets:", blocker.targets)
    print("LIVE TEST OK" if blocker.running is False else "LIVE TEST FAILED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
