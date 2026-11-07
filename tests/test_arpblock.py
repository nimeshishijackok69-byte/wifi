"""Offline checks for the ARP blocker: safety guards and packet contents."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import arpblock  # noqa: E402
from netguard.netinfo import Interface  # noqa: E402

FAILS = []


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label + (f"  [{detail}]" if detail and not condition else ""))
    if not condition:
        FAILS.append(label)


def main() -> int:
    iface = Interface("Wi-Fi", "192.168.1.36", "255.255.255.0", "192.168.1.1",
                      "C4-13-75-93-DD-29", "Wi-Fi")
    gateway = "4C:AE:1C:21:30:29"
    me = "C4:13:75:93:DD:29"

    blocker = arpblock.ArpBlocker()

    ok, msg = blocker.add(me, "192.168.1.36", iface, gateway)
    check("refuse this computer", not ok and "this computer" in msg.lower(), msg)

    ok, msg = blocker.add(gateway, "192.168.1.1", iface, gateway)
    check("refuse the router", not ok and "router" in msg.lower(), msg)

    ok, msg = blocker.add("E2:93:95:08:18:57", "", iface, gateway)
    check("refuse device without IP", not ok and "ip" in msg.lower(), msg)

    ok, msg = blocker.add("E2:93:95:08:18:57", "192.168.1.33", iface, "")
    check("refuse unknown gateway MAC", not ok and "router" in msg.lower(), msg)

    # Frame contents ------------------------------------------------------
    captured: list = []
    original = blocker._send
    blocker._send = lambda pkts: captured.extend(pkts)
    try:
        blocker._gateway_ip = "192.168.1.1"
        blocker._gateway_mac = gateway
        blocker._local_mac = me
        blocker._iface_name = "TEST"
        blocker._poison({"mac": "E2:93:95:08:18:57", "ip": "192.168.1.33"},
                        blocker._gateway_ip, blocker._gateway_mac,
                        blocker._local_mac, blocker._iface_name)

        check("two forged replies", len(captured) == 2, str(len(captured)))
        to_target, to_gateway = captured
        check("target learns gateway is at us",
              to_target[0].dst.lower() == "e2:93:95:08:18:57"
              and to_target[1].op == 2
              and to_target[1].psrc == "192.168.1.1"
              and to_target[1].hwsrc.upper() == me.upper(),
              str(to_target.summary()))
        check("gateway learns target is at us",
              to_gateway[0].dst.lower() == gateway.lower()
              and to_gateway[1].op == 2
              and to_gateway[1].psrc == "192.168.1.33"
              and to_gateway[1].hwsrc.upper() == me.upper(),
              str(to_gateway.summary()))
    finally:
        blocker._send = original

    # Restore sends the true mappings back ---------------------------------
    captured.clear()
    blocker._send = lambda pkts: captured.extend(pkts)
    try:
        blocker._restore_one({"mac": "E2:93:95:08:18:57", "ip": "192.168.1.33"})
        check("restore sends frames", len(captured) >= 2, str(len(captured)))
        check("restore uses the real target MAC", captured[1][1].hwsrc.upper() == "E2:93:95:08:18:57",
              str(captured[1].summary()))
        check("restore uses the real gateway MAC", captured[0][1].hwsrc.upper() == gateway.upper(),
              str(captured[0].summary()))
    finally:
        blocker._send = original

    # Fix 1: health snapshot -------------------------------------------------
    blocker._targets.clear()
    blocker.stop()
    h = blocker.health()
    check("health idle", h["running"] is False and h["targets"] == 0, str(h))
    blocker._last_error = "boom"
    check("health surfaces error", blocker.health()["last_error"] == "boom")
    blocker.clear_error()
    check("clear_error", blocker.health()["last_error"] == "")

    # Fix 1: refresh adopts a changed gateway/interface ---------------------
    blocker._gateway_ip = "192.168.1.1"
    blocker._gateway_mac = gateway
    blocker._local_mac = me
    blocker._iface_name = "OLD"
    blocker._resolve_iface = lambda *a, **k: "NEW"
    changed = blocker.refresh(iface, gateway)
    check("refresh detects change", changed is True)
    check("refresh adopted iface", blocker._iface_name == "NEW")
    changed2 = blocker.refresh(iface, gateway)
    check("refresh no-op when unchanged", changed2 is False)
    blocker.stop()
    blocker._targets.clear()

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL ARP TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
