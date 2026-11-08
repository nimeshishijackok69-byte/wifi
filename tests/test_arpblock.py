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

    # Fix 2: target follows a DHCP IP change --------------------------------
    blocker._gateway_ip = "192.168.1.1"
    blocker._gateway_mac = gateway
    blocker._local_ip = "192.168.1.36"
    blocker._local_mac = me
    blocker._targets["E2:93:95:08:18:57"] = {"mac": "E2:93:95:08:18:57", "ip": "192.168.1.33"}
    blocker.refresh_targets({"E2:93:95:08:18:57": "192.168.1.50"})
    check("follows new IP", blocker.target_ip("E2:93:95:08:18:57") == "192.168.1.50")
    check("follow event logged", any("192.168.1.33" in e and "192.168.1.50" in e for e in blocker.drain_events()))

    # Fix 2: never adopt gateway / own IP -----------------------------------
    blocker.refresh_targets({"E2:93:95:08:18:57": "192.168.1.1"})
    check("refuses gateway IP", blocker.target_ip("E2:93:95:08:18:57") == "192.168.1.50")

    # Fix 2: unseen device stays blocked ------------------------------------
    blocker.refresh_targets({})
    check("empty scan keeps target", blocker.is_blocking("E2:93:95:08:18:57"))
    blocker.refresh_targets({"AA:BB:CC:DD:EE:FF": "192.168.1.60"})
    check("unrelated scan keeps target", blocker.target_ip("E2:93:95:08:18:57") == "192.168.1.50")

    # Fix 2: IP handed to another device -> release, don't block new owner --
    blocker.refresh_targets({"AA:BB:CC:DD:EE:FF": "192.168.1.50"})
    check("releases on takeover", not blocker.is_blocking("E2:93:95:08:18:57"))
    check("release event logged", any("stopped blocking" in e for e in blocker.drain_events()))
    blocker.stop()
    blocker._targets.clear()

    # Fix 4: add() proves the first send before claiming success -----------
    b2 = arpblock.ArpBlocker()
    real_readiness = arpblock.readiness
    arpblock.readiness = lambda iface=None: (True, "")
    b2._resolve_iface = lambda *a, **k: "TEST"
    sent: list = []
    b2._send = lambda pkts: sent.extend(pkts)
    started_threads = []
    real_start = b2._start_thread
    # run the real loop thread but with a fast interval via _stop waiting
    try:
        ok, msg = b2.add("E2:93:95:08:18:57", "192.168.1.33", iface, gateway)
        check("add succeeds with working send", ok is True, msg)
        check("add sent poison synchronously", len(sent) >= 2, str(len(sent)))
        check("add target registered", b2.is_blocking("E2:93:95:08:18:57"))
    finally:
        # a failing send must make add() fail and register nothing
        def boom(pkts):
            raise RuntimeError("no adapter")
        b2._send = boom
        ok, msg = b2.add("AA:BB:CC:DD:EE:FF", "192.168.1.60", iface, gateway)
        check("add fails when first send fails", ok is False and "Could not send" in msg, msg)
        check("failed add not registered", not b2.is_blocking("AA:BB:CC:DD:EE:FF"))
        b2.stop()
        b2._targets.clear()
        arpblock.readiness = real_readiness

    # Fix 4: remove->add race (last target removed, new one added) ---------
    b3 = arpblock.ArpBlocker()
    arpblock.readiness = lambda iface=None: (True, "")
    b3._resolve_iface = lambda *a, **k: "TEST"
    b3._send = lambda pkts: None
    try:
        b3.add("E2:93:95:08:18:57", "192.168.1.33", iface, gateway)
        check("remove() restores ok", b3.remove("E2:93:95:08:18:57") is True)
        ok, _msg = b3.add("AA:BB:CC:DD:EE:FF", "192.168.1.60", iface, gateway)
        check("re-add after remove succeeds", ok is True)
        check("re-added target blocking", b3.is_blocking("AA:BB:CC:DD:EE:FF"))
        import time as _t
        _t.sleep(0.2)
        check("thread still alive after re-add", b3.running is True)
    finally:
        b3.stop()
        b3._targets.clear()
        arpblock.readiness = real_readiness

    # Fix 4: restore retry + honest failure --------------------------------
    b4 = arpblock.ArpBlocker()
    b4._gateway_ip = "192.168.1.1"
    b4._gateway_mac = gateway
    b4._local_mac = me
    b4._iface_name = "TEST"
    calls = {"n": 0}
    def flaky_send(pkts):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise RuntimeError("flaky")
    b4._send = flaky_send
    check("restore succeeds after retries", b4._restore_one({"mac": "E2:93:95:08:18:57", "ip": "192.168.1.33"}) is True)
    def dead_send(pkts):
        raise RuntimeError("dead")
    b4._send = dead_send
    check("restore reports failure", b4._restore_one({"mac": "E2:93:95:08:18:57", "ip": "192.168.1.33"}) is False)
    check("restore failure event", any("Restore packets failed" in e for e in b4.drain_events()))
    b4.stop()

    # Regression: _resolve_iface must accept (dest_ip, local_ip) — refresh()
    # calls it with two args. The old test masked this with lambda *a.
    import inspect as _inspect
    params = list(_inspect.signature(arpblock.ArpBlocker._resolve_iface).parameters)
    check("_resolve_iface signature", len(params) >= 3, str(params))
    b5 = arpblock.ArpBlocker()
    try:
        result = b5._resolve_iface("192.168.1.1", "192.168.1.36")
        check("_resolve_iface 2-arg call", result is None or isinstance(result, str), str(result))
    except TypeError as exc:
        check("_resolve_iface 2-arg call", False, str(exc))
    # refresh() end-to-end with the REAL _resolve_iface (no *a mock)
    b5._gateway_ip, b5._gateway_mac, b5._local_mac, b5._iface_name = "192.168.1.1", gateway, me, "OLD"
    b5._targets["E2:93:95:08:18:57"] = {"mac": "E2:93:95:08:18:57", "ip": "192.168.1.33"}
    try:
        b5.refresh(iface, gateway)
        check("refresh with targets does not raise", True)
    except TypeError as exc:
        check("refresh with targets does not raise", False, str(exc))
    b5.stop()

    # Fix 9: retarget carries a block across MAC rotation -------------------
    b6 = arpblock.ArpBlocker()
    b6._gateway_ip, b6._local_ip = "192.168.1.1", "192.168.1.36"
    b6._targets["E2:93:95:08:18:57"] = {"mac": "E2:93:95:08:18:57", "ip": "192.168.1.33"}
    check("retarget ok", b6.retarget("E2:93:95:08:18:57", "AA:BB:CC:DD:EE:FF", "192.168.1.33") is True)
    check("retarget moved entry", not b6.is_blocking("E2:93:95:08:18:57") and b6.target_ip("AA:BB:CC:DD:EE:FF") == "192.168.1.33")
    check("retarget refuses gateway IP", b6.retarget("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66", "192.168.1.1") is False)
    b6.stop()

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL ARP TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
