"""GUI-level test: connect to the mock router, scan, block, unblock.

Uses a temporary APPDATA so the real settings/inventory are untouched.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

temp = tempfile.mkdtemp(prefix="netguard-test-")
os.environ["APPDATA"] = temp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mock_router import MockRouter  # noqa: E402

import netguard.app as appmod  # noqa: E402
from netguard.store import Store  # noqa: E402

FAILS = []


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label + (f"  [{detail}]" if detail and not condition else ""))
    if not condition:
        FAILS.append(label)


def check_aliases() -> None:
    """Fix 9: pure alias detection (no GUI needed)."""
    devices = {
        "E2:93:95:08:18:57": {"ip": "192.168.1.33", "hostname": "POCO-C55", "blocked": True},
        "4C:AE:1C:21:30:29": {"ip": "192.168.1.1", "hostname": "Router", "blocked": False},
    }
    # Rotated phone: new randomised MAC, same IP + hostname.
    raw = {
        "AA:BB:CC:DD:EE:FF": {"ip": "192.168.1.33", "hostname": "POCO-C55"},
        "4C:AE:1C:21:30:29": {"ip": "192.168.1.1", "hostname": "Router"},
    }
    out = appmod.find_mac_aliases(devices, raw, {"E2:93:95:08:18:57"}, set())
    check("alias detected on rotation", len(out) == 1 and out[0][1] == "AA:BB:CC:DD:EE:FF", str(out))
    # Different hostname -> not an alias (could be a takeover).
    raw2 = {"AA:BB:CC:DD:EE:FF": {"ip": "192.168.1.33", "hostname": "Someone-Else"}}
    out2 = appmod.find_mac_aliases(devices, raw2, {"E2:93:95:08:18:57"}, set())
    check("alias refused on hostname mismatch", out2 == [], str(out2))
    # Still-online old MAC -> not an alias.
    raw3 = {"E2:93:95:08:18:57": {"ip": "192.168.1.33", "hostname": "POCO-C55"},
            "AA:BB:CC:DD:EE:FF": {"ip": "192.168.1.33", "hostname": "POCO-C55"}}
    out3 = appmod.find_mac_aliases(devices, raw3, {"E2:93:95:08:18:57"}, set())
    check("no alias while old MAC online", out3 == [], str(out3))


def pump(app, seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        app.update()
        time.sleep(0.03)


def wait_for(app, predicate, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        app.update()
        if predicate():
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    check_aliases()
    appmod.messagebox.askyesno = lambda *a, **k: True
    appmod.messagebox.showerror = lambda *a, **k: print("  [dialog]", a[1] if len(a) > 1 else a)
    appmod.messagebox.showinfo = lambda *a, **k: None

    server = MockRouter().start()
    app = appmod.NetGuardApp()
    app.withdraw()
    pump(app, 2.5)

    try:
        app.connect_router(server.url, "excitel", "admin@123", None)
        check("gui connect", wait_for(app, lambda: app.router_state == "connected", 6), app.router_state)

        # The startup scan (from _first_run) may still be running when we
        # connect and start_scan() then no-ops. Retry until a scan that ran
        # *after* connect lists the mock device (pre-existing race, exposed
        # when the live LAN fingerprint probes are slow).
        target = "16:4F:BD:EE:9C:3C"
        listed = False
        for _attempt in range(4):
            app.start_scan(True)
            check("gui scan finishes", wait_for(app, lambda: not app.scanning, 15))
            pump(app, 0.5)
            if target in app.rows:
                listed = True
                break
        check("mock device listed", listed, str(list(app.rows))[:200])

        app.tree.selection_set(target)
        app._act_block(False)
        check("gui block", wait_for(app, lambda: Store().record(target).get("blocked") is True, 8))
        check("gui row marked blocked", app.rows[target].blocked)

        app.tree.selection_set(target)
        app._act_block(True)
        check("gui unblock", wait_for(app, lambda: Store().record(target).get("blocked") is False, 8))

        # Fix 12: the dialog must construct, and a failed login must not
        # overwrite the last known-good saved password.
        seed = Store()
        seed.config["router_url"] = server.url
        seed.config["username"] = "excitel"
        seed.config["remember_password"] = True
        seed.password = "admin@123"
        seed.save_config()
        app.store.load()
        dialog = appmod.SettingsDialog(app)
        check("settings dialog constructs", dialog is not None)
        dialog.pwd.delete(0, "end")
        dialog.pwd.insert(0, "admin@124")
        dialog.save_and_test()
        failed = wait_for(app, lambda: app.router_state == "failed", 10)
        check("failed login keeps good stored password", failed and Store().password == "admin@123")
        dialog.destroy()
    finally:
        app.destroy()
        server.stop()

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL GUI TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
