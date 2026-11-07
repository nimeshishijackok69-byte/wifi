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
    finally:
        app.destroy()
        server.stop()

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL GUI TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
