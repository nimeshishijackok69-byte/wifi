"""End-to-end test of the router adapter against the mock ONT."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mock_router import MockRouter  # noqa: E402
from netguard.router import HuaweiRouter, LoginError, RouterError  # noqa: E402

FAILS = []


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label + (f"  [{detail}]" if detail and not condition else ""))
    if not condition:
        FAILS.append(label)


def main() -> int:
    server = MockRouter().start()
    try:
        router = HuaweiRouter(server.url, timeout=5)

        # Wrong password is reported clearly.
        try:
            router.login("excitel", "wrong")
            check("reject bad password", False)
        except LoginError as exc:
            check("reject bad password", "password" in str(exc).lower(), str(exc))

        version = router.login("excitel", "admin@123")
        check("login", bool(version), version)

        clients = router.clients()
        macs = {c["mac"] for c in clients}
        check("client discovery", "C4:13:75:93:DD:29" in macs and len(clients) >= 3, str(macs))
        names = {c["mac"]: c["hostname"] for c in clients}
        check("client hostname", names.get("C4:13:75:93:DD:29") == "DESKTOP-IG27U9C", str(names))

        info = router.info()
        check("filter page found", info["filter_page"].endswith("macfilter.asp"), str(info))

        target = "16:4F:BD:EE:9C:3C"
        ok, msg = router.set_block(target, True)
        check("block", ok, msg)
        check("blocked list", target in router.blocked_macs(), str(router.blocked_macs()))

        ok, msg = router.set_block(target, False)
        check("unblock", ok, msg)
        check("unblocked list", target not in router.blocked_macs(), str(router.blocked_macs()))

        # Fix 3: relogin re-establishes the session with remembered creds.
        version = router.relogin()
        check("relogin", bool(version) and router.logged_in, version)
        check("blocked readable after relogin", router.blocked_macs() == set())

        # Fix 3: blocked_macs raises instead of silently returning set().
        orig = router._filter_page_html
        router._filter_page_html = lambda: (_ for _ in ()).throw(RouterError("link down"))
        try:
            router.blocked_macs()
            check("blocked_macs raises on failure", False)
        except RouterError:
            check("blocked_macs raises on failure", True)
        router._filter_page_html = orig

        # Fix 3: an unverifiable change is a FAILURE, not "applied".
        calls = {"n": 0}
        def flaky():
            calls["n"] += 1
            if calls["n"] >= 2:
                raise RouterError("link down")
            return orig()
        router._filter_page_html = flaky
        ok2, msg2 = router.set_block(target, True)
        router._filter_page_html = orig
        check("unverifiable is a failure", not ok2 and "verify" in msg2.lower(), msg2)
        # The (unverified) add really landed on the mock; clean up.
        check("unverified add did land", target in router.blocked_macs())
        router.set_block(target, False)

        # Fix 5: a full filter never overwrites an occupied slot.
        from netguard.router import parse_page
        full_html = (
            '<form action="/boaform/admin/formWlanMacFilter" method="post">'
            '<input type="text" name="macaddr1" value="AA:BB:CC:DD:EE:FF">'
            '<input type="text" name="macaddr2" value="11:22:33:44:55:66">'
            "</form>"
        )
        page = parse_page(full_html)
        ok5, msg5 = router._add_mac(page, target)
        check("full filter refuses overwrite", ok5 is False and "no empty slot" in msg5.lower(), msg5)
        # An already-blocked MAC is idempotent, not an error.
        dup_html = full_html.replace("AA:BB:CC:DD:EE:FF", target)
        ok6, msg6 = router._add_mac(parse_page(dup_html), target)
        check("already-blocked is idempotent", ok6 is True, msg6)
    finally:
        server.stop()

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
