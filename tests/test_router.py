"""End-to-end test of the router adapter against the mock ONT."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mock_router import MockRouter  # noqa: E402
from netguard.router import HuaweiRouter, LoginError  # noqa: E402

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
    finally:
        server.stop()

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
