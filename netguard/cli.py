"""Command line helpers - useful for testing the router connection.

    python -m netguard.cli scan
    python -m netguard.cli router --user excitel --password ****
    python -m netguard.cli pages  --user excitel --password ****
"""

from __future__ import annotations

import argparse
import sys
import time

from . import netinfo, scanner
from .oui import VendorDB
from .router import HuaweiRouter, LoginError
from .store import APP_DIR, Store


def cmd_scan(_args) -> int:
    iface = netinfo.active_interface()
    if not iface:
        print("No active network interface.")
        return 1
    print(f"Interface : {iface.name}")
    print(f"Local IP  : {iface.ip}/{iface.mask}")
    print(f"Gateway   : {iface.gateway}  mac={netinfo.gateway_mac(iface.gateway)}")
    print(f"Network   : {iface.network}\n")
    vendors = VendorDB(APP_DIR)
    start = time.time()
    devices = scanner.scan(iface, vendors)
    print(f"{'IP':<16}{'MAC':<20}{'VENDOR':<26}HOST")
    for mac, dev in sorted(devices.items(), key=lambda kv: tuple(int(p) for p in kv[1].ip.split(".")) if kv[1].ip else (999,)):
        print(f"{dev.ip:<16}{mac:<20}{(dev.vendor or '-')[:24]:<26}{dev.hostname}")
    print(f"\n{len(devices)} devices in {time.time() - start:.1f}s")
    return 0


def _login(args):
    url = args.url
    if not url:
        iface = netinfo.active_interface()
        url = f"http://{iface.gateway}" if iface and iface.gateway else "http://192.168.1.1"
    router = HuaweiRouter(url, timeout=10)
    print(f"Connecting to {url} as {args.user} ...")
    try:
        version = router.login(args.user, args.password)
    except LoginError as exc:
        print(f"LOGIN FAILED: {exc}")
        return None
    print(f"LOGGED IN. version={version}")
    return router


def cmd_router(args) -> int:
    router = _login(args)
    if not router:
        return 1
    print("info:", router.info())
    clients = router.clients()
    print(f"\n{len(clients)} clients:")
    for c in clients:
        print(f"  {c['mac']}  {c.get('ip', ''):<16} {c.get('hostname', '')}")
    print("\nblocked:", sorted(router.blocked_macs()))
    return 0


def cmd_pages(args) -> int:
    router = _login(args)
    if not router:
        return 1
    pages = router._crawl(["/html/ssmp/frame.asp", "/html/ssmp/index.asp", "/admin/main.asp"])
    for path, html in pages.items():
        print(f"--- {path}  ({len(html)} bytes)")
        text = " ".join(html.split())
        print("    " + text[:300])
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="netguard")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("scan").set_defaults(func=cmd_scan)

    for name, func in (("router", cmd_router), ("pages", cmd_pages)):
        p = sub.add_parser(name)
        p.add_argument("--url", default="")
        p.add_argument("--user", default="excitel")
        p.add_argument("--password", required=True)
        p.set_defaults(func=func)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
