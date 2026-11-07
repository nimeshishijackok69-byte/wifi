"""Print likely-device guesses for every non-router, non-self device seen."""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import fingerprint, netinfo, scanner  # noqa: E402
from netguard.oui import VendorDB, normalize  # noqa: E402
from netguard.store import APP_DIR, Store  # noqa: E402


def main() -> int:
    iface = netinfo.active_interface()
    vendors = VendorDB(APP_DIR)
    devices = scanner.scan(iface, vendors)
    store = Store()
    fingerprints = fingerprint.fingerprint_all(
        devices,
        vendors,
        store.devices,
        skip_macs={normalize(iface.mac), normalize(netinfo.gateway_mac(iface.gateway))},
    )
    print(f"scanned {len(devices)} device(s) at {time.strftime('%H:%M:%S')}")
    for mac, dev in sorted(devices.items(), key=lambda item: item[1].ip):
        fp = fingerprints.get(mac)
        print()
        print(f"{dev.ip:<16} {mac}")
        if fp:
            print(f"  likely: {fp.guess} ({fp.confidence}, {fp.category})")
            for note in fp.evidence[:8]:
                print(f"  - {note}")
        else:
            print("  likely: (router/self)")

    # Save the identification so the GUI shows the same guesses.
    raw = {}
    for mac, dev in devices.items():
        fp = fingerprints.get(mac)
        raw[mac] = {
            "ip": dev.ip,
            "hostname": dev.hostname,
            "vendor": dev.vendor,
            "online": True,
            "source": "arp",
        }
        if fp:
            raw[mac].update(fp.as_dict())
    store.merge_scan(raw)
    return 0


if __name__ == "__main__":
    sys.exit(main())
