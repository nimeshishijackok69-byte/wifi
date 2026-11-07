import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import netinfo, scanner  # noqa: E402
from netguard.oui import VendorDB
from netguard.store import APP_DIR

i = netinfo.active_interface()
v = VendorDB(APP_DIR)
d = scanner.scan(i, v, deep=True)

print(f"{len(d)} devices visible on {i.network} at " + time.strftime("%H:%M:%S"))
print()
print(f"{'IP':<16}{'MAC':<20}{'VENDOR':<22}HOST")
for mac, dev in sorted(d.items(), key=lambda kv: tuple(int(p) for p in kv[1].ip.split("."))):
    print(f"{dev.ip:<16}{mac:<20}{(dev.vendor or '-')[:20]:<22}{dev.hostname or '-'}")
print()
print("My PC MAC:", i.mac, "| Gateway MAC:", netinfo.gateway_mac(i.gateway))
