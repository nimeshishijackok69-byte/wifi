"""MAC address vendor lookup.

Uses a small built-in table first (works offline and instantly), then an
optional on-disk cache of the full IEEE OUI registry which is downloaded once
in the background the first time the app runs with internet access.
"""

from __future__ import annotations

import csv
import io
import os
import threading
import urllib.request

# A compact set of prefixes covering the devices found in typical homes.
BUILTIN = {
    "000C29": "VMware",
    "00155D": "Microsoft (Hyper-V)",
    "001A11": "Google",
    "001B63": "Apple",
    "001C42": "Parallels",
    "001E52": "Apple",
    "0021E9": "Apple",
    "0023DF": "Apple",
    "002436": "Apple",
    "0025BC": "Apple",
    "002608": "Apple",
    "0026B0": "Apple",
    "00306E": "Hewlett Packard",
    "0050F2": "Microsoft",
    "005056": "VMware",
    "00A0C9": "Intel",
    "00E04C": "Realtek",
    "00E0FC": "Huawei",
    "041E64": "Apple",
    "04421A": "ASUSTek",
    "04D9F5": "ASUSTek",
    "08606E": "ASUSTek",
    "0C4DE9": "Apple",
    "0C8268": "Tenda",
    "0CD746": "Apple",
    "101F74": "Hewlett Packard",
    "10C37B": "ASUSTek",
    "14CC20": "TP-Link",
    "18B430": "Nest Labs",
    "1C1AC0": "Apple",
    "1C5F2B": "D-Link",
    "20A7F9": "Samsung",
    "24A43C": "Ubiquiti",
    "24F5A2": "Belkin",
    "28CFE9": "Apple",
    "2C3033": "NETGEAR",
    "2CAE2B": "Samsung",
    "30B5C2": "TP-Link",
    "34CE00": "Xiaomi",
    "3C2EFF": "Apple",
    "3C5A37": "Samsung",
    "3CAA3F": "iRobot",
    "3CB87A": "Huawei",
    "40B076": "ASUSTek",
    "44D9E7": "Ubiquiti",
    "48A6B8": "Sonos",
    "4CAE1C": "Huawei",
    "50F0D3": "Samsung",
    "50F14A": "Xiaomi",
    "54A050": "ASUSTek",
    "5C514F": "Intel",
    "5CAAFD": "Sonos",
    "60A4D0": "Samsung",
    "641666": "Nest Labs",
    "64B473": "Xiaomi",
    "68C63A": "Espressif",
    "6C40C6": "Cisco",
    "70EE50": "Belkin",
    "74DA38": "Edimax",
    "78D6F0": "Samsung",
    "7C11CB": "Huawei",
    "7CDFA1": "Espressif",
    "801F02": "Edimax",
    "803773": "NETGEAR",
    "84D47E": "Aruba",
    "8C8590": "Apple",
    "90A2DA": "Amazon",
    "94B10A": "Samsung",
    "98DED0": "TP-Link",
    "A020A6": "Espressif",
    "A4C138": "Amazon",
    "A4CF12": "Espressif",
    "AC63BE": "Amazon",
    "B0BE76": "TP-Link",
    "B827EB": "Raspberry Pi",
    "B8E937": "Apple",
    "BC1485": "Samsung",
    "C05627": "Belkin",
    "C0EEFB": "Huawei",
    "C46E1F": "TP-Link",
    "C80E14": "ASUSTek",
    "CC2D1B": "Google",
    "D052A8": "NETGEAR",
    "D0BE2C": "Cisco",
    "D4F547": "Google",
    "D850E6": "Amazon",
    "D8B6B7": "Espressif",
    "DC4F22": "Espressif",
    "E43A6E": "Shenzhen (IoT)",
    "E45F01": "Raspberry Pi",
    "E4956E": "TP-Link",
    "E4F042": "Google",
    "E8162B": "Huawei",
    "E8DE27": "TP-Link",
    "ECFA5C": "Xiaomi",
    "F008D1": "Espressif",
    "F01898": "Apple",
    "F0B429": "Xiaomi",
    "F4F5D8": "Samsung",
    "F8FFC2": "Apple",
    "FC9D05": "Realtek",
}

_IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_LOCAL_NAMES = {"Realtek", "Intel", "Espressif", "Shenzhen (IoT)"}


class VendorDB:
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self._file = os.path.join(cache_dir, "oui.csv")
        self._map: dict[str, str] = {}
        self._lock = threading.Lock()
        self._load_cache()
        if not self._map:
            threading.Thread(target=self._download, daemon=True).start()

    # -- public -----------------------------------------------------------
    def lookup(self, mac: str) -> str:
        prefix = normalize(mac).replace(":", "")[:6].upper()
        with self._lock:
            name = self._map.get(prefix)
        if name:
            return name
        return BUILTIN.get(prefix, "")

    # -- internal ---------------------------------------------------------
    def _load_cache(self) -> None:
        try:
            if not os.path.exists(self._file):
                return
            with open(self._file, "r", encoding="utf-8", errors="ignore", newline="") as fh:
                reader = csv.reader(fh)
                next(reader, None)
                for row in reader:
                    if len(row) >= 3 and len(row[1]) == 6:
                        self._map[row[1].upper()] = _clean(row[2])
        except Exception:
            self._map = {}

    def _download(self) -> None:
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            req = urllib.request.Request(_IEEE_URL, headers={"User-Agent": "NetGuard/1.0"})
            with urllib.request.urlopen(req, timeout=25) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
            if len(raw) < 500_000:
                return
            parsed: dict[str, str] = {}
            for row in csv.reader(io.StringIO(raw)):
                if len(row) >= 3 and len(row[1]) == 6:
                    parsed[row[1].upper()] = _clean(row[2])
            if len(parsed) < 1000:
                return
            with open(self._file, "w", encoding="utf-8", newline="") as fh:
                fh.write(raw)
            with self._lock:
                self._map = parsed
        except Exception:
            pass


def _clean(name: str) -> str:
    name = " ".join(name.split())
    for suffix in (" Co.,Ltd.", " Co., Ltd.", " CO.,LTD.", " Ltd.", " Inc.", " GmbH"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    return name.strip(" ,")


def normalize(mac: str) -> str:
    """Return a MAC as AA:BB:CC:DD:EE:FF (upper case, colon separated)."""
    hexonly = "".join(ch for ch in str(mac) if ch in "0123456789abcdefABCDEF")
    if len(hexonly) < 12:
        return str(mac).upper()
    hexonly = hexonly[:12].upper()
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


def is_unicast(mac: str) -> bool:
    try:
        first = int(normalize(mac).split(":")[0], 16)
    except Exception:
        return False
    return not (first & 1)
