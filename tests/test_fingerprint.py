"""Offline checks for the device-identification helpers."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import fingerprint  # noqa: E402

FAILS = []


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label + (f"  [{detail}]" if detail and not condition else ""))
    if not condition:
        FAILS.append(label)


def main() -> int:
    check("randomised MAC detected", fingerprint.is_randomized("E2:93:95:08:18:57"))
    check("randomised MAC 2", fingerprint.is_randomized("16:4F:BD:EE:9C:3C"))
    check("randomised MAC 3", fingerprint.is_randomized("56:C9:E9:15:AF:05"))
    check("normal Huawei MAC not randomised", not fingerprint.is_randomized("4C:AE:1C:21:30:29"))
    check("normal Apple MAC not randomised", not fingerprint.is_randomized("EC:65:49:12:34:56"))

    # Classification helpers with canned signals.
    check("camera keyword", fingerprint._contains("hikvision camera", fingerprint._CAMERA_WORDS))
    check("tv keyword", fingerprint._contains("bravia 4k", fingerprint._TV_WORDS))
    check("phone keyword", fingerprint._contains("iphone 15", fingerprint._PHONE_WORDS))
    check("printer keyword", fingerprint._contains("canon laserjet", fingerprint._PRINTER_WORDS))

    # mDNS parser: a single compressed PTR answer.
    packet = fingerprint._parse_mdns(_sample_packet())
    check("mDNS parser sample", packet == ["iPhone._airplay._tcp.local"], str(packet))

    # Cache round-trip through fingerprint_all.
    class FakeDevice:
        def __init__(self, ip, mac, hostname="", vendor=""):
            self.ip = ip
            self.mac = mac
            self.hostname = hostname
            self.vendor = vendor

    import time
    now = time.time()
    existing = {
        "E2:93:95:08:18:57": {
            "ip": "192.168.1.33",
            "guess": "Phone / tablet / laptop (random MAC)",
            "guess_category": "phone",
            "guess_confidence": "Low",
            "randomized": True,
            "guess_evidence": ["Randomised/private MAC"],
            "fingerprint_at": now,
            "last_seen": now,
        }
    }
    out = fingerprint.fingerprint_all(
        {"E2:93:95:08:18:57": FakeDevice("192.168.1.33", "E2:93:95:08:18:57")},
        existing=existing,
        skip_macs={"4C:AE:1C:21:30:29"},
        now=now,
    )
    check("cache reused", out["E2:93:95:08:18:57"].guess.startswith("Phone"), out["E2:93:95:08:18:57"].guess)

    # The same IP returning with a different MAC gets a note.
    moved = fingerprint.fingerprint_all(
        {"AA:BB:CC:DD:EE:FF": FakeDevice("192.168.1.33", "AA:BB:CC:DD:EE:FF")},
        existing=existing,
        now=now + 10,
    )
    note = " ".join(moved["AA:BB:CC:DD:EE:FF"].evidence)
    check("previous MAC noted", "E2:93:95:08:18:57" in note, note)

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL FINGERPRINT TESTS PASSED")
    return 1 if FAILS else 0


def _sample_packet() -> bytes:
    # header: id, flags, qd=1, an=1, ns=0, ar=0
    # question: _airplay._tcp.local A
    # answer: pointer to question name -> _airplay._tcp.local. PTR target iPhone._airplay._tcp.local
    header = b"\x10\x00\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00"
    qname = b"\x08_airplay\x04_tcp\x05local\x00"
    question = qname + b"\x00\xff\x00\x01"
    # answer name = C00C (offset 12), type PTR, class IN, ttl 120, rdlen 29
    answer = b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x78\x00\x1d" + b"\x06iPhone" + qname
    return header + question + answer


if __name__ == "__main__":
    sys.exit(main())
