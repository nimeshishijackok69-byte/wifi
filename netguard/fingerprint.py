"""Best-effort device identification for the LAN inventory.

A MAC address only tells us the vendor when the manufacturer assigned it.
Phones, tablets and laptops increasingly use *randomised* (locally
administered) MAC addresses specifically so they cannot be tracked by MAC -
in that case the vendor field becomes useless.  This module therefore adds
passive-looking, low-traffic clues:

* whether the address is locally assigned (randomised) or global,
* the router/DHCP or NetBIOS name, if any,
* open ports (SMB, RTSP, SSH, web …),
* the web server header / page title,
* UPnP/SSDP identification (TVs, media servers, cameras),
* mDNS service names (AirPlay, iPhone, printer, HomeKit, …).

Nothing is sent on behalf of the target and no credentials are used.  The
guesses are deliberately labelled as *likely* - the UI always shows why.
"""

from __future__ import annotations

import http.client
import re
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import netinfo
from .oui import normalize

# Ports we touch, each with a short timeout.  80/443 cover web/admin pages,
# 445 is Windows/NAS file sharing, 554/8554 are camera/media streams,
# 22/23 are Linux/embedded devices, 8080/8000/9000 are IoT apps and prints.
_PROBE_PORTS = (80, 443, 22, 23, 445, 554, 8000, 8080, 8554, 9000, 38080)

_CACHE_SECONDS = 300

_PHONE_WORDS = (
    "iphone", "ipad", "android", "oneplus", "redmi", "poco", "galaxy",
    "pixel", "xiaomi", "oppo", "vivo", "realme", "motorola", "nokia",
    "honor", "infinix", "tecno", "phone",
)
_LAPTOP_WORDS = (
    "macbook", "thinkpad", "ideapad", "vivobook", "surface", "laptop",
    "notebook", "desktop-", "pc-", "windows", "dell", "lenovo",
)
_TV_WORDS = (
    "tv", "bravia", "firetv", "fire tv", "chromecast", "roku", "appletv",
    "apple tv", "hisense", "tcl", "dlna", "upnp", "google tv", "android tv",
)
_CAMERA_WORDS = (
    "camera", "cam", "doorbell", "tapo", "wyze", "arlo", "hikvision",
    "dahua", "reolink", "imou", "ezviz", "eufy", "ring", "blink", "yi",
    "mi home", "creality", "ipcam",
)
_PRINTER_WORDS = ("printer", "laserjet", "canon", "epson", "brother", "deskjet")
_SPEAKER_WORDS = (
    "echo", "alexa", "google home", "nest", "homepod", "sonos", "speaker",
    "soundbar", "google nest",
)
_CONSOLE_WORDS = (
    "playstation", "ps5", "ps4", "xbox", "nintendo", "switch", "console",
)
_IOT_WORDS = (
    "esp32", "esp8266", "tuya", "sonoff", "shelly", "smart plug",
    "smart bulb", "aqara", "homekit", "matter", "zigbee", "sensor",
)
_NAS_WORDS = ("nas", "synology", "qnap", "asustor", "truenas", "unraid", "openmediavault")
_ROUTER_WORDS = (
    "router", "gateway", "access point", "onu", "ont", "mesh", "extender",
    "repeater", "fiberhub", "wifi",
)


@dataclass
class Fingerprint:
    guess: str = "Unknown device"
    category: str = "device"
    confidence: str = "Low"
    randomized: bool = False
    evidence: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "guess": self.guess,
            "guess_category": self.category,
            "guess_confidence": self.confidence,
            "randomized": self.randomized,
            "guess_evidence": list(self.evidence),
            "fingerprint_at": time.time(),
        }


# ---------------------------------------------------------------------------
# Randomised MAC detection
# ---------------------------------------------------------------------------
def is_randomized(mac: str) -> bool:
    """True for locally administered addresses (the privacy bit is set)."""
    try:
        first = int(normalize(mac).split(":")[0], 16)
    except Exception:
        return False
    return bool(first & 0b10)


# ---------------------------------------------------------------------------
# Probes (all best-effort, all bounded)
# ---------------------------------------------------------------------------
def _open_ports(ip: str) -> list[int]:
    def probe(port: int) -> int | None:
        try:
            with socket.create_connection((ip, port), timeout=0.12) as sock:
                return port
        except Exception:
            return None

    if not ip:
        return []
    with ThreadPoolExecutor(max_workers=len(_PROBE_PORTS)) as pool:
        return sorted(p for p in pool.map(probe, _PROBE_PORTS) if p)


def _http_fingerprint(ip: str, ports: list[int]) -> list[str]:
    notes: list[str] = []
    for port in (80, 8080, 8000):
        if port not in ports:
            continue
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=0.6)
            conn.request("GET", "/", headers={"User-Agent": "NetGuard/1.0"})
            resp = conn.getresponse()
            server = resp.getheader("Server", "").strip()
            body = resp.read(8192).decode("utf-8", errors="ignore")
            conn.close()
            if server:
                notes.append(f"Web server: {server}")
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if title_match:
                title = " ".join(title_match.group(1).split()).strip()
                if title:
                    notes.append(f'Web title: "{title[:80]}"')
            if notes:
                break
        except Exception:
            continue
    return notes


def _ssdp(ip: str) -> list[str]:
    notes: list[str] = []
    query = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        'ST: ssdp:all\r\n'
        'MAN: "ns=01"\r\n'
        "MX: 1\r\n\r\n"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.6)
            sock.sendto(query.encode(), (ip, 1900))
            data, _ = sock.recvfrom(4096)
            text = data.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                key, _, value = line.partition(":")
                if key.strip().lower() in ("server", "x-user-agent", "user-agent") and value.strip():
                    notes.append(f"UPnP: {value.strip()}")
    except Exception:
        pass
    return notes


def _read_name(packet: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 8 or offset >= len(packet):
        return "", offset
    labels: list[str] = []
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                return ".".join(labels), offset + 2
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            target, _ = _read_name(packet, pointer, depth + 1)
            if target:
                labels.append(target)
            return ".".join(labels), offset + 2
        if length & 0xC0:
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(labels), offset


def _parse_mdns(packet: bytes) -> list[str]:
    out: list[str] = []
    if len(packet) < 12:
        return out
    try:
        _id, _flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet, 0)
        offset = 12
        for _ in range(qd):
            _name, offset = _read_name(packet, offset)
            offset += 4
        for _ in range(an + ns + ar):
            name, offset = _read_name(packet, offset)
            if offset + 10 > len(packet):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", packet, offset)
            offset += 10
            end = offset + rdlen
            if end > len(packet) + 4:
                break
            rdata = b""
            try:
                if rtype == 12:  # PTR target
                    rdata, _ = _read_name(packet, offset)
                elif rtype == 33:  # SRV target
                    if offset + 6 < len(packet):
                        rdata, _ = _read_name(packet, offset + 6)
                elif rtype == 16:  # TXT strings
                    pos = offset
                    strings: list[str] = []
                    while pos < end:
                        size = packet[pos]
                        pos += 1
                        strings.append(packet[pos : pos + size].decode("utf-8", errors="ignore"))
                        pos += size
                    rdata = " ".join(s for s in strings if s)
                elif rtype == 1 and rdlen == 4:
                    rdata = socket.inet_ntoa(packet[offset:end])
            except Exception:
                rdata = ""
            if rdata:
                out.append(rdata)
            offset = end
    except Exception:
        pass
    return out


def _mdns(ip: str) -> list[str]:
    records: list[str] = []
    queries = (
        "_services._dns-sd._udp.local.",
        "_http._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_sftp-ssh._tcp.local.",
        "_ipp._tcp.local.",
        "_homekit-s accessory._tcp.local.",
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            for i, qname in enumerate(queries):
                labels = b""
                for part in qname.rstrip(".").split("."):
                    labels += bytes([len(part)]) + part.encode()
                packet = struct.pack("!HHHHHH", 0x1000 + i, 0, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 255, 1)
                try:
                    sock.sendto(packet, (ip, 5353))
                except Exception:
                    break
            seen: set[str] = set()
            while True:
                try:
                    packet, _ = sock.recvfrom(8192)
                except Exception:
                    break
                for record in _parse_mdns(packet):
                    record = " ".join(record.split()).strip()
                    if record and record not in seen:
                        seen.add(record)
                        records.append(record)
    except Exception:
        pass
    return records


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def _contains(text: str, words: tuple[str, ...]) -> bool:
    return any(word in text for word in words)


def guess(ip: str, mac: str, vendor: str = "", hostname: str = "") -> Fingerprint:
    mac = normalize(mac)
    randomized = is_randomized(mac)
    evidence: list[str] = []
    notes: list[str] = []

    if randomized:
        evidence.append("Randomised/private MAC - vendor and brand are hidden by design")
    elif vendor:
        evidence.append(f"MAC vendor: {vendor}")
    else:
        evidence.append("MAC vendor not in the known registry")

    ports = _open_ports(ip)
    if ports:
        evidence.append("Open ports: " + ", ".join(str(p) for p in ports))
    else:
        evidence.append("No common services answered")

    try:
        nb_name = netinfo.netbios_name(ip, timeout=0.6)
    except Exception:
        nb_name = ""
    if nb_name and nb_name.lower() != hostname.lower():
        notes.append(f"NetBIOS name: {nb_name}")

    http_notes = _http_fingerprint(ip, ports)
    notes.extend(http_notes)
    ssdp_notes = _ssdp(ip)
    notes.extend(ssdp_notes)
    mdns_records = _mdns(ip)
    if mdns_records:
        notes.append("mDNS: " + ", ".join(mdns_records[:5]))
    evidence.extend(notes)

    all_text = " ".join(
        [hostname, vendor, nb_name, " ".join(notes), " ".join(mdns_records)]
    ).lower()

    # Strong named hints first.
    if _contains(all_text, _PHONE_WORDS):
        label = "iPhone" if "iphone" in all_text else "iPad" if "ipad" in all_text else "Phone / Android"
        return Fingerprint(label, "phone", "High", randomized, evidence)
    if _contains(all_text, _LAPTOP_WORDS):
        return Fingerprint("Laptop / computer", "laptop", "High", randomized, evidence)
    if _contains(all_text, _CAMERA_WORDS) or 8554 in ports:
        return Fingerprint("IP camera", "camera", "High" if _contains(all_text, _CAMERA_WORDS) else "Medium", randomized, evidence)
    if 554 in ports and not _contains(all_text, _TV_WORDS):
        return Fingerprint("IP camera / media streamer", "camera", "Medium", randomized, evidence)
    if _contains(all_text, _NAS_WORDS) or (445 in ports and _contains(all_text, ("smb", "samba", "shares"))):
        return Fingerprint("NAS / file server", "device", "Medium", randomized, evidence)
    if _contains(all_text, _PRINTER_WORDS):
        return Fingerprint("Printer", "printer", "High", randomized, evidence)
    if _contains(all_text, _SPEAKER_WORDS):
        return Fingerprint("Smart speaker / soundbar", "speaker", "High", randomized, evidence)
    if _contains(all_text, _CONSOLE_WORDS):
        return Fingerprint("Game console", "console", "High", randomized, evidence)
    if _contains(all_text, _TV_WORDS):
        return Fingerprint("TV / streaming device", "tv", "High", randomized, evidence)
    if _contains(all_text, _IOT_WORDS):
        return Fingerprint("Smart home / IoT device", "iot", "Medium", randomized, evidence)
    if _contains(all_text, _ROUTER_WORDS) or 1900 in ports or "boa" in all_text:
        return Fingerprint("Router / access point", "router", "Medium", randomized, evidence)

    if 445 in ports:
        return Fingerprint("Windows computer or NAS", "laptop", "Medium", randomized, evidence)
    if 22 in ports and 80 in ports:
        return Fingerprint("Linux / embedded device", "iot", "Medium", randomized, evidence)

    # Fall back to the MAC story.
    if randomized:
        if not ports:
            return Fingerprint(
                "Phone/laptop (random MAC)", "phone", "Low",
                randomized, evidence,
            )
        return Fingerprint(
            "Phone/laptop (random MAC)", "phone", "Low",
            randomized, evidence,
        )
    if vendor:
        category = "device"
        if vendor.lower() in ("apple", "samsung", "google", "amazon"):
            category = "phone"
        elif vendor.lower() in ("hikvision", "dahua", "reolink"):
            category = "camera"
        return Fingerprint(f"{vendor} device", category, "Low", randomized, evidence)

    return Fingerprint("Unknown device", "device", "Low", randomized, evidence)


def fingerprint_all(
    devices: dict,
    vendors=None,
    existing: dict | None = None,
    skip_macs: set[str] | None = None,
    now: float | None = None,
) -> dict[str, Fingerprint]:
    """Devices maps MAC -> object with ip/hostname/vendor. Returns MAC -> Fingerprint."""
    existing = existing or {}
    skip = {normalize(m) for m in (skip_macs or set()) if m}
    now = now or time.time()
    results: dict[str, Fingerprint] = {}

    # Index previous records by IP so a randomised-MAC neighbour can be
    # recognised when its address changes between scans.
    by_ip: dict[str, tuple[str, dict]] = {}
    for old_mac, rec in existing.items():
        old_ip = rec.get("ip") if isinstance(rec, dict) else ""
        if old_ip:
            by_ip.setdefault(old_ip, (normalize(old_mac), rec if isinstance(rec, dict) else {}))

    work: list[str] = []

    def from_cache(mac: str) -> Fingerprint | None:
        rec = existing.get(mac) or {}
        if not isinstance(rec, dict):
            return None
        stamp = rec.get("fingerprint_at", 0)
        if now - stamp > _CACHE_SECONDS or not rec.get("guess"):
            return None
        return Fingerprint(
            guess=rec.get("guess", "Unknown device"),
            category=rec.get("guess_category", "device"),
            confidence=rec.get("guess_confidence", "Low"),
            randomized=bool(rec.get("randomized", is_randomized(mac))),
            evidence=list(rec.get("guess_evidence") or []),
        )

    for mac, device in devices.items():
        mac = normalize(mac)
        if mac in skip:
            continue
        cached = from_cache(mac)
        if cached:
            results[mac] = cached
        else:
            work.append(mac)

    def probe(mac: str) -> tuple[str, Fingerprint]:
        device = devices[mac]
        result = guess(device.ip, mac, getattr(device, "vendor", ""), getattr(device, "hostname", ""))
        prev = by_ip.get(device.ip)
        if prev and prev[0] != mac:
            old_mac, old_rec = prev
            when = old_rec.get("last_seen", 0)
            if now - when < 86400:
                evidence = list(result.evidence)
                evidence.append(f"Used {device.ip} earlier today as {old_mac}")
                result = Fingerprint(
                    guess=result.guess,
                    category=result.category,
                    confidence=result.confidence,
                    randomized=result.randomized,
                    evidence=evidence,
                )
        return mac, result

    if work:
        with ThreadPoolExecutor(max_workers=min(8, len(work))) as pool:
            for mac, result in pool.map(probe, work):
                results[mac] = result

    return results
