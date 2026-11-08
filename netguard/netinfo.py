"""Windows network helpers: interface discovery, ARP table, hostnames."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _run(args: list[str], timeout: float = 6.0) -> str:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
        out = proc.stdout or b""
        return out.decode("utf-8", errors="ignore")
    except Exception:
        try:
            out = subprocess.run(args, capture_output=True, timeout=timeout).stdout or b""
            return out.decode("oem", errors="ignore")
        except Exception:
            return ""


class Interface:
    def __init__(self, name: str, ip: str, mask: str, gateway: str, mac: str, description: str):
        self.name = name
        self.ip = ip
        self.mask = mask
        self.gateway = gateway
        self.mac = mac
        self.description = description

    @property
    def network(self) -> ipaddress.IPv4Network:
        try:
            return ipaddress.IPv4Network(f"{self.ip}/{self.mask}", strict=False)
        except ValueError:
            return ipaddress.IPv4Network(f"{self.ip}/24", strict=False)

    def __repr__(self) -> str:
        return f"<Interface {self.name} {self.ip}/{self.mask} gw={self.gateway}>"


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC_FULL_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\b")


def list_interfaces(text: str | None = None, routes: str | None = None) -> list[Interface]:
    """Enumerate IPv4 interfaces from ipconfig, locale-independently.

    Fix 7: the old parser matched English labels ("IPv4 Address", "Default
    Gateway", ...), so non-English Windows returned nothing. IP addresses,
    subnet masks and MACs are the same in every locale, so this parses
    values by shape instead of labels.

    The gateway comes from the IPv4 routing table, not from ipconfig's
    presentation order.  ipconfig lists DNS servers after the gateway, and a
    LAN that runs its own resolver (Pi-hole/AdGuard) therefore used to
    masquerade as the router — wrong admin URL, wrong safety guard, and ARP
    replies forged with the wrong source address.
    """
    if text is None:
        text = _run(["ipconfig", "/all"], timeout=8)
        if routes is None:
            routes = _run(["route", "print", "-4"], timeout=6)
    if not text:
        return []

    route_gateway, route_iface = parse_default_route(routes) if routes else ("", "")

    blocks: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            current = {"title": line.strip().rstrip(":"), "ips": [], "macs": []}
            blocks.append(current)
            continue
        if current is None:
            continue
        current["ips"].extend(_IPV4_RE.findall(line))
        current["macs"].extend(_MAC_FULL_RE.findall(line))

    candidates: list[Interface] = []
    for block in blocks:
        ips = [ip for ip in block["ips"] if not ip.startswith("169.254.") and not ip.startswith(("0.", "255."))]
        if not ips:
            continue
        ip = ips[0]
        try:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        except ValueError:
            continue
        masks = [v for v in block["ips"] if v.startswith("255.")]
        mask = masks[0] if masks else "255.255.255.0"
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        except ValueError:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)

        gateway = ""
        if route_gateway:
            if route_iface:
                matched = route_iface == ip
            else:
                try:
                    matched = ipaddress.ip_address(route_gateway) in net
                except ValueError:
                    matched = False
            if matched:
                gateway = route_gateway
        if not gateway and not route_gateway:
            # Only when there is NO route table at all (offline/synthetic
            # input) may we guess the gateway as the first *other* in-subnet
            # address. H1: when a default route exists but belongs to another
            # adapter, inventing a gateway here picks the LAN DNS server and
            # ARP-poisons the wrong host. Leave it "" and let readiness refuse.
            for other in ips:
                if other == ip or other == mask:
                    continue
                try:
                    if ipaddress.ip_address(other) in net:
                        gateway = other
                        break
                except ValueError:
                    continue
        mac = block["macs"][0] if block["macs"] else ""
        candidates.append(Interface(block["title"], ip, mask, gateway, mac, block["title"]))
    return candidates


def parse_default_route(text: str) -> tuple[str, str]:
    """Return ``(gateway, interface_ip)`` for the best IPv4 default route.

    ``route print -4`` rows are:
    ``0.0.0.0  0.0.0.0  192.168.1.1  192.168.1.36  25``
    The lowest metric wins (Windows itself uses it).
    """
    best: tuple[str, str, int] | None = None
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        destination, netmask, gateway = parts[0], parts[1], parts[2]
        if destination != "0.0.0.0" or netmask != "0.0.0.0":
            continue
        if not _IPV4_RE.fullmatch(gateway) or gateway.startswith(("0.", "255.")):
            continue
        iface = parts[3] if _IPV4_RE.fullmatch(parts[3]) else ""
        metric = 1 << 30
        if len(parts) >= 5:
            try:
                metric = int(parts[4])
            except ValueError:
                pass
        if best is None or metric < best[2]:
            best = (gateway, iface, metric)
    return (best[0], best[1]) if best else ("", "")


def default_route(text: str | None = None) -> tuple[str, str]:
    if text is None:
        text = _run(["route", "print", "-4"], timeout=6)
    return parse_default_route(text)


def iface_key(iface: Interface | None) -> str:
    """Stable id for a saved user selection (survives DHCP IP changes)."""
    if not iface:
        return ""
    mac = (iface.mac or "").upper().replace("-", ":")
    return mac or iface.ip


def active_interface(prefer: str | None = None, text: str | None = None) -> Interface | None:
    """Pick the interface that owns the default route (falling back to Wi-Fi).

    ``prefer`` is an iface_key() (usually the physical MAC) chosen by the
    user in the header selector; it wins over the Wi-Fi heuristic so dual-
    router setups stop guessing wrong.
    """
    candidates = list_interfaces(text)
    if not candidates:
        return None
    if prefer and not isinstance(prefer, str):
        prefer = None
    if prefer:
        want = prefer.upper().replace("-", ":")
        for c in candidates:
            if (c.mac or "").upper().replace("-", ":") == want or c.ip == prefer:
                return c
        # Preference gone (adapter unplugged) — fall through with a clear
        # signal to the caller instead of silently pretending it matched.
    with_gw = [c for c in candidates if c.gateway]
    pool = with_gw or candidates
    for c in pool:
        if "wi-fi" in c.name.lower() or "wireless" in c.name.lower() or "wlan" in c.name.lower():
            return c
    return pool[0]


def gateway_mac(gateway: str) -> str:
    if not gateway:
        return ""
    neighbors = arp_table()
    return neighbors.get(gateway, "")


_MAC_RE = re.compile(r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")


def arp_table() -> dict[str, str]:
    """Map IP -> MAC from the Windows neighbour cache (dynamic + static)."""
    text = _run(["arp", "-a"], timeout=6)
    result: dict[str, str] = {}
    for line in text.splitlines():
        m = _MAC_RE.search(line)
        if not m:
            continue
        parts = line.split()
        ip = ""
        for part in parts:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", part):
                ip = part
                break
        if not ip:
            continue
        mac = m.group(1).replace("-", ":").upper()
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        result[ip] = mac
    return result


def _dns_name(packet: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name."""
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
            target, _ = _dns_name(packet, pointer, depth + 1)
            if target:
                labels.append(target)
            return ".".join(labels), offset + 2
        if length & 0xC0:
            break
        offset += 1
        labels.append(packet[offset : offset + length].decode("utf-8", errors="ignore"))
        offset += length
    return ".".join(labels), offset


def gateway_reverse_dns(ip: str, server: str, timeout: float = 0.8) -> str:
    """Ask the LAN gateway directly for this address's PTR/DHCP hostname.

    Windows' own resolver may use an upstream DNS server that knows nothing
    about your LAN, while the router embeds lease hostnames in its local DNS
    (for example ``OPPO-A15.hgu_lan``).  Querying it explicitly is what makes
    most phone names appear.
    """
    if not ip or not server:
        return ""
    try:
        labels = [part for part in reversed(ip.split(".")) if part] + ["in-addr", "arpa"]
    except Exception:
        return ""
    qname = b""
    for label in labels:
        part = label.encode("ascii", errors="ignore")[:63]
        qname += bytes([len(part)]) + part
    qname += b"\x00"
    query_id = int.from_bytes(os.urandom(2), "big")
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 12, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data, _ = sock.recvfrom(4096)
    except Exception:
        return ""
    if len(data) < 12:
        return ""
    try:
        qd, an = struct.unpack_from("!HH", data, 4)
        offset = 12
        for _ in range(qd):
            _name, offset = _dns_name(data, offset)
            offset += 4
        for _ in range(an):
            _owner, offset = _dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if rtype == 12:
                target, _ = _dns_name(data, offset)
                name = (target.split(".")[0] or "").strip()
                if name and name != ip.lower():
                    return name
            offset += rdlen
    except Exception:
        return ""
    return ""


def gateway_reverse_dns_many(ips: list[str], server: str, timeout: float = 0.8) -> dict[str, str]:
    """Concurrent gateway PTR lookups for a whole subnet."""
    if not server:
        return {}

    def lookup(ip: str) -> tuple[str, str]:
        return ip, gateway_reverse_dns(ip, server, timeout=timeout)

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(ips)))) as pool:
        return {ip: name for ip, name in pool.map(lookup, ips) if name}


def reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    if not name or name == ip:
        return ""
    return name.split(".")[0]


_NB_RE = re.compile(r"^\s*(\S+?)\s*<00>\s+UNIQUE", re.MULTILINE)


def netbios_name(ip: str, timeout: float = 1.4) -> str:
    """Ask a Windows/Samba host for its NetBIOS name."""
    text = _run(["nbtstat", "-A", ip], timeout=timeout)
    m = _NB_RE.search(text)
    return m.group(1).strip() if m else ""
