"""LAN device discovery.

Discovery is deliberately passive-friendly: a short UDP burst forces the
Windows ARP cache to resolve every host, then the neighbour table is read.
The gateway's own DNS is then queried explicitly for PTR records - home
routers embed their DHCP lease hostnames there even when Windows' default
resolver (which may point upstream) does not know them.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field

from . import netinfo
from .oui import VendorDB, is_unicast, normalize


@dataclass
class Device:
    mac: str
    ip: str = ""
    hostname: str = ""
    vendor: str = ""
    source: str = "arp"          # arp | router | both
    connection: str = ""          # Wi-Fi / Ethernet / ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    blocked: bool = False
    online: bool = True
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> str:
        return normalize(self.mac)

    @property
    def display_name(self) -> str:
        return self.hostname or self.vendor or self.ip or self.mac


def _udp_probe(ip: str) -> None:
    for port in (9, 53, 5353):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.05)
            s.sendto(b"\x00", (ip, port))
            s.close()
        except Exception:
            pass


def _tcp_probe(ip: str) -> None:
    for port in (80, 443):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            s.connect((ip, port))
            s.close()
            return
        except Exception:
            continue


def arp_sweep(iface: netinfo.Interface, deep: bool = False) -> dict[str, str]:
    """Populate and read the ARP table. Returns IP -> MAC."""
    net = iface.network
    hosts: list[str] = []
    for host in net.hosts():
        address = str(host)
        if address == iface.ip:
            continue
        hosts.append(address)
        # Stop while enumerating: the 1024 cap must bound the work and the
        # memory, not just trim the finished list.
        if len(hosts) >= 1024:
            break

    with ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(_udp_probe, hosts))
    time.sleep(0.35)

    found = {ip: mac for ip, mac in netinfo.arp_table().items() if ipaddress.ip_address(ip) in net}

    if deep:
        # A TCP touch wakes devices that ignore UDP and works through APs that
        # drop broadcast-ish traffic.
        with ThreadPoolExecutor(max_workers=64) as pool:
            list(pool.map(_tcp_probe, hosts))
        time.sleep(0.4)
        for ip, mac in netinfo.arp_table().items():
            if ipaddress.ip_address(ip) in net and ip not in found:
                found[ip] = mac

    return found


def resolve_names(ips: list[str], timeout: float = 1.6, gateway: str = "") -> dict[str, str]:
    """Reverse names: gateway PTR first (it knows DHCP hostnames), then system DNS."""
    names: dict[str, str] = {}
    if gateway:
        try:
            names.update(netinfo.gateway_reverse_dns_many(ips, gateway, timeout=min(timeout, 0.8)))
        except Exception:
            pass
    missing = [ip for ip in ips if ip not in names]
    if missing:
        pool = ThreadPoolExecutor(max_workers=min(32, max(1, len(missing))))
        try:
            futures = {pool.submit(netinfo.reverse_dns, ip): ip for ip in missing}
            done, _ = wait(futures, timeout=timeout)
            for fut in done:
                try:
                    name = fut.result()
                except Exception:
                    name = ""
                if name:
                    names[futures[fut]] = name
        finally:
            pool.shutdown(wait=False)
    return names


def resolve_netbios(ips: list[str], timeout: float = 0.8) -> dict[str, str]:
    """NetBIOS fallback for hosts the router's DNS does not know."""
    found: dict[str, str] = {}
    subset = ips[:16]
    if not subset:
        return found
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        futures = {pool.submit(netinfo.netbios_name, ip): ip for ip in subset}
        done, _ = wait(futures, timeout=timeout + 1.5)
        for fut in done:
            try:
                name = fut.result()
            except Exception:
                name = ""
            if name:
                found[futures[fut]] = name
    finally:
        pool.shutdown(wait=False)
    return found


def scan(iface: netinfo.Interface, vendors: VendorDB, deep: bool = False) -> dict[str, Device]:
    """Return every device currently visible on the LAN, keyed by MAC."""
    arp = arp_sweep(iface, deep=deep)
    names = resolve_names(list(arp.keys()), gateway=iface.gateway)
    if deep:
        missing = [ip for ip in arp if ip not in names]
        if missing:
            names.update(resolve_netbios(missing))
    now = time.time()
    devices: dict[str, Device] = {}
    for ip, mac in arp.items():
        mac = normalize(mac)
        if not is_unicast(mac):
            continue
        devices[mac] = Device(
            mac=mac,
            ip=ip,
            hostname=names.get(ip, ""),
            vendor=vendors.lookup(mac),
            source="arp",
            first_seen=now,
            last_seen=now,
            online=True,
        )
    return devices


def classify(device: Device) -> str:
    """Best-effort device category used for the icon column."""
    text = f"{device.hostname} {device.vendor}".lower()
    rules = [
        ("phone", ["iphone", "android", "oneplus", "redmi", "poco", "galaxy", "pixel", "phone", "xiaomi", "oppo", "vivo", "realme", "motorola", "nokia"]),
        ("laptop", ["laptop", "macbook", "thinkpad", "ideapad", "notebook", "vivobook", "surface", "pc-", "desktop"]),
        ("tv", ["tv", "bravia", "firetv", "fire tv", "chromecast", "roku", "appletv", "apple tv", "mi box", "smart-tv", "hisense", "tcl"]),
        ("speaker", ["alexa", "echo", "sonos", "google home", "homepod", "speaker"]),
        ("console", ["playstation", "ps5", "ps4", "xbox", "nintendo", "switch"]),
        ("camera", ["cam", "camera", "yi", "tapo", "wyze", "arlo", "doorbell"]),
        ("printer", ["printer", "hp-", "canon", "epson", "brother"]),
        ("router", ["router", "gateway", "access point", "onu", "ont", "mesh", "extender", "repeater"]),
        ("iot", ["esp", "tuya", "shelly", "sonoff", "smart", "plug", "bulb", "aqara"]),
    ]
    for label, keys in rules:
        if any(k in text for k in keys):
            return label
    return "device"
