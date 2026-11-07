"""Probe the router's UPnP (IGD) services for DHCP client names.

Many Huawei ONTs expose WANIPConnection so LAN apps can read the host list
without a password.  This prints the discovery XML location(s) and the
results of GetHostNumberOfEntries / GetHostEntry / GetAssociatedDeviceList.
"""

from __future__ import annotations

import socket
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET

SEARCHES = (
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)
GROUP = ("239.255.255.250", 1900)


def discover(seconds=6.0):
    locations: set[str] = set()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 1900))
    except OSError:
        pass
    end = time.time() + seconds
    while time.time() < end:
        for st in SEARCHES:
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {GROUP[0]}:{GROUP[1]}\r\n"
                'MAN: "ns=01"\r\n'
                "MX: 3\r\n"
                f"ST: {st}\r\n\r\n"
            )
            try:
                sock.sendto(msg.encode(), GROUP)
            except OSError:
                pass
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            continue
        headers = data.decode("utf-8", errors="ignore")
        for line in headers.splitlines():
            if line.lower().startswith("location:"):
                locations.add(line.partition(":")[2].strip())
        print(f"[{addr[0]}] {headers.splitlines()[0] if headers else ''}")
    sock.close()
    return sorted(locations)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "NetGuard/1.0"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def soap(control_url: str, action: str, args: str = "") -> str:
    body = (
        f'<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        f"{args}</u:{action}></s:Body></s:Envelope>"
    )
    req = urllib.request.Request(
        control_url,
        data=body.encode(),
        method="POST",
        headers={
            "User-Agent": "NetGuard/1.0",
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"urn:schemas-upnp-org:service:WANIPConnection:1#{action}"',
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def find_control(xml_text: str, service: str = "WANIPConnection") -> tuple[str, str] | None:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None
    ns = {"d": "urn:schemas-upnp-org:device-1-0"}
    for svc in root.iter():
        if svc.tag.endswith("serviceType") and service in (svc.text or ""):
            parent_url = ""
            name = ""
            url = ""
            for child in svc.iter():
                if child.tag.endswith("serviceType"):
                    name = child.text or ""
                elif child.tag.endswith("controlURL"):
                    url = child.text or ""
            return name, url
    # Fallback: raw regex-ish scan.
    import re

    m = re.search(service + r"[^<]*</.*?controlURL>\s*([^<]+)", xml_text, re.S)
    if m:
        return service, m.group(1).strip()
    return None


def main() -> int:
    locations = discover()
    print("locations:", locations)
    for loc in locations:
        try:
            xml_text = fetch(loc)
        except Exception as exc:
            print(loc, "FETCH FAIL", exc)
            continue
        found = find_control(xml_text)
        if not found:
            print(loc, "no WANIPConnection service in XML")
            continue
        name, control = found
        if control.startswith("/"):
            base = "/".join(loc.split("/")[:3])
            control = base + control
        print("service:", name, "control:", control)
        try:
            print(soap(control, "GetHostNumberOfEntries")[:600])
        except Exception as exc:
            print("GetHostNumberOfEntries FAIL", exc)
        for i in range(0, 12):
            try:
                print(f"entry {i}:", soap(control, "GetHostEntry", f"<NewHostNumber>{i}</NewHostNumber>")[:400])
            except Exception as exc:
                print(f"entry {i} FAIL", exc)
                break
        try:
            print(soap(control, "GetAssociatedDeviceList")[:1200])
        except Exception as exc:
            print("GetAssociatedDeviceList FAIL", exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
