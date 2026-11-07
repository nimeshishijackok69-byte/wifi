"""ARP-based device blocking ("force offline") for IPv4 LANs.

The router can only be told to block a device when its admin password is
known.  When it is not, this module takes the *local* route: the computer
answers ARP for the target and for the gateway, so neither side can find the
other and the target loses its connection.  Nothing is forwarded - packets
are simply dropped, so this is a block, not a man-in-the-middle.

Requirements on Windows:

* the **Npcap** packet driver (https://npcap.com) - standard, free, used by
  Wireshark and Nmap;
* NetGuard running **as administrator**, because raw frames are sent.

The block only lasts while NetGuard is running and the computer stays on the
network.  ``stop()`` (and app shutdown) restores the correct ARP mappings.
"""

from __future__ import annotations

import ctypes
import os
import threading

from . import netinfo
from .oui import normalize

# How often forged replies are repeated.  Windows/Android caches expire ARP
# entries in ~30 s and the Linux/Android defaults are 60 s, so 1.5 s is
# comfortably inside the window without flooding the LAN.
INTERVAL = 1.5

_NPCAP_PATHS = (
    r"C:\Windows\System32\Npcap\wpcap.dll",
    r"C:\Windows\System32\wpcap.dll",
    r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
)


def is_admin() -> bool:
    """True when the process can send raw frames."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def npcap_installed() -> bool:
    if os.name != "nt":
        return True
    return any(os.path.exists(path) for path in _NPCAP_PATHS)


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
    except Exception:
        return False
    return True


def readiness(iface: netinfo.Interface | None = None) -> tuple[bool, str]:
    """Human-readable prerequisites check used by the UI."""
    if os.name != "nt":
        return False, "This build supports Windows only."
    if not npcap_installed():
        return False, (
            "The Npcap packet driver is not installed.\n\n"
            "It is free and standard (Wireshark/Nmap use it). NetGuard can install it for you."
        )
    if not scapy_available():
        return False, "The Python package 'scapy' is missing (pip install scapy)."
    if not is_admin():
        return False, "NetGuard must run as administrator to send the blocking packets."
    if iface is None:
        return False, "No active network adapter was found."
    if not iface.gateway:
        return False, "This network has no gateway address."
    return True, ""


class ArpBlocker:
    """Keeps a set of devices poisoned and restores them on stop."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._targets: dict[str, dict] = {}  # mac -> {ip, mac}
        self._iface_name: str | None = None
        self._local_mac = ""
        self._gateway_ip = ""
        self._gateway_mac = ""
        self._last_error = ""
        self._events: list[str] = []
        self._cycle = 0
        self._socket = None

    # -- state ------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def drain_events(self) -> list[str]:
        """Messages for the UI (e.g. a target changed IP and was released)."""
        with self._lock:
            events, self._events = self._events, []
        return events

    @property
    def targets(self) -> list[dict]:
        with self._lock:
            return [dict(t) for t in self._targets.values()]

    @property
    def last_error(self) -> str:
        return self._last_error

    def is_blocking(self, mac: str) -> bool:
        with self._lock:
            return normalize(mac) in self._targets

    # -- lifecycle --------------------------------------------------------
    def add(self, mac: str, ip: str, iface: netinfo.Interface, gateway_mac: str) -> tuple[bool, str]:
        mac = normalize(mac)
        if not mac or not ip:
            return False, "The device has no known IP address right now."
        if not gateway_mac:
            return False, "The router's MAC address is unknown; refresh and try again."
        if mac == normalize(iface.mac or ""):
            return False, "That is this computer - it will never be blocked."
        if mac == normalize(gateway_mac):
            return False, "That is the router itself - it will never be blocked."

        ok, message = readiness(iface)
        if not ok:
            return False, message

        with self._lock:
            self._targets[mac] = {"mac": mac, "ip": ip}
            self._gateway_ip = iface.gateway
            self._gateway_mac = normalize(gateway_mac)
            self._local_mac = normalize(iface.mac or "")
            self._iface_name = self._resolve_iface(ip)

        self._start_thread()
        return True, f"Forcing {ip} offline."

    def remove(self, mac: str) -> None:
        mac = normalize(mac)
        with self._lock:
            target = self._targets.pop(mac, None)
            empty = not self._targets
        if target:
            self._restore_one(target)
        if empty:
            self._close_socket()

    def stop(self) -> None:
        """Stop poisoning and put every ARP table back."""
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=3)
        self._thread = None
        with self._lock:
            remaining = list(self._targets.values())
            self._targets.clear()
        for target in remaining:
            self._restore_one(target)
        self._close_socket()

    # -- internals --------------------------------------------------------
    def _resolve_iface(self, ip: str) -> str | None:
        """Map the local IPv4 address to the Npcap device scapy can send on."""
        try:
            from scapy.all import conf as scapy_conf

            scapy_conf.use_pcap = True
            try:
                return scapy_conf.route.route(ip)[0]
            except Exception:
                pass
            for name, iface in scapy_conf.ifaces.items():
                ips = getattr(iface, "ips", {}) or {}
                if ip in ips.values():
                    return name
        except Exception:
            pass
        return None

    def _start_thread(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="arpblock", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                targets = list(self._targets.values())
                gateway_ip = self._gateway_ip
                gateway_mac = self._gateway_mac
                local_mac = self._local_mac
                iface_name = self._iface_name
            if not targets or not gateway_ip:
                break

            # Safety: if an address was handed to a different device, stop
            # poisoning it so the new owner is not blocked by accident.
            self._cycle += 1
            if self._cycle % 8 == 0:
                self._revalidate(targets)

            with self._lock:
                targets = list(self._targets.values())

            for target in targets:
                try:
                    self._poison(target, gateway_ip, gateway_mac, local_mac, iface_name)
                except Exception as exc:  # keep other targets alive
                    self._last_error = str(exc)
            self._stop.wait(INTERVAL)

    def _revalidate(self, targets: list[dict]) -> None:
        table = netinfo.arp_table()
        for target in targets:
            current = table.get(target["ip"], "")
            if current and normalize(current) != target["mac"]:
                with self._lock:
                    self._targets.pop(target["mac"], None)
                    self._events.append(
                        f"{target['ip']} now belongs to {current}; stopped blocking it."
                    )

    # -- packet helpers ---------------------------------------------------
    def _send(self, packets: list) -> None:
        """Send frames on a kept-open pcap handle (fast, and no drops)."""
        from scapy.all import conf

        conf.use_pcap = True
        if self._socket is None:
            self._socket = conf.L2socket(iface=self._iface_name)
        for packet in packets:
            self._socket.send(packet)

    def _close_socket(self) -> None:
        sock, self._socket = self._socket, None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def _poison(self, target: dict, gateway_ip: str, gateway_mac: str,
                local_mac: str, iface_name: str | None) -> None:
        from scapy.all import ARP, Ether

        ip = target["ip"]
        mac = target["mac"]
        # Tell the target that the router lives at our address …
        to_target = Ether(dst=mac, src=local_mac) / ARP(
            op=2, hwsrc=local_mac, psrc=gateway_ip, hwdst=mac, pdst=ip,
        )
        # … and tell the router that the target lives at our address.
        to_gateway = Ether(dst=gateway_mac, src=local_mac) / ARP(
            op=2, hwsrc=local_mac, psrc=ip, hwdst=gateway_mac, pdst=gateway_ip,
        )
        try:
            self._send([to_target, to_gateway])
        except Exception:
            # A stale handle (adapter reset, sleep) - rebuild once and retry.
            self._close_socket()
            self._send([to_target, to_gateway])

    def _restore_one(self, target: dict) -> None:
        """Re-announce the true mappings so the two sides can talk again."""
        if not (self._gateway_ip and self._gateway_mac):
            return
        try:
            from scapy.all import ARP, Ether

            ip = target["ip"]
            mac = target["mac"]
            to_target = Ether(dst=mac, src=self._gateway_mac) / ARP(
                op=2, hwsrc=self._gateway_mac, psrc=self._gateway_ip, hwdst=mac, pdst=ip,
            )
            to_gateway = Ether(dst=self._gateway_mac, src=mac) / ARP(
                op=2, hwsrc=mac, psrc=ip, hwdst=self._gateway_mac, pdst=self._gateway_ip,
            )
            self._send([to_target, to_gateway] * 3)
        except Exception as exc:
            self._last_error = str(exc)
