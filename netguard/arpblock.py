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
A crash / kill / power loss cannot send restore packets: the device then
recovers when its ARP cache expires (~30-60 s, up to ~2 min on some IoT).
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
            "It is free and standard (Wireshark/Nmap use it). NetGuard can open the official download page."
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
        self._local_ip = ""
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

    def health(self) -> dict:
        """Snapshot for the UI: is the poison thread alive, any error yet?"""
        with self._lock:
            return {
                "running": self.running,
                "targets": len(self._targets),
                "last_error": self._last_error,
            }

    def clear_error(self) -> None:
        with self._lock:
            self._last_error = ""

    def refresh(self, iface: netinfo.Interface, gateway_mac: str) -> bool:
        """Adopt a freshly resolved interface/gateway without restarting.

        Called by the app when it re-resolves the network (Fix 1). The old
        implementation cached gateway IP/MAC, local MAC and the Npcap device
        name forever at add() time, so a Wi-Fi change or gateway ARP miss
        silently broke an 'active' block. Returns True when anything changed
        (the open socket is closed so the next send rebuilds it on the new
        adapter).
        """
        if iface is None or not iface.gateway:
            return False
        # An empty lookup only preserves the old MAC for the same gateway;
        # it must never carry the old router identity onto a new gateway.
        if gateway_mac:
            new_gw_mac = normalize(gateway_mac)
        else:
            new_gw_mac = self._gateway_mac if iface.gateway == self._gateway_ip else ""
        new_local = normalize(iface.mac or "") or self._local_mac
        new_iface_name = self._resolve_iface(iface.gateway, iface.ip)
        with self._lock:
            changed = (
                self._gateway_ip != iface.gateway
                or (new_gw_mac != self._gateway_mac)
                or (new_local and self._local_mac != new_local)
                or (new_iface_name and self._iface_name != new_iface_name)
                or (iface.ip and self._local_ip != iface.ip)
            )
            if not changed:
                return False
            self._gateway_ip = iface.gateway
            if iface.ip:
                self._local_ip = iface.ip
            if new_gw_mac:
                self._gateway_mac = new_gw_mac
            elif not gateway_mac:
                self._gateway_mac = ""
            if new_local:
                self._local_mac = new_local
            if new_iface_name:
                self._iface_name = new_iface_name
            self._events.append(
                "Network refreshed: ARP blocker now uses gateway "
                f"{iface.gateway} ({self._gateway_mac or 'MAC unknown'}) "
                f"on {self._iface_name or iface.name}."
            )
        self._close_socket()
        return True

    def refresh_targets(self, observed: dict[str, str]) -> None:
        """Follow blocked devices when DHCP moves them to a new IP (Fix 2).

        Previously the IP was pinned at add() time forever: if the phone got
        a new lease it came back online while the app kept poisoning the old
        address — and if that old address was handed to someone else, the new
        owner was blocked instead. The app now calls this after every scan
        with the merged MAC->IP view (ARP sweep + router DHCP list):

        * same MAC, new IP  -> point the poison at the new IP, log it.
        * old IP now owned by a different MAC -> release without poisoning
          the new owner (the poisoned cache entries expire on their own).
        * target not seen at all -> keep blocking the old IP; a single
          missed scan never releases a device.
        """
        norm_observed: dict[str, str] = {}
        for mac, ip in observed.items():
            if not mac or not ip or ip.startswith(("0.", "255.")):
                continue
            norm_observed[normalize(mac)] = ip
        if not norm_observed:
            return
        ip_to_mac = {ip: mac for mac, ip in norm_observed.items()}
        with self._lock:
            for mac, target in list(self._targets.items()):
                if mac in norm_observed:
                    new_ip = norm_observed[mac]
                    # Never adopt an address that belongs to us or the router.
                    if new_ip in (self._gateway_ip, self._local_ip) or new_ip == target["ip"]:
                        continue
                    old_ip = target["ip"]
                    target["ip"] = new_ip
                    self._events.append(
                        f"{mac} moved {old_ip} -> {new_ip}; still forced offline (now on {new_ip})."
                    )
                elif target["ip"] in ip_to_mac:
                    # Somebody else owns the old IP now — do not block them.
                    old_ip = target["ip"]
                    owner = ip_to_mac[old_ip]
                    del self._targets[mac]
                    self._events.append(
                        f"{old_ip} now belongs to {owner}; stopped blocking {mac} "
                        "so the new owner is not cut off."
                    )

    def target_ip(self, mac: str) -> str:
        with self._lock:
            target = self._targets.get(normalize(mac))
            return target["ip"] if target else ""

    def retarget(self, old_mac: str, new_mac: str, new_ip: str) -> bool:
        """Move a block from a rotated MAC to its new MAC (Fix 9).

        The poison loop reads targets every cycle, so repointing the dict
        entry is enough — no thread restart. Returns False if the old MAC
        was not blocked or the new MAC must never be adopted.
        """
        old_mac, new_mac = normalize(old_mac), normalize(new_mac)
        if not old_mac or not new_mac or old_mac == new_mac or not new_ip:
            return False
        if new_ip in (self._gateway_ip, self._local_ip):
            return False
        with self._lock:
            target = self._targets.pop(old_mac, None)
            if target is None:
                return False
            self._targets[new_mac] = {"mac": new_mac, "ip": new_ip}
            self._events.append(
                f"{old_mac} rotated MAC -> {new_mac} ({new_ip}); block carried over."
            )
        return True

    # -- lifecycle --------------------------------------------------------
    def add(self, mac: str, ip: str, iface: netinfo.Interface, gateway_mac: str) -> tuple[bool, str]:
        mac = normalize(mac)
        if not mac or not ip:
            return False, "The device has no known IP address right now."
        if not gateway_mac:
            return False, "The router's MAC address is unknown; refresh and try again."
        if mac == normalize(iface.mac or "") or ip == iface.ip:
            return False, "That is this computer - it will never be blocked."
        if mac == normalize(gateway_mac) or ip == iface.gateway:
            return False, "That is the router itself - it will never be blocked."

        ok, message = readiness(iface)
        if not ok:
            return False, message

        with self._lock:
            target = {"mac": mac, "ip": ip}
            self._targets[mac] = target
            self._gateway_ip = iface.gateway
            self._gateway_mac = normalize(gateway_mac)
            self._local_mac = normalize(iface.mac or "")
            self._local_ip = iface.ip or ""
            self._iface_name = self._resolve_iface(ip)
            gateway_ip = self._gateway_ip
            gateway_mac_norm = self._gateway_mac
            local_mac = self._local_mac
            iface_name = self._iface_name

        self._start_thread()
        # Fix 4 (F4): prove the first poison send actually works *before*
        # telling the user it succeeded. Previously add() returned True the
        # moment the thread started, so a dead socket/adapter showed as
        # "forced offline" while nothing was sent.
        try:
            self._poison(target, gateway_ip, gateway_mac_norm, local_mac, iface_name)
        except Exception as exc:
            self._last_error = str(exc)
            with self._lock:
                self._targets.pop(mac, None)
            self._close_socket()
            return False, f"Could not send the blocking packets: {exc}"
        # A stale failure from an earlier adapter must not keep the UI in a
        # warning state now that sending demonstrably works again.
        if self._last_error:
            self.clear_error()
        return True, f"Forcing {ip} offline."

    def remove(self, mac: str) -> bool:
        """Stop blocking one device and restore it. Returns restore success.

        Returns True when nothing was blocked or the restore packets were
        sent; False when the restore could not be sent (see events).
        """
        mac = normalize(mac)
        with self._lock:
            target = self._targets.pop(mac, None)
            empty = not self._targets
        ok = True
        if target:
            ok = self._restore_one(target)
        if empty:
            self._close_socket()
        return ok

    def stop(self) -> list[str]:
        """Stop poisoning and put every ARP table back.

        Returns the list of MACs whose restore packets failed (empty = all
        restored). Callers should log this instead of assuming success
        (Fix 4, F7).
        """
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=3)
        self._thread = None
        with self._lock:
            remaining = list(self._targets.values())
            self._targets.clear()
        failed: list[str] = []
        for target in remaining:
            if not self._restore_one(target):
                failed.append(target["mac"])
        self._close_socket()
        return failed

    # -- internals --------------------------------------------------------
    def _resolve_iface(self, ip: str, local_ip: str = "") -> str | None:
        """Map the local IPv4 address to the Npcap device scapy can send on."""
        try:
            from scapy.all import conf as scapy_conf

            scapy_conf.use_pcap = True
            try:
                return scapy_conf.route.route(ip)[0]
            except Exception:
                pass
            target_ip = local_ip or ip
            for name, iface in scapy_conf.ifaces.items():
                ips = getattr(iface, "ips", {}) or {}
                if target_ip in ips.values():
                    return name
        except Exception:
            pass
        return None

    def _start_thread(self) -> None:
        # Fix 4 (F8): clear the stop flag first. After stop() (or a timed-out
        # join on a hung send), the old thread may still be alive with _stop
        # set; clearing it resurrects that thread for the new target instead
        # of leaving the new target unpoisoned.
        self._stop.clear()
        if self.running:
            return
        self._thread = threading.Thread(target=self._loop, name="arpblock", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                with self._lock:
                    targets = list(self._targets.values())
                    gateway_ip = self._gateway_ip
                    gateway_mac = self._gateway_mac
                    local_mac = self._local_mac
                    iface_name = self._iface_name
                if not targets or not gateway_ip:
                    # Fix 4 (F8): idle-wait instead of exiting. The old
                    # "break" raced with add(): remove-last made the loop
                    # exit, and the next add() saw running=True and started
                    # nothing — a target that looked blocked but never was.
                    self._stop.wait(INTERVAL)
                    continue

                # Safety: if an address was handed to a different device, stop
                # poisoning it so the new owner is not blocked by accident.
                self._cycle += 1
                if self._cycle % 8 == 0:
                    self._revalidate(targets)

                with self._lock:
                    targets = list(self._targets.values())

                cycle_ok = True
                # Keep the state lock across membership checks and the poison
                # sends.  A remove() that wins the lock first removes the
                # target and restores it; one that waits cannot report success
                # before a stale poison is sent.  The send is only the two
                # forged ARP replies, so holding the lock here is short-lived.
                with self._lock:
                    for target in targets:
                        if target["mac"] not in self._targets:
                            continue
                        try:
                            self._poison(target, gateway_ip, gateway_mac, local_mac, iface_name)
                        except Exception as exc:  # keep other targets alive
                            cycle_ok = False
                            self._last_error = str(exc)
                            if self._last_error not in self._events:
                                self._events.append(f"ARP send error: {exc}")
                # Recovery is a fact once a full cycle has been sent again;
                # otherwise the badge stays "check log" forever.
                if cycle_ok and self._last_error:
                    self.clear_error()
            except Exception as exc:  # never let the thread die silently
                self._last_error = str(exc)
                self._events.append(f"ARP blocker error: {exc}")
                # wait instead of spinning if something keeps failing
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

    def _restore_one(self, target: dict) -> bool:
        """Re-announce true mappings; retry on failure. Returns success.

        Fix 4 (F7): previously this sent once and swallowed errors, so a
        failed restore still showed as restored. Now it retries (rebuilding
        a stale socket between attempts), records a visible event on
        ultimate failure, and reports the outcome to the caller.
        Note: "sent" is the strongest claim we can make from this machine —
        some stacks ignore unsolicited ARP replies, in which case the
        device still recovers when its ARP cache expires (~30-60 s).
        """
        if not (self._gateway_ip and self._gateway_mac):
            self._last_error = "Cannot restore: gateway MAC unknown."
            self._events.append("⚠ Restore skipped: gateway MAC unknown — device may take ~60s to recover.")
            return False
        last_exc: Exception | None = None
        for _attempt in range(3):
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
                return True
            except Exception as exc:
                last_exc = exc
                self._close_socket()
        self._last_error = str(last_exc or "unknown")
        self._events.append(
            f"⚠ Restore packets failed for {target['ip']} ({target['mac']}): {last_exc} "
            "— the device may stay offline up to ~60s until caches expire."
        )
        return False
