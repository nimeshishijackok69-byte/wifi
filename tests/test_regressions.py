"""Regression tests for the critical bugs fixed after the audit.

Each check names the failure mode it locks down, so a future refactor that
reintroduces it fails here instead of on a live network.
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

temp = tempfile.mkdtemp(prefix="netguard-regress-")
os.environ["APPDATA"] = temp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mock_router  # noqa: E402
from mock_router import MockRouter  # noqa: E402

import netguard.app as appmod  # noqa: E402
import netguard.fingerprint as fingerprint  # noqa: E402
from netguard import arpblock, netinfo  # noqa: E402
from netguard.router import (  # noqa: E402
    HuaweiRouter,
    RouterError,
    SessionExpired,
    filter_macs,
    parse_page,
)
from netguard.store import Store  # noqa: E402

FAILS = []


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label + (f"  [{detail}]" if detail and not condition else ""))
    if not condition:
        FAILS.append(label)


# ---------------------------------------------------------------------------
# Router: a dead session must raise, never look like "nobody is blocked".
# ---------------------------------------------------------------------------
def test_session_expiry() -> None:
    server = MockRouter().start()
    try:
        router = HuaweiRouter(server.url, timeout=5)
        router.login("excitel", "admin@123")
        target = "16:4F:BD:EE:9C:3C"
        ok, msg = router.set_block(target, True)
        check("expiry: setup block", ok, msg)

        server.state.sessions.clear()  # idle cookie timeout
        try:
            blocked = router.blocked_macs()
            check("expired session raises", False, repr(blocked))
        except SessionExpired:
            check("expired session raises", True)
        check("expired session clears logged_in", router.logged_in is False)

        version = router.relogin()
        check("expiry: relogin works", bool(version) and router.logged_in, version)
        check("expiry: block survives relogin", target in router.blocked_macs(), str(router.blocked_macs()))
    finally:
        server.stop()


def test_http_error_is_not_empty() -> None:
    class Err(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def do_GET(self):  # noqa: N802
            body = b"<h1>500 Internal Server Error</h1>"
            self.send_response(500)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Err)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        router = HuaweiRouter(f"http://127.0.0.1:{httpd.server_address[1]}", timeout=5)
        router.logged_in = True
        router._filter_page = "/html/ssmp/macfilter/macfilter.asp"
        router._crawled = True
        try:
            router.blocked_macs()
            check("HTTP 500 raises", False)
        except SessionExpired:
            check("HTTP 500 raises", False, "misreported as session expiry")
        except RouterError as exc:
            check("HTTP 500 raises", "500" in str(exc), str(exc))
    finally:
        httpd.shutdown()


# ---------------------------------------------------------------------------
# Filter-mode detection: an unselected "Whitelist" option is not allow mode.
# ---------------------------------------------------------------------------
def test_filter_mode_options() -> None:
    page = """<html><body><h2>MAC Filter</h2>
    <table><tr><th>MAC Address</th></tr>{blocked}</table>
    <form action="/boaform/admin/formWlanMacFilter" method="post">
    <input type="hidden" name="submit-url" value="/x.asp">
    <select name="filtertype">
      <option value="0" selected>Blacklist (Deny)</option>
      <option value="1">Whitelist (Allow)</option>
    </select>
    <input type="text" name="macaddr1" value="">
    <input type="submit" name="add" value="Add">
    </form></body></html>"""
    original = mock_router.FILTER
    mock_router.FILTER = page
    server = MockRouter().start()
    try:
        router = HuaweiRouter(server.url, timeout=5)
        router.login("excitel", "admin@123")
        info = router.info()
        check("blacklist-selected page is blacklist", info["filter_semantics"] == "block", str(info))
        target = "16:4F:BD:EE:9C:3C"
        ok, msg = router.set_block(target, True)
        check("blocking works with a dual-option select", ok, msg)
        check("dual-option block reached the router", target in server.state.blocked)
    finally:
        server.stop()
        mock_router.FILTER = original

    # A select whose selected label says Whitelist must refuse.
    allow_page = """<html><body>
    <form action="/boaform/admin/formWlanMacFilter" method="post">
    <select name="filtertype">
      <option value="0">Blacklist</option>
      <option value="1" selected>Whitelist</option>
    </select>
    <input type="text" name="macaddr1" value="">
    <input type="submit" name="add" value="Add">
    </form></body></html>"""
    router = HuaweiRouter("http://192.168.1.1", timeout=2)
    router.logged_in = True
    router._filter_page = "/f.asp"
    router._crawled = True
    router.get = lambda _path: allow_page
    router.post = lambda *_a, **_k: "<ok>"
    ok, msg = router.set_block("AA:BB:CC:DD:EE:FF", True)
    check("whitelist-selected page refuses", ok is False and "allow-list" in msg.lower(), msg)

    # A numeric control must not hide explicit visible wording.  This is the
    # dangerous combination: filtertype=1 with a "Whitelist" heading.
    hidden_page = """<html><body><h2>MAC Filter — Whitelist</h2>
    <form action="/boaform/admin/formWlanMacFilter" method="post">
    <input type="hidden" name="filtertype" value="1">
    <input type="text" name="macaddr1" value="">
    <input type="submit" name="add" value="Add">
    </form></body></html>"""
    router3 = HuaweiRouter("http://192.168.1.1", timeout=2)
    router3.logged_in = True
    router3._filter_page = "/f.asp"
    router3._crawled = True
    router3.get = lambda _path: hidden_page
    router3.post = lambda *_a, **_k: "<ok>"
    ok, msg = router3.set_block("AA:BB:CC:DD:EE:FF", True)
    check("numeric mode does not hide whitelist wording", ok is False and "allow-list" in msg.lower(), msg)

    # A device *named* "Whitelist-Printer" in a MAC table is not a mode.
    device_named = """<html><body><table>
    <tr><td>Whitelist-Printer</td><td>AA:BB:CC:DD:EE:FF</td><td>192.168.1.50</td></tr>
    </table><form action="/x"><input type="text" name="macaddr1" value=""></form></body></html>"""
    router4 = HuaweiRouter("http://192.168.1.1", timeout=2)
    router4.logged_in = True
    router4._filter_page = "/f.asp"
    router4.get = lambda _path: device_named
    router4._learn_filter_mode()
    check("device name does not set allow mode", router4._filter_semantics == "", router4._filter_semantics)

    # But a mode label in a table without MACs is still read.
    label_table = "<html><table><tr><td>Filter Mode:</td><td>Whitelist</td></tr></table></html>"
    router5 = HuaweiRouter("http://192.168.1.1", timeout=2)
    router5.logged_in = True
    router5._filter_page = "/f.asp"
    router5.get = lambda _path: label_table
    router5._learn_filter_mode()
    check("mode label in a non-MAC table is read", router5._filter_semantics == "allow", router5._filter_semantics)

    # A later word-free page must clear the latched "allow" (no stickiness).
    pages = {"html": "<html>MAC filter: Whitelist</html>"}
    router2 = HuaweiRouter("http://192.168.1.1", timeout=2)
    router2.logged_in = True
    router2._filter_page = "/f.asp"
    router2.get = lambda _path: pages["html"]
    router2._learn_filter_mode()
    check("plain whitelist text detected", router2._filter_semantics == "allow", router2._filter_semantics)
    pages["html"] = "<html>MAC filter (no mode words)</html>"
    router2._learn_filter_mode()
    check("allow flag does not stick", router2._filter_semantics == "", router2._filter_semantics)


# ---------------------------------------------------------------------------
# One MAC extractor: tables, form slots, delete checkboxes and links.
# ---------------------------------------------------------------------------
def test_filter_mac_extraction() -> None:
    html = """<html><body>
    <table><tr><td>AA:BB:CC:DD:EE:01</td></tr></table>
    <form action="/x">
      <input type="hidden" name="filtertype" value="0">
      <input type="text" name="macaddr1" value="AA:BB:CC:DD:EE:02">
      <input type="checkbox" name="delmac" value="AA:BB:CC:DD:EE:03">
    </form>
    <a href="/x?macaddr=AA:BB:CC:DD:EE:04&action=delete">remove</a>
    </body></html>"""
    macs = filter_macs(html)
    wanted = {f"AA:BB:CC:DD:EE:0{i}" for i in range(1, 5)}
    check("extractor sees table + slots + checkbox + link", macs == wanted, str(sorted(macs)))

    page = parse_page(
        '<form action="/x"><select name="filtertype">'
        '<option value="0">Blacklist</option>'
        '<option value="1" selected>Whitelist</option></select></form>'
    )
    form = page.forms[0]
    check("option labels are parsed", form.options("filtertype")[1]["label"] == "Whitelist", str(form.options("filtertype")))
    check("selected option is used", form.selected_option("filtertype")["value"] == "1")


# ---------------------------------------------------------------------------
# Slot-based firmware: verify both directions, and never post the add form.
# ---------------------------------------------------------------------------
SLOT_PAGE = """<html><body><h2>MAC Filter</h2>
<form action="/boaform/admin/formWlanMacFilter" method="post">
<input type="hidden" name="submit-url" value="/x.asp">
<input type="hidden" name="filtertype" value="0">
<input type="text" name="macaddr1" value="{m1}">
<input type="text" name="macaddr2" value="">
<input type="checkbox" name="enable" value="1" checked>
<input type="submit" name="add" value="Add">
<input type="submit" name="del" value="Delete">
</form></body></html>"""


def make_slot_router(delete_works: bool):
    mac = "AA:BB:CC:DD:EE:FF"
    state = {"html": SLOT_PAGE.format(m1=mac)}
    router = HuaweiRouter("http://192.168.1.1", timeout=2)
    router.logged_in = True
    router._filter_page = "/html/ssmp/macfilter/macfilter.asp"
    router._crawled = True
    router.get = lambda _path: state["html"]

    def post(_path, data, referer=""):
        fields = dict(data)
        if "add" in fields:
            for name in ("macaddr1", "macaddr2"):
                marker = f'name="{name}" value=""'
                if marker in state["html"] and fields.get(name):
                    state["html"] = state["html"].replace(
                        marker, f'name="{name}" value="{fields[name]}"'
                    )
                    break
        if "del" in fields and delete_works:
            state["html"] = state["html"].replace(mac, "")
        return "<ok>"

    router.post = post
    return router, state, mac


def test_slot_verification() -> None:
    # A delete the router silently ignored must not report success.
    router, state, mac = make_slot_router(delete_works=False)
    ok, msg = router.set_block(mac, False)
    check("silent delete failure is a failure", ok is False and "did not apply" in msg.lower(), msg)
    check("silent delete really left the MAC", mac in filter_macs(state["html"]))

    # A successful add into an empty slot must be verified as success.
    router, state, _mac = make_slot_router(delete_works=True)
    new_mac = "11:22:33:44:55:66"
    ok, msg = router.set_block(new_mac, True)
    check("slot-based add verifies", ok is True and "verified" in msg.lower(), msg)
    check("slot-based add reached the page", new_mac in filter_macs(state["html"]))


DELETE_PAGE = """<html><body>
<table><tr><th>MAC Address</th></tr><tr><td>{mac}</td></tr></table>
<form action="/boaform/admin/formWlanMacFilter" method="post">
<input type="hidden" name="submit-url" value="/x.asp">
<input type="text" name="macaddr1" value="{mac}">
<input type="text" name="macaddr2" value="">
<input type="submit" name="add" value="Add">
</form>
<form action="/boaform/admin/formWlanMacFilter" method="post">
<input type="hidden" name="submit-url" value="/x.asp">
<input type="checkbox" name="delmac" value="{mac}">
<input type="submit" name="del" value="Delete">
</form></body></html>"""


def test_delete_chooses_delete_form() -> None:
    mac = "AA:BB:CC:DD:EE:FF"
    state = {"html": DELETE_PAGE.format(mac=mac)}
    posted: list[dict] = []
    router = HuaweiRouter("http://192.168.1.1", timeout=2)
    router.logged_in = True
    router._filter_page = "/html/ssmp/macfilter/macfilter.asp"
    router._crawled = True
    router.get = lambda _path: state["html"]

    def post(_path, data, referer=""):
        fields = dict(data)
        posted.append(fields)
        if "del" in fields:
            state["html"] = state["html"].replace(f"<tr><td>{mac}</td></tr>", "")
            state["html"] = state["html"].replace(f'value="{mac}"', 'value=""')
        return "<ok>"

    router.post = post
    ok, msg = router.set_block(mac, False)
    check("pre-filled add form does not swallow the unblock", ok is True, msg)
    check("only the delete form was posted", len(posted) == 1 and "del" in posted[0], str(posted))
    check("delete reached the page", mac not in filter_macs(state["html"]))


# ---------------------------------------------------------------------------
# Filter entries are not clients, and an unknown IP never erases a known one.
# ---------------------------------------------------------------------------
def test_filter_page_not_clients() -> None:
    original = mock_router.DHCP
    # A client page that mentions "MAC Filter" in its navigation must still
    # be treated as a client page.
    mock_router.DHCP = original.replace(
        "<h2>DHCP Information</h2>", '<a href="/x">MAC Filter</a><h2>DHCP Information</h2>'
    )
    server = MockRouter().start()
    try:
        ghost = "DE:AD:BE:EF:00:01"
        server.state.blocked.add(ghost)
        router = HuaweiRouter(server.url, timeout=5)
        router.login("excitel", "admin@123")
        clients = {c["mac"]: c for c in router.clients()}
        check("filter-only MAC is not a client", ghost not in clients, str(sorted(clients)))
        check("real clients still found", "16:4F:BD:EE:9C:3C" in clients, str(sorted(clients)))
        check("nav text does not hide the client page", router.info()["client_page"].endswith("dhcpinfo.asp"), str(router.info()))
        check("ghost is still blocked", ghost in router.blocked_macs())
    finally:
        server.stop()
        mock_router.DHCP = original


def test_store_preserves_ip() -> None:
    store = Store()
    mac = "DE:AD:BE:EF:00:01"
    store.merge_scan({mac: {"ip": "192.168.1.50", "hostname": "Old", "vendor": ""}})
    store.merge_scan({mac: {"ip": "", "hostname": "", "vendor": "", "connection": "", "online": True}})
    check("empty scan does not wipe stored IP", store.devices[mac].get("ip") == "192.168.1.50", str(store.devices[mac]))


# ---------------------------------------------------------------------------
# Gateway: routing table wins over ipconfig presentation order.
# ---------------------------------------------------------------------------
IPCONFIG_DNS = (
    "Wireless LAN adapter Wi-Fi:\n"
    "   Connection-specific DNS Suffix  . : lan\n"
    "   Physical Address. . . . . . . . . : C4-13-75-93-DD-29\n"
    "   IPv4 Address. . . . . . . . . . . : 192.168.1.36(Preferred)\n"
    "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
    "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
    "   DHCP Server . . . . . . . . . . . : 192.168.1.1\n"
    "   DNS Servers . . . . . . . . . . . : 192.168.1.2\n"
)
ROUTE_TEXT = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.36     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
"""


def test_gateway_from_route_table() -> None:
    gateway, iface_ip = netinfo.parse_default_route(ROUTE_TEXT)
    check("default route parsed", gateway == "192.168.1.1" and iface_ip == "192.168.1.36", f"{gateway}/{iface_ip}")

    iface = netinfo.list_interfaces(IPCONFIG_DNS, routes=ROUTE_TEXT)[0]
    check("DNS server is not the gateway", iface.gateway == "192.168.1.1", iface.gateway)

    # DNS listed *before* the gateway (split DNS) — route table still wins.
    split = IPCONFIG_DNS.replace(
        "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
        "   DHCP Server . . . . . . . . . . . : 192.168.1.1\n"
        "   DNS Servers . . . . . . . . . . . : 192.168.1.2\n",
        "   DNS Servers . . . . . . . . . . . : 192.168.1.2\n"
        "   Default Gateway . . . . . . . . . : 192.168.1.1\n",
    )
    iface2 = netinfo.list_interfaces(split, routes=ROUTE_TEXT)[0]
    check("route table beats line order", iface2.gateway == "192.168.1.1", iface2.gateway)

    # Two default routes: the lowest metric wins.
    two = (
        "          0.0.0.0          0.0.0.0       10.0.0.1       10.0.0.5     50\n"
        "          0.0.0.0          0.0.0.0     192.168.1.1   192.168.1.36     10\n"
    )
    check("lowest metric wins", netinfo.parse_default_route(two)[0] == "192.168.1.1")


# ---------------------------------------------------------------------------
# Export, elevation and Npcap flow.
# ---------------------------------------------------------------------------
def test_csv_sanitising() -> None:
    for evil in ("=cmd|' /c calc'!A1", "+1+1", "-2+3", "@SUM(A1)", "\t=1"):
        safe = appmod.csv_safe(evil)
        check(f"csv neutralises {evil[:12]!r}", safe.startswith("'"), safe)
    check("csv leaves normal text alone", appmod.csv_safe("Rahul's phone") == "Rahul's phone")
    check("csv leaves MAC/IP alone", appmod.csv_safe("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF")


class FakeShell:
    def __init__(self, result: int):
        self.result = result

    def ShellExecuteW(self, *_args):
        return self.result


def make_fake_app():
    class FakeApp:
        def __init__(self):
            self.closed = False
            self.logs: list[str] = []

        def _on_close(self):
            self.closed = True

        def log_line(self, message):
            self.logs.append(message)

    app = FakeApp()
    app._relaunch_admin = appmod.NetGuardApp._relaunch_admin.__get__(app)
    app._install_npcap = appmod.NetGuardApp._install_npcap.__get__(app)
    return app


def test_elevation_and_npcap() -> None:
    real_windll = ctypes.windll
    real_admin = appmod.is_admin
    real_error = appmod.messagebox.showerror
    errors: list[str] = []
    appmod.is_admin = lambda: False
    appmod.messagebox.showerror = lambda *a, **k: errors.append(str(a[1]) if len(a) > 1 else "")
    try:
        ctypes.windll = type("W", (), {"shell32": FakeShell(5)})()
        app = make_fake_app()
        app._relaunch_admin()
        check("failed elevation does not close the app", app.closed is False)
        check("failed elevation is reported", bool(errors), str(errors))

        ctypes.windll = type("W", (), {"shell32": FakeShell(42)})()
        app2 = make_fake_app()
        app2._relaunch_admin()
        check("successful elevation closes the old window", app2.closed is True)
    finally:
        ctypes.windll = real_windll
        appmod.is_admin = real_admin
        appmod.messagebox.showerror = real_error

    real_open = appmod.webbrowser.open
    opened: list[str] = []
    appmod.webbrowser.open = lambda url: opened.append(url) or True
    try:
        app3 = make_fake_app()
        app3._install_npcap()
        check("Npcap flow opens the official page", opened == ["https://npcap.com/#download"], str(opened))
        check("Npcap flow explains the next step", any("npcap.com" in line.lower() for line in app3.logs))
    finally:
        appmod.webbrowser.open = real_open


# ---------------------------------------------------------------------------
# ARP: recovery clears a stale error.
# ---------------------------------------------------------------------------
def test_arp_error_clears() -> None:
    iface = netinfo.Interface("Wi-Fi", "192.168.1.36", "255.255.255.0", "192.168.1.1",
                              "C4-13-75-93-DD-29", "Wi-Fi")
    real_readiness = arpblock.readiness
    arpblock.readiness = lambda _iface=None: (True, "")
    blocker = arpblock.ArpBlocker()
    blocker._resolve_iface = lambda *_a, **_k: "TEST"
    blocker._send = lambda _pkts: None
    blocker._last_error = "stale adapter failure"
    try:
        ok, msg = blocker.add("E2:93:95:08:18:57", "192.168.1.33", iface, "4C:AE:1C:21:30:29")
        check("successful add clears stale ARP error", ok and blocker.health()["last_error"] == "", msg)
    finally:
        blocker.stop()
        arpblock.readiness = real_readiness


# ---------------------------------------------------------------------------
# Identification: HTTPS pages and a syntactically valid HomeKit query.
# ---------------------------------------------------------------------------
def test_fingerprint_https_and_mdns() -> None:
    class FakeResponse:
        def getheader(self, name, default=""):
            return "nginx" if name.lower() == "server" else default

        def read(self, _n):
            return b"<html><title>HTTPS admin</title></html>"

    used: list[tuple] = []

    class FakeHTTPSConnection:
        def __init__(self, host, port, timeout=None, context=None):
            used.append((host, port, context is not None))

        def request(self, *_a, **_k):
            pass

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    real_https = fingerprint.http.client.HTTPSConnection
    fingerprint.http.client.HTTPSConnection = FakeHTTPSConnection
    try:
        notes = fingerprint._http_fingerprint("192.168.1.99", [443])
    finally:
        fingerprint.http.client.HTTPSConnection = real_https
    check("HTTPS port is actually probed", used and used[0][1] == 443 and used[0][2] is True, str(used))
    check("HTTPS page yields clues", any("nginx" in note for note in notes), str(notes))

    queries = fingerprint._MDNS_QUERIES
    check("HomeKit mDNS query is valid", "_hap._tcp.local." in queries, str(queries))
    check("mDNS labels fit one byte", all(len(part) <= 63 for q in queries for part in q.rstrip(".").split(".")))


def test_scan_error_and_corrupt_store() -> None:
    # C3: corrupt devices.json must not brick anything.
    import json as _json
    store_mod = __import__("netguard.store", fromlist=["Store"])
    s = Store.__new__(Store)
    s.config = dict(store_mod.DEFAULT_CONFIG)
    s.devices = {}
    real_path = store_mod.DEVICES_FILE
    tmp = tempfile.mkdtemp()
    store_mod.DEVICES_FILE = os.path.join(tmp, "devices.json")
    try:
        open(store_mod.DEVICES_FILE, "w").write("[]")
        s.load()
        check("list devices.json coerced to {}", s.devices == {}, str(s.devices))
        # non-dict record is replaced, not fatal
        open(store_mod.DEVICES_FILE, "w").write(_json.dumps({"AA:BB:CC:DD:EE:FF": "garbage"}))
        s.load()
        rec = s.record("AA:BB:CC:DD:EE:FF")
        check("non-dict record coerced", isinstance(rec, dict) and rec["blocked"] is False, str(rec))
    finally:
        store_mod.DEVICES_FILE = real_path

    # C1: scanner exception must not forge authoritative blocked=set().
    import inspect as _inspect
    src = _inspect.getsource(appmod.NetGuardApp._scan_worker)
    check("scanner error path passes router_ok=False", "_scan_done({}, {}, set(), m, 0, None, False" in src, "")

    # H1: non-default adapter must not invent a DNS-as-gateway.
    split = (
        "Wi-Fi:\n"
        "   IPv4 Address. . . : 192.168.1.36\n"
        "   Subnet Mask . . . : 255.255.255.0\n"
        "   Default Gateway . : 192.168.1.1\n"
        "   DNS Servers . . . : 192.168.1.2\n"
        "   Physical Address. : AA-BB-CC-DD-EE-FF\n"
    )
    routes = " 0.0.0.0 0.0.0.0 192.168.1.1 192.168.1.36 10\n"
    iface = netinfo.list_interfaces(split, routes=routes)[0]
    check("H1 default adapter keeps route gateway", iface.gateway == "192.168.1.1", iface.gateway)
    # A second NIC whose route belongs to Wi-Fi gets NO invented gateway.
    split2 = split + (
        "\nEthernet:\n"
        "   IPv4 Address. . . : 172.16.0.5\n"
        "   Subnet Mask . . . : 255.255.255.0\n"
        "   DNS Servers . . . : 172.16.0.2\n"
        "   Physical Address. : 11-22-33-44-55-66\n"
    )
    ifaces = netinfo.list_interfaces(split2, routes=routes)
    eth = [i for i in ifaces if i.ip == "172.16.0.5"][0]
    check("H1 non-default adapter gets no DNS gateway", eth.gateway == "", eth.gateway)


def main() -> int:
    test_session_expiry()
    test_http_error_is_not_empty()
    test_filter_mode_options()
    test_filter_mac_extraction()
    test_slot_verification()
    test_delete_chooses_delete_form()
    test_filter_page_not_clients()
    test_store_preserves_ip()
    test_gateway_from_route_table()
    test_csv_sanitising()
    test_elevation_and_npcap()
    test_arp_error_clears()
    test_fingerprint_https_and_mdns()
    test_scan_error_and_corrupt_store()

    print()
    print("FAILED: " + ", ".join(FAILS) if FAILS else "ALL REGRESSION TESTS PASSED")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
