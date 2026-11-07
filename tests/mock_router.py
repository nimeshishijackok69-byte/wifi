"""A tiny fake Huawei ONT used to test the router adapter offline.

It imitates the parts of the Boa firmware that NetGuard relies on:
session cookie, CSRF token login, a client list page, and a MAC filter page
with add form + per-row delete checkboxes.
"""

from __future__ import annotations

import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOGIN_PAGE = """<html><body>
<form action="/boaform/admin/formLogin" method="POST">
<input type="text" name="username1">
<input type="password" name="psd1">
<input type="hidden" name="username" value="">
<input type="hidden" name="psd" value="">
<input type='hidden' name='csrftoken' value='{token}' />
</form></body></html>"""

FRAME = """<html><frameset>
<frame src="/html/ssmp/menu.asp">
<frame src="/html/ssmp/dhcpinfo/dhcpinfo.asp">
</frameset></html>"""

MENU = """<html><body>
<a href="/html/ssmp/dhcpinfo/dhcpinfo.asp">DHCP Information</a>
<a href="/html/ssmp/macfilter/macfilter.asp">MAC Filter</a>
</body></html>"""

DHCP = """<html><body><h2>DHCP Information</h2>
<table border=1>
<tr><th>Index</th><th>Host Name</th><th>IP Address</th><th>MAC Address</th><th>Interface</th></tr>
{rows}
</table></body></html>"""

FILTER = """<html><body><h2>MAC Filter</h2>
<table border=1><tr><th>MAC Address</th></tr>{blocked}</table>
<form action="/boaform/admin/formWlanMacFilter" method="post">
<input type="hidden" name="submit-url" value="/html/ssmp/macfilter/macfilter.asp">
<input type="hidden" name="filtertype" value="0">
<input type="text" name="macaddr1" value="">
<input type="text" name="macaddr2" value="">
<input type="submit" name="add" value="Add">
</form>
<form action="/boaform/admin/formWlanMacFilter" method="post">
<input type="hidden" name="submit-url" value="/html/ssmp/macfilter/macfilter.asp">
{checkboxes}
<input type="submit" name="del" value="Delete">
</form>
</body></html>"""


class State:
    def __init__(self):
        self.user = "excitel"
        self.password = "admin@123"
        self.token = "tok123"
        self.sessions: set[str] = set()
        self.clients = [
            ("DESKTOP-IG27U9C", "192.168.1.36", "C4:13:75:93:DD:29", "WLAN"),
            ("Rahuls-Phone", "192.168.1.34", "16:4F:BD:EE:9C:3C", "WLAN"),
            ("Smart-TV", "192.168.1.43", "56:C9:E9:15:AF:05", "LAN"),
        ]
        self.blocked: set[str] = set()


class Handler(BaseHTTPRequestHandler):
    state: State

    def log_message(self, *_args):
        pass

    def _send(self, body: str, code: int = 200, headers=None):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                name, _, value = part.partition("=")
                if name.strip() == "session":
                    return value.strip()
        return ""

    def _authed(self) -> bool:
        return self._cookie() in self.state.sessions

    def do_GET(self):  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        s = self.state
        if path in ("/", "/admin/login.asp"):
            return self._send(LOGIN_PAGE.format(token=s.token))
        if not self._authed():
            return self._send("", 302, {"Location": "/admin/login.asp"})
        if path == "/html/ssmp/frame.asp":
            return self._send(FRAME)
        if path == "/html/ssmp/menu.asp":
            return self._send(MENU)
        if path == "/html/ssmp/dhcpinfo/dhcpinfo.asp":
            rows = "".join(
                f"<tr><td>{i}</td><td>{h}</td><td>{ip}</td><td>{mac}</td><td>{iface}</td></tr>"
                for i, (h, ip, mac, iface) in enumerate(s.clients, 1)
            )
            return self._send(DHCP.format(rows=rows))
        if path == "/html/ssmp/macfilter/macfilter.asp":
            blocked = "".join(f"<tr><td>{m}</td></tr>" for m in sorted(s.blocked))
            checks = "".join(
                f'<input type="checkbox" name="delmac" value="{m}">{m}<br>' for m in sorted(s.blocked)
            )
            return self._send(FILTER.format(blocked=blocked, checkboxes=checks))
        return self._send("", 404)

    def do_POST(self):  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode()
        fields = urllib.parse.parse_qs(raw, keep_blank_values=True)
        s = self.state

        if path == "/boaform/admin/formLogin":
            user = fields.get("username", [""])[0]
            pwd = fields.get("psd", [""])[0]
            if fields.get("csrftoken", [""])[0] != s.token:
                return self._send("<h4>ERROR:bad csrf</h4>")
            if user != s.user:
                return self._send("<h4>ERROR:invalid username!</h4>")
            if pwd != s.password:
                return self._send("<h4>ERROR:bad password!</h4>")
            token = "sess%d" % (len(s.sessions) + 1)
            s.sessions.add(token)
            return self._send(
                "<html><script>top.location.href='/html/ssmp/frame.asp'</script></html>",
                headers={"Set-Cookie": f"session={token}; Path=/"},
            )

        if not self._authed():
            return self._send("", 302, {"Location": "/admin/login.asp"})

        if path == "/boaform/admin/formWlanMacFilter":
            if "add" in fields:
                for key, values in fields.items():
                    if key.lower().startswith("macaddr"):
                        for value in values:
                            if value.strip():
                                s.blocked.add(value.strip().upper().replace("-", ":"))
            if "del" in fields:
                for value in fields.get("delmac", []):
                    s.blocked.discard(value.strip().upper().replace("-", ":"))
            return self._send(
                "", 302, {"Location": "/html/ssmp/macfilter/macfilter.asp"}
            )
        return self._send("", 404)


class MockRouter:
    def __init__(self):
        self.state = State()
        handler = type("BoundHandler", (Handler,), {"state": self.state})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def start(self) -> "MockRouter":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
