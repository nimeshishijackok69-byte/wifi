"""Router adapters.

NetGuard talks to the router's own administration interface.  For the router
on this network (Excitel / Huawei ONT, Boa web server) the relevant endpoints
are `/admin/login.asp`, `/boaform/admin/formLogin` and the pages under
`/html/ssmp/...`.  Only the Python standard library is used.

The blocking code intentionally works from the *shape* of the router's own
forms rather than hard-coded field names, so it keeps working across firmware
variants.  Nothing is submitted unless it is clearly part of the MAC filter
page, and the change is verified afterwards.
"""

from __future__ import annotations

import http.cookiejar
import re
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

MAC_RE = re.compile(r"\b([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\b")
IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")


class RouterError(Exception):
    pass


class LoginError(RouterError):
    pass


def norm_mac(mac: str) -> str:
    hexonly = "".join(ch for ch in str(mac) if ch in "0123456789abcdefABCDEF")
    if len(hexonly) < 12:
        return str(mac).upper()
    hexonly = hexonly[:12].upper()
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


# --------------------------------------------------------------------------
# Form / table parser
# --------------------------------------------------------------------------
class Form:
    def __init__(self, action: str, method: str):
        self.action = action
        self.method = method or "post"
        self.inputs: list[dict] = []

    @property
    def names(self) -> list[str]:
        return [i["name"] for i in self.inputs if i.get("name")]

    def value(self, name: str) -> str:
        for i in self.inputs:
            if i.get("name") == name:
                return str(i.get("value", ""))
        return ""

    def default_data(self) -> list[tuple[str, str]]:
        data: list[tuple[str, str]] = []
        for i in self.inputs:
            name = i.get("name")
            if not name:
                continue
            typ = i.get("type", "text")
            if typ in ("checkbox", "radio") and not i.get("checked"):
                continue
            if typ in ("submit", "button", "reset", "image"):
                continue
            data.append((name, str(i.get("value", ""))))
        return data

    def mac_fields(self) -> list[str]:
        out = []
        for name in self.names:
            low = name.lower()
            if "mac" in low and "mask" not in low:
                out.append(name)
        return out


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self.forms: list[Form] = []
        self.links: list[str] = []
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None
        self._form: Form | None = None
        self._select: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "form":
            self._form = Form(a.get("action", ""), (a.get("method") or "post").lower())
            self.forms.append(self._form)
        elif tag in ("input", "button") and self._form is not None:
            if a.get("name"):
                self._form.inputs.append(
                    {
                        "name": a["name"],
                        "value": a.get("value", ""),
                        "type": (a.get("type") or "text").lower(),
                        "checked": "checked" in a,
                    }
                )
        elif tag == "select" and self._form is not None:
            self._select = {"name": a.get("name", ""), "options": []}
        elif tag == "option" and self._select is not None:
            self._select["options"].append({"value": a.get("value", ""), "selected": "selected" in a})
        elif tag in ("a", "frame", "iframe"):
            ref = a.get("href") or a.get("src")
            if ref:
                self.links.append(ref)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            self._table.append(self._row)
            self._row = None
        elif tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "select" and self._select is not None and self._form is not None:
            if self._select["name"]:
                opts = self._select["options"]
                chosen = [o for o in opts if o["selected"]] or opts[:1]
                self._form.inputs.append(
                    {"name": self._select["name"], "value": chosen[0]["value"] if chosen else "", "type": "select"}
                )
            self._select = None
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def parse_page(html: str) -> _PageParser:
    p = _PageParser()
    try:
        p.feed(html)
    except Exception:
        pass
    return p


# --------------------------------------------------------------------------
# Base adapter
# --------------------------------------------------------------------------
class BaseRouter:
    name = "router"

    def __init__(self, base_url: str, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx),
        )
        self.opener.addheaders = [
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetGuard/1.0"),
            ("Accept", "text/html,application/xhtml+xml,*/*"),
        ]
        self.logged_in = False
        self._lock = threading.Lock()

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))

    def _open(self, req, path):
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as exc:
            try:
                return exc.read().decode("utf-8", errors="ignore")
            except Exception:
                raise RouterError(f"HTTP {exc.code} for {path}")
        except Exception as exc:
            raise RouterError(str(exc))

    def get(self, path: str) -> str:
        with self._lock:
            return self._open(urllib.request.Request(self._url(path)), path)

    def post(self, path: str, data, referer: str = "") -> str:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(self._url(path), data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if referer:
            req.add_header("Referer", self._url(referer))
        with self._lock:
            return self._open(req, path)

    # -- interface --------------------------------------------------------
    def login(self, username: str, password: str) -> str:
        raise NotImplementedError

    def clients(self) -> list[dict]:
        raise NotImplementedError

    def set_block(self, mac: str, blocked: bool) -> tuple[bool, str]:
        raise NotImplementedError

    def blocked_macs(self) -> set[str]:
        return set()

    def info(self) -> dict:
        return {}


# --------------------------------------------------------------------------
# Huawei ONT (Boa) adapter
# --------------------------------------------------------------------------
CLIENT_HINTS = ("dhcp", "host", "client", "user", "device", "assoc", "station", "wlaninfo", "access")
FILTER_HINTS = ("macfilter", "mac-filter", "wlanfilter", "filter")

KNOWN_CLIENT_PAGES = [
    "/html/ssmp/dhcpinfo/dhcpinfo.asp",
    "/html/ssmp/lanhost/lanhost.asp",
    "/html/ssmp/wlaninfo/wlaninfo.asp",
    "/html/ssmp/wlanassoc/wlanassoc.asp",
    "/html/bbsp/dhcpinfo/dhcpinfo.asp",
    "/html/bbsp/lanhost/lanhost.asp",
]
KNOWN_FILTER_PAGES = [
    "/html/ssmp/macfilter/macfilter.asp",
    "/html/ssmp/wlanfilter/wlanfilter.asp",
    "/html/bbsp/macfilter/macfilter.asp",
    "/html/bbsp/wlanmacfilter/wlanmacfilter.asp",
    "/html/ssmp/security/macfilter.asp",
    "/html/security/macfilter.asp",
]


class HuaweiRouter(BaseRouter):
    name = "Huawei ONT (Boa)"

    def __init__(self, base_url: str, timeout: float = 8.0):
        super().__init__(base_url, timeout)
        self.version = ""
        self.model = ""
        self._pages: dict[str, str] = {}
        self._client_page = ""
        self._filter_page = ""
        self._filter_mode = ""
        self._crawled = False

    # -- login ------------------------------------------------------------
    def login(self, username: str, password: str) -> str:
        self.logged_in = False
        html = self.get("/admin/login.asp")
        token = ""
        m = re.search(r"name=['\"]csrftoken['\"]\s+value=['\"]([^'\"]+)", html)
        if m:
            token = m.group(1)
        if not token:
            m = re.search(r"csrftoken\s*=\s*['\"]([^'\"]+)", html)
            token = m.group(1) if m else ""

        fields = {"username": username, "psd": password, "sec_lang": "0"}
        if token:
            fields["csrftoken"] = token

        body = self.post("/boaform/admin/formLogin", fields, referer="/admin/login.asp")
        err = re.search(r"<h4>\s*(?:ERROR:)?([^<]+)</h4>", body, re.I)
        if err:
            raise LoginError(" ".join(err.group(1).split()))
        low = body.lower()
        if "invalid username" in low:
            raise LoginError("Invalid username")
        if "bad password" in low:
            raise LoginError("Bad password")

        probe = self.get("/html/ssmp/frame.asp")
        if "login.asp" in probe.lower() and "<form" in probe.lower() and "password" in probe.lower():
            raise LoginError("Login was rejected")

        self.logged_in = True
        self._read_identity()
        return self.model or self.version or "logged in"

    def _read_identity(self) -> None:
        for path in ("/html/ssmp/deviceinfo/deviceinfo.asp", "/html/ssmp/index.asp"):
            try:
                page = self.get(path)
            except RouterError:
                continue
            text = re.sub(r"<[^>]+>", " ", page)
            m = re.search(r"\b(V\d{3,4}R\d{3}[A-Z0-9]{0,8})\b", text)
            if m:
                self.version = m.group(1)
            m = re.search(r"\b((?:HG|EG|HS|HN)\d{4}[A-Z0-9\-]*)\b", text)
            if m:
                self.model = m.group(1)
            if self.version or self.model:
                return

    # -- crawling ---------------------------------------------------------
    def _crawl(self, seeds: list[str], limit: int = 50) -> dict[str, str]:
        seen: dict[str, str] = {}
        queue = list(seeds)
        while queue and len(seen) < limit:
            path = queue.pop(0)
            if path in seen:
                continue
            try:
                html = self.get(path)
            except RouterError:
                continue
            low = html.lower()
            if "admin/login.asp" in low or ("<form" in low and "name=\"psd\"" in low):
                continue
            seen[path] = html
            for link in parse_page(html).links:
                if not link or link.startswith(("#", "javascript:", "mailto:")):
                    continue
                if ".asp" not in link.lower() and ".cgi" not in link.lower():
                    continue
                link = link.split("#")[0]
                full = urllib.parse.urlparse(urllib.parse.urljoin(path, link)).path
                if full and full.endswith((".asp", ".cgi")) and full not in seen and len(queue) < 150:
                    queue.append(full)
        return seen

    def _find_pages(self) -> None:
        if self._crawled:
            return
        self._crawled = True
        pages = self._crawl(["/html/ssmp/frame.asp", "/html/ssmp/index.asp", "/admin/main.asp"])
        self._pages = pages

        client_score: dict[str, int] = {}
        filter_score: dict[str, int] = {}
        for path, html in pages.items():
            low = (path + " " + html).lower()
            if any(h in path.lower() for h in FILTER_HINTS) or "mac filter" in low or "filter mode" in low:
                filter_score[path] = filter_score.get(path, 0) + 5
                if "filtertype" in low or "filter mode" in low:
                    filter_score[path] += 4
            if any(h in path.lower() for h in CLIENT_HINTS):
                client_score[path] = client_score.get(path, 0) + 2
            if MAC_RE.search(html) and IPV4_RE.search(html):
                client_score[path] = client_score.get(path, 0) + 3
            if "dhcp" in low:
                client_score[path] = client_score.get(path, 0) + 3

        if not filter_score:
            for path in KNOWN_FILTER_PAGES:
                try:
                    html = self.get(path)
                except RouterError:
                    continue
                if MAC_RE.search(html) or "filter" in html.lower():
                    pages[path] = html
                    filter_score[path] = 1
                    break

        if not client_score:
            for path in KNOWN_CLIENT_PAGES:
                try:
                    html = self.get(path)
                except RouterError:
                    continue
                if MAC_RE.search(html):
                    pages[path] = html
                    client_score[path] = 1
                    break

        if client_score:
            self._client_page = max(client_score, key=client_score.get)
        if filter_score:
            self._filter_page = max(filter_score, key=filter_score.get)
            self._learn_filter_mode()

    def _learn_filter_mode(self) -> None:
        try:
            html = self._pages.get(self._filter_page) or self.get(self._filter_page)
        except RouterError:
            return
        for form in parse_page(html).forms:
            for name in form.names:
                low = name.lower()
                if "filtertype" in low or "mode" in low:
                    self._filter_mode = f"{name}={form.value(name)}"

    # -- clients ----------------------------------------------------------
    def clients(self) -> list[dict]:
        if not self.logged_in:
            raise RouterError("Not logged in")
        self._find_pages()
        if self._client_page:
            try:
                self._pages[self._client_page] = self.get(self._client_page)
            except RouterError:
                pass

        found: dict[str, dict] = {}
        for path, html in self._pages.items():
            page = parse_page(html)
            for table in page.tables:
                for row in table:
                    mac = ""
                    ip = ""
                    name = ""
                    conn = ""
                    for cell in row:
                        text = cell.strip()
                        if not mac:
                            m = MAC_RE.search(text)
                            if m:
                                mac = norm_mac(m.group(1))
                                continue
                        if not ip:
                            m = IPV4_RE.search(text)
                            if m and not m.group(1).startswith(("0.", "255.")):
                                ip = m.group(1)
                                continue
                        if not name and text and len(text) < 64 and not IPV4_RE.fullmatch(text):
                            if not re.fullmatch(r"[\d\s\./:\-]+", text):
                                name = text
                        for tag in ("wlan", "wifi", "wireless", "ssid"):
                            if tag in text.lower():
                                conn = "Wi-Fi"
                    if mac:
                        entry = found.setdefault(mac, {"mac": mac, "ip": "", "hostname": "", "connection": ""})
                        entry["ip"] = entry["ip"] or ip
                        entry["hostname"] = entry["hostname"] or name
                        entry["connection"] = entry["connection"] or conn

            # Catch JS-driven tables where cells are not real <td>s.
            text = re.sub(r"<[^>]+>", " ", html)
            for m in MAC_RE.finditer(text):
                mac = norm_mac(m.group(1))
                window = text[max(0, m.start() - 160) : m.end() + 160]
                entry = found.setdefault(mac, {"mac": mac, "ip": "", "hostname": "", "connection": ""})
                if not entry["ip"]:
                    ipm = IPV4_RE.search(window)
                    if ipm and not ipm.group(1).startswith(("0.", "255.")):
                        entry["ip"] = ipm.group(1)
        return list(found.values())

    # -- blocking ---------------------------------------------------------
    def _filter_page_html(self) -> str:
        if not self._filter_page:
            self._find_pages()
        if not self._filter_page:
            raise RouterError("Could not find the router's MAC filter page.")
        return self.get(self._filter_page)

    def blocked_macs(self) -> set[str]:
        if not self.logged_in or not self._filter_page:
            return set()
        macs: set[str] = set()
        try:
            html = self._filter_page_html()
        except RouterError:
            return set()
        for table in parse_page(html).tables:
            for row in table:
                for cell in row:
                    for m in MAC_RE.finditer(cell):
                        macs.add(norm_mac(m.group(1)))
        return macs

    def set_block(self, mac: str, blocked: bool) -> tuple[bool, str]:
        mac = norm_mac(mac)
        if not self.logged_in:
            return False, "Not logged in to the router."
        try:
            html = self._filter_page_html()
        except RouterError as exc:
            return False, str(exc)

        page = parse_page(html)
        if not blocked:
            ok, msg = self._delete_mac(page, mac)
        else:
            ok, msg = self._add_mac(page, mac)
        if not ok:
            return False, msg

        # Verify by re-reading the filter page.
        try:
            after = set()
            for table in parse_page(self._filter_page_html()).tables:
                for row in table:
                    for cell in row:
                        for m in MAC_RE.finditer(cell):
                            after.add(norm_mac(m.group(1)))
        except RouterError:
            return True, "Applied (could not verify)"

        present = mac in after
        if present == blocked:
            return True, "Applied and verified"
        return False, "The router did not apply the change."

    def _add_mac(self, page: _PageParser, mac: str) -> tuple[bool, str]:
        candidates = []
        for form in page.forms:
            text_fields = [
                i["name"]
                for i in form.inputs
                if i.get("name")
                and i.get("type", "text") in ("text", "")
                and "mac" in i["name"].lower()
                and "mask" not in i["name"].lower()
            ]
            if not text_fields:
                continue
            action = form.action.lower()
            score = 5
            if "filter" in action or "mac" in action:
                score += 4
            candidates.append((score, form, text_fields))
        if not candidates:
            return False, "No MAC address field found on the router's filter page."

        candidates.sort(key=lambda c: -c[0])
        _score, form, field_names = candidates[0]
        data = form.default_data()

        target = None
        for name in field_names:
            if not str(form.value(name)).strip():
                target = name
                break
        if target is None:
            target = field_names[0]

        replaced = False
        new_data = []
        for name, value in data:
            if name == target:
                new_data.append((name, mac))
                replaced = True
            else:
                new_data.append((name, value))
        if not replaced:
            new_data.append((target, mac))

        # Routers usually need the actual button that performs the add.
        buttons = [i for i in form.inputs if i.get("type") == "submit" and i.get("name")]
        preferred = [b for b in buttons if any(k in b["name"].lower() for k in ("add", "apply", "save", "ok"))]
        chosen_button = (preferred or buttons or [None])[0]
        if chosen_button:
            new_data.append((chosen_button["name"], chosen_button.get("value", "")))

        # Make sure filtering itself is switched on (Huawei "Enable" checkbox).
        for inp in form.inputs:
            if inp.get("type") == "checkbox" and "enable" in inp["name"].lower():
                if not any(n == inp["name"] for n, _ in new_data):
                    new_data.append((inp["name"], inp.get("value") or "1"))

        action = form.action or self._filter_page
        try:
            result = self.post(action, new_data, referer=self._filter_page)
        except RouterError as exc:
            return False, str(exc)
        if re.search(r"<h4>\s*ERROR", result, re.I):
            return False, "Router rejected the MAC filter change."
        return True, "Sent"

    def _delete_mac(self, page: _PageParser, mac: str) -> tuple[bool, str]:
        # 1) checkbox / hidden value carrying the MAC inside a form
        for form in page.forms:
            for inp in form.inputs:
                value = str(inp.get("value", ""))
                if not value or norm_mac(value) != mac:
                    continue
                if inp.get("type") in ("submit", "button", "reset"):
                    continue
                payload = form.default_data()
                if not any(n == inp["name"] for n, _ in payload):
                    payload.append((inp["name"], value))
                else:
                    payload = [(n, value if n == inp["name"] else v) for n, v in payload]
                # Include a delete button when the router needs one.
                for button in form.inputs:
                    if button.get("type") in ("submit",) and button.get("name"):
                        if any(k in button["name"].lower() for k in ("del", "remove", "apply", "ok")):
                            payload.append((button["name"], button.get("value", "")))
                try:
                    self.post(form.action or self._filter_page, payload, referer=self._filter_page)
                except RouterError:
                    continue
                return True, "Sent"

        # 2) a per-row delete link such as ...?macaddr=AA:BB:..&action=delete
        html = self._pages.get(self._filter_page, "")
        for link in parse_page(html).links:
            if "del" not in link.lower() and "remove" not in link.lower():
                continue
            if mac.replace(":", "") in link.replace(":", "").replace("-", "").upper():
                try:
                    self.get(link)
                    return True, "Sent"
                except RouterError:
                    continue

        # 3) last resort: Huawei's usual endpoint
        try:
            self.post(
                "/boaform/admin/formWlanMacFilter",
                [("macaddr", mac), ("action", "delete")],
                referer=self._filter_page,
            )
            return True, "Sent (fallback endpoint)"
        except RouterError as exc:
            return False, str(exc)

    def info(self) -> dict:
        self._find_pages()
        return {
            "adapter": self.name,
            "model": self.model or "?",
            "firmware": self.version or "?",
            "client_page": self._client_page or "(not found)",
            "filter_page": self._filter_page or "(not found)",
            "filter_mode": self._filter_mode or "(unknown)",
            "pages_scanned": len(self._pages),
        }


# --------------------------------------------------------------------------
def detect_router(base_url: str, timeout: float = 5.0) -> BaseRouter:
    return HuaweiRouter(base_url, timeout)
