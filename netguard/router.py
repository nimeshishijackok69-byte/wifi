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


def valid_ipv4(ip: str) -> bool:
    """True only for dotted quads with every octet in 0-255."""
    try:
        parts = str(ip).split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except Exception:
        return False


class RouterError(Exception):
    pass


class LoginError(RouterError):
    pass


class SessionExpired(RouterError):
    """The router answered with its login page instead of real content.

    A dropped session must never look like a successful read: returning an
    empty page would make the UI show every blocked device as unblocked.
    """


# Explicit mode wording only.  "Whitelist" appearing as one *unselected*
# option must not switch the semantics — see _learn_filter_mode().
_ALLOW_RE = re.compile(
    r"\b(?:white[\s_-]*list|allow[\s_-]*list|permit[\s_-]*list|allowed[\s_-]*list)\b",
    re.I,
)
_BLOCK_RE = re.compile(
    r"\b(?:black[\s_-]*list|block[\s_-]*list|deny[\s_-]*list|denied[\s_-]*list)\b",
    re.I,
)


def _mode_word(text: str) -> str:
    text = text or ""
    if _ALLOW_RE.search(text):
        return "allow"
    if _BLOCK_RE.search(text):
        return "block"
    return ""


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
        self.selects: dict[str, list[dict]] = {}

    @property
    def names(self) -> list[str]:
        return [i["name"] for i in self.inputs if i.get("name")]

    def value(self, name: str) -> str:
        for i in self.inputs:
            if i.get("name") == name:
                return str(i.get("value", ""))
        return ""

    def options(self, name: str) -> list[dict]:
        return self.selects.get(name, [])

    def selected_option(self, name: str) -> dict | None:
        """The option the browser would submit, with its human label."""
        options = self.options(name)
        for option in options:
            if option.get("selected"):
                return option
        chosen = self.value(name)
        for option in options:
            if str(option.get("value", "")) == chosen:
                return option
        return options[0] if options else None

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
        self._option: dict | None = None

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
            self._option = {
                "value": a.get("value", ""),
                "selected": "selected" in a,
                "label": "",
            }
            self._select["options"].append(self._option)
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
        elif tag == "option":
            if self._option is not None:
                self._option["label"] = " ".join(self._option["label"].split())
                self._option = None
        elif tag == "select" and self._select is not None and self._form is not None:
            if self._select["name"]:
                opts = self._select["options"]
                chosen = [o for o in opts if o["selected"]] or opts[:1]
                self._form.selects[self._select["name"]] = [dict(o) for o in opts]
                self._form.inputs.append(
                    {"name": self._select["name"], "value": chosen[0]["value"] if chosen else "", "type": "select"}
                )
            self._select = None
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._option is not None:
            self._option["label"] += data
        if self._cell is not None:
            self._cell.append(data)


def parse_page(html: str) -> _PageParser:
    p = _PageParser()
    try:
        p.feed(html)
    except Exception:
        pass
    return p


def filter_macs(html: str) -> set[str]:
    """Every MAC the filter page is actually holding.

    Firmware represents the same list in one of three places: a table row, a
    text slot in the add/edit form, or a per-row delete checkbox/link.  The
    old code only read tables, so on slot-based firmware verification was
    blind: a failed unblock reported "Applied and verified" and a successful
    block reported "the router did not apply the change".
    """
    page = parse_page(html)
    macs: set[str] = set()

    for table in page.tables:
        for row in table:
            for cell in row:
                for match in MAC_RE.finditer(cell):
                    macs.add(norm_mac(match.group(1)))

    for form in page.forms:
        for inp in form.inputs:
            kind = str(inp.get("type", "")).lower()
            if kind in ("submit", "button", "reset", "image"):
                continue
            for match in MAC_RE.finditer(str(inp.get("value", ""))):
                macs.add(norm_mac(match.group(1)))

    # Per-row delete links (…?macaddr=AA:BB:…&action=delete).
    for link in page.links:
        low = link.lower()
        if not any(word in low for word in ("del", "remove", "action=delete")):
            continue
        for match in MAC_RE.finditer(link):
            macs.add(norm_mac(match.group(1)))

    return macs


def _delete_form_score(form: Form, mac: str) -> int:
    """How strongly a form looks like *the* delete control for ``mac``.

    An add form can also contain the MAC (firmware pre-fills its slots), so
    the presence of a MAC alone is not enough.  Explicit delete controls win;
    an "Add" button is a strong signal that the form is not a delete form.
    """
    score = 0
    action = (form.action or "").lower()
    if any(word in action for word in ("del", "remove", "delete")):
        score += 6

    has_add_button = False
    for inp in form.inputs:
        name = str(inp.get("name", "")).lower()
        kind = str(inp.get("type", "text")).lower()
        value = str(inp.get("value", ""))
        if kind in ("submit", "button", "reset", "image"):
            if any(word in name for word in ("del", "remove")):
                score += 10
            elif "add" in name:
                has_add_button = True
            continue
        if norm_mac(value) != mac:
            continue
        if any(word in name for word in ("del", "remove")):
            score += 9
        elif kind in ("checkbox", "radio"):
            score += 8
        elif "mac" in name:
            score += 1

    if has_add_button:
        score -= 4
    return score


# --------------------------------------------------------------------------
# Base adapter
# --------------------------------------------------------------------------
class BaseRouter:
    name = "router"

    def __init__(self, base_url: str, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        # Router credentials traverse this opener, so TLS must be authenticated.
        # Keep SSL verification and hostname checking enabled rather than
        # trusting arbitrary certificates on the local network.
        ctx = ssl.create_default_context()
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
        """Return ``(body, status, final_url)``; never hide an HTTP error."""
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                status = int(getattr(resp, "status", 200) or 200)
                return body, status, resp.geturl()
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return body, int(exc.code), getattr(exc, "url", path) or path
        except Exception as exc:
            raise RouterError(str(exc))

    @staticmethod
    def _is_login_request(path: str) -> bool:
        low = (path or "").lower()
        return "login.asp" in low or "formlogin" in low

    @staticmethod
    def _looks_like_login(url: str, body: str) -> bool:
        """Recognise a router login form without mistaking an account page.

        The password-change page on Huawei Boa firmware also uses ``psd`` and
        ``psd1`` fields, so a bare ``name="psd"`` is not evidence of a dead
        session.  A login form is instead identified by its form-login
        destination (or a username/password pair posted like the Boa login).
        """
        if "login.asp" in (url or "").lower():
            return True
        try:
            page = parse_page(body or "")
        except Exception:
            return False
        for form in page.forms:
            action = (form.action or "").lower()
            names = {str(inp.get("name", "")).lower() for inp in form.inputs}
            has_login_target = "formlogin" in action or "login" in action
            has_username = bool(names & {"username", "username1", "user", "userid"})
            has_password = bool(names & {"psd", "psd1", "password", "passwd", "pwd"})
            if has_login_target and has_password:
                return True
            if "csrftoken" in names and has_username and has_password:
                return True
        return False

    def _request(self, req, path: str) -> str:
        body, status, final_url = self._open(req, path)
        if status >= 400:
            raise RouterError(f"Router returned HTTP {status} for {path}")
        # Most Boa/Huawei firmware answers an expired cookie with a 302 to the
        # login page, which urllib follows, so the status is 200 and the body
        # is a login form.  Treat that as a dead session, never as content.
        if not self._is_login_request(path) and self._looks_like_login(final_url, body):
            self.logged_in = False
            raise SessionExpired(f"Router session expired (login page returned for {path}).")
        return body

    def get(self, path: str) -> str:
        with self._lock:
            return self._request(urllib.request.Request(self._url(path)), path)

    def post(self, path: str, data, referer: str = "") -> str:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(self._url(path), data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if referer:
            req.add_header("Referer", self._url(referer))
        with self._lock:
            return self._request(req, path)

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
        self._filter_semantics = ""  # "allow" | "block" | ""
        self._crawled = False
        # Credentials are kept in memory only so a dropped session can be
        # re-established without asking the user again (Fix 3).
        self._user = ""
        self._password = ""

    # -- login ------------------------------------------------------------
    def login(self, username: str, password: str) -> str:
        self.logged_in = False
        self._user = username
        self._password = password
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

        try:
            probe = self.get("/html/ssmp/frame.asp")
        except SessionExpired as exc:
            raise LoginError("Login was rejected") from exc
        if self._looks_like_login("", probe):
            raise LoginError("Login was rejected")
        # H4: success must be POSITIVE, not "not a login shape". A firmware
        # re-rendering the login form with name="password" would otherwise
        # be accepted as logged-in, and every later read would be empty.
        _low_probe = probe.lower()
        if not any(m in _low_probe for m in ("menu", "dhcp", "frame", "ssmp", ".asp")):
            raise LoginError("Login was rejected")

        self.logged_in = True
        self._read_identity()
        return self.model or self.version or "logged in"

    def relogin(self) -> str:
        """Re-establish a dropped session with the remembered credentials.

        The app calls this once when a router read fails mid-session (Fix 3)
        instead of failing every scan forever on a dead cookie.
        """
        if not self._user or not self._password:
            raise RouterError("Router session expired and no credentials are remembered.")
        # Force a fresh crawl so cached pages from the dead session are not
        # served as if they were current.
        self._crawled = False
        self._pages = {}
        self._client_page = ""
        self._filter_page = ""
        self._filter_mode = ""
        self._filter_semantics = ""
        return self.login(self._user, self._password)

    def _read_identity(self) -> None:
        for path in ("/html/ssmp/deviceinfo/deviceinfo.asp", "/html/ssmp/index.asp"):
            try:
                page = self.get(path)
            except SessionExpired:
                raise
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
            except SessionExpired:
                raise
            except RouterError:
                continue
            low = html.lower()
            if "admin/login.asp" in low or self._looks_like_login(path, html):
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

        filter_score: dict[str, int] = {}
        for path, html in pages.items():
            low = (path + " " + html).lower()
            path_low = path.lower()
            if (
                any(h in path_low for h in FILTER_HINTS)
                or "filtertype" in low
                or "filter mode" in low
            ):
                filter_score[path] = filter_score.get(path, 0) + 5
                if "filtertype" in low or "filter mode" in low:
                    filter_score[path] += 4

        if not filter_score:
            for path in KNOWN_FILTER_PAGES:
                try:
                    html = self.get(path)
                except SessionExpired:
                    raise
                except RouterError:
                    continue
                if MAC_RE.search(html) or "filter" in html.lower():
                    pages[path] = html
                    filter_score[path] = 1
                    break

        if filter_score:
            self._filter_page = max(filter_score, key=filter_score.get)
            try:
                self._learn_filter_mode(pages.get(self._filter_page) or "")
            except SessionExpired:
                raise
            except RouterError:
                pass

        # Client pages are scored only after the filter page is known: a
        # client page may mention "MAC Filter" in its navigation, so mere
        # word presence must not exclude it.  Only the actual filter page
        # (and paths that are obviously filter paths) are skipped.
        client_score: dict[str, int] = {}
        for path, html in pages.items():
            path_low = path.lower()
            if path == self._filter_page or any(h in path_low for h in FILTER_HINTS):
                continue
            low = (path + " " + html).lower()
            if any(h in path_low for h in CLIENT_HINTS):
                client_score[path] = client_score.get(path, 0) + 2
            if MAC_RE.search(html) and IPV4_RE.search(html):
                client_score[path] = client_score.get(path, 0) + 3
            if "dhcp" in low:
                client_score[path] = client_score.get(path, 0) + 3

        if not client_score:
            for path in KNOWN_CLIENT_PAGES:
                if path == self._filter_page or any(h in path.lower() for h in FILTER_HINTS):
                    continue
                try:
                    html = self.get(path)
                except SessionExpired:
                    raise
                except RouterError:
                    continue
                if MAC_RE.search(html):
                    pages[path] = html
                    client_score[path] = 1
                    break

        if client_score:
            self._client_page = max(client_score, key=client_score.get)

    def _learn_filter_mode(self, html: str | None = None) -> None:
        """Classify the filter as blacklist or allow-list from the live page.

        Fix 2 root cause: the old code searched the whole HTML for the word
        "whitelist".  A normal blacklist page lists *both* modes in its
        <select>, so the mere presence of the unselected option latched
        allow-list and disabled blocking.  Only the **selected option** of the
        mode control (or, when there is no control, explicit visible wording)
        may decide the semantics.  The result is recomputed every time so a
        stale "allow" cannot outlive the page that produced it.
        """
        self._filter_semantics = ""
        self._filter_mode = ""
        if html is None:
            if not self._filter_page:
                return
            try:
                html = self.get(self._filter_page)
            except SessionExpired:
                raise
            except RouterError:
                return

        page = parse_page(html)
        modes: list[str] = []
        mode_select_seen = False
        for form in page.forms:
            is_filter_form = "filter" in (form.action or "").lower() or bool(form.mac_fields())
            for name in form.selects:
                low = name.lower()
                if not ("filtertype" in low or ("mode" in low and is_filter_form)):
                    continue
                mode_select_seen = True
                selected = form.selected_option(name)
                if selected is None:
                    continue
                self._filter_mode = f"{name}={selected.get('value', '')}"
                modes.append(_mode_word(f"{selected.get('value', '')} {selected.get('label', '')}"))
            for name in form.names:
                if name in form.selects:
                    continue
                low = name.lower()
                if not ("filtertype" in low or ("mode" in low and is_filter_form)):
                    continue
                value = form.value(name)
                self._filter_mode = self._filter_mode or f"{name}={value}"
                modes.append(_mode_word(value))

        if any(modes):
            if "allow" in modes:
                self._filter_semantics = "allow"
            elif "block" in modes:
                self._filter_semantics = "block"
            return

        # C2: a visible mode <select> whose selected value carries no
        # recognisable word (numeric-only, non-English) must fail closed —
        # assuming blacklist here can allow one device and deny the LAN.
        # Hidden inputs are the legacy form and do not count as a choice.
        if mode_select_seen:
            self._filter_semantics = "unknown"
            return

        # No control gave an explicit word (numeric-only mode, or no mode
        # control at all).  Visible text is the remaining signal, but option
        # labels and device tables are removed first: an unselected
        # "Whitelist" option, or a device *named* "Whitelist-Printer",
        # must never decide anything.
        visible = re.sub(r"<(?:script|style|select)\b.*?</(?:script|style|select)>", " ", html, flags=re.I | re.S)
        visible = re.sub(
            r"<table\b.*?</table>",
            lambda m: " " if MAC_RE.search(m.group(0)) else m.group(0),
            visible,
            flags=re.I | re.S,
        )
        text = " ".join(re.sub(r"<[^>]+>", " ", visible).split())
        self._filter_semantics = _mode_word(text)

    # -- clients ----------------------------------------------------------
    def clients(self) -> list[dict]:
        if not self.logged_in:
            raise RouterError("Not logged in")
        self._find_pages()
        if self._client_page:
            try:
                self._pages[self._client_page] = self.get(self._client_page)
            except SessionExpired:
                raise
            except RouterError:
                pass

        # M1: snapshot under the request lock so a concurrent relogin()
        # reassigning _pages cannot mutate the dict mid-iteration.
        with self._lock:
            pages_snapshot = dict(self._pages)
            filter_page = self._filter_page

        found: dict[str, dict] = {}
        for path, html in pages_snapshot.items():
            if path == filter_page or any(h in path.lower() for h in FILTER_HINTS):
                continue
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
                            if m and valid_ipv4(m.group(1)) and not m.group(1).startswith(("0.", "255.")):
                                ip = m.group(1)
                                continue
                        if not name and text and len(text) < 64 and not IPV4_RE.fullmatch(text):
                            if not re.fullmatch(r"[\d\s\./:\-]+", text):
                                name = text
                        for tag in ("wlan", "wifi", "wireless", "ssid"):
                            if tag in text.lower():
                                conn = "Wi-Fi"
                    if mac and ip:
                        entry = found.setdefault(mac, {"mac": mac, "ip": "", "hostname": "", "connection": ""})
                        entry["ip"] = entry["ip"] or ip
                        entry["hostname"] = entry["hostname"] or name
                        entry["connection"] = entry["connection"] or conn

            # Catch JS-driven tables where cells are not real <td>s.  An IP
            # near the MAC is required for the same reason.
            text = re.sub(r"<[^>]+>", " ", html)
            for m in MAC_RE.finditer(text):
                mac = norm_mac(m.group(1))
                window = text[max(0, m.start() - 160) : m.end() + 160]
                ipm = IPV4_RE.search(window)
                if not ipm or not valid_ipv4(ipm.group(1)) or ipm.group(1).startswith(("0.", "255.")):
                    continue
                entry = found.setdefault(mac, {"mac": mac, "ip": "", "hostname": "", "connection": ""})
                entry["ip"] = entry["ip"] or ipm.group(1)
        return list(found.values())

    # -- blocking ---------------------------------------------------------
    def _filter_page_html(self) -> str:
        if not self._filter_page:
            self._find_pages()
        if not self._filter_page:
            raise RouterError("Could not find the router's MAC filter page.")
        return self.get(self._filter_page)

    def blocked_macs(self) -> set[str]:
        """MACs currently in the router filter.

        A read failure raises instead of returning an empty set: returning
        set() made the UI show *everyone* as unblocked while the router still
        blocked them.  Session expiry raises SessionExpired, which the app
        answers with one relogin.
        """
        if not self.logged_in:
            raise SessionExpired("Not logged in to the router.")
        return filter_macs(self._filter_page_html())  # raises on failure

    def set_block(self, mac: str, blocked: bool) -> tuple[bool, str]:
        mac = norm_mac(mac)
        if not self.logged_in:
            return False, "Not logged in to the router."
        try:
            html = self._filter_page_html()
        except SessionExpired:
            raise
        except RouterError as exc:
            return False, str(exc)

        # Always re-read the live page: in allow-list mode adding a MAC
        # *allows* it and blocks everyone else.  NetGuard only speaks
        # blacklist fluently, so refuse rather than do the opposite.
        try:
            self._learn_filter_mode(html)
        except SessionExpired:
            raise
        if self._filter_semantics == "allow":
            return False, (
                "Router is in allow-list (whitelist) mode. "
                "NetGuard only supports blacklist mode — switch the filter "
                "to blacklist/deny on the router first."
            )
        if self._filter_semantics == "unknown":
            return False, (
                "Could not determine the router's MAC filter mode "
                f"({self._filter_mode or 'no mode label'}). Blocking could "
                "allow this device and deny the whole LAN, so NetGuard "
                "refuses. Check Router diagnostics, then retry."
            )

        page = parse_page(html)
        if not blocked:
            ok, msg = self._delete_mac(page, mac)
        else:
            ok, msg = self._add_mac(page, mac)
        if not ok:
            return False, msg

        # Verify by re-reading the filter page.  A read failure is a failure,
        # not a success — and the extractor must see slot-based entries too.
        after: set[str] | None = None
        for _attempt in range(2):
            try:
                after = filter_macs(self._filter_page_html())
                break
            except SessionExpired:
                raise
            except RouterError:
                after = None
        if after is None:
            return False, (
                "Sent the change but could not verify it on the router. "
                "Treating it as NOT applied — check Router diagnostics, then retry."
            )

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

        # Fix 5: never overwrite an occupied slot. The old code fell back to
        # field_names[0] when every slot was full, silently unblocking
        # whoever lived there. Fail honestly instead — unless the MAC is
        # already listed, in which case the block is already in place.
        for name in field_names:
            existing = str(form.value(name)).strip()
            if existing and norm_mac(existing) == mac:
                return True, "Already blocked"
        target = None
        for name in field_names:
            if not str(form.value(name)).strip():
                target = name
                break
        if target is None:
            return False, (
                "The router's MAC filter has no empty slot left. "
                "Unblock a device (or clear the filter on the router) and retry."
            )

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
        except SessionExpired:
            raise
        except RouterError as exc:
            return False, str(exc)
        if re.search(r"<h4>\s*ERROR", result, re.I):
            return False, "Router rejected the MAC filter change."
        return True, "Sent"

    def _delete_mac(self, page: _PageParser, mac: str) -> tuple[bool, str]:
        # 1) a form that actually owns the delete control for this MAC.
        #    Score first: firmware often pre-fills the *add* form with the
        #    same MAC, and posting that form does nothing (or re-adds it).
        candidates: list[tuple[int, Form, list[dict]]] = []
        for form in page.forms:
            matches = [
                inp
                for inp in form.inputs
                if str(inp.get("type", "text")).lower() not in ("submit", "button", "reset", "image")
                and norm_mac(str(inp.get("value", ""))) == mac
            ]
            if not matches:
                continue
            candidates.append((_delete_form_score(form, mac), form, matches))
        candidates.sort(key=lambda item: -item[0])

        if candidates and candidates[0][0] > 0:
            _score, form, matches = candidates[0]
            names = {str(inp.get("name", "")) for inp in matches if inp.get("name")}
            payload = [(name, value) for name, value in form.default_data() if name not in names]
            for inp in matches:
                if inp.get("name"):
                    payload.append((inp["name"], str(inp.get("value", ""))))
            # Only a delete-like button.  Never press "Add" on a form that
            # merely happens to contain the MAC.
            for button in form.inputs:
                name = str(button.get("name", ""))
                low = name.lower()
                if button.get("type") in ("submit", "image") and name:
                    if any(k in low for k in ("del", "remove", "apply", "ok", "save")) and "add" not in low:
                        payload.append((name, button.get("value", "")))
                        break
            try:
                self.post(form.action or self._filter_page, payload, referer=self._filter_page)
            except SessionExpired:
                raise
            except RouterError:
                pass
            else:
                return True, "Sent"

        # 2) a per-row delete link such as ...?macaddr=AA:BB:..&action=delete
        for link in page.links:
            low = link.lower()
            if not any(word in low for word in ("del", "remove", "action=delete")):
                continue
            if mac.replace(":", "") in link.replace(":", "").replace("-", "").upper():
                try:
                    self.get(link)
                    return True, "Sent"
                except SessionExpired:
                    raise
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
        except SessionExpired:
            raise
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
            "filter_semantics": self._filter_semantics or "(unknown — blacklist assumed)",
            "pages_scanned": len(self._pages),
        }


# --------------------------------------------------------------------------
def detect_router(base_url: str, timeout: float = 5.0) -> BaseRouter:
    return HuaweiRouter(base_url, timeout)
