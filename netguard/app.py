"""NetGuard - a desktop GUI for seeing and controlling devices on your LAN."""

from __future__ import annotations

import csv
import os
import queue
import sys
import threading
import time
import tkinter as tk
import webbrowser
from dataclasses import dataclass, field
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, __version__, fingerprint, netinfo, scanner
from .arpblock import ArpBlocker, is_admin, npcap_installed
from .oui import VendorDB, normalize
from .router import HuaweiRouter, LoginError, RouterError
from .store import APP_DIR, Store

# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------
BG = "#F4F6FA"
CARD = "#FFFFFF"
INK = "#0F172A"
MUTED = "#64748B"
LINE = "#E2E8F0"
ACCENT = "#2563EB"
ACCENT_DARK = "#1D4ED8"
DANGER = "#DC2626"
OK = "#15803D"
NEW = "#7C3AED"
HEADER_BG = "#0B1220"
HEADER_INK = "#E2E8F0"

FONT = "Segoe UI"


def ago(ts: float) -> str:
    if not ts:
        return "never"
    delta = time.time() - ts
    if delta < 45:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


def human(ts: float) -> str:
    if not ts:
        return "-"
    return time.strftime("%d %b %Y, %H:%M", time.localtime(ts))


# --------------------------------------------------------------------------
# Row model
# --------------------------------------------------------------------------
@dataclass
class Row:
    mac: str
    ip: str = ""
    name: str = ""
    vendor: str = ""
    kind: str = "device"
    guess: str = ""
    evidence: tuple[str, ...] = ()
    randomized: bool = False
    connection: str = ""
    online: bool = False
    blocked: bool = False
    arp_blocked: bool = False
    protected: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    is_me: bool = False
    is_router: bool = False
    source: str = "arp"

    @property
    def title(self) -> str:
        if self.is_router:
            return "Router / Gateway"
        if self.is_me:
            return self.name or "This computer"
        if self.name:
            return self.name
        if self.guess and self.guess != "Unknown device":
            return self.guess
        return self.vendor or "Unknown device"


# --------------------------------------------------------------------------
# Small dialogs
# --------------------------------------------------------------------------
class SettingsDialog(tk.Toplevel):
    def __init__(self, app: "NetGuardApp"):
        super().__init__(app)
        self.app = app
        self.title("Router connection")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(app)
        self.grab_set()

        cfg = app.store.config
        pad = {"padx": 18, "pady": (0, 10)}

        tk.Label(self, text="Router admin login", font=(FONT, 15, "bold"), bg=BG, fg=INK).pack(anchor="w", padx=18, pady=(16, 2))
        tk.Label(
            self,
            text="NetGuard uses the router's own web interface to list clients and apply blocks.\n"
            "Enter the same details you use at http://192.168.1.1",
            font=(FONT, 9), bg=BG, fg=MUTED, justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 14))

        self.url = self._field("Router address", cfg.get("router_url") or app.default_router_url())
        self.user = self._field("Username", cfg.get("username", "excitel"))
        self.pwd = self._field("Password", app.store.password, show="•")

        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=18, pady=(0, 8))
        self.remember = tk.BooleanVar(value=cfg.get("remember_password", True))
        tk.Checkbutton(
            row, text="Remember password (encrypted with Windows DPAPI)", variable=self.remember,
            bg=BG, fg=INK, font=(FONT, 9), activebackground=BG, selectcolor=CARD,
        ).pack(anchor="w")

        self.status = tk.Label(self, text="", font=(FONT, 9), bg=BG, fg=MUTED, justify="left", wraplength=420)
        self.status.pack(anchor="w", padx=18, pady=(2, 10))

        tk.Label(
            self,
            text="Tip: Excitel ONTs use the username “excitel”. The password is on the\n"
                 "sticker underneath the router (not the Wi-Fi password), or ask Excitel support.",
            font=(FONT, 8), bg=BG, fg="#94A3B8", justify="left",
        ).pack(anchor="w", padx=18, pady=(0, 10))

        buttons = tk.Frame(self, bg=BG)
        buttons.pack(fill="x", padx=18, pady=(0, 18))
        self.test_btn = ttk.Button(buttons, text="Test && save", style="Accent.TButton", command=self.save_and_test)
        self.test_btn.pack(side="left")
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="left", padx=8)
        ttk.Button(buttons, text="Open router page", command=lambda: webbrowser.open(self.url.get() or "http://192.168.1.1")).pack(side="right")

        self.update_idletasks()
        x = app.winfo_x() + (app.winfo_width() - self.winfo_width()) // 2
        y = app.winfo_y() + 90
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _field(self, label: str, value: str, show: str | None = None) -> tk.Entry:
        tk.Label(self, text=label, font=(FONT, 9, "bold"), bg=BG, fg=MUTED).pack(anchor="w", padx=18, pady=(0, 3))
        entry = tk.Entry(self, font=(FONT, 10), bg=CARD, fg=INK, relief="solid", bd=1, width=46, show=show)
        entry.insert(0, value)
        entry.pack(fill="x", **pad)
        return entry

    def save_and_test(self) -> None:
        url = self.url.get().strip().rstrip("/")
        if not url.startswith("http"):
            url = "http://" + url
        user = self.user.get().strip()
        pwd = self.pwd.get()
        if not user or not pwd:
            self.status.configure(text="Enter both the username and the password.", fg=DANGER)
            return

        self.app.store.config["router_url"] = url
        self.app.store.config["username"] = user
        self.app.store.config["remember_password"] = self.remember.get()
        self.app.store.password = pwd
        self.app.store.save_config()

        self.status.configure(text="Connecting to the router…", fg=MUTED)
        self.test_btn.state(["disabled"])
        self.app.connect_router(url, user, pwd, self)


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------
class NetGuardApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {__version__}  •  Network device manager")
        self.geometry("1180x800")
        self.minsize(1000, 680)
        self.configure(bg=BG)

        self.store = Store()
        self.vendors = VendorDB(APP_DIR)
        self.iface = netinfo.active_interface()
        self.my_mac = normalize(self.iface.mac) if self.iface and self.iface.mac else ""
        self.gateway_mac = netinfo.gateway_mac(self.iface.gateway) if self.iface else ""

        self.router: HuaweiRouter | None = None
        self.router_state = "not configured"
        self.arp = ArpBlocker()
        self.rows: dict[str, Row] = {}
        self.scanning = False
        self.last_scan: float = 0.0
        self.queue: queue.Queue = queue.Queue()
        # Fix 1: track what ARP health we last reported, so we log each new
        # failure exactly once instead of spamming every scan.
        self._last_arp_error: str = ""
        self._last_arp_running: bool | None = None
        self._last_net_refresh: float = 0.0

        self._build_style()
        self._build_ui()
        self._refresh_network_info()
        self._update_router_badge()
        self._update_arp_indicator()
        self.bind("<F5>", lambda _e: self.start_scan(True))
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.after(120, self._drain_queue)
        self.after(200, self._first_run)
        self.after(1000, self._tick)

    # -- appearance -------------------------------------------------------
    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("TButton", font=(FONT, 9), padding=(12, 6))
        style.configure("Accent.TButton", font=(FONT, 9, "bold"), padding=(14, 6))
        style.configure("Compact.TButton", font=(FONT, 9), padding=(10, 3))
        style.map("Accent.TButton", background=[("active", ACCENT_DARK)])
        style.configure("Treeview", font=(FONT, 9), rowheight=32, background=CARD, fieldbackground=CARD, borderwidth=0)
        style.configure("Treeview.Heading", font=(FONT, 9, "bold"), padding=(8, 8))
        style.map("Treeview", background=[("selected", "#DBEAFE")], foreground=[("selected", INK)])
        style.configure("TEntry", padding=5)

    def _build_ui(self) -> None:
        # Header ---------------------------------------------------------
        header = tk.Frame(self, bg=HEADER_BG)
        header.pack(fill="x")
        inner = tk.Frame(header, bg=HEADER_BG)
        inner.pack(fill="x", padx=20, pady=14)

        left = tk.Frame(inner, bg=HEADER_BG)
        left.pack(side="left")
        tk.Label(left, text=APP_NAME, font=(FONT, 18, "bold"), bg=HEADER_BG, fg="white").pack(anchor="w")
        self.subtitle = tk.Label(left, text="", font=(FONT, 9), bg=HEADER_BG, fg="#94A3B8")
        self.subtitle.pack(anchor="w", pady=(2, 0))

        right = tk.Frame(inner, bg=HEADER_BG)
        right.pack(side="right")
        self.net_badge = tk.Label(right, text="", font=(FONT, 9, "bold"), bg="#1E293B", fg="#CBD5E1", padx=12, pady=6)
        self.net_badge.pack(side="right", padx=(10, 0))
        self.router_badge = tk.Label(right, text="", font=(FONT, 9, "bold"), bg="#1E293B", fg="#CBD5E1", padx=12, pady=6)
        self.router_badge.pack(side="right")

        # Toolbar --------------------------------------------------------
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=18, pady=(12, 6))

        self.scan_btn = ttk.Button(bar, text="Scan now", style="Accent.TButton", command=lambda: self.start_scan(True))
        self.scan_btn.pack(side="left")

        self.auto_var = tk.BooleanVar(value=self.store.config.get("auto_refresh", True))
        tk.Checkbutton(
            bar, text="Auto refresh", variable=self.auto_var, command=self._save_auto,
            bg=BG, fg=INK, font=(FONT, 9), activebackground=BG, selectcolor=CARD,
        ).pack(side="left", padx=(14, 4))
        self.interval_var = tk.StringVar(value=str(self.store.config.get("interval", 20)))
        ttk.Combobox(bar, textvariable=self.interval_var, values=["10", "20", "30", "60", "120"], width=4, state="readonly").pack(side="left")
        tk.Label(bar, text="sec", font=(FONT, 9), bg=BG, fg=MUTED).pack(side="left", padx=(4, 14))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.render())

        right_bar = tk.Frame(bar, bg=BG)
        right_bar.pack(side="right")
        self.offline_var = tk.BooleanVar(value=self.store.config.get("show_offline", False))
        tk.Checkbutton(
            right_bar, text="Show offline", variable=self.offline_var, command=self._save_offline,
            bg=BG, fg=INK, font=(FONT, 9), activebackground=BG, selectcolor=CARD,
        ).pack(side="left", padx=(0, 16))
        tk.Label(right_bar, text="Search", font=(FONT, 9), bg=BG, fg=MUTED).pack(side="left", padx=(0, 6))
        search = tk.Entry(right_bar, textvariable=self.search_var, font=(FONT, 9), bg=CARD, fg=INK,
                          relief="solid", bd=1, width=22)
        search.pack(side="left")

        self.arp_indicator = tk.Frame(right_bar, bg=BG)
        self.arp_label = tk.Label(self.arp_indicator, text="", font=(FONT, 9, "bold"), bg="#FFEDD5", fg="#9A3412", padx=8, pady=3)
        self.arp_label.pack(side="left")
        ttk.Button(self.arp_indicator, text="Restore all", command=self._restore_all).pack(side="left", padx=(6, 12))

        # Banner (shown until the router login succeeds) ------------------
        self.banner = tk.Frame(self, bg="#FEF3C7", highlightbackground="#FCD34D", highlightthickness=1)
        self.banner_label = tk.Label(
            self.banner,
            text="Router blocking needs the admin password.  You can still use “Force offline” on any device.",
            font=(FONT, 9), bg="#FEF3C7", fg="#92400E", anchor="w",
        )
        self.banner_label.pack(side="left", padx=12, pady=7)
        ttk.Button(self.banner, text="Connect", command=lambda: SettingsDialog(self)).pack(side="right", padx=8, pady=4)
        self.admin_btn = ttk.Button(self.banner, text="Run as admin", command=self._relaunch_admin)
        if not is_admin():
            self.admin_btn.pack(side="right", pady=4)
        self.banner.pack(fill="x", padx=18, pady=(0, 6))

        # Main split -----------------------------------------------------
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 8))

        table_card = tk.Frame(body, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        table_card.pack(side="left", fill="both", expand=True)

        columns = ("status", "name", "guess", "ip", "mac", "vendor", "kind", "seen")
        self.tree = ttk.Treeview(table_card, columns=columns, show="headings", selectmode="browse")
        widths = {"status": 92, "name": 180, "guess": 170, "ip": 104, "mac": 140, "vendor": 130, "kind": 78, "seen": 76}
        labels = {"status": "", "name": "Device", "guess": "Likely device", "ip": "IP address", "mac": "MAC",
                  "vendor": "Vendor", "kind": "Type", "seen": "Last seen"}
        for col in columns:
            self.tree.heading(col, text=labels[col], anchor="w" if col in ("name", "guess", "vendor") else "center")
            self.tree.column(col, width=widths[col], anchor="w" if col in ("name", "guess", "vendor") else "center",
                             stretch=col in ("name", "guess", "vendor"))
        self.tree.tag_configure("blocked", foreground=DANGER)
        self.tree.tag_configure("offline", foreground="#94A3B8")
        self.tree.tag_configure("me", foreground=ACCENT)
        self.tree.tag_configure("router", foreground="#7C3AED")
        self.tree.tag_configure("odd", background="#FAFBFD")

        scroll = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_details())
        self.tree.bind("<Double-1>", lambda _e: self._act_block(False))
        self.tree.bind("<Button-3>", self._context_menu)

        # Details --------------------------------------------------------
        side = tk.Frame(body, bg=CARD, width=300, highlightbackground=LINE, highlightthickness=1)
        side.pack(side="right", fill="y", padx=(12, 0))
        side.pack_propagate(False)

        self.detail_icon = tk.Label(side, text="◉", font=(FONT, 26), bg=CARD, fg=ACCENT)
        self.detail_icon.pack(pady=(14, 0))
        self.detail_name = tk.Label(side, text="Select a device", font=(FONT, 13, "bold"), bg=CARD, fg=INK, wraplength=260)
        self.detail_name.pack(pady=(2, 0))
        self.detail_state = tk.Label(side, text="", font=(FONT, 9, "bold"), bg=CARD, fg=MUTED)
        self.detail_state.pack()

        # Primary actions stay above the fold regardless of window height.
        actions = tk.Frame(side, bg=CARD)
        actions.pack(fill="x", padx=16, pady=(8, 4))
        self.block_btn = ttk.Button(actions, text="Block device", style="Accent.TButton",
                                    command=self._block_button_action)
        self.block_btn.pack(fill="x", pady=(0, 4))
        self.arp_btn = ttk.Button(actions, text="Force offline", style="Compact.TButton", command=self._act_arp)
        self.arp_btn.pack(fill="x", pady=(0, 4))
        self.protect_btn = ttk.Button(actions, text="Protect device", style="Compact.TButton",
                                      command=self._toggle_protect)
        self.protect_btn.pack(fill="x", pady=(0, 4))
        ttk.Button(actions, text="Identify device", style="Compact.TButton",
                   command=self._identify_selected).pack(fill="x", pady=(0, 4))
        ttk.Button(actions, text="Rename…", style="Compact.TButton",
                   command=self._rename_selected).pack(fill="x", pady=(0, 4))
        ttk.Button(actions, text="Copy MAC", style="Compact.TButton", command=self._copy_mac).pack(fill="x")

        info = tk.Frame(side, bg=CARD)
        info.pack(fill="x", padx=18, pady=(6, 0))
        self.detail_fields: dict[str, tk.Label] = {}
        for key, label in (("ip", "IP address"), ("mac", "MAC address"), ("vendor", "Vendor"),
                           ("guess", "Likely device"), ("kind", "Type"), ("connection", "Connection"),
                           ("first", "First seen"), ("seen", "Last seen")):
            line = tk.Frame(info, bg=CARD)
            line.pack(fill="x", pady=1)
            tk.Label(line, text=label, font=(FONT, 8), bg=CARD, fg=MUTED, width=13, anchor="w").pack(side="left")
            value = tk.Label(line, text="-", font=(FONT, 8), bg=CARD, fg=INK, anchor="e", justify="right", wraplength=150)
            value.pack(side="right", fill="x", expand=True)
            self.detail_fields[key] = value
        self.detail_evidence = tk.Label(
            side, text="", font=(FONT, 7), bg=CARD, fg=MUTED,
            justify="left", anchor="nw", wraplength=260,
        )
        self.detail_evidence.pack(fill="x", padx=18, pady=(8, 0))

        # Log ------------------------------------------------------------
        log_frame = tk.Frame(self, bg=BG)
        log_frame.pack(fill="x", padx=18, pady=(0, 12))
        self.log = tk.Text(log_frame, height=5, font=("Consolas", 8), bg="#0B1220", fg="#CBD5E1",
                           relief="flat", padx=10, pady=8, state="disabled", wrap="word")
        self.log.pack(fill="x")

        # Footer ---------------------------------------------------------
        footer = tk.Frame(self, bg=BG)
        footer.pack(fill="x", padx=18, pady=(0, 10))
        self.footer = tk.Label(footer, text="Ready", font=(FONT, 9), bg=BG, fg=MUTED)
        self.footer.pack(side="left")
        ttk.Button(footer, text="Router diagnostics", command=self._diagnostics).pack(side="right", padx=(8, 0))
        ttk.Button(footer, text="Export CSV", command=self._export).pack(side="right", padx=(8, 0))
        ttk.Button(footer, text="Router login", command=lambda: SettingsDialog(self)).pack(side="right")

    # -- small helpers ----------------------------------------------------
    def default_router_url(self) -> str:
        if self.iface and self.iface.gateway:
            return f"http://{self.iface.gateway}"
        return "http://192.168.1.1"

    def log_line(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{stamp}] {text}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def post(self, fn) -> None:
        self.queue.put(fn)

    def _drain_queue(self) -> None:
        try:
            while True:
                fn = self.queue.get_nowait()
                try:
                    fn()
                except Exception as exc:  # never let a callback kill the UI
                    self.log_line(f"UI error: {exc}")
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    def _refresh_network_info(self, force: bool = False) -> None:
        """Re-resolve the active interface and the gateway MAC (Fix 1).

        Previously this ran once at startup, so a Wi-Fi change or an empty
        ARP cache at launch broke Force offline / router detection for the
        whole session. Now it re-checks at most every 45 s (and immediately
        whenever the gateway MAC is still unknown), updates the ARP blocker
        in place, and logs any change.
        """
        now = time.time()
        last = getattr(self, "_last_net_refresh", 0.0)
        need_resolve = force or (now - last >= 45) or not self.gateway_mac
        if need_resolve:
            self._last_net_refresh = now
            old = self.iface
            try:
                new_iface = netinfo.active_interface()
            except Exception:
                new_iface = None
            if new_iface is not None:
                same = (
                    old is not None
                    and new_iface.ip == old.ip
                    and new_iface.gateway == old.gateway
                    and normalize(new_iface.mac or "") == normalize(old.mac or "")
                )
                if not same:
                    if old is not None:
                        self.log_line(
                            f"Network changed: {old.ip} (gw {old.gateway or '—'}) -> "
                            f"{new_iface.ip} (gw {new_iface.gateway or '—'})."
                        )
                    self.iface = new_iface
                    self.my_mac = normalize(new_iface.mac) if new_iface.mac else ""
            # Gateway MAC comes from the ARP cache, which a scan populates —
            # always retry it while unknown instead of waiting 45 s.
            if self.iface and self.iface.gateway:
                fresh = netinfo.gateway_mac(self.iface.gateway)
                if fresh and normalize(fresh) != self.gateway_mac:
                    self.log_line(f"Gateway MAC resolved: {normalize(fresh)} ({self.iface.gateway}).")
                    self.gateway_mac = normalize(fresh)
            # Keep any live ARP blocks pointed at the current network.
            if self.arp.targets and self.iface:
                if self.arp.refresh(self.iface, self.gateway_mac):
                    for msg in self.arp.drain_events():
                        self.log_line(msg)

        if not self.iface:
            self.subtitle.configure(text="No active network connection")
            self.net_badge.configure(text="OFFLINE", fg="#FCA5A5")
            return
        net = self.iface.network
        gw = self.iface.gateway or "—"
        if not self.gateway_mac and self.iface.gateway:
            gw += " (MAC ?)"
        self.subtitle.configure(
            text=f"{self.iface.name}  •  {self.iface.ip}  •  gateway {gw}  •  {net}"
        )
        self.net_badge.configure(text=f"LAN {net}", fg="#A7F3D0")

    def _update_router_badge(self) -> None:
        state = self.router_state
        if state == "connected":
            self.router_badge.configure(text="ROUTER CONNECTED", fg="#A7F3D0")
            try:
                self.banner.pack_forget()
            except Exception:
                pass
        else:
            try:
                if not self.banner.winfo_ismapped():
                    self.banner.pack(fill="x", padx=18, pady=(0, 6))
            except Exception:
                pass
            if state.startswith("failed") or state == "error":
                self.router_badge.configure(text="ROUTER LOGIN FAILED", fg="#FCA5A5")
                self.banner_label.configure(
                    text="Router login failed. Check the username/password, then connect again.",
                    fg="#991B1B", bg="#FEE2E2",
                )
                self.banner.configure(bg="#FEE2E2", highlightbackground="#FCA5A5")
            elif state == "connecting":
                self.router_badge.configure(text="CONNECTING…", fg="#FDE68A")
            else:
                self.router_badge.configure(text="ROUTER NOT CONNECTED", fg="#CBD5E1")
                self.banner_label.configure(
                    text="Router blocking needs the admin password.  You can still use “Force offline” on any device.",
                    fg="#92400E", bg="#FEF3C7",
                )
                self.banner.configure(bg="#FEF3C7", highlightbackground="#FCD34D")

    def _first_run(self) -> None:
        if not self.iface:
            messagebox.showwarning(APP_NAME, "No active network adapter was found.\nConnect to Wi-Fi or Ethernet and reopen the app.")
            return
        if not self.store.config.get("router_url"):
            self.store.config["router_url"] = self.default_router_url()
            self.store.save_config()
        pwd = self.store.password
        if pwd and self.store.config.get("username"):
            self.connect_router(self.store.config["router_url"], self.store.config["username"], pwd, None)
        else:
            self.log_line("Router login needed to block devices. Click “Router login”.")
        self.start_scan(True)

    # -- router -----------------------------------------------------------
    def connect_router(self, url: str, user: str, pwd: str, dialog: SettingsDialog | None) -> None:
        self.router_state = "connecting"
        self._update_router_badge()

        def work():
            try:
                router = HuaweiRouter(url, timeout=10)
                version = router.login(user, pwd)
                self.post(lambda: self._router_ok(router, version, dialog))
            except LoginError as exc:
                message = str(exc)
                self.post(lambda m=message: self._router_fail(m, dialog, login=True))
            except Exception as exc:
                message = str(exc)
                self.post(lambda m=message: self._router_fail(m, dialog, login=False))

        threading.Thread(target=work, daemon=True).start()

    def _router_ok(self, router: HuaweiRouter, version: str, dialog: SettingsDialog | None) -> None:
        self.router = router
        self.router_state = "connected"
        self._update_router_badge()
        self.log_line(f"Connected to {router.name} {('(' + version + ')') if version else ''}.")
        self.footer.configure(text="Router connected")
        if dialog:
            dialog.status.configure(text=f"Success — logged in. {version}", fg=OK)
            dialog.test_btn.state(["!disabled"])
            self.after(900, dialog.destroy)
        self.start_scan(True)

    def _router_fail(self, message: str, dialog: SettingsDialog | None, login: bool) -> None:
        self.router_state = "failed" if login else "error"
        self._update_router_badge()
        self.log_line(f"Router login failed: {message}")
        if dialog:
            dialog.status.configure(text=f"Login failed: {message}", fg=DANGER)
            dialog.test_btn.state(["!disabled"])
        else:
            self.footer.configure(text="Router login failed — blocking is unavailable")

    # -- scanning ---------------------------------------------------------
    def start_scan(self, manual: bool = False) -> None:
        if not self.iface or self.scanning:
            return
        self.scanning = True
        self.scan_btn.state(["disabled"])
        self.footer.configure(text="Scanning the network…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        started = time.time()
        try:
            found = scanner.scan(self.iface, self.vendors, deep=self.store.config.get("deep_scan", False))
        except Exception as exc:
            self.scanning = False
            message = f"Scan error: {exc}"
            self.post(lambda m=message: self._scan_done({}, {}, set(), m))
            return

        router_clients: dict[str, dict] = {}
        blocked: set[str] = set()
        router_error = ""
        if self.router and self.router.logged_in:
            try:
                for c in self.router.clients():
                    mac = normalize(c["mac"])
                    router_clients[mac] = c
                blocked = {normalize(m) for m in self.router.blocked_macs()}
            except Exception as exc:
                router_error = str(exc)

        # Best-effort device identification so randomised MACs are not all
        # just “Unknown”.  This only probes each device it already found.
        try:
            skip = {m for m in (self.my_mac, self.gateway_mac) if m}
            fingerprints = fingerprint.fingerprint_all(
                found,
                self.vendors,
                self.store.devices,
                skip_macs=skip,
            )
        except Exception:
            fingerprints = {}

        self.post(lambda: self._scan_done(found, router_clients, blocked, router_error, started, fingerprints))

    def _scan_done(self, found: dict, router_clients: dict, blocked: set, router_error: str = "", started: float = 0, fingerprints: dict | None = None) -> None:
        fingerprints = fingerprints or {}
        self.scanning = False
        self.scan_btn.state(["!disabled"])
        self.last_scan = time.time()
        # The sweep just populated the ARP cache, so the gateway MAC that was
        # missing at launch may be resolvable now — refresh before classifying
        # the router / self rows below.
        self._refresh_network_info()

        raw: dict[str, dict] = {}
        for mac, dev in found.items():
            fp = fingerprints.get(mac)
            entry = {"ip": dev.ip, "hostname": dev.hostname, "vendor": dev.vendor, "connection": "", "online": True, "source": "arp"}
            if fp:
                entry.update(fp.as_dict())
            raw[mac] = entry
        for mac, c in router_clients.items():
            entry = raw.setdefault(mac, {"ip": "", "hostname": "", "vendor": "", "connection": "", "online": True, "source": "router"})
            entry["ip"] = entry["ip"] or c.get("ip", "")
            entry["hostname"] = entry["hostname"] or c.get("hostname", "")
            entry["connection"] = c.get("connection", "")
            entry["source"] = "both" if entry["ip"] else "router"

        self.store.merge_scan(raw)
        now = time.time()
        new_macs = [mac for mac in raw if mac not in self.rows] if self.rows else []

        rows: dict[str, Row] = {}
        # Keep previously known devices so "show offline" and block lists work.
        for mac, rec in self.store.devices.items():
            mac = normalize(mac)
            live = raw.get(mac)
            row = Row(
                mac=mac,
                ip=(live or {}).get("ip", rec.get("ip", "")),
                name=rec.get("name") or (live or {}).get("hostname", ""),
                vendor=self.vendors.lookup(mac),
                guess=(live or {}).get("guess") or rec.get("guess", ""),
                evidence=tuple((live or {}).get("guess_evidence") or rec.get("guess_evidence") or ()),
                randomized=bool((live or {}).get("randomized", rec.get("randomized", False))),
                connection=(live or {}).get("connection", ""),
                online=bool(live),
                blocked=(mac in blocked) if self.router_state == "connected" else bool(rec.get("blocked")),
                arp_blocked=self.arp.is_blocking(mac),
                protected=bool(rec.get("protected", False)),
                first_seen=rec.get("first_seen", 0),
                last_seen=now if live else rec.get("last_seen", 0),
                source=(live or {}).get("source", ""),
            )
            rec_category = rec.get("guess_category") or (live or {}).get("guess_category", "")
            row.kind = rec_category or scanner.classify(
                scanner.Device(mac=mac, hostname=row.name, vendor=row.vendor)
            )
            row.is_me = bool(self.my_mac) and mac == self.my_mac
            row.is_router = bool(self.gateway_mac) and mac == self.gateway_mac
            if row.is_router:
                row.kind = "router"
                row.name = row.name or "Router"
            rows[mac] = row

        # Devices the router knows but the store has never seen.
        for mac, info in raw.items():
            if mac not in rows:
                row = Row(mac=mac, ip=info["ip"], name=info["hostname"], vendor=self.vendors.lookup(mac),
                          guess=info.get("guess", ""), evidence=tuple(info.get("guess_evidence") or ()),
                          randomized=bool(info.get("randomized", False)),
                          connection=info["connection"], online=True, blocked=mac in blocked,
                          arp_blocked=self.arp.is_blocking(mac),
                          protected=bool(self.store.devices.get(mac, {}).get("protected", False)),
                          first_seen=now, last_seen=now)
                row.kind = info.get("guess_category") or scanner.classify(scanner.Device(mac=mac, hostname=row.name, vendor=row.vendor))
                rows[mac] = row

        # This computer is not always present in the ARP cache; show it anyway.
        if self.my_mac and self.my_mac not in rows:
            import socket as _socket

            me = Row(mac=self.my_mac, ip=self.iface.ip if self.iface else "", name=_socket.gethostname(),
                     vendor=self.vendors.lookup(self.my_mac), online=True, first_seen=now, last_seen=now)
            me.kind = "computer"
            me.is_me = True
            rows[self.my_mac] = me
        elif self.my_mac in rows:
            me = rows[self.my_mac]
            me.is_me = True
            me.kind = "computer"
            me.online = True
            me.last_seen = now
            me.ip = me.ip or (self.iface.ip if self.iface else "")
            me.name = me.name or "This computer"

        # Remember the authoritative blocked state from the router.
        for mac, row in rows.items():
            rec = self.store.record(mac)
            if blocked or self.router_state == "connected":
                rec["blocked"] = row.blocked
        self.store.save_devices()

        self.rows = rows
        self.render()
        elapsed = (time.time() - started) if started else 0
        online = sum(1 for r in rows.values() if r.online)
        self.footer.configure(text=f"{online} device{'s' if online != 1 else ''} online  •  scan took {elapsed:.1f}s  •  {ago(self.last_scan)}")
        self.log_line(f"Scan complete: {online} online, {len(rows)} known." + (f" Router: {router_error}" if router_error else ""))
        for message in self.arp.drain_events():
            self.log_line(message)
        self._check_arp_health()
        self._update_arp_indicator()
        for mac in new_macs:
            row = rows.get(mac)
            if row and not row.is_router and not row.is_me:
                self.log_line(f"New device joined: {row.title} ({row.ip or 'no IP'}, {mac})")
                try:
                    self.bell()
                except tk.TclError:
                    pass

    # -- rendering --------------------------------------------------------
    def render(self) -> None:
        query = self.search_var.get().strip().lower()
        show_offline = self.offline_var.get()
        selected = self.tree.selection()
        selected_mac = selected[0] if selected else None

        self.tree.delete(*self.tree.get_children())
        rows = sorted(
            self.rows.values(),
            key=lambda r: (not r.online, not r.is_router, r.blocked, (r.name or r.ip or r.mac).lower()),
        )
        count = 0
        for idx, row in enumerate(rows):
            if not show_offline and not row.online:
                continue
            haystack = f"{row.name} {row.ip} {row.mac} {row.vendor} {row.kind} {row.guess} {' '.join(row.evidence)}".lower()
            if query and query not in haystack:
                continue
            if row.arp_blocked:
                status = "⛔ Forced off"
                tags = ("blocked",)
            elif row.blocked:
                status = "⛔ Blocked"
                tags = ("blocked",)
            elif row.is_me:
                status = "● You"
                tags = ("me",)
            elif row.is_router:
                status = "● Router"
                tags = ("router",)
            elif row.online:
                status = "● Online"
                tags = ()
            else:
                status = "○ Offline"
                tags = ("offline",)
            if idx % 2 and not tags:
                tags = ("odd",)
            self.tree.insert(
                "", "end", iid=row.mac,
                values=(status, row.title + ("  🛡" if row.protected else ""),
                        row.guess or ("Unknown device" if not row.is_me and not row.is_router else "—"),
                        row.ip or "—", row.mac,
                        row.vendor or "—", row.kind.title(), ago(row.last_seen)),
                tags=tags,
            )
            count += 1
        if selected_mac and self.tree.exists(selected_mac):
            self.tree.selection_set(selected_mac)
        self._show_details()

    # -- details ----------------------------------------------------------
    def selected_row(self) -> Row | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.rows.get(sel[0])

    def _show_details(self) -> None:
        row = self.selected_row()
        if not row:
            self.detail_name.configure(text="Select a device")
            self.detail_state.configure(text="")
            self.detail_icon.configure(text="◉", fg="#CBD5E1")
            for label in self.detail_fields.values():
                label.configure(text="—")
            self.detail_evidence.configure(text="")
            self.block_btn.configure(text="Block device")
            self.block_btn.state(["disabled"])
            self.arp_btn.state(["disabled"])
            self.protect_btn.state(["disabled"])
            return

        self.detail_name.configure(text=row.title)
        if row.arp_blocked:
            self.detail_state.configure(text="FORCED OFFLINE (ARP)", fg="#C2410C")
            self.detail_icon.configure(text="⛔", fg="#C2410C")
        elif row.blocked:
            self.detail_state.configure(text="BLOCKED ON ROUTER", fg=DANGER)
            self.detail_icon.configure(text="⛔", fg=DANGER)
        elif row.online:
            self.detail_state.configure(text="ONLINE", fg=OK)
            self.detail_icon.configure(text="◉", fg=ACCENT if not row.is_router else "#7C3AED")
        else:
            self.detail_state.configure(text="OFFLINE", fg=MUTED)
            self.detail_icon.configure(text="○", fg="#94A3B8")

        values = {
            "ip": row.ip or "—",
            "mac": row.mac,
            "vendor": row.vendor or "Unknown",
            "guess": row.guess or "Unknown device",
            "kind": row.kind.title(),
            "connection": row.connection or ("This PC" if row.is_me else "—"),
            "first": human(row.first_seen),
            "seen": ago(row.last_seen),
        }
        for key, value in values.items():
            self.detail_fields[key].configure(text=value)
        evidence = list(row.evidence)
        if row.randomized:
            evidence.append("This device is deliberately hiding its maker (random MAC).")
        self.detail_evidence.configure(text="\n".join(evidence[:10]) if evidence else "No extra clues found yet. Use 🔍 Identify device again if the device was just turned on.")

        can_block = not row.is_me and not row.is_router
        self.block_btn.configure(text="Unblock" if row.blocked else "Block device")
        self.block_btn.state(["!disabled"] if can_block else ["disabled"])
        self.arp_btn.configure(text="Restore connection" if row.arp_blocked else "Force offline")
        self.arp_btn.state(["!disabled"] if can_block else ["disabled"])
        self.protect_btn.configure(text="Unprotect" if row.protected else "Protect this device")
        self.protect_btn.state(["!disabled"] if can_block else ["disabled"])

    def _block_button_action(self) -> None:
        row = self.selected_row()
        if row:
            self._act_block(row.blocked)

    # -- actions ----------------------------------------------------------
    def _act_block(self, unblock: bool) -> None:
        row = self.selected_row()
        if not row:
            return
        if row.is_me or row.is_router:
            messagebox.showinfo(APP_NAME, "You cannot block this computer or the router itself.")
            return
        if row.protected and not unblock:
            if not messagebox.askyesno(
                APP_NAME,
                f"“{row.title}” is marked as protected (yours or family).\n\nBlock it anyway?",
            ):
                return
        if not (self.router and self.router.logged_in):
            if messagebox.askyesno(APP_NAME, "You are not logged in to the router, so blocking is unavailable.\n\nOpen the router login now?"):
                SettingsDialog(self)
            return

        verb = "Unblock" if unblock else "Block"
        extra = "\n\nThe device will be disconnected immediately." if not unblock else ""
        if not messagebox.askyesno(
            APP_NAME,
            f"{verb} “{row.title}” ({row.mac})?\n\n{extra}".strip(),
        ):
            return

        self.footer.configure(text=f"{verb}ing {row.title}…")

        def work():
            try:
                ok, msg = self.router.set_block(row.mac, not unblock)
                self.post(lambda: self._block_done(row.mac, ok, msg, unblock))
            except Exception as exc:
                message = str(exc)
                self.post(lambda m=message: self._block_done(row.mac, False, m, unblock))

        threading.Thread(target=work, daemon=True).start()

    def _block_done(self, mac: str, ok: bool, message: str, unblock: bool) -> None:
        verb = "unblocked" if unblock else "blocked"
        if not ok:
            self.log_line(f"Failed to {verb[:-1]}e {mac}: {message}")
            messagebox.showerror(APP_NAME, f"Could not {'unblock' if unblock else 'block'} the device.\n\n{message}")
            self.footer.configure(text="Action failed")
            return
        row = self.rows.get(mac)
        if row:
            row.blocked = not unblock
        rec = self.store.record(mac)
        rec["blocked"] = not unblock
        self.store.save_devices()
        self.log_line(f"Device {mac} {verb}.")
        self.footer.configure(text=f"Device {verb}")
        self.render()
        self.after(1500, lambda: self.start_scan(False))

    # -- ARP blocking ("force offline") -----------------------------------
    def _act_arp(self) -> None:
        row = self.selected_row()
        if not row:
            return
        if row.is_me or row.is_router:
            messagebox.showinfo(APP_NAME, "This computer and the router itself can never be forced offline.")
            return

        if row.arp_blocked:
            self.arp.remove(row.mac)
            row.arp_blocked = False
            self.log_line(f"Connection restored for {row.title} ({row.mac}).")
            self.footer.configure(text="Connection restored")
            self.render()
            self._update_arp_indicator()
            return

        if row.protected:
            if not messagebox.askyesno(
                APP_NAME,
                f"“{row.title}” is marked as protected.\n\n"
                "It is probably yours or a family member's. Force it offline anyway?",
            ):
                return

        if not row.ip:
            messagebox.showinfo(
                APP_NAME,
                "This device has no IP address right now, so it cannot be targeted.\n"
                "Run a scan while it is online and try again.",
            )
            return
        if not self.iface:
            messagebox.showerror(APP_NAME, "No active network adapter.")
            return

        ok, message = self.arp.add(row.mac, row.ip, self.iface, self.gateway_mac)
        if not ok:
            self._arp_failed(message)
            return
        row.arp_blocked = True
        self.log_line(f"Force offline ON for {row.title} ({row.ip}, {row.mac}).")
        self.footer.configure(text=f"Forcing {row.title} offline")
        self.render()
        self._update_arp_indicator()

    def _toggle_protect(self) -> None:
        row = self.selected_row()
        if not row or row.is_me or row.is_router:
            return
        rec = self.store.record(row.mac)
        rec["protected"] = not rec.get("protected", False)
        row.protected = bool(rec["protected"])
        self.store.save_devices()
        if row.protected:
            if row.arp_blocked:
                self.arp.remove(row.mac)
                row.arp_blocked = False
                self._update_arp_indicator()
            self.log_line(f"{row.title} is now protected - never blocked by accident.")
        else:
            self.log_line(f"{row.title} is no longer protected.")
        self.render()

    def _restore_all(self) -> None:
        count = len(self.arp.targets)
        if not count:
            return
        if not messagebox.askyesno(APP_NAME, f"Restore the connection for all {count} blocked device(s)?"):
            return
        self.arp.stop()
        for row in self.rows.values():
            row.arp_blocked = False
        self.log_line(f"Restored {count} device(s).")
        self.footer.configure(text="All devices restored")
        self.render()
        self._update_arp_indicator()

    def _check_arp_health(self) -> None:
        """Surface poison-thread death / send errors (Fix 1).

        Previously last_error was recorded but never shown, and the UI
        counted the in-memory dict even if the thread was dead. Log each
        new state once; recovery is logged too.
        """
        health = self.arp.health()
        error = health["last_error"] or ""
        running = health["running"]
        if error and error != self._last_arp_error:
            self.log_line(f"⚠ Force-offline error: {error}")
            self.footer.configure(text=f"⚠ Force-offline failing: {error[:90]}")
        if health["targets"] and not running:
            if self._last_arp_running is not False:
                self.log_line(
                    "⚠ ARP blocker thread stopped but "
                    f"{health['targets']} device(s) are still marked forced offline — "
                    "they may be back online. Restore and re-add to recover."
                )
        elif running and self._last_arp_running is False:
            self.log_line("ARP blocker thread recovered.")
        self._last_arp_error = error
        self._last_arp_running = running

    def _update_arp_indicator(self) -> None:
        try:
            health = self.arp.health()
            count = health["targets"]
            if count:
                dead = not health["running"]
                if dead:
                    self.arp_label.configure(
                        text=f"⚠ Blocker stopped — {count} device{'s' if count != 1 else ''} may be online",
                        bg="#FEE2E2", fg="#991B1B",
                    )
                elif health["last_error"]:
                    self.arp_label.configure(
                        text=f"{count} forced offline ⚠ check log",
                        bg="#FEF3C7", fg="#92400E",
                    )
                else:
                    self.arp_label.configure(
                        text=f"{count} device{'s' if count != 1 else ''} forced offline",
                        bg="#FFEDD5", fg="#9A3412",
                    )
                if not self.arp_indicator.winfo_ismapped():
                    self.arp_indicator.pack(side="left", padx=(8, 0))
            else:
                if self.arp_indicator.winfo_ismapped():
                    self.arp_indicator.pack_forget()
        except Exception:
            pass

    def _arp_failed(self, message: str) -> None:
        if "Npcap" in message:
            answer = messagebox.askyesno(
                APP_NAME,
                message + "\n\nInstall it now? (Free, one installer window. Restart NetGuard afterwards.)",
            )
            if answer:
                self._install_npcap()
            return
        if "administrator" in message:
            if messagebox.askyesno(APP_NAME, message + "\n\nRestart NetGuard as administrator now?"):
                self._relaunch_admin()
            return
        messagebox.showerror(APP_NAME, message)

    def _install_npcap(self) -> None:
        installer = os.path.join(os.environ.get("TEMP", ""), "opencode", "npcap-1.90.exe")
        if os.path.exists(installer):
            try:
                import ctypes

                ctypes.windll.shell32.ShellExecuteW(None, "runas", installer, "", None, 1)
                self.log_line("Npcap installer opened - follow the wizard, then restart NetGuard.")
                return
            except Exception:
                pass
        webbrowser.open("https://npcap.com/#download")
        self.log_line("Opened npcap.com - download and install it, then restart NetGuard.")

    def _relaunch_admin(self) -> None:
        if is_admin():
            return
        try:
            import ctypes

            params = "-m netguard"
            if getattr(sys, "frozen", False):
                params = ""
                target = sys.executable
            else:
                target = sys.executable
            ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, os.getcwd(), 1)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not restart as administrator:\n{exc}")
            return
        self._on_close()

    def _on_close(self) -> None:
        try:
            if self.arp.running or self.arp.targets:
                self.arp.stop()
        except Exception:
            pass
        self.destroy()

    def _identify_selected(self) -> None:
        """Re-run fingerprinting for the selected device, ignoring the cache."""
        row = self.selected_row()
        if not row or not row.ip:
            return
        self.footer.configure(text=f"Identifying {row.title}…")

        def work():
            try:
                device = scanner.Device(mac=row.mac, ip=row.ip, hostname=row.name, vendor=row.vendor)
                result = fingerprint.guess(row.ip, row.mac, row.vendor, row.name)
            except Exception as exc:
                message = str(exc)
                self.post(lambda m=message: (self.log_line(f"Identification failed: {m}"), self.footer.configure(text="Identification failed")))
                return
            self.post(lambda r=result, mac=row.mac: self._identify_done(mac, r))

        threading.Thread(target=work, daemon=True).start()

    def _identify_done(self, mac: str, result: fingerprint.Fingerprint) -> None:
        rec = self.store.record(mac)
        rec.update(result.as_dict())
        self.store.save_devices()
        row = self.rows.get(mac)
        if row:
            row.guess = result.guess
            row.kind = result.category
            row.evidence = tuple(result.evidence)
            row.randomized = result.randomized
        self.log_line(f"Likely device for {mac}: {result.guess} ({result.confidence})")
        self.footer.configure(text=f"Likely device: {result.guess}")
        self.render()

    def _rename_selected(self) -> None:
        row = self.selected_row()
        if not row:
            return
        from tkinter import simpledialog

        name = simpledialog.askstring(APP_NAME, "Name this device:", initialvalue=row.name, parent=self)
        if name is None:
            return
        rec = self.store.record(row.mac)
        rec["name"] = name.strip()
        self.store.save_devices()
        row.name = name.strip()
        self.render()

    def _copy_mac(self) -> None:
        row = self.selected_row()
        if row:
            self.clipboard_clear()
            self.clipboard_append(row.mac)
            self.footer.configure(text="MAC address copied")

    def _context_menu(self, event) -> None:
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
        menu = tk.Menu(self, tearoff=0)
        row = self.rows.get(row_id) if row_id else None
        menu.add_command(label="Block device", command=lambda: self._act_block(False))
        menu.add_command(label="Unblock", command=lambda: self._act_block(True))
        menu.add_separator()
        menu.add_command(
            label="Restore connection" if row and row.arp_blocked else "Force offline (no password)",
            command=self._act_arp,
        )
        menu.add_command(
            label="Unprotect" if row and row.protected else "Protect this device",
            command=self._toggle_protect,
        )
        menu.add_separator()
        menu.add_command(label="Identify device", command=self._identify_selected)
        menu.add_command(label="Rename…", command=self._rename_selected)
        menu.add_command(label="Copy MAC", command=self._copy_mac)
        menu.add_command(label="Open router admin page", command=lambda: webbrowser.open(self.store.config.get("router_url") or self.default_router_url()))
        menu.tk_popup(event.x_root, event.y_root)

    def _export(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export device list", defaultextension=".csv",
            initialfile="netguard-devices.csv", filetypes=[("CSV files", "*.csv")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(["Name", "Likely device", "Evidence", "IP", "MAC", "Vendor", "Type", "Online", "Blocked", "First seen", "Last seen"])
                for row in sorted(self.rows.values(), key=lambda r: (r.name or r.ip)):
                    writer.writerow([row.title, row.guess or "Unknown device", "; ".join(row.evidence),
                                     row.ip, row.mac, row.vendor, row.kind,
                                     "yes" if row.online else "no", "yes" if row.blocked else "no",
                                     human(row.first_seen), human(row.last_seen)])
            self.footer.configure(text=f"Exported to {path}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not export:\n{exc}")

    def _diagnostics(self) -> None:
        if not (self.router and self.router.logged_in):
            messagebox.showinfo(APP_NAME, "Connect to the router first (Router login).")
            return
        try:
            info = self.router.info()
            clients = self.router.clients()
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Diagnostics failed:\n{exc}")
            return
        lines = [f"{k}: {v}" for k, v in info.items()]
        lines.append(f"clients found: {len(clients)}")
        lines.append("")
        for c in clients[:30]:
            lines.append(f"  {c.get('mac')}  {str(c.get('ip', '')):<15}  {c.get('hostname', '')}")

        win = tk.Toplevel(self)
        win.title("Router diagnostics")
        win.configure(bg=BG)
        win.geometry("620x420")
        win.transient(self)
        tk.Label(win, text="Router diagnostics", font=(FONT, 14, "bold"), bg=BG, fg=INK).pack(anchor="w", padx=16, pady=(14, 4))
        tk.Label(win, text="Read-only view of what NetGuard found on the router.",
                 font=(FONT, 9), bg=BG, fg=MUTED).pack(anchor="w", padx=16, pady=(0, 8))
        box = tk.Text(win, font=("Consolas", 9), bg=CARD, fg=INK, relief="solid", bd=1, padx=10, pady=10)
        box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        box.insert("1.0", "\n".join(lines))
        box.configure(state="disabled")

    # -- persistence helpers ---------------------------------------------
    def _tick(self) -> None:
        try:
            self._refresh_network_info()
            self._check_arp_health()
            self._update_arp_indicator()
        except Exception:
            pass
        try:
            if self.auto_var.get() and not self.scanning and self.iface:
                self.start_scan(False)
        except Exception:
            pass
        try:
            interval = max(5, int(self.interval_var.get() or 20))
        except ValueError:
            interval = 20
        self.after(interval * 1000, self._tick)

    def _save_auto(self) -> None:
        self.store.config["auto_refresh"] = self.auto_var.get()
        self.store.save_config()

    def _save_offline(self) -> None:
        self.store.config["show_offline"] = self.offline_var.get()
        self.store.save_config()
        self.render()
