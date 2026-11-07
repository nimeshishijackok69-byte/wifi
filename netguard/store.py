"""Local persistence for settings and the device inventory."""

from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import tempfile
import threading

APP_DIR = os.path.join(os.environ.get("APPDATA", tempfile.gettempdir()), "NetGuard")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
DEVICES_FILE = os.path.join(APP_DIR, "devices.json")

_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# Windows DPAPI so the router password is not stored in clear text.
# --------------------------------------------------------------------------
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _protect(text: str) -> str:
    if not text:
        return ""
    try:
        raw = text.encode("utf-8")
        blob_in = _Blob(len(raw), ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_char)))
        blob_out = _Blob()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), "NetGuard", None, None, None, 0, ctypes.byref(blob_out)
        )
        if not ok:
            return "plain:" + text
        data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return "dpapi:" + base64.b64encode(data).decode()
    except Exception:
        return "plain:" + text


def _unprotect(token: str) -> str:
    if not token:
        return ""
    try:
        if token.startswith("dpapi:"):
            raw = base64.b64decode(token[6:])
            blob_in = _Blob(len(raw), ctypes.cast(ctypes.create_string_buffer(raw), ctypes.POINTER(ctypes.c_char)))
            blob_out = _Blob()
            ok = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
            )
            if not ok:
                return ""
            data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return data.decode("utf-8", errors="ignore")
        if token.startswith("plain:"):
            return token[6:]
        return token
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "router_url": "",
    "username": "excitel",
    "password_token": "",
    "remember_password": True,
    "auto_refresh": True,
    "interval": 20,
    "deep_scan": False,
    "show_offline": False,
}


class Store:
    def __init__(self) -> None:
        os.makedirs(APP_DIR, exist_ok=True)
        self.config = dict(DEFAULT_CONFIG)
        self.devices: dict[str, dict] = {}
        self.load()

    # -- io ---------------------------------------------------------------
    def load(self) -> None:
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                self.config.update(json.load(fh))
        except Exception:
            pass
        try:
            with open(DEVICES_FILE, "r", encoding="utf-8") as fh:
                self.devices = json.load(fh)
        except Exception:
            self.devices = {}

    def save_config(self) -> None:
        with _LOCK:
            _atomic_write(CONFIG_FILE, self.config)

    def save_devices(self) -> None:
        with _LOCK:
            _atomic_write(DEVICES_FILE, self.devices)

    # -- credentials ------------------------------------------------------
    @property
    def password(self) -> str:
        return _unprotect(self.config.get("password_token", ""))

    @password.setter
    def password(self, value: str) -> None:
        if self.config.get("remember_password", True):
            self.config["password_token"] = _protect(value)
        else:
            self.config["password_token"] = ""

    @property
    def password_is_plain(self) -> bool:
        """True when DPAPI failed and the token is stored in clear text.

        Fix 5: _protect() silently fell back to "plain:" — callers must
        surface that instead of claiming DPAPI encryption.
        """
        return str(self.config.get("password_token", "")).startswith("plain:")

    # -- device records ---------------------------------------------------
    def record(self, mac: str) -> dict:
        return self.devices.setdefault(mac, {"name": "", "first_seen": 0, "last_seen": 0, "blocked": False})

    def merge_scan(self, devices: dict[str, dict]) -> None:
        """devices maps mac -> {ip, hostname, vendor, ...}"""
        import time

        now = time.time()
        for mac, info in devices.items():
            rec = self.record(mac)
            rec["last_seen"] = now
            if not rec.get("first_seen"):
                rec["first_seen"] = now
            if info.get("hostname") and not rec.get("name"):
                rec["hostname"] = info["hostname"]
            rec["ip"] = info.get("ip", rec.get("ip", ""))
            if "blocked" in info:
                rec["blocked"] = bool(info["blocked"])
            for key in ("guess", "guess_category", "guess_confidence", "guess_evidence"):
                if info.get(key):
                    rec[key] = info[key]
            if info.get("randomized") is not None:
                rec["randomized"] = bool(info["randomized"])
            if info.get("fingerprint_at"):
                rec["fingerprint_at"] = info["fingerprint_at"]
        self.save_devices()


def _atomic_write(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        pass
