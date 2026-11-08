# NetGuard

A small Windows desktop app that shows every device on your Wi-Fi/Ethernet and
lets you **block** or **unblock** a device — through your own router, or, if the
router admin password is unknown, with **Force offline** (ARP blocking).

For a plain-language guide, see **[USER_MANUAL.md](USER_MANUAL.md)**.

Built for the router in this home: an Excitel-branded Huawei ONT
(web UI at `http://192.168.1.1`, Boa web server, pages under `/html/ssmp/…`).
It also works with other Huawei ONTs that use the same web interface.

```
NetGuard/
├─ NetGuard.bat          ← double-click to run (no console window)
├─ NetGuard-admin.bat    ← same, launched as administrator (needed for Force offline)
├─ NetGuard-debug.bat    ← same, but keeps the console open for error messages
├─ netguard/             ← the application
└─ tests/                ← offline test suite with a fake router
```

The core app needs only Python 3.10+ and the standard library. **Force offline**
additionally needs:
- the free **Npcap** packet driver (Wireshark/Nmap use it; the app opens its official download page),
- the **scapy** Python package (`pip install scapy`), and
- the app running **as administrator** (`NetGuard-admin.bat`).

---

## Quick start

1. Connect the PC to the router's Wi-Fi.
2. Double-click **NetGuard.bat**.
3. To block through the router, click **Router login** and enter the admin
   credentials:
   - **Username:** `excitel`
   - **Password:** the router admin password (see *Finding the password* below)
4. Press **Test & save**. When the badge turns green you can block devices.

The device list itself works **without** the router login — it is built from the
local ARP table and reverse DNS. If you do not have the router password, select
a device and use **Force offline** instead (see below).

---

## What you can do

| Action | How |
| --- | --- |
| See every device | Automatic; refresh every 20 s (configurable) |
| Who is this? | Hover the row, or read the details panel: vendor, hostname, type |
| Likely device | **Likely device** column + evidence in the details panel (see below); **Identify device** re-checks a device |
| Block / disconnect | Select a device → **Block device**. The router adds its MAC to the MAC filter and drops it immediately. |
| Unblock | Select a blocked device → **Unblock** |
| Force offline (no password) | Select a device → **Force offline**. Works without router login; lasts while NetGuard stays open. |
| Restore | The button becomes **Restore connection**; **Restore all** undoes every force-offline at once. |
| Protect a device | **Protect this device** marks it as yours/family so it is never blocked by accident (🛡 in the list). |
| Rename | Give devices friendly names (“Rahul’s phone”) — stored locally |
| Export | **Export CSV** for a spreadsheet |
| Diagnose | **Router diagnostics** shows which router pages were found |

Router blocking uses the router's own **MAC filter**, so it survives reboots and
works for phones, TVs, laptops and wired devices alike.

---

## Force offline (when the router password is lost)

The router can only ban a device when its admin password is known. **Force
offline** takes a different route: this computer answers ARP for the target, so
the target and the router can no longer find each other. Traffic is **dropped**,
not forwarded — this is a block, not a man-in-the-middle.

What it needs:

1. **Npcap** installed (free; <https://npcap.com>). NetGuard opens the official
   download page the first time you need it; it never runs an installer itself.
2. NetGuard started **as administrator** (`NetGuard-admin.bat`, or accept the
   “Restart as administrator” prompt). Windows requires this to send raw frames.
3. This PC switched on and on the same network.

Limits, honestly:

- The block ends when NetGuard is closed, or the PC sleeps/disconnects. That is
  by design: closing the app restores every device.
- **Clean close only.** If NetGuard crashes, is killed from Task Manager, or
  the PC loses power, no restore packets can be sent. The device then stays
  offline until its ARP cache expires — typically ~30–60 s, up to ~2 min on
  some IoT gear. It cannot stay offline forever: nothing is persisted.
- The router still counts the device as connected; it simply gets no traffic.
- IPv4 only. This LAN has no IPv6, which is why the method is reliable here.
- Some antivirus products flag ARP manipulation, because attackers use the same
  mechanism. Here it runs only on your own network.

Safety built in: the router and this computer can never be targeted, **Protect**
marks family devices, and if a blocked IP is later handed to a different device,
NetGuard notices and stops blocking it.

---

## Identifying devices (and the honest limit)

A MAC address only reveals the maker when the manufacturer assigned it. Phones,
tablets and laptops increasingly use *randomised* (locally administered) MAC
addresses, so their vendor and brand are deliberately hidden. In that case,
**no tool can identify a device by MAC alone** — the address is random.

NetGuard therefore adds a **Likely device** column and an evidence list using:

- whether the MAC is randomised or a normal manufacturer address;
- host/DHCP or NetBIOS name, if offered;
- open ports (SMB, RTSP, SSH, web …);
- web server header and page title;
- UPnP/SSDP identification; and
- mDNS names/services.

It can usually name TVs, cameras, printers, speakers, PCs, consoles, NAS and
normal-MAC devices. A randomised-MAC neighbour is shown as a personal
phone/tablet/laptop, but not its person or brand.

To tell yours from strangers reliably:

1. Pick a device and **Protect device** + rename it if it looks like yours.
2. Or turn a phone's Wi-Fi off (or force it offline) one at a time and watch
   which row disappears / loses internet.
3. The router DHCP host name is the strongest automatic name, but it requires
   the router admin password.

If the same IP reappears with a new random MAC, NetGuard notes “Used this IP
earlier as …” so the two rows can be linked.

---

## Finding the router password

The login is the same one used at <http://192.168.1.1>.

- Look at the sticker on the **bottom** of the ONT (the photo of the top label
  only shows the MAC/serial). Huawei stickers usually print
  `Username / Password`, often `user` / a random password.
- Excitel's installer often sets a custom admin password; the Wi-Fi password is
  *not* necessarily the same.
- If the password is lost, Excitel support can give it, or a factory reset of
  the ONT restores the printed credentials (this also resets Wi-Fi settings).

The app never sends credentials anywhere except to your own router.

---

## How it works (short version)

1. **Discovery** – a UDP burst makes Windows resolve every address in the /24,
   then the ARP neighbour table is read. NetGuard then asks the **gateway
   directly for PTR records** (for example `33.1.168.192.in-addr.arpa`). Home
   routers embed DHCP lease hostnames there, which is how the app can name
   phones without the admin password. Windows' normal resolver usually points
   upstream and does not know LAN hostnames, so it is used only as a fallback.
2. **Identification** – each online unknown device is lightly fingerprinted
   (private/random MAC check, open ports, web/UPnP/mDNS names) so the list can
   label likely categories. Cached results are reused for five minutes.
3. **Router list** – after login, NetGuard crawls the router's frameset, finds
   the DHCP-host page and the MAC-filter page, and parses their tables.
4. **Blocking** – it fills the filter page's own “add MAC” form and submits it,
   then re-reads the page to *verify* the MAC is listed. Unblock uses the row's
   delete control (or `…?macaddr=…&action=delete` as a fallback).
5. **Safety** – the router itself and this computer can never be blocked.
   **Block device** always asks for confirmation; **Force offline** asks
   only for **Protected** devices.
6. **Force offline** – sends forged ARP replies to the target and the gateway
   every 1.5 s, so neither can resolve the other; nothing is forwarded. Stopping
   the block re-announces the correct mappings several times.

Stored data lives in `%APPDATA%\NetGuard\`:

- `config.json` – router URL, username, settings. The password is encrypted with
  Windows DPAPI (only your Windows user can decrypt it). If DPAPI fails,
  NetGuard logs a warning and the password is stored in plain text instead.
- `devices.json` – names, first/last seen, blocked, protected and identification state.

---

## Troubleshooting

**“ROUTER LOGIN FAILED: bad password”**
The username exists but the password is wrong. Check the sticker / call Excitel.

**“Could not find the router's MAC filter page”**
Open **Router diagnostics**. It lists the pages NetGuard found. Some firmware
hides MAC filtering behind *Security → MAC Filter*; open that page once in a
browser, then press **Scan now**.

**A blocked device still appears “Online”**
ARP entries linger for a minute. The device is actually filtered by the router;
the status clears on the next scan.

**The app shows no devices**
Windows may isolate clients (guest Wi-Fi / AP isolation) or the PC is on a
different subnet. Use the router login: the DHCP list still shows every client.

**“Force offline” says it needs the Npcap driver**
Install Npcap from <https://npcap.com> (NetGuard opens that page for you), then
restart NetGuard.

**“Force offline” says it needs administrator**
Close and open **NetGuard-admin.bat**, or accept the “Restart as administrator”
prompt. Windows does not allow raw packets otherwise.

**A force-offline device still appears “Online”**
Expected: the router still counts it as connected. It has no working traffic.
The status in NetGuard means “still visible on the network”, not “has internet”.

---

## Tests

```
python tests\test_router.py
python tests\test_app_flow.py
python tests\test_arpblock.py
python tests\test_fingerprint.py
python tests\test_network_names.py
python tests\test_regressions.py
```

The first runs the full router flow (login → client list → block → verify →
unblock) against a local mock ONT, so it works without touching the real router.
The second drives the GUI against the same mock. The third checks the ARP
safety guards and the exact frames that would be sent (no packets leave the PC).
The fourth checks the randomised-MAC detector, the mDNS parser and the
identification cache. The fifth checks the gateway PTR name lookup, both
against a canned DNS reply and, on a live network, against the router itself.
The last locks down the audited failure modes: session expiry, HTTP errors,
filter-mode detection, slot-based verification, delete-form selection, phantom
client rows, IP preservation, gateway selection, CSV injection, elevation
failure and the Npcap flow.

`tools\fingerprint_devices.py` prints the current LAN identification guesses.
`tools\arp_selftest.py` is a one-off check that this PC can actually send raw
frames; run it **as administrator** after installing Npcap. It only asks the
router to identify itself and sends one harmless ARP for a reserved test address.
