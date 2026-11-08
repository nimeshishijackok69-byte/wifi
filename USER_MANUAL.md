# NetGuard user manual

NetGuard shows every device connected to your home Wi-Fi and lets you disconnect a device you do not want there.

You do **not** need the router password just to see devices. You need it only for the permanent **Block device** option. If you do not know it, use **Force offline** instead.

---

## Quick start (30 seconds)

1. Connect this computer to the home Wi-Fi.
2. Double-click **`NetGuard.bat`**.
3. Wait a few seconds. You will see a list of connected devices.
4. Find the device you want to remove and click it once.
5. Click **Force offline**.
6. The device should lose internet in a few seconds.

That is it. If you want it to work, read the one-time setup below.

---

## What the list means

The table has one row per device. Each row shows:

- **Device** – the name NetGuard found, for example `POCO-C55`, or the name you gave it with **Rename**.
- **Likely device** – an extra guess about what it probably is, like a phone or laptop.
- **IP address** – the address it has on your home network.
- **MAC address** – the hardware address of that device.
- **Vendor** – the company that made the device, when known. Phones using a private MAC may show `—`.
- **Type** – phone, computer, router, TV, etc.
- **Last seen** – how recently the device was visible.

Two rows are always special:

- **This computer** – your computer. It cannot be blocked by NetGuard.
- **Router / Gateway** – your router. It cannot be blocked either.

At the time this manual was tested, the list on the home router looked like:

| Device | Where it is |
|---|---|
| Router / Gateway | `192.168.1.1` (Huawei) |
| OPPO-A15 | `192.168.1.33` |
| POCO-C55 | `192.168.1.34` |
| V2207 | `192.168.1.38` |
| moto-g45-5G | `192.168.1.42` |
| motorola-edge-50-fusion | `192.168.1.43` |
| This computer | `192.168.1.36` |

Your list may change as people join or leave the network.

---

## First-time setup

### Step 1: install the blocking driver

“Force offline” needs a free program called **Npcap**. It is the same packet driver used by Wireshark and Nmap.

- If NetGuard asks you to get it, click **Yes** to open the official Npcap download page in your browser.
- Download and run the Npcap installer, click **Next** a few times and then **Finish**.
- If Npcap is already installed, you do not need to do anything here.

### Step 2: run NetGuard as administrator

“Force offline” only works when NetGuard runs as administrator.

- If you opened `NetGuard.bat`, you may see a yellow banner at the top.
- Click **Run as admin**.
- Windows will ask for permission. Click **Yes**.
- NetGuard will reopen. That is normal.

You can also directly double-click **`NetGuard-admin.bat`**.

---

## See and identify devices

### Scan now

Click **Scan now** to refresh the list. NetGuard also checks automatically every 20 seconds. You can change that time in the box next to **Auto refresh**.

### Search

Type part of a device name, IP address or MAC address in **Search** to find it quickly.

### Show offline

By default, NetGuard hides devices that have left. Tick **Show offline** if you want to see devices that were connected earlier but are not online now.

### Rename a device

Select a device and click **Rename…**. Use a name you will recognise later, such as:

- `My phone`
- `Mother's phone`
- `TV`
- `Unknown neighbour phone?`

The name is saved, so it stays on that device next time you open NetGuard.

### Identify device

Click **Identify device** if the name is unclear. NetGuard looks for simple clues on that device and shows why it made its guess in the details panel.

Because a phone may use a private, random MAC address, sometimes the exact brand is hidden. The router DNS name is usually the most useful name, and NetGuard reads it automatically.

---

## Mark your family's devices as safe

Do this before blocking anyone.

1. Click **your phone**.
2. Click **Protect device**.
3. Rename it to something clear, like `My phone`.
4. Repeat for your family's devices.

A 🛡 sign appears next to a protected device. NetGuard will stop and ask you to confirm before it blocks a protected one.

---

## Disconnect a device without the router password

Use this if you do not know the Excitel router password.

1. Click **Run as admin** if the yellow banner is still shown.
2. Select the device you want to disconnect.
3. Click **Force offline**.
4. NetGuard does not ask for confirmation for a normal device (you can undo it at any time). If the device is **Protected**, it asks you to confirm first — click **Yes** to go ahead.
5. Wait a few seconds and check that phone. It should still show as connected to Wi-Fi, but its internet should stop working.

### Undo it

Select the same device and click **Restore connection**. It should reconnect within a few seconds, up to about a minute. The log at the bottom says whether the restore packets were sent.

If you have blocked more than one device, click **Restore all** at the top of the window to bring them all back at once.

### If you close NetGuard

Closing NetGuard stops all force-offline blocking and restores everyone. That is intentional and safe.

> **Important:** this restore only works on a clean close. If NetGuard crashes, you kill it in Task Manager, or the PC loses power, the device stays offline until its network cache expires — usually 30–60 seconds, sometimes up to about 2 minutes. It always comes back on its own; the block is never saved permanently.

---

## Permanent router block (needs the router password)

If you later find the router password, you can ask the router itself to block a device. This is more permanent: it keeps working even if NetGuard is closed.

1. Click **Router login**.
2. Type the username and password you use at `http://192.168.1.1`. On this router the username is usually `excitel`.
3. Click **Test & save**.
4. When the top badge says **ROUTER CONNECTED**, select a device.
5. Click **Block device** and confirm.

To undo it, select the blocked device and click **Unblock**.

If the router says the password is wrong, NetGuard cannot do the permanent block. Use **Force offline** instead.

---

## Right-click menu

You can also right-click a device to:

- Block or unblock it
- Force it offline or restore it
- Protect it
- Identify it
- Rename it
- Copy its MAC address
- Open the router admin page

---

## Export the list

Click **Export CSV** to save the device list as a spreadsheet file. This is handy if you want to keep a record of the devices you have seen.

---

## Common questions

### My phone still says “Connected” after I block it. Did it fail?

No. With **Force offline**, the device can remain connected to Wi-Fi, but its internet stops. Check whether websites stop loading on that phone.

With a **router block**, the router drops the device itself. Its status in NetGuard may still say “Online” for about a minute because old network information can linger. Press **Scan now** after a minute.

### It says Npcap is missing. What do I do?

Install Npcap from <https://npcap.com> (the **Force offline** prompt opens that page), then restart NetGuard.

### It says it needs administrator. What do I do?

Close NetGuard and open **`NetGuard-admin.bat`** instead. Click **Yes** when Windows asks.

### The device list looks empty. What do I do?

Click **Scan now**. Make sure this computer is on the same home Wi-Fi. If it still looks empty, the router may be hiding clients from this computer. Restart NetGuard and try again.

### Why does a device have no name?

Some phones hide their brand with a private MAC address. Click **Identify device**, or rename the row once you recognise it by turning that phone's Wi-Fi off and watching which row disappears.

### Why does my antivirus warn me?

“Force offline” uses the same kind of network packet that security tools monitor. It is used here only on your own home network, and NetGuard does not forward or read your internet traffic.

### Where are my settings saved?

They are saved on this computer in:

```text
%APPDATA%\NetGuard\
```

The router password, if you save it, is stored using Windows encryption (DPAPI). If Windows encryption fails, NetGuard logs a warning saying so — the password is then stored in plain text in that file, so only rely on it on your own computer. It is only sent to your own router, not to the internet.

---

## A safe way to learn which device is which

1. Protect and rename your own phone and your family's phones.
2. Pick one unknown device.
3. Click **Force offline**.
4. Ask around the house: “Did your internet stop?” or test that phone's browser.
5. If it is yours, click **Restore connection** and protect it.
6. If nobody recognises it, leave it forced offline until you are sure; protect it if you learn it is yours.

---

## One-page reminder

- **`NetGuard.bat`** – normal launch
- **`NetGuard-admin.bat`** – needed for **Force offline**
- Click a device → **Protect device** before blocking anything
- Click a device → **Force offline** to disconnect it without the router password
- Click **Restore connection** to bring it back
- Click **Router login** only if you know the Excitel admin password and want a permanent router block
