# A9000 Capture Tool

A Windows desktop app for surveying nearby Wi-Fi radios, visualizing their advertised channel overlap, and saving **passive 802.11 captures** as Wireshark-readable PCAP files. The raw capture backend is built for the **NETGEAR A9000** (`USB\VID_0846&PID_9072`, MediaTek MT7925AU) with a WinUSB binding.

The app listens on a selected channel. It can record the authentication, association, and EAPOL frames exchanged when a device connects, along with the other frames received on that channel. It has no Wi-Fi frame injection controls.

## What it does

| View | Features |
| --- | --- |
| **Networks** | Live BSSID list with SSID, band, channel, frequency, RSSI, advertised PHY, width, and security information. Inspect decoded information elements or export the current list as CSV/JSON. |
| **Channel overlaps** | Plot approximate frequency footprints and identify BSSIDs with a shared primary channel or overlapping advertised widths. Switch between the available bands. |
| **Capture** | Lock the A9000 to one channel and save received 802.11 frames in Radiotap PCAP format. Optionally limit saved frames by AP, client MAC, or frame scope. |

The A9000 survey updates the list as APs are found during each sweep. Automatic sweeps pause while a capture is running and resume afterward.

## Requirements

- Windows and Python **3.11 or newer**.
- A NETGEAR A9000 bound to **WinUSB** for passive surveys and raw capture.
- Dependencies from `requirements.txt`: PySide6, PyUSB, and `libusb-package`.
- Wireshark to inspect the resulting `.pcap` files (optional for running the app).

An Intel AX200 or other Windows Wi-Fi adapter can be selected as a **Windows WLAN discovery source** for the network and overlap views. Raw 802.11 capture in this release requires the A9000. This is a user-space USB application using WinUSB, not an installable replacement kernel Wi-Fi driver. Binding the A9000 to WinUSB means Windows will no longer use that adapter for ordinary Wi-Fi connections until its normal driver is restored.

### A9000 driver binding

If your A9000 already works with WinUSB, keep that binding. Otherwise, use [Zadig](https://zadig.akeo.ie/) to select the **A9000 only**, verify hardware ID **VID `0846`, PID `9072`**, and install WinUSB. Close any program using the adapter, then unplug and reconnect it. Make sure you have another way to connect to the internet before switching the A9000's driver.

To restore ordinary Wi-Fi later, use Windows Device Manager to update the A9000's driver back to the NETGEAR driver. A9000 Capture Tool does not need wifit3 running; close it before launching this app because both programs need the adapter.

## Install and run

From PowerShell in this repository's folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

The commands use the environment's Python directly, so PowerShell activation is unnecessary. Keep `vendor/wifit3/` and its firmware assets beside the application files when copying the project. The app loads the firmware included in that directory when needed.

## Capture a device connecting

1. Select **A9000 · passive USB monitor** under **Discovery source**. Wait for your AP to appear in **Networks**. Selecting its row fills the capture channel and AP selection.
2. Open **Capture** and confirm the AP's **primary channel**. The A9000 stays on this one channel for the entire recording.
3. Choose **All frames** for a full channel recording. To save just management and EAPOL frames, choose **Connection frames**. Leave **AP filter** and **Client filter** off for the most complete recording; they filter packets *when saving*, after reception.
4. Choose an output path ending in `.pcap`. The default duration is **90 seconds**; `0` records until you press **Stop and save PCAP**. The app will not overwrite an existing file.
5. Press **Start passive capture**, then connect or reconnect your test device normally. Stop the capture if needed and open the PCAP in Wireshark.

Useful Wireshark display filters:

```text
wlan.fc.type == 0 || eapol
wlan.addr == aa:bb:cc:dd:ee:ff
```

The first shows management frames and EAPOL. Replace the address in the second with your device's current MAC address; some phones use a private MAC per network. The in-app event log reports observed connection events and the saved frame count, while Wireshark provides the detailed packet view.

**AP filter** enables a list labeled with SSID, BSSID, and channel. With the box unchecked, that list is disabled and the selected AP does not limit what is saved. A client MAC filter can be entered separately. `Export CSV` and `Export JSON` save the *discovered network list*, not captured packets; use **Capture** for PCAP.

## Survey behavior and limits

- A9000 survey channels in this release: **1–14, 36, 40, 44, 48, 149, 153, 157, 161, 165**. Its raw capture path does **not** support 6 GHz. A separate adapter's Windows WLAN discovery results may include 6 GHz networks.
- Each A9000 sweep listens for about **300 ms per channel**, so a full sweep takes roughly 7–9 seconds. The default **15-second** automatic survey interval is a wait *after* the sweep finishes; available waits are 10, 15, 30, 60, 120, or 300 seconds. Windows WLAN scans use a minimum 30-second interval.
- One adapter on one channel can miss activity on other channels. A short survey dwell can also miss an AP that does not transmit while that channel is visited.
- The overlap view estimates spectrum occupied from advertised information. It does not measure airtime use, interference, or channel utilization. A BSSID identifies a radio network, not necessarily a separate physical AP; unknown widths are shown as minimum footprints.
- PCAP timestamps are computer reception times, not precise over-the-air times. Radiotap carries the selected channel and RSSI when available; the receive path does not provide rate/noise information and strips the frame check sequence.
- Packet capture does not automatically decrypt protected data traffic. Captures can contain device identifiers and connection details; review them before sharing or committing them to a public repository.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| A9000 startup or USB error | Close wifit3 and other programs using the A9000; confirm the `0846:9072` device has a WinUSB binding; unplug/replug it and restart the app. |
| No APs appear | Allow a full sweep, confirm that nearby APs are active on the supported channels, and verify that **A9000 · passive USB monitor** is the selected discovery source. |
| PCAP misses the connection | Start capture before the device connects and select the AP's actual primary channel. Try **All frames** with AP and client filters off; check whether the phone uses a private MAC. |
| Capture button is disabled | Wait for the A9000 status to report ready. A Windows WLAN adapter can survey but cannot run this raw capture backend. |
| Output file already exists | Choose a new `.pcap` filename; existing recordings are never overwritten. |

## Project files

| Path | Purpose |
| --- | --- |
| `app.py` | PySide6 GUI and application flow. |
| `monitor_engine.py` | A9000 USB startup, channel surveys, and fixed-channel capture. |
| `frame_logic.py` | Beacon decoding and optional capture filters. |
| `analyzer.py`, `native_wifi.py` | Network metadata, overlap analysis, and Windows WLAN discovery. |
| `pcap_writer.py` | Radiotap PCAP output. |
| `vendor/wifit3/` | Trimmed MT7925AU receive-side implementation and firmware assets. |

Run the offline tests from the project folder with:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_decoder.py test_monitor.py
```

The A9000 capture path has been exercised on a Windows A9000 with a real phone connection. The tests cover frame decoding, filtering, and PCAP structure; they do not replace live testing on other A9000 systems.

## Credits and license

The `vendor/wifit3/` directory contains a trimmed receive-side port from [derv82/wifit3 v0.3.3](https://github.com/derv82/wifit3/tree/v0.3.3), commit `75714287b8085f16fb28f225da0ccc8d85b5529f`. The bundled MediaTek firmware has its own terms in [`vendor/wifit3/chips/mt7925au/assets/LICENCE.mediatek`](vendor/wifit3/chips/mt7925au/assets/LICENCE.mediatek).

The Python application is distributed under **GPL-2.0-only**; see [`LICENSE`](LICENSE). Keep the license, upstream notices, and firmware license with the project when publishing it.
