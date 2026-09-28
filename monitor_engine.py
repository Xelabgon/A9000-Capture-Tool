"""A9000 fixed-channel capture and receive-only periodic channel surveys."""

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
from queue import Empty, Queue
import sys
import time
from typing import Callable

from frame_logic import include_frame, inspect_frame, network_from_frame
from pcap_writer import PcapWriter


CHANNELS = tuple(range(1, 15)) + (36, 40, 44, 48, 149, 153, 157, 161, 165)
VID, PID = 0x0846, 0x9072
SURVEY_DWELL_SECONDS = 0.30


@dataclass(frozen=True)
class CaptureOptions:
    channel: int
    output: Path
    duration: float
    scope: str = "All frames"
    bssid: str = ""
    client: str = ""


class MonitorEngine:
    """Runs entirely inside a QThread; callbacks report GUI-safe signals."""

    def __init__(self, emit: Callable[[str, object], None]):
        self.emit = emit
        self.commands: Queue = Queue()
        self.interval = 15
        self.transport = None
        self.device = None
        self.rx = None
        self.mcu = None
        self.channel = None
        self.settle_until = 0.0
        self.antenna_mask = 0x3
        self.mode = "idle"
        self.survey = {}
        self.capture = None
        self.options = None
        self.writer = None
        self.deadline = None
        self.counts = {"frames": 0, "management": 0, "control": 0,
                       "data": 0, "eapol": 0, "bad_fcs": 0}
        self.failed = None

    def submit(self, action: str, value=None):
        self.commands.put((action, value))

    async def open(self):
        if os.name != "nt":
            raise RuntimeError("Live A9000 capture requires Windows and WinUSB")
        vendor = str(Path(__file__).resolve().parent / "vendor")
        if vendor not in sys.path:
            sys.path.insert(0, vendor)
        import libusb_package
        import usb.core
        import usb.util
        from wifit3.chips.mt7925au import init, mcu, rx
        from wifit3.chips.mt7925au.constants import (
            EP_OUT_FW, EP_OUT_MCU, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY,
        )
        from wifit3.chips.mt7925au.firmware import MT7925AUFirmwareLoader
        from wifit3.chips.mt7925au.transport import MT7925AUTransport

        class ReceiveOnlyTransport(MT7925AUTransport):
            async def send_bulk_checked(self, data, ep, timeout=2000):
                if ep not in (EP_OUT_FW, EP_OUT_MCU):
                    raise RuntimeError(f"Frame injection endpoint blocked: 0x{ep:02X}")
                return await super().send_bulk_checked(data, ep, timeout)

        self.usb_util = usb.util
        self.mcu, self.rx = mcu, rx
        backend = libusb_package.get_libusb1_backend()
        if backend is None:
            raise RuntimeError("No libusb backend found")
        devices = list(usb.core.find(find_all=True, idVendor=VID, idProduct=PID,
                                     backend=backend))
        if len(devices) != 1:
            raise RuntimeError(f"Found {len(devices)} A9000 adapters (need exactly one). "
                               "Close wifit3 and check the WinUSB binding.")
        self.device = devices[0]
        self.transport = ReceiveOnlyTransport(self.device)
        assets = Path(__file__).resolve().parent / "vendor/wifit3/chips/mt7925au/assets"
        firmware = MT7925AUFirmwareLoader(self.transport, assets)
        self.transport._on_fatal = self._usb_failure
        self.emit("status", "Checking A9000 firmware...")
        firmware._claim_vendor_interface(clear_halts=False)
        warm = bool(self.transport.read_reg32(MT_CONN_ON_MISC) & MT_TOP_MISC2_FW_N9_RDY)
        if warm:
            self.emit("status", "Reattaching to running A9000 firmware...")
            if firmware.dma_need_reinit():
                firmware._dma_init(resume=True)
            self.transport.drain_rx()
            self.transport.start_rx()
            for _ in range(3):
                reply = await self.transport.send_mcu_command(*mcu.get_nic_capability())
                caps = mcu.parse_nic_capability(reply or b"")
                if caps.mac:
                    break
            self.antenna_mask = caps.antenna_mask if caps.mac else 0x3
            await self.set_channel(CHANNELS[0])
        else:
            self.emit("status", "Loading A9000 firmware...")
            if not await firmware.load_firmware():
                raise RuntimeError("Firmware failed to start. Unplug/replug A9000 and retry.")
            self.transport.start_rx()
            state = await init.post_boot_init(self.transport)
            self.antenna_mask = state.caps.antenna_mask
            await init.enter_monitor(self.transport, CHANNELS[0], state.caps.has_6ghz)
            self.channel = CHANNELS[0]
        self.transport.subscribe(self._on_raw)
        self.emit("ready", True)
        self.emit("status", "A9000 monitor ready; scanning nearby radios...")

    def _usb_failure(self, exc):
        self.failed = exc

    async def set_channel(self, channel: int):
        if channel not in CHANNELS:
            raise ValueError(f"Unsupported A9000 channel: {channel}")
        if self.channel == channel:
            return
        # Mirrors the upstream warm channel-switch command. The firmware's
        # channel response is not guaranteed, so use the upstream no-wait path.
        await self.transport.send_mcu_command(*self.mcu.config_sniffer(channel),
                                              wait_resp=False)
        self.channel = channel
        self.settle_until = time.monotonic() + 0.07

    def _on_raw(self, data: bytes):
        decoded = self.rx.decode_frame(data, self.antenna_mask)
        if decoded is None:
            return
        start, end, rssi, bad_fcs = decoded
        if bad_fcs:
            self.counts["bad_fcs"] += 1
            return
        frame = bytes(data[start:end])
        if self.mode == "survey":
            if time.monotonic() < self.settle_until:
                return
            network = network_from_frame(frame, self.channel, rssi)
            if network is not None:
                prior = self.survey.get(network.bssid)
                if prior is None or network.ssid != "<hidden>" or prior.ssid == "<hidden>":
                    self.survey[network.bssid] = network
        elif self.mode == "capture":
            info = inspect_frame(frame)
            if not include_frame(info, self.options.scope,
                                 self.options.bssid, self.options.client):
                return
            try:
                self.writer.write(frame, rssi)
                if self.writer.packets % 100 == 0:
                    self.capture.flush()
            except OSError as exc:
                self.failed = exc
                return
            self.counts["frames"] += 1
            self.counts[{0: "management", 1: "control", 2: "data"}.get(
                info.frame_type, "data")] += 1
            if info.eapol:
                self.counts["eapol"] += 1
            if info.event:
                self.emit("event", (time.strftime("%H:%M:%S"), info.event,
                                    info.bssid or "", self.channel, rssi))

    async def survey_once(self, stop_requested: Callable[[], bool]) -> bool:
        self.survey = {}
        self.mode = "survey"
        last_partial = 0.0
        last_count = 0
        for channel in CHANNELS:
            if stop_requested() or self.failed or not self.commands.empty():
                self.mode = "idle"
                return False
            await self.set_channel(channel)
            self.emit("status", f"Passive survey: channel {channel} · "
                                f"{len(self.survey)} BSSIDs seen")
            await asyncio.sleep(SURVEY_DWELL_SECONDS)
            now = time.monotonic()
            if len(self.survey) > last_count and now - last_partial >= 0.75:
                self.emit("survey_partial", list(self.survey.values()))
                last_partial, last_count = now, len(self.survey)
        self.mode = "idle"
        self.emit("networks", list(self.survey.values()))
        self.emit("status", f"Survey complete: {len(self.survey)} BSSIDs. "
                            f"Next sweep in {self.interval} s.")
        return True

    async def start_capture(self, options: CaptureOptions):
        if options.channel not in CHANNELS or options.duration < 0:
            raise ValueError("Unsupported channel or negative duration")
        if options.output.exists():
            raise FileExistsError(f"Capture already exists: {options.output}")
        await self.set_channel(options.channel)
        self.capture = options.output.open("xb")
        self.writer = PcapWriter(self.capture, options.channel)
        self.options = options
        self.counts = {key: 0 for key in self.counts}
        self.deadline = time.monotonic() + options.duration if options.duration else None
        self.mode = "capture"
        self.emit("capture_started", str(options.output))
        self.emit("status", f"Capturing channel {options.channel}; reconnect the device now.")

    def stop_capture(self):
        if self.mode != "capture":
            return
        self.mode = "idle"
        handle = self.capture
        self.capture = self.writer = None
        try:
            handle.flush()
        finally:
            handle.close()
        saved = (str(self.options.output), dict(self.counts))
        self.options = None
        self.deadline = None
        self.emit("capture_done", saved)

    async def run(self, stop_requested: Callable[[], bool]):
        try:
            await self.open()
            next_sweep = time.monotonic()
            next_stats = time.monotonic()
            while not stop_requested():
                if self.failed:
                    raise RuntimeError(f"USB receive or capture failed: {self.failed}")
                if self.mode == "capture" and self.deadline is not None and time.monotonic() >= self.deadline:
                    self.stop_capture()
                    next_sweep = time.monotonic() + self.interval
                try:
                    action, value = self.commands.get_nowait()
                except Empty:
                    action = None
                if action == "capture":
                    if self.mode == "capture":
                        self.emit("error", "A capture is already running")
                    else:
                        try:
                            await self.start_capture(value)
                        except (OSError, ValueError) as exc:
                            self.emit("error", str(exc))
                elif action == "stop":
                    self.stop_capture()
                    next_sweep = time.monotonic() + self.interval
                elif action == "interval":
                    self.interval = max(10, int(value))
                    next_sweep = time.monotonic() + self.interval
                elif action == "rescan":
                    if self.mode != "capture":
                        next_sweep = time.monotonic()
                if self.mode == "capture" and time.monotonic() >= next_stats:
                    self.emit("statistics", dict(self.counts))
                    next_stats = time.monotonic() + 1
                if self.mode != "capture" and time.monotonic() >= next_sweep:
                    finished = await self.survey_once(stop_requested)
                    if finished:
                        next_sweep = time.monotonic() + self.interval
                await asyncio.sleep(0.05)
        except Exception as exc:
            self.emit("error", str(exc))
        finally:
            try:
                self.stop_capture()
            except Exception as exc:
                self.emit("error", f"Could not finalize PCAP: {exc}")
            try:
                if self.transport is not None:
                    self.transport.subscribe(None)
                    await self.transport.stop_rx()
                if self.device is not None:
                    self.usb_util.dispose_resources(self.device)
            except Exception as exc:
                self.emit("error", f"Could not release A9000: {exc}")
            finally:
                self.emit("ready", False)
                self.emit("status", "A9000 stopped")
