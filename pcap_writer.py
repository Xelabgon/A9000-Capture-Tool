"""Stream raw 802.11 MPDUs into a libpcap file with minimal Radiotap metadata."""

import struct
import time


LINKTYPE_IEEE802_11_RADIOTAP = 127


def channel_frequency(channel: int) -> tuple[int, int]:
    """Return MHz and Radiotap 2 GHz / 5 GHz band flag."""
    if channel == 14:
        return 2484, 0x0080
    if 1 <= channel <= 13:
        return 2407 + 5 * channel, 0x0080
    if 36 <= channel <= 177:
        return 5000 + 5 * channel, 0x0100
    raise ValueError(f"Unsupported 2.4/5 GHz channel: {channel}")


def radiotap(channel: int, rssi: int | None) -> bytes:
    freq, flags = channel_frequency(channel)
    # Radiotap bit 3: channel (u16 MHz, u16 flags), aligned at byte 8.
    # Bit 5: optional signed dBm antenna signal, aligned at byte 12.
    with_signal = rssi is not None and -127 <= rssi <= 0
    present = (1 << 3) | ((1 << 5) if with_signal else 0)
    header_len = 12 + int(with_signal)
    header = struct.pack("<BBHIHH", 0, 0, header_len, present, freq, flags)
    return header + (struct.pack("<b", rssi) if with_signal else b"")


class PcapWriter:
    """Write each received frame immediately; the caller owns the file handle."""

    def __init__(self, file, channel: int):
        channel_frequency(channel)
        self.file = file
        self.channel = channel
        self.packets = 0
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                    65535, LINKTYPE_IEEE802_11_RADIOTAP))

    def write(self, frame: bytes, rssi: int | None = None,
              timestamp_ns: int | None = None) -> None:
        if len(frame) < 2:
            return
        ns = time.time_ns() if timestamp_ns is None else timestamp_ns
        sec, remainder = divmod(ns, 1_000_000_000)
        payload = radiotap(self.channel, rssi) + frame
        self.file.write(struct.pack("<IIII", sec, remainder // 1000,
                                    len(payload), len(payload)))
        self.file.write(payload)
        self.packets += 1
