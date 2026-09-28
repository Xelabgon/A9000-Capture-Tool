"""Decode A9000 monitor frames for discovery and connection capture filtering."""

from dataclasses import dataclass
from datetime import datetime
import struct

from analyzer import Network, describe_ies, parse_elements
from pcap_writer import channel_frequency


def mac(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in raw)


def normalize_mac(value: str) -> str:
    parts = value.replace("-", ":").strip().split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError("Use six hexadecimal bytes, e.g. AA:BB:CC:DD:EE:FF")
    try:
        return mac(bytes(int(part, 16) for part in parts))
    except ValueError as exc:
        raise ValueError("MAC address must contain only hexadecimal bytes") from exc


@dataclass(frozen=True)
class FrameInfo:
    frame_type: int
    subtype: int
    bssid: str | None
    addresses: frozenset[str]
    eapol: str | None
    event: str | None


def inspect_frame(frame: bytes) -> FrameInfo | None:
    if len(frame) < 2:
        return None
    fc = int.from_bytes(frame[:2], "little")
    kind, subtype = (fc >> 2) & 3, (fc >> 4) & 15
    addresses = frozenset(mac(frame[i:i + 6]) for i in (4, 10, 16)
                          if len(frame) >= i + 6)
    bssid = None
    event = None
    eapol = None
    if kind in (0, 2) and len(frame) >= 24:
        a1, a2, a3 = [mac(frame[i:i + 6]) for i in (4, 10, 16)]
        ds = (fc >> 8) & 3
        bssid = a3 if kind == 0 or ds == 0 else a1 if ds == 1 else a2 if ds == 2 else None
        if ds == 3 and len(frame) >= 30:
            addresses |= {mac(frame[24:30])}
        if kind == 0:
            if subtype == 11 and len(frame) >= 30:
                algorithm, sequence, status = struct.unpack_from("<HHH", frame, 24)
                event = (f"Authentication alg {algorithm}, step {sequence}, "
                         f"status {status}")
            elif subtype in (0, 2):
                event = "Association request" if subtype == 0 else "Reassociation request"
            elif subtype in (1, 3) and len(frame) >= 28:
                status = struct.unpack_from("<H", frame, 26)[0]
                event = ("Association" if subtype == 1 else "Reassociation") + f" response, status {status}"
            elif subtype == 12:
                event = "Deauthentication observed"
        else:
            offset = 24 + (6 if ds == 3 else 0) + (2 if subtype & 8 else 0)
            if fc & 0x8000 and subtype & 8:  # HT control after QoS control
                offset += 4
            e = frame[offset:]
            if len(e) >= 8 and e[:8] == b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
                e = e[8:]
                if len(e) >= 7 and e[1] == 3:
                    flags = struct.unpack_from(">H", e, 5)[0]
                    pairwise = bool(flags & 0x0008)
                    ack, mic, secure = bool(flags & 0x80), bool(flags & 0x100), bool(flags & 0x200)
                    if pairwise:
                        eapol = "M1" if ack and not mic else "M3" if ack else "M4" if secure else "M2"
                    else:
                        eapol = "Group key"
                    event = f"EAPOL {eapol}"
                else:
                    eapol, event = "Other", "EAPOL"
    return FrameInfo(kind, subtype, bssid, addresses, eapol, event)


def network_from_frame(frame: bytes, channel: int, rssi: int | None) -> Network | None:
    info = inspect_frame(frame)
    if info is None or info.frame_type != 0 or info.subtype not in (5, 8):
        return None
    if len(frame) < 36 or info.bssid is None:
        return None
    elements, warning = parse_elements(frame[36:])
    advertised_channel = next((bytes.fromhex(e.hex_data)[0] for e in elements
                               if e.number in (3, 61) and e.hex_data), None)
    if advertised_channel is not None and advertised_channel != channel:
        # USB RX can deliver frames queued just before a channel switch.
        return None
    ssid_raw = next((bytes.fromhex(e.hex_data) for e in elements if e.number == 0), b"")
    ssid = ssid_raw.decode("utf-8", "replace") or "<hidden>"
    freq, _ = channel_frequency(channel)
    band = "2.4 GHz" if channel <= 14 else "5 GHz"
    capabilities = int.from_bytes(frame[34:36], "little")
    phy, width, security = describe_ies(elements, band, 0, bool(capabilities & 0x10))
    if phy.startswith("Driver:"):
        phy = "Unknown (no PHY capability IE)"
    interval = int.from_bytes(frame[32:34], "little") * 1.024
    return Network("A9000 passive USB", ssid, info.bssid, float(freq), band,
                   str(channel), rssi if rssi is not None else -128, -1, phy,
                   "Raw 802.11 (PHY rate unknown)", width, security, interval,
                   datetime.now().astimezone().isoformat(timespec="seconds"),
                   frame[36:].hex(" "), elements, warning)


def include_frame(info: FrameInfo | None, scope: str, bssid: str = "",
                  client: str = "") -> bool:
    """Apply optional filters after reception; keep target AP beacons as context."""
    if info is None:
        return False
    if scope == "Connection frames" and info.frame_type != 0 and info.eapol is None:
        return False
    if bssid and info.bssid != bssid:
        return False
    if client and client not in info.addresses:
        if not (bssid and info.bssid == bssid and info.frame_type == 0
                and info.subtype in (5, 8)):
            return False
    return True
