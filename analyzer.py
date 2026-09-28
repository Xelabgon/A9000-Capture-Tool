"""Small, conservative decoder for Windows Native Wi-Fi BSS entries."""

from dataclasses import asdict, dataclass, field


IE_NAMES = {
    0: "SSID", 1: "Supported rates", 3: "DS parameter set", 5: "TIM",
    7: "Country", 45: "HT capabilities", 48: "RSN (security)",
    50: "Extended rates", 61: "HT operation", 71: "Multiple BSSID",
    191: "VHT capabilities", 192: "VHT operation", 221: "Vendor specific",
    255: "Extension",
}
EXT_NAMES = {35: "HE capabilities (802.11ax)", 36: "HE operation",
             108: "EHT capabilities (802.11be)", 109: "EHT operation"}
PHY_NAMES = {1: "FHSS", 2: "DSSS", 3: "IR", 4: "OFDM (a)",
             5: "HR-DSSS (b)", 6: "ERP (g)", 7: "HT (n)",
             8: "VHT (ac)", 9: "DMG (ad)", 10: "HE (ax)",
             11: "EHT (be)"}


@dataclass
class Element:
    number: int
    name: str
    hex_data: str


@dataclass
class Network:
    interface: str
    ssid: str
    bssid: str
    frequency_mhz: float
    band: str
    channel: str
    rssi_dbm: int
    signal_quality: int
    advertised_phy: str
    driver_phy: str
    operating_width: str
    security_hint: str
    beacon_interval_ms: float
    observed_at: str
    ie_hex: str
    elements: list[Element] = field(default_factory=list)
    warning: str = ""

    def export(self):
        return asdict(self)


@dataclass
class Footprint:
    """Approximate occupied frequency intervals, in MHz."""
    ranges: list[tuple[float, float]]
    estimated: bool
    description: str


def spectrum_footprint(network: Network) -> Footprint:
    """Prefer operation IEs; otherwise show a clearly marked 20/22 MHz lower bound.

    The BSS frequency is the primary channel, not the centre of a bonded channel.
    In particular, an 80 MHz AP on channel 36 occupies 5170–5250 MHz when
    VHT operation identifies channel 42 as its centre.
    """
    primary = network.frequency_mhz
    fallback_width = 22 if network.band == "2.4 GHz" else 20
    fallback = Footprint([(primary - fallback_width / 2, primary + fallback_width / 2)],
                         True, f"≥{fallback_width} MHz shown; actual width unknown")
    if network.band not in ("2.4 GHz", "5 GHz", "6 GHz"):
        return fallback

    # The 6 GHz operating channel width lives in HE/EHT operation, which v0.2
    # does not decode. Never reuse a VHT or HT centre from another band.
    if network.band == "6 GHz":
        return fallback

    ies = {}
    for element in network.elements:
        if element.number in (61, 192):
            ies[element.number] = bytes.fromhex(element.hex_data)

    if network.band == "5 GHz":
        vht = ies.get(192, b"")
        if len(vht) >= 3 and vht[0] in (1, 2, 3) and vht[1]:
            center_0 = 5000 + 5 * vht[1]
            center_1 = 5000 + 5 * vht[2] if vht[2] else None
            if vht[0] == 1:
                if center_1 and abs(vht[1] - vht[2]) == 8:
                    ranges = [(center_1 - 80, center_1 + 80)]
                    label = "160 MHz (VHT operation)"
                else:
                    ranges = [(center_0 - 40, center_0 + 40)]
                    label = "80 MHz (VHT operation)"
            elif vht[0] == 2:
                ranges = [(center_0 - 80, center_0 + 80)]
                label = "160 MHz (VHT operation)"
            else:
                ranges = ([(center_0 - 40, center_0 + 40),
                           (center_1 - 40, center_1 + 40)] if center_1 else [])
                label = "80+80 MHz (VHT operation)"
            if (ranges and any(low <= primary < high for low, high in ranges)
                    and all(4900 <= low < high <= 5930 for low, high in ranges)):
                return Footprint(ranges, False, label)

    ht = ies.get(61, b"")
    if len(ht) >= 2:
        secondary = ht[1] & 3
        if secondary in (1, 3):
            center = primary + (10 if secondary == 1 else -10)
            return Footprint([(center - 20, center + 20)], False,
                             "40 MHz (HT operation)")
        if secondary == 0:
            width = 22 if network.band == "2.4 GHz" else 20
            return Footprint([(primary - width / 2, primary + width / 2)], False,
                             f"{width} MHz (HT operation)")
    return fallback


def channel_analysis(networks: list[Network]):
    """Return footprint and overlap classifications indexed by BSS list order."""
    footprints = [spectrum_footprint(n) for n in networks]
    shared = [set() for _ in networks]
    adjacent = [set() for _ in networks]
    for i, first in enumerate(networks):
        for j in range(i + 1, len(networks)):
            second = networks[j]
            if first.band != second.band:
                continue
            crossing = any(min(a_high, b_high) > max(a_low, b_low) + 0.01
                           for a_low, a_high in footprints[i].ranges
                           for b_low, b_high in footprints[j].ranges)
            if crossing:
                target = shared if abs(first.frequency_mhz - second.frequency_mhz) < 0.1 else adjacent
                target[i].add(j)
                target[j].add(i)
    return footprints, shared, adjacent


def parse_elements(blob: bytes):
    """Return parsed IEs and a warning if a length is invalid; never read past blob."""
    elements = []
    i = 0
    while i < len(blob):
        if len(blob) - i < 2:
            return elements, f"Truncated element header at byte {i}"
        number, length = blob[i], blob[i + 1]
        i += 2
        if length > len(blob) - i:
            return elements, f"Element {number} at byte {i - 2} exceeds IE buffer"
        data = blob[i:i + length]
        i += length
        extension = data[0] if number == 255 and data else None
        name = (EXT_NAMES.get(extension, f"Extension {extension}")
                if extension is not None else IE_NAMES.get(number, f"Element {number}"))
        elements.append(Element(number, name, data.hex(" ")))
    return elements, ""


def band_and_channel(frequency_khz: int):
    mhz = frequency_khz / 1000
    if 2400 <= mhz <= 2500:
        channel = 14 if mhz == 2484 else round((mhz - 2407) / 5)
        return mhz, "2.4 GHz", str(channel) if 1 <= channel <= 14 else "?"
    if 5000 <= mhz < 5925:
        channel = round((mhz - 5000) / 5)
        return mhz, "5 GHz", str(channel) if channel > 0 else "?"
    if 5925 <= mhz <= 7125:
        channel = 2 if mhz == 5935 else round((mhz - 5950) / 5)
        return mhz, "6 GHz", str(channel) if channel >= 1 else "?"
    return mhz, "Other", "?"


def describe_ies(elements: list[Element], band: str, driver_phy: int,
                 privacy: bool):
    ids = {e.number for e in elements}
    ext = set()
    by_id = {}
    for element in elements:
        raw = bytes.fromhex(element.hex_data)
        by_id[element.number] = raw
        if element.number == 255 and raw:
            ext.add(raw[0])

    if 108 in ext:
        standard = "802.11be (advertised)"
    elif 35 in ext:
        standard = "802.11ax (advertised)"
    elif 191 in ids:
        standard = "802.11ac (advertised)"
    elif 45 in ids:
        standard = "802.11n (advertised)"
    else:
        # This is a driver-reported PHY, not proof of per-frame modulation.
        standard = f"Driver: {PHY_NAMES.get(driver_phy, 'unknown')}"

    width = "Unknown"
    vht = by_id.get(192, b"")
    ht = by_id.get(61, b"")
    if len(vht) >= 3 and vht[0] in (1, 2, 3):
        if vht[0] == 1:
            width = "160 MHz" if vht[2] and abs(vht[1] - vht[2]) == 8 else "80 MHz"
        elif vht[0] == 2:
            width = "160 MHz"
        else:
            width = "80+80 MHz"
    elif len(ht) >= 2:
        width = "40 MHz" if ht[1] & 0x03 in (1, 3) else "20 MHz"
    if band == "6 GHz":
        # 6 GHz width comes from HE/EHT operation; the HT/VHT IEs do not apply.
        width = "Unknown (6 GHz operation not decoded)"

    if 48 in ids:
        security = "RSN advertised (inspect IE for details)"
    elif privacy:
        security = "Privacy flag set; method unknown"
    else:
        security = "No privacy flag / no RSN"
    return standard, width, security
