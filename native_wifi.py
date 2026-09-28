"""Windows WLAN API access. No Npcap or monitor mode is used."""

import ctypes as C
from ctypes import wintypes as W
from datetime import datetime
import os
import uuid

from analyzer import Network, PHY_NAMES, band_and_channel, describe_ies, parse_elements


DWORD = C.c_uint32
ULONG = C.c_uint32
USHORT = C.c_uint16
LONG = C.c_int32
BYTE = C.c_uint8
ULONGLONG = C.c_uint64


class GUID(C.Structure):
    _fields_ = [("Data1", DWORD), ("Data2", USHORT), ("Data3", USHORT),
                ("Data4", BYTE * 8)]


class InterfaceInfo(C.Structure):
    # Use UTF-16 code units explicitly: c_wchar is 4 bytes off Windows.
    _fields_ = [("guid", GUID), ("description", USHORT * 256), ("state", DWORD)]


class SSID(C.Structure):
    _fields_ = [("length", ULONG), ("data", BYTE * 32)]


class RateSet(C.Structure):
    _fields_ = [("length", ULONG), ("rates", USHORT * 126)]


class BssEntry(C.Structure):
    _fields_ = [("ssid", SSID), ("phy_id", ULONG), ("bssid", BYTE * 6),
                ("bss_type", DWORD), ("phy_type", DWORD), ("rssi", LONG),
                ("quality", ULONG), ("in_domain", BYTE), ("beacon_period", USHORT),
                ("timestamp", ULONGLONG), ("host_timestamp", ULONGLONG),
                ("capability", USHORT), ("frequency_khz", ULONG),
                ("rate_set", RateSet), ("ie_offset", ULONG), ("ie_size", ULONG)]


def check(result, operation):
    if result:
        hint = (" Allow location access in Windows Settings → Privacy & security → Location "
                "(including desktop apps), then retry." if result == 5 else "")
        raise OSError(f"{operation} failed: Windows error {result}. {os.strerror(result)}.{hint}")


def read_bss_list(address: int):
    """Copy BSS data while WLAN owns the allocation. Bounds checked against total size."""
    total = DWORD.from_address(address).value
    count = DWORD.from_address(address + 4).value
    size = C.sizeof(BssEntry)
    if total < 8 or total > 64 * 1024 * 1024 or count > (total - 8) // size:
        raise ValueError("Invalid WLAN BSS list size or count")
    entry_base = address + 8
    networks = []
    for n in range(count):
        entry_address = entry_base + n * size
        entry = BssEntry.from_buffer_copy(C.string_at(entry_address, size))
        start = entry_address + entry.ie_offset
        end = start + entry.ie_size
        if (entry.ie_size > 2324 or entry.ie_offset < size or
                start < address or end > address + total):
            blob = b""
            warning = "Invalid IE offset or length; IEs skipped"
        else:
            blob = C.string_at(start, entry.ie_size)
            warning = ""
        elements, parse_warning = parse_elements(blob)
        warning = "; ".join(x for x in (warning, parse_warning) if x)
        ssid_length = min(entry.ssid.length, 32)
        ssid = bytes(entry.ssid.data[:ssid_length]).decode("utf-8", "replace")
        mhz, band, channel = band_and_channel(entry.frequency_khz)
        phy, width, security = describe_ies(elements, band, entry.phy_type,
                                             bool(entry.capability & 0x10))
        networks.append((ssid or "<hidden>", ":".join(f"{b:02X}" for b in entry.bssid),
                         mhz, band, channel, entry.rssi, entry.quality, phy,
                         entry.phy_type, width, security, entry.beacon_period * 1.024,
                         blob.hex(" "), elements, warning))
    return networks


class WifiApi:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("Live scans require Windows 10/11")
        self.dll = C.WinDLL("wlanapi")
        self.dll.WlanOpenHandle.argtypes = [DWORD, C.c_void_p, C.POINTER(DWORD), C.POINTER(C.c_void_p)]
        self.dll.WlanOpenHandle.restype = DWORD
        self.dll.WlanCloseHandle.argtypes = [C.c_void_p, C.c_void_p]
        self.dll.WlanCloseHandle.restype = DWORD
        self.dll.WlanEnumInterfaces.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_void_p)]
        self.dll.WlanEnumInterfaces.restype = DWORD
        self.dll.WlanGetNetworkBssList.argtypes = [C.c_void_p, C.POINTER(GUID), C.c_void_p,
                                                    DWORD, C.c_bool, C.c_void_p, C.POINTER(C.c_void_p)]
        self.dll.WlanGetNetworkBssList.restype = DWORD
        self.dll.WlanScan.argtypes = [C.c_void_p, C.POINTER(GUID), C.c_void_p, C.c_void_p, C.c_void_p]
        self.dll.WlanScan.restype = DWORD
        self.dll.WlanFreeMemory.argtypes = [C.c_void_p]
        self.dll.WlanFreeMemory.restype = None
        self.handle = C.c_void_p()

    def __enter__(self):
        negotiated = DWORD()
        check(self.dll.WlanOpenHandle(2, None, C.byref(negotiated), C.byref(self.handle)),
              "WlanOpenHandle")
        return self

    def __exit__(self, *_):
        if self.handle:
            self.dll.WlanCloseHandle(self.handle, None)

    def interfaces(self):
        pointer = C.c_void_p()
        check(self.dll.WlanEnumInterfaces(self.handle, None, C.byref(pointer)),
              "WlanEnumInterfaces")
        try:
            address = pointer.value
            count = DWORD.from_address(address).value
            if count > 128:
                raise ValueError("Invalid WLAN interface count")
            result = []
            for n in range(count):
                item = InterfaceInfo.from_buffer_copy(C.string_at(address + 8 + n * C.sizeof(InterfaceInfo),
                                                                  C.sizeof(InterfaceInfo)))
                name = bytes(item.description).decode("utf-16-le").split("\0", 1)[0]
                uid = str(uuid.UUID(bytes_le=bytes(item.guid)))
                result.append((uid, name, item.state))
            return result
        finally:
            self.dll.WlanFreeMemory(pointer)

    def scan(self, guid_text):
        guid = GUID.from_buffer_copy(uuid.UUID(guid_text).bytes_le)
        check(self.dll.WlanScan(self.handle, C.byref(guid), None, None, None), "WlanScan")

    def bss_list(self, guid_text, interface_name):
        guid = GUID.from_buffer_copy(uuid.UUID(guid_text).bytes_le)
        pointer = C.c_void_p()
        check(self.dll.WlanGetNetworkBssList(self.handle, C.byref(guid), None, 3, False,
                                             None, C.byref(pointer)), "WlanGetNetworkBssList")
        try:
            observed_at = datetime.now().astimezone().isoformat(timespec="seconds")
            return [Network(interface_name, *row[:8],
                            PHY_NAMES.get(row[8], "Unknown"),
                            *row[9:12], observed_at, *row[12:])
                    for row in read_bss_list(pointer.value)]
        finally:
            self.dll.WlanFreeMemory(pointer)
