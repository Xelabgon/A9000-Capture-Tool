"""Synthetic 802.11 frames; never stores a user's wireless capture."""

import io
import struct
import unittest

from frame_logic import include_frame, inspect_frame, network_from_frame
from pcap_writer import PcapWriter


AP = bytes.fromhex("020000000001")
CLIENT = bytes.fromhex("020000000002")
AP_MAC = "02:00:00:00:00:01"
CLIENT_MAC = "02:00:00:00:00:02"


def header(fc, a1, a2, a3):
    return struct.pack("<HH", fc, 0) + a1 + a2 + a3 + b"\x00\x00"


class MonitorTests(unittest.TestCase):
    def test_beacon_discovery_and_overlap_input(self):
        beacon = (header(0x80, b"\xff" * 6, AP, AP) +
                  b"\x00" * 8 + struct.pack("<HH", 100, 0x11) +
                  b"\x00\x03Lab\x03\x01\x06\x3d\x02\x06\x00")
        net = network_from_frame(beacon, 6, -51)
        self.assertEqual((net.ssid, net.bssid, net.channel, net.rssi_dbm),
                         ("Lab", AP_MAC, "6", -51))
        self.assertIsNone(network_from_frame(beacon, 11, -51))
        self.assertTrue(include_frame(inspect_frame(beacon), "Connection frames", AP_MAC, CLIENT_MAC))

    def test_auth_assoc_and_four_way_capture_filters(self):
        auth = header(0xB0, AP, CLIENT, AP) + struct.pack("<HHH", 0, 1, 0)
        assoc = header(0x00, AP, CLIENT, AP) + b"\x00" * 4
        self.assertIn("Authentication", inspect_frame(auth).event)
        self.assertEqual(inspect_frame(assoc).event, "Association request")
        for flags, expected in ((0x008A, "M1"), (0x010A, "M2"),
                                (0x13CA, "M3"), (0x030A, "M4")):
            from_ap = expected in ("M1", "M3")
            frame = (header(0x0208 if from_ap else 0x0108,
                            CLIENT if from_ap else AP,
                            AP if from_ap else CLIENT,
                            AP) + b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" +
                     b"\x02\x03\x00\x00\x02" + struct.pack(">H", flags))
            info = inspect_frame(frame)
            self.assertEqual(info.eapol, expected)
            self.assertTrue(include_frame(info, "Connection frames", AP_MAC, CLIENT_MAC))
            self.assertFalse(include_frame(info, "Connection frames", AP_MAC,
                                           "02:00:00:00:00:03"))

    def test_wireshark_pcap_layout(self):
        frame = header(0xB0, AP, CLIENT, AP) + struct.pack("<HHH", 0, 1, 0)
        stream = io.BytesIO()
        writer = PcapWriter(stream, 157)
        writer.write(frame, -53, 1_700_000_000_000_001_000)
        data = stream.getvalue()
        self.assertEqual(struct.unpack_from("<I", data, 20)[0], 127)
        self.assertEqual(struct.unpack_from("<IIII", data, 24)[:2],
                         (1_700_000_000, 1))
        self.assertEqual(struct.unpack_from("<HH", data, 48), (5785, 0x100))
        self.assertEqual(data[24 + 16 + 13:], frame)


if __name__ == "__main__":
    unittest.main()
