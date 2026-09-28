"""Run with: py -3 -m unittest test_decoder.py"""

import ctypes as C
import unittest

from analyzer import (Network, band_and_channel, channel_analysis, describe_ies,
                      parse_elements, spectrum_footprint)
from native_wifi import BssEntry, read_bss_list


class DecoderTests(unittest.TestCase):
    def network(self, channel, frequency, band="5 GHz", ies=b"", bssid="02:00:00:00:00:01"):
        elements, _ = parse_elements(ies)
        return Network("A9000", "Lab", bssid, frequency, band, str(channel), -55,
                       85, "802.11ac", "VHT", "Unknown", "RSN", 102.4,
                       "today", ies.hex(" "), elements)

    def test_extension_capabilities_and_truncated_ie(self):
        elements, warning = parse_elements(b"\xff\x02\x6c\x01\xff\x02\x23\x01")
        self.assertEqual(warning, "")
        self.assertEqual(elements[0].name, "EHT capabilities (802.11be)")
        self.assertEqual(describe_ies(elements, "5 GHz", 10, False)[0],
                         "802.11be (advertised)")
        _, warning = parse_elements(b"\x2d\xff\x00")
        self.assertIn("exceeds IE buffer", warning)

    def test_6ghz_and_ht_width(self):
        self.assertEqual(band_and_channel(5935000), (5935, "6 GHz", "2"))
        elements, _ = parse_elements(b"\x3d\x02\x24\x01")
        self.assertEqual(describe_ies(elements, "5 GHz", 7, False)[1], "40 MHz")
        self.assertIn("Unknown", describe_ies(elements, "6 GHz", 7, False)[1])

    def test_native_bss_length_bounds(self):
        entry = BssEntry()
        entry.ssid.length = 3
        entry.ssid.data[:3] = b"Lab"
        entry.frequency_khz = 5180000
        entry.ie_offset = C.sizeof(BssEntry)
        entry.ie_size = 4
        blob = b"\xff\x02\x23\x00"
        size = 8 + C.sizeof(entry) + len(blob)
        raw = C.create_string_buffer(size)
        C.c_uint32.from_buffer(raw, 0).value = size
        C.c_uint32.from_buffer(raw, 4).value = 1
        C.memmove(C.addressof(raw) + 8, C.byref(entry), C.sizeof(entry))
        C.memmove(C.addressof(raw) + 8 + C.sizeof(entry), blob, len(blob))
        row = read_bss_list(C.addressof(raw))[0]
        self.assertEqual(row[0], "Lab")
        self.assertEqual(row[7], "802.11ax (advertised)")
        entry.ie_offset = size + 100
        C.memmove(C.addressof(raw) + 8, C.byref(entry), C.sizeof(entry))
        self.assertIn("IEs skipped", read_bss_list(C.addressof(raw))[0][-1])

    def test_5ghz_bonded_block_is_centered_on_vht_segment(self):
        # Primary 36 = 5180 MHz; VHT centre 42 = 5210 MHz, thus 5170–5250.
        ap36 = self.network(36, 5180, ies=b"\xc0\x03\x01\x2a\x00")
        ap44 = self.network(44, 5220, bssid="02:00:00:00:00:02")
        footprint = spectrum_footprint(ap36)
        self.assertEqual(footprint.ranges, [(5170, 5250)])
        self.assertFalse(footprint.estimated)
        _, same, adjacent = channel_analysis([ap36, ap44])
        self.assertEqual(same, [set(), set()])
        self.assertEqual(adjacent, [{1}, {0}])

    def test_24ghz_channel_one_and_six_separate_but_one_and_five_overlap(self):
        one = self.network(1, 2412, band="2.4 GHz")
        six = self.network(6, 2437, band="2.4 GHz")
        five = self.network(5, 2432, band="2.4 GHz")
        footprints, _, adjacent = channel_analysis([one, six, five])
        self.assertTrue(footprints[0].estimated)
        self.assertNotIn(1, adjacent[0])
        self.assertIn(2, adjacent[0])

    def test_6ghz_unknown_width_is_marked_lower_bound(self):
        ap = self.network(5, 5975, band="6 GHz", ies=b"\xff\x02\x6d\x00")
        footprint = spectrum_footprint(ap)
        self.assertTrue(footprint.estimated)
        self.assertEqual(footprint.ranges, [(5965, 5985)])


if __name__ == "__main__":
    unittest.main()
