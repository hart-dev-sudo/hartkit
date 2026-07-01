import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.arp_table import parse_arp_table, BROADCAST_MAC

WINDOWS_ARP_OUTPUT = """
Interface: 192.168.1.100 --- 0xe
  Internet Address      Physical Address      Type
  192.168.1.1            aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.255          ff-ff-ff-ff-ff-ff     static
"""

UNIX_ARP_OUTPUT = """
? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
? (192.168.1.50) at 11:22:33:44:55:66 [ether] on eth0
"""


class TestParseArpTable(unittest.TestCase):
    def test_parses_windows_style_output(self):
        entries = parse_arp_table(WINDOWS_ARP_OUTPUT)
        self.assertEqual(entries["192.168.1.1"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(entries["192.168.1.255"], BROADCAST_MAC)

    def test_parses_unix_style_output(self):
        entries = parse_arp_table(UNIX_ARP_OUTPUT)
        self.assertEqual(entries["192.168.1.1"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(entries["192.168.1.50"], "11:22:33:44:55:66")

    def test_normalizes_mac_separator(self):
        entries = parse_arp_table("192.168.1.1  AA-BB-CC-DD-EE-FF")
        self.assertEqual(entries["192.168.1.1"], "aa:bb:cc:dd:ee:ff")

    def test_empty_output_returns_empty_dict(self):
        self.assertEqual(parse_arp_table(""), {})

    def test_lines_without_mac_are_ignored(self):
        entries = parse_arp_table("Interface: 192.168.1.100 --- 0xe\nsome garbage line")
        self.assertEqual(entries, {})


if __name__ == "__main__":
    unittest.main()
