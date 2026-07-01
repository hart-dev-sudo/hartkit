import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.ports import COMMON_PORTS, PROBE_PORTS


class TestPortLists(unittest.TestCase):
    def test_common_ports_non_empty(self):
        self.assertGreater(len(COMMON_PORTS), 0)

    def test_probe_ports_non_empty(self):
        self.assertGreater(len(PROBE_PORTS), 0)

    def test_all_ports_in_valid_range(self):
        for port in COMMON_PORTS + PROBE_PORTS:
            self.assertIsInstance(port, int)
            self.assertGreaterEqual(port, 1)
            self.assertLessEqual(port, 65535)

    def test_probe_ports_are_subset_of_expected_services(self):
        # PROBE_PORTS exists to elicit a quick response for host-alive checks
        self.assertIn(80, PROBE_PORTS)
        self.assertIn(443, PROBE_PORTS)


if __name__ == "__main__":
    unittest.main()
