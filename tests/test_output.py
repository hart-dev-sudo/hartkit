import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.output import save_results


class TestSaveResults(unittest.TestCase):
    def test_writes_expected_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "out.txt")
            save_results(path, "Scan: example.com", ["[OPEN] Port 80"], "1 open port(s) found")

            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("Scan: example.com", content)
            self.assertIn("[OPEN] Port 80", content)
            self.assertIn("1 open port(s) found", content)

    def test_writes_utf8_separator_without_crashing(self):
        # Regression test: save_results used to open files without an explicit
        # encoding, which crashed on Windows (cp1252 default) writing the "─"
        # separator line. Explicit utf-8 must round-trip cleanly.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "out.txt")
            save_results(path, "header", [], "summary")

            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("─" * 50, content)


if __name__ == "__main__":
    unittest.main()
