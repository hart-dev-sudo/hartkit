import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.tcp_probe import probe_port


class TestProbePort(unittest.TestCase):
    def test_probe_port_true_when_open(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def accept_once():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=accept_once, daemon=True)
        t.start()
        try:
            self.assertTrue(probe_port("127.0.0.1", port, timeout=1.0))
        finally:
            server.close()
            t.join(timeout=1)

    def test_probe_port_false_when_closed(self):
        # Grab an ephemeral port then release it immediately - nothing listens there
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        self.assertFalse(probe_port("127.0.0.1", port, timeout=0.5))


if __name__ == "__main__":
    unittest.main()
