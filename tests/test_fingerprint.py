import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.fingerprint import probe_passive, probe_http, HTTP_PORTS, TLS_PORTS


def _serve_once(respond):
    """Starts a one-shot local TCP server. `respond(conn)` handles the connection."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def handle():
        try:
            conn, _ = server.accept()
            respond(conn)
            conn.close()
        except OSError:
            pass
        finally:
            server.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


class TestProbePassive(unittest.TestCase):
    def test_reads_banner_sent_immediately(self):
        port = _serve_once(lambda conn: conn.sendall(b"SSH-2.0-TestServer\r\n"))
        result = probe_passive("127.0.0.1", port, timeout=1.0)
        self.assertEqual(result, "SSH-2.0-TestServer")


class TestProbeHttp(unittest.TestCase):
    def test_parses_status_and_server_header(self):
        response = b"HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\nContent-Length: 0\r\n\r\n"

        def respond(conn):
            conn.recv(4096)
            conn.sendall(response)

        port = _serve_once(respond)
        result = probe_http("127.0.0.1", port, timeout=1.0)
        self.assertEqual(result, "HTTP/1.1 200 OK | Server: TestServer/1.0")

    def test_omits_server_suffix_when_header_absent(self):
        response = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"

        def respond(conn):
            conn.recv(4096)
            conn.sendall(response)

        port = _serve_once(respond)
        result = probe_http("127.0.0.1", port, timeout=1.0)
        self.assertEqual(result, "HTTP/1.0 404 Not Found")


class TestPortSets(unittest.TestCase):
    def test_http_and_tls_port_sets_are_disjoint(self):
        self.assertEqual(HTTP_PORTS & TLS_PORTS, set())


if __name__ == "__main__":
    unittest.main()
