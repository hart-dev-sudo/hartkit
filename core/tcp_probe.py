import select
import socket


def probe_port(host, port, timeout=0.1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex((str(host), port))
        ready = select.select([], [sock], [], timeout)
        if ready[1]:
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            sock.close()
            return err == 0
        sock.close()
        return False
    except socket.error:
        return False
