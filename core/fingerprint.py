import socket
import ssl

# Ports where the server won't speak first — we have to send a
# protocol-appropriate probe before anything comes back.
HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 3000, 5000, 9000, 8888}
TLS_PORTS = {443, 8443, 993, 995, 465, 990, 636, 3269, 5061, 8883}
ACTIVE_PROBES = {
    6379: b"PING\r\n",      # Redis
    11211: b"version\r\n",  # Memcached
}


def _read_all(sock, timeout, max_bytes=8192):
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def probe_passive(host, port, timeout):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        data = _read_all(sock, timeout)
    return data.decode("utf-8", errors="ignore").strip()


def probe_active(host, port, timeout):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(ACTIVE_PROBES[port])
        data = _read_all(sock, timeout)
    return data.decode("utf-8", errors="ignore").strip()


def probe_http(host, port, timeout):
    request = (
        f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: hartkit\r\nConnection: close\r\n\r\n"
    ).encode()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(request)
        data = _read_all(sock, timeout)

    header_block = data.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
    lines = header_block.splitlines()
    if not lines:
        return None

    status_line = lines[0]
    server = None
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break

    return f"{status_line} | Server: {server}" if server else status_line


def probe_tls(host, port, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            version = ssock.version()
            cipher = ssock.cipher()
    cipher_name = cipher[0] if cipher else "unknown cipher"
    return f"{version} ({cipher_name})"


def fingerprint(host, port, timeout=2.0):
    try:
        if port in TLS_PORTS:
            return probe_tls(host, port, timeout)

        if port in HTTP_PORTS:
            result = probe_http(host, port, timeout)
            if result:
                return result

        passive = probe_passive(host, port, timeout)
        if passive:
            return passive

        if port in ACTIVE_PROBES:
            active = probe_active(host, port, timeout)
            if active:
                return active

        return "(no banner)"
    except (OSError, ssl.SSLError):
        return None
