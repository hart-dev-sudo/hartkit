import socket
import concurrent.futures

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return True
        return False
    except socket.error:
        return False

def scan_range(host, start_port, end_port):
    print(f"\nScanning {host} from port {start_port} to {end_port}\n")
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    print(f"[OPEN] Port {port}")
                    open_ports.append(port)
            except Exception as e:
                print(f"Error occurred while scanning port {port}: {e}")

    open_ports.sort()
    return open_ports

if __name__ == "__main__":
    scan_range("scanme.nmap.org", 1, 100)                    