import socket
import concurrent.futures
import ipaddress

def ping_host(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((str(host), 80))
        sock.close()
        return str(host) if result == 0 else None
    except socket.error:
        return None

def sweep(network):
    print(f"\nSweeping {network}\n")
    live_hosts = []

    net = ipaddress.ip_network(network, strict=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, net.hosts())

    for host in results:
        if host:
            print(f"[UP] {host}")
            live_hosts.append(host)

    return live_hosts

if __name__ == "__main__":
    sweep("192.168.1.0/24")