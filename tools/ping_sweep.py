import socket
import select
import concurrent.futures
import ipaddress
import argparse
import sys
import threading
import time

PROBE_PORTS = [22, 23, 80, 443, 445, 3389, 8080, 8443]

def probe_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex((str(host), port))
        ready = select.select([], [sock], [], 0.1)
        if ready[1]:
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            sock.close()
            return err == 0
        sock.close()
        return False
    except socket.error:
        return False

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "(no hostname)"

def progress_bar(done, total, width=40):
    filled = int(width * done / total)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * done / total)
    sys.stdout.write(f"\r  [{bar}] {pct}% ({done}/{total})")
    sys.stdout.flush()

def sweep(network, output=None):
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())
    total = len(hosts)
    lock = threading.Lock()

    print(f"\nSweeping {network} ({total} hosts)\n")

    found = set()
    port_counts = {}
    hosts_done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        future_to_key = {
            executor.submit(probe_port, host, port): (str(host), port)
            for host in hosts
            for port in PROBE_PORTS
        }
        for future in concurrent.futures.as_completed(future_to_key):
            host_str, port = future_to_key[future]
            try:
                if future.result():
                    found.add(host_str)
            except Exception as e:
                print(f"\nError: {e}")
            port_counts[host_str] = port_counts.get(host_str, 0) + 1
            if port_counts[host_str] == len(PROBE_PORTS):
                with lock:
                    hosts_done += 1
                    progress_bar(hosts_done, total)

    live_hosts = sorted(found, key=lambda ip: ipaddress.ip_address(ip))
    print()

    lines = []
    for ip in live_hosts:
        hostname = resolve_hostname(ip)
        lines.append(f"[UP] {ip}  |  {hostname}")

    for line in lines:
        print(line)

    return lines

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP ping sweep — multi-port host discovery")
    parser.add_argument("network", nargs="?", default="192.168.1.0/24", help="Target network in CIDR notation (default: 192.168.1.0/24)")
    parser.add_argument("--output", type=str, help="Save results to file")
    args = parser.parse_args()

    start_time = time.time()
    lines = sweep(args.network, output=args.output)
    elapsed = time.time() - start_time

    summary = f"\n{len(lines)} host(s) up on {args.network} in {elapsed:.1f}s"
    print(summary)

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Sweep: {args.network}\n")
            f.write(f"{'─' * 50}\n")
            for line in lines:
                f.write(line + "\n")
            f.write(summary + "\n")
        print(f"Results saved to {args.output}")
