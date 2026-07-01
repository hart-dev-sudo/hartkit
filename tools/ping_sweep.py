import os
import socket
import concurrent.futures
import ipaddress
import argparse
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.progress import progress_bar
from core.tcp_probe import probe_port
from core.ports import PROBE_PORTS
from core.output import save_results
from core.defaults import DEFAULT_NETWORK

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "(no hostname)"

def sweep(network, timeout=0.1):
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
            executor.submit(probe_port, host, port, timeout): (str(host), port)
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
    parser = argparse.ArgumentParser(
        description="TCP ping sweep — multi-port host discovery",
        epilog="For authorized use only. Do not scan networks you do not own or have explicit permission to test."
    )
    parser.add_argument("network", nargs="?", default=DEFAULT_NETWORK, help=f"Target network in CIDR notation (default: {DEFAULT_NETWORK})")
    parser.add_argument("--timeout", type=float, default=0.1, choices=[0.1, 0.3, 0.5, 1.0],
                        metavar="{0.1,0.3,0.5,1.0}",
                        help="Probe timeout in seconds (default: 0.1 — fast/LAN; 0.3 balanced; 0.5/1.0 for slower networks)")
    parser.add_argument("--output", type=str, help="Save results to file")
    args = parser.parse_args()

    print("For authorized use only. Do not scan networks you do not own or have explicit permission to test.")

    start_time = time.time()
    lines = sweep(args.network, timeout=args.timeout)
    elapsed = time.time() - start_time

    summary = f"\n{len(lines)} host(s) up on {args.network} in {elapsed:.1f}s"
    print(summary)

    if args.output:
        save_results(args.output, f"Sweep: {args.network}", lines, summary)
        print(f"Results saved to {args.output}")
