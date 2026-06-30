import socket
import concurrent.futures
import ipaddress
import argparse
import sys
import threading
import time

def ping_host(host):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((str(host), 80))
        sock.close()
        return str(host) if result == 0 else None
    except socket.error:
        return None

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
    done = 0
    lock = threading.Lock()
    live_hosts = []

    print(f"\nSweeping {network} ({total} hosts)\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_host = {executor.submit(ping_host, host): host for host in hosts}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                result = future.result()
                if result:
                    live_hosts.append(result)
            except Exception as e:
                print(f"\nError: {e}")
            with lock:
                done += 1
                progress_bar(done, total)

    print()
    live_hosts.sort(key=lambda ip: ipaddress.ip_address(ip))

    lines = [f"[UP] {host}" for host in live_hosts]
    for line in lines:
        print(line)

    summary = f"\n{len(live_hosts)} host(s) up on {network}"
    print(summary)

    if output:
        with open(output, "w") as f:
            f.write(f"Sweep: {network}\n")
            f.write(f"{'─' * 50}\n")
            for line in lines:
                f.write(line + "\n")
            f.write(summary + "\n")
        print(f"Results saved to {output}")

    return live_hosts

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP ping sweep — host discovery via port 80")
    parser.add_argument("network", nargs="?", default="192.168.1.0/24", help="Target network in CIDR notation (default: 192.168.1.0/24)")
    parser.add_argument("--output", type=str, help="Save results to file")
    args = parser.parse_args()

    start_time = time.time()
    sweep(args.network, output=args.output)
    elapsed = time.time() - start_time
    print(f"Completed in {elapsed:.1f}s")
