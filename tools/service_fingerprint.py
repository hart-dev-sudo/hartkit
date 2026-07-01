import os
import sys
import argparse
import concurrent.futures
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.progress import progress_bar
from core.ports import COMMON_PORTS
from core.fingerprint import fingerprint
from core.output import save_results
from core.defaults import DEFAULT_HOST


def scan_range(host, ports, timeout):
    total = len(ports)
    done = 0
    lock = threading.Lock()
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(fingerprint, host, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result is not None:
                    results[port] = result
            except Exception as e:
                print(f"\nError fingerprinting port {port}: {e}")
            with lock:
                done += 1
                progress_bar(done, total)

    print()
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Service fingerprinter — protocol-aware probing (HTTP, TLS, and raw banners)",
        epilog="For authorized use only. Do not scan hosts you do not own or have explicit permission to test."
    )
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST, help=f"Target host or IP (default: {DEFAULT_HOST})")
    parser.add_argument("--ports", type=str, help="Comma-separated list of specific ports to fingerprint (e.g. 22,80,443)")
    parser.add_argument("--start", type=int, default=1, help="Start port for a range scan (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port for a range scan (default: 1024)")
    parser.add_argument("--common", action="store_true", help="Fingerprint common ports instead of a range")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection/probe timeout in seconds (default: 2.0)")
    parser.add_argument("--output", type=str, help="Save results to file")
    args = parser.parse_args()

    if args.ports:
        ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})
        label = f"{len(ports)} specified port(s)"
    elif args.common:
        ports = sorted(set(COMMON_PORTS))
        label = f"common ports ({len(ports)} ports)"
    else:
        ports = list(range(args.start, args.end + 1))
        label = f"ports {args.start}-{args.end}"

    print("For authorized use only. Do not scan hosts you do not own or have explicit permission to test.")
    print(f"\nFingerprinting {args.host} — {label}\n")

    start_time = time.time()
    results = scan_range(args.host, ports, args.timeout)
    elapsed = time.time() - start_time

    lines = []
    for port in sorted(results):
        lines.append(f"[OPEN] Port {port}  |  {results[port]}")

    for line in lines:
        print(line)

    summary = f"\n{len(results)} open port(s) fingerprinted on {args.host} in {elapsed:.1f}s"
    print(summary)

    if args.output:
        save_results(args.output, f"Fingerprint: {args.host} — {label}", lines, summary)
        print(f"Results saved to {args.output}")
