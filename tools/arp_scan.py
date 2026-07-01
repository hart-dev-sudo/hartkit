import os
import sys
import argparse
import concurrent.futures
import ipaddress
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.progress import progress_bar
from core.tcp_probe import probe_port
from core.ports import PROBE_PORTS
from core.arp_table import get_arp_table, BROADCAST_MAC
from core.output import save_results
from core.defaults import DEFAULT_NETWORK

# Small set of well-known OUI prefixes, common in labs/VMs/homelab gear.
# Not an authoritative OUI database (those run to tens of thousands of
# entries) — just a courtesy lookup for the most common virtualization
# and SBC vendors. Unrecognized prefixes fall back to "(unknown vendor)".
KNOWN_VENDORS = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:1c:14": "VMware",
    "08:00:27": "VirtualBox (Oracle)",
    "0a:00:27": "VirtualBox (Oracle) host-only",
    "00:15:5d": "Microsoft Hyper-V",
    "00:16:3e": "Xen",
    "52:54:00": "QEMU/KVM (libvirt)",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "28:cd:c1": "Raspberry Pi Trading",
}


def vendor_lookup(mac):
    return KNOWN_VENDORS.get(mac[:8], "(unknown vendor)")


def touch_hosts(hosts, timeout):
    total = len(hosts)
    done = 0
    lock = threading.Lock()
    host_counts = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        future_to_key = {
            executor.submit(probe_port, host, port, timeout): (str(host), port)
            for host in hosts
            for port in PROBE_PORTS
        }
        for future in concurrent.futures.as_completed(future_to_key):
            host_str, _ = future_to_key[future]
            try:
                future.result()
            except Exception as e:
                print(f"\nError: {e}")
            host_counts[host_str] = host_counts.get(host_str, 0) + 1
            if host_counts[host_str] == len(PROBE_PORTS):
                with lock:
                    done += 1
                    progress_bar(done, total)
    print()


def scan(network, timeout=0.1):
    net = ipaddress.ip_network(network, strict=False)
    hosts = list(net.hosts())
    total = len(hosts)

    print(f"\nTouching {total} hosts on {network} to populate the ARP cache\n")
    touch_hosts(hosts, timeout)

    arp_table = get_arp_table()

    lines = []
    for ip_str, mac in sorted(arp_table.items(), key=lambda kv: ipaddress.ip_address(kv[0])):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip not in net:
            continue
        if mac == BROADCAST_MAC or mac.startswith("01:00:5e"):
            continue
        lines.append(f"[ARP] {ip_str}  |  {mac}  |  {vendor_lookup(mac)}")

    for line in lines:
        print(line)

    return lines


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ARP scanner — local host discovery via the OS ARP cache",
        epilog="For authorized use only. Do not scan networks you do not own or have explicit permission to test."
    )
    parser.add_argument("network", nargs="?", default=DEFAULT_NETWORK, help=f"Target network in CIDR notation (default: {DEFAULT_NETWORK})")
    parser.add_argument("--timeout", type=float, default=0.1, choices=[0.1, 0.3, 0.5, 1.0],
                        metavar="{0.1,0.3,0.5,1.0}",
                        help="Probe timeout in seconds (default: 0.1 — fast/LAN; 0.3 balanced; 0.5/1.0 for slower networks)")
    parser.add_argument("--output", type=str, help="Save results to file")
    args = parser.parse_args()

    print("For authorized use only. Do not scan networks you do not own or have explicit permission to test.")
    print("Note: ARP only resolves hosts on your local subnet/broadcast domain, not routed networks.")

    start_time = time.time()
    lines = scan(args.network, timeout=args.timeout)
    elapsed = time.time() - start_time

    summary = f"\n{len(lines)} host(s) found on {args.network} in {elapsed:.1f}s"
    print(summary)

    if args.output:
        save_results(args.output, f"ARP scan: {args.network}", lines, summary)
        print(f"Results saved to {args.output}")
