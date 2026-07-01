import os
import sys
import argparse
import concurrent.futures
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.dns_proto import query, doh_query, QTYPES, DOH_DEFAULT_URL
from core.progress import progress_bar
from core.output import save_results
from core.defaults import DEFAULT_DOMAIN

DEFAULT_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def udp_reachable(server, port, timeout=1.5):
    try:
        query("com", "NS", server=server, port=port, timeout=timeout)
        return True
    except (OSError, ValueError):
        return False


def lookup(domain, qtype, resolver):
    try:
        if resolver["doh"]:
            rcode, records = doh_query(domain, qtype, doh_url=resolver["doh_url"], timeout=resolver["timeout"])
        else:
            rcode, records = query(domain, qtype, server=resolver["server"], port=resolver["port"], timeout=resolver["timeout"])
        if rcode != 0 or not records:
            return []
        return records
    except (OSError, ValueError):
        return []


def enumerate_records(domain, types, resolver):
    lines = []
    for qtype in types:
        for record in lookup(domain, qtype, resolver):
            lines.append(f"[{record['type']}] {record['name']}  |  {record['data']}  (ttl={record['ttl']})")
    return lines


def brute_subdomains(domain, wordlist_path, resolver):
    with open(wordlist_path, "r") as f:
        words = [line.strip() for line in f if line.strip()]

    total = len(words)
    done = 0
    lock = threading.Lock()
    found = []

    print(f"\nBrute-forcing {total} subdomains of {domain}\n")

    def check(word):
        sub = f"{word}.{domain}"
        return sub, lookup(sub, "A", resolver)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check, word): word for word in words}
        for future in concurrent.futures.as_completed(futures):
            try:
                sub, records = future.result()
                for record in records:
                    found.append(f"[{record['type']}] {sub}  |  {record['data']}  (ttl={record['ttl']})")
            except Exception as e:
                print(f"\nError: {e}")
            with lock:
                done += 1
                progress_bar(done, total)

    print()
    return sorted(found)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS enumerator — raw UDP record lookup and subdomain brute-force",
        epilog="For authorized use only. Do not enumerate domains you do not own or have explicit permission to test."
    )
    parser.add_argument("domain", nargs="?", default=DEFAULT_DOMAIN, help=f"Target domain (default: {DEFAULT_DOMAIN})")
    parser.add_argument("--types", type=str, default=",".join(DEFAULT_TYPES),
                        help=f"Comma-separated record types to query (default: {','.join(DEFAULT_TYPES)}). Available: {','.join(QTYPES)}")
    parser.add_argument("--server", type=str, default="8.8.8.8", help="DNS server to query (default: 8.8.8.8)")
    parser.add_argument("--port", type=int, default=53, help="DNS server port (default: 53)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Query timeout in seconds (default: 2.0)")
    parser.add_argument("--doh", action="store_true",
                        help="Query over DNS-over-HTTPS instead of raw UDP (use on networks that block/filter plain UDP:53)")
    parser.add_argument("--doh-url", type=str, default=DOH_DEFAULT_URL,
                        help=f"DoH endpoint to use with --doh (default: {DOH_DEFAULT_URL})")
    parser.add_argument("--no-auto-doh", action="store_true",
                        help="Disable automatic DoH fallback when raw UDP:53 appears blocked (force raw UDP only)")
    parser.add_argument("--wordlist", type=str, help="Wordlist file for subdomain brute-force (A records only)")
    parser.add_argument("--output", type=str, help="Save results to file")
    args = parser.parse_args()

    print("For authorized use only. Do not enumerate domains you do not own or have explicit permission to test.")

    requested_types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    unknown = [t for t in requested_types if t not in QTYPES]
    if unknown:
        parser.error(f"Unknown record type(s): {', '.join(unknown)}. Available: {','.join(QTYPES)}")

    resolver = {
        "doh": args.doh,
        "doh_url": args.doh_url,
        "server": args.server,
        "port": args.port,
        "timeout": args.timeout,
    }

    if not resolver["doh"] and not args.no_auto_doh and not udp_reachable(args.server, args.port):
        print(f"Raw UDP DNS to {args.server}:{args.port} appears blocked on this network — falling back to DNS-over-HTTPS ({args.doh_url}).\n")
        resolver["doh"] = True

    transport_desc = args.doh_url if resolver["doh"] else f"{args.server}:{args.port}"
    print(f"\nQuerying {args.domain} — {', '.join(requested_types)} (via {transport_desc})\n")

    start_time = time.time()
    lines = enumerate_records(args.domain, requested_types, resolver)
    for line in lines:
        print(line)

    if args.wordlist:
        found = brute_subdomains(args.domain, args.wordlist, resolver)
        for line in found:
            print(line)
        lines += found

    elapsed = time.time() - start_time
    summary = f"\n{len(lines)} record(s) found for {args.domain} in {elapsed:.1f}s"
    print(summary)

    if args.output:
        save_results(args.output, f"DNS enumeration: {args.domain}", lines, summary)
        print(f"Results saved to {args.output}")
