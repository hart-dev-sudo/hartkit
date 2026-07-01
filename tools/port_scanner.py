import socket
import concurrent.futures
import argparse
import sys
import threading
import time

COMMON_PORTS = [
      7,   9,  13,  17,  19,  20,  21,  22,  23,  24,  25,  26,  37,  49,
     50,  51,  52,  53,  54,  57,  58,  59,  65,  66,  67,  68,  69,  70,
     71,  72,  73,  74,  75,  76,  77,  78,  79,  80,  81,  82,  83,  84,
     85,  86,  87,  88,  89,  90,  99, 100, 106, 109, 110, 111, 113, 119,
    125, 135, 139, 143, 144, 146, 161, 162, 163, 164, 174, 177, 179, 199,
    211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366,
    389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481,
    497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555,
    563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683,
    687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787,
    800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912,
    981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1007, 1009, 1010, 1011,
   1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1110, 1234,
   1433, 1434, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
   3000, 3001, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
   5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 7937,
   7938, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9999,
  10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except Exception:
                banner = ""
            sock.close()
            return banner if banner else "(no banner)"
        sock.close()
        return None
    except socket.error:
        return None

def progress_bar(done, total, width=40):
    filled = int(width * done / total)
    bar = "█" * filled + "░" * (width - filled)
    pct = int(100 * done / total)
    sys.stdout.write(f"\r  [{bar}] {pct}% ({done}/{total})")
    sys.stdout.flush()

def scan_range(host, ports):
    total = len(ports)
    done = 0
    lock = threading.Lock()
    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                banner = future.result()
                if banner:
                    results[port] = banner
            except Exception as e:
                print(f"\nError scanning port {port}: {e}")
            with lock:
                done += 1
                progress_bar(done, total)

    print()
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TCP port scanner with banner grabbing",
        epilog="For authorized use only. Do not scan hosts you do not own or have explicit permission to test."
    )
    parser.add_argument("host", nargs="?", default="scanme.nmap.org", help="Target host or IP (default: scanme.nmap.org)")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--common", action="store_true", help="Scan common ports instead of a range")
    parser.add_argument("--output", type=str, help="Save results to file")
    args = parser.parse_args()

    if args.common:
        ports = sorted(set(COMMON_PORTS))
        label = f"common ports ({len(ports)} ports)"
    else:
        ports = range(args.start, args.end + 1)
        label = f"ports {args.start}-{args.end}"

    print("For authorized use only. Do not scan hosts you do not own or have explicit permission to test.")
    print(f"\nScanning {args.host} — {label}\n")

    start_time = time.time()
    results = scan_range(args.host, ports)
    elapsed = time.time() - start_time

    lines = []
    for port in sorted(results):
        lines.append(f"[OPEN] Port {port}  |  {results[port]}")

    for line in lines:
        print(line)

    summary = f"\n{len(results)} open port(s) found on {args.host} in {elapsed:.1f}s"
    print(summary)

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"Scan: {args.host} — {label}\n")
            f.write(f"{'─' * 50}\n")
            for line in lines:
                f.write(line + "\n")
            f.write(summary + "\n")
        print(f"Results saved to {args.output}")
