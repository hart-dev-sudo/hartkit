# hartkit

A personal network & security toolkit built incrementally — one layover at a time.

## What is this?

hartkit is a growing collection of networking and security tools built from scratch in Python. Each tool is written to understand the underlying protocols, not just wrap existing utilities.

## Tools

| Tool | Description | Status |
|------|-------------|--------|
| `tools/port_scanner.py` | TCP port scanner — threaded, banner grabbing, common-ports/range support | Feature complete |
| `tools/ping_sweep.py` | Ping sweep / host discovery — multi-port TCP probing, hostname resolution | Feature complete |
| `tools/arp_scan.py` | ARP scanner — local host discovery via the OS ARP cache, MAC + vendor lookup | Feature complete |
| `tools/service_fingerprint.py` | Service fingerprinter — protocol-aware probing (HTTP, TLS handshake, raw banners) | Feature complete |
| `tools/dns_enum.py` | DNS enumerator — raw UDP record lookup (A/AAAA/MX/NS/TXT/CNAME/SOA), DoH fallback, subdomain brute-force | Feature complete |

"Feature complete" means the tool does what its description says and has been manually verified against real targets. The `core/` protocol logic has unit test coverage (see [Testing](#testing)); the CLI tools themselves (argparse wiring, orchestration) do not, since that's harder to test without live network state.

## Structure

```
hartkit/
├── tools/    # individual tools (CLI entry points)
├── core/     # shared building blocks used by tools/
│   ├── progress.py       # terminal progress bar
│   ├── tcp_probe.py      # single-port TCP reachability probe
│   ├── ports.py          # shared port lists (PROBE_PORTS, COMMON_PORTS)
│   ├── arp_table.py      # OS ARP cache query + parsing
│   ├── dns_proto.py      # raw DNS packet builder/parser + DoH transport
│   ├── fingerprint.py    # protocol-aware service probing (HTTP/TLS/banners)
│   ├── output.py         # shared --output file writer
│   ├── defaults.py       # default target for each tool (see below)
│   └── local_config.py   # optional, gitignored — override defaults for your own network
└── tests/    # unit tests for core/ (see Testing)
```

Every tool defaults to a safe public target (`scanme.nmap.org`, `192.168.1.0/24`, `example.com`) out of the box. If you want your own tools to default to your own host/network/domain instead, create `core/local_config.py` (never committed — see `.gitignore`) with:

```python
HOST = "my-server"
NETWORK = "10.0.0.0/24"
DOMAIN = "my-domain.example"
```

`core/defaults.py` picks these up automatically when present and falls back to the generic values when the file doesn't exist, so a fresh clone always gets the safe public defaults.

## Usage

Each tool runs standalone:

```bash
python tools/<toolname>.py
```

## Testing

Unit tests cover the `core/` protocol and parsing logic (DNS packet building/parsing, ARP table parsing, port lists, output formatting, default-fallback behavior, and local TCP/HTTP probing against loopback test servers) — no live network access or third-party packages required:

```bash
python -m unittest discover -s tests
```

## Requirements

- Python 3.x, stdlib only
- Optional: `certifi`, used by `dns_enum.py`'s DNS-over-HTTPS fallback if installed. Without it, the tool falls back to your OS's default certificate store — this works out of the box on Windows and Linux; on macOS, a stock Python install may need `certifi` (or the bundled `Install Certificates.command`) before HTTPS works at all, which is a general Python-on-macOS quirk, not specific to this tool.

## Intended Use

These tools are built for educational purposes and authorized security testing only. Do not use them against networks, hosts, or systems you do not own or have explicit written permission to test. Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction.

For safe practice, use [scanme.nmap.org](http://scanme.nmap.org) — a host maintained by the Nmap project explicitly for this purpose — or your own lab environment.

The author assumes no liability for misuse of these tools.

## License

MIT
