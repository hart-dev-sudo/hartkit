# hartkit

A personal network & security toolkit built incrementally — one layover at a time.

## What is this?

hartkit is a growing collection of networking and security tools built from scratch in Python. Each tool is written to understand the underlying protocols, not just wrap existing utilities.

## Tools

| Tool | Description | Status |
|------|-------------|--------|
| `tools/port_scanner.py` | TCP port scanner — threaded, banner grabbing, range support | In progress |
| `tools/ping_sweep.py` | Ping sweep / host discovery — scans a subnet for live hosts | In progress |

## Structure

```
hartkit/
├── tools/    # individual tools
├── core/     # shared utilities
└── tests/    # tests
```

## Usage

Each tool runs standalone:

```bash
python tools/<toolname>.py
```

## Requirements

- Python 3.x
- See individual tools for additional dependencies

## Intended Use

These tools are built for educational purposes and authorized security testing only. Do not use them against networks, hosts, or systems you do not own or have explicit written permission to test. Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction.

For safe practice, use [scanme.nmap.org](http://scanme.nmap.org) — a host maintained by the Nmap project explicitly for this purpose — or your own lab environment.

The author assumes no liability for misuse of these tools.

## License

MIT
