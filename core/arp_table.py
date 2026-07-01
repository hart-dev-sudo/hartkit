import re
import subprocess

_IP_PATTERN = r"\d{1,3}(?:\.\d{1,3}){3}"
_MAC_PATTERN = r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
_ENTRY_RE = re.compile(rf"({_IP_PATTERN}).*?({_MAC_PATTERN})")

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def parse_arp_table(output):
    entries = {}
    for line in output.splitlines():
        match = _ENTRY_RE.search(line)
        if not match:
            continue
        ip, mac = match.group(1), match.group(2).lower().replace("-", ":")
        entries[ip] = mac
    return entries


def get_arp_table(timeout=10):
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=timeout
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    return parse_arp_table(result.stdout)
