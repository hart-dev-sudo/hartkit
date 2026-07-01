try:
    from core import local_config as _local
except ImportError:
    _local = None

DEFAULT_HOST = getattr(_local, "HOST", "scanme.nmap.org")
DEFAULT_NETWORK = getattr(_local, "NETWORK", "192.168.1.0/24")
DEFAULT_DOMAIN = getattr(_local, "DOMAIN", "example.com")
