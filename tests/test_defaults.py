import importlib
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _reload_defaults_with_local_config(fake_module):
    """Reloads core.defaults with core.local_config replaced by fake_module
    (or removed entirely, if fake_module is None), restoring prior state after."""
    sys.modules.pop("core.defaults", None)
    had_original = "core.local_config" in sys.modules
    original = sys.modules.get("core.local_config")

    if fake_module is None:
        sys.modules["core.local_config"] = None  # forces ImportError on import
    else:
        sys.modules["core.local_config"] = fake_module

    try:
        return importlib.import_module("core.defaults")
    finally:
        sys.modules.pop("core.defaults", None)
        if had_original:
            sys.modules["core.local_config"] = original
        else:
            sys.modules.pop("core.local_config", None)


class TestDefaultsFallback(unittest.TestCase):
    def test_falls_back_to_generic_when_local_config_absent(self):
        defaults = _reload_defaults_with_local_config(None)
        self.assertEqual(defaults.DEFAULT_HOST, "scanme.nmap.org")
        self.assertEqual(defaults.DEFAULT_NETWORK, "192.168.1.0/24")
        self.assertEqual(defaults.DEFAULT_DOMAIN, "example.com")

    def test_uses_local_config_values_when_present(self):
        fake_module = types.ModuleType("core.local_config")
        fake_module.HOST = "test-host.example"
        fake_module.NETWORK = "10.0.0.0/24"
        fake_module.DOMAIN = "test-domain.example"

        defaults = _reload_defaults_with_local_config(fake_module)
        self.assertEqual(defaults.DEFAULT_HOST, "test-host.example")
        self.assertEqual(defaults.DEFAULT_NETWORK, "10.0.0.0/24")
        self.assertEqual(defaults.DEFAULT_DOMAIN, "test-domain.example")

    def test_partial_local_config_falls_back_per_field(self):
        fake_module = types.ModuleType("core.local_config")
        fake_module.HOST = "test-host.example"
        # NETWORK and DOMAIN deliberately omitted

        defaults = _reload_defaults_with_local_config(fake_module)
        self.assertEqual(defaults.DEFAULT_HOST, "test-host.example")
        self.assertEqual(defaults.DEFAULT_NETWORK, "192.168.1.0/24")
        self.assertEqual(defaults.DEFAULT_DOMAIN, "example.com")


if __name__ == "__main__":
    unittest.main()
