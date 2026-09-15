"""
The plugin registers the commands it claims to, and importing it is safe.

Registration happens as a side effect of import, so a typo in that block only
shows up when Binary Ninja loads the plugin — which is exactly the failure this
catches earlier.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _harness as h

h.load_plugin()


class TestCommandRegistration(unittest.TestCase):
    def setUp(self):
        self.commands = h.registered_commands()

    def test_caller_and_reachability_commands_survive(self):
        self.assertIn("API Xref Hunter\\Find callers of APIs…", self.commands)
        self.assertIn("API Xref Hunter\\Does this function reach an API?…",
                      self.commands)

    def test_branch_commands_are_registered(self):
        self.assertIn("API Xref Hunter\\Find branches on API results…",
                      self.commands)
        self.assertIn(
            "API Xref Hunter\\Branches on API results in this function…",
            self.commands)

    def test_every_preset_gets_a_quick_scan(self):
        from api_xref_hunter.core import DEFAULT_PRESETS
        for name in DEFAULT_PRESETS:
            self.assertIn(f"API Xref Hunter\\Quick scan\\{name}", self.commands)


class TestPublicApi(unittest.TestCase):
    def test_branch_entry_points_are_exported(self):
        import api_xref_hunter as plugin
        for name in ("find_api_branches", "build_branch_report", "guard_summary"):
            self.assertTrue(hasattr(plugin, name), f"{name} is not exported")


if __name__ == "__main__":
    unittest.main()
