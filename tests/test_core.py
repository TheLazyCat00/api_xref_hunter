"""
Caller search behaviour that the branch tests do not cover.

    python3 -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _harness as h

h.load_plugin()

from api_xref_hunter import core  # noqa: E402  (needs the stubs installed)


class TestUnmatchedPatterns(unittest.TestCase):
    """A pattern that resolved something must never be called unmatched."""

    def _view(self, symbol_name):
        symbol = h.Symbol(symbol_name, 0x2000)
        func = h.Function("caller", 0x1000, None)
        return h.FakeBinaryView(
            symbols=[symbol], functions=[func],
            code_refs={0x2000: [h.CodeRef(func, 0x1004)]},
        )

    def test_a_pattern_matching_through_a_stripped_name_is_not_unmatched(self):
        # Resolution matches the decoration-stripped spelling, so the
        # unmatched check has to see that spelling too.
        bv = self._view("_RegOpenKeyExW@20")
        result = core.find_api_callers(bv, ["RegOpenKeyExW"], mode="exact")
        self.assertEqual(len(result.callers), 1)
        self.assertEqual(result.unmatched_patterns, [])

    def test_a_pattern_matching_through_a_module_prefix_is_not_unmatched(self):
        bv = self._view("advapi32!RegOpenKeyExW")
        result = core.find_api_callers(bv, ["RegOpenKeyExW"], mode="exact")
        self.assertEqual(result.unmatched_patterns, [])

    def test_a_pattern_matching_nothing_is_still_reported(self):
        bv = self._view("_RegOpenKeyExW@20")
        result = core.find_api_callers(bv, ["RegOpenKeyExW", "NtOpenKey"],
                                       mode="exact")
        self.assertEqual(result.unmatched_patterns, ["NtOpenKey"])

    def test_matched_symbol_names_collects_every_spelling(self):
        bv = self._view("_RegOpenKeyExW@20")
        names = core.matched_symbol_names(bv, [0x2000])
        self.assertIn("_RegOpenKeyExW@20", names)
        self.assertIn("RegOpenKeyExW", names)

    def test_matched_symbol_names_tolerates_an_address_with_no_symbol(self):
        bv = self._view("_RegOpenKeyExW@20")
        self.assertEqual(core.matched_symbol_names(bv, [0xdead]), set())


if __name__ == "__main__":
    unittest.main()
