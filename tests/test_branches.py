"""
Tests for branch analysis, against the fake IL in `_harness.py`.

Each test builds a small function by hand — the call, what it produced, and
the conditional that tests it — and checks what the analysis makes of it.

    python3 -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _harness as h

h.load_plugin()

from api_xref_hunter import branches  # noqa: E402  (needs the stubs installed)


REG_QUERY = 0x2000
EXIT_PROCESS = 0x2010
CREATE_PROCESS = 0x2020
WRITE_FILE = 0x2030

SYMBOLS = [
    h.Symbol("RegQueryValueExW", REG_QUERY),
    h.Symbol("ExitProcess", EXIT_PROCESS),
    h.Symbol("CreateProcessW", CREATE_PROCESS),
    h.Symbol("WriteFile", WRITE_FILE),
]


def call(address, target, output=(), params=()):
    return h.Expr("MLIL_CALL_SSA", [], address=address,
                  dest=h.const(target), output=list(output), params=list(params))


def branch(address, condition, true_index, false_index, reads):
    inst = h.Expr("MLIL_IF", [condition, true_index, false_index],
                  address=address, condition=condition,
                  true=true_index, false=false_index)
    inst.reads = list(reads)
    return inst


def assign(address, dest, src_var):
    inst = h.Expr("MLIL_SET_VAR_SSA", [dest, h.var_ssa(src_var)],
                  address=address, dest=dest, src=h.var_ssa(src_var))
    inst.reads = [src_var]
    return inst


def link(blocks, edges):
    """`edges` is {block index: [successor index, ...]}."""
    for index, succs in edges.items():
        blocks[index].outgoing_edges = [h.Edge(blocks[s]) for s in succs]


def diamond_function(instructions, block_ranges, edges, name="check_value",
                     start=0x1000):
    blocks = [h.BasicBlock(i, lo, hi) for i, (lo, hi) in enumerate(block_ranges)]
    link(blocks, edges)
    il = h.ILFunction(instructions, blocks)
    return h.Function(name, start, il)


def build_bv(functions):
    return h.FakeBinaryView(symbols=SYMBOLS, functions=functions)


class TestReturnValueBranch(unittest.TestCase):
    """The plain case: `if (RegQueryValueExW(...) != 0)`."""

    def setUp(self):
        eax = h.SSAVariable(h.Variable("eax"), 1)
        data = h.Variable("var_10")
        instructions = [
            call(0x1000, REG_QUERY, output=[eax], params=[h.address_of(data)]),
            branch(0x1006,
                   h.cmp_expr("MLIL_CMP_NE", h.var_ssa(eax), h.const(0), "!="),
                   2, 4, reads=[eax]),
            call(0x1010, EXIT_PROCESS),
            h.Expr("MLIL_GOTO", [6], address=0x1016),
            call(0x1020, CREATE_PROCESS),
            h.Expr("MLIL_GOTO", [6], address=0x1026),
            h.Expr("MLIL_RET", [], address=0x1030),
        ]
        self.func = diamond_function(
            instructions,
            [(0, 2), (2, 4), (4, 6), (6, 7)],
            {0: [1, 2], 1: [3], 2: [3], 3: []},
        )
        self.bv = build_bv([self.func])
        self.guards, self.untested = branches.analyze_function_branches(
            self.bv, self.func, [(0x1000, "RegQueryValueExW")])

    def test_finds_one_guard_on_the_return_value(self):
        self.assertEqual(len(self.guards), 1)
        self.assertEqual(self.untested, [])
        guard = self.guards[0]
        self.assertEqual(guard.api, "RegQueryValueExW")
        self.assertEqual(guard.call_site, 0x1000)
        self.assertEqual(guard.condition_site, 0x1006)
        self.assertEqual(guard.origin, "return value")
        self.assertEqual(guard.hops, 0)
        self.assertEqual(guard.condition, "eax#1 != 0")

    def test_each_arm_reports_the_calls_it_guards(self):
        guard = self.guards[0]
        self.assertEqual(guard.true_side.call_names, ["ExitProcess"])
        self.assertEqual(guard.false_side.call_names, ["CreateProcessW"])
        self.assertEqual(guard.true_side.entry, 0x1010)
        self.assertEqual(guard.false_side.entry, 0x1020)

    def test_the_merge_block_belongs_to_neither_arm(self):
        # Block 3 runs whichever way the branch went, so neither side claims
        # it — and neither side is credited with its return.
        guard = self.guards[0]
        self.assertEqual(guard.true_side.blocks, 1)
        self.assertEqual(guard.false_side.blocks, 1)
        self.assertFalse(guard.true_side.returns)
        self.assertFalse(guard.false_side.returns)


class TestPropagation(unittest.TestCase):
    def _function_with_copies(self, copies):
        """call -> `copies` successive assignments -> a branch on the result."""
        eax = h.SSAVariable(h.Variable("eax"), 1)
        instructions = [call(0x1000, REG_QUERY, output=[eax])]
        current = eax
        for i in range(copies):
            dest = h.SSAVariable(h.Variable(f"status{i}"), 1)
            instructions.append(assign(0x1006 + i * 2, dest, current))
            current = dest
        branch_index = len(instructions)
        instructions.append(
            branch(0x1100,
                   h.cmp_expr("MLIL_CMP_E", h.var_ssa(current), h.const(0), "=="),
                   branch_index + 1, branch_index + 2, reads=[current]))
        instructions.append(call(0x1110, WRITE_FILE))
        instructions.append(h.Expr("MLIL_RET", [], address=0x1120))
        n = branch_index
        func = diamond_function(
            instructions,
            [(0, n + 1), (n + 1, n + 2), (n + 2, n + 3)],
            {0: [1, 2], 1: [2], 2: []},
        )
        return func, build_bv([func])

    def test_follows_the_value_through_assignments(self):
        func, bv = self._function_with_copies(3)
        guards, _ = branches.analyze_function_branches(
            bv, func, [(0x1000, "RegQueryValueExW")])
        self.assertEqual(len(guards), 1)
        self.assertEqual(guards[0].hops, 3)
        self.assertEqual(guards[0].true_side.call_names, ["WriteFile"])

    def test_stops_following_past_the_hop_limit(self):
        func, bv = self._function_with_copies(3)
        guards, untested = branches.analyze_function_branches(
            bv, func, [(0x1000, "RegQueryValueExW")], max_hops=2)
        self.assertEqual(guards, [])
        self.assertEqual(len(untested), 1)

    def test_one_armed_if_reports_the_empty_arm(self):
        func, bv = self._function_with_copies(0)
        guards, _ = branches.analyze_function_branches(
            bv, func, [(0x1000, "RegQueryValueExW")])
        guard = guards[0]
        # The true arm holds the WriteFile; the false arm jumps straight to the
        # block that runs either way, so it guards nothing.
        self.assertFalse(guard.true_side.is_empty)
        self.assertTrue(guard.false_side.is_empty)
        self.assertEqual(guard.false_side.blocks, 0)


class TestSeveralTests(unittest.TestCase):
    """One result tested twice — `if (res != 0) ... if (res == 2) ...`."""

    def setUp(self):
        eax = h.SSAVariable(h.Variable("eax"), 1)
        instructions = [
            call(0x1000, REG_QUERY, output=[eax]),
            branch(0x1006,
                   h.cmp_expr("MLIL_CMP_NE", h.var_ssa(eax), h.const(0), "!="),
                   2, 3, reads=[eax]),
            call(0x1010, EXIT_PROCESS),
            branch(0x1020,
                   h.cmp_expr("MLIL_CMP_E", h.var_ssa(eax), h.const(2), "=="),
                   4, 5, reads=[eax]),
            call(0x1030, WRITE_FILE),
            h.Expr("MLIL_RET", [], address=0x1040),
        ]
        self.func = diamond_function(
            instructions,
            [(0, 2), (2, 3), (3, 4), (4, 5), (5, 6)],
            {0: [1, 2], 1: [2], 2: [3, 4], 3: [4], 4: []},
        )
        self.bv = build_bv([self.func])
        self.guards, _ = branches.analyze_function_branches(
            self.bv, self.func, [(0x1000, "RegQueryValueExW")])

    def test_both_conditionals_are_reported(self):
        self.assertEqual(len(self.guards), 2)
        self.assertEqual([g.condition_site for g in self.guards], [0x1006, 0x1020])
        self.assertEqual([g.condition for g in self.guards],
                         ["eax#1 != 0", "eax#1 == 2"])

    def test_each_guards_only_its_own_arm(self):
        first, second = self.guards
        self.assertEqual(first.true_side.call_names, ["ExitProcess"])
        self.assertEqual(second.true_side.call_names, ["WriteFile"])


class TestMultipleCallSites(unittest.TestCase):
    """Two calls in one function are analysed independently."""

    def setUp(self):
        first = h.SSAVariable(h.Variable("eax"), 1)
        second = h.SSAVariable(h.Variable("eax"), 2)
        instructions = [
            call(0x1000, REG_QUERY, output=[first]),
            branch(0x1006,
                   h.cmp_expr("MLIL_CMP_NE", h.var_ssa(first), h.const(0), "!="),
                   2, 3, reads=[first]),
            call(0x1010, EXIT_PROCESS),
            call(0x1020, REG_QUERY, output=[second]),
            branch(0x1026,
                   h.cmp_expr("MLIL_CMP_NE", h.var_ssa(second), h.const(0), "!="),
                   5, 6, reads=[second]),
            call(0x1030, CREATE_PROCESS),
            h.Expr("MLIL_RET", [], address=0x1040),
        ]
        self.func = diamond_function(
            instructions,
            [(0, 2), (2, 3), (3, 5), (5, 6), (6, 7)],
            {0: [1, 2], 1: [2], 2: [3, 4], 3: [4], 4: []},
        )
        self.bv = build_bv([self.func])
        self.guards, _ = branches.analyze_function_branches(
            self.bv, self.func,
            [(0x1000, "RegQueryValueExW"), (0x1020, "RegQueryValueExW")])

    def test_each_call_gets_its_own_guard(self):
        self.assertEqual(len(self.guards), 2)
        self.assertEqual([g.call_site for g in self.guards], [0x1000, 0x1020])
        self.assertEqual(self.guards[0].true_side.call_names, ["ExitProcess"])
        self.assertEqual(self.guards[1].true_side.call_names, ["CreateProcessW"])


class TestOutParameter(unittest.TestCase):
    """The data a registry read hands back arrives through `&var`, not eax."""

    def setUp(self):
        eax = h.SSAVariable(h.Variable("eax"), 1)
        data = h.Variable("var_10")
        read_back = h.SSAVariable(data, 2)
        instructions = [
            call(0x1000, REG_QUERY, output=[eax], params=[h.address_of(data)]),
            branch(0x1006,
                   h.cmp_expr("MLIL_CMP_E", h.var_ssa(read_back),
                              h.const(1), "=="),
                   2, 3, reads=[read_back]),
            call(0x1010, CREATE_PROCESS),
            h.Expr("MLIL_RET", [], address=0x1020),
        ]
        self.func = diamond_function(
            instructions, [(0, 2), (2, 3), (3, 4)],
            {0: [1, 2], 1: [2], 2: []},
        )
        self.bv = build_bv([self.func])
        self.guards, _ = branches.analyze_function_branches(
            self.bv, self.func, [(0x1000, "RegQueryValueExW")])

    def test_tracks_the_variable_whose_address_was_passed(self):
        self.assertEqual(len(self.guards), 1)
        guard = self.guards[0]
        self.assertEqual(guard.origin, "out-parameter 1 (&var_10)")
        self.assertEqual(guard.true_side.call_names, ["CreateProcessW"])


class TestUntestedResults(unittest.TestCase):
    def _single_call_function(self, tail):
        eax = h.SSAVariable(h.Variable("eax"), 1)
        instructions = [call(0x1000, REG_QUERY, output=[eax])] + tail(eax)
        func = diamond_function(
            instructions, [(0, len(instructions))], {0: []})
        return func, build_bv([func])

    def test_result_nothing_reads_is_reported_as_unused(self):
        func, bv = self._single_call_function(
            lambda _eax: [h.Expr("MLIL_RET", [], address=0x1010)])
        guards, untested = branches.analyze_function_branches(
            bv, func, [(0x1000, "RegQueryValueExW")])
        self.assertEqual(guards, [])
        self.assertEqual(len(untested), 1)
        self.assertEqual(untested[0].api, "RegQueryValueExW")
        self.assertEqual(untested[0].fate, [])

    def test_result_leaving_the_function_says_where_it_went(self):
        def tail(eax):
            ret = h.Expr("MLIL_RET", [h.var_ssa(eax)], address=0x1010)
            ret.reads = [eax]
            return [ret]

        func, bv = self._single_call_function(tail)
        _, untested = branches.analyze_function_branches(
            bv, func, [(0x1000, "RegQueryValueExW")])
        self.assertEqual(len(untested), 1)
        self.assertIn("returned from the function", untested[0].fate[0])

    def test_result_handed_to_a_helper_is_named(self):
        def tail(eax):
            inner = call(0x1010, CREATE_PROCESS, params=[h.var_ssa(eax)])
            inner.reads = [eax]
            return [inner, h.Expr("MLIL_RET", [], address=0x1020)]

        func, bv = self._single_call_function(tail)
        _, untested = branches.analyze_function_branches(
            bv, func, [(0x1000, "RegQueryValueExW")])
        self.assertIn("passed to", untested[0].fate[0])


class TestWholeBinaryScan(unittest.TestCase):
    """find_api_branches: pattern -> symbol -> xref -> guard, end to end."""

    def setUp(self):
        eax = h.SSAVariable(h.Variable("eax"), 1)
        instructions = [
            call(0x1000, REG_QUERY, output=[eax]),
            branch(0x1006,
                   h.cmp_expr("MLIL_CMP_NE", h.var_ssa(eax), h.const(0), "!="),
                   2, 3, reads=[eax]),
            call(0x1010, WRITE_FILE),
            h.Expr("MLIL_RET", [], address=0x1020),
        ]
        self.func = diamond_function(
            instructions, [(0, 2), (2, 3), (3, 4)],
            {0: [1, 2], 1: [2], 2: []}, name="load_config", start=0x1000)
        self.bv = h.FakeBinaryView(
            symbols=SYMBOLS,
            functions=[self.func],
            code_refs={REG_QUERY: [h.CodeRef(self.func, 0x1000)]},
        )

    def test_resolves_patterns_and_reports_the_branch(self):
        result = branches.find_api_branches(self.bv, ["Reg*Value*"])
        self.assertEqual(result.call_sites, 1)
        self.assertEqual(result.functions_scanned, 1)
        self.assertEqual(len(result.guards), 1)
        self.assertEqual(result.guards[0].function.name, "load_config")
        self.assertEqual(result.unmatched_patterns, [])

    def test_patterns_matching_no_symbol_are_reported(self):
        result = branches.find_api_branches(self.bv, ["Reg*Value*", "NtOpenKey"])
        self.assertEqual(result.unmatched_patterns, ["NtOpenKey"])

    def test_restricting_to_other_functions_finds_nothing(self):
        elsewhere = diamond_function([h.Expr("MLIL_RET", [], address=0x9000)],
                                     [(0, 1)], {0: []}, name="other",
                                     start=0x9000)
        result = branches.find_api_branches(self.bv, ["Reg*Value*"],
                                            functions=[elsewhere])
        self.assertEqual(result.call_sites, 0)
        self.assertEqual(result.guards, [])

    def test_report_names_both_arms_and_the_condition(self):
        result = branches.find_api_branches(self.bv, ["Reg*Value*"])
        report = branches.build_branch_report(result, "sample.exe")
        self.assertIn("load_config", report)
        self.assertIn("`if (eax#1 != 0)`", report)
        self.assertIn("when true", report)
        self.assertIn("when false", report)
        self.assertIn("WriteFile", report)
        self.assertIn("binaryninja://?expr=0x1006", report)

    def test_report_without_call_sites_says_so(self):
        result = branches.find_api_branches(self.bv, ["NoSuchApi*"])
        report = branches.build_branch_report(result)
        self.assertIn("No call sites to analyse", report)


if __name__ == "__main__":
    unittest.main()
