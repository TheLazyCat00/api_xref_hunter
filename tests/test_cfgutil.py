"""
Tests for the graph reasoning behind branch analysis.

`cfgutil` imports no Binary Ninja, so this runs anywhere:

    python3 -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cfgutil import guarded_region, reachable


class TestReachable(unittest.TestCase):
    def test_includes_start_and_follows_edges(self):
        graph = {0: [1, 2], 1: [3], 2: [3], 3: []}
        self.assertEqual(reachable(graph, 0), {0, 1, 2, 3})
        self.assertEqual(reachable(graph, 1), {1, 3})
        self.assertEqual(reachable(graph, 3), {3})

    def test_terminates_on_a_loop(self):
        graph = {0: [1], 1: [2], 2: [1, 3], 3: []}
        self.assertEqual(reachable(graph, 0), {0, 1, 2, 3})

    def test_skip_edge_drops_exactly_one_edge(self):
        graph = {0: [1, 2], 1: [3], 2: [3], 3: []}
        self.assertEqual(reachable(graph, 0, skip_edge=(0, 1)), {0, 2, 3})
        # The dropped edge is directional and specific to that pair.
        self.assertEqual(reachable(graph, 0, skip_edge=(1, 0)), {0, 1, 2, 3})

    def test_skip_edge_drops_one_copy_not_every_copy(self):
        # A block with two edges to the same target still reaches it when one
        # of them is removed.
        graph = {0: [1, 1], 1: []}
        self.assertEqual(reachable(graph, 0, skip_edge=(0, 1)), {0, 1})

    def test_unknown_node_has_no_successors(self):
        self.assertEqual(reachable({}, 7), {7})


class TestGuardedRegion(unittest.TestCase):
    def test_diamond_excludes_the_merge_block(self):
        #      0
        #     / \
        #    1   2      <- then / else
        #     \ /
        #      3        <- runs either way
        graph = {0: [1, 2], 1: [3], 2: [3], 3: []}
        self.assertEqual(guarded_region(graph, 0, 0, 1), {1})
        self.assertEqual(guarded_region(graph, 0, 0, 2), {2})

    def test_one_armed_if(self):
        #   0 --true--> 1 --> 2
        #   0 --false-------> 2
        graph = {0: [1, 2], 1: [2], 2: []}
        self.assertEqual(guarded_region(graph, 0, 0, 1), {1})
        # The false arm goes straight to code that runs either way: it guards
        # nothing, and saying so is the point.
        self.assertEqual(guarded_region(graph, 0, 0, 2), set())

    def test_whole_subtree_is_guarded_not_just_the_first_block(self):
        #   0 -> 1 -> {4, 5} -> 6 ;  0 -> 2 -> 6
        graph = {0: [1, 2], 1: [4, 5], 4: [6], 5: [6], 2: [6], 6: []}
        self.assertEqual(guarded_region(graph, 0, 0, 1), {1, 4, 5})
        self.assertEqual(guarded_region(graph, 0, 0, 2), {2})

    def test_early_return_arm_keeps_its_own_block(self):
        #   0 --true--> 1 (return)
        #   0 --false-> 2 (the rest of the function)
        graph = {0: [1, 2], 1: [], 2: [3], 3: []}
        self.assertEqual(guarded_region(graph, 0, 0, 1), {1})
        self.assertEqual(guarded_region(graph, 0, 0, 2), {2, 3})

    def test_both_arms_jumping_to_one_block_guard_nothing(self):
        # `if (c) goto L; else goto L;` — L runs either way, so neither arm
        # guards it.
        graph = {0: [1, 1], 1: []}
        self.assertEqual(guarded_region(graph, 0, 0, 1), set())

    def test_target_reachable_another_way_guards_nothing(self):
        # 1 is also entered from 4, so reaching 1 does not imply the branch
        # went that way.
        graph = {0: [1, 2], 1: [3], 2: [4], 4: [1], 3: []}
        self.assertEqual(guarded_region(graph, 0, 0, 1), set())

    def test_loop_body_guarded_by_the_latch(self):
        #   0 -> 1 (header) -> 2 (body) -> 1 ; 1 -> 3 (exit)
        graph = {0: [1], 1: [2, 3], 2: [1], 3: []}
        # The body is only entered by the header taking its back edge.
        self.assertEqual(guarded_region(graph, 0, 1, 2), {2})
        # The exit is only entered by the header taking the other edge.
        self.assertEqual(guarded_region(graph, 0, 1, 3), {3})

    def test_nested_branch_region_contains_the_inner_arms(self):
        #   0 -> 1 -> {2,3} -> 4 -> 6 ; 0 -> 5 -> 6
        graph = {0: [1, 5], 1: [2, 3], 2: [4], 3: [4], 4: [6], 5: [6], 6: []}
        self.assertEqual(guarded_region(graph, 0, 0, 1), {1, 2, 3, 4})
        self.assertEqual(guarded_region(graph, 1, 1, 2), {2})


if __name__ == "__main__":
    unittest.main()
