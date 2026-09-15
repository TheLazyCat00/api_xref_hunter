"""
API Xref Hunter — control-flow graph helpers.

Pure Python, deliberately free of any `binaryninja` import: the graph reasoning
behind branch analysis is the part most likely to be subtly wrong, and keeping
it here means it can be exercised without a Binary Ninja install (see
`tests/test_cfgutil.py`).

A graph is a plain adjacency map, `{node: [successor, ...]}`, where nodes are
whatever the caller uses to identify a basic block — `branches.py` passes IL
basic block indices.
"""

from typing import Dict, Optional, Sequence, Set, Tuple

Graph = Dict[int, Sequence[int]]


def reachable(
    graph: Graph,
    start: int,
    skip_edge: Optional[Tuple[int, int]] = None,
) -> Set[int]:
    """
    Every node reachable from `start`, including `start` itself.

    `skip_edge` drops a single `(src, dst)` edge for the walk, which is how
    `guarded_region` asks "could control get here some other way?".
    """
    seen = {start}
    stack = [start]
    while stack:
        node = stack.pop()
        for succ in graph.get(node, ()):
            if skip_edge is not None and (node, succ) == skip_edge:
                continue
            if succ in seen:
                continue
            seen.add(succ)
            stack.append(succ)
    return seen


def guarded_region(graph: Graph, entry: int, branch: int, target: int) -> Set[int]:
    """
    The nodes that run *only* when `branch` hands control to `target`.

    This is the code one side of a conditional guards. It is not simply
    "everything after the branch": in the usual diamond, both arms fall back
    into a merge block that runs either way, and the merge is not guarded by
    either side. So the region is what `target` leads to, minus everything that
    control can reach without taking this edge at all.

    Returns an empty set when the branch guards nothing on that side — an arm
    that jumps straight to the merge point, or a target that doubles as a loop
    header reachable from elsewhere.
    """
    elsewhere = reachable(graph, entry, skip_edge=(branch, target))
    return reachable(graph, target) - elsewhere

