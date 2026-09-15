"""
API Xref Hunter — branch analysis: what the binary *does* with an API's result.

`core.py` answers "who calls this API". This module answers the other half of
the question: once the API has returned, which conditional branches test what
it produced, and what code hangs off each side of those branches. That is how
you find the code a registry read actually gates — the `jz` after
`RegQueryValueExW` and the block that only runs when the value was there.

The analysis, per call site:

1. **Seed.** Take what the call produced: the return value (the call's MLIL SSA
   outputs) and any out-parameter, i.e. an argument passed as `&var`, which is
   how the Win32 registry and crypto APIs hand back the data you branch on.
2. **Propagate.** Walk MLIL SSA def-use forward from those seeds, through
   copies, phi nodes and field assignments, until the value reaches the
   condition of an `if`. Each assignment is a hop, and hops are bounded.
3. **Attribute.** For the conditional found, compute the basic blocks each arm
   guards (`cfgutil.guarded_region`) and summarise them by the calls they make
   — which is what turns "there is a branch here" into "on success it calls
   CreateProcessW".

Limits worth knowing, since they decide whether a negative result means
anything:

- **Intraprocedural.** Propagation stops at the function boundary. If the
  result is returned or handed to a helper, that is reported as an untested
  use naming where the value went, not followed into the callee.
- **Out-parameters are matched by variable, not by memory.** A write the API
  performs through a pointer is invisible in the caller's IL, so reads of the
  variable whose address was passed are treated as carrying the API's data
  from the call site onward. A variable reused for something else afterwards
  can therefore over-report.
- **The condition is reported, not interpreted.** Which arm means "success"
  depends on the API's contract — `RegOpenKeyExW` returns 0 on success while
  `CreateFileW` returns -1 on failure — so both arms are shown with their
  condition text and you read off which is which.
- Everything rests on Binary Ninja's MLIL SSA, so it sees only what analysis
  resolved: an indirect call through a `GetProcAddress` pointer has no
  matching symbol to seed from in the first place.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from binaryninja import BinaryView
from binaryninja.log import log_warn

from . import cfgutil
from .core import PLUGIN_NAME, resolve_targets, unmatched_patterns

# How many assignments a value may pass through before we stop following it.
# Compilers rarely put more than a couple of copies between a call and the
# test of its result; a high bound mostly buys unrelated variables.
DEFAULT_MAX_HOPS = 6

# Ceiling on SSA variables visited per call site, so a pathological function
# cannot stall a whole-binary scan.
MAX_VISITS_PER_SITE = 512

# Instructions scanned when looking for reads of an out-parameter.
MAX_OUT_PARAM_SCAN = 4096

# Operation names are compared as strings rather than against imported enum
# members: the MediumLevelILOperation members present vary between Binary Ninja
# versions, and an AttributeError at import time would take the plugin down.
_CALL_OPS = {
    "MLIL_CALL_SSA", "MLIL_CALL_UNTYPED_SSA",
    "MLIL_TAILCALL_SSA", "MLIL_TAILCALL_UNTYPED_SSA",
    "MLIL_SYSCALL_SSA", "MLIL_SYSCALL_UNTYPED_SSA",
}
_ASSIGN_OPS = {
    "MLIL_SET_VAR_SSA", "MLIL_SET_VAR_SSA_FIELD",
    "MLIL_SET_VAR_ALIASED", "MLIL_SET_VAR_ALIASED_FIELD",
    "MLIL_VAR_PHI",
}
_RET_OPS = {"MLIL_RET", "MLIL_RET_HINT"}
_STORE_OPS = {"MLIL_STORE_SSA", "MLIL_STORE_STRUCT_SSA"}


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

@dataclass
class GuardedSide:
    """One arm of a conditional, and the code reaching it depends on."""
    taken: bool                                   # the `if` condition's value
    entry: Optional[int] = None                   # address the arm starts at
    blocks: int = 0                               # basic blocks it guards
    calls: List[Tuple[int, str]] = field(default_factory=list)
    returns: bool = False                         # the arm returns from the function

    @property
    def label(self) -> str:
        return "when true" if self.taken else "when false"

    @property
    def call_names(self) -> List[str]:
        return list(dict.fromkeys(name for _, name in self.calls))

    @property
    def is_empty(self) -> bool:
        """The arm guards no code of its own — it jumps to the merge point."""
        return self.blocks == 0


@dataclass
class ApiGuard:
    """A conditional whose outcome depends on what an API call produced."""
    function: object                 # binaryninja.Function
    api: str
    call_site: int                   # address of the call to the API
    origin: str                      # "return value" / "out-parameter 2 (&var_10)"
    condition_site: int              # address of the branching instruction
    condition: str                   # the condition as source text
    hops: int                        # assignments between the call and the test
    true_side: GuardedSide
    false_side: GuardedSide

    @property
    def sides(self) -> List[GuardedSide]:
        return [self.true_side, self.false_side]


@dataclass
class UntestedCall:
    """An API call whose result no conditional in this function tests."""
    function: object
    api: str
    call_site: int
    fate: List[str] = field(default_factory=list)   # where the value went instead


@dataclass
class BranchResult:
    guards: List[ApiGuard] = field(default_factory=list)
    untested: List[UntestedCall] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    mode: str = "glob"
    unmatched_patterns: List[str] = field(default_factory=list)
    call_sites: int = 0
    functions_scanned: int = 0

    def __len__(self) -> int:
        return len(self.guards)

    def by_function(self) -> Dict[int, List[ApiGuard]]:
        out: Dict[int, List[ApiGuard]] = defaultdict(list)
        for guard in self.guards:
            out[guard.function.start].append(guard)
        return dict(out)


# --------------------------------------------------------------------------
# IL access — deliberately forgiving, versions differ in the details
# --------------------------------------------------------------------------

def _op(inst) -> str:
    operation = getattr(inst, "operation", None)
    return getattr(operation, "name", "") or str(operation)


def _is_ssa_var(obj) -> bool:
    return hasattr(obj, "var") and hasattr(obj, "version")


def _var_key(ssa_var) -> Tuple:
    var = getattr(ssa_var, "var", None)
    ident = getattr(var, "identifier", None)
    return (ident if ident is not None else str(var), getattr(ssa_var, "version", -1))


def _ssa_form(func):
    try:
        mlil = func.mlil
        return mlil.ssa_form if mlil is not None else None
    except Exception:
        return None


def _expr_text(expr) -> str:
    """The expression as it reads on screen, falling back to repr."""
    try:
        tokens = expr.tokens
        if tokens:
            return "".join(t.text for t in tokens).strip()
    except Exception:
        pass
    return str(expr)


def _collect_ssa_vars(expr, depth: int = 0, out: Optional[List] = None) -> List:
    """Every SSA variable read anywhere inside an expression tree."""
    if out is None:
        out = []
    if depth > 24 or expr is None:
        return out
    if _is_ssa_var(expr):
        out.append(expr)
        return out
    operands = getattr(expr, "operands", None)
    if operands is None:
        return out
    for operand in operands:
        if isinstance(operand, (list, tuple)):
            for item in operand:
                _collect_ssa_vars(item, depth + 1, out)
        else:
            _collect_ssa_vars(operand, depth + 1, out)
    return out


def _reads(expr, ssa_var) -> bool:
    key = _var_key(ssa_var)
    return any(_var_key(v) == key for v in _collect_ssa_vars(expr))


def _ssa_var_uses(il, ssa_var) -> List:
    """Instructions using an SSA variable; older versions return indices."""
    try:
        uses = il.get_ssa_var_uses(ssa_var)
    except Exception:
        return []
    resolved = []
    for use in uses or []:
        if isinstance(use, int):
            try:
                resolved.append(il[use])
            except Exception:
                continue
        else:
            resolved.append(use)
    return resolved


def _call_at(il, addr: int):
    """The MLIL SSA call instruction at `addr`, or None."""
    try:
        for inst in il.instructions:
            if inst.address == addr and _op(inst) in _CALL_OPS:
                return inst
    except Exception:
        return None
    return None


def _output_vars(call_inst) -> List:
    """SSA variables the call defines, i.e. where its return value landed."""
    output = getattr(call_inst, "output", None)
    if output is None:
        return []
    # Untyped calls wrap their outputs in a CALL_OUTPUT_SSA expression.
    candidates = getattr(output, "dest", None)
    if candidates is None:
        candidates = output
    if _is_ssa_var(candidates):
        return [candidates]
    try:
        items = list(candidates)
    except TypeError:
        return []
    return [item for item in items if _is_ssa_var(item)]


def _params(call_inst) -> List:
    params = getattr(call_inst, "params", None)
    if params is None:
        return []
    inner = getattr(params, "src", None)
    if isinstance(inner, (list, tuple)):
        params = inner
    try:
        return list(params)
    except TypeError:
        return []


def _call_target_name(bv: BinaryView, inst) -> str:
    dest = getattr(inst, "dest", None)
    addr = getattr(dest, "constant", None)
    if addr is None:
        return "(indirect call)"
    try:
        sym = bv.get_symbol_at(addr)
        if sym is not None:
            return sym.name
        target = bv.get_function_at(addr)
        if target is not None:
            return target.name
    except Exception:
        pass
    return hex(addr)


def _block_graph(il) -> Tuple[Dict[int, List[int]], Dict[int, object], Optional[int]]:
    """Adjacency map over IL basic block indices, plus the blocks themselves."""
    graph: Dict[int, List[int]] = {}
    blocks: Dict[int, object] = {}
    for block in il.basic_blocks:
        blocks[block.index] = block
        succs = []
        for edge in block.outgoing_edges:
            target = getattr(edge, "target", None)
            if target is not None:
                succs.append(target.index)
        graph[block.index] = succs
    entry = None
    try:
        entry_block = il.get_basic_block_at(0)
        entry = entry_block.index if entry_block is not None else None
    except Exception:
        pass
    if entry is None and blocks:
        entry = min(blocks)
    return graph, blocks, entry


# --------------------------------------------------------------------------
# Seeding: what the call produced
# --------------------------------------------------------------------------

def _out_param_seeds(il, call_inst, call_addr: int, graph, blocks,
                     call_block_index: Optional[int]) -> List[Tuple[object, str]]:
    """
    Seeds for arguments passed as `&var`.

    Binary Ninja cannot see the API writing through the pointer, so the write
    never appears in the caller's IL. Reads of that variable from the call site
    onward are therefore treated as carrying whatever the API stored — an
    approximation, and the reason this can over-report when a variable is
    reused later for something unrelated.
    """
    pointed_at = []
    for position, param in enumerate(_params(call_inst), start=1):
        if _op(param) != "MLIL_ADDRESS_OF":
            continue
        var = getattr(param, "src", None)
        if var is None:
            continue
        pointed_at.append((var, f"out-parameter {position} (&{var})"))
    if not pointed_at:
        return []

    downstream = (cfgutil.reachable(graph, call_block_index)
                  if call_block_index is not None else set(blocks))

    seeds: List[Tuple[object, str]] = []
    seen: Set[Tuple] = set()
    scanned = 0
    for index in sorted(downstream):
        block = blocks.get(index)
        if block is None:
            continue
        for i in range(block.start, block.end):
            scanned += 1
            if scanned > MAX_OUT_PARAM_SCAN:
                return seeds
            try:
                inst = il[i]
            except Exception:
                continue
            # Within the call's own block, only code after the call can be
            # reading what the call stored.
            if inst.address <= call_addr and index == call_block_index:
                continue
            for ssa_var in _collect_ssa_vars(inst):
                for var, origin in pointed_at:
                    if getattr(ssa_var, "var", None) != var:
                        continue
                    key = _var_key(ssa_var)
                    if key in seen:
                        continue
                    seen.add(key)
                    seeds.append((ssa_var, origin))
    return seeds


def _seeds_for_call(il, call_inst, call_addr, graph, blocks,
                    call_block_index) -> List[Tuple[object, str]]:
    seeds = [(var, "return value") for var in _output_vars(call_inst)]
    seeds.extend(_out_param_seeds(il, call_inst, call_addr, graph, blocks,
                                  call_block_index))
    return seeds


# --------------------------------------------------------------------------
# Propagation: from the value to the conditions that test it
# --------------------------------------------------------------------------

def _trace_to_conditions(il, seeds, max_hops: int):
    """
    Forward def-use walk from each seed to the `if` conditions reading it.

    Returns `(conditions, fate)` where conditions maps an instruction index to
    `(if_instruction, origin, hops)`, and fate describes what else the value
    fed into — which is what gets reported when nothing tests it.
    """
    conditions: Dict[int, Tuple[object, str, int]] = {}
    fate: List[str] = []
    seen: Set[Tuple] = set()
    visits = 0

    queue = deque((var, origin, 0) for var, origin in seeds)
    while queue and visits < MAX_VISITS_PER_SITE:
        ssa_var, origin, hops = queue.popleft()
        key = _var_key(ssa_var)
        if key in seen:
            continue
        seen.add(key)
        visits += 1

        for use in _ssa_var_uses(il, ssa_var):
            op = _op(use)

            if op == "MLIL_IF":
                condition = getattr(use, "condition", None)
                if condition is None or not _reads(condition, ssa_var):
                    continue
                index = getattr(use, "instr_index", id(use))
                previous = conditions.get(index)
                if previous is None or previous[2] > hops:
                    conditions[index] = (use, origin, hops)
                continue

            if op in _ASSIGN_OPS:
                if hops >= max_hops:
                    continue
                dest = getattr(use, "dest", None)
                targets = [dest] if _is_ssa_var(dest) else _collect_ssa_vars(dest)
                for target in targets:
                    queue.append((target, origin, hops + 1))
                continue

            if op in _CALL_OPS:
                fate.append(f"passed to {_expr_text(getattr(use, 'dest', None))} "
                            f"at {hex(use.address)}")
            elif op in _RET_OPS:
                fate.append(f"returned from the function at {hex(use.address)}")
            elif op in _STORE_OPS:
                fate.append(f"stored to memory at {hex(use.address)}")

    return conditions, list(dict.fromkeys(fate))


# --------------------------------------------------------------------------
# Attribution: what each arm of the branch guards
# --------------------------------------------------------------------------

def _summarise_side(bv: BinaryView, il, blocks, region: Set[int],
                    taken: bool) -> GuardedSide:
    side = GuardedSide(taken=taken, blocks=len(region))
    if not region:
        return side

    ordered = sorted(region)
    first = blocks.get(ordered[0])
    if first is not None:
        try:
            side.entry = il[first.start].address
        except Exception:
            side.entry = getattr(getattr(first, "source_block", None), "start", None)

    for index in ordered:
        block = blocks.get(index)
        if block is None:
            continue
        for i in range(block.start, block.end):
            try:
                inst = il[i]
            except Exception:
                continue
            op = _op(inst)
            if op in _CALL_OPS:
                side.calls.append((inst.address, _call_target_name(bv, inst)))
            elif op in _RET_OPS:
                side.returns = True
    return side


def _build_guard(bv: BinaryView, func, il, graph, blocks, entry: Optional[int],
                 if_inst, api: str, call_site: int, origin: str,
                 hops: int) -> Optional[ApiGuard]:
    if entry is None:
        return None
    try:
        branch_block = il.get_basic_block_at(if_inst.instr_index)
        true_block = il.get_basic_block_at(if_inst.true)
        false_block = il.get_basic_block_at(if_inst.false)
    except Exception:
        return None
    if branch_block is None or true_block is None or false_block is None:
        return None

    true_region = cfgutil.guarded_region(graph, entry, branch_block.index,
                                         true_block.index)
    false_region = cfgutil.guarded_region(graph, entry, branch_block.index,
                                          false_block.index)

    return ApiGuard(
        function=func,
        api=api,
        call_site=call_site,
        origin=origin,
        condition_site=if_inst.address,
        condition=_expr_text(getattr(if_inst, "condition", None)),
        hops=hops,
        true_side=_summarise_side(bv, il, blocks, true_region, True),
        false_side=_summarise_side(bv, il, blocks, false_region, False),
    )


# --------------------------------------------------------------------------
# Per-function and whole-binary entry points
# --------------------------------------------------------------------------

def analyze_function_branches(
    bv: BinaryView,
    func,
    sites: Sequence[Tuple[int, str]],
    max_hops: int = DEFAULT_MAX_HOPS,
) -> Tuple[List[ApiGuard], List[UntestedCall]]:
    """
    Analyse the given `(call address, api name)` sites inside one function.

    Returns the conditionals those calls' results feed, and the calls whose
    results nothing in this function tests.
    """
    il = _ssa_form(func)
    if il is None:
        return [], []

    graph, blocks, entry = _block_graph(il)
    guards: List[ApiGuard] = []
    untested: List[UntestedCall] = []

    for call_addr, api in sites:
        call_inst = _call_at(il, call_addr)
        if call_inst is None:
            continue
        call_block = None
        try:
            block = il.get_basic_block_at(call_inst.instr_index)
            call_block = block.index if block is not None else None
        except Exception:
            pass

        seeds = _seeds_for_call(il, call_inst, call_addr, graph, blocks, call_block)
        if not seeds:
            untested.append(UntestedCall(func, api, call_addr,
                                         ["the call has no result in IL"]))
            continue

        conditions, fate = _trace_to_conditions(il, seeds, max_hops)
        if not conditions:
            untested.append(UntestedCall(func, api, call_addr, fate))
            continue

        for if_inst, origin, hops in conditions.values():
            guard = _build_guard(bv, func, il, graph, blocks, entry, if_inst,
                                 api, call_addr, origin, hops)
            if guard is not None:
                guards.append(guard)

    guards.sort(key=lambda g: (g.call_site, g.condition_site))
    return guards, untested


def find_api_branches(
    bv: BinaryView,
    patterns: Sequence[str],
    mode: str = "glob",
    case_sensitive: bool = False,
    include_local_functions: bool = True,
    max_hops: int = DEFAULT_MAX_HOPS,
    functions: Optional[Iterable] = None,
    progress=None,
) -> BranchResult:
    """
    Find every conditional whose outcome depends on a matching API's result.

    `functions` restricts the scan to those functions; the default is the whole
    binary.
    """
    result = BranchResult(patterns=list(patterns), mode=mode)
    targets = resolve_targets(bv, patterns, mode=mode,
                              case_sensitive=case_sensitive,
                              include_local_functions=include_local_functions)
    if not targets:
        result.unmatched_patterns = list(patterns)
        return result

    only = None
    if functions is not None:
        only = {f.start for f in functions}

    sites: Dict[int, List[Tuple[int, str]]] = defaultdict(list)
    owners: Dict[int, object] = {}
    for addr, api in targets.items():
        try:
            refs = bv.get_code_refs(addr)
        except Exception:
            continue
        for ref in refs:
            caller = ref.function
            if caller is None or caller.start in targets:
                continue          # a thunk forwarding to the API is not a caller
            if only is not None and caller.start not in only:
                continue
            sites[caller.start].append((ref.address, api))
            owners[caller.start] = caller

    result.call_sites = sum(len(v) for v in sites.values())
    result.functions_scanned = len(sites)

    for done, (start, func_sites) in enumerate(sorted(sites.items()), start=1):
        if progress:
            progress(done, len(sites))
        try:
            guards, untested = analyze_function_branches(
                bv, owners[start], func_sites, max_hops=max_hops)
        except Exception as exc:
            log_warn(f"{PLUGIN_NAME}: branch analysis failed in "
                     f"{owners[start].name}: {exc}")
            continue
        result.guards.extend(guards)
        result.untested.extend(untested)

    result.guards.sort(key=lambda g: (g.function.name.lower(), g.call_site))
    result.untested.sort(key=lambda u: (u.function.name.lower(), u.call_site))
    result.unmatched_patterns = unmatched_patterns(
        patterns, set(targets.values()), mode, case_sensitive)
    return result


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _nav(addr: int, text: Optional[str] = None) -> str:
    label = text if text is not None else hex(addr)
    return f"[{label}](binaryninja://?expr={hex(addr)})"


def _side_row(side: GuardedSide) -> str:
    if side.is_empty:
        return (f"| {side.label} | — | 0 | "
                f"nothing of its own — falls through to code that runs either way |")
    calls = side.call_names
    if calls:
        rendered = ", ".join(f"`{c}`" for c in calls[:12])
        if len(calls) > 12:
            rendered += f" … (+{len(calls) - 12})"
    else:
        rendered = "no calls"
    if side.returns:
        rendered += " — returns"
    entry = _nav(side.entry) if side.entry is not None else "—"
    return f"| {side.label} | {entry} | {side.blocks} | {rendered} |"


def build_branch_report(result: BranchResult, binary_name: str = "") -> str:
    lines = [f"# {PLUGIN_NAME} — branches on API results", ""]
    if binary_name:
        lines.append(f"**Binary:** `{binary_name}`  ")
    lines.append(f"**Match mode:** `{result.mode}`  ")
    lines.append(f"**Patterns:** `{', '.join(result.patterns)}`  ")
    lines.append("")

    if not result.call_sites:
        lines.append("No call sites to analyse — nothing calls a matching API.")
        if result.unmatched_patterns:
            lines.append("")
            lines.append("Patterns with no matching symbol: `"
                         + "`, `".join(result.unmatched_patterns) + "`")
        return "\n".join(lines)

    lines.append(
        f"**{len(result.guards)}** conditional(s) branch on an API result, from "
        f"**{result.call_sites}** call site(s) across "
        f"**{result.functions_scanned}** function(s)."
    )
    lines.append("")
    lines.append("Which arm means success depends on the API: `RegOpenKeyExW` "
                 "returns `ERROR_SUCCESS` (0) when it worked, while "
                 "`CreateFileW` returns `-1` when it failed. The condition is "
                 "shown as written so you can read off which is which.")
    lines.append("")

    for func_start, guards in sorted(
        result.by_function().items(),
        key=lambda kv: kv[1][0].function.name.lower(),
    ):
        func_name = guards[0].function.name
        lines.append(f"## {_nav(func_start, func_name)}")
        lines.append("")
        for guard in guards:
            hop_text = ("tested directly" if guard.hops == 0
                        else f"{guard.hops} assignment(s) later")
            lines.append(
                f"### `{guard.api}` at {_nav(guard.call_site)} — {guard.origin}"
            )
            lines.append("")
            lines.append(
                f"Branch at {_nav(guard.condition_site)}: "
                f"`if ({guard.condition})` — {hop_text}."
            )
            lines.append("")
            lines.append("| Arm | Starts at | Blocks | Guards |")
            lines.append("|---|---|---|---|")
            lines.append(_side_row(guard.true_side))
            lines.append(_side_row(guard.false_side))
            lines.append("")

    if result.untested:
        lines.append("## Results no branch tests")
        lines.append("")
        lines.append("These calls succeed or fail without this function acting "
                     "on the difference — or the value leaves the function "
                     "before anything tests it.")
        lines.append("")
        lines.append("| API | Call site | In | Where the value goes |")
        lines.append("|---|---|---|---|")
        for call in result.untested:
            fate = "; ".join(call.fate[:3]) if call.fate else "unused"
            lines.append(
                f"| `{call.api}` | {_nav(call.call_site)} | "
                f"{_nav(call.function.start, call.function.name)} | {fate} |"
            )
        lines.append("")

    if result.unmatched_patterns:
        lines.append("## Patterns with no match")
        lines.append("")
        lines.append("`" + "`, `".join(result.unmatched_patterns) + "`")

    return "\n".join(lines)
