# API Xref Hunter

A Binary Ninja plugin for the two questions worth asking about an API in a
binary.

**Who calls it?** Point it at a set of names — typed in, or picked from an
editable preset — and it resolves them to symbols, walks the cross-references,
and gives you every caller grouped by function rather than a flat list of call
sites.

**What happens because of it?** Once the call has returned, which conditionals
test what it produced, and what code only runs because one of them went a
particular way. That is the `jz` after a registry read and the block it gates,
reported as *this arm calls `CreateProcessW`, that arm returns*.

## Install

Copy the `api_xref_hunter` folder into your Binary Ninja user plugins directory:

| OS | Path |
|---|---|
| Linux | `~/.binaryninja/plugins/` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |
| Windows | `%APPDATA%\Binary Ninja\plugins\` |

Restart Binary Ninja. The commands appear under `Plugins → API Xref Hunter`,
and in the Command Palette (`Ctrl/Cmd-P`) by name.

## Commands

- **Find callers of APIs…** — the main dialog: pick a preset and/or type your
  own patterns, choose match mode and depth, run.
- **Quick scan → <preset>** — one-click scan using a preset with defaults.
- **Edit presets…** — edit the stored preset JSON in place.
- **Reset presets to defaults** — restore the shipped set.
- **Does this function reach an API?…** — right-click inside a function; walks
  the call graph downward and reports the shortest chain to a matching API.
- **Find branches on API results…** — every conditional in the binary whose
  outcome depends on what a matching API returned.
- **Branches on API results in this function…** — right-click inside a
  function to ask the same thing about just that function.

## Match modes

| Mode | Example pattern | Matches |
|---|---|---|
| `glob` (default) | `Reg*Key*` | `RegOpenKeyExW`, `RegDeleteKeyA` |
| `exact` | `RegOpenKeyExW` | only that name |
| `substring` | `openkey` | `RegOpenKeyExW` (case-insensitive) |
| `regex` | `^Nt(Open\|Create)Key` | `NtOpenKeyEx`, `NtCreateKey` |

Matching is case-insensitive by default and is tried against each symbol's
`name`, `short_name` and `raw_name`, plus a decoration-stripped form — so
`RegOpenKeyExW` still matches a symbol imported as `advapi32!RegOpenKeyExW`
or `__imp_RegOpenKeyExW@20`.

## Caller depth

Depth `1` gives direct callers only. Higher values walk the call graph upward,
so a function that calls a wrapper that calls a wrapper that calls
`RegOpenKeyExW` is still reported, annotated with the callee it reaches
through. Useful on binaries that funnel all API access through a dispatcher.

## Branches on API results

Caller search tells you a function touches `RegQueryValueExW`. It does not tell
you that the binary only installs persistence when the value was already there.
Branch analysis does.

For each call to a matching API it takes what the call produced, follows it to
the conditionals that test it, and reports what each arm of those conditionals
guards:

```
cfg_load
  RegQueryValueExW at 0x401234 — out-parameter 2 (&var_10)
  Branch at 0x401240:  if (var_10 == 0)  — 1 assignment(s) later

    when true   0x401250   1 block    RegSetValueExW, WriteFile
    when false  0x401290   3 blocks   CreateProcessW — returns
```

What it follows:

- **The return value**, through copies and phi nodes, until it reaches the
  condition of an `if`. Each assignment in between is a *hop*, and the hop
  budget is configurable (6 by default) — raising it finds longer chains and
  more unrelated variables with them.
- **Out-parameters**, i.e. arguments passed as `&var`. This matters more than
  the return value for the registry: `RegQueryValueExW` returns a status code,
  but the data you branch on comes back through the buffer pointer.

What each arm reports is the set of blocks that run *only* because the branch
went that way. The merge block both arms fall back into belongs to neither, so
an arm that reports `CreateProcessW` really does gate that call, and an arm
that guards nothing says so instead of claiming the rest of the function.

Calls whose result nothing tests get their own section, naming where the value
went instead — returned, passed to another function, stored, or simply unused.
An ignored return value is a finding too.

### Which arm is success?

The plugin does not label the arms, because only the API's contract can:
`RegOpenKeyExW` returns `ERROR_SUCCESS` (0) when it worked, `CreateFileW`
returns `-1` when it failed, and `GetProcAddress` returns `NULL`. The condition
is shown as written so you can read off which side is which.

## Output

### Sidebar panel

The plugin registers an **API Hunter** sidebar widget that sits alongside
Symbols, Tags and Cross References. It has a preset dropdown, a pattern box,
match mode, a depth spinner, and a results tree grouped into direct and
indirect callers. Double-click a function or a call site to navigate there.

The **Reaches?** button answers the single-function question: does whatever
the cursor is currently inside ever reach a matching API? It shows the
shortest call chain, one hop per row, each row navigable.

The **Branches?** button runs branch analysis on that same function, and builds
a tree of API call → the test it feeds → one row per arm listing the calls that
arm guards. Every row navigates, so you can walk from the condition into the
code it gates without leaving the panel.

Drag the divider between the **Function** and **Address** columns to split the
tree however you like — long mangled names get more room, or the addresses do.
The width you drag to is pinned and remembered across sessions, in
`apiXrefHunter.functionColumnWidth` (pixels). Double-click the divider to unpin
it again: at `0`, the default, the Function column sizes itself to whatever
results are on screen, stopping short of crowding out the Address column.

### Other output

- A **markdown report** tab with `binaryninja://` links, for the menu commands.
- Full results in the **Log**.
- Optionally, each caller is **tagged** with an `API Hit` tag summarising which
  APIs it touches, which persists in the analysis database and makes results
  browsable from the Tags panel too.

## Presets

Presets live in Binary Ninja's settings under `apiXrefHunter.presets` as a JSON
object mapping a name to a list of patterns. Shipped sets: Registry, Process
injection, Network, Filesystem, Crypto, Dynamic resolution, Anti-analysis,
Memory (libc). Add your own via **Edit presets…** or directly in settings:

```json
{
  "My COM stuff": ["CoCreateInstance", "CoInitialize*", "CLSIDFrom*"]
}
```

## Headless use

```python
import binaryninja
from api_xref_hunter.core import find_api_callers, build_report, resolve_targets, reaches

with binaryninja.load("sample.exe") as bv:
    result = find_api_callers(bv, ["Reg*Key*", "Nt*Key*"], mode="glob", max_depth=2)
    for hit in result.callers:
        print(f"{hit.name} @ {hex(hit.start)} depth={hit.depth}",
              sorted(hit.apis))
    print(build_report(result, "sample.exe"))

    # "does function A ever reach a registry API?"
    targets = resolve_targets(bv, ["Reg*Key*"])
    chain = reaches(bv, bv.get_function_at(0x401000), targets, max_depth=8)
    print(chain)   # ['main', 'cfg_load', 'read_setting', 'RegOpenKeyExW'] or None
```

Branch analysis has the same shape:

```python
from api_xref_hunter.branches import (
    build_branch_report, find_api_branches, guard_summary,
)

with binaryninja.load("sample.exe") as bv:
    result = find_api_branches(bv, ["Reg*Value*"], max_hops=6)

    for guard in result.guards:
        print(guard_summary(guard))
        # cfg_load @ 0x401234: RegQueryValueExW -> if (var_10 == 0) at 0x401240
        #   [true: RegSetValueExW, WriteFile] [false: CreateProcessW]
        for side in guard.sides:
            print(" ", side.label, side.call_names, "returns" if side.returns else "")

    for call in result.untested:
        print(f"{call.api} @ {hex(call.call_site)} result ignored: {call.fate}")

    print(build_branch_report(result, "sample.exe"))
```

Pass `functions=[func]` to scope it to one function. `find_api_branches` returns
a `BranchResult` with `.guards` (`ApiGuard`: function, api, call_site, origin,
condition_site, condition, hops, and a `true_side`/`false_side` pair of
`GuardedSide`), `.untested`, and the same `.unmatched_patterns` signal as
`find_api_callers`.

`reaches` walks `callee_addresses` rather than `callees`, because `callees`
omits calls to imported functions — which is exactly the case for the Windows
APIs this plugin usually targets. A BFS built on `callees` returns "no" for
every registry API in the binary.

`find_api_callers` returns a `HuntResult` with `.callers` (a list of
`CallerHit`: function, apis, sites, depth, via), `.matched_symbols`
(API name → call site count) and `.unmatched_patterns` — patterns that
resolved to no symbol at all, which is your signal that an API is either
absent or resolved dynamically at runtime.

## Notes and limits

- Only finds **statically resolvable** calls. A binary resolving APIs through
  `GetProcAddress` and calling them via a pointer won't show up — check the
  `unmatched_patterns` section, and consider scanning the
  **Dynamic resolution** preset instead.
- `Imports only` vs `Imports + local functions` controls whether internal
  functions whose names match are treated as targets too. Keep local functions
  on when working with a binary that has symbols.
- Thunks that merely forward to a matched API are excluded from the caller
  list, so you get real callers rather than the import stub.

Branch analysis adds its own:

- **It stops at the function boundary.** A result that is returned, or handed
  to a helper that does the testing, is reported as untested *here*, naming
  where the value went. Follow it yourself from there.
- **Out-parameters are tracked by variable, not by memory.** The API's write
  through the pointer is invisible in the caller's IL, so reads of that
  variable from the call site onward are assumed to carry what the API stored.
  A variable the compiler reuses later for something else can over-report.
- **A missing branch is not proof of a missing check.** The value may be tested
  through a path the hop budget cut off, in a caller, or by a construct MLIL
  models differently. Treat it as "nothing found", not "nothing there".

## Layout

| File | Contents |
|---|---|
| `core.py` | Matching, caller search, reachability, reporting. No UI imports. |
| `branches.py` | Branch analysis: MLIL SSA def-use, guarded regions, report. |
| `cfgutil.py` | The graph reasoning behind it. Imports no Binary Ninja. |
| `__init__.py` | Command registration; loads the sidebar when the UI is up. |
| `sidebar.py` | The Qt sidebar widget. Only imported when `core_ui_enabled()`. |
| `tests/` | Runs without Binary Ninja: `python3 -m unittest discover -s tests`. |

`tests/_harness.py` stubs enough of the Binary Ninja API, and enough fake MLIL
SSA, to exercise the def-use walk and region attribution on hand-built
functions — so the analysis is testable on a machine with no licence.

## License

MIT.
