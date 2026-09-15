# API Xref Hunter

A Binary Ninja plugin that answers one question well: **which functions in this
binary call any of the APIs I care about?**

Point it at a set of names — typed in, or picked from an editable preset — and
it resolves them to symbols, walks the cross-references, and gives you every
caller grouped by function rather than a flat list of call sites.

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

## Output

### Sidebar panel

The plugin registers an **API Hunter** sidebar widget that sits alongside
Symbols, Tags and Cross References. It has a preset dropdown, a pattern box,
match mode, a depth spinner, and a results tree grouped into direct and
indirect callers. Double-click a function or a call site to navigate there.

The **Reaches?** button answers the single-function question: does whatever
the cursor is currently inside ever reach a matching API? It shows the
shortest call chain, one hop per row, each row navigable.

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

## Layout

| File | Contents |
|---|---|
| `core.py` | Matching, search, reachability, reporting. No UI imports. |
| `__init__.py` | Command registration; loads the sidebar when the UI is up. |
| `sidebar.py` | The Qt sidebar widget. Only imported when `core_ui_enabled()`. |

## License

MIT.
