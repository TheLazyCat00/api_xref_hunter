"""
API Xref Hunter — core analysis logic (no UI dependencies).

Find every function that calls any API from a user-defined set of names.

Ships with editable presets (registry, network, process injection, crypto,
filesystem, ...) and supports glob / regex / substring / exact matching,
optional transitive (indirect) caller discovery, a clickable markdown report,
and optional tagging so hits show up in the Tags sidebar.

Also usable headlessly:

    import binaryninja
    from api_xref_hunter import find_api_callers

    with binaryninja.load("sample.exe") as bv:
        result = find_api_callers(bv, ["Reg*Key*", "NtOpenKey"])
        for caller in result.callers:
            print(caller.function.name, sorted(caller.apis))
"""

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set

import binaryninja
from binaryninja import BinaryView, Settings, SymbolType
from binaryninja.log import log_error, log_info, log_warn
from binaryninja.plugin import BackgroundTaskThread, PluginCommand

PLUGIN_NAME = "API Xref Hunter"
SETTINGS_GROUP = "apiXrefHunter"
PRESETS_KEY = f"{SETTINGS_GROUP}.presets"
LAST_QUERY_KEY = f"{SETTINGS_GROUP}.lastQuery"
TAG_TYPE_NAME = "API Hit"

MATCH_MODES = ["glob", "exact", "substring", "regex"]

# Symbol kinds that can plausibly be a call target.
TARGET_SYMBOL_TYPES = (
    SymbolType.ImportedFunctionSymbol,
    SymbolType.ImportAddressSymbol,
    SymbolType.ExternalSymbol,
    SymbolType.FunctionSymbol,
    SymbolType.LibraryFunctionSymbol,
)

DEFAULT_PRESETS: Dict[str, List[str]] = {
    "Registry": [
        "Reg*Key*", "Reg*Value*", "RegCloseKey", "RegFlushKey",
        "RegConnectRegistry*", "RegGetValue*",
        "NtOpenKey*", "NtCreateKey*", "NtQueryValueKey", "NtSetValueKey",
        "NtDeleteKey", "NtDeleteValueKey", "NtEnumerateKey", "NtEnumerateValueKey",
        "ZwOpenKey*", "ZwCreateKey*", "ZwQueryValueKey", "ZwSetValueKey",
    ],
    "Process injection": [
        "OpenProcess", "VirtualAlloc*", "VirtualProtect*", "WriteProcessMemory",
        "ReadProcessMemory", "CreateRemoteThread*", "QueueUserAPC",
        "SetThreadContext", "GetThreadContext", "ResumeThread", "SuspendThread",
        "NtMapViewOfSection", "NtUnmapViewOfSection", "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
        "RtlCreateUserThread",
    ],
    "Network": [
        "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "WSA*", "getaddrinfo", "gethostbyname",
        "InternetOpen*", "InternetConnect*", "InternetReadFile*",
        "HttpOpenRequest*", "HttpSendRequest*", "URLDownloadToFile*",
        "WinHttp*",
    ],
    "Filesystem": [
        "CreateFile*", "ReadFile*", "WriteFile*", "DeleteFile*", "MoveFile*",
        "CopyFile*", "FindFirstFile*", "FindNextFile*", "SetFileAttributes*",
        "GetTempPath*", "GetTempFileName*",
        "NtCreateFile", "NtWriteFile", "NtReadFile",
    ],
    "Crypto": [
        "Crypt*", "BCrypt*", "NCrypt*",
        "EVP_*", "AES_*", "MD5*", "SHA1*", "SHA256*", "RC4*",
        "RtlEncryptMemory", "RtlDecryptMemory",
    ],
    "Dynamic resolution": [
        "LoadLibrary*", "GetProcAddress", "GetModuleHandle*",
        "LdrLoadDll", "LdrGetProcedureAddress", "dlopen", "dlsym",
    ],
    "Anti-analysis": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString*", "GetTickCount*", "QueryPerformanceCounter",
        "Sleep", "SleepEx", "CreateToolhelp32Snapshot", "Process32*",
    ],
    "Memory (libc)": [
        "malloc", "calloc", "realloc", "free",
        "memcpy", "memmove", "strcpy", "strcat", "sprintf", "gets",
        "system", "exec*", "popen",
    ],
}


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

_SETTINGS_OK = False


def _preset_file() -> str:
    """Fallback store, used only if Settings registration fails."""
    try:
        return os.path.join(binaryninja.user_directory(), "api_xref_hunter.json")
    except Exception:
        return os.path.join(os.path.expanduser("~"), ".api_xref_hunter.json")


def register_settings() -> bool:
    """
    Register the settings group. Must be called once at import time, before any
    get_string/set_string, or Binary Ninja logs 'Invalid Setting!' on every read.
    Returns True if both settings registered.
    """
    global _SETTINGS_OK
    if _SETTINGS_OK:
        return True
    try:
        settings = Settings()
        settings.register_group(SETTINGS_GROUP, PLUGIN_NAME)
        ok_presets = settings.register_setting(
            PRESETS_KEY,
            json.dumps({
                "title": "Presets",
                "description": (
                    "JSON object mapping a preset name to a list of API name "
                    "patterns. Edit this to define your own reusable API sets."
                ),
                "type": "string",
                "default": json.dumps(DEFAULT_PRESETS, indent=2),
            }),
        )
        ok_last = settings.register_setting(
            LAST_QUERY_KEY,
            json.dumps({
                "title": "Last query",
                "description": "Most recently used pattern list, prefilled next run.",
                "type": "string",
                "default": "",
            }),
        )
        _SETTINGS_OK = bool(ok_presets and ok_last)
        if not _SETTINGS_OK:
            log_warn(f"{PLUGIN_NAME}: settings registration was rejected; "
                     f"presets will be stored in {_preset_file()} instead.")
    except Exception as exc:
        _SETTINGS_OK = False
        log_warn(f"{PLUGIN_NAME}: settings unavailable ({exc}); "
                 f"presets will be stored in {_preset_file()} instead.")
    return _SETTINGS_OK


def get_setting(key: str, default: str = "") -> str:
    """Read a registered setting without tripping 'Invalid Setting!' errors."""
    if not _SETTINGS_OK:
        return default
    try:
        return Settings().get_string(key) or default
    except Exception:
        return default


def set_setting(key: str, value: str) -> bool:
    if not _SETTINGS_OK:
        return False
    try:
        return bool(Settings().set_string(key, value))
    except Exception:
        return False


def load_presets() -> Dict[str, List[str]]:
    """Read presets from settings, then the fallback file, then the defaults."""
    raw = get_setting(PRESETS_KEY)
    if not raw and not _SETTINGS_OK:
        try:
            path = _preset_file()
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    raw = fh.read()
        except Exception:
            raw = ""
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and parsed:
                return {str(k): [str(p) for p in v] for k, v in parsed.items()}
        except Exception as exc:  # malformed user JSON shouldn't break the plugin
            log_warn(f"{PLUGIN_NAME}: could not parse stored presets ({exc}); "
                     "using built-in defaults.")
    return dict(DEFAULT_PRESETS)


def save_presets(presets: Dict[str, Sequence[str]]) -> bool:
    payload = json.dumps({k: list(v) for k, v in presets.items()}, indent=2)
    if set_setting(PRESETS_KEY, payload):
        return True
    try:
        with open(_preset_file(), "w", encoding="utf-8") as fh:
            fh.write(payload)
        return True
    except Exception as exc:
        log_error(f"{PLUGIN_NAME}: failed to save presets: {exc}")
        return False


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

def _build_matcher(patterns: Sequence[str], mode: str, case_sensitive: bool):
    """Return a predicate testing a symbol name against the patterns."""
    mode = mode if mode in MATCH_MODES else "glob"

    def norm(s: str) -> str:
        return s if case_sensitive else s.lower()

    pats = [norm(p) for p in patterns if p.strip()]

    if mode == "regex":
        flags = 0 if case_sensitive else re.IGNORECASE
        compiled = []
        for p in patterns:
            if not p.strip():
                continue
            try:
                compiled.append(re.compile(p, flags))
            except re.error as exc:
                log_warn(f"{PLUGIN_NAME}: skipping invalid regex {p!r}: {exc}")
        return lambda name: any(c.search(name) for c in compiled)

    if mode == "exact":
        wanted = set(pats)
        return lambda name: norm(name) in wanted

    if mode == "substring":
        return lambda name: any(p in norm(name) for p in pats)

    # glob (default)
    return lambda name: any(fnmatch.fnmatchcase(norm(name), p) for p in pats)


def _symbol_names(sym) -> Set[str]:
    """All name spellings a symbol might be matched under."""
    names = set()
    for attr in ("name", "short_name", "raw_name", "full_name"):
        value = getattr(sym, attr, None)
        if isinstance(value, str) and value:
            names.add(value)
            # Strip common decorations: advapi32!Foo, _Foo@8, __imp_Foo
            stripped = value.split("!")[-1]
            stripped = stripped.lstrip("_")
            stripped = stripped.split("@")[0]
            if stripped:
                names.add(stripped)
    return names


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

@dataclass
class CallerHit:
    function: object                      # binaryninja.Function
    apis: Set[str] = field(default_factory=set)
    sites: List[int] = field(default_factory=list)
    depth: int = 1                        # 1 = direct caller, 2+ = transitive
    via: Optional[str] = None             # name of the callee it reaches through

    @property
    def name(self) -> str:
        return self.function.name

    @property
    def start(self) -> int:
        return self.function.start


@dataclass
class HuntResult:
    callers: List[CallerHit] = field(default_factory=list)
    matched_symbols: Dict[str, int] = field(default_factory=dict)
    unmatched_patterns: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    mode: str = "glob"

    def __len__(self) -> int:
        return len(self.callers)


# --------------------------------------------------------------------------
# Core search
# --------------------------------------------------------------------------

def find_api_callers(
    bv: BinaryView,
    patterns: Sequence[str],
    mode: str = "glob",
    case_sensitive: bool = False,
    include_local_functions: bool = True,
    max_depth: int = 1,
    progress=None,
) -> HuntResult:
    """
    Find every function calling any symbol whose name matches `patterns`.

    max_depth=1 returns direct callers only. Higher values walk the call graph
    upward, so wrappers around a wrapper around RegOpenKeyExW are still found.
    """
    matcher = _build_matcher(patterns, mode, case_sensitive)
    result = HuntResult(patterns=list(patterns), mode=mode)

    allowed_types = list(TARGET_SYMBOL_TYPES)
    if not include_local_functions:
        allowed_types = [t for t in allowed_types
                         if t not in (SymbolType.FunctionSymbol,)]

    # 1. Resolve patterns to concrete symbol addresses.
    targets: Dict[int, str] = {}   # address -> display name
    for sym in bv.get_symbols():
        if sym.type not in allowed_types:
            continue
        names = _symbol_names(sym)
        if any(matcher(n) for n in names):
            targets[sym.address] = sym.name

    if not targets:
        result.unmatched_patterns = list(patterns)
        return result

    # 2. Direct callers.
    hits: Dict[int, CallerHit] = {}   # function start -> hit
    for addr, api_name in targets.items():
        count = 0
        for ref in bv.get_code_refs(addr):
            caller = ref.function
            if caller is None:
                continue
            if caller.start in targets:
                # a thunk for the API itself, not an interesting caller
                continue
            hit = hits.get(caller.start)
            if hit is None:
                hit = CallerHit(function=caller, depth=1)
                hits[caller.start] = hit
            hit.apis.add(api_name)
            hit.sites.append(ref.address)
            count += 1
        result.matched_symbols[api_name] = count
        if progress:
            progress(len(result.matched_symbols), len(targets))

    # 3. Optional transitive callers.
    if max_depth > 1:
        frontier = list(hits.values())
        depth = 1
        while frontier and depth < max_depth:
            depth += 1
            next_frontier = []
            for hit in frontier:
                for parent in _callers_of(bv, hit.function):
                    if parent.start in hits or parent.start in targets:
                        continue
                    parent_hit = CallerHit(
                        function=parent,
                        apis=set(hit.apis),
                        depth=depth,
                        via=hit.function.name,
                    )
                    hits[parent.start] = parent_hit
                    next_frontier.append(parent_hit)
            frontier = next_frontier

    result.callers = sorted(hits.values(), key=lambda h: (h.depth, h.name.lower()))

    # 4. Report patterns that matched nothing at all.
    matched_names = set(targets.values())
    for pat in patterns:
        single = _build_matcher([pat], mode, case_sensitive)
        if not any(single(n) for n in matched_names):
            result.unmatched_patterns.append(pat)

    return result


def _callers_of(bv: BinaryView, func) -> Iterable:
    """Functions that call `func`, tolerant of API differences across versions."""
    try:
        callers = func.callers
        if callers is not None:
            return list(callers)
    except Exception:
        pass
    out = []
    for ref in bv.get_code_refs(func.start):
        if ref.function is not None:
            out.append(ref.function)
    return out


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _nav(addr: int, text: Optional[str] = None) -> str:
    label = text if text is not None else hex(addr)
    return f"[{label}](binaryninja://?expr={hex(addr)})"


def build_report(result: HuntResult, binary_name: str = "") -> str:
    lines = [f"# {PLUGIN_NAME}", ""]
    if binary_name:
        lines.append(f"**Binary:** `{binary_name}`  ")
    lines.append(f"**Match mode:** `{result.mode}`  ")
    lines.append(f"**Patterns:** `{', '.join(result.patterns)}`  ")
    lines.append("")

    if not result.callers:
        lines.append("No matching API symbols were found, or nothing calls them.")
        if result.unmatched_patterns:
            lines.append("")
            lines.append("Patterns with no matching symbol: `"
                         + "`, `".join(result.unmatched_patterns) + "`")
        return "\n".join(lines)

    direct = [h for h in result.callers if h.depth == 1]
    indirect = [h for h in result.callers if h.depth > 1]

    lines.append(f"**{len(direct)}** function(s) call a matching API directly"
                 + (f", **{len(indirect)}** indirectly." if indirect else "."))
    lines.append("")

    lines.append("## APIs found")
    lines.append("")
    lines.append("| API | Call sites |")
    lines.append("|---|---|")
    for api, count in sorted(result.matched_symbols.items(),
                             key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| `{api}` | {count} |")
    lines.append("")

    lines.append("## Direct callers")
    lines.append("")
    for hit in direct:
        lines.append(f"### {_nav(hit.start, hit.name)}")
        lines.append("")
        lines.append(f"`{hex(hit.start)}` — calls: "
                     + ", ".join(f"`{a}`" for a in sorted(hit.apis)))
        lines.append("")
        site_links = ", ".join(_nav(a) for a in sorted(set(hit.sites))[:24])
        more = "" if len(set(hit.sites)) <= 24 else " …"
        lines.append(f"Call sites: {site_links}{more}")
        lines.append("")

    if indirect:
        lines.append("## Indirect callers")
        lines.append("")
        lines.append("| Function | Address | Depth | Reaches via |")
        lines.append("|---|---|---|---|")
        for hit in indirect:
            lines.append(
                f"| {_nav(hit.start, hit.name)} | `{hex(hit.start)}` | "
                f"{hit.depth} | `{hit.via}` |"
            )
        lines.append("")

    if result.unmatched_patterns:
        lines.append("## Patterns with no match")
        lines.append("")
        lines.append("`" + "`, `".join(result.unmatched_patterns) + "`")

    return "\n".join(lines)


def tag_callers(bv: BinaryView, result: HuntResult) -> int:
    """Tag each caller so hits are browsable in the Tags sidebar. Returns count."""
    try:
        tag_type = bv.tag_types.get(TAG_TYPE_NAME)
        if tag_type is None:
            tag_type = bv.create_tag_type(TAG_TYPE_NAME, "🔎")
    except Exception as exc:
        log_warn(f"{PLUGIN_NAME}: could not create tag type: {exc}")
        return 0

    tagged = 0
    for hit in result.callers:
        summary = ", ".join(sorted(hit.apis))
        if hit.depth > 1:
            summary = f"(indirect via {hit.via}) {summary}"
        try:
            hit.function.add_tag(tag_type, summary)
            tagged += 1
        except Exception:
            try:
                bv.add_user_data_tag(hit.start, tag_type, summary)
                tagged += 1
            except Exception:
                pass
    return tagged



# --------------------------------------------------------------------------
# Reachability: does function A ever reach any matching API?
# --------------------------------------------------------------------------

def resolve_targets(
    bv: BinaryView,
    patterns: Sequence[str],
    mode: str = "glob",
    case_sensitive: bool = False,
    include_local_functions: bool = True,
) -> Dict[int, str]:
    """Resolve patterns to a dict of {address: symbol name}."""
    matcher = _build_matcher(patterns, mode, case_sensitive)
    allowed = list(TARGET_SYMBOL_TYPES)
    if not include_local_functions:
        allowed = [t for t in allowed if t != SymbolType.FunctionSymbol]

    targets: Dict[int, str] = {}
    for sym in bv.get_symbols():
        if sym.type not in allowed:
            continue
        if any(matcher(n) for n in _symbol_names(sym)):
            targets[sym.address] = sym.name
    return targets


def reaches(
    bv: BinaryView,
    src,
    targets: Dict[int, str],
    max_depth: int = 8,
) -> Optional[List[str]]:
    """
    Breadth-first search downward from `src` for any address in `targets`.

    Returns the shortest call chain as a list of names, or None.

    Uses `callee_addresses` rather than `callees` deliberately: `callees` omits
    calls to imported functions (they have no Function object), which is
    exactly the case for the Windows APIs this plugin usually targets.
    """
    from collections import deque

    seen = {src.start}
    queue = deque([(src, [src.name])])

    while queue:
        func, path = queue.popleft()
        if len(path) > max_depth:
            continue
        try:
            callee_addrs = list(func.callee_addresses)
        except Exception:
            callee_addrs = [c.start for c in getattr(func, "callees", [])]

        for addr in callee_addrs:
            if addr in targets:
                return path + [targets[addr]]
            if addr in seen:
                continue
            seen.add(addr)
            callee = bv.get_function_at(addr)
            if callee is not None:
                queue.append((callee, path + [callee.name]))
    return None


def reaches_report(src_name: str, chain: Optional[List[str]]) -> str:
    if chain is None:
        return f"`{src_name}` does not reach any matching API."
    return "  ->  ".join(f"`{n}`" for n in chain)


# Register settings at import time — before anything calls get_setting().
register_settings()
