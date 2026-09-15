"""
API Xref Hunter — Binary Ninja plugin.

Find every function that calls any API from a user-defined set of names, and
check whether a given function ever reaches one (directly or through a chain).

Analysis logic lives in core.py; this module registers commands and, when the
UI is running, the sidebar widget in sidebar.py.

Headless use:

    import binaryninja
    from api_xref_hunter.core import find_api_callers, resolve_targets, reaches

    with binaryninja.load("sample.exe") as bv:
        result = find_api_callers(bv, ["Reg*Key*"], max_depth=2)
        targets = resolve_targets(bv, ["Reg*Key*"])
        print(reaches(bv, bv.get_function_at(0x401000), targets))
"""

import json
from typing import List

from binaryninja import BinaryView, core_ui_enabled
from binaryninja.log import log_error, log_info
from binaryninja.plugin import BackgroundTaskThread, PluginCommand

from .core import (
    DEFAULT_PRESETS,
    LAST_QUERY_KEY,
    MATCH_MODES,
    PLUGIN_NAME,
    TAG_TYPE_NAME,
    build_report,
    find_api_callers,
    get_setting,
    load_presets,
    reaches,
    reaches_report,
    resolve_targets,
    save_presets,
    set_setting,
    tag_callers,
)

# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

class _HuntTask(BackgroundTaskThread):
    def __init__(self, bv, patterns, mode, case_sensitive,
                 include_local, max_depth, do_tag):
        super().__init__(f"{PLUGIN_NAME}: searching…", can_cancel=True)
        self.bv = bv
        self.patterns = patterns
        self.mode = mode
        self.case_sensitive = case_sensitive
        self.include_local = include_local
        self.max_depth = max_depth
        self.do_tag = do_tag

    def run(self):
        def progress(done, total):
            if self.cancelled:
                raise KeyboardInterrupt()
            self.progress = f"{PLUGIN_NAME}: {done}/{total} APIs resolved"

        try:
            result = find_api_callers(
                self.bv,
                self.patterns,
                mode=self.mode,
                case_sensitive=self.case_sensitive,
                include_local_functions=self.include_local,
                max_depth=self.max_depth,
                progress=progress,
            )
        except KeyboardInterrupt:
            log_info(f"{PLUGIN_NAME}: cancelled.")
            return
        except Exception as exc:
            log_error(f"{PLUGIN_NAME}: search failed: {exc}")
            return

        log_info(f"{PLUGIN_NAME}: {len(result)} caller(s) found.")
        for hit in result.callers:
            log_info(f"  {hit.name} @ {hex(hit.start)} -> "
                     + ", ".join(sorted(hit.apis)))

        if self.do_tag and result.callers:
            n = tag_callers(self.bv, result)
            log_info(f"{PLUGIN_NAME}: tagged {n} function(s) as '{TAG_TYPE_NAME}'.")

        report = build_report(result, getattr(self.bv.file, "filename", "") or "")
        try:
            self.bv.show_markdown_report(PLUGIN_NAME, report, report)
        except Exception:
            log_info(report)


def _prompt_and_run(bv: BinaryView) -> None:
    from binaryninja.interaction import (
        ChoiceField, MultilineTextField, SeparatorField, TextLineField,
        get_form_input,
    )

    presets = load_presets()
    preset_names = ["(use the box below)"] + sorted(presets.keys())

    last = get_setting(LAST_QUERY_KEY, "")

    preset_field = ChoiceField("Preset", preset_names, 0)
    names_field = MultilineTextField(
        "API names / patterns (one per line, or comma separated)", last
    )
    mode_field = ChoiceField("Match mode", MATCH_MODES, 0)
    depth_field = TextLineField("Max caller depth (1 = direct only)", "1")
    opts_field = ChoiceField(
        "Options",
        [
            "Imports only",
            "Imports + local functions",
            "Imports + local functions, tag results",
            "Imports only, tag results",
        ],
        1,
    )

    ok = get_form_input(
        [
            f"{PLUGIN_NAME} — find every function calling a set of APIs.",
            SeparatorField(),
            preset_field,
            names_field,
            SeparatorField(),
            mode_field,
            depth_field,
            opts_field,
        ],
        PLUGIN_NAME,
    )
    if not ok:
        return

    raw = (names_field.result or "").strip()
    chosen_preset = preset_names[preset_field.result]
    patterns: List[str] = []
    if chosen_preset != preset_names[0]:
        patterns.extend(presets.get(chosen_preset, []))
    if raw:
        for chunk in raw.replace(",", "\n").splitlines():
            chunk = chunk.strip()
            if chunk and not chunk.startswith("#"):
                patterns.append(chunk)

    patterns = list(dict.fromkeys(patterns))  # dedupe, keep order
    if not patterns:
        log_error(f"{PLUGIN_NAME}: no patterns given.")
        return

    try:
        max_depth = max(1, int((depth_field.result or "1").strip()))
    except ValueError:
        max_depth = 1

    opt = opts_field.result
    include_local = opt in (1, 2)
    do_tag = opt in (2, 3)

    if raw:
        set_setting(LAST_QUERY_KEY, raw)

    _HuntTask(
        bv, patterns, MATCH_MODES[mode_field.result],
        case_sensitive=False,
        include_local=include_local,
        max_depth=max_depth,
        do_tag=do_tag,
    ).start()


def _run_preset(bv: BinaryView, preset_name: str) -> None:
    presets = load_presets()
    patterns = presets.get(preset_name)
    if not patterns:
        log_error(f"{PLUGIN_NAME}: preset {preset_name!r} not found.")
        return
    _HuntTask(bv, patterns, "glob", False, True, 1, False).start()


def _edit_presets(bv: BinaryView) -> None:
    from binaryninja.interaction import MultilineTextField, get_form_input

    current = json.dumps(load_presets(), indent=2)
    field = MultilineTextField("Presets (JSON)", current)
    if not get_form_input([field], f"{PLUGIN_NAME} — Edit presets"):
        return
    try:
        parsed = json.loads(field.result)
        assert isinstance(parsed, dict)
    except Exception as exc:
        log_error(f"{PLUGIN_NAME}: invalid JSON, not saved: {exc}")
        return
    if save_presets(parsed):
        log_info(f"{PLUGIN_NAME}: presets saved ({len(parsed)} set(s)).")


def _reset_presets(bv: BinaryView) -> None:
    if save_presets(DEFAULT_PRESETS):
        log_info(f"{PLUGIN_NAME}: presets restored to defaults.")


# --------------------------------------------------------------------------
# Reachability command
# --------------------------------------------------------------------------

class _ReachTask(BackgroundTaskThread):
    def __init__(self, bv, func, patterns, mode, depth):
        super().__init__(f"{PLUGIN_NAME}: reachability…", can_cancel=True)
        self.bv = bv
        self.func = func
        self.patterns = patterns
        self.mode = mode
        self.depth = depth

    def run(self):
        try:
            targets = resolve_targets(self.bv, self.patterns, mode=self.mode)
        except Exception as exc:
            log_error(f"{PLUGIN_NAME}: {exc}")
            return
        if not targets:
            log_info(f"{PLUGIN_NAME}: no symbols matched those patterns.")
            return
        chain = reaches(self.bv, self.func, targets, max_depth=self.depth)
        text = reaches_report(self.func.name, chain)
        log_info(f"{PLUGIN_NAME}: {text}")
        try:
            self.bv.show_markdown_report(
                f"{PLUGIN_NAME} — reachability",
                f"# Does `{self.func.name}` reach a matching API?\n\n{text}\n",
                text,
            )
        except Exception:
            pass


def _check_reach(bv: BinaryView, func) -> None:
    """Does this function ever reach a matching API, directly or via a chain?"""
    from binaryninja.interaction import ChoiceField, MultilineTextField, get_form_input

    presets = load_presets()
    preset_names = ["(use the box below)"] + sorted(presets.keys())
    preset_field = ChoiceField("Preset", preset_names, 1)
    names_field = MultilineTextField("Extra API names / patterns", "")
    mode_field = ChoiceField("Match mode", MATCH_MODES, 0)

    if not get_form_input(
        [f"Does {func.name} ever reach one of these APIs?",
         preset_field, names_field, mode_field],
        f"{PLUGIN_NAME} — reachability",
    ):
        return

    patterns: List[str] = []
    chosen = preset_names[preset_field.result]
    if chosen != preset_names[0]:
        patterns.extend(presets.get(chosen, []))
    for chunk in (names_field.result or "").replace(",", "\n").splitlines():
        chunk = chunk.strip()
        if chunk:
            patterns.append(chunk)
    patterns = list(dict.fromkeys(patterns))
    if not patterns:
        log_error(f"{PLUGIN_NAME}: no patterns given.")
        return

    _ReachTask(bv, func, patterns, MATCH_MODES[mode_field.result], 8).start()


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------

PluginCommand.register(
    f"{PLUGIN_NAME}\\Find callers of APIs…",
    "Find every function that calls any API from a configurable name set",
    _prompt_and_run,
)

PluginCommand.register_for_function(
    f"{PLUGIN_NAME}\\Does this function reach an API?…",
    "Check whether this function ever reaches a matching API, directly or via a chain",
    _check_reach,
)

for _name in sorted(DEFAULT_PRESETS.keys()):
    PluginCommand.register(
        f"{PLUGIN_NAME}\\Quick scan\\{_name}",
        f"Find all callers of {_name} APIs",
        (lambda n: (lambda bv: _run_preset(bv, n)))(_name),
    )

PluginCommand.register(
    f"{PLUGIN_NAME}\\Edit presets…",
    "Edit the stored API name presets",
    _edit_presets,
)

PluginCommand.register(
    f"{PLUGIN_NAME}\\Reset presets to defaults",
    "Restore the built-in preset list",
    _reset_presets,
)

# The sidebar is UI-only; importing it headlessly would pull in PySide6.
if core_ui_enabled():
    try:
        from . import sidebar
        sidebar.register()
    except Exception as _exc:  # never let a UI failure break the core commands
        log_error(f"{PLUGIN_NAME}: sidebar unavailable ({_exc}); "
                  "menu commands still work.")
