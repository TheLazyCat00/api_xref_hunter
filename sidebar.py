"""
API Xref Hunter — sidebar widget.

Puts results in the sidebar alongside Symbols, Tags and Cross References
instead of a one-shot report tab. Only imported when the UI is running.

Note the import order: binaryninjaui must be imported before PySide6, both to
ensure the correct PySide6 is loaded and to keep this module from being
imported in headless sessions.
"""

from binaryninjaui import (
    Sidebar,
    SidebarContextSensitivity,
    SidebarWidget,
    SidebarWidgetLocation,
    SidebarWidgetType,
    UIActionHandler,
)

from PySide6 import QtCore
from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QImage, QPainter
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from binaryninja import execute_on_main_thread
from binaryninja.log import log_error, log_info
from binaryninja.plugin import BackgroundTaskThread

from . import branches, core

WIDGET_NAME = "API Hunter"

# Narrowest either column may be dragged, in pixels. A stored width below
# this is treated as unset, i.e. as "size the Function column to its contents".
MIN_COLUMN_WIDTH = 40

# Sizing to contents is capped at this fraction of the panel: sidebars are
# narrow and a long mangled name would otherwise push Address out of sight.
# Dragging is not capped — a width the user picked is a width they meant.
MAX_AUTO_FIT_FRACTION = 0.6


def _navigate(widget, addr: int) -> None:
    """Jump the active view to `addr`, tolerant of API differences."""
    frame = getattr(widget, "frame", None)
    data = getattr(widget, "data", None)

    if frame is not None:
        try:
            frame.navigate(addr)
            return
        except Exception:
            pass
    try:
        from binaryninjaui import UIContext
        ctx = UIContext.activeContext()
        if ctx is not None and data is not None:
            ctx.navigateForBinaryView(data, addr)
            return
    except Exception:
        pass
    if data is not None:
        try:
            data.navigate(data.view, addr)
        except Exception as exc:
            log_error(f"API Xref Hunter: could not navigate to {hex(addr)}: {exc}")


class _ScanTask(BackgroundTaskThread):
    """Runs the search off the UI thread, then repaints the tree on the main one."""

    def __init__(self, widget, bv, patterns, mode, depth, include_local):
        super().__init__("API Hunter: scanning…", can_cancel=True)
        self.widget = widget
        self.bv = bv
        self.patterns = patterns
        self.mode = mode
        self.depth = depth
        self.include_local = include_local

    def run(self):
        try:
            result = core.find_api_callers(
                self.bv,
                self.patterns,
                mode=self.mode,
                include_local_functions=self.include_local,
                max_depth=self.depth,
            )
        except Exception as exc:
            # Bind the text here: `exc` is unbound once the except block ends,
            # so a lambda capturing it would raise on the main thread instead
            # of showing the failure.
            message = f"Failed: {exc}"
            log_error(f"API Xref Hunter: scan failed: {exc}")
            execute_on_main_thread(lambda: self.widget.set_status(message))
            return
        execute_on_main_thread(lambda: self.widget.populate(result))


class _ReachTask(BackgroundTaskThread):
    def __init__(self, widget, bv, func, patterns, mode, depth, include_local):
        super().__init__("API Hunter: reachability…", can_cancel=True)
        self.widget = widget
        self.bv = bv
        self.func = func
        self.patterns = patterns
        self.mode = mode
        self.depth = depth
        self.include_local = include_local

    def run(self):
        try:
            targets = core.resolve_targets(
                self.bv, self.patterns, mode=self.mode,
                include_local_functions=self.include_local,
            )
            chain = core.reaches(self.bv, self.func, targets, max_depth=self.depth)
        except Exception as exc:
            log_error(f"API Xref Hunter: reachability failed: {exc}")
            return
        execute_on_main_thread(lambda: self.widget.show_chain(self.func, chain))


class _BranchTask(BackgroundTaskThread):
    """What does the function at the cursor do with these APIs' results?"""

    def __init__(self, widget, bv, func, patterns, mode):
        super().__init__("API Hunter: branches…", can_cancel=True)
        self.widget = widget
        self.bv = bv
        self.func = func
        self.patterns = patterns
        self.mode = mode

    def run(self):
        try:
            result = branches.find_api_branches(
                self.bv, self.patterns, mode=self.mode, functions=[self.func],
            )
        except Exception as exc:
            message = f"Failed: {exc}"
            log_error(f"API Xref Hunter: branch analysis failed: {exc}")
            execute_on_main_thread(lambda: self.widget.set_status(message))
            return
        execute_on_main_thread(
            lambda: self.widget.populate_branches(self.func, result))


class ApiHunterSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        SidebarWidget.__init__(self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        self.data = data
        self.frame = frame
        self._current_offset = 0

        layout = QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # --- preset + mode row
        top = QHBoxLayout()
        self.preset = QComboBox()
        self.preset.addItem("(custom)")
        for name_ in sorted(core.load_presets().keys()):
            self.preset.addItem(name_)
        self.preset.currentIndexChanged.connect(self._preset_changed)
        top.addWidget(self.preset, 2)

        self.mode = QComboBox()
        self.mode.addItems(core.MATCH_MODES)
        top.addWidget(self.mode, 1)
        layout.addLayout(top)

        # --- pattern box
        self.patterns = QLineEdit()
        self.patterns.setPlaceholderText("Reg*Key*, NtOpenKey  (comma separated)")
        self.patterns.returnPressed.connect(self.scan)
        layout.addWidget(self.patterns)

        # --- depth + buttons
        row = QHBoxLayout()
        row.addWidget(QLabel("Depth"))
        self.depth = QSpinBox()
        self.depth.setRange(1, 16)
        self.depth.setValue(1)
        self.depth.setToolTip("1 = direct callers only; higher walks the call graph")
        row.addWidget(self.depth)

        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.scan)
        row.addWidget(self.scan_btn)
        layout.addLayout(row)

        # The two questions about the function at the cursor get their own row:
        # four controls on one line is unreadable at sidebar widths.
        here = QHBoxLayout()
        self.reach_btn = QPushButton("Reaches?")
        self.reach_btn.setToolTip(
            "Does the function at the current offset ever reach a matching API?"
        )
        self.reach_btn.clicked.connect(self.check_reach)
        here.addWidget(self.reach_btn)

        self.branch_btn = QPushButton("Branches?")
        self.branch_btn.setToolTip(
            "What does the function at the current offset do differently "
            "depending on what a matching API returned?"
        )
        self.branch_btn.clicked.connect(self.check_branches)
        here.addWidget(self.branch_btn)
        layout.addLayout(here)

        # --- results
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Function", "Address"])
        self.tree.setColumnCount(2)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemDoubleClicked.connect(self._item_activated)
        self._setup_header()
        layout.addWidget(self.tree, 1)

        self.status = QLabel("Enter API names or pick a preset, then Scan.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.setLayout(layout)

    # -- column layout -----------------------------------------------------

    def _setup_header(self):
        """
        Make the Function/Address divider draggable and remember where it lands.

        Both sections are Interactive (Stretch and ResizeToContents would each
        pin the divider in place), with the last section stretching so the
        Address column simply takes whatever the Function column leaves.

        Dragging the divider pins a width, which is stored and restored next
        time. Double-clicking it clears that width again, back to sizing the
        Function column to whatever the results happen to be.
        """
        header = self.tree.header()
        header.setSectionsMovable(False)
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(MIN_COLUMN_WIDTH)
        header.setCascadingSectionResizes(False)

        # Writing a setting on every pixel of a drag would be wasteful, so the
        # save is debounced until the drag settles.
        self._suppress_width_save = False
        self._width_save_timer = QtCore.QTimer(self)
        self._width_save_timer.setSingleShot(True)
        self._width_save_timer.setInterval(500)
        self._width_save_timer.timeout.connect(self._save_column_width)
        header.sectionResized.connect(self._column_resized)
        header.sectionHandleDoubleClicked.connect(self._divider_double_clicked)

        self.apply_column_width()

    def _stored_column_width(self) -> int:
        """The pinned Function column width, or 0 to size it to contents."""
        try:
            width = int(core.get_setting(core.FUNCTION_COLUMN_WIDTH_KEY, "0") or 0)
        except ValueError:
            return 0
        return width if width >= MIN_COLUMN_WIDTH else 0

    def apply_column_width(self):
        """
        Restore the pinned width, or fit the Function column to its contents.

        Called again after every repopulate so that an unpinned column keeps
        tracking the names actually on screen, within the cap below.
        """
        width = self._stored_column_width()
        self._suppress_width_save = True
        try:
            if width:
                self.tree.setColumnWidth(0, width)
            else:
                self.tree.resizeColumnToContents(0)
                self._cap_auto_fit()
        finally:
            self._suppress_width_save = False

    def _cap_auto_fit(self):
        """Keep a fitted column from crowding the Address column off the panel."""
        viewport = self.tree.viewport().width()
        if viewport <= MIN_COLUMN_WIDTH * 2:  # not laid out yet; nothing to cap against
            return
        limit = int(viewport * MAX_AUTO_FIT_FRACTION)
        if self.tree.columnWidth(0) > limit:
            self.tree.setColumnWidth(0, limit)

    def _column_resized(self, index, _old, _new):
        """Queue a save when the user drags the divider, not when we resize."""
        if index == 0 and not self._suppress_width_save:
            self._width_save_timer.start()

    def _divider_double_clicked(self, index):
        """Unpin the column: Qt fits it to contents and it stays that way."""
        if index != 0:
            return
        self._width_save_timer.stop()
        core.set_setting(core.FUNCTION_COLUMN_WIDTH_KEY, "0")
        # Qt does its own fit once this slot returns; that resize is ours, not
        # the user pinning a width, so it must not be saved back.
        self._suppress_width_save = True
        QtCore.QTimer.singleShot(0, self._resume_width_save)

    def _resume_width_save(self):
        """Re-arm saving once Qt's own fit-to-contents resize has gone through."""
        self._suppress_width_save = False

    def _save_column_width(self):
        """Pin the width the divider was dragged to, for the next session."""
        core.set_setting(core.FUNCTION_COLUMN_WIDTH_KEY,
                         str(self.tree.columnWidth(0)))

    # -- sidebar callbacks -------------------------------------------------

    def notifyOffsetChanged(self, offset):
        self._current_offset = offset

    def notifyViewChanged(self, view_frame):
        self.frame = view_frame
        if view_frame is None:
            self.data = None
        else:
            try:
                self.data = view_frame.getCurrentViewInterface().getData()
            except Exception:
                pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    # -- helpers -----------------------------------------------------------

    def set_status(self, text: str):
        self.status.setText(text)

    def _preset_changed(self, index):
        if index <= 0:
            return
        name = self.preset.itemText(index)
        pats = core.load_presets().get(name, [])
        self.patterns.setText(", ".join(pats))

    def _collect_patterns(self):
        raw = self.patterns.text().strip()
        pats = [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]
        return list(dict.fromkeys(pats))

    def _item_activated(self, item, _column):
        addr = item.data(0, Qt.UserRole)
        if isinstance(addr, int):
            _navigate(self, addr)

    # -- actions -----------------------------------------------------------

    def scan(self):
        if self.data is None:
            self.set_status("No binary view active.")
            return
        pats = self._collect_patterns()
        if not pats:
            self.set_status("No patterns given.")
            return
        self.set_status("Scanning…")
        self.tree.clear()
        _ScanTask(
            self, self.data, pats, self.mode.currentText(),
            self.depth.value(), True,
        ).start()

    def check_reach(self):
        func = self._function_at_cursor()
        if func is None:
            return
        pats = self._collect_patterns()
        if not pats:
            self.set_status("No patterns given.")
            return
        self.set_status("Checking reachability…")
        _ReachTask(
            self, self.data, func, pats, self.mode.currentText(),
            max(self.depth.value(), 8), True,
        ).start()

    def check_branches(self):
        func = self._function_at_cursor()
        if func is None:
            return
        pats = self._collect_patterns()
        if not pats:
            self.set_status("No patterns given.")
            return
        self.set_status(f"Analysing branches in {func.name}…")
        self.tree.clear()
        _BranchTask(self, self.data, func, pats, self.mode.currentText()).start()

    def _function_at_cursor(self):
        """The function the cursor sits in, or None with the reason on screen."""
        if self.data is None:
            self.set_status("No binary view active.")
            return None
        funcs = self.data.get_functions_containing(self._current_offset) or []
        if not funcs:
            self.set_status("Cursor is not inside a function.")
            return None
        return funcs[0]

    # -- rendering ---------------------------------------------------------

    def populate(self, result):
        self.tree.clear()
        if not result.callers:
            msg = "No callers found."
            if result.unmatched_patterns:
                msg += "  Unmatched: " + ", ".join(result.unmatched_patterns)
            self.set_status(msg)
            return

        direct = [h for h in result.callers if h.depth == 1]
        indirect = [h for h in result.callers if h.depth > 1]

        def add_group(label, hits):
            if not hits:
                return
            group = QTreeWidgetItem(self.tree, [f"{label} ({len(hits)})", ""])
            group.setExpanded(True)
            f = group.font(0)
            f.setBold(True)
            group.setFont(0, f)
            for hit in hits:
                node = QTreeWidgetItem(group, [hit.name, hex(hit.start)])
                node.setData(0, Qt.UserRole, hit.start)
                if hit.depth > 1:
                    node.setToolTip(0, f"reaches via {hit.via}")
                for api in sorted(hit.apis):
                    QTreeWidgetItem(node, [api, ""])
                for site in sorted(set(hit.sites))[:32]:
                    leaf = QTreeWidgetItem(node, ["call site", hex(site)])
                    leaf.setData(0, Qt.UserRole, site)

        add_group("Direct callers", direct)
        add_group("Indirect callers", indirect)
        self.apply_column_width()

        total_sites = sum(result.matched_symbols.values())
        msg = (f"{len(direct)} direct"
               + (f", {len(indirect)} indirect" if indirect else "")
               + f" — {len(result.matched_symbols)} API(s), {total_sites} call site(s).")
        if result.unmatched_patterns:
            msg += "  Unmatched: " + ", ".join(result.unmatched_patterns)
        self.set_status(msg)

    def show_chain(self, func, chain):
        self.tree.clear()
        if chain is None:
            self.set_status(f"{func.name} does not reach any matching API.")
            return
        root = QTreeWidgetItem(self.tree, [f"{func.name} reaches:", ""])
        root.setExpanded(True)
        f = root.font(0)
        f.setBold(True)
        root.setFont(0, f)
        for i, name in enumerate(chain):
            item = QTreeWidgetItem(root, [f"{'  ' * i}{'→ ' if i else ''}{name}", ""])
            fn = None
            try:
                matches = self.data.get_functions_by_name(name)
                fn = matches[0] if matches else None
            except Exception:
                pass
            if fn is not None:
                item.setData(0, Qt.UserRole, fn.start)
                item.setText(1, hex(fn.start))
        self.apply_column_width()
        self.set_status(f"Shortest chain: {len(chain) - 1} hop(s).")


    def populate_branches(self, func, result):
        """
        Show each conditional that tests an API result, and what its arms guard.

        The tree reads top down as the question does: the API call, the test it
        feeds, then one row per arm naming the calls that only happen if the
        branch goes that way.
        """
        self.tree.clear()

        if not result.call_sites:
            self.set_status(f"{func.name} calls no matching API.")
            return

        if result.guards:
            root = QTreeWidgetItem(
                self.tree, [f"Branches on API results ({len(result.guards)})", ""])
            root.setExpanded(True)
            bold = root.font(0)
            bold.setBold(True)
            root.setFont(0, bold)

            for guard in result.guards:
                node = QTreeWidgetItem(
                    root,
                    [f"{guard.api} → if ({guard.condition})",
                     hex(guard.condition_site)],
                )
                node.setData(0, Qt.UserRole, guard.condition_site)
                node.setExpanded(True)
                hops = ("tested directly" if guard.hops == 0
                        else f"{guard.hops} assignment(s) later")
                node.setToolTip(
                    0,
                    f"call at {hex(guard.call_site)} — {guard.origin}, {hops}",
                )

                call_row = QTreeWidgetItem(node, ["call site", hex(guard.call_site)])
                call_row.setData(0, Qt.UserRole, guard.call_site)

                for side in guard.sides:
                    if side.is_empty:
                        QTreeWidgetItem(node, [f"{side.label}: nothing of its own", ""])
                        continue
                    names = side.call_names
                    summary = ", ".join(names[:6]) if names else "no calls"
                    if len(names) > 6:
                        summary += f" (+{len(names) - 6})"
                    if side.returns:
                        summary += " — returns"
                    arm = QTreeWidgetItem(
                        node,
                        [f"{side.label}: {summary}",
                         hex(side.entry) if side.entry is not None else ""],
                    )
                    if side.entry is not None:
                        arm.setData(0, Qt.UserRole, side.entry)
                    for addr, name in side.calls[:32]:
                        leaf = QTreeWidgetItem(arm, [name, hex(addr)])
                        leaf.setData(0, Qt.UserRole, addr)

        if result.untested:
            group = QTreeWidgetItem(
                self.tree,
                [f"Results no branch tests ({len(result.untested)})", ""])
            group.setExpanded(True)
            bold = group.font(0)
            bold.setBold(True)
            group.setFont(0, bold)
            for call in result.untested:
                item = QTreeWidgetItem(group, [call.api, hex(call.call_site)])
                item.setData(0, Qt.UserRole, call.call_site)
                if call.fate:
                    item.setToolTip(0, "; ".join(call.fate))

        self.apply_column_width()
        self.set_status(
            f"{func.name}: {len(result.guards)} branch(es) on an API result "
            f"from {result.call_sites} call site(s)"
            + (f", {len(result.untested)} result(s) untested." if result.untested
               else ".")
        )


class ApiHunterSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        # Sidebar icons are 28x28 points; 56x56 pixels for HiDPI. Grayscale,
        # white = the shape. Binary Ninja makes it theme aware automatically.
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 48))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "A")
        p.end()
        SidebarWidgetType.__init__(self, icon, WIDGET_NAME)

    def createWidget(self, frame, data):
        return ApiHunterSidebarWidget(WIDGET_NAME, frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.LeftContent

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext


def register():
    Sidebar.addSidebarWidgetType(ApiHunterSidebarWidgetType())
    log_info("API Xref Hunter: sidebar widget registered.")
