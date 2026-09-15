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

from . import core

WIDGET_NAME = "API Hunter"


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
            log_error(f"API Xref Hunter: scan failed: {exc}")
            execute_on_main_thread(lambda: self.widget.set_status(f"Failed: {exc}"))
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

        self.reach_btn = QPushButton("Reaches?")
        self.reach_btn.setToolTip(
            "Does the function at the current offset ever reach a matching API?"
        )
        self.reach_btn.clicked.connect(self.check_reach)
        row.addWidget(self.reach_btn)
        layout.addLayout(row)

        # --- results
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Function", "Address"])
        self.tree.setColumnCount(2)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemDoubleClicked.connect(self._item_activated)
        layout.addWidget(self.tree, 1)

        self.status = QLabel("Enter API names or pick a preset, then Scan.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.setLayout(layout)

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
        if self.data is None:
            self.set_status("No binary view active.")
            return
        pats = self._collect_patterns()
        if not pats:
            self.set_status("No patterns given.")
            return
        funcs = self.data.get_functions_containing(self._current_offset) or []
        if not funcs:
            self.set_status("Cursor is not inside a function.")
            return
        self.set_status("Checking reachability…")
        _ReachTask(
            self, self.data, funcs[0], pats, self.mode.currentText(),
            max(self.depth.value(), 8), True,
        ).start()

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
        self.set_status(f"Shortest chain: {len(chain) - 1} hop(s).")


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
