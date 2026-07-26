"""Side-by-side Split View for Vodou.

Split View shows two open tabs next to each other inside one window. The design
goal is that it *borrows* existing WebView widgets rather than creating new ones:
the very same QWebEngineView objects are reparented into the split panes and,
on exit, handed straight back to the tab stack. Because the widgets are reused —
never recreated or reloaded — every bit of a tab's live state survives entering,
swapping, and leaving Split View: navigation history, scroll position, form
data, focus, JavaScript state, and media playback all carry over untouched.

Ownership split (so this file stays a dumb, reusable *view*):
  * This module never decides *which* tabs go where and never destroys a view.
    It only mounts views the controller hands it, and on unmount reparents them
    to None so the controller can put them back in the tab strip.
  * The controller (BrowserWindow) drives everything else — the tab strip,
    the address bar, sessions — through the signals below.

Extensibility: the layout is a QSplitter with a list of panes, so a future
horizontal split or a third pane is a matter of constructing SplitView with a
different orientation / pane count and handing it more views; nothing here
hard-codes "exactly two".
"""

from __future__ import annotations

from PyQt6.QtCore import QEvent, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSplitter,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

# Carried in a drag started from the tab strip so a pane knows it's a tab drop
# (and which tab). The controller fills in the payload; panes only check type.
TAB_MIME = "application/x-vodou-tab"


class _Pane(QFrame):
    """One side of the split: a slim header (title + controls) above a holder
    that a borrowed WebView is dropped into. Focused panes get an accent frame
    so it's always clear which side the address bar and shortcuts act on."""

    focus_requested = pyqtSignal(object)      # -> the WebView in this pane
    replace_requested = pyqtSignal(object)    # -> this _Pane (controller picks)
    return_requested = pyqtSignal(object)     # -> this _Pane (send back to strip)
    tab_dropped = pyqtSignal(object, int)     # -> (this _Pane, source tab index)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("splitPane")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setAcceptDrops(True)
        self._view: QWidget | None = None
        self._focused = False
        self._accent = QColor("#4c8bf5")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(2, 2, 2, 2)
        outer.setSpacing(0)

        header = QFrame()
        header.setObjectName("splitPaneHeader")
        header.setFixedHeight(26)
        header.installEventFilter(self)          # click header -> focus pane
        hb = QHBoxLayout(header)
        hb.setContentsMargins(8, 0, 4, 0)
        hb.setSpacing(2)

        self._title = QLabel("—")
        self._title.setObjectName("splitPaneTitle")
        self._title.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)

        self._replace_btn = QToolButton()
        self._replace_btn.setObjectName("splitPaneBtn")
        self._replace_btn.setText("⇄")
        self._replace_btn.setToolTip("Show a different tab in this pane")
        self._replace_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._replace_btn.clicked.connect(
            lambda: self.replace_requested.emit(self))

        self._return_btn = QToolButton()
        self._return_btn.setObjectName("splitPaneBtn")
        self._return_btn.setText("⤢")
        self._return_btn.setToolTip("Return this tab to the tab strip")
        self._return_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._return_btn.clicked.connect(
            lambda: self.return_requested.emit(self))

        hb.addWidget(self._title, 1)
        hb.addWidget(self._replace_btn)
        hb.addWidget(self._return_btn)

        self._holder = QWidget()
        self._holder.setObjectName("splitPaneHolder")
        hv = QVBoxLayout(self._holder)
        hv.setContentsMargins(0, 0, 0, 0)
        hv.setSpacing(0)
        self._holder_layout = hv

        outer.addWidget(header)
        outer.addWidget(self._holder, 1)
        self._repaint_frame()

    # -- borrowed view ----------------------------------------------------
    @property
    def view(self) -> QWidget | None:
        return self._view

    def set_view(self, view: QWidget | None) -> None:
        """Mount a WebView (reparents it in). Passing None clears the pane."""
        if self._view is view:
            return
        if self._view is not None:
            self._holder_layout.removeWidget(self._view)
        self._view = view
        if view is not None:
            self._holder_layout.addWidget(view)
            view.show()

    def take_view(self) -> QWidget | None:
        """Detach the WebView without deleting it and return it, so the caller
        can reparent it elsewhere (the tab stack). Preserves all page state."""
        view = self._view
        if view is not None:
            self._holder_layout.removeWidget(view)
            view.setParent(None)
        self._view = None
        return view

    def set_title(self, text: str) -> None:
        self._title.setText(text or "—")
        self._title.setToolTip(text or "")

    # -- focus visuals ----------------------------------------------------
    def set_accent(self, color: QColor) -> None:
        self._accent = QColor(color)
        self._repaint_frame()

    def set_focused(self, on: bool) -> None:
        if on == self._focused:
            return
        self._focused = on
        self._repaint_frame()

    def _repaint_frame(self) -> None:
        if self._focused:
            c = self._accent
            self.setStyleSheet(
                f"#splitPane {{ border: 2px solid "
                f"rgba({c.red()},{c.green()},{c.blue()},220); "
                f"border-radius: 4px; }}")
        else:
            self.setStyleSheet(
                "#splitPane { border: 2px solid rgba(128,128,128,60); "
                "border-radius: 4px; }")

    # -- events -----------------------------------------------------------
    def eventFilter(self, obj, event) -> bool:
        if (event.type() == QEvent.Type.MouseButtonPress
                and self._view is not None):
            self.focus_requested.emit(self._view)
        return super().eventFilter(obj, event)

    def mousePressEvent(self, event) -> None:
        if self._view is not None:
            self.focus_requested.emit(self._view)
        super().mousePressEvent(event)

    # -- drag & drop: accept a tab dragged out of the strip ---------------
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasFormat(TAB_MIME):
            event.acceptProposedAction()
            self.set_focused(True)          # highlight the drop target
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:
        # Drop the drop-target highlight; the controller re-asserts the real
        # focused pane on its next focus signal.
        if self._view is not None:
            self.focus_requested.emit(self._view)
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:
        data = event.mimeData()
        if not data.hasFormat(TAB_MIME):
            event.ignore()
            return
        try:
            src_index = int(bytes(data.data(TAB_MIME)).decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            event.ignore()
            return
        event.acceptProposedAction()
        self.tab_dropped.emit(self, src_index)


class SplitView(QWidget):
    """A row (or column) of panes that host borrowed WebViews side by side.

    The controller uses it like this:
        sv = SplitView()
        sv.mount([view_left, view_right])      # reparents them in
        ... user interacts ...
        views = sv.unmount()                   # hands them back, in order

    Signals let the controller own all the real decisions.
    """

    exit_requested = pyqtSignal()
    swap_requested = pyqtSignal()
    focus_changed = pyqtSignal(object)        # -> WebView that gained focus
    replace_requested = pyqtSignal(object)    # -> _Pane to refill
    return_requested = pyqtSignal(object)     # -> WebView to send to the strip
    tab_dropped = pyqtSignal(object, int)     # -> (_Pane, source tab index)

    def __init__(self, pane_count: int = 2,
                 orientation: Qt.Orientation = Qt.Orientation.Horizontal,
                 parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("splitViewRoot")
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # -- control strip --------------------------------------------------
        bar = QFrame()
        bar.setObjectName("splitBar")
        bar.setFixedHeight(30)
        bb = QHBoxLayout(bar)
        bb.setContentsMargins(10, 0, 8, 0)
        bb.setSpacing(6)
        tag = QLabel("Split view")
        tag.setObjectName("splitBarTag")
        self._swap_btn = QToolButton()
        self._swap_btn.setObjectName("splitBarBtn")
        self._swap_btn.setText("⇄  Swap sides")
        self._swap_btn.setToolTip("Swap the left and right tabs (no reload)")
        self._swap_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._swap_btn.clicked.connect(self.swap_requested.emit)
        self._exit_btn = QToolButton()
        self._exit_btn.setObjectName("splitBarBtn")
        self._exit_btn.setText("✕  Exit split")
        self._exit_btn.setToolTip("Close split view and return both tabs to "
                                  "the strip")
        self._exit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._exit_btn.clicked.connect(self.exit_requested.emit)
        bb.addWidget(tag)
        bb.addStretch(1)
        bb.addWidget(self._swap_btn)
        bb.addWidget(self._exit_btn)

        # -- panes ----------------------------------------------------------
        self._splitter = QSplitter(orientation)
        self._splitter.setObjectName("splitViewSplitter")
        self._splitter.setChildrenCollapsible(False)
        self._splitter.setHandleWidth(6)
        self._panes: list[_Pane] = []
        for _ in range(max(2, pane_count)):
            pane = _Pane()
            pane.focus_requested.connect(self._on_pane_focus)
            pane.replace_requested.connect(self.replace_requested.emit)
            pane.return_requested.connect(self._on_pane_return)
            pane.tab_dropped.connect(self.tab_dropped.emit)
            self._panes.append(pane)
            self._splitter.addWidget(pane)

        root.addWidget(bar)
        root.addWidget(self._splitter, 1)

        self._focused_view: QWidget | None = None
        self._saved_sizes: list[int] | None = None

    # -- mount / unmount --------------------------------------------------
    def mount(self, views: list[QWidget]) -> None:
        """Place the given views into the panes, left to right."""
        for pane, view in zip(self._panes, views):
            pane.set_view(view)
        # Balance the panes on first mount, or restore the remembered ratio.
        if self._saved_sizes and len(self._saved_sizes) == len(self._panes):
            self._splitter.setSizes(self._saved_sizes)
        else:
            self._splitter.setSizes([1] * len(self._panes))
        if views:
            self.set_focused_view(views[0])

    def unmount(self) -> list[QWidget]:
        """Detach every view (without deleting) and return them in pane order.
        Remembers the divider position for the next time Split View opens."""
        self._saved_sizes = self._splitter.sizes()
        views: list[QWidget] = []
        for pane in self._panes:
            v = pane.take_view()
            if v is not None:
                views.append(v)
        self._focused_view = None
        return views

    # -- pane / view helpers ----------------------------------------------
    @property
    def panes(self) -> list[_Pane]:
        return list(self._panes)

    def views(self) -> list[QWidget]:
        return [p.view for p in self._panes if p.view is not None]

    def pane_of_view(self, view: QWidget) -> _Pane | None:
        for pane in self._panes:
            if pane.view is view:
                return pane
        return None

    def other_pane(self, pane: _Pane) -> _Pane | None:
        for p in self._panes:
            if p is not pane:
                return p
        return None

    @property
    def focused_view(self) -> QWidget | None:
        return self._focused_view

    def set_view_in_pane(self, pane: _Pane, view: QWidget | None) -> None:
        pane.set_view(view)
        if view is not None:
            self.set_focused_view(view)

    def swap(self) -> None:
        """Exchange the two panes' views with no reload, keeping the divider
        ratio and the currently focused tab focused."""
        if len(self._panes) != 2:
            return
        left, right = self._panes
        sizes = self._splitter.sizes()
        lv = left.take_view()
        rv = right.take_view()
        left.set_view(rv)
        right.set_view(lv)
        self._splitter.setSizes(sizes)
        # Keep whichever tab was focused focused, now on its new side.
        if self._focused_view is not None:
            self._reassert_focus_frames()

    def set_titles(self, titles: dict) -> None:
        """titles: {view: text}. Unknown views are ignored."""
        for pane in self._panes:
            if pane.view in titles:
                pane.set_title(titles[pane.view])

    def set_title_for(self, view: QWidget, text: str) -> None:
        pane = self.pane_of_view(view)
        if pane is not None:
            pane.set_title(text)

    def set_accent(self, color: QColor) -> None:
        for pane in self._panes:
            pane.set_accent(color)

    # -- focus ------------------------------------------------------------
    def set_focused_view(self, view: QWidget | None) -> None:
        self._focused_view = view
        self._reassert_focus_frames()
        if view is not None:
            self.focus_changed.emit(view)

    def _reassert_focus_frames(self) -> None:
        for pane in self._panes:
            pane.set_focused(pane.view is self._focused_view
                             and pane.view is not None)

    def _on_pane_focus(self, view) -> None:
        if view is not None and view is not self._focused_view:
            self.set_focused_view(view)
        else:
            self._reassert_focus_frames()

    def _on_pane_return(self, pane: _Pane) -> None:
        if pane.view is not None:
            self.return_requested.emit(pane.view)
