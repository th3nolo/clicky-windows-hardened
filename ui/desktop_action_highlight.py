"""Non-activating, click-through highlight for an exact desktop target."""

from __future__ import annotations

import math
import time
from typing import Callable

from PyQt6.QtCore import QRect, QTimer, Qt, pyqtSlot
from PyQt6.QtWidgets import QApplication, QLabel, QWidget

from automation.models import DesktopBounds
from automation.review import DesktopHighlightRequest
from screen.topology import (
    MonitorDescriptor,
    MonitorTopologyError,
    discover_desktop_topology,
)


LogicalBoundsRouter = Callable[[DesktopBounds], QRect]


def _overlay_flags() -> Qt.WindowType:
    return (
        Qt.WindowType.FramelessWindowHint
        | Qt.WindowType.WindowStaysOnTopHint
        | Qt.WindowType.Tool
        | Qt.WindowType.WindowTransparentForInput
        | Qt.WindowType.WindowDoesNotAcceptFocus
    )


class _TargetFrame(QWidget):
    def __init__(self) -> None:
        super().__init__(None)
        self.setWindowFlags(_overlay_flags())
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setStyleSheet(
            "background: transparent;"
            "border: 3px solid #5bd6ff;"
            "border-radius: 5px;"
        )


class _TargetLabel(QLabel):
    def __init__(self) -> None:
        super().__init__(None)
        self.setWindowFlags(_overlay_flags())
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setStyleSheet(
            "background: #102033;"
            "color: #f4fbff;"
            "border: 1px solid #5bd6ff;"
            "border-radius: 5px;"
            "padding: 5px 8px;"
            "font-weight: 600;"
        )


class QtDesktopTargetHighlighter:
    """Show one inert target frame and local name without taking focus."""

    def __init__(
        self,
        *,
        router: LogicalBoundsRouter | None = None,
        clock=time.time,
    ) -> None:
        if router is not None and not callable(router):
            raise TypeError("Desktop highlight coordinate router is invalid")
        if not callable(clock):
            raise TypeError("Desktop highlight clock is invalid")
        self._router = router or physical_bounds_to_logical
        self._clock = clock
        self._frame: _TargetFrame | None = None
        self._label: _TargetLabel | None = None
        self._expiry: QTimer | None = None
        self._review_id: str | None = None

    @property
    def active_review_id(self) -> str | None:
        return self._review_id

    @pyqtSlot(object)
    def show(self, request: DesktopHighlightRequest) -> None:
        if not isinstance(request, DesktopHighlightRequest):
            raise TypeError("Desktop highlight request is invalid")
        application = QApplication.instance()
        if application is None:
            raise RuntimeError("Desktop highlighting requires QApplication")
        remaining = request.expires_at - float(self._clock())
        if not math.isfinite(remaining) or remaining <= 0:
            raise RuntimeError("Desktop highlight request is expired")
        logical = self._router(request.bounds)
        if logical.width() <= 0 or logical.height() <= 0:
            raise RuntimeError("Desktop highlight geometry is invalid")
        self._ensure_widgets()
        assert self._frame is not None
        assert self._label is not None
        assert self._expiry is not None
        self._review_id = request.review_id
        self._frame.setGeometry(logical)
        self._label.setText(
            f"Review only — {request.action.value}: {request.display_name}"
        )
        self._label.adjustSize()
        label_x = logical.left()
        label_y = logical.top() + 4
        self._label.move(label_x, label_y)
        self._frame.show()
        self._label.show()
        self._frame.raise_()
        self._label.raise_()
        self._expiry.start(max(1, min(round(remaining * 1_000), 30_000)))

    @pyqtSlot(str)
    def clear(self, review_id: str) -> None:
        if review_id != self._review_id:
            return
        self._clear_current()

    def is_active(self, review_id: str) -> bool:
        return bool(
            review_id == self._review_id
            and self._frame is not None
            and self._label is not None
            and self._frame.isVisible()
            and self._label.isVisible()
        )

    def close(self) -> None:
        self._clear_current()
        for widget in (self._frame, self._label):
            if widget is not None:
                widget.close()
                widget.deleteLater()
        self._frame = None
        self._label = None
        self._expiry = None

    def _ensure_widgets(self) -> None:
        if self._frame is not None:
            return
        self._frame = _TargetFrame()
        self._label = _TargetLabel()
        self._expiry = QTimer(self._frame)
        self._expiry.setSingleShot(True)
        self._expiry.timeout.connect(self._clear_current)

    def _clear_current(self) -> None:
        self._review_id = None
        if self._expiry is not None:
            self._expiry.stop()
        if self._frame is not None:
            self._frame.hide()
        if self._label is not None:
            self._label.clear()
            self._label.hide()


def physical_bounds_to_logical(bounds: DesktopBounds) -> QRect:
    """Route one physical UIA rectangle through exactly one monitor."""

    if not isinstance(bounds, DesktopBounds):
        raise TypeError("Desktop target bounds are invalid")
    monitors = discover_desktop_topology()
    monitor = _containing_monitor(bounds, monitors)
    scale_x = monitor.logical.width / monitor.physical.width
    scale_y = monitor.logical.height / monitor.physical.height
    left = monitor.logical.left + (
        bounds.left - monitor.physical.left
    ) * scale_x
    top = monitor.logical.top + (
        bounds.top - monitor.physical.top
    ) * scale_y
    right = left + bounds.width * scale_x
    bottom = top + bounds.height * scale_y
    logical_left = math.floor(left)
    logical_top = math.floor(top)
    logical_right = math.ceil(right)
    logical_bottom = math.ceil(bottom)
    return QRect(
        logical_left,
        logical_top,
        logical_right - logical_left,
        logical_bottom - logical_top,
    )


def _containing_monitor(
    bounds: DesktopBounds,
    monitors: list[MonitorDescriptor],
) -> MonitorDescriptor:
    right = bounds.left + bounds.width
    bottom = bounds.top + bounds.height
    matches = [
        monitor
        for monitor in monitors
        if (
            monitor.physical.left <= bounds.left
            and monitor.physical.top <= bounds.top
            and right <= monitor.physical.right
            and bottom <= monitor.physical.bottom
        )
    ]
    if len(matches) != 1:
        raise MonitorTopologyError(
            "desktop target does not fit exactly one monitor"
        )
    return matches[0]


__all__ = [
    "QtDesktopTargetHighlighter",
    "physical_bounds_to_logical",
]
