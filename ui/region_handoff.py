"""Cancelable frozen-screen selection and explicit one-use handoff UI."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Sequence

from PyQt6.QtCore import (
    QPoint,
    QRect,
    QTimer,
    Qt,
    pyqtSignal,
)
from PyQt6.QtGui import (
    QCloseEvent,
    QColor,
    QKeyEvent,
    QMouseEvent,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from config import cfg
from handoff.image_capture import (
    build_selected_image,
    capture_desktop_bundle,
)
from handoff.models import (
    HandoffDataClass,
    HandoffDestination,
    HandoffSelectionError,
    PhysicalRegion,
    SelectionShape,
    build_handoff_intent,
    build_handoff_review,
)
from handoff.selection import (
    MAX_LASSO_POINTS,
    LassoPoint,
    RegionCaptureBundle,
    RegionSelectionCoordinator,
    RegionSelectionFailure,
    TransientMonitorFrame,
    TransientSelectionPayload,
    logical_points_to_physical,
    logical_region_to_physical,
)
from handoff.routing import ReviewedRegionHandoff
from privacy_controls import screen_capture_allowed
from screen.topology import (
    MonitorDescriptor,
    Rect,
    discover_desktop_topology,
)
from turn_coordinator import TurnCoordinator, TurnSession


SELECTION_TIMEOUT_MS = 60_000
MIN_RECTANGLE_LOGICAL_PIXELS = 4
MAX_PURPOSE_CHARACTERS = 2_000


class RegionSelectionModeDialog(QDialog):
    """Require a visible mode choice before any screen capture."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.selection_shape: SelectionShape | None = None
        self.setWindowTitle("Select a screen region")
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(True)
        self.setMinimumWidth(440)
        self.setStyleSheet(_DIALOG_STYLE)
        layout = QVBoxLayout(self)
        title = _plain_label(
            "What shape do you want to select?",
            heading=True,
        )
        layout.addWidget(title)
        explanation = _plain_label(
            "Clicky will capture a frozen local preview only after you "
            "choose. Escape cancels. Nothing is sent until you review the "
            "exact crop, destination, and purpose."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        buttons = QHBoxLayout()
        rectangle = QPushButton("Rectangle")
        rectangle.clicked.connect(
            lambda: self._choose(SelectionShape.RECTANGLE)
        )
        circle = QPushButton("Freehand circle")
        circle.clicked.connect(
            lambda: self._choose(SelectionShape.ELLIPSE_MASK)
        )
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        for button in (rectangle, circle, cancel):
            button.setAutoDefault(False)
            button.setDefault(False)
            buttons.addWidget(button)
        layout.addLayout(buttons)

    def _choose(self, shape: SelectionShape) -> None:
        self.selection_shape = shape
        self.accept()


class RegionSelectionOverlay(QDialog):
    """One input-consuming overlay backed by one immutable captured frame."""

    selection_started = pyqtSignal(object)
    rectangle_selected = pyqtSignal(object, object)
    lasso_selected = pyqtSignal(object, object)
    cancel_requested = pyqtSignal()
    selection_failed = pyqtSignal(str)

    def __init__(
        self,
        frame: TransientMonitorFrame,
        shape: SelectionShape,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(frame, TransientMonitorFrame):
            raise TypeError("Region overlay frame is invalid")
        if not isinstance(shape, SelectionShape):
            raise TypeError("Region overlay shape is invalid")
        self._frame = frame
        self._shape = shape
        self._start: QPoint | None = None
        self._current: QPoint | None = None
        self._points: list[QPoint] = []
        self._consumed = False
        self._background = QPixmap()
        if not self._background.loadFromData(bytes(frame.jpeg_bytes), "JPEG"):
            raise HandoffSelectionError(
                "Frozen monitor preview could not be decoded"
            )
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
        )
        self.setModal(False)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.CrossCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        logical = frame.monitor.logical
        self.setGeometry(
            logical.left,
            logical.top,
            logical.width,
            logical.height,
        )

    @property
    def monitor(self) -> MonitorDescriptor:
        return self._frame.monitor

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.drawPixmap(self.rect(), self._background)
        painter.fillRect(self.rect(), QColor(5, 10, 20, 75))
        pen = QPen(QColor("#52d7ff"), 3)
        painter.setPen(pen)
        if (
            self._shape is SelectionShape.RECTANGLE
            and self._start is not None
            and self._current is not None
        ):
            painter.drawRect(
                QRect(self._start, self._current).normalized()
            )
        elif len(self._points) >= 2:
            path = QPainterPath()
            path.moveTo(self._points[0])
            for point in self._points[1:]:
                path.lineTo(point)
            painter.drawPath(path)
        painter.setPen(QColor("#ffffff"))
        instruction = (
            "Drag a rectangle"
            if self._shape is SelectionShape.RECTANGLE
            else "Draw one closed freehand circle"
        )
        painter.drawText(
            QRect(24, 20, max(1, self.width() - 48), 80),
            Qt.AlignmentFlag.AlignLeft
            | Qt.AlignmentFlag.AlignTop,
            f"{instruction} on this screen\nEscape cancels • 60-second limit",
        )

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if (
            self._consumed
            or event.button() is not Qt.MouseButton.LeftButton
        ):
            event.accept()
            return
        point = event.position().toPoint()
        self._start = point
        self._current = point
        self._points = [point]
        self.selection_started.emit(self)
        self.update()
        event.accept()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._consumed or self._start is None:
            event.accept()
            return
        point = event.position().toPoint()
        self._current = point
        if (
            self._shape is SelectionShape.ELLIPSE_MASK
            and (
                not self._points
                or (point - self._points[-1]).manhattanLength() >= 3
            )
        ):
            if len(self._points) >= MAX_LASSO_POINTS:
                self._consumed = True
                self.selection_failed.emit(
                    "Freehand selection point limit exceeded"
                )
                event.accept()
                return
            self._points.append(point)
        self.update()
        event.accept()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if (
            self._consumed
            or self._start is None
            or event.button() is not Qt.MouseButton.LeftButton
        ):
            event.accept()
            return
        self._consumed = True
        self._current = event.position().toPoint()
        try:
            if self._shape is SelectionShape.RECTANGLE:
                selected = QRect(
                    self._start,
                    self._current,
                ).normalized()
                if (
                    selected.width() < MIN_RECTANGLE_LOGICAL_PIXELS
                    or selected.height() < MIN_RECTANGLE_LOGICAL_PIXELS
                ):
                    raise HandoffSelectionError(
                        "Selected rectangle is too small"
                    )
                global_top_left = self.mapToGlobal(selected.topLeft())
                physical = logical_region_to_physical(
                    self.monitor,
                    Rect(
                        global_top_left.x(),
                        global_top_left.y(),
                        selected.width(),
                        selected.height(),
                    ),
                )
                self.rectangle_selected.emit(self.monitor, physical)
            else:
                end = self._current
                if (
                    not self._points
                    or end != self._points[-1]
                ):
                    self._points.append(end)
                global_points = tuple(
                    self.mapToGlobal(point)
                    for point in self._points
                )
                physical_points = logical_points_to_physical(
                    self.monitor,
                    (
                        (point.x(), point.y())
                        for point in global_points
                    ),
                )
                self.lasso_selected.emit(
                    self.monitor,
                    physical_points,
                )
        except Exception as exc:
            self.selection_failed.emit(str(exc))
        self.update()
        event.accept()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.cancel_requested.emit()
            event.accept()
            return
        event.accept()

    def closeEvent(self, event: QCloseEvent) -> None:
        event.accept()


class RegionHandoffPreview(QDialog):
    """Show exact selected bytes and require an explicit destination."""

    review_requested = pyqtSignal(object, str)

    def __init__(
        self,
        payload: TransientSelectionPayload,
        available_destinations: tuple[HandoffDestination, ...],
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(payload, TransientSelectionPayload):
            raise TypeError("Region handoff preview is invalid")
        self._payload = payload
        if (
            not isinstance(available_destinations, tuple)
            or not available_destinations
            or any(
                not isinstance(item, HandoffDestination)
                for item in available_destinations
            )
            or len(set(available_destinations))
            != len(available_destinations)
        ):
            raise TypeError(
                "Region handoff destinations are invalid"
            )
        self.setWindowTitle("Review selected screen region")
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setModal(False)
        self.setMinimumSize(560, 480)
        self.setStyleSheet(_DIALOG_STYLE)
        layout = QVBoxLayout(self)
        layout.addWidget(
            _plain_label(
                "Review the exact selected pixels",
                heading=True,
            )
        )
        status = _plain_label(
            "Nothing has been sent, inserted, or used by a task. "
            "Approve only after checking the exact destination and pixels."
        )
        status.setWordWrap(True)
        layout.addWidget(status)
        pixmap = QPixmap()
        if not pixmap.loadFromData(
            bytes(payload.image.content),
            "JPEG",
        ):
            raise HandoffSelectionError(
                "Selected image preview could not be decoded"
            )
        image = QLabel()
        image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        image.setStyleSheet(
            "background: #080d16; border: 1px solid #38516f;"
        )
        image.setPixmap(
            pixmap.scaled(
                520,
                280,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
        )
        image.setToolTip(
            f"Exact payload: {pixmap.width()} × {pixmap.height()} pixels"
        )
        layout.addWidget(image, stretch=1)
        self._destination = QComboBox()
        self._destination.addItem("Choose a destination…", None)
        labels = {
            HandoffDestination.TUTOR_CONTEXT: "Tutor context",
            HandoffDestination.COMPOSE_PREVIEW: "Compose preview",
            HandoffDestination.TASK_AGENT_NEW_RUN: (
                "New Task Agent run"
            ),
        }
        for destination in available_destinations:
            self._destination.addItem(
                labels[destination],
                destination,
            )
        layout.addWidget(self._destination)
        data_class = _plain_label(
            "Data class: selected screen pixels. Approval sends only this "
            "reviewed crop to the chosen destination for one use."
        )
        data_class.setWordWrap(True)
        layout.addWidget(data_class)
        self._purpose = QLineEdit()
        self._purpose.setMaxLength(MAX_PURPOSE_CHARACTERS)
        self._purpose.setPlaceholderText(
            "What should the destination use this region for?"
        )
        layout.addWidget(self._purpose)
        buttons = QHBoxLayout()
        cancel = QPushButton("Cancel and discard")
        cancel.setAutoDefault(False)
        cancel.setDefault(False)
        cancel.clicked.connect(self.reject)
        self._approve = QPushButton("Approve and route once")
        self._approve.setAutoDefault(False)
        self._approve.setDefault(False)
        self._approve.setEnabled(False)
        self._approve.clicked.connect(self._request_review)
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(self._approve)
        layout.addLayout(buttons)
        self._destination.currentIndexChanged.connect(
            self._update_approval
        )
        self._purpose.textChanged.connect(self._update_approval)

    def _update_approval(self, *_args) -> None:
        self._approve.setEnabled(
            isinstance(
                self._destination.currentData(),
                HandoffDestination,
            )
            and bool(self._purpose.text().strip())
        )

    def _request_review(self) -> None:
        destination = self._destination.currentData()
        purpose = self._purpose.text().strip()
        if (
            not isinstance(destination, HandoffDestination)
            or not purpose
        ):
            return
        self._approve.setEnabled(False)
        self.review_requested.emit(destination, purpose)

ModePicker = Callable[[], SelectionShape | None]
CaptureBundleFactory = Callable[..., RegionCaptureBundle]
TopologyProvider = Callable[[], Sequence[MonitorDescriptor]]


class QtRegionHandoffController(QDialog):
    """Own one capture, one selection, and one explicit preview review."""

    reviewed = pyqtSignal(object)
    failed = pyqtSignal(str)
    cancelled = pyqtSignal(str)

    def __init__(
        self,
        turns: TurnCoordinator,
        *,
        available_destinations: tuple[HandoffDestination, ...],
        clock: Callable[[], float] = time.monotonic,
        mode_picker: ModePicker | None = None,
        capture_factory: CaptureBundleFactory = capture_desktop_bundle,
        topology_provider: TopologyProvider = discover_desktop_topology,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(turns, TurnCoordinator):
            raise TypeError("Region handoff turn coordinator is invalid")
        for callback, label in (
            (clock, "clock"),
            (capture_factory, "capture factory"),
            (topology_provider, "topology provider"),
        ):
            if not callable(callback):
                raise TypeError(
                    f"Region handoff {label} is invalid"
                )
        if mode_picker is not None and not callable(mode_picker):
            raise TypeError("Region handoff mode picker is invalid")
        self._turns = turns
        self._clock = clock
        self._mode_picker = mode_picker
        self._capture_factory = capture_factory
        self._topology_provider = topology_provider
        if (
            not isinstance(available_destinations, tuple)
            or not available_destinations
            or any(
                not isinstance(item, HandoffDestination)
                for item in available_destinations
            )
            or len(set(available_destinations))
            != len(available_destinations)
        ):
            raise TypeError(
                "Region handoff destinations are invalid"
            )
        self._available_destinations = available_destinations
        self._session: TurnSession | None = None
        self._generation: str | None = None
        self._flow: RegionSelectionCoordinator | None = None
        self._overlays: list[RegionSelectionOverlay] = []
        self._preview: RegionHandoffPreview | None = None
        self._cancel_reason: RegionSelectionFailure | None = None
        self._expiry = QTimer(self)
        self._expiry.setSingleShot(True)
        self._expiry.timeout.connect(self._expire)
        self.hide()

    @property
    def active(self) -> bool:
        return bool(
            self._session is not None
            and self._turns.is_current(self._session)
        )

    def start(self) -> bool:
        if not screen_capture_allowed(cfg):
            self.failed.emit(
                "Enable Screen capture in Privacy permissions first."
            )
            return False
        shape = self._pick_mode()
        if shape is None:
            self.cancelled.emit("Selection cancelled before capture.")
            return False
        session = self._turns.start_processing()
        if session is None:
            self.failed.emit(
                "Finish or stop the current Clicky turn before selecting."
            )
            return False
        self._session = session
        self._cancel_reason = None
        self._generation = f"capture-{secrets.token_hex(16)}"
        self._turns.bind_cancel(
            session,
            "region-handoff",
            self._cancel_from_turn,
        )
        try:
            bundle = self._capture_factory(
                generation=self._generation,
                clock=self._clock,
            )
            self._flow = RegionSelectionCoordinator(
                bundle,
                image_builder=build_selected_image,
                topology_provider=self._topology_provider,
                generation_provider=lambda: self._generation,
                clock=self._clock,
                selection_id_factory=lambda: (
                    f"selection-{secrets.token_hex(16)}"
                ),
            )
            self._show_overlays(bundle.frames, shape)
            self._expiry.start(SELECTION_TIMEOUT_MS)
            return True
        except Exception as exc:
            self._fail(str(exc))
            return False

    def cancel(
        self,
        reason: RegionSelectionFailure = (
            RegionSelectionFailure.USER_CANCELLED
        ),
    ) -> bool:
        if not isinstance(reason, RegionSelectionFailure):
            raise TypeError("Region handoff cancellation is invalid")
        session = self._session
        if session is None:
            return False
        self._cancel_reason = reason
        if self._turns.cancel(session):
            return True
        self._cancel_from_turn()
        return False

    def _pick_mode(self) -> SelectionShape | None:
        if self._mode_picker is not None:
            chosen = self._mode_picker()
            if chosen is not None and not isinstance(
                chosen,
                SelectionShape,
            ):
                raise TypeError("Region handoff mode is invalid")
            return chosen
        dialog = RegionSelectionModeDialog()
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.selection_shape

    def _show_overlays(
        self,
        frames: tuple[TransientMonitorFrame, ...],
        shape: SelectionShape,
    ) -> None:
        self._close_overlays()
        for frame in frames:
            overlay = RegionSelectionOverlay(frame, shape)
            overlay.selection_started.connect(
                self._selection_started
            )
            overlay.rectangle_selected.connect(
                self._rectangle_selected
            )
            overlay.lasso_selected.connect(self._lasso_selected)
            overlay.cancel_requested.connect(self.cancel)
            overlay.selection_failed.connect(self._fail)
            self._overlays.append(overlay)
        for overlay in self._overlays:
            overlay.show()
            overlay.raise_()
        if self._overlays:
            self._overlays[0].activateWindow()
            self._overlays[0].setFocus(
                Qt.FocusReason.ActiveWindowFocusReason
            )

    def _selection_started(
        self,
        selected_overlay: RegionSelectionOverlay,
    ) -> None:
        for overlay in self._overlays:
            if overlay is not selected_overlay:
                overlay.setEnabled(False)

    def _rectangle_selected(
        self,
        monitor: MonitorDescriptor,
        region: PhysicalRegion,
    ) -> None:
        flow = self._flow
        if flow is None:
            return
        try:
            payload = flow.select_rectangle(
                monitor.stable_id,
                region,
            )
            self._open_preview(payload)
        except Exception as exc:
            self._fail(str(exc))

    def _lasso_selected(
        self,
        monitor: MonitorDescriptor,
        points: tuple[LassoPoint, ...],
    ) -> None:
        flow = self._flow
        if flow is None:
            return
        try:
            payload = flow.select_lasso(
                monitor.stable_id,
                points,
            )
            self._open_preview(payload)
        except Exception as exc:
            self._fail(str(exc))

    def _open_preview(
        self,
        payload: TransientSelectionPayload,
    ) -> None:
        self._close_overlays()
        preview = RegionHandoffPreview(
            payload,
            self._available_destinations,
        )
        preview.review_requested.connect(self._approve)
        preview.rejected.connect(self.cancel)
        self._preview = preview
        preview.show()
        preview.raise_()
        preview.activateWindow()

    def _approve(
        self,
        destination: HandoffDestination,
        purpose: str,
    ) -> None:
        flow = self._flow
        session = self._session
        if flow is None or session is None:
            return
        try:
            flow.validate_for_review()
            payload = flow.payload
            if payload is None:
                raise HandoffSelectionError(
                    "Selected pixels are unavailable"
                )
            now = float(self._clock())
            intent = build_handoff_intent(
                payload.selection,
                intent_id=f"intent-{secrets.token_hex(16)}",
                destination=destination,
                data_class=HandoffDataClass.SCREEN_PIXELS,
                purpose=purpose,
                created_at=now,
                expires_at=payload.selection.expires_at,
            )
            review = build_handoff_review(intent)
            completed = flow.complete()
            result = ReviewedRegionHandoff(
                completed,
                intent,
                review,
            )
            self._expiry.stop()
            self._close_preview()
            if not self._turns.complete(session):
                result.wipe()
                self._reset()
                return
            self._reset()
            self.reviewed.emit(result)
        except Exception as exc:
            self._fail(str(exc))

    def _expire(self) -> None:
        self._cancel_reason = RegionSelectionFailure.EXPIRED
        self.cancel(RegionSelectionFailure.EXPIRED)

    def _fail(self, message: str) -> None:
        flow = self._flow
        if (
            flow is not None
            and flow.state.value not in {
                "completed",
                "cancelled",
                "failed",
            }
        ):
            flow.fail(RegionSelectionFailure.INVALID_SELECTION)
        session = self._session
        self._close_all()
        if session is not None:
            self._turns.complete(session)
        self._reset()
        self.failed.emit(
            message or "Screen region selection failed closed."
        )

    def _cancel_from_turn(self) -> None:
        reason = self._cancel_reason or (
            RegionSelectionFailure.SUPERSEDED
        )
        flow = self._flow
        if flow is not None:
            flow.cancel(reason)
        self._close_all()
        self._reset()
        self.cancelled.emit(
            {
                RegionSelectionFailure.EXPIRED: (
                    "Screen region selection expired and was discarded."
                ),
                RegionSelectionFailure.SUPERSEDED: (
                    "Screen region selection was replaced and discarded."
                ),
            }.get(
                reason,
                "Screen region selection was cancelled and discarded.",
            )
        )

    def _close_all(self) -> None:
        self._expiry.stop()
        self._close_overlays()
        self._close_preview()

    def _close_overlays(self) -> None:
        overlays, self._overlays = self._overlays, []
        for overlay in overlays:
            overlay.hide()
            overlay.close()
            overlay.deleteLater()

    def _close_preview(self) -> None:
        preview, self._preview = self._preview, None
        if preview is not None:
            preview.blockSignals(True)
            preview.hide()
            preview.deleteLater()

    def _reset(self) -> None:
        self._session = None
        self._generation = None
        self._flow = None
        self._cancel_reason = None


def _plain_label(text: str, *, heading: bool = False) -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    if heading:
        label.setStyleSheet(
            "font-size: 16px; font-weight: 600; color: #ffffff;"
        )
    return label


_DIALOG_STYLE = (
    "QDialog { background: #101827; color: #eef3ff; }"
    "QLabel { color: #eef3ff; background: transparent; }"
    "QPushButton, QComboBox, QLineEdit { background: #263b61; "
    "color: #eef3ff; border: 1px solid #4e6a9b; border-radius: 6px; "
    "padding: 8px 11px; }"
    "QPushButton:hover { background: #315080; }"
    "QPushButton:disabled { color: #8090aa; background: #182338; }"
)


__all__ = [
    "QtRegionHandoffController",
    "RegionHandoffPreview",
    "RegionSelectionModeDialog",
    "RegionSelectionOverlay",
    "ReviewedRegionHandoff",
]
