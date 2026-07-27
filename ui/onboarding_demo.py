"""Replayable, synthetic hotkey and pointing practice."""

from __future__ import annotations

import math
import threading

from PyQt6.QtCore import (
    QEasingCurve,
    QPointF,
    QRectF,
    Qt,
    QTimer,
    QVariantAnimation,
    pyqtSignal,
    pyqtSlot,
)
from PyQt6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


_active_lock = threading.Lock()
_active_demo: OnboardingDemoDialog | None = None


def display_hotkey(value: str) -> str:
    return " + ".join(part.strip().title() for part in value.split("+"))


class DemoCanvas(QWidget):
    """Local synthetic content; it never represents a captured screen."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(245)
        self._phase = "idle"
        self._point_progress = 0.0
        self._pulse = 0.0
        self._pulse_timer = QTimer(self)
        self._pulse_timer.timeout.connect(self._tick_pulse)
        self._pulse_timer.start(40)
        self._point_animation = QVariantAnimation(self)
        self._point_animation.setStartValue(0.0)
        self._point_animation.setEndValue(1.0)
        self._point_animation.setDuration(1500)
        self._point_animation.setEasingCurve(
            QEasingCurve.Type.InOutCubic
        )
        self._point_animation.valueChanged.connect(
            self._set_point_progress
        )

    def set_phase(self, phase: str) -> None:
        self._phase = phase
        if phase != "pointing":
            self._point_animation.stop()
            self._point_progress = 0.0
        self.update()

    def start_pointing(self, finished) -> None:
        self._phase = "pointing"
        self._point_progress = 0.0
        try:
            self._point_animation.finished.disconnect()
        except (TypeError, RuntimeError):
            pass
        self._point_animation.finished.connect(finished)
        self._point_animation.start()
        self.update()

    def reset(self) -> None:
        self._point_animation.stop()
        self._phase = "idle"
        self._point_progress = 0.0
        self.update()

    def _set_point_progress(self, value) -> None:
        self._point_progress = float(value)
        self.update()

    def _tick_pulse(self) -> None:
        self._pulse = (self._pulse + 0.12) % (2 * math.pi)
        if self._phase in {"listening", "thinking", "pointing", "complete"}:
            self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor("#151922"))

        card = QRectF(24, 22, max(200, self.width() - 48), self.height() - 44)
        painter.setPen(QPen(QColor("#30384a"), 1))
        painter.setBrush(QColor("#1d2330"))
        painter.drawRoundedRect(card, 16, 16)

        painter.setPen(QColor("#7f8ca8"))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(
            QRectF(card.left() + 22, card.top() + 16, 260, 24),
            Qt.AlignmentFlag.AlignLeft,
            "SYNTHETIC PRACTICE SCREEN",
        )
        painter.setPen(QColor("#eef2ff"))
        painter.setFont(QFont("Segoe UI", 15, QFont.Weight.DemiBold))
        painter.drawText(
            QRectF(card.left() + 22, card.top() + 49, 360, 34),
            Qt.AlignmentFlag.AlignLeft,
            "Learn without sharing your screen",
        )

        button = QRectF(
            card.right() - 205,
            card.bottom() - 76,
            172,
            42,
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#2f6feb"))
        painter.drawRoundedRect(button, 9, 9)
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", 10, QFont.Weight.DemiBold))
        painter.drawText(
            button,
            Qt.AlignmentFlag.AlignCenter,
            "Example button",
        )

        if self._phase == "listening":
            self._draw_listening(painter, card)
        elif self._phase == "thinking":
            self._draw_thinking(painter, card)
        elif self._phase in {"pointing", "complete"}:
            progress = (
                self._point_progress if self._phase == "pointing" else 1.0
            )
            self._draw_pointer(painter, card, button, progress)

    def _draw_listening(self, painter: QPainter, card: QRectF) -> None:
        painter.setPen(QPen(QColor("#4ade80"), 3))
        origin_x = card.left() + 38
        origin_y = card.bottom() - 54
        for index in range(7):
            height = 8 + 17 * abs(math.sin(self._pulse + index * 0.65))
            x = origin_x + index * 12
            painter.drawLine(
                QPointF(x, origin_y - height / 2),
                QPointF(x, origin_y + height / 2),
            )
        painter.setPen(QColor("#b8f7cf"))
        painter.drawText(
            QRectF(origin_x + 100, origin_y - 15, 180, 30),
            Qt.AlignmentFlag.AlignLeft,
            "Listening simulation…",
        )

    def _draw_thinking(self, painter: QPainter, card: QRectF) -> None:
        center = QPointF(card.left() + 62, card.bottom() - 54)
        painter.setPen(QPen(QColor("#5aa2ff"), 4))
        start = int(math.degrees(self._pulse) * 16)
        painter.drawArc(
            QRectF(center.x() - 16, center.y() - 16, 32, 32),
            start,
            210 * 16,
        )
        painter.setPen(QColor("#bfd9ff"))
        painter.drawText(
            QRectF(center.x() + 30, center.y() - 15, 180, 30),
            Qt.AlignmentFlag.AlignLeft,
            "Thinking…",
        )

    def _draw_pointer(
        self,
        painter: QPainter,
        card: QRectF,
        button: QRectF,
        progress: float,
    ) -> None:
        start = QPointF(card.left() + 58, card.bottom() - 54)
        end = button.center()
        arc = math.sin(progress * math.pi) * 42
        point = QPointF(
            start.x() + (end.x() - start.x()) * progress,
            start.y() + (end.y() - start.y()) * progress - arc,
        )
        halo = 21 + 4 * math.sin(self._pulse)
        painter.setPen(QPen(QColor("#77aaff"), 3))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(end, halo, halo)

        path = QPainterPath()
        path.moveTo(point.x(), point.y() - 14)
        path.lineTo(point.x() - 11, point.y() + 11)
        path.lineTo(point.x() + 11, point.y() + 11)
        path.closeSubpath()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#69a5ff"))
        painter.drawPath(path)

        if progress > 0.72:
            bubble = QRectF(
                max(card.left() + 20, end.x() - 176),
                end.y() - 73,
                160,
                34,
            )
            painter.setBrush(QColor("#f8faff"))
            painter.drawRoundedRect(bubble, 9, 9)
            painter.setPen(QColor("#182033"))
            painter.setFont(QFont("Segoe UI", 9, QFont.Weight.DemiBold))
            painter.drawText(
                bubble,
                Qt.AlignmentFlag.AlignCenter,
                "Clicky points right here",
            )


class OnboardingDemoDialog(QDialog):
    """Practice the real hotkey while all capability paths stay bypassed."""

    hotkey_pressed = pyqtSignal()
    hotkey_released = pyqtSignal()

    def __init__(self, hotkey: str, parent=None):
        super().__init__(parent)
        self.hotkey = hotkey
        self.phase = "idle"
        self._pressed = False
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("Practice Clicky")
        self.setMinimumSize(640, 500)
        self.setModal(False)
        self.setStyleSheet(
            "QDialog { background: #0e1014; color: #e8eaed; }"
            "QLabel { color: #e8eaed; }"
            "QLabel#title { font-size: 22px; font-weight: 700; }"
            "QLabel#privacy { color: #9aa5ba; font-size: 12px; }"
            "QLabel#state { color: #cfe0ff; font-size: 14px; font-weight: 600; }"
            "QPushButton { background: #2f6feb; color: white; border: none;"
            " padding: 9px 16px; border-radius: 8px; font-weight: 600; }"
            "QPushButton#secondary { background: transparent; color: #c8cfdd;"
            " border: 1px solid #343c4d; }"
        )
        self._thinking_timer = QTimer(self)
        self._thinking_timer.setSingleShot(True)
        self._thinking_timer.timeout.connect(self._start_pointing)
        self._auto_release_timer = QTimer(self)
        self._auto_release_timer.setSingleShot(True)
        self._auto_release_timer.timeout.connect(self._handle_hotkey_release)
        self.hotkey_pressed.connect(self._handle_hotkey_press)
        self.hotkey_released.connect(self._handle_hotkey_release)
        self._build_ui()
        self.reset_demo()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)

        title = QLabel("Practice push-to-talk and pointing")
        title.setObjectName("title")
        layout.addWidget(title)

        instructions = QLabel(
            f"Hold {display_hotkey(self.hotkey)}, say a pretend question, "
            "then release it. While this window is open, the hotkey controls "
            "only this practice."
        )
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        privacy = QLabel(
            "Synthetic content only: no microphone, screen capture, model, "
            "transcript, file, or network request is used."
        )
        privacy.setObjectName("privacy")
        privacy.setWordWrap(True)
        layout.addWidget(privacy)

        self.state_label = QLabel("")
        self.state_label.setObjectName("state")
        layout.addWidget(self.state_label)

        self.canvas = DemoCanvas()
        layout.addWidget(self.canvas, 1)

        row = QHBoxLayout()
        self.play_button = QPushButton("Play automatic demo")
        self.play_button.clicked.connect(self.play_automatic_demo)
        row.addWidget(self.play_button)
        self.replay_button = QPushButton("Reset and replay")
        self.replay_button.setObjectName("secondary")
        self.replay_button.clicked.connect(self.reset_demo)
        row.addWidget(self.replay_button)
        row.addStretch(1)
        close_button = QPushButton("Done")
        close_button.setObjectName("secondary")
        close_button.clicked.connect(self.close)
        row.addWidget(close_button)
        layout.addLayout(row)

    @pyqtSlot()
    def _handle_hotkey_press(self) -> None:
        if self._pressed:
            return
        self._thinking_timer.stop()
        self._auto_release_timer.stop()
        self._pressed = True
        self.phase = "listening"
        self.state_label.setText(
            "1. Listening — keep holding the hotkey"
        )
        self.canvas.set_phase("listening")

    @pyqtSlot()
    def _handle_hotkey_release(self) -> None:
        if not self._pressed:
            return
        self._pressed = False
        self.phase = "thinking"
        self.state_label.setText(
            "2. Thinking — the real app would transcribe and answer now"
        )
        self.canvas.set_phase("thinking")
        self._thinking_timer.start(650)

    @pyqtSlot()
    def _start_pointing(self) -> None:
        if self.phase != "thinking":
            return
        self.phase = "pointing"
        self.state_label.setText(
            "3. Speaking — Clicky flies to the local example target"
        )
        self.canvas.start_pointing(self._finish_demo)

    @pyqtSlot()
    def _finish_demo(self) -> None:
        if self.phase != "pointing":
            return
        self.phase = "complete"
        self.state_label.setText(
            "Complete — choose Reset and replay, or hold the hotkey again"
        )
        self.canvas.set_phase("complete")

    @pyqtSlot()
    def play_automatic_demo(self) -> None:
        self.reset_demo()
        self._handle_hotkey_press()
        self._auto_release_timer.start(850)

    @pyqtSlot()
    def reset_demo(self) -> None:
        self._thinking_timer.stop()
        self._auto_release_timer.stop()
        self._pressed = False
        self.phase = "idle"
        self.state_label.setText(
            f"Ready — hold {display_hotkey(self.hotkey)}"
        )
        self.canvas.reset()

    def closeEvent(self, event) -> None:
        self.reset_demo()
        _clear_active_demo(self)
        super().closeEvent(event)


def _clear_active_demo(dialog: OnboardingDemoDialog) -> None:
    global _active_demo
    with _active_lock:
        if _active_demo is dialog:
            _active_demo = None


def show_onboarding_demo(
    hotkey: str,
    parent=None,
) -> OnboardingDemoDialog:
    """Show or focus the single replayable practice window."""

    global _active_demo
    with _active_lock:
        dialog = _active_demo
        if dialog is None:
            dialog = OnboardingDemoDialog(hotkey, parent)
            dialog.destroyed.connect(
                lambda _object=None, current=dialog: _clear_active_demo(
                    current
                )
            )
            _active_demo = dialog
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    return dialog


def route_demo_hotkey_press() -> bool:
    """Return True when the hotkey was consumed by synthetic practice."""

    with _active_lock:
        dialog = _active_demo
    if dialog is None:
        return False
    try:
        dialog.hotkey_pressed.emit()
    except RuntimeError:
        _clear_active_demo(dialog)
        return False
    return True


def route_demo_hotkey_release() -> bool:
    """Return True when release was consumed by synthetic practice."""

    with _active_lock:
        dialog = _active_demo
    if dialog is None:
        return False
    try:
        dialog.hotkey_released.emit()
    except RuntimeError:
        _clear_active_demo(dialog)
        return False
    return True
