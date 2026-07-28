"""Bounded local-only meter for the already-selected microphone."""

from __future__ import annotations

import math
import secrets
import time
from typing import Callable

from PyQt6.QtCore import QTimer, Qt, pyqtSlot
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)


TEST_DURATION_SECONDS = 10.0


class MicrophoneTestDialog(QDialog):
    """Display RMS only; the owning audio service retains the hard boundary."""

    def __init__(
        self,
        selected_device: str,
        start_test: Callable[[str, float], bool],
        stop_test: Callable[[str | None, str], bool],
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not callable(start_test) or not callable(stop_test):
            raise TypeError("microphone test controls are required")
        self._start_test = start_test
        self._stop_test = stop_test
        self._active_id: str | None = None
        self._deadline = 0.0

        self.setWindowTitle("Test selected microphone")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setStyleSheet(
            "QDialog { background: #101319; color: #e8edf7; }"
            "QLabel { color: #e8edf7; }"
            "QProgressBar { background: #191f2a; color: #e8edf7;"
            " border: 1px solid #343d50; border-radius: 7px;"
            " text-align: center; min-height: 24px; }"
            "QProgressBar::chunk { background: #45d483;"
            " border-radius: 6px; }"
            "QPushButton { background: #2f6feb; color: white; border: none;"
            " padding: 9px 15px; border-radius: 7px; font-weight: 600; }"
            "QPushButton#secondary { background: transparent; color: #c8d0df;"
            " border: 1px solid #343d50; }"
            "QPushButton:disabled { color: #7c879b; background: #242a35; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 22)
        layout.setSpacing(12)

        title = QLabel("Selected microphone level")
        title.setStyleSheet("font-size: 21px; font-weight: 700;")
        layout.addWidget(title)

        self.device = QLabel(f"Device: {selected_device}")
        self.device.setTextFormat(Qt.TextFormat.PlainText)
        self.device.setWordWrap(True)
        layout.addWidget(self.device)

        boundary = QLabel(
            "This 10-second test stays on this device and displays only a "
            "live volume level. It does not transcribe, listen for a wake "
            "word, speak, capture the screen, or contact any provider."
        )
        boundary.setWordWrap(True)
        layout.addWidget(boundary)

        self.meter = QProgressBar()
        self.meter.setRange(0, 100)
        self.meter.setValue(0)
        self.meter.setFormat("Not started")
        layout.addWidget(self.meter)

        self.status = QLabel("Ready. Speak normally after selecting Start.")
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #b9d3ff;")
        layout.addWidget(self.status)

        buttons = QHBoxLayout()
        self.start_button = QPushButton("Start local test")
        self.start_button.clicked.connect(self._start)
        buttons.addWidget(self.start_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setObjectName("secondary")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self._stop)
        buttons.addWidget(self.stop_button)
        buttons.addStretch(1)
        close_button = QPushButton("Close")
        close_button.setObjectName("secondary")
        close_button.clicked.connect(self.close)
        buttons.addWidget(close_button)
        layout.addLayout(buttons)

        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._tick)

    @pyqtSlot()
    def _start(self) -> None:
        if self._active_id is not None:
            return
        test_id = secrets.token_hex(16)
        # Set pending ownership first so an immediate audio callback cannot be
        # mistaken for a stale result.
        self._active_id = test_id
        if not self._start_test(test_id, TEST_DURATION_SECONDS):
            self._active_id = None
            self.status.setText(
                "The local test could not start. Stop any active voice "
                "operation and check Microphone privacy permission."
            )
            return
        self._deadline = time.monotonic() + TEST_DURATION_SECONDS
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status.setText(
            "Testing locally. No audio content is retained or sent."
        )
        self._timer.start()
        self._tick()

    @pyqtSlot()
    def _stop(self) -> None:
        self._finish("stopped")

    def _finish(self, reason: str) -> None:
        test_id = self._active_id
        self._active_id = None
        self._deadline = 0.0
        self._timer.stop()
        self.meter.setValue(0)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if test_id is not None:
            self._stop_test(test_id, reason)
        if reason == "timeout":
            self.meter.setFormat("Test complete")
            self.status.setText(
                "The 10-second local test ended automatically."
            )
        elif reason == "permission_revoked":
            self.meter.setFormat("Permission revoked")
            self.status.setText(
                "Microphone permission was revoked; the test stopped."
            )
        elif reason in ("device_changed", "device_reset"):
            self.meter.setFormat("Device changed")
            self.status.setText(
                "The selected microphone changed; start a new test."
            )
        else:
            self.meter.setFormat("Stopped")
            self.status.setText("The local microphone test is stopped.")

    @pyqtSlot(str, float)
    def receive_level(self, test_id: str, rms: float) -> None:
        if test_id != self._active_id:
            return
        level = max(0.0, min(float(rms), 1.0))
        dbfs = 20.0 * math.log10(max(level, 0.001))
        value = round(max(0.0, min(100.0, (dbfs + 60.0) / 60.0 * 100.0)))
        self.meter.setValue(value)
        self._update_meter_text(dbfs)

    @pyqtSlot(str, str)
    def manager_stopped(self, test_id: str, reason: str) -> None:
        if test_id == self._active_id:
            self._finish(reason)

    @pyqtSlot()
    def _tick(self) -> None:
        if self._active_id is None:
            return
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            self._finish("timeout")
            return
        self._update_meter_text(None, remaining)

    def _update_meter_text(
        self,
        dbfs: float | None,
        remaining: float | None = None,
    ) -> None:
        if remaining is None:
            remaining = max(0.0, self._deadline - time.monotonic())
        level = "Waiting for audio" if dbfs is None else f"{dbfs:.0f} dBFS"
        self.meter.setFormat(f"{level}  •  {remaining:.1f}s")

    def closeEvent(self, event: QCloseEvent) -> None:
        self._finish("closed")
        super().closeEvent(event)
