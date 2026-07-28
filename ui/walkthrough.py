"""Explicit manual-advance progress surface for visual walkthroughs."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from walkthrough.controller import WalkthroughProgress


class WalkthroughPanel(QWidget):
    continue_requested = pyqtSignal()
    cancel_requested = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._active = False
        self.setWindowTitle("Clicky visual walkthrough")
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setMinimumWidth(440)
        self.setStyleSheet(
            "QWidget { background: #101827; color: #eef3ff; }"
            "QLabel { background: transparent; }"
            "QPushButton { background: #2f6feb; color: white; border: none;"
            " border-radius: 6px; padding: 8px 13px; font-weight: 600; }"
            "QPushButton#secondary { background: transparent; color: #c8d0df;"
            " border: 1px solid #445a7d; }"
            "QPushButton:disabled { color: #7c879b; background: #242a35; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(10)
        title = QLabel("Visual walkthrough")
        title.setStyleSheet("font-size: 19px; font-weight: 700;")
        layout.addWidget(title)

        self.progress = QLabel("")
        self.progress.setStyleSheet("color: #9fc3ff; font-weight: 600;")
        layout.addWidget(self.progress)

        self.narration = QLabel("")
        self.narration.setTextFormat(Qt.TextFormat.PlainText)
        self.narration.setWordWrap(True)
        self.narration.setMinimumHeight(72)
        layout.addWidget(self.narration)

        boundary = QLabel(
            "Highlights and the Clicky pointer are visual guidance only. "
            "Clicky will not click or change the highlighted application."
        )
        boundary.setWordWrap(True)
        boundary.setStyleSheet("color: #aeb8ca;")
        layout.addWidget(boundary)

        buttons = QHBoxLayout()
        self.continue_button = QPushButton("Continue")
        self.continue_button.clicked.connect(self.continue_requested)
        buttons.addWidget(self.continue_button)
        buttons.addStretch(1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("secondary")
        self.cancel_button.clicked.connect(
            lambda: self.cancel_requested.emit("cancelled")
        )
        buttons.addWidget(self.cancel_button)
        layout.addLayout(buttons)
        self.hide()

    @pyqtSlot(object)
    def show_progress(self, progress: WalkthroughProgress) -> None:
        if not isinstance(progress, WalkthroughProgress):
            return
        self._active = True
        self.progress.setText(
            f"Step {progress.current} of {progress.total}  •  "
            f"{progress.remaining} remaining"
        )
        self.narration.setText(progress.narration)
        busy = progress.advancing or progress.paused_for_voice
        self.continue_button.setEnabled(not busy)
        if progress.advancing:
            self.continue_button.setText("Refreshing screen…")
        elif progress.paused_for_voice:
            self.continue_button.setText("Listening for “continue”…")
        elif progress.remaining == 0:
            self.continue_button.setText("Finish")
        else:
            self.continue_button.setText("Continue")
        self.adjustSize()
        self.show()
        self.raise_()

    @pyqtSlot(str)
    def end_walkthrough(self, _reason: str) -> None:
        self._active = False
        self.narration.clear()
        self.progress.clear()
        self.continue_button.setEnabled(False)
        self.hide()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._active:
            self.cancel_requested.emit("closed")
        super().closeEvent(event)
