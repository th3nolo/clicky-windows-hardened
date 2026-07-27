"""Explicit, content-safe recovery UI for Global Dictation results."""

from __future__ import annotations

from PyQt6.QtCore import QTimer, Qt, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from dictation.insertion import InsertionStatus
from dictation.outcome import DictationRunOutcome


_STATUS_LABELS = {
    InsertionStatus.VERIFIED_INSERTED: "Inserted and verified",
    InsertionStatus.ATTEMPTED_UNVERIFIED: (
        "Insertion attempted — the destination cannot confirm it"
    ),
    InsertionStatus.BLOCKED: "Not inserted — destination changed or was blocked",
    InsertionStatus.UNSUPPORTED: "Not inserted — destination is unsupported",
    InsertionStatus.FAILED: (
        "Insertion failed — the destination may contain partial text"
    ),
}
RECOVERY_TTL_MS = 60_000


class DictationResultPanel(QWidget):
    """Show result metadata first; reveal dictated text only on user request."""

    copy_requested = pyqtSignal(object)
    dismissed = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._outcome: DictationRunOutcome | None = None
        self._expiry = QTimer(self)
        self._expiry.setSingleShot(True)
        self._expiry.timeout.connect(self._dismiss)
        self.setWindowTitle("Global Dictation result")
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setMinimumWidth(420)
        self.setStyleSheet(
            "QWidget { background: #101827; color: #eef3ff; }"
            "QLabel { background: transparent; }"
            "QPushButton { background: #263b61; border: 1px solid #4e6a9b; "
            "border-radius: 6px; padding: 6px 10px; }"
            "QPushButton:hover { background: #315080; }"
            "QPlainTextEdit { background: #0b111d; border: 1px solid #445a7d; "
            "border-radius: 6px; padding: 6px; }"
        )

        layout = QVBoxLayout(self)
        self._status = QLabel()
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        self._destination = QLabel()
        self._destination.setWordWrap(True)
        layout.addWidget(self._destination)

        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setMaximumHeight(140)
        self._preview.setVisible(False)
        layout.addWidget(self._preview)

        buttons = QHBoxLayout()
        self._preview_button = QPushButton("Retry as safe preview")
        self._preview_button.clicked.connect(self._reveal_preview)
        self._copy_button = QPushButton("Copy")
        self._copy_button.clicked.connect(self._request_copy)
        self._dismiss_button = QPushButton("Dismiss")
        self._dismiss_button.clicked.connect(self._dismiss)
        buttons.addWidget(self._preview_button)
        buttons.addWidget(self._copy_button)
        buttons.addStretch(1)
        buttons.addWidget(self._dismiss_button)
        layout.addLayout(buttons)
        self.hide()

    @pyqtSlot(object)
    def show_result(self, outcome: DictationRunOutcome) -> None:
        self.clear_sensitive()
        if not isinstance(outcome, DictationRunOutcome):
            return
        self._outcome = outcome
        insertion = outcome.insertion
        self._status.setText(_STATUS_LABELS[insertion.status])
        destination = outcome.application_name or "unknown application"
        self._destination.setText(f"Destination: {destination}")
        recoverable = insertion.preview is not None
        self._preview_button.setVisible(recoverable)
        self._copy_button.setVisible(recoverable)
        self._copy_button.setEnabled(recoverable)
        self._copy_button.setText("Copy")
        self._expiry.start(RECOVERY_TTL_MS)
        self.adjustSize()
        screen = self.screen()
        if screen is not None:
            area = screen.availableGeometry()
            self.move(
                area.right() - self.width() - 24,
                area.bottom() - self.height() - 74,
            )
        self.show()

    @pyqtSlot()
    def clear_sensitive(self) -> None:
        self._expiry.stop()
        self._preview.clear()
        self._preview.setVisible(False)
        self._outcome = None

    @pyqtSlot(object)
    def set_copy_result(self, result) -> None:
        if getattr(result, "copied", False) is True:
            self._copy_button.setText("Copied")
            self._copy_button.setEnabled(False)
            self._preview.clear()
            self._preview.setVisible(False)
            self._outcome = None
        else:
            self._copy_button.setText("Copy unavailable")
            self._copy_button.setEnabled(False)

    def _reveal_preview(self) -> None:
        outcome = self._outcome
        preview = outcome.insertion.preview if outcome is not None else None
        if preview is None:
            return
        self._preview.setPlainText(preview.text)
        self._preview.setVisible(True)
        self.adjustSize()

    def _request_copy(self) -> None:
        if self._outcome is not None:
            self.copy_requested.emit(self._outcome)

    def _dismiss(self) -> None:
        outcome = self._outcome
        self.clear_sensitive()
        self.hide()
        if outcome is not None:
            self.dismissed.emit(outcome)
