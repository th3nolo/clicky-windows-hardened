"""Content-free visible state for Global Dictation."""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import QLabel

from dictation.models import DictationSnapshot, DictationState


_STATE_LABELS = {
    DictationState.CAPTURING: "Dictation · Listening",
    DictationState.FINALIZING: "Dictation · Finalizing",
    DictationState.READY_TO_COMMIT: "Dictation · Ready",
    DictationState.COMMITTING: "Dictation · Inserting",
    DictationState.COMPLETED: "Dictation · Inserted",
    DictationState.CANCELLED: "Dictation · Cancelled",
    DictationState.FAILED: "Dictation · Failed",
}


class DictationIndicator(QLabel):
    """Small mode/state indicator that never displays dictated content."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setStyleSheet(
            "background: #172033; color: #f4f7ff; "
            "border: 1px solid #4b638f; border-radius: 10px; "
            "padding: 8px 12px; font-size: 12px;"
        )
        self.hide()

    @pyqtSlot(object)
    def set_snapshot(self, snapshot: DictationSnapshot) -> None:
        if (
            not isinstance(snapshot, DictationSnapshot)
            or snapshot.state is DictationState.IDLE
        ):
            self.hide()
            return
        label = _STATE_LABELS[snapshot.state]
        if (
            snapshot.state is DictationState.FAILED
            and isinstance(snapshot.result_code, str)
            and snapshot.result_code.startswith("blocked_")
        ):
            label = "Dictation · Blocked"
        self.setText(label)
        self.adjustSize()
        screen = self.screen()
        if screen is not None:
            area = screen.availableGeometry()
            self.move(
                area.right() - self.width() - 24,
                area.bottom() - self.height() - 24,
            )
        self.show()
