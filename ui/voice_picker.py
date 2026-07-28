"""Reviewed provider voice selection with a bounded synthetic preview."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from audio.tts.voice_catalog import ReviewedVoice
from audio.tts.voice_preview import VOICE_PREVIEW_TEXT


class VoicePickerDialog(QDialog):
    """Expose fixed IDs only; the manager owns preview permission and timeout."""

    def __init__(
        self,
        *,
        provider_label: str,
        provider: str,
        destination: str,
        voices: Sequence[ReviewedVoice],
        selected_voice_id: str,
        cloud_tts_allowed: bool,
        save_voice: Callable[[str, str], bool],
        start_preview: Callable[[str, str, str], bool],
        stop_preview: Callable[[str | None, str], bool],
        parent=None,
    ) -> None:
        super().__init__(parent)
        if (
            not isinstance(provider, str)
            or not provider
            or not isinstance(destination, str)
            or not destination
        ):
            raise ValueError("Voice provider metadata is required")
        if not callable(save_voice) or not callable(start_preview) or not callable(
            stop_preview
        ):
            raise TypeError("Voice controls are required")
        reviewed = tuple(voices)
        if (
            not reviewed
            or any(item.provider != provider for item in reviewed)
            or selected_voice_id not in {item.voice_id for item in reviewed}
        ):
            raise ValueError("Reviewed voice selection is invalid")

        self._provider = provider
        self._destination = destination
        self._voices = reviewed
        self._save_voice = save_voice
        self._start_preview = start_preview
        self._stop_preview = stop_preview
        self._active_preview_id: str | None = None
        self._cloud_tts_allowed = cloud_tts_allowed is True

        self.setWindowTitle("Speech voice")
        self.setModal(True)
        self.setMinimumWidth(540)
        self.setStyleSheet(
            "QDialog { background: #101319; color: #e8edf7; }"
            "QLabel { color: #e8edf7; }"
            "QComboBox { background: #191f2a; color: #e8edf7;"
            " border: 1px solid #343d50; border-radius: 7px;"
            " padding: 8px; min-height: 22px; }"
            "QPushButton { background: #2f6feb; color: white; border: none;"
            " padding: 9px 15px; border-radius: 7px; font-weight: 600; }"
            "QPushButton#secondary { background: transparent; color: #c8d0df;"
            " border: 1px solid #343d50; }"
            "QPushButton:disabled { color: #7c879b; background: #242a35; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 22)
        layout.setSpacing(12)

        title = QLabel("Speech voice")
        title.setStyleSheet("font-size: 21px; font-weight: 700;")
        layout.addWidget(title)

        boundary = QLabel(
            "This setting selects a voice for text-to-speech only. It does "
            "not change Writing Style Profiles, instructions, model persona, "
            "or conversation history."
        )
        boundary.setWordWrap(True)
        layout.addWidget(boundary)

        self.provider = QLabel(
            f"Provider: {provider_label}\nDestination: {destination}"
        )
        self.provider.setTextFormat(Qt.TextFormat.PlainText)
        self.provider.setWordWrap(True)
        layout.addWidget(self.provider)

        self.voice_combo = QComboBox()
        selected_index = 0
        for index, voice in enumerate(reviewed):
            self.voice_combo.addItem(voice.label, voice.voice_id)
            if voice.voice_id == selected_voice_id:
                selected_index = index
        self.voice_combo.setCurrentIndex(selected_index)
        self.voice_combo.currentIndexChanged.connect(self._selection_changed)
        layout.addWidget(self.voice_combo)

        self.voice_id = QLabel()
        self.voice_id.setTextFormat(Qt.TextFormat.PlainText)
        self.voice_id.setWordWrap(True)
        self.voice_id.setStyleSheet("color: #aeb8ca;")
        layout.addWidget(self.voice_id)
        self._selection_changed()

        preview_notice = QLabel(
            f'Preview sends only this fixed synthetic text: "{VOICE_PREVIEW_TEXT}"'
        )
        preview_notice.setTextFormat(Qt.TextFormat.PlainText)
        preview_notice.setWordWrap(True)
        layout.addWidget(preview_notice)

        self.status = QLabel(
            "Ready."
            if self._cloud_tts_allowed
            else (
                "Preview is disabled until cloud text-to-speech permission "
                "is granted in Privacy permissions."
            )
        )
        self.status.setWordWrap(True)
        self.status.setStyleSheet("color: #b9d3ff;")
        layout.addWidget(self.status)

        buttons = QHBoxLayout()
        self.save_button = QPushButton("Save voice")
        self.save_button.clicked.connect(self._save)
        buttons.addWidget(self.save_button)
        self.preview_button = QPushButton("Preview fixed text")
        self.preview_button.setEnabled(self._cloud_tts_allowed)
        self.preview_button.clicked.connect(self._preview)
        buttons.addWidget(self.preview_button)
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

    def selected_voice_id(self) -> str:
        return str(self.voice_combo.currentData())

    @pyqtSlot()
    def _selection_changed(self) -> None:
        self.voice_id.setText(f"Reviewed voice ID: {self.selected_voice_id()}")

    @pyqtSlot()
    def _save(self) -> None:
        if self._save_voice(self._provider, self.selected_voice_id()):
            self.status.setText(
                "Voice saved for this provider. Writing style and persona "
                "were not changed."
            )
        else:
            self.status.setText("The reviewed voice could not be saved.")

    @pyqtSlot()
    def _preview(self) -> None:
        if self._active_preview_id is not None or not self._cloud_tts_allowed:
            return
        preview_id = secrets.token_hex(16)
        self._active_preview_id = preview_id
        if not self._start_preview(
            preview_id,
            self._provider,
            self.selected_voice_id(),
        ):
            self._active_preview_id = None
            self.status.setText(
                "Preview did not start. Check permission and stop any active "
                "voice operation."
            )
            return
        self.preview_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status.setText(
            f"Previewing fixed text with {self._provider} at "
            f"{self._destination}."
        )

    @pyqtSlot()
    def _stop(self) -> None:
        preview_id = self._active_preview_id
        if preview_id is not None:
            self._stop_preview(preview_id, "stopped")

    @pyqtSlot(str, bool, str)
    def preview_stopped(
        self,
        preview_id: str,
        succeeded: bool,
        reason: str,
    ) -> None:
        if preview_id != self._active_preview_id:
            return
        self._active_preview_id = None
        self.preview_button.setEnabled(self._cloud_tts_allowed)
        self.stop_button.setEnabled(False)
        messages = {
            "completed": "Fixed voice preview completed.",
            "timeout": "Voice preview reached its 12-second limit.",
            "permission_revoked": "Cloud TTS permission was revoked.",
            "selection_changed": "Voice changed; start a new preview.",
            "shutdown": "Voice preview stopped during shutdown.",
            "cancelled": "Voice preview stopped.",
            "stopped": "Voice preview stopped.",
        }
        self.status.setText(
            messages.get(
                reason,
                "Fixed voice preview completed."
                if succeeded
                else "Voice preview failed without a provider fallback.",
            )
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        preview_id = self._active_preview_id
        self._active_preview_id = None
        if preview_id is not None:
            self._stop_preview(preview_id, "closed")
        super().closeEvent(event)


__all__ = ["VoicePickerDialog"]
