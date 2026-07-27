"""Explicit, persisted privacy permissions shown before sensitive I/O starts."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from config import cfg
from privacy_controls import PRIVACY_NOTICE_VERSION, notice_accepted


class PrivacyConsentDialog(QDialog):
    """Collect four independent permissions; closing grants nothing."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Clicky privacy permissions")
        self.setModal(True)
        self.setMinimumWidth(600)

        layout = QVBoxLayout(self)
        title = QLabel("<b>Choose what Clicky may access</b>")
        title.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(title)

        explanation = QLabel(
            "Each permission is optional and starts disabled. You can change "
            "these choices later from Setup & Diagnostics → Privacy permissions."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        self.microphone = QCheckBox("Allow microphone access")
        self.microphone.setChecked(bool(cfg.microphone_consent))
        self.microphone.setToolTip(
            "Clicky keeps a microphone stream open for local wake-word detection "
            "and captures audio only after wake or push-to-talk."
        )
        layout.addWidget(self.microphone)
        mic_notice = QLabel(
            "The microphone remains open while Clicky is running so the local "
            "wake-word detector can listen. This permission alone does not allow "
            "Clicky to send speech audio to a cloud provider."
        )
        mic_notice.setWordWrap(True)
        layout.addWidget(mic_notice)

        self.cloud_stt = QCheckBox("Allow cloud speech-to-text")
        self.cloud_stt.setChecked(bool(cfg.cloud_stt_consent))
        self.cloud_stt.setToolTip(
            "When a cloud speech provider is selected, Clicky may send captured "
            "microphone audio to that provider for transcription."
        )
        layout.addWidget(self.cloud_stt)
        stt_notice = QLabel(
            "Deepgram live mode streams bounded microphone frames while you "
            "speak. Batch cloud modes upload the completed capture. Local "
            "Whisper modes do neither. Granting this permission does not select "
            "a cloud provider."
        )
        stt_notice.setWordWrap(True)
        layout.addWidget(stt_notice)

        self.cloud_tts = QCheckBox("Allow cloud text-to-speech")
        self.cloud_tts.setChecked(bool(cfg.cloud_tts_consent))
        self.cloud_tts.setToolTip(
            "Assistant response text is sent to Microsoft Edge TTS, OpenAI, or "
            "ElevenLabs, depending on the selected provider."
        )
        layout.addWidget(self.cloud_tts)
        tts_notice = QLabel(
            "All spoken assistant responses are sent as text to the selected "
            "speech service. The default Edge TTS service sends text to Microsoft "
            "even though it does not require an API key."
        )
        tts_notice.setWordWrap(True)
        layout.addWidget(tts_notice)

        self.screen_capture = QCheckBox("Allow screen capture and model sharing")
        self.screen_capture.setChecked(bool(cfg.screen_capture_consent))
        self.screen_capture.setToolTip(
            "Clicky captures every monitor. Images stay local for Ollama/LM Studio "
            "and are sent to the selected cloud model for cloud providers."
        )
        layout.addWidget(self.screen_capture)
        screen_notice = QLabel(
            "Clicky captures all monitors for visual questions. Images stay on "
            "the machine with Ollama or LM Studio, but are sent to the selected "
            "cloud AI provider otherwise. The window-title Privacy Guard is only "
            "a heuristic and can miss sensitive content."
        )
        screen_notice.setWordWrap(True)
        layout.addWidget(screen_notice)

        buttons = QHBoxLayout()
        keep_disabled = QPushButton("Keep all disabled")
        keep_disabled.clicked.connect(self._keep_disabled)
        save = QPushButton("Save permissions")
        save.setDefault(True)
        save.clicked.connect(self._save)
        buttons.addWidget(keep_disabled)
        buttons.addStretch(1)
        buttons.addWidget(save)
        layout.addLayout(buttons)

    def _persist(
        self,
        microphone: bool,
        cloud_stt: bool,
        cloud_tts: bool,
        screen: bool,
    ) -> None:
        cfg.set_privacy_permissions(
            microphone=microphone,
            cloud_stt=cloud_stt,
            cloud_tts=cloud_tts,
            screen_capture=screen,
            notice_version=PRIVACY_NOTICE_VERSION,
        )
        self.accept()

    def _keep_disabled(self) -> None:
        self._persist(False, False, False, False)

    def _save(self) -> None:
        self._persist(
            self.microphone.isChecked(),
            self.cloud_stt.isChecked(),
            self.cloud_tts.isChecked(),
            self.screen_capture.isChecked(),
        )


def request_privacy_permissions(parent=None, *, force: bool = False) -> bool:
    """Show the modal when needed and return whether the notice was accepted."""
    if notice_accepted(cfg) and not force:
        return True
    dialog = PrivacyConsentDialog(parent)
    dialog.exec()
    return notice_accepted(cfg)
