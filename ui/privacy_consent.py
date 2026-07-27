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
from feature_gates import (
    ActionCapability,
    build_feature_available,
)
from privacy_controls import PRIVACY_NOTICE_VERSION, notice_accepted


class PrivacyConsentDialog(QDialog):
    """Collect independent permissions; closing grants nothing."""

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

        self.coding_agent = QCheckBox(
            "Allow Codex and Qwen Code read-only response providers"
        )
        self.coding_agent.setChecked(bool(cfg.coding_agent_consent))
        self.coding_agent.setToolTip(
            "Allows Clicky to start an already-installed Codex or Qwen Code "
            "process only to return a response after you select that provider."
        )
        layout.addWidget(self.coding_agent)
        coding_agent_notice = QLabel(
            "These are response providers, not Task Agents. They can contact "
            "their configured cloud service to return text, but cannot edit "
            "files, run tools, or perform external actions through Clicky. "
            "Clicky never installs them, copies their login tokens, or starts "
            "them merely to discover providers. Runs use an isolated temporary "
            "working directory and restrictive flags."
        )
        coding_agent_notice.setWordWrap(True)
        layout.addWidget(coding_agent_notice)

        self.global_dictation = None
        if build_feature_available(ActionCapability.GLOBAL_DICTATION):
            self.global_dictation = QCheckBox(
                "Allow Global Dictation to insert transcribed text"
            )
            self.global_dictation.setChecked(
                cfg.global_dictation_permission is True
            )
            self.global_dictation.setToolTip(
                "Uses the dedicated dictation hotkey and inserts one final "
                "transcript into the focused, verified text control."
            )
            layout.addWidget(self.global_dictation)
            dictation_notice = QLabel(
                "STT transcribes; Global Dictation inserts. This permission "
                "does not allow screen capture, a response model, memory, "
                "connectors, a Task Agent, or desktop automation. Microphone "
                "and any cloud speech permission remain separate."
            )
            dictation_notice.setWordWrap(True)
            layout.addWidget(dictation_notice)

        self.screen_compose = None
        if build_feature_available(
            ActionCapability.SCREEN_AWARE_COMPOSE
        ):
            self.screen_compose = QCheckBox(
                "Allow Screen-Aware Compose to create reviewed drafts"
            )
            self.screen_compose.setChecked(
                cfg.screen_compose_permission is True
            )
            self.screen_compose.setToolTip(
                "Uses an explicitly authorized screen capture and selected "
                "response provider to create a bounded text draft."
            )
            layout.addWidget(self.screen_compose)
            compose_notice = QLabel(
                "Screen-Aware Compose creates text for your review. It cannot "
                "send, submit, click, run, or claim an external action. Screen "
                "capture permission remains separate, and insertion requires "
                "a later explicit approval."
            )
            compose_notice.setWordWrap(True)
            layout.addWidget(compose_notice)

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
        coding_agent: bool,
    ) -> None:
        cfg.set_privacy_permissions(
            microphone=microphone,
            cloud_stt=cloud_stt,
            cloud_tts=cloud_tts,
            screen_capture=screen,
            coding_agent=coding_agent,
            notice_version=PRIVACY_NOTICE_VERSION,
            global_dictation=(
                self.global_dictation.isChecked()
                if self.global_dictation is not None
                else None
            ),
            screen_compose=(
                self.screen_compose.isChecked()
                if self.screen_compose is not None
                else None
            ),
        )
        self.accept()

    def _keep_disabled(self) -> None:
        if self.global_dictation is not None:
            self.global_dictation.setChecked(False)
        if self.screen_compose is not None:
            self.screen_compose.setChecked(False)
        self._persist(False, False, False, False, False)

    def _save(self) -> None:
        self._persist(
            self.microphone.isChecked(),
            self.cloud_stt.isChecked(),
            self.cloud_tts.isChecked(),
            self.screen_capture.isChecked(),
            self.coding_agent.isChecked(),
        )


def request_privacy_permissions(parent=None, *, force: bool = False) -> bool:
    """Show the modal when needed and return whether the notice was accepted."""
    if notice_accepted(cfg) and not force:
        return True
    dialog = PrivacyConsentDialog(parent)
    dialog.exec()
    return notice_accepted(cfg)
