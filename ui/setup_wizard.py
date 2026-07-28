"""First-run checks and manual setup guidance for the hardened build.

This wizard is intentionally read-only: it never downloads or executes Ollama
and never requests a model download. It only checks already-provisioned local
state and tells the user how to finish setup outside Clicky.
"""

from __future__ import annotations

import os
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from ai import ollama_bootstrap as ob
from config import cfg


def _flag_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    directory = Path(base) / "Clicky"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "setup_complete.flag"


def setup_already_ran() -> bool:
    return _flag_path().exists()


def mark_setup_complete() -> None:
    try:
        _flag_path().write_text("ok", encoding="utf-8")
    except Exception:
        pass


class SetupWizard(QDialog):
    """Read-only local dependency and model check."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Clicky Setup")
        self.setModal(False)
        self.setMinimumSize(560, 380)
        self.setStyleSheet("""
            QDialog { background: #0e1014; color: #e8eaed; }
            QLabel  { color: #e8eaed; }
            QLabel#title { font-size: 22px; font-weight: 700; }
            QLabel#subtitle { color: #a0a3a8; font-size: 13px; }
            QLabel#status { color: #c8cbd0; font-size: 13px; }
            QPushButton {
                background: #1f6feb; color: white; border: none;
                padding: 10px 18px; border-radius: 8px;
                font-weight: 600; font-size: 13px;
            }
            QPushButton:hover  { background: #2f7fff; }
            QPushButton:disabled { background: #333; color: #888; }
            QPushButton#secondary {
                background: transparent; color: #a0a3a8;
                border: 1px solid #2a2d33;
            }
            QPushButton#secondary:hover { color: #e8eaed; border-color: #444; }
        """)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 24)
        layout.setSpacing(14)

        self.title = QLabel("Welcome to Clicky")
        self.title.setObjectName("title")
        layout.addWidget(self.title)

        self.subtitle = QLabel("")
        self.subtitle.setObjectName("subtitle")
        self.subtitle.setWordWrap(True)
        self.subtitle.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.subtitle)

        self.status = QLabel("")
        self.status.setObjectName("status")
        self.status.setWordWrap(True)
        self.status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addSpacing(8)
        layout.addWidget(self.status)
        layout.addStretch(1)

        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        self.skip_btn = QPushButton("Skip - I'll use an API key")
        self.skip_btn.setObjectName("secondary")
        self.skip_btn.clicked.connect(self._on_skip)
        button_row.addWidget(self.skip_btn)
        self.practice_btn = QPushButton("Practice hotkey + pointing")
        self.practice_btn.setObjectName("secondary")
        self.practice_btn.clicked.connect(self._open_practice)
        button_row.addWidget(self.practice_btn)
        self.suggestions_btn = QPushButton("Local app ideas")
        self.suggestions_btn.setObjectName("secondary")
        self.suggestions_btn.clicked.connect(
            self._open_app_suggestions
        )
        button_row.addWidget(self.suggestions_btn)
        button_row.addStretch(1)
        self.action_btn = QPushButton("Check local setup")
        self.action_btn.clicked.connect(self._on_action)
        button_row.addWidget(self.action_btn)
        layout.addLayout(button_row)

        self._set_step("intro")

    def _set_step(self, step: str) -> None:
        self._step = step
        self.action_btn.setEnabled(True)
        self.skip_btn.setEnabled(True)
        self.skip_btn.show()

        if step == "intro":
            if ob.is_ollama_running():
                self.title.setText("Ollama detected")
                self.subtitle.setText(
                    "Clicky found a running Ollama server. It will now check only "
                    "for models that are already installed."
                )
                self.status.setText("")
                self.action_btn.setText("Check installed models")
            else:
                self.title.setText("Step 1 of 3 - Install Ollama separately")
                self.subtitle.setText(
                    "The hardened build never downloads or launches installers. "
                    "Install Ollama yourself, verify its Windows publisher, start "
                    "the server, then return here."
                )
                self.status.setText(ob.installation_guidance())
                self.action_btn.setText("Check again")
            self.skip_btn.setText("Skip - I'll use an API key")

        elif step == "text_model":
            name = cfg.ollama_text_model
            self.title.setText("Step 2 of 3 - Provision the text model")
            self.subtitle.setText(
                "Clicky will not download this model. Review and install it "
                "outside Clicky, then check again."
            )
            self.status.setText(ob.model_guidance(
                name,
                cfg.ollama_text_model_digest if step == "text_model" else cfg.ollama_vision_model_digest,
                "OLLAMA_TEXT_MODEL_DIGEST" if step == "text_model" else "OLLAMA_VISION_MODEL_DIGEST",
            ))
            self.action_btn.setText("Check again")
            self.skip_btn.setText("Skip - use another provider")

        elif step == "vision_model":
            name = cfg.ollama_vision_model
            self.title.setText("Step 3 of 3 - Provision the vision model (optional)")
            self.subtitle.setText(
                "The vision model is needed for screen-aware features. Clicky "
                "will only use it after it is already installed locally."
            )
            self.status.setText(ob.model_guidance(
                name,
                cfg.ollama_text_model_digest if step == "text_model" else cfg.ollama_vision_model_digest,
                "OLLAMA_TEXT_MODEL_DIGEST" if step == "text_model" else "OLLAMA_VISION_MODEL_DIGEST",
            ))
            self.action_btn.setText("Check again")
            self.skip_btn.setText("Skip - add it later")

        elif step == "done":
            self.title.setText("Local setup detected")
            hotkey = "+".join(part.strip().capitalize() for part in cfg.hotkey.split("+"))
            self.subtitle.setText(
                f"Clicky is ready. Hold {hotkey} anywhere on Windows to start "
                "a conversation. Wake-word detection also requires a separately "
                "provisioned local tiny.en speech model."
            )
            self.status.setText("")
            self.action_btn.setText("Start using Clicky")
            self.skip_btn.hide()
            mark_setup_complete()

    def _on_action(self) -> None:
        if self._step == "intro":
            if ob.is_ollama_running():
                self._goto_next_model_step()
            else:
                self.status.setText(ob.installation_guidance())
        elif self._step == "text_model":
            if ob.is_model_installed(
                cfg.ollama_text_model,
                cfg.ollama_text_model_digest,
                "OLLAMA_TEXT_MODEL_DIGEST",
            ):
                self._set_step("vision_model")
            else:
                self.status.setText(ob.model_guidance(
                    cfg.ollama_text_model,
                    cfg.ollama_text_model_digest,
                    "OLLAMA_TEXT_MODEL_DIGEST",
                ))
        elif self._step == "vision_model":
            if ob.is_model_installed(
                cfg.ollama_vision_model,
                cfg.ollama_vision_model_digest,
                "OLLAMA_VISION_MODEL_DIGEST",
            ):
                self._set_step("done")
            else:
                self.status.setText(ob.model_guidance(
                    cfg.ollama_vision_model,
                    cfg.ollama_vision_model_digest,
                    "OLLAMA_VISION_MODEL_DIGEST",
                ))
        elif self._step == "done":
            self.accept()

    def _on_skip(self) -> None:
        if self._step == "intro":
            mark_setup_complete()
            self.reject()
        elif self._step == "text_model":
            self._set_step("vision_model")
        elif self._step == "vision_model":
            self._set_step("done")

    def _goto_next_model_step(self) -> None:
        if not ob.is_model_installed(
                cfg.ollama_text_model,
                cfg.ollama_text_model_digest,
                "OLLAMA_TEXT_MODEL_DIGEST",
            ):
            self._set_step("text_model")
        elif not ob.is_model_installed(
                cfg.ollama_vision_model,
                cfg.ollama_vision_model_digest,
                "OLLAMA_VISION_MODEL_DIGEST",
            ):
            self._set_step("vision_model")
        else:
            self._set_step("done")

    def _open_practice(self) -> None:
        from ui.onboarding_demo import show_onboarding_demo

        show_onboarding_demo(cfg.hotkey, self)

    def _open_app_suggestions(self) -> None:
        from ui.app_suggestions import show_app_suggestions

        show_app_suggestions(self)


def maybe_show_setup_wizard(parent=None) -> SetupWizard | None:
    """Open the read-only setup check only when local state is incomplete."""
    if setup_already_ran():
        return None
    if ob.is_ollama_running() and ob.is_model_installed(
                cfg.ollama_text_model,
                cfg.ollama_text_model_digest,
                "OLLAMA_TEXT_MODEL_DIGEST",
            ):
        mark_setup_complete()
        return None

    wizard = SetupWizard(parent)
    wizard.show()
    return wizard
