"""Visible speech-input readiness and local-only fallback policy."""

from __future__ import annotations

import html
import threading

from PyQt6.QtCore import QObject, QTimer, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
)

from audio.stt.readiness import (
    LOCAL_FALLBACK_PROVIDERS,
    collect_stt_readiness,
    fallback_label,
)
from config import cfg


class _ReadinessSignals(QObject):
    completed = pyqtSignal(object)


class SpeechReadinessDialog(QDialog):
    """Read-only provider check plus explicit local fallback selection."""

    fallback_changed = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Speech input readiness")
        self.setMinimumSize(680, 560)
        self.setModal(True)
        self.setStyleSheet(
            "QDialog { background: #101319; color: #e8edf7; }"
            "QLabel { color: #e8edf7; }"
            "QTextBrowser, QComboBox { background: #191f2a; color: #e8edf7;"
            " border: 1px solid #343d50; border-radius: 7px; padding: 7px; }"
            "QPushButton { background: #2f6feb; color: white; border: none;"
            " padding: 9px 15px; border-radius: 7px; font-weight: 600; }"
            "QPushButton#secondary { background: transparent; color: #c8d0df;"
            " border: 1px solid #343d50; }"
        )
        self._signals = _ReadinessSignals(self)
        self._signals.completed.connect(self._show_results)
        self._checking = False
        self._build_ui()
        QTimer.singleShot(0, self.refresh_readiness)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 22)
        layout.setSpacing(12)

        title = QLabel("Speech input readiness and fallback")
        title.setStyleSheet("font-size: 21px; font-weight: 700;")
        layout.addWidget(title)

        explanation = QLabel(
            "This check does not open the microphone or contact a provider. "
            "Cloud rows show configuration and consent; local rows verify the "
            "exact pre-provisioned model bytes."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        selected = cfg.describe()
        self.selected_label = QLabel(
            f"Selected: {selected['stt']} — {selected['stt_mode']}"
        )
        self.selected_label.setStyleSheet(
            "color: #b9d3ff; font-weight: 600;"
        )
        layout.addWidget(self.selected_label)

        self.results = QTextBrowser()
        self.results.setOpenExternalLinks(False)
        self.results.setHtml("<p>Checking speech providers…</p>")
        layout.addWidget(self.results, 1)

        fallback_title = QLabel("If the selected provider fails")
        fallback_title.setStyleSheet("font-weight: 700;")
        layout.addWidget(fallback_title)

        fallback_help = QLabel(
            "Fallback is off by default. If you opt in, captured audio may "
            "retry only through the chosen verified local batch engine. Clicky "
            "never falls across cloud providers."
        )
        fallback_help.setWordWrap(True)
        layout.addWidget(fallback_help)

        self.fallback_combo = QComboBox()
        self.fallback_combo.addItem(fallback_label(""), "")
        active = cfg.stt_provider()
        for provider in LOCAL_FALLBACK_PROVIDERS:
            if provider != active:
                self.fallback_combo.addItem(
                    fallback_label(provider),
                    provider,
                )
        saved = cfg.stt_fallback_provider()
        index = self.fallback_combo.findData(saved)
        self.fallback_combo.setCurrentIndex(max(0, index))
        layout.addWidget(self.fallback_combo)

        self.policy_status = QLabel(
            f"Current policy: {fallback_label(saved)}"
        )
        self.policy_status.setWordWrap(True)
        self.policy_status.setStyleSheet("color: #aeb8ca;")
        layout.addWidget(self.policy_status)

        buttons = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh checks")
        self.refresh_button.setObjectName("secondary")
        self.refresh_button.clicked.connect(self.refresh_readiness)
        buttons.addWidget(self.refresh_button)
        buttons.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.setObjectName("secondary")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)
        save = QPushButton("Save fallback policy")
        save.clicked.connect(self._save)
        buttons.addWidget(save)
        layout.addLayout(buttons)

    @pyqtSlot()
    def refresh_readiness(self) -> None:
        if self._checking:
            return
        self._checking = True
        self.refresh_button.setEnabled(False)
        self.results.setHtml("<p>Checking speech providers…</p>")

        def worker() -> None:
            try:
                rows = collect_stt_readiness(cfg)
            except Exception:
                rows = ()
            try:
                self._signals.completed.emit(rows)
            except RuntimeError:
                pass

        threading.Thread(target=worker, daemon=True).start()

    @pyqtSlot(object)
    def _show_results(self, rows) -> None:
        self._checking = False
        self.refresh_button.setEnabled(True)
        if not rows:
            self.results.setHtml(
                "<p><b>Readiness check failed.</b> No provider request was "
                "made. Close and reopen this window to retry.</p>"
            )
            return
        blocks = []
        for row in rows:
            color = "#45d483" if row.ready else "#ffb454"
            status = "READY" if row.ready else "NEEDS SETUP"
            blocks.append(
                "<div style='margin-bottom:14px'>"
                f"<b>{html.escape(row.label)}</b> "
                f"<span style='color:{color}'>{status}</span><br>"
                f"{html.escape(row.mode)}<br>"
                f"<span style='color:#9fb0c9'>Destination: "
                f"{html.escape(row.destination)}</span><br>"
                f"{html.escape(row.detail)}"
                "</div>"
            )
        self.results.setHtml("".join(blocks))

    @pyqtSlot()
    def _save(self) -> None:
        selected = str(self.fallback_combo.currentData() or "")
        self.fallback_changed.emit(selected)
        self.accept()
