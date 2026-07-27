"""Non-activating, explicit review UI for Screen-Aware Compose drafts."""

from __future__ import annotations

from typing import Protocol

from PyQt6.QtCore import QTimer, Qt, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ai.provider_catalog import provider_label
from compose.models import (
    Draft,
    DraftInsertionApproval,
    validate_draft_review_context,
)
from dictation.policy import TargetDecision, TargetLease
from feature_gates import RunCapabilityGrant


COMPOSE_PREVIEW_TTL_MS = 5 * 60_000


class ComposeTargetGuard(Protocol):
    def revalidate(self, lease: TargetLease) -> TargetDecision: ...


class ComposePreviewPanel(QWidget):
    """Review one draft without gaining authority to mutate its destination."""

    insert_approved = pyqtSignal(object)
    copy_requested = pyqtSignal(object)
    regenerate_requested = pyqtSignal(object)
    cancelled = pyqtSignal(str)

    def __init__(
        self,
        targets: ComposeTargetGuard,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not callable(getattr(targets, "revalidate", None)):
            raise TypeError("Compose preview requires a target guard")
        self._targets = targets
        self._draft: Draft | None = None
        self._target: TargetLease | None = None
        self._grant: RunCapabilityGrant | None = None
        self._active = False
        self._copy_pending = False
        self._regeneration_pending = False

        self._expiry = QTimer(self)
        self._expiry.setSingleShot(True)
        self._expiry.timeout.connect(self._cancel)

        self.setWindowTitle("Screen-Aware Compose draft")
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setAcceptDrops(False)
        self.setMinimumWidth(520)
        self.setStyleSheet(
            "QWidget { background: #101827; color: #eef3ff; }"
            "QLabel { background: transparent; }"
            "QPushButton { background: #263b61; border: 1px solid #4e6a9b; "
            "border-radius: 6px; padding: 7px 11px; }"
            "QPushButton:hover { background: #315080; }"
            "QPushButton:disabled { color: #8090aa; background: #182338; }"
            "QPlainTextEdit { background: #0b111d; border: 1px solid #445a7d; "
            "border-radius: 6px; padding: 8px; }"
        )

        layout = QVBoxLayout(self)
        self._status = self._plain_label(
            "Review this draft before choosing an action."
        )
        self._status.setWordWrap(True)
        layout.addWidget(self._status)

        self._destination = self._plain_label("")
        self._destination.setWordWrap(True)
        layout.addWidget(self._destination)

        self._metadata = self._plain_label("")
        self._metadata.setWordWrap(True)
        layout.addWidget(self._metadata)

        self._preview = QPlainTextEdit()
        self._preview.setReadOnly(True)
        self._preview.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._preview.setMaximumHeight(240)
        self._preview.setAcceptDrops(False)
        layout.addWidget(self._preview)

        self._character_count = self._plain_label("0 characters")
        layout.addWidget(self._character_count)

        buttons = QHBoxLayout()
        self._insert_button = self._button("Insert", self._request_insert)
        self._copy_button = self._button("Copy", self._request_copy)
        self._regenerate_button = self._button(
            "Regenerate",
            self._request_regenerate,
        )
        self._cancel_button = self._button("Cancel", self._cancel)
        buttons.addWidget(self._insert_button)
        buttons.addWidget(self._copy_button)
        buttons.addWidget(self._regenerate_button)
        buttons.addStretch(1)
        buttons.addWidget(self._cancel_button)
        layout.addLayout(buttons)
        self._set_actions_enabled(False)
        self.hide()

    @staticmethod
    def _plain_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        return label

    @staticmethod
    def _button(text: str, callback) -> QPushButton:
        button = QPushButton(text)
        button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        button.clicked.connect(callback)
        return button

    @pyqtSlot(object, object, object)
    def show_draft(
        self,
        draft: Draft,
        target: TargetLease,
        grant: RunCapabilityGrant,
    ) -> None:
        """Show a validated draft while retaining its original target lease."""

        validate_draft_review_context(draft, target, grant)
        self.clear_sensitive()
        self._draft = draft
        self._target = target
        self._grant = grant
        self._active = True
        self._copy_pending = False
        self._regeneration_pending = False
        provenance = draft.provenance
        profile = provenance.style_profile_id or "Default"
        self._status.setText(
            "Review this draft. Nothing has been inserted or sent."
        )
        self._destination.setText(
            f"Destination: {provenance.destination_application}"
        )
        self._metadata.setText(
            f"Writing profile: {profile}  •  "
            f"Provider: {provider_label(provenance.provider_id)}"
        )
        self._preview.setPlainText(draft.text)
        self._character_count.setText(
            f"{draft.character_count} characters"
        )
        self._copy_button.setText("Copy")
        self._regenerate_button.setText("Regenerate")
        self._set_actions_enabled(True)
        self._expiry.start(COMPOSE_PREVIEW_TTL_MS)
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
        self._draft = None
        self._target = None
        self._grant = None
        self._active = False
        self._copy_pending = False
        self._regeneration_pending = False
        self._set_actions_enabled(False)

    @pyqtSlot(str, bool)
    def set_copy_result(self, run_id: str, copied: bool) -> None:
        draft = self._draft
        if (
            not self._active
            or draft is None
            or draft.provenance.run_id != run_id
            or type(copied) is not bool
            or not self._copy_pending
        ):
            return
        self._copy_button.setText(
            "Copied" if copied else "Copy unavailable"
        )
        self._copy_button.setEnabled(False)
        self._status.setText(
            (
                "Draft copied. Nothing was inserted or sent."
                if copied
                else "Copy failed. The destination was not changed."
            )
        )

    @pyqtSlot(str)
    def set_regeneration_failed(self, run_id: str) -> None:
        draft = self._draft
        if (
            not self._active
            or draft is None
            or draft.provenance.run_id != run_id
            or not self._regeneration_pending
        ):
            return
        self._status.setText(
            "Regeneration failed. The current draft remains unchanged."
        )
        self._insert_button.setEnabled(True)
        self._copy_button.setEnabled(not self._copy_pending)
        self._regenerate_button.setEnabled(True)
        self._regenerate_button.setText("Regenerate")
        self._regeneration_pending = False

    def _request_insert(self) -> None:
        draft = self._draft
        target = self._target
        grant = self._grant
        if (
            not self._active
            or draft is None
            or target is None
            or grant is None
        ):
            return
        try:
            decision = self._targets.revalidate(target)
        except Exception:
            decision = None
        if (
            not isinstance(decision, TargetDecision)
            or not decision.allowed
            or decision.lease is None
        ):
            self._status.setText(
                "Insert unavailable: the destination changed or is blocked."
            )
            self._insert_button.setEnabled(False)
            return
        try:
            approval = DraftInsertionApproval(
                draft=draft,
                target=decision.lease,
                grant=grant,
            )
        except (TypeError, ValueError):
            self._status.setText(
                "Insert unavailable: the destination identity changed."
            )
            self._insert_button.setEnabled(False)
            return
        self._active = False
        self._expiry.stop()
        self._set_actions_enabled(False)
        self.insert_approved.emit(approval)
        self.clear_sensitive()
        self.hide()

    def _request_copy(self) -> None:
        draft = self._draft
        if (
            not self._active
            or draft is None
            or self._copy_pending
        ):
            return
        self._copy_pending = True
        self._copy_button.setText("Copy requested")
        self._copy_button.setEnabled(False)
        self.copy_requested.emit(draft)

    def _request_regenerate(self) -> None:
        draft = self._draft
        if (
            not self._active
            or draft is None
            or self._regeneration_pending
        ):
            return
        self._regeneration_pending = True
        self._insert_button.setEnabled(False)
        self._copy_button.setEnabled(False)
        self._regenerate_button.setEnabled(False)
        self._regenerate_button.setText("Regenerating…")
        self.regenerate_requested.emit(draft)

    def _cancel(self) -> None:
        draft = self._draft
        run_id = draft.provenance.run_id if draft is not None else ""
        was_active = self._active
        self.clear_sensitive()
        self.hide()
        if was_active:
            self.cancelled.emit(run_id)

    def _set_actions_enabled(self, enabled: bool) -> None:
        self._insert_button.setEnabled(enabled)
        self._copy_button.setEnabled(enabled)
        self._regenerate_button.setEnabled(enabled)
        self._cancel_button.setEnabled(enabled)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._cancel()
        event.accept()
