"""Build-gated routing from one reviewed region to Compose preview."""

from __future__ import annotations

import asyncio
import hashlib
import math
import time
from collections.abc import Callable, Mapping

from PyQt6.QtCore import QObject, QTimer, Qt, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from capability_registry import CapabilityGrant, CapabilityId
from compose.models import (
    DEFAULT_DRAFT_CHARS,
    ComposeInvocation,
    ComposeProviderSelection,
    Draft,
    DraftInsertionApproval,
)
from compose.region_context import ReviewedRegionCaptureGateway
from dictation.policy import TargetDecision, TargetLease
from feature_gates import (
    DEFAULT_BUILD_FEATURE_FLAGS,
    ActionCapability,
    BuildFeatureFlag,
    action_capability_allowed,
)
from handoff.models import HandoffDestination
from handoff.routing import HandoffRouteContext
from privacy_controls import screen_capture_allowed
from turn_coordinator import TurnCoordinator, TurnSession
from ui.compose_preview import ComposePreviewPanel


TARGET_POLL_INTERVAL_MS = 250
TARGET_STABLE_OBSERVATIONS = 3


class ComposeRegionRouteError(RuntimeError):
    """A region could not enter the gated Compose caller safely."""


class ComposeTargetPicker(QWidget):
    """Non-activating status UI for explicit editable-target acquisition."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Choose the Compose destination")
        self.setWindowFlags(
            Qt.WindowType.Tool
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.WindowDoesNotAcceptFocus
        )
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setAcceptDrops(False)
        self.setMinimumWidth(440)
        self.setStyleSheet(
            "QWidget { background: #101827; color: #eef3ff; }"
            "QLabel { background: transparent; padding: 4px; }"
        )
        layout = QVBoxLayout(self)
        self._title = self._label(
            "Focus the exact editable field for this draft."
        )
        self._title.setStyleSheet(
            "font-size: 15px; font-weight: 600; padding: 4px;"
        )
        layout.addWidget(self._title)
        self._status = self._label("")
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        self.hide()

    @staticmethod
    def _label(text: str) -> QLabel:
        label = QLabel(text)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        return label

    def show_waiting(self) -> None:
        self._status.setText(
            "Click the intended ordinary text field. Clicky binds only an "
            "allowed field that remains focused for a short countdown. "
            "Press Escape to cancel."
        )
        self._show_without_activation()

    def show_candidate(
        self,
        application_name: str,
        target_type: str,
        observation: int,
    ) -> None:
        self._status.setText(
            f"Candidate: {application_name} ({target_type}). "
            f"Keep it focused: {observation}/"
            f"{TARGET_STABLE_OBSERVATIONS}. Escape cancels."
        )
        self._show_without_activation()

    def show_generating(self, application_name: str) -> None:
        self._status.setText(
            f"Destination bound: {application_name}. Creating one draft "
            "from the reviewed region. Nothing is being inserted or sent."
        )
        self._show_without_activation()

    def clear_sensitive(self) -> None:
        self._status.clear()
        self.hide()

    def _show_without_activation(self) -> None:
        self.adjustSize()
        screen = self.screen()
        if screen is not None:
            area = screen.availableGeometry()
            self.move(
                area.right() - self.width() - 24,
                area.bottom() - self.height() - 74,
            )
        self.show()


class ComposeRegionHandoffController(QObject):
    """Acquire one target, generate one draft, then await explicit review."""

    failed = pyqtSignal(str)
    draft_shown = pyqtSignal(str)
    copy_finished = pyqtSignal(str, bool)
    insertion_finished = pyqtSignal(str, str)
    _draft_ready = pyqtSignal(object, object, object, object)
    _generation_failed = pyqtSignal(object, str)
    _cancel_ui = pyqtSignal(object)

    def __init__(
        self,
        turns: TurnCoordinator,
        *,
        targets,
        service_factory: Callable[[object], object],
        insertion_service,
        provider_selection: Callable[[], ComposeProviderSelection],
        response_language: Callable[[], str],
        submit: Callable[[object, TurnSession], object],
        config_provider: Callable[[], object],
        clock: Callable[[], float] = time.monotonic,
        clipboard_writer: Callable[[str], bool] | None = None,
        build_flags: Mapping[
            ActionCapability, BuildFeatureFlag
        ] = DEFAULT_BUILD_FEATURE_FLAGS,
        preview: ComposePreviewPanel | None = None,
        picker: ComposeTargetPicker | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(turns, TurnCoordinator):
            raise TypeError("Compose region turn coordinator is invalid")
        if (
            not callable(getattr(targets, "capture", None))
            or not callable(getattr(targets, "revalidate", None))
        ):
            raise TypeError("Compose region target guard is invalid")
        for callback, label in (
            (service_factory, "service factory"),
            (provider_selection, "provider selection"),
            (response_language, "response language"),
            (submit, "turn submission"),
            (config_provider, "configuration"),
            (clock, "clock"),
        ):
            if not callable(callback):
                raise TypeError(
                    f"Compose region {label} callback is invalid"
                )
        if not callable(getattr(insertion_service, "insert", None)):
            raise TypeError("Compose region insertion service is invalid")
        if not isinstance(build_flags, Mapping):
            raise TypeError("Compose region build flags are invalid")
        self._turns = turns
        self._targets = targets
        self._service_factory = service_factory
        self._insertion = insertion_service
        self._provider_selection = provider_selection
        self._response_language = response_language
        self._submit = submit
        self._config_provider = config_provider
        self._clock = clock
        self._clipboard_writer = (
            clipboard_writer or _write_clipboard
        )
        self._build_flags = build_flags
        self._preview = preview or ComposePreviewPanel(targets)
        self._picker = picker or ComposeTargetPicker()
        self._poll = QTimer(self)
        self._poll.setInterval(TARGET_POLL_INTERVAL_MS)
        self._poll.timeout.connect(self._poll_target)
        self._session: TurnSession | None = None
        self._context: HandoffRouteContext | None = None
        self._grant: CapabilityGrant | None = None
        self._provider: ComposeProviderSelection | None = None
        self._service = None
        self._request = None
        self._target: TargetLease | None = None
        self._candidate_key: tuple[object, ...] | None = None
        self._candidate_count = 0
        self._response_language_value = ""
        self._preview.insert_approved.connect(
            self._insert_approved
        )
        self._preview.copy_requested.connect(
            self._copy_requested
        )
        self._preview.cancelled.connect(
            self._preview_cancelled
        )
        self._draft_ready.connect(self._show_draft)
        self._generation_failed.connect(
            self._handle_generation_failure
        )
        self._cancel_ui.connect(self._clear_cancelled_ui)

    @property
    def active(self) -> bool:
        session = self._session
        return bool(
            session is not None
            and self._turns.is_current(session)
        )

    def route(self, context: HandoffRouteContext) -> str:
        """Accept one Compose destination and wait for an explicit target."""

        if (
            not isinstance(context, HandoffRouteContext)
            or context.destination
            is not HandoffDestination.COMPOSE_PREVIEW
        ):
            if isinstance(context, HandoffRouteContext):
                context.wipe()
            raise TypeError("Compose region route is invalid")
        if self.active:
            context.wipe()
            raise ComposeRegionRouteError(
                "Finish or cancel the current Compose draft first"
            )
        if self._session is not None:
            self._clear_state()
        try:
            provider = self._provider_selection()
            if not isinstance(provider, ComposeProviderSelection):
                raise TypeError("Compose provider selection is invalid")
            language = self._response_language()
            if not isinstance(language, str) or not language.strip():
                raise TypeError("Compose response language is invalid")
            run_id = (
                "compose-"
                + hashlib.sha256(
                    context.route_id.encode("utf-8")
                ).hexdigest()
            )
            grant = CapabilityGrant(
                run_id,
                frozenset(
                    {CapabilityId.COMPOSE_SCREEN_CONTEXT}
                ),
            )
            config = self._config_provider()
            if (
                not action_capability_allowed(
                    config,
                    ActionCapability.SCREEN_AWARE_COMPOSE,
                    grant=grant,
                    run_id=run_id,
                    build_flags=self._build_flags,
                )
                or not screen_capture_allowed(config)
            ):
                raise ComposeRegionRouteError(
                    "Screen-Aware Compose is unavailable or not permitted"
                )
        except ComposeRegionRouteError:
            context.wipe()
            raise
        except Exception:
            context.wipe()
            raise ComposeRegionRouteError(
                "Compose provider or permission setup is unavailable"
            ) from None

        session = self._turns.start_processing()
        if session is None:
            context.wipe()
            raise ComposeRegionRouteError(
                "Finish or stop the current Clicky turn before Compose"
            )
        self._session = session
        self._context = context
        self._grant = grant
        self._provider = provider
        self._response_language_value = language.strip()
        self._candidate_key = None
        self._candidate_count = 0
        self._turns.bind_cancel(
            session,
            "compose-region",
            lambda: self._cancel_from_turn(session),
        )
        self._picker.show_waiting()
        self._poll.start()
        return f"compose-region-{session.sequence}"

    @pyqtSlot()
    def _poll_target(self) -> None:
        session = self._session
        context = self._context
        if (
            session is None
            or context is None
            or not self._turns.is_current(session)
        ):
            self._clear_state()
            return
        try:
            now = float(self._clock())
        except Exception:
            self._fail_current(
                "Compose target selection could not continue."
            )
            return
        if (
            not math.isfinite(now)
            or now < 0
            or now >= context.expires_at
        ):
            self._fail_current(
                "The reviewed region expired before a destination was bound."
            )
            return
        try:
            decision = self._targets.capture()
        except Exception:
            decision = None
        if (
            not isinstance(decision, TargetDecision)
            or not decision.allowed
            or decision.lease is None
        ):
            self._candidate_key = None
            self._candidate_count = 0
            self._picker.show_waiting()
            return
        lease = decision.lease
        descriptor = lease.descriptor
        key = (
            descriptor.identity_key
            + descriptor.focus_key
            + descriptor.policy_key
        )
        if key == self._candidate_key:
            self._candidate_count += 1
        else:
            self._candidate_key = key
            self._candidate_count = 1
        target_type = (
            f"{descriptor.framework_id}:{descriptor.control_type}"
        )
        self._picker.show_candidate(
            descriptor.application_name,
            target_type,
            self._candidate_count,
        )
        if self._candidate_count >= TARGET_STABLE_OBSERVATIONS:
            self._poll.stop()
            self._begin_generation(lease)

    def _begin_generation(self, target: TargetLease) -> None:
        session = self._session
        context = self._context
        grant = self._grant
        provider = self._provider
        if (
            session is None
            or context is None
            or grant is None
            or provider is None
            or not self._turns.is_current(session)
        ):
            self._fail_current(
                "Compose region context became unavailable."
            )
            return
        try:
            current_provider = self._provider_selection()
            if current_provider != provider:
                raise ComposeRegionRouteError(
                    "The selected provider changed before Compose."
                )
            gateway = ReviewedRegionCaptureGateway(
                context,
                clock=self._clock,
            )
            service = self._service_factory(gateway)
            if (
                not callable(getattr(service, "prepare_request", None))
                or not callable(getattr(service, "generate_draft", None))
            ):
                raise TypeError("Compose service is invalid")
            invocation = ComposeInvocation(
                run_id=grant.run_id,
                grant=grant,
                instruction=context.purpose,
                target=target,
                authorized_screenshot_ids=(context.selection_id,),
                provider=provider,
                response_language=self._response_language_value,
                style_profile_id=None,
                max_output_chars=DEFAULT_DRAFT_CHARS,
            )
            request = service.prepare_request(
                invocation,
                self._config_provider(),
            )
            self._service = service
            self._request = request
            self._target = target
            self._picker.show_generating(target.application_name)
            worker = self._generate_draft(
                session,
                service,
                request,
                target,
                grant,
                context.expires_at,
            )
            try:
                future = self._submit(worker, session)
            except Exception:
                close = getattr(worker, "close", None)
                if callable(close):
                    close()
                raise
            if future is None:
                raise ComposeRegionRouteError(
                    "The Compose worker loop is unavailable."
                )
        except Exception:
            context.wipe()
            self._fail_current(
                "Compose could not safely create a request for this target."
            )

    async def _generate_draft(
        self,
        session: TurnSession,
        service,
        request,
        target: TargetLease,
        grant: CapabilityGrant,
        expires_at: float,
    ) -> None:
        try:
            if not self._turns.is_current(session):
                return
            now = float(self._clock())
            if (
                not math.isfinite(now)
                or now < 0
                or now >= expires_at
            ):
                raise ComposeRegionRouteError(
                    "The reviewed region expired before generation."
                )
            draft = await service.generate_draft(
                request,
                self._config_provider(),
            )
            if not isinstance(draft, Draft):
                raise TypeError("Compose service returned an invalid draft")
            if self._turns.is_current(session):
                self._draft_ready.emit(
                    session,
                    draft,
                    target,
                    grant,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            if self._turns.is_current(session):
                self._generation_failed.emit(
                    session,
                    "Compose generation failed without changing the "
                    "destination.",
                )

    @pyqtSlot(object, object, object, object)
    def _show_draft(
        self,
        session: TurnSession,
        draft: Draft,
        target: TargetLease,
        grant: CapabilityGrant,
    ) -> None:
        if (
            session != self._session
            or not self._turns.is_current(session)
            or draft.provenance.run_id != grant.run_id
        ):
            return
        try:
            self._preview.show_region_draft(
                draft,
                target,
                grant,
            )
        except Exception:
            self._fail_current(
                "The Compose draft could not be shown safely."
            )
            return
        self._picker.clear_sensitive()
        self._service = None
        self._request = None
        self._context = None
        self.draft_shown.emit(grant.run_id)

    @pyqtSlot(object, str)
    def _handle_generation_failure(
        self,
        session: TurnSession,
        message: str,
    ) -> None:
        if (
            session == self._session
            and self._turns.is_current(session)
        ):
            self._fail_current(message)

    @pyqtSlot(object)
    def _copy_requested(self, draft: Draft) -> None:
        session = self._session
        if (
            session is None
            or not self._turns.is_current(session)
            or not isinstance(draft, Draft)
            or self._grant is None
            or draft.provenance.run_id != self._grant.run_id
        ):
            return

        def copy_if_current() -> None:
            try:
                copied = self._clipboard_writer(draft.text) is True
            except Exception:
                copied = False
            self._preview.set_copy_result(
                draft.provenance.run_id,
                copied,
            )
            self.copy_finished.emit(
                draft.provenance.run_id,
                copied,
            )

        self._turns.run_if_current(
            session,
            copy_if_current,
        )

    @pyqtSlot(object)
    def _insert_approved(
        self,
        approval: DraftInsertionApproval,
    ) -> None:
        session = self._session
        grant = self._grant
        if (
            session is None
            or not self._turns.is_current(session)
            or grant is None
            or not isinstance(approval, DraftInsertionApproval)
            or approval.run_id != grant.run_id
        ):
            return

        def insert_if_current() -> None:
            try:
                result = self._insertion.insert(
                    approval,
                    self._config_provider(),
                )
                status = result.status.value
                result_code = result.result_code
            except Exception:
                status = "failed"
                result_code = "compose_insertion_failed"
            self.insertion_finished.emit(status, result_code)
            self._complete_current()

        self._turns.run_if_current(
            session,
            insert_if_current,
        )

    @pyqtSlot(str)
    def _preview_cancelled(self, run_id: str) -> None:
        grant = self._grant
        if (
            grant is not None
            and run_id == grant.run_id
            and self.active
        ):
            self._complete_current()

    def _fail_current(self, message: str) -> None:
        session = self._session
        self.failed.emit(message)
        if session is not None and self._turns.is_current(session):
            self._turns.cancel(session)
        else:
            self._clear_state()

    def _complete_current(self) -> None:
        session = self._session
        self._clear_state()
        if session is not None:
            self._turns.complete(session)

    def _cancel_from_turn(self, session: TurnSession) -> None:
        context = self._context
        if context is not None:
            context.wipe()
        self._cancel_ui.emit(session)

    @pyqtSlot(object)
    def _clear_cancelled_ui(self, session: TurnSession) -> None:
        if session == self._session:
            self._clear_state()

    def _clear_state(self) -> None:
        context = self._context
        if context is not None:
            context.wipe()
        self._poll.stop()
        self._picker.clear_sensitive()
        self._preview.clear_sensitive()
        self._preview.hide()
        self._session = None
        self._context = None
        self._grant = None
        self._provider = None
        self._service = None
        self._request = None
        self._target = None
        self._candidate_key = None
        self._candidate_count = 0
        self._response_language_value = ""


def _write_clipboard(text: str) -> bool:
    if not isinstance(text, str) or not text:
        return False
    application = QApplication.instance()
    if application is None:
        return False
    clipboard = application.clipboard()
    clipboard.setText(text)
    return clipboard.text() == text


__all__ = [
    "ComposeRegionHandoffController",
    "ComposeRegionRouteError",
    "ComposeTargetPicker",
    "TARGET_POLL_INTERVAL_MS",
    "TARGET_STABLE_OBSERVATIONS",
]
