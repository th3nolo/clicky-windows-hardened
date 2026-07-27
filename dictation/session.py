"""Thread-safe dictation state and shared turn ownership."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from typing import Protocol, TypeVar

from capability_registry import CapabilityGrant, CapabilityId
from dictation.models import (
    DictationCommit,
    DictationSession,
    DictationSnapshot,
    DictationState,
    validate_final_transcript,
    validate_result_code,
)
from dictation.policy import (
    TargetDecision,
    blocked_result_code,
    user_visible_reason,
)
from dictation.targeting import SecureTargetGuard
from feature_gates import (
    DEFAULT_BUILD_FEATURE_FLAGS,
    ActionCapability,
    ActionPermissionConfiguration,
    BuildFeatureFlag,
    action_capability_allowed,
    build_feature_available,
    user_permission_allowed,
)
from privacy_controls import microphone_allowed
from turn_coordinator import TurnCoordinator


StateCallback = Callable[[DictationSnapshot], object]
T = TypeVar("T")


class DictationTargetBlocked(RuntimeError):
    """Safe user-facing target denial without UI text or dictated content."""

    def __init__(self, decision: TargetDecision) -> None:
        self.decision = decision
        super().__init__(user_visible_reason(decision.reason))


class DictationConfiguration(ActionPermissionConfiguration, Protocol):
    microphone_consent: bool


class DictationSessionCoordinator:
    """Own dictation state while sharing one microphone turn coordinator."""

    def __init__(
        self,
        turns: TurnCoordinator,
        *,
        targets: SecureTargetGuard | None = None,
        on_state: StateCallback | None = None,
        build_flags: Mapping[
            ActionCapability, BuildFeatureFlag
        ] = DEFAULT_BUILD_FEATURE_FLAGS,
    ) -> None:
        self._turns = turns
        self._targets = targets
        self._on_state = on_state
        self._build_flags = build_flags
        self._lock = threading.RLock()
        self._active: DictationSession | None = None
        self._requested_cancel_codes: dict[str, str] = {}

    @property
    def active(self) -> DictationSession | None:
        with self._lock:
            return self._active

    def snapshot(self) -> DictationSnapshot:
        with self._lock:
            if self._active is None:
                return DictationSnapshot(None, DictationState.IDLE)
            return self._active.snapshot()

    def begin_capture(
        self,
        config: DictationConfiguration,
    ) -> DictationSession | None:
        """Create the per-run grant from an explicit dictation-hotkey press."""
        capability = ActionCapability.GLOBAL_DICTATION
        if (
            not build_feature_available(capability, self._build_flags)
            or not user_permission_allowed(config, capability)
            or not microphone_allowed(config)
        ):
            raise PermissionError(
                "Global Dictation is unavailable or not permitted"
            )
        if self._targets is None:
            raise RuntimeError("Secure dictation target inspection is unavailable")
        target_decision = self._targets.capture()
        if not target_decision.allowed or target_decision.lease is None:
            raise DictationTargetBlocked(target_decision)
        turn = self._turns.start_capture()
        if turn is None:
            return None
        run_id = f"dictation-{turn.sequence}"
        grant = CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(
                {CapabilityId.DICTATION_INSERT_TEXT}
            ),
        )
        if not action_capability_allowed(
            config,
            capability,
            grant=grant,
            run_id=run_id,
            build_flags=self._build_flags,
        ):
            self._turns.complete(turn)
            raise PermissionError(
                "Global Dictation is unavailable or not permitted"
            )

        session = DictationSession(
            run_id=run_id,
            turn=turn,
            grant=grant,
            target=target_decision.lease,
        )
        with self._lock:
            self._active = session
        self._turns.bind_cancel(
            turn,
            "dictation-session-state",
            lambda: self._mark_cancelled(
                session,
                self._take_cancel_code(session),
            ),
        )
        self._publish(session)
        return session

    def release_capture(self, session: DictationSession) -> bool:
        if not self._turns.release_capture(session.turn):
            return False
        return self._transition_if_current(
            session,
            DictationState.FINALIZING,
        )

    def accept_final_transcript(
        self,
        session: DictationSession,
        transcript: str,
    ) -> bool:
        final = validate_final_transcript(transcript)

        def accept() -> None:
            with self._lock:
                if (
                    self._active is not session
                    or session.state is not DictationState.FINALIZING
                ):
                    raise ValueError(
                        "Only the current finalizing session accepts a transcript"
                    )
                session.final_transcript = final
                session.transition(DictationState.READY_TO_COMMIT)
                self._publish_locked(session)

        ran, _ = self._turns.run_if_current(session.turn, accept)
        return ran

    def begin_commit(
        self,
        session: DictationSession,
    ) -> DictationCommit | None:
        def ready() -> bool:
            with self._lock:
                return (
                    self._active is session
                    and session.state is DictationState.READY_TO_COMMIT
                    and session.final_transcript is not None
                )

        current, is_ready = self._turns.run_if_current(
            session.turn,
            ready,
        )
        if not current or not is_ready:
            return None
        if self._targets is None:
            self.fail(session, "blocked_inspector_error")
            return None
        target_decision = self._targets.revalidate(session.target)
        if not target_decision.allowed or target_decision.lease is None:
            self.fail(
                session,
                blocked_result_code(target_decision.reason),
            )
            return None
        commit: list[DictationCommit] = []

        def prepare() -> None:
            with self._lock:
                if (
                    self._active is not session
                    or session.state is not DictationState.READY_TO_COMMIT
                    or session.final_transcript is None
                ):
                    return
                session.target = target_decision.lease
                session.transition(DictationState.COMMITTING)
                commit.append(
                    DictationCommit(
                        run_id=session.run_id,
                        turn=session.turn,
                        grant=session.grant,
                        target=session.target,
                        transcript=session.final_transcript,
                    )
                )
                self._publish_locked(session)

        ran, _ = self._turns.run_if_current(session.turn, prepare)
        return commit[0] if ran and commit else None

    def commit_is_current(self, commit: DictationCommit) -> bool:
        with self._lock:
            matches = (
                self._active is not None
                and self._active.run_id == commit.run_id
                and self._active.state is DictationState.COMMITTING
            )
        return matches and self._turns.is_current(commit.turn)

    def complete_commit(self, session: DictationSession) -> bool:
        def complete() -> None:
            with self._lock:
                if (
                    self._active is not session
                    or session.state is not DictationState.COMMITTING
                ):
                    raise ValueError(
                        "Only the current committing session can complete"
                    )
                session.transition(
                    DictationState.COMPLETED,
                    result_code="completed",
                )
                session.final_transcript = None
                self._publish_locked(session)

        return self._turns.complete(session.turn, complete)

    def execute_commit(
        self,
        commit: DictationCommit,
        callback: Callable[[], T],
    ) -> tuple[bool, T | None]:
        """Run one owned insertion and close its turn before cancellation races."""

        def execute() -> T | None:
            with self._lock:
                session = self._active
                if (
                    session is None
                    or session.run_id != commit.run_id
                    or session.state is not DictationState.COMMITTING
                ):
                    return None
            try:
                outcome = callback()
                terminal_success = (
                    getattr(outcome, "terminal_success", False) is True
                )
                result_code = getattr(
                    outcome,
                    "result_code",
                    "insertion_failed",
                )
                validate_result_code(result_code)
            except Exception:
                outcome = None
                terminal_success = False
                result_code = "insertion_exception"

            with self._lock:
                if (
                    self._active is not session
                    or session.state is not DictationState.COMMITTING
                ):
                    return None
                session.transition(
                    (
                        DictationState.COMPLETED
                        if terminal_success
                        else DictationState.FAILED
                    ),
                    result_code=result_code,
                )
                session.final_transcript = None
                self._publish_locked(session)
            if not self._turns.complete(commit.turn):
                return None
            return outcome

        return self._turns.run_if_current(commit.turn, execute)

    def fail(
        self,
        session: DictationSession,
        result_code: str,
    ) -> bool:
        validate_result_code(result_code)

        def mark_failed() -> None:
            with self._lock:
                if self._active is not session or session.terminal:
                    return
                session.transition(
                    DictationState.FAILED,
                    result_code=result_code,
                )
                self._publish_locked(session)

        return self._turns.complete(session.turn, mark_failed)

    def cancel(
        self,
        session: DictationSession,
        result_code: str = "cancelled",
    ) -> bool:
        validate_result_code(result_code)
        with self._lock:
            if self._active is not session or session.terminal:
                return False
            self._requested_cancel_codes[session.run_id] = result_code
        cancelled = self._turns.cancel(
            session.turn,
        )
        if not cancelled:
            with self._lock:
                self._requested_cancel_codes.pop(session.run_id, None)
        return cancelled

    def _transition_if_current(
        self,
        session: DictationSession,
        state: DictationState,
    ) -> bool:
        def transition() -> None:
            with self._lock:
                if self._active is not session or session.terminal:
                    return
                session.transition(state)
                self._publish_locked(session)

        ran, _ = self._turns.run_if_current(session.turn, transition)
        return ran

    def _mark_cancelled(
        self,
        session: DictationSession,
        result_code: str,
    ) -> None:
        with self._lock:
            if self._active is not session or session.terminal:
                return
            session.transition(
                DictationState.CANCELLED,
                result_code=result_code,
            )
            self._publish_locked(session)

    def _take_cancel_code(self, session: DictationSession) -> str:
        with self._lock:
            return self._requested_cancel_codes.pop(
                session.run_id,
                "superseded",
            )

    def _publish(self, session: DictationSession) -> None:
        with self._lock:
            self._publish_locked(session)

    def _publish_locked(self, session: DictationSession) -> None:
        if self._on_state is not None:
            self._on_state(session.snapshot())
