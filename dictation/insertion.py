"""Exactly-once, truthfully classified dictation insertion broker."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Protocol

from dictation.models import DictationCommit, MAX_FINAL_TRANSCRIPT_CHARS
from dictation.policy import TargetLease
from dictation.session import DictationSessionCoordinator
from dictation.targeting import SecureTargetGuard
from feature_gates import MAX_RUN_ID_LENGTH


class InsertionIntent(str, Enum):
    INSERT_AT_SELECTION = "insert_at_selection"
    REPLACE_WHOLE_VALUE = "replace_whole_value"


class InsertionStatus(str, Enum):
    VERIFIED_INSERTED = "verified_inserted"
    ATTEMPTED_UNVERIFIED = "attempted_unverified"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


class InsertionAdapterKind(str, Enum):
    REVIEWED_APPLICATION_API = "reviewed_application_api"
    UIA_VALUE_REPLACE = "uia_value_replace"
    UNICODE_SEND_INPUT = "unicode_send_input"
    CLIPBOARD_PASTE = "clipboard_paste"
    PREVIEW_COPY = "preview_copy"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class MutationOutcome:
    attempted: bool
    succeeded: bool
    verified: bool = False
    clipboard_restored: bool | None = None
    clipboard_changed_externally: bool | None = None

    def __post_init__(self) -> None:
        for value in (
            self.attempted,
            self.succeeded,
            self.verified,
        ):
            if type(value) is not bool:
                raise TypeError("Mutation truth values must be booleans")
        for value in (
            self.clipboard_restored,
            self.clipboard_changed_externally,
        ):
            if value is not None and type(value) is not bool:
                raise TypeError(
                    "Clipboard truth values must be booleans or unknown"
                )
        if self.verified and not self.succeeded:
            raise ValueError("A failed mutation cannot be verified")
        if self.succeeded and not self.attempted:
            raise ValueError("A successful mutation must have been attempted")


@dataclass(frozen=True, slots=True)
class CopyPreview:
    run_id: str
    application_name: str
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class InsertionRequest:
    commit: DictationCommit = field(repr=False)
    intent: InsertionIntent = InsertionIntent.INSERT_AT_SELECTION
    clipboard_fallback_approved: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.commit, DictationCommit):
            raise TypeError("Insertion requires a dictation commit token")
        if not isinstance(self.intent, InsertionIntent):
            raise TypeError("Insertion intent is invalid")
        if type(self.clipboard_fallback_approved) is not bool:
            raise TypeError("Clipboard approval must be explicit")


@dataclass(frozen=True, slots=True)
class ExplicitInsertionRequest:
    """Text insertion authorized by a reviewed caller outside dictation."""

    run_id: str
    target: TargetLease = field(repr=False)
    text: str = field(repr=False)
    intent: InsertionIntent = InsertionIntent.INSERT_AT_SELECTION
    clipboard_fallback_approved: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or len(self.run_id) > MAX_RUN_ID_LENGTH
            or self.run_id.strip() != self.run_id
            or not self.run_id.isprintable()
        ):
            raise ValueError("Explicit insertion run ID is invalid")
        if not isinstance(self.target, TargetLease):
            raise TypeError("Explicit insertion requires a target lease")
        if (
            not isinstance(self.text, str)
            or not self.text.strip()
            or len(self.text) > MAX_FINAL_TRANSCRIPT_CHARS
            or any(
                ord(character) < 32 and character not in "\n\t"
                for character in self.text
            )
        ):
            raise ValueError("Explicit insertion text is invalid")
        if not isinstance(self.intent, InsertionIntent):
            raise TypeError("Insertion intent is invalid")
        if type(self.clipboard_fallback_approved) is not bool:
            raise TypeError("Clipboard approval must be explicit")


@dataclass(frozen=True, slots=True)
class InsertionResult:
    status: InsertionStatus
    adapter: InsertionAdapterKind
    result_code: str
    application_name: str | None = None
    clipboard_restored: bool | None = None
    clipboard_changed_externally: bool | None = None
    preview: CopyPreview | None = field(default=None, repr=False)

    @property
    def terminal_success(self) -> bool:
        return self.status in {
            InsertionStatus.VERIFIED_INSERTED,
            InsertionStatus.ATTEMPTED_UNVERIFIED,
        }


@dataclass(frozen=True, slots=True)
class CopyResult:
    copied: bool
    result_code: str


@dataclass(frozen=True, slots=True)
class _InsertionSubject:
    run_id: str
    target: TargetLease = field(repr=False)
    text: str = field(repr=False)


class ReviewedApplicationAdapter(Protocol):
    def supports(
        self,
        target: TargetLease,
        intent: InsertionIntent,
    ) -> bool: ...

    def insert(
        self,
        target: TargetLease,
        text: str,
        intent: InsertionIntent,
    ) -> MutationOutcome: ...


class InsertionBackend(Protocol):
    def value_pattern_available(self, target: TargetLease) -> bool: ...

    def replace_whole_value(
        self,
        target: TargetLease,
        text: str,
    ) -> MutationOutcome: ...

    def unicode_input_available(self, target: TargetLease) -> bool: ...

    def send_unicode(
        self,
        target: TargetLease,
        text: str,
    ) -> MutationOutcome: ...

    def clipboard_paste_available(self, target: TargetLease) -> bool: ...

    def paste_via_clipboard(
        self,
        target: TargetLease,
        text: str,
    ) -> MutationOutcome: ...

    def copy_text(self, text: str) -> bool: ...


class InsertionBroker:
    """Select one ordered adapter and never retry a mutation implicitly."""

    def __init__(
        self,
        sessions: DictationSessionCoordinator,
        targets: SecureTargetGuard,
        backend: InsertionBackend,
        *,
        application_adapters: tuple[
            ReviewedApplicationAdapter, ...
        ] = (),
    ) -> None:
        self._sessions = sessions
        self._targets = targets
        self._backend = backend
        self._application_adapters = application_adapters
        self._lock = threading.Lock()
        self._mutation_lock = threading.Lock()
        self._claimed_runs: set[str] = set()
        self._pending_previews: dict[str, CopyPreview] = {}

    def insert(self, request: InsertionRequest) -> InsertionResult:
        commit = request.commit
        subject = _InsertionSubject(
            run_id=commit.run_id,
            target=commit.target,
            text=commit.transcript,
        )
        if not self._claim(subject.run_id):
            return _result(
                InsertionStatus.BLOCKED,
                InsertionAdapterKind.NONE,
                "insertion_duplicate_blocked",
                subject,
            )

        if not self._sessions.commit_is_current(commit):
            return _result(
                InsertionStatus.BLOCKED,
                InsertionAdapterKind.NONE,
                "insertion_stale_blocked",
                subject,
            )

        ran, outcome = self._sessions.execute_commit(
            commit,
            lambda: self._safe_insert(
                subject,
                request.intent,
                request.clipboard_fallback_approved,
            ),
        )
        if not ran or outcome is None:
            return _result(
                InsertionStatus.BLOCKED,
                InsertionAdapterKind.NONE,
                "insertion_stale_blocked",
                subject,
            )
        self._store_preview(subject.run_id, outcome)
        return outcome

    def insert_explicit(
        self,
        request: ExplicitInsertionRequest,
    ) -> InsertionResult:
        """Execute one caller-approved request through the same adapters."""

        if not isinstance(request, ExplicitInsertionRequest):
            raise TypeError("Explicit insertion requires a typed request")
        subject = _InsertionSubject(
            run_id=request.run_id,
            target=request.target,
            text=request.text,
        )
        if not self._claim(subject.run_id):
            return _result(
                InsertionStatus.BLOCKED,
                InsertionAdapterKind.NONE,
                "insertion_duplicate_blocked",
                subject,
            )
        outcome = self._safe_insert(
            subject,
            request.intent,
            request.clipboard_fallback_approved,
        )
        self._store_preview(subject.run_id, outcome)
        return outcome

    def _claim(self, run_id: str) -> bool:
        with self._lock:
            if run_id in self._claimed_runs:
                return False
            self._claimed_runs.add(run_id)
            return True

    def _safe_insert(
        self,
        subject: _InsertionSubject,
        intent: InsertionIntent,
        clipboard_fallback_approved: bool,
    ) -> InsertionResult:
        with self._mutation_lock:
            try:
                outcome = self._insert_target_text(
                    subject,
                    intent,
                    clipboard_fallback_approved,
                )
            except Exception:
                outcome = _result(
                    InsertionStatus.FAILED,
                    InsertionAdapterKind.NONE,
                    "insertion_backend_failed",
                    subject,
                )
            if not outcome.terminal_success and outcome.preview is None:
                outcome = replace(
                    outcome,
                    preview=CopyPreview(
                        run_id=subject.run_id,
                        application_name=subject.target.application_name,
                        text=subject.text,
                    ),
                )
            return outcome

    def _insert_target_text(
        self,
        subject: _InsertionSubject,
        intent: InsertionIntent,
        clipboard_fallback_approved: bool,
    ) -> InsertionResult:
        target_decision = self._targets.revalidate(subject.target)
        if not target_decision.allowed or target_decision.lease is None:
            return _result(
                InsertionStatus.BLOCKED,
                InsertionAdapterKind.NONE,
                f"insertion_target_{target_decision.reason.value}",
                subject,
            )
        target = target_decision.lease

        for adapter in self._application_adapters:
            if adapter.supports(target, intent):
                return _mutation_result(
                    adapter.insert(target, subject.text, intent),
                    InsertionAdapterKind.REVIEWED_APPLICATION_API,
                    subject,
                )

        if (
            intent is InsertionIntent.REPLACE_WHOLE_VALUE
            and self._backend.value_pattern_available(target)
        ):
            return _mutation_result(
                self._backend.replace_whole_value(
                    target,
                    subject.text,
                ),
                InsertionAdapterKind.UIA_VALUE_REPLACE,
                subject,
            )

        if (
            intent is InsertionIntent.INSERT_AT_SELECTION
            and self._backend.unicode_input_available(target)
        ):
            return _mutation_result(
                self._backend.send_unicode(target, subject.text),
                InsertionAdapterKind.UNICODE_SEND_INPUT,
                subject,
            )

        if (
            intent is InsertionIntent.INSERT_AT_SELECTION
            and clipboard_fallback_approved
            and self._backend.clipboard_paste_available(target)
        ):
            return _mutation_result(
                self._backend.paste_via_clipboard(
                    target,
                    subject.text,
                ),
                InsertionAdapterKind.CLIPBOARD_PASTE,
                subject,
            )

        preview = CopyPreview(
            run_id=subject.run_id,
            application_name=target.application_name,
            text=subject.text,
        )
        return _result(
            InsertionStatus.UNSUPPORTED,
            InsertionAdapterKind.PREVIEW_COPY,
            "insertion_unsupported",
            subject,
            preview=preview,
        )

    def _store_preview(
        self,
        run_id: str,
        outcome: InsertionResult,
    ) -> None:
        if outcome.preview is not None:
            with self._lock:
                self._pending_previews[run_id] = outcome.preview

    def copy_preview(self, preview: CopyPreview) -> CopyResult:
        if not isinstance(preview, CopyPreview):
            return CopyResult(False, "copy_preview_invalid")
        with self._lock:
            if self._pending_previews.get(preview.run_id) is not preview:
                return CopyResult(False, "copy_preview_already_used")
            self._pending_previews.pop(preview.run_id, None)
        try:
            copied = self._backend.copy_text(preview.text)
        except Exception:
            copied = False
        return CopyResult(
            copied,
            (
                "copy_preview_copied"
                if copied
                else "copy_preview_failed"
            ),
        )

    def discard_preview(self, preview: CopyPreview) -> bool:
        """Forget one recovery copy without touching any external state."""

        if not isinstance(preview, CopyPreview):
            return False
        with self._lock:
            if self._pending_previews.get(preview.run_id) is not preview:
                return False
            self._pending_previews.pop(preview.run_id, None)
            return True


def _mutation_result(
    outcome: MutationOutcome,
    adapter: InsertionAdapterKind,
    subject: _InsertionSubject,
) -> InsertionResult:
    if not outcome.attempted or not outcome.succeeded:
        status = InsertionStatus.FAILED
        suffix = "failed"
    elif outcome.verified:
        status = InsertionStatus.VERIFIED_INSERTED
        suffix = "verified"
    else:
        status = InsertionStatus.ATTEMPTED_UNVERIFIED
        suffix = "attempted_unverified"
    return _result(
        status,
        adapter,
        f"insertion_{adapter.value}_{suffix}",
        subject,
        clipboard_restored=outcome.clipboard_restored,
        clipboard_changed_externally=(
            outcome.clipboard_changed_externally
        ),
    )


def _result(
    status: InsertionStatus,
    adapter: InsertionAdapterKind,
    result_code: str,
    subject: _InsertionSubject,
    *,
    clipboard_restored: bool | None = None,
    clipboard_changed_externally: bool | None = None,
    preview: CopyPreview | None = None,
) -> InsertionResult:
    return InsertionResult(
        status=status,
        adapter=adapter,
        result_code=result_code,
        application_name=subject.target.application_name,
        clipboard_restored=clipboard_restored,
        clipboard_changed_externally=clipboard_changed_externally,
        preview=preview,
    )
