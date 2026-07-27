"""Typed states and values for one global dictation session."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from capability_registry import CapabilityGrant
from dictation.policy import TargetLease
from turn_coordinator import TurnSession


MAX_FINAL_TRANSCRIPT_CHARS = 32 * 1024
MAX_RESULT_CODE_CHARS = 96


class DictationState(str, Enum):
    IDLE = "idle"
    CAPTURING = "capturing"
    FINALIZING = "finalizing"
    READY_TO_COMMIT = "ready_to_commit"
    COMMITTING = "committing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_DICTATION_STATES = frozenset(
    {
        DictationState.COMPLETED,
        DictationState.CANCELLED,
        DictationState.FAILED,
    }
)

_ALLOWED_TRANSITIONS = {
    DictationState.CAPTURING: frozenset(
        {
            DictationState.FINALIZING,
            DictationState.CANCELLED,
            DictationState.FAILED,
        }
    ),
    DictationState.FINALIZING: frozenset(
        {
            DictationState.READY_TO_COMMIT,
            DictationState.CANCELLED,
            DictationState.FAILED,
        }
    ),
    DictationState.READY_TO_COMMIT: frozenset(
        {
            DictationState.COMMITTING,
            DictationState.CANCELLED,
            DictationState.FAILED,
        }
    ),
    DictationState.COMMITTING: frozenset(
        {
            DictationState.COMPLETED,
            DictationState.CANCELLED,
            DictationState.FAILED,
        }
    ),
}


@dataclass(frozen=True, slots=True)
class DictationSnapshot:
    run_id: str | None
    state: DictationState
    result_code: str | None = None


@dataclass(frozen=True, slots=True)
class DictationCommit:
    run_id: str
    turn: TurnSession
    grant: CapabilityGrant
    target: TargetLease = field(repr=False)
    transcript: str = field(repr=False)


@dataclass(slots=True)
class DictationSession:
    run_id: str
    turn: TurnSession
    grant: CapabilityGrant
    target: TargetLease = field(repr=False)
    state: DictationState = DictationState.CAPTURING
    final_transcript: str | None = field(default=None, repr=False)
    result_code: str | None = None

    def snapshot(self) -> DictationSnapshot:
        return DictationSnapshot(
            run_id=self.run_id,
            state=self.state,
            result_code=self.result_code,
        )

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_DICTATION_STATES

    def transition(
        self,
        state: DictationState,
        *,
        result_code: str | None = None,
    ) -> None:
        if state not in _ALLOWED_TRANSITIONS.get(self.state, frozenset()):
            raise ValueError(
                f"Invalid dictation transition: {self.state.value} "
                f"to {state.value}"
            )
        if result_code is not None:
            validate_result_code(result_code)
        self.state = state
        self.result_code = result_code
        if state in {
            DictationState.CANCELLED,
            DictationState.FAILED,
        }:
            self.final_transcript = None


def validate_final_transcript(transcript: str) -> str:
    if not isinstance(transcript, str):
        raise TypeError("Final transcript must be text")
    if not transcript or len(transcript) > MAX_FINAL_TRANSCRIPT_CHARS:
        raise ValueError("Final transcript is empty or exceeds the size limit")
    if any(
        ord(character) < 32 and character not in "\n\t"
        for character in transcript
    ):
        raise ValueError("Final transcript contains unsupported control text")
    return transcript


def validate_result_code(result_code: str) -> str:
    if (
        not isinstance(result_code, str)
        or not result_code
        or len(result_code) > MAX_RESULT_CODE_CHARS
        or not result_code.isprintable()
    ):
        raise ValueError("Dictation result code must be bounded metadata")
    return result_code
