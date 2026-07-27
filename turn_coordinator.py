"""Thread-safe ownership for one user-visible Clicky turn at a time.

Hotkey callbacks, the Qt thread, and the asyncio worker can all race.  This
module gives every capture/response a monotonically increasing identity and
keeps cancellation callbacks behind the same lock as identity changes.  A
superseded turn therefore becomes stale before any of its work is cancelled,
and it cannot emit UI after a replacement turn starts.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
import threading
from typing import Callable, Protocol, TypeVar


class Cancellable(Protocol):
    def cancel(self) -> object: ...


class TurnPhase(Enum):
    IDLE = auto()
    CAPTURING = auto()
    PROCESSING = auto()
    SPEAKING = auto()


@dataclass(frozen=True, slots=True)
class TurnSession:
    sequence: int


T = TypeVar("T")
CancelCallback = Callable[[], object]


class TurnCoordinator:
    """Own the current turn and all resources that must stop with it."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._next_sequence = 1
        self._active: TurnSession | None = None
        self._phase = TurnPhase.IDLE
        self._cancellations: dict[str, CancelCallback] = {}

    @property
    def phase(self) -> TurnPhase:
        with self._lock:
            return self._phase

    @property
    def active(self) -> TurnSession | None:
        with self._lock:
            return self._active

    def is_current(self, session: TurnSession) -> bool:
        with self._lock:
            return self._active == session

    def start_capture(self) -> TurnSession | None:
        """Start one capture, replacing processing/speaking work atomically.

        A repeated press while the same capture is already active is ignored.
        Cancellation callbacks run while the coordinator lock is held, after
        the old identity is invalidated and before the new identity is visible.
        """

        with self._lock:
            if self._phase is TurnPhase.CAPTURING:
                return None
            self._cancel_current_locked()
            return self._new_session_locked(TurnPhase.CAPTURING)

    def start_processing(self) -> TurnSession | None:
        """Start a non-microphone turn only when no other turn is active."""

        with self._lock:
            if self._active is not None:
                return None
            return self._new_session_locked(TurnPhase.PROCESSING)

    def release_capture(self, session: TurnSession) -> bool:
        with self._lock:
            if self._active != session or self._phase is not TurnPhase.CAPTURING:
                return False
            self._phase = TurnPhase.PROCESSING
            return True

    def set_phase(self, session: TurnSession, phase: TurnPhase) -> bool:
        if phase not in (TurnPhase.PROCESSING, TurnPhase.SPEAKING):
            raise ValueError("active turns may transition only to processing or speaking")
        with self._lock:
            if self._active != session:
                return False
            self._phase = phase
            return True

    def bind_cancel(
        self,
        session: TurnSession,
        name: str,
        callback: CancelCallback,
    ) -> bool:
        """Attach a named resource to a turn, cancelling immediately if stale."""

        if not name:
            raise ValueError("cancellation resource name must not be empty")
        with self._lock:
            if self._active != session:
                self._call_cancel(callback)
                return False
            previous = self._cancellations.pop(name, None)
            if previous is not None:
                self._call_cancel(previous)
            self._cancellations[name] = callback
            return True

    def bind_task(
        self,
        session: TurnSession,
        task: Cancellable,
        *,
        name: str = "turn-task",
    ) -> bool:
        return self.bind_cancel(session, name, task.cancel)

    def unbind_cancel(self, session: TurnSession, name: str) -> bool:
        with self._lock:
            if self._active != session:
                return False
            return self._cancellations.pop(name, None) is not None

    def run_if_current(
        self,
        session: TurnSession,
        callback: Callable[..., T],
        *args,
        **kwargs,
    ) -> tuple[bool, T | None]:
        """Run a UI/state mutation while replacement turns are excluded."""

        with self._lock:
            if self._active != session:
                return False, None
            return True, callback(*args, **kwargs)

    def complete(
        self,
        session: TurnSession,
        callback: Callable[[], object] | None = None,
    ) -> bool:
        """Finish only the current turn without invoking cancellation hooks."""

        with self._lock:
            if self._active != session:
                return False
            self._active = None
            self._phase = TurnPhase.IDLE
            self._cancellations.clear()
            if callback is not None:
                callback()
            return True

    def cancel_active(
        self,
        callback: Callable[[], object] | None = None,
    ) -> bool:
        with self._lock:
            had_active = self._active is not None
            self._cancel_current_locked()
            if callback is not None:
                callback()
            return had_active

    def cancel(
        self,
        session: TurnSession,
        callback: Callable[[], object] | None = None,
    ) -> bool:
        """Cancel exactly one current session without touching a replacement."""
        with self._lock:
            if self._active != session:
                return False
            self._cancel_current_locked()
            if callback is not None:
                callback()
            return True

    def _new_session_locked(self, phase: TurnPhase) -> TurnSession:
        session = TurnSession(self._next_sequence)
        self._next_sequence += 1
        self._active = session
        self._phase = phase
        self._cancellations = {}
        return session

    def _cancel_current_locked(self) -> None:
        callbacks = tuple(
            callback for _, callback in sorted(self._cancellations.items())
        )
        self._active = None
        self._phase = TurnPhase.IDLE
        self._cancellations = {}
        for callback in callbacks:
            self._call_cancel(callback)

    @staticmethod
    def _call_cancel(callback: CancelCallback) -> None:
        try:
            callback()
        except Exception:
            # Every registered resource still gets its cancellation attempt.
            pass
