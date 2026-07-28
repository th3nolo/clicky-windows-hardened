"""Global stop ownership for one desktop-automation run.

The coordinator invalidates a run before invoking cancellation callbacks and
runs a guarded callback while holding the same lock used by stop(). A queued
action therefore either finishes before stop takes effect or observes a stale
lease and never starts.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from typing import Callable, TypeVar


MAX_RUN_ID_CHARS = 128
MAX_CANCEL_NAME_CHARS = 128
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
CancelCallback = Callable[[], object]
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class AutomationRunLease:
    sequence: int
    run_id: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence <= 0:
            raise ValueError("Automation run sequence is invalid")
        _identifier(self.run_id, MAX_RUN_ID_CHARS, "Automation run ID")


class AutomationStopController:
    """Own one automation run and all resources stopped with it."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._next_sequence = 1
        self._active: AutomationRunLease | None = None
        self._cancellations: dict[str, CancelCallback] = {}

    @property
    def active(self) -> AutomationRunLease | None:
        with self._lock:
            return self._active

    def begin(self, run_id: str) -> AutomationRunLease:
        _identifier(run_id, MAX_RUN_ID_CHARS, "Automation run ID")
        with self._lock:
            self._stop_locked()
            lease = AutomationRunLease(self._next_sequence, run_id)
            self._next_sequence += 1
            self._active = lease
            self._cancellations = {}
            return lease

    def is_active(self, lease: AutomationRunLease) -> bool:
        if not isinstance(lease, AutomationRunLease):
            return False
        with self._lock:
            return self._active == lease

    def bind_cancel(
        self,
        lease: AutomationRunLease,
        name: str,
        callback: CancelCallback,
    ) -> bool:
        if not isinstance(lease, AutomationRunLease):
            raise TypeError("Automation run lease is invalid")
        _identifier(name, MAX_CANCEL_NAME_CHARS, "Cancellation name")
        if not callable(callback):
            raise TypeError("Cancellation callback is invalid")
        with self._lock:
            if self._active != lease:
                self._call_cancel(callback)
                return False
            previous = self._cancellations.pop(name, None)
            if previous is not None:
                self._call_cancel(previous)
            self._cancellations[name] = callback
            return True

    def unbind_cancel(
        self,
        lease: AutomationRunLease,
        name: str,
    ) -> bool:
        _identifier(name, MAX_CANCEL_NAME_CHARS, "Cancellation name")
        with self._lock:
            if self._active != lease:
                return False
            return self._cancellations.pop(name, None) is not None

    def run_if_active(
        self,
        lease: AutomationRunLease,
        callback: Callable[..., T],
        *args: object,
        **kwargs: object,
    ) -> tuple[bool, T | None]:
        """Run a queued step only while stop and replacement are excluded."""

        if not isinstance(lease, AutomationRunLease):
            raise TypeError("Automation run lease is invalid")
        if not callable(callback):
            raise TypeError("Automation callback is invalid")
        with self._lock:
            if self._active != lease:
                return False, None
            return True, callback(*args, **kwargs)

    def finish(self, lease: AutomationRunLease) -> bool:
        if not isinstance(lease, AutomationRunLease):
            return False
        with self._lock:
            if self._active != lease:
                return False
            self._active = None
            self._cancellations = {}
            return True

    def stop(self) -> bool:
        with self._lock:
            had_active = self._active is not None
            self._stop_locked()
            return had_active

    def _stop_locked(self) -> None:
        callbacks = tuple(
            callback for _, callback in sorted(self._cancellations.items())
        )
        self._active = None
        self._cancellations = {}
        for callback in callbacks:
            self._call_cancel(callback)

    @staticmethod
    def _call_cancel(callback: CancelCallback) -> None:
        try:
            callback()
        except Exception:
            # Every remaining resource still receives its cancellation attempt.
            pass


class GlobalAutomationStopHotkey:
    """Register one handle-specific, non-suppressing global stop key."""

    def __init__(
        self,
        controller: AutomationStopController,
        *,
        key: str = "esc",
    ) -> None:
        if not isinstance(controller, AutomationStopController):
            raise TypeError("Automation stop controller is invalid")
        _identifier(key, 32, "Automation stop key")
        self._controller = controller
        self._key = key
        self._handle: object | None = None

    @property
    def started(self) -> bool:
        return self._handle is not None

    def start(self) -> bool:
        if self._handle is not None:
            return False
        import keyboard

        self._handle = keyboard.add_hotkey(
            self._key,
            self._controller.stop,
            suppress=False,
            trigger_on_release=False,
        )
        if self._handle is None:
            raise RuntimeError("Automation stop hotkey registration failed")
        return True

    def close(self) -> bool:
        handle = self._handle
        self._handle = None
        if handle is None:
            return False
        import keyboard

        keyboard.remove_hotkey(handle)
        return True


def _identifier(value: str, limit: int, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) > limit
        or not _IDENTIFIER.fullmatch(value)
    ):
        raise ValueError(f"{label} is invalid")


__all__ = [
    "AutomationRunLease",
    "AutomationStopController",
    "GlobalAutomationStopHotkey",
]
