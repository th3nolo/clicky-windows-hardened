"""Dismissible generic meeting countdowns with lock/share suppression."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from connectors.google_calendar import _format_utc, _rfc3339
from connectors.google_calendar_upcoming import CalendarUpcomingResult


MAX_COUNTDOWN_LEAD_MINUTES = 60
MAX_VISIBLE_COUNTDOWNS = 3
MAX_DISMISSALS = 256
MAX_DISMISSAL_BYTES = 64 * 1024
DISMISSAL_STATE_VERSION = 1
_UTC = timezone.utc


@dataclass(frozen=True, slots=True)
class MeetingCountdownPrivacy:
    session_locked: bool
    screen_shared: bool

    def __post_init__(self) -> None:
        if type(self.session_locked) is not bool or type(self.screen_shared) is not bool:
            raise TypeError("Countdown privacy flags must be booleans")

    @property
    def may_display(self) -> bool:
        return not self.session_locked and not self.screen_shared


@dataclass(frozen=True, slots=True)
class MeetingCountdown:
    opaque_event_id: str
    starts_at: str
    ends_at: str
    remaining_seconds: int
    display_text: str = "Meeting soon"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.opaque_event_id, str)
            or len(self.opaque_event_id) != 64
        ):
            raise ValueError("Countdown event identity is invalid")
        start = _rfc3339(self.starts_at, "Countdown start")
        end = _rfc3339(self.ends_at, "Countdown end")
        if end <= start:
            raise ValueError("Countdown event range is invalid")
        if (
            type(self.remaining_seconds) is not int
            or not 0 <= self.remaining_seconds <= MAX_COUNTDOWN_LEAD_MINUTES * 60
        ):
            raise ValueError("Countdown remaining time is invalid")
        if self.display_text != "Meeting soon":
            raise ValueError("Countdown text must remain generic")


class MeetingDismissalStore:
    """Persist opaque event dismissals only until the event ends."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("Countdown dismissal path must be a Path")
        self._path = path
        self._lock = threading.RLock()

    def dismiss(self, opaque_event_id: str, *, until: str) -> None:
        MeetingCountdown(
            opaque_event_id=opaque_event_id,
            starts_at="2026-01-01T00:00:00Z",
            ends_at="2026-01-01T00:00:01Z",
            remaining_seconds=0,
        )
        expiry = _rfc3339(until, "Countdown dismissal expiry")
        with self._lock:
            values = self._load()
            values[opaque_event_id] = _format_utc(expiry)
            if len(values) > MAX_DISMISSALS:
                ordered = sorted(
                    values.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )[:MAX_DISMISSALS]
                values = dict(ordered)
            self._save(values)

    def is_dismissed(
        self,
        opaque_event_id: str,
        *,
        now: datetime,
    ) -> bool:
        if now.tzinfo is None:
            raise TypeError("Countdown time must be timezone-aware")
        with self._lock:
            values = self._load()
            current = now.astimezone(_UTC)
            retained = {
                event_id: expiry
                for event_id, expiry in values.items()
                if _rfc3339(expiry, "Countdown dismissal expiry") > current
            }
            if retained != values:
                self._save(retained)
            return opaque_event_id in retained

    def _load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        mode = self._path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            return {}
        if self._path.stat().st_size > MAX_DISMISSAL_BYTES:
            return {}
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", "dismissed"}
            or payload["version"] != DISMISSAL_STATE_VERSION
            or not isinstance(payload["dismissed"], dict)
            or len(payload["dismissed"]) > MAX_DISMISSALS
        ):
            return {}
        clean: dict[str, str] = {}
        for event_id, expiry in payload["dismissed"].items():
            if (
                isinstance(event_id, str)
                and len(event_id) == 64
                and isinstance(expiry, str)
            ):
                try:
                    _rfc3339(expiry, "Countdown dismissal expiry")
                except ValueError:
                    continue
                clean[event_id] = expiry
        return clean

    def _save(self, values: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        parent_mode = self._path.parent.lstat().st_mode
        if stat.S_ISLNK(parent_mode) or not stat.S_ISDIR(parent_mode):
            raise OSError("Countdown dismissal directory is unsafe")
        payload = json.dumps(
            {
                "version": DISMISSAL_STATE_VERSION,
                "dismissed": dict(sorted(values.items())),
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(payload) > MAX_DISMISSAL_BYTES:
            raise ValueError("Countdown dismissal state exceeds its bound")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="meeting_dismissals.",
            suffix=".tmp",
            dir=self._path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def build_meeting_countdowns(
    result: CalendarUpcomingResult,
    *,
    enabled: bool,
    privacy: MeetingCountdownPrivacy,
    now: datetime,
    lead_minutes: int = 15,
    dismissals: MeetingDismissalStore | None = None,
) -> tuple[MeetingCountdown, ...]:
    """Create at most three generic cards; hidden means no content at all."""

    if not isinstance(result, CalendarUpcomingResult):
        raise TypeError("Upcoming Calendar result is required")
    if type(enabled) is not bool:
        raise TypeError("Countdown enablement must be boolean")
    if not isinstance(privacy, MeetingCountdownPrivacy):
        raise TypeError("Countdown privacy state is required")
    if now.tzinfo is None:
        raise TypeError("Countdown time must be timezone-aware")
    if (
        type(lead_minutes) is not int
        or not 1 <= lead_minutes <= MAX_COUNTDOWN_LEAD_MINUTES
    ):
        raise ValueError("Countdown lead time is invalid")
    if not enabled or not privacy.may_display:
        return ()

    current = now.astimezone(_UTC)
    horizon = current + timedelta(minutes=lead_minutes)
    cards: list[MeetingCountdown] = []
    for event in result.events:
        start = _rfc3339(event.starts_at, "Countdown start")
        if start < current or start > horizon:
            continue
        if dismissals is not None and dismissals.is_dismissed(
            event.opaque_event_id,
            now=current,
        ):
            continue
        cards.append(
            MeetingCountdown(
                opaque_event_id=event.opaque_event_id,
                starts_at=event.starts_at,
                ends_at=event.ends_at,
                remaining_seconds=max(
                    0,
                    int((start - current).total_seconds()),
                ),
            )
        )
        if len(cards) >= MAX_VISIBLE_COUNTDOWNS:
            break
    return tuple(cards)


__all__ = [
    "MeetingCountdown",
    "MeetingCountdownPrivacy",
    "MeetingDismissalStore",
    "build_meeting_countdowns",
]
