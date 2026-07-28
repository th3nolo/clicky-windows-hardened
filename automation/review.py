"""Highlight and revalidate one read-only desktop-action review."""

from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from automation.models import (
    MAX_TARGET_TEXT_CHARS,
    DesktopActionKind,
    DesktopBounds,
)
from automation.policy import (
    DesktopPolicyDecision,
    DesktopPolicyStatus,
    DesktopTargetLease,
)
from automation.stop import AutomationRunLease, AutomationStopController
from automation.targeting import DesktopTargetGuard


MIN_REVIEW_TTL_SECONDS = 1.0
MAX_REVIEW_TTL_SECONDS = 30.0
_SHA256_CHARS = 64


class DesktopReviewStatus(str, Enum):
    READY = "ready"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class DesktopHighlightRequest:
    """Inert UI request bound to one exact observed target."""

    review_id: str
    run_id: str
    action: DesktopActionKind
    application_name: str
    control_name: str
    control_type: str
    bounds: DesktopBounds
    target_identity_digest: str
    target_review_digest: str
    expires_at: float

    def __post_init__(self) -> None:
        _digest(self.review_id, "Desktop review ID")
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or len(self.run_id) > 128
            or not self.run_id.isprintable()
        ):
            raise ValueError("Desktop highlight run ID is invalid")
        if not isinstance(self.action, DesktopActionKind):
            raise TypeError("Desktop highlight action is invalid")
        for value in (
            self.application_name,
            self.control_name,
            self.control_type,
        ):
            if (
                not isinstance(value, str)
                or len(value) > MAX_TARGET_TEXT_CHARS
                or "\x00" in value
                or (value and not value.isprintable())
            ):
                raise ValueError("Desktop highlight label is invalid")
        if not self.application_name or not self.control_type:
            raise ValueError("Desktop highlight identity is incomplete")
        if not isinstance(self.bounds, DesktopBounds):
            raise TypeError("Desktop highlight bounds are invalid")
        _digest(
            self.target_identity_digest,
            "Desktop target identity digest",
        )
        _digest(
            self.target_review_digest,
            "Desktop target review digest",
        )
        if (
            type(self.expires_at) not in (int, float)
            or not math.isfinite(self.expires_at)
        ):
            raise ValueError("Desktop highlight expiry is invalid")

    @property
    def display_name(self) -> str:
        control = self.control_name or self.control_type
        return f"{self.application_name} — {control}"


class DesktopTargetHighlighter(Protocol):
    def show(self, request: DesktopHighlightRequest) -> None: ...

    def clear(self, review_id: str) -> None: ...

    def is_active(self, review_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class DesktopReviewLease:
    request: DesktopHighlightRequest
    target_lease: DesktopTargetLease = field(repr=False)
    run_lease: AutomationRunLease = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.request, DesktopHighlightRequest):
            raise TypeError("Desktop review request is invalid")
        if not isinstance(self.target_lease, DesktopTargetLease):
            raise TypeError("Desktop review target lease is invalid")
        if not isinstance(self.run_lease, AutomationRunLease):
            raise TypeError("Desktop review run lease is invalid")
        target = self.target_lease.target
        if self.request.run_id != self.run_lease.run_id:
            raise ValueError("Desktop review run identity does not match")
        if self.request.target_identity_digest != target.identity_digest:
            raise ValueError("Desktop review target identity does not match")
        if self.request.target_review_digest != target.review_digest:
            raise ValueError("Desktop review presentation does not match")


@dataclass(frozen=True, slots=True)
class DesktopReviewResult:
    status: DesktopReviewStatus
    policy: DesktopPolicyDecision | None = None
    lease: DesktopReviewLease | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.status, DesktopReviewStatus):
            raise TypeError("Desktop review status is invalid")
        if self.policy is not None and not isinstance(
            self.policy,
            DesktopPolicyDecision,
        ):
            raise TypeError("Desktop review policy decision is invalid")
        if self.lease is not None and not isinstance(
            self.lease,
            DesktopReviewLease,
        ):
            raise TypeError("Desktop review lease is invalid")
        if self.status is DesktopReviewStatus.READY:
            if (
                self.lease is None
                or self.policy is None
                or not self.policy.allowed
            ):
                raise ValueError("Ready desktop review requires an allowed lease")
        elif self.lease is not None:
            raise ValueError("Only a ready desktop review may expose a lease")

    @property
    def ready(self) -> bool:
        return self.status is DesktopReviewStatus.READY


class DesktopTargetReviewController:
    """Coordinate read-only capture, highlight, stop, and revalidation."""

    def __init__(
        self,
        guard: DesktopTargetGuard,
        highlighter: DesktopTargetHighlighter,
        stops: AutomationStopController,
        *,
        clock=time.time,
    ) -> None:
        if not isinstance(guard, DesktopTargetGuard):
            raise TypeError("Desktop target guard is invalid")
        if (
            not callable(getattr(highlighter, "show", None))
            or not callable(getattr(highlighter, "clear", None))
            or not callable(getattr(highlighter, "is_active", None))
        ):
            raise TypeError("Desktop target highlighter is invalid")
        if not isinstance(stops, AutomationStopController):
            raise TypeError("Automation stop controller is invalid")
        if not callable(clock):
            raise TypeError("Desktop review clock is invalid")
        self._guard = guard
        self._highlighter = highlighter
        self._stops = stops
        self._clock = clock

    def preview(
        self,
        run_lease: AutomationRunLease,
        *,
        action: DesktopActionKind,
        ttl_seconds: float = 10.0,
    ) -> DesktopReviewResult:
        if not isinstance(run_lease, AutomationRunLease):
            raise TypeError("Automation run lease is invalid")
        if not isinstance(action, DesktopActionKind):
            raise TypeError("Desktop action kind is invalid")
        if (
            type(ttl_seconds) not in (int, float)
            or not math.isfinite(ttl_seconds)
            or not MIN_REVIEW_TTL_SECONDS
            <= ttl_seconds
            <= MAX_REVIEW_TTL_SECONDS
        ):
            raise ValueError("Desktop review TTL is invalid")
        if not self._stops.is_active(run_lease):
            return DesktopReviewResult(DesktopReviewStatus.CANCELLED)

        decision = self._guard.capture(action)
        if not decision.allowed:
            status = (
                DesktopReviewStatus.UNAVAILABLE
                if decision.status is DesktopPolicyStatus.UNAVAILABLE
                else DesktopReviewStatus.BLOCKED
            )
            return DesktopReviewResult(status, decision)
        assert decision.lease is not None
        target = decision.lease.target
        expires_at = float(self._clock()) + float(ttl_seconds)
        review_id = _review_id(
            run_lease,
            action=action,
            target_review_digest=target.review_digest,
            expires_at=expires_at,
        )
        request = DesktopHighlightRequest(
            review_id=review_id,
            run_id=run_lease.run_id,
            action=action,
            application_name=target.application_name,
            control_name=target.control_name,
            control_type=target.control_type,
            bounds=target.bounds,
            target_identity_digest=target.identity_digest,
            target_review_digest=target.review_digest,
            expires_at=expires_at,
        )
        try:
            self._highlighter.show(request)
        except Exception:
            self._safe_clear(review_id)
            return DesktopReviewResult(DesktopReviewStatus.UNAVAILABLE)
        cancel_name = _cancel_name(review_id)
        if not self._stops.bind_cancel(
            run_lease,
            cancel_name,
            lambda: self._safe_clear(review_id),
        ):
            return DesktopReviewResult(DesktopReviewStatus.CANCELLED)
        lease = DesktopReviewLease(
            request=request,
            target_lease=decision.lease,
            run_lease=run_lease,
        )
        return DesktopReviewResult(
            DesktopReviewStatus.READY,
            decision,
            lease,
        )

    def revalidate(self, lease: DesktopReviewLease) -> DesktopReviewResult:
        if not isinstance(lease, DesktopReviewLease):
            raise TypeError("Desktop review lease is invalid")
        if not self._stops.is_active(lease.run_lease):
            self._safe_clear(lease.request.review_id)
            return DesktopReviewResult(DesktopReviewStatus.CANCELLED)
        if float(self._clock()) > lease.request.expires_at:
            self.clear(lease)
            return DesktopReviewResult(DesktopReviewStatus.EXPIRED)
        try:
            highlighted = self._highlighter.is_active(
                lease.request.review_id
            )
        except Exception:
            highlighted = False
        if not highlighted:
            self.clear(lease)
            return DesktopReviewResult(DesktopReviewStatus.UNAVAILABLE)
        decision = self._guard.revalidate(
            lease.target_lease,
            action=lease.request.action,
        )
        if not decision.allowed:
            self.clear(lease)
            status = (
                DesktopReviewStatus.UNAVAILABLE
                if decision.status is DesktopPolicyStatus.UNAVAILABLE
                else DesktopReviewStatus.BLOCKED
            )
            return DesktopReviewResult(status, decision)
        current = decision.lease.target if decision.lease is not None else None
        if (
            current is None
            or current.identity_digest
            != lease.request.target_identity_digest
            or current.review_digest != lease.request.target_review_digest
        ):
            self.clear(lease)
            return DesktopReviewResult(DesktopReviewStatus.BLOCKED, decision)
        return DesktopReviewResult(
            DesktopReviewStatus.READY,
            decision,
            lease,
        )

    def clear(self, lease: DesktopReviewLease) -> bool:
        if not isinstance(lease, DesktopReviewLease):
            return False
        self._safe_clear(lease.request.review_id)
        return self._stops.unbind_cancel(
            lease.run_lease,
            _cancel_name(lease.request.review_id),
        )

    def _safe_clear(self, review_id: str) -> None:
        try:
            self._highlighter.clear(review_id)
        except Exception:
            pass


def _review_id(
    run_lease: AutomationRunLease,
    *,
    action: DesktopActionKind,
    target_review_digest: str,
    expires_at: float,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "action": action.value,
                "expires_at": expires_at,
                "run_id": run_lease.run_id,
                "sequence": run_lease.sequence,
                "target_review_digest": target_review_digest,
            }
        )
    ).hexdigest()


def _cancel_name(review_id: str) -> str:
    _digest(review_id, "Desktop review ID")
    return f"highlight:{review_id}"


def _digest(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_CHARS
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} is invalid")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


__all__ = [
    "DesktopHighlightRequest",
    "DesktopReviewLease",
    "DesktopReviewResult",
    "DesktopReviewStatus",
    "DesktopTargetHighlighter",
    "DesktopTargetReviewController",
]
