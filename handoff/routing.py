"""One-use, exact-destination routing for reviewed screen-region context."""

from __future__ import annotations

import hashlib
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from handoff.models import (
    MAX_CAPTURE_BYTES,
    HandoffDataClass,
    HandoffDestination,
    HandoffIntent,
    HandoffReview,
    HandoffSelectionError,
)
from handoff.selection import TransientSelectionPayload


MAX_LIVE_ROUTE_CLAIMS = 256
MAX_ROUTE_REFERENCE_CHARS = 128
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class HandoffRoutingError(RuntimeError):
    """Reviewed context could not be routed without weakening its binding."""


class HandoffReplayError(HandoffRoutingError):
    """One reviewed intent was already claimed."""


class HandoffDestinationUnavailableError(HandoffRoutingError):
    """The exact reviewed destination has no enabled caller."""


@dataclass(frozen=True, slots=True)
class ReviewedRegionHandoff:
    """Exact intent/review evidence plus transient selected bytes."""

    payload: TransientSelectionPayload = field(repr=False)
    intent: HandoffIntent = field(repr=False)
    review: HandoffReview

    def __post_init__(self) -> None:
        if not isinstance(self.payload, TransientSelectionPayload):
            raise TypeError("Reviewed region payload is invalid")
        if not isinstance(self.intent, HandoffIntent):
            raise TypeError("Reviewed region intent is invalid")
        if not isinstance(self.review, HandoffReview):
            raise TypeError("Reviewed region evidence is invalid")
        selection = self.payload.selection
        if (
            self.intent.selection_id != selection.selection_id
            or self.intent.selection_digest != selection.selection_digest
            or self.review.intent_id != self.intent.intent_id
            or self.review.intent_digest != self.intent.intent_digest
            or self.review.destination is not self.intent.destination
            or self.review.data_class is not self.intent.data_class
            or self.review.expires_at != self.intent.expires_at
        ):
            raise HandoffSelectionError(
                "Reviewed region evidence is inconsistent"
            )

    def wipe(self) -> None:
        self.payload.wipe()


@dataclass(frozen=True, slots=True)
class HandoffRouteContext:
    """Transient exact bytes owned by one accepted destination caller."""

    route_id: str
    intent_id: str
    intent_digest: str
    selection_id: str
    selection_digest: str
    destination: HandoffDestination
    data_class: HandoffDataClass
    purpose: str = field(repr=False)
    media_type: str
    image_content: bytearray = field(repr=False)
    image_sha256: str
    width: int
    height: int
    accepted_at: float
    expires_at: float
    mask_sha256: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        for value, label in (
            (self.route_id, "Route ID"),
            (self.intent_id, "Intent ID"),
            (self.selection_id, "Selection ID"),
        ):
            if (
                not isinstance(value, str)
                or len(value) > MAX_ROUTE_REFERENCE_CHARS
                or _OPAQUE_ID.fullmatch(value) is None
            ):
                raise HandoffRoutingError(f"{label} is invalid")
        for digest, label in (
            (self.intent_digest, "Intent digest"),
            (self.selection_digest, "Selection digest"),
            (self.image_sha256, "Image digest"),
        ):
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise HandoffRoutingError(f"{label} is invalid")
        if not isinstance(self.destination, HandoffDestination):
            raise TypeError("Route destination is invalid")
        if self.data_class is not HandoffDataClass.SCREEN_PIXELS:
            raise HandoffRoutingError(
                "Only reviewed screen-pixel routing is implemented"
            )
        if (
            not isinstance(self.purpose, str)
            or not self.purpose.strip()
            or len(self.purpose) > 2_000
        ):
            raise HandoffRoutingError("Route purpose is invalid")
        if self.media_type != "image/jpeg":
            raise HandoffRoutingError(
                "Route image must be the exact reviewed JPEG"
            )
        if (
            type(self.width) is not int
            or type(self.height) is not int
            or not 1 <= self.width <= 16_384
            or not 1 <= self.height <= 16_384
        ):
            raise HandoffRoutingError(
                "Route image dimensions are invalid"
            )
        if (
            not isinstance(self.image_content, bytearray)
            or not 1 <= len(self.image_content) <= MAX_CAPTURE_BYTES
            or not self.image_content.startswith(b"\xff\xd8\xff")
            or not self.image_content.endswith(b"\xff\xd9")
            or hashlib.sha256(self.image_content).hexdigest()
            != self.image_sha256
        ):
            raise HandoffRoutingError("Route image bytes are invalid")
        if self.mask_sha256 is not None and (
            not isinstance(self.mask_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.mask_sha256) is None
        ):
            raise HandoffRoutingError("Route mask digest is invalid")
        for value, label in (
            (self.accepted_at, "Route acceptance time"),
            (self.expires_at, "Route expiry"),
        ):
            if (
                type(value) not in (int, float)
                or not math.isfinite(float(value))
                or float(value) < 0
            ):
                raise HandoffRoutingError(f"{label} is invalid")
        if self.accepted_at >= self.expires_at:
            raise HandoffRoutingError("Route context is expired")

    def wipe(self) -> None:
        self.image_content[:] = b"\x00" * len(self.image_content)


@dataclass(frozen=True, slots=True)
class HandoffRouteReceipt:
    """Content-free proof that one exact destination accepted ownership."""

    route_id: str
    route_reference: str
    intent_digest: str
    selection_digest: str
    destination: HandoffDestination
    accepted_at: float

    def __post_init__(self) -> None:
        for value, label in (
            (self.route_id, "Route ID"),
            (self.route_reference, "Route reference"),
        ):
            if (
                not isinstance(value, str)
                or len(value) > MAX_ROUTE_REFERENCE_CHARS
                or _OPAQUE_ID.fullmatch(value) is None
            ):
                raise HandoffRoutingError(f"{label} is invalid")
        for digest in (self.intent_digest, self.selection_digest):
            if (
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise HandoffRoutingError("Route receipt digest is invalid")
        if not isinstance(self.destination, HandoffDestination):
            raise TypeError("Route receipt destination is invalid")
        if (
            type(self.accepted_at) not in (int, float)
            or not math.isfinite(float(self.accepted_at))
            or float(self.accepted_at) < 0
        ):
            raise HandoffRoutingError(
                "Route receipt acceptance time is invalid"
            )


DestinationHandler = Callable[[HandoffRouteContext], str]


class HandoffRouter:
    """Claim each reviewed intent once and call only its bound destination."""

    def __init__(
        self,
        handlers: Mapping[HandoffDestination, DestinationHandler],
        *,
        clock: Callable[[], float] = time.monotonic,
        route_id_factory: Callable[[], str],
    ) -> None:
        if not isinstance(handlers, Mapping) or not handlers:
            raise TypeError("Handoff router requires destination handlers")
        checked: dict[HandoffDestination, DestinationHandler] = {}
        for destination, handler in handlers.items():
            if not isinstance(destination, HandoffDestination):
                raise TypeError("Handoff router destination is invalid")
            if not callable(handler):
                raise TypeError("Handoff destination handler is invalid")
            checked[destination] = handler
        if not callable(clock) or not callable(route_id_factory):
            raise TypeError("Handoff router callbacks are invalid")
        self._handlers = checked
        self._clock = clock
        self._route_id_factory = route_id_factory
        self._lock = threading.Lock()
        self._claimed: dict[str, float] = {}

    @property
    def available_destinations(self) -> tuple[HandoffDestination, ...]:
        return tuple(
            destination
            for destination in HandoffDestination
            if destination in self._handlers
        )

    def route(
        self,
        reviewed: ReviewedRegionHandoff,
    ) -> HandoffRouteReceipt:
        if not isinstance(reviewed, ReviewedRegionHandoff):
            raise TypeError("Handoff routing requires reviewed region context")
        try:
            self._validate_reviewed(reviewed)
            now = float(self._clock())
            if now >= reviewed.intent.expires_at:
                raise HandoffRoutingError(
                    "Reviewed region route expired"
                )
            handler = self._handlers.get(reviewed.intent.destination)
            if handler is None:
                raise HandoffDestinationUnavailableError(
                    "The reviewed destination is unavailable"
                )
            if not math.isfinite(now) or now < 0:
                raise HandoffRoutingError(
                    "The handoff route clock is invalid"
                )
            with self._lock:
                self._claimed = {
                    digest: expiry
                    for digest, expiry in self._claimed.items()
                    if expiry > now
                }
                if reviewed.intent.intent_digest in self._claimed:
                    raise HandoffReplayError(
                        "Reviewed region route was already consumed"
                    )
                if len(self._claimed) >= MAX_LIVE_ROUTE_CLAIMS:
                    raise HandoffRoutingError(
                        "Too many live handoff route claims"
                    )
                self._claimed[
                    reviewed.intent.intent_digest
                ] = reviewed.intent.expires_at
            context: HandoffRouteContext | None = None
            try:
                route_id = self._route_id_factory()
                context = HandoffRouteContext(
                    route_id=route_id,
                    intent_id=reviewed.intent.intent_id,
                    intent_digest=reviewed.intent.intent_digest,
                    selection_id=reviewed.intent.selection_id,
                    selection_digest=reviewed.intent.selection_digest,
                    destination=reviewed.intent.destination,
                    data_class=reviewed.intent.data_class,
                    purpose=reviewed.intent.purpose,
                    media_type=reviewed.payload.image.media_type,
                    image_content=bytearray(
                        reviewed.payload.image.content
                    ),
                    image_sha256=(
                        reviewed.payload.selection.capture_sha256
                    ),
                    width=reviewed.payload.selection.region.width,
                    height=reviewed.payload.selection.region.height,
                    mask_sha256=(
                        reviewed.payload.selection.mask_sha256
                    ),
                    accepted_at=now,
                    expires_at=reviewed.intent.expires_at,
                )
                reference = handler(context)
                receipt = HandoffRouteReceipt(
                    route_id=route_id,
                    route_reference=reference,
                    intent_digest=reviewed.intent.intent_digest,
                    selection_digest=(
                        reviewed.intent.selection_digest
                    ),
                    destination=reviewed.intent.destination,
                    accepted_at=now,
                )
            except Exception as exc:
                if context is not None:
                    context.wipe()
                raise HandoffRoutingError(
                    "The reviewed destination did not accept the route"
                ) from exc
            return receipt
        finally:
            reviewed.wipe()

    @staticmethod
    def _validate_reviewed(
        reviewed: ReviewedRegionHandoff,
    ) -> None:
        selection = reviewed.payload.selection
        intent = reviewed.intent
        review = reviewed.review
        if (
            intent.selection_id != selection.selection_id
            or intent.selection_digest != selection.selection_digest
            or review.intent_id != intent.intent_id
            or review.intent_digest != intent.intent_digest
            or review.destination is not intent.destination
            or review.data_class is not intent.data_class
            or review.expires_at != intent.expires_at
            or hashlib.sha256(
                reviewed.payload.image.content
            ).hexdigest()
            != selection.capture_sha256
        ):
            raise HandoffRoutingError(
                "Reviewed handoff evidence changed before routing"
            )


__all__ = [
    "HandoffDestinationUnavailableError",
    "HandoffReplayError",
    "HandoffRouteContext",
    "HandoffRouteReceipt",
    "HandoffRouter",
    "HandoffRoutingError",
    "ReviewedRegionHandoff",
]
