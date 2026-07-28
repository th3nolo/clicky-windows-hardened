"""Immutable contracts for one explicit screen-region handoff.

The models in this module carry screen/topology metadata and cryptographic
digests only. They intentionally contain no screenshot bytes, OCR text,
provider request, insertion authority, task grant, or desktop action.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Sequence

from capability_registry import CapabilityId
from screen.topology import MonitorDescriptor, Rect


HANDOFF_SCHEMA_VERSION = 1
MAX_REGION_EDGE_PIXELS = 16_384
MAX_REGION_PIXELS = 67_108_864
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_PURPOSE_CHARS = 2_000
MAX_LABEL_CHARS = 256
MAX_CAPTURE_GENERATION_CHARS = 128
MAX_SELECTION_LIFETIME_SECONDS = 120.0
MAX_COORDINATE_MAGNITUDE = 10_000_000
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STABLE_MONITOR_ID = re.compile(r"^monitor-[0-9a-f]{16}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class HandoffSelectionError(ValueError):
    """A selection or review could not be bound without guessing."""


class SelectionShape(str, Enum):
    RECTANGLE = "rectangle"
    ELLIPSE_MASK = "ellipse_mask"


class HandoffDestination(str, Enum):
    TUTOR_CONTEXT = "tutor_context"
    COMPOSE_PREVIEW = "compose_preview"
    TASK_AGENT_NEW_RUN = "task_agent_new_run"


class HandoffDataClass(str, Enum):
    """What the destination is allowed to receive after explicit review."""

    SCREEN_PIXELS = "screen_pixels"
    REDACTED_IMAGE = "redacted_image"
    OCR_TEXT = "ocr_text"


@dataclass(frozen=True, slots=True)
class PhysicalRegion:
    """Positive-area rectangle in physical virtual-desktop pixels."""

    left: int
    top: int
    width: int
    height: int

    def __post_init__(self) -> None:
        for coordinate in (self.left, self.top):
            if (
                type(coordinate) is not int
                or abs(coordinate) > MAX_COORDINATE_MAGNITUDE
            ):
                raise HandoffSelectionError(
                    "Selection origin is invalid"
                )
        for edge in (self.width, self.height):
            if (
                type(edge) is not int
                or not 1 <= edge <= MAX_REGION_EDGE_PIXELS
            ):
                raise HandoffSelectionError(
                    "Selection size is invalid"
                )
        if self.pixel_count > MAX_REGION_PIXELS:
            raise HandoffSelectionError(
                "Selection pixel limit exceeded"
            )
        if (
            abs(self.right) > MAX_COORDINATE_MAGNITUDE
            or abs(self.bottom) > MAX_COORDINATE_MAGNITUDE
        ):
            raise HandoffSelectionError(
                "Selection bounds are invalid"
            )

    @property
    def right(self) -> int:
        return self.left + self.width

    @property
    def bottom(self) -> int:
        return self.top + self.height

    @property
    def pixel_count(self) -> int:
        return self.width * self.height

    @property
    def identity_key(self) -> tuple[int, int, int, int]:
        return (self.left, self.top, self.width, self.height)

    def inside(self, outer: Rect) -> bool:
        return (
            self.left >= outer.left
            and self.top >= outer.top
            and self.right <= outer.right
            and self.bottom <= outer.bottom
        )


@dataclass(frozen=True, slots=True)
class MonitorSnapshot:
    """DPI/topology identity used for capture-time revalidation."""

    stable_id: str
    capture_index: int
    physical: PhysicalRegion
    logical_left: int
    logical_top: int
    logical_width: int
    logical_height: int
    dpi_x: float
    dpi_y: float
    topology_digest: str

    def __post_init__(self) -> None:
        if _STABLE_MONITOR_ID.fullmatch(self.stable_id) is None:
            raise HandoffSelectionError(
                "Monitor identity is invalid"
            )
        if (
            type(self.capture_index) is not int
            or not 1 <= self.capture_index <= 64
        ):
            raise HandoffSelectionError(
                "Capture monitor index is invalid"
            )
        if not isinstance(self.physical, PhysicalRegion):
            raise TypeError("Physical monitor bounds are invalid")
        for coordinate in (self.logical_left, self.logical_top):
            if (
                type(coordinate) is not int
                or abs(coordinate) > MAX_COORDINATE_MAGNITUDE
            ):
                raise HandoffSelectionError(
                    "Logical monitor origin is invalid"
                )
        for edge in (self.logical_width, self.logical_height):
            if type(edge) is not int or not 1 <= edge <= MAX_REGION_EDGE_PIXELS:
                raise HandoffSelectionError(
                    "Logical monitor size is invalid"
                )
        for dpi in (self.dpi_x, self.dpi_y):
            if (
                type(dpi) not in (int, float)
                or not math.isfinite(float(dpi))
                or not 48.0 <= float(dpi) <= 960.0
            ):
                raise HandoffSelectionError(
                    "Monitor DPI is invalid"
                )
        _digest(self.topology_digest, "Topology digest")

    @classmethod
    def from_descriptor(
        cls,
        descriptor: MonitorDescriptor,
        *,
        topology_digest_value: str,
    ) -> MonitorSnapshot:
        if not isinstance(descriptor, MonitorDescriptor):
            raise TypeError("Monitor descriptor is invalid")
        return cls(
            stable_id=descriptor.stable_id,
            capture_index=descriptor.capture_index,
            physical=PhysicalRegion(
                descriptor.physical.left,
                descriptor.physical.top,
                descriptor.physical.width,
                descriptor.physical.height,
            ),
            logical_left=descriptor.logical.left,
            logical_top=descriptor.logical.top,
            logical_width=descriptor.logical.width,
            logical_height=descriptor.logical.height,
            dpi_x=float(descriptor.dpi_x),
            dpi_y=float(descriptor.dpi_y),
            topology_digest=topology_digest_value,
        )

    @property
    def identity_key(self) -> tuple[object, ...]:
        return (
            self.stable_id,
            self.capture_index,
            self.physical.identity_key,
            self.logical_left,
            self.logical_top,
            self.logical_width,
            self.logical_height,
            float(self.dpi_x),
            float(self.dpi_y),
            self.topology_digest,
        )


@dataclass(frozen=True, slots=True)
class HandoffSelection:
    """Content-free evidence for one transient selected capture."""

    selection_id: str
    schema_version: int
    shape: SelectionShape
    monitor: MonitorSnapshot
    region: PhysicalRegion
    capture_generation: str
    captured_at: float
    expires_at: float
    capture_sha256: str = field(repr=False)
    capture_byte_count: int
    mask_sha256: str | None = field(default=None, repr=False)
    own_windows_excluded: bool = True

    def __post_init__(self) -> None:
        _opaque_id(self.selection_id, "Selection ID")
        if self.schema_version != HANDOFF_SCHEMA_VERSION:
            raise HandoffSelectionError(
                "Handoff schema version is unsupported"
            )
        if not isinstance(self.shape, SelectionShape):
            raise TypeError("Selection shape is invalid")
        if not isinstance(self.monitor, MonitorSnapshot):
            raise TypeError("Selection monitor is invalid")
        if not isinstance(self.region, PhysicalRegion):
            raise TypeError("Selection region is invalid")
        if not self.region.inside(
            Rect(*self.monitor.physical.identity_key)
        ):
            raise HandoffSelectionError(
                "Selection is outside its monitor"
            )
        _opaque_id(
            self.capture_generation,
            "Capture generation",
            maximum=MAX_CAPTURE_GENERATION_CHARS,
        )
        _timestamp(self.captured_at, "Capture time")
        _timestamp(self.expires_at, "Selection expiry")
        lifetime = self.expires_at - self.captured_at
        if not 0 < lifetime <= MAX_SELECTION_LIFETIME_SECONDS:
            raise HandoffSelectionError(
                "Selection lifetime is invalid"
            )
        _digest(self.capture_sha256, "Capture digest")
        if (
            type(self.capture_byte_count) is not int
            or not 1 <= self.capture_byte_count <= MAX_CAPTURE_BYTES
        ):
            raise HandoffSelectionError(
                "Capture byte count is invalid"
            )
        if self.shape is SelectionShape.ELLIPSE_MASK:
            _digest(self.mask_sha256, "Selection mask digest")
        elif self.mask_sha256 is not None:
            raise HandoffSelectionError(
                "Rectangle selection cannot carry a mask"
            )
        if self.own_windows_excluded is not True:
            raise HandoffSelectionError(
                "Handoff capture must exclude Clicky-owned windows"
            )

    @property
    def selection_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "capture_byte_count": self.capture_byte_count,
                    "capture_generation": self.capture_generation,
                    "capture_sha256": self.capture_sha256,
                    "captured_at": self.captured_at,
                    "expires_at": self.expires_at,
                    "mask_sha256": self.mask_sha256,
                    "monitor": list(self.monitor.identity_key),
                    "own_windows_excluded": self.own_windows_excluded,
                    "region": list(self.region.identity_key),
                    "schema_version": self.schema_version,
                    "selection_id": self.selection_id,
                    "shape": self.shape.value,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class HandoffIntent:
    """One destination choice; still no capability or execution authority."""

    intent_id: str
    selection_id: str
    selection_digest: str
    destination: HandoffDestination
    data_class: HandoffDataClass
    purpose: str = field(repr=False)
    created_at: float
    expires_at: float

    def __post_init__(self) -> None:
        _opaque_id(self.intent_id, "Handoff intent ID")
        _opaque_id(self.selection_id, "Selection ID")
        _digest(self.selection_digest, "Selection digest")
        if not isinstance(self.destination, HandoffDestination):
            raise TypeError("Handoff destination is invalid")
        if not isinstance(self.data_class, HandoffDataClass):
            raise TypeError("Handoff data class is invalid")
        _bounded_text(
            self.purpose,
            maximum=MAX_PURPOSE_CHARS,
            label="Handoff purpose",
        )
        _timestamp(self.created_at, "Handoff intent time")
        _timestamp(self.expires_at, "Handoff intent expiry")
        lifetime = self.expires_at - self.created_at
        if not 0 < lifetime <= MAX_SELECTION_LIFETIME_SECONDS:
            raise HandoffSelectionError(
                "Handoff intent lifetime is invalid"
            )

    @property
    def intent_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "created_at": self.created_at,
                    "data_class": self.data_class.value,
                    "destination": self.destination.value,
                    "expires_at": self.expires_at,
                    "intent_id": self.intent_id,
                    "purpose_sha256": hashlib.sha256(
                        self.purpose.encode("utf-8")
                    ).hexdigest(),
                    "selection_digest": self.selection_digest,
                    "selection_id": self.selection_id,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class HandoffReview:
    """Exact labels the UI must show before later one-use routing."""

    intent_id: str
    intent_digest: str
    destination: HandoffDestination
    destination_label: str
    data_class: HandoffDataClass
    data_class_label: str
    required_capabilities: tuple[CapabilityId, ...]
    expires_at: float

    def __post_init__(self) -> None:
        _opaque_id(self.intent_id, "Handoff intent ID")
        _digest(self.intent_digest, "Handoff intent digest")
        if not isinstance(self.destination, HandoffDestination):
            raise TypeError("Handoff review destination is invalid")
        if not isinstance(self.data_class, HandoffDataClass):
            raise TypeError("Handoff review data class is invalid")
        for value, label in (
            (self.destination_label, "Destination label"),
            (self.data_class_label, "Data class label"),
        ):
            _bounded_text(value, maximum=MAX_LABEL_CHARS, label=label)
        expected = required_capabilities(self.destination)
        if self.required_capabilities != expected:
            raise HandoffSelectionError(
                "Handoff review capability labels are inconsistent"
            )
        _timestamp(self.expires_at, "Handoff review expiry")


def topology_digest(monitors: Sequence[MonitorDescriptor]) -> str:
    """Digest one complete ordered topology without labels or screen pixels."""

    if (
        not isinstance(monitors, Sequence)
        or not monitors
        or len(monitors) > 64
        or any(not isinstance(item, MonitorDescriptor) for item in monitors)
    ):
        raise HandoffSelectionError(
            "Monitor topology is invalid"
        )
    snapshots = [
        MonitorSnapshot.from_descriptor(
            item,
            topology_digest_value="0" * 64,
        )
        for item in monitors
    ]
    identities = [
        {
            "capture_index": item.capture_index,
            "dpi_x": float(item.dpi_x),
            "dpi_y": float(item.dpi_y),
            "logical": [
                item.logical_left,
                item.logical_top,
                item.logical_width,
                item.logical_height,
            ],
            "physical": list(item.physical.identity_key),
            "stable_id": item.stable_id,
        }
        for item in sorted(snapshots, key=lambda value: value.stable_id)
    ]
    if len({item["stable_id"] for item in identities}) != len(identities):
        raise HandoffSelectionError(
            "Monitor identities are not unique"
        )
    return hashlib.sha256(
        _canonical_json({"monitors": identities})
    ).hexdigest()


def capture_handoff_selection(
    *,
    selection_id: str,
    shape: SelectionShape,
    monitor: MonitorDescriptor,
    topology_digest_value: str,
    region: PhysicalRegion,
    capture_generation: str,
    capture_sha256: str,
    capture_byte_count: int,
    captured_at: float,
    expires_at: float,
    mask_sha256: str | None = None,
) -> HandoffSelection:
    """Build one selection after capture/exclusion has already succeeded."""

    snapshot = MonitorSnapshot.from_descriptor(
        monitor,
        topology_digest_value=topology_digest_value,
    )
    return HandoffSelection(
        selection_id=selection_id,
        schema_version=HANDOFF_SCHEMA_VERSION,
        shape=shape,
        monitor=snapshot,
        region=region,
        capture_generation=capture_generation,
        captured_at=captured_at,
        expires_at=expires_at,
        capture_sha256=capture_sha256,
        capture_byte_count=capture_byte_count,
        mask_sha256=mask_sha256,
        own_windows_excluded=True,
    )


def validate_current_selection(
    selection: HandoffSelection,
    *,
    monitor: MonitorDescriptor,
    topology_digest_value: str,
    capture_generation: str,
    now: float,
) -> None:
    """Fail closed when topology, DPI, generation, bounds, or time changed."""

    if not isinstance(selection, HandoffSelection):
        raise TypeError("Handoff selection is invalid")
    _timestamp(now, "Selection revalidation time")
    if now >= selection.expires_at:
        raise HandoffSelectionError("Handoff selection expired")
    _opaque_id(
        capture_generation,
        "Capture generation",
        maximum=MAX_CAPTURE_GENERATION_CHARS,
    )
    current = MonitorSnapshot.from_descriptor(
        monitor,
        topology_digest_value=topology_digest_value,
    )
    if (
        current.identity_key != selection.monitor.identity_key
        or capture_generation != selection.capture_generation
        or not selection.region.inside(monitor.physical)
    ):
        raise HandoffSelectionError(
            "Handoff selection no longer matches the screen"
        )


def build_handoff_intent(
    selection: HandoffSelection,
    *,
    intent_id: str,
    destination: HandoffDestination,
    data_class: HandoffDataClass,
    purpose: str,
    created_at: float,
    expires_at: float,
) -> HandoffIntent:
    if not isinstance(selection, HandoffSelection):
        raise TypeError("Handoff selection is invalid")
    if created_at < selection.captured_at or expires_at > selection.expires_at:
        raise HandoffSelectionError(
            "Handoff intent is outside the selection lifetime"
        )
    return HandoffIntent(
        intent_id=intent_id,
        selection_id=selection.selection_id,
        selection_digest=selection.selection_digest,
        destination=destination,
        data_class=data_class,
        purpose=purpose,
        created_at=created_at,
        expires_at=expires_at,
    )


def build_handoff_review(intent: HandoffIntent) -> HandoffReview:
    if not isinstance(intent, HandoffIntent):
        raise TypeError("Handoff intent is invalid")
    return HandoffReview(
        intent_id=intent.intent_id,
        intent_digest=intent.intent_digest,
        destination=intent.destination,
        destination_label={
            HandoffDestination.TUTOR_CONTEXT: "Tutor context",
            HandoffDestination.COMPOSE_PREVIEW: "Compose preview",
            HandoffDestination.TASK_AGENT_NEW_RUN: "New Task Agent run",
        }[intent.destination],
        data_class=intent.data_class,
        data_class_label={
            HandoffDataClass.SCREEN_PIXELS: (
                "Selected screen pixels may be sent to the chosen provider"
            ),
            HandoffDataClass.REDACTED_IMAGE: (
                "A reviewed redacted image may be sent to the destination"
            ),
            HandoffDataClass.OCR_TEXT: (
                "Locally extracted text may be sent to the destination"
            ),
        }[intent.data_class],
        required_capabilities=required_capabilities(intent.destination),
        expires_at=intent.expires_at,
    )


def required_capabilities(
    destination: HandoffDestination,
) -> tuple[CapabilityId, ...]:
    if not isinstance(destination, HandoffDestination):
        raise TypeError("Handoff destination is invalid")
    return {
        HandoffDestination.TUTOR_CONTEXT: (),
        HandoffDestination.COMPOSE_PREVIEW: (
            CapabilityId.COMPOSE_SCREEN_CONTEXT,
        ),
        HandoffDestination.TASK_AGENT_NEW_RUN: (
            CapabilityId.TASK_AGENT_RUN,
            CapabilityId.TASK_REGION_CONTEXT,
        ),
    }[destination]


def _opaque_id(
    value: object,
    label: str,
    *,
    maximum: int = 128,
) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or _OPAQUE_ID.fullmatch(value) is None
    ):
        raise HandoffSelectionError(f"{label} is invalid")


def _digest(value: object, label: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise HandoffSelectionError(f"{label} is invalid")


def _timestamp(value: object, label: str) -> None:
    if (
        type(value) not in (int, float)
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise HandoffSelectionError(f"{label} is invalid")


def _bounded_text(
    value: object,
    *,
    maximum: int,
    label: str,
) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
        or not value.isprintable()
    ):
        raise HandoffSelectionError(f"{label} is invalid")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
