"""Transient, fail-closed region-selection state and geometry.

This module has no Qt, screen-capture, provider, task, insertion, or desktop
action dependency. UI and capture adapters inject exact frames and current
topology, then receive one transient payload that must be reviewed elsewhere.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Sequence

from handoff.models import (
    MAX_CAPTURE_BYTES,
    HandoffSelection,
    HandoffSelectionError,
    PhysicalRegion,
    SelectionShape,
    capture_handoff_selection,
    topology_digest,
    validate_current_selection,
)
from screen.topology import MonitorDescriptor, Rect


MAX_CAPTURE_MONITORS = 64
MAX_CAPTURE_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_LASSO_POINTS = 256
MIN_LASSO_POINTS = 12
MIN_LASSO_AREA_PIXELS = 64.0
MAX_LASSO_GAP_PIXELS = 96.0
MAX_MEDIA_TYPE_CHARS = 127
_MEDIA_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$"
)


class RegionSelectionState(str, Enum):
    SELECTING = "selecting"
    REVIEWING = "reviewing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class RegionSelectionFailure(str, Enum):
    USER_CANCELLED = "user_cancelled"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    CAPTURE_DENIED = "capture_denied"
    CAPTURE_FAILED = "capture_failed"
    DISPLAY_CHANGED = "display_changed"
    INVALID_SELECTION = "invalid_selection"
    OWNED_WINDOW_OVERLAP = "owned_window_overlap"


@dataclass(frozen=True, slots=True)
class LassoPoint:
    x: int
    y: int

    def __post_init__(self) -> None:
        if type(self.x) is not int or type(self.y) is not int:
            raise HandoffSelectionError("Lasso point is invalid")
        if abs(self.x) > 10_000_000 or abs(self.y) > 10_000_000:
            raise HandoffSelectionError("Lasso point is invalid")


@dataclass(frozen=True, slots=True)
class TransientMonitorFrame:
    """One exact full-resolution JPEG kept only for the active UI flow."""

    monitor: MonitorDescriptor
    jpeg_bytes: bytearray = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.monitor, MonitorDescriptor):
            raise TypeError("Transient frame monitor is invalid")
        if (
            not isinstance(self.jpeg_bytes, bytearray)
            or not 4 <= len(self.jpeg_bytes) <= MAX_CAPTURE_BYTES
            or not self.jpeg_bytes.startswith(b"\xff\xd8\xff")
            or not self.jpeg_bytes.endswith(b"\xff\xd9")
        ):
            raise HandoffSelectionError(
                "Transient monitor frame is invalid"
            )

    def wipe(self) -> None:
        self.jpeg_bytes[:] = b"\x00" * len(self.jpeg_bytes)


@dataclass(frozen=True, slots=True)
class RegionCaptureBundle:
    """One topology-bound capture generation; never persisted."""

    generation: str
    captured_at: float
    expires_at: float
    topology_sha256: str
    frames: tuple[TransientMonitorFrame, ...] = field(repr=False)
    owned_window_regions: tuple[PhysicalRegion, ...] = field(
        default=(),
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            not isinstance(self.generation, str)
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                self.generation,
            )
        ):
            raise HandoffSelectionError(
                "Capture generation is invalid"
            )
        _timestamp(self.captured_at, "Capture time")
        _timestamp(self.expires_at, "Capture expiry")
        if not 0 < self.expires_at - self.captured_at <= 120.0:
            raise HandoffSelectionError(
                "Capture lifetime is invalid"
            )
        if (
            not isinstance(self.frames, tuple)
            or not 1 <= len(self.frames) <= MAX_CAPTURE_MONITORS
            or any(
                not isinstance(frame, TransientMonitorFrame)
                for frame in self.frames
            )
        ):
            raise HandoffSelectionError(
                "Capture frames are invalid"
            )
        if sum(len(frame.jpeg_bytes) for frame in self.frames) > (
            MAX_CAPTURE_BUNDLE_BYTES
        ):
            raise HandoffSelectionError(
                "Capture bundle byte limit exceeded"
            )
        monitor_ids = tuple(frame.monitor.stable_id for frame in self.frames)
        if len(set(monitor_ids)) != len(monitor_ids):
            raise HandoffSelectionError(
                "Capture monitor identities are duplicated"
            )
        expected = topology_digest(
            tuple(frame.monitor for frame in self.frames)
        )
        if self.topology_sha256 != expected:
            raise HandoffSelectionError(
                "Capture topology digest is invalid"
            )
        if (
            not isinstance(self.owned_window_regions, tuple)
            or len(self.owned_window_regions) > 256
            or any(
                not isinstance(region, PhysicalRegion)
                for region in self.owned_window_regions
            )
        ):
            raise HandoffSelectionError(
                "Owned-window regions are invalid"
            )

    def frame_for(self, monitor_id: str) -> TransientMonitorFrame:
        matches = [
            frame
            for frame in self.frames
            if frame.monitor.stable_id == monitor_id
        ]
        if len(matches) != 1:
            raise HandoffSelectionError(
                "Selected monitor is unavailable"
            )
        return matches[0]

    def wipe(self) -> None:
        for frame in self.frames:
            frame.wipe()


@dataclass(frozen=True, slots=True)
class BuiltSelectionImage:
    """Exact selected bytes returned by a reviewed local image adapter."""

    content: bytearray = field(repr=False)
    media_type: str
    mask_sha256: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.content, bytearray)
            or not 1 <= len(self.content) <= MAX_CAPTURE_BYTES
        ):
            raise HandoffSelectionError(
                "Selected image payload is invalid"
            )
        if (
            not isinstance(self.media_type, str)
            or len(self.media_type) > MAX_MEDIA_TYPE_CHARS
            or _MEDIA_TYPE.fullmatch(self.media_type) is None
        ):
            raise HandoffSelectionError(
                "Selected image media type is invalid"
            )
        if self.mask_sha256 is not None and (
            not isinstance(self.mask_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.mask_sha256) is None
        ):
            raise HandoffSelectionError(
                "Selected image mask digest is invalid"
            )

    def wipe(self) -> None:
        self.content[:] = b"\x00" * len(self.content)


@dataclass(frozen=True, slots=True)
class TransientSelectionPayload:
    """Selection evidence plus exact preview/routing bytes."""

    selection: HandoffSelection
    image: BuiltSelectionImage = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.selection, HandoffSelection):
            raise TypeError("Transient selection is invalid")
        if not isinstance(self.image, BuiltSelectionImage):
            raise TypeError("Transient selected image is invalid")
        if hashlib.sha256(self.image.content).hexdigest() != (
            self.selection.capture_sha256
        ):
            raise HandoffSelectionError(
                "Selected image digest is inconsistent"
            )
        if len(self.image.content) != self.selection.capture_byte_count:
            raise HandoffSelectionError(
                "Selected image byte count is inconsistent"
            )
        if self.image.mask_sha256 != self.selection.mask_sha256:
            raise HandoffSelectionError(
                "Selected image mask is inconsistent"
            )

    def wipe(self) -> None:
        self.image.wipe()


SelectionImageBuilder = Callable[
    [
        TransientMonitorFrame,
        PhysicalRegion,
        tuple[LassoPoint, ...] | None,
    ],
    BuiltSelectionImage,
]
TopologyProvider = Callable[[], Sequence[MonitorDescriptor]]
GenerationProvider = Callable[[], str | None]


class RegionSelectionCoordinator:
    """Consume one capture bundle into at most one reviewable payload."""

    def __init__(
        self,
        bundle: RegionCaptureBundle,
        *,
        image_builder: SelectionImageBuilder,
        topology_provider: TopologyProvider,
        generation_provider: GenerationProvider,
        clock: Callable[[], float],
        selection_id_factory: Callable[[], str],
    ) -> None:
        if not isinstance(bundle, RegionCaptureBundle):
            raise TypeError("Region capture bundle is invalid")
        for callback, label in (
            (image_builder, "image builder"),
            (topology_provider, "topology provider"),
            (generation_provider, "generation provider"),
            (clock, "clock"),
            (selection_id_factory, "selection ID factory"),
        ):
            if not callable(callback):
                raise TypeError(f"Region selection {label} is invalid")
        self._bundle: RegionCaptureBundle | None = bundle
        self._image_builder = image_builder
        self._topology_provider = topology_provider
        self._generation_provider = generation_provider
        self._clock = clock
        self._selection_id_factory = selection_id_factory
        self._state = RegionSelectionState.SELECTING
        self._failure: RegionSelectionFailure | None = None
        self._payload: TransientSelectionPayload | None = None

    @property
    def state(self) -> RegionSelectionState:
        return self._state

    @property
    def failure(self) -> RegionSelectionFailure | None:
        return self._failure

    @property
    def payload(self) -> TransientSelectionPayload | None:
        return self._payload

    def select_rectangle(
        self,
        monitor_id: str,
        region: PhysicalRegion,
    ) -> TransientSelectionPayload:
        return self._select(
            monitor_id,
            region,
            shape=SelectionShape.RECTANGLE,
            lasso_points=None,
        )

    def select_lasso(
        self,
        monitor_id: str,
        points: Sequence[LassoPoint],
    ) -> TransientSelectionPayload:
        try:
            sanitized = sanitize_lasso(points)
            region = lasso_bounds(sanitized)
        except Exception:
            self.fail(RegionSelectionFailure.INVALID_SELECTION)
            raise
        return self._select(
            monitor_id,
            region,
            shape=SelectionShape.ELLIPSE_MASK,
            lasso_points=sanitized,
        )

    def validate_for_review(self) -> None:
        """Revalidate exact topology/generation immediately before approval."""

        if (
            self._state is not RegionSelectionState.REVIEWING
            or self._payload is None
            or self._bundle is None
        ):
            raise HandoffSelectionError(
                "Region selection is not awaiting review"
            )
        self._current_monitor(
            self._payload.selection.monitor.stable_id,
            now=float(self._clock()),
        )

    def complete(self) -> TransientSelectionPayload:
        if (
            self._state is not RegionSelectionState.REVIEWING
            or self._payload is None
        ):
            raise HandoffSelectionError(
                "Region selection is not awaiting completion"
            )
        self.validate_for_review()
        self._state = RegionSelectionState.COMPLETED
        payload = self._payload
        self._wipe_bundle()
        return payload

    def cancel(
        self,
        reason: RegionSelectionFailure = (
            RegionSelectionFailure.USER_CANCELLED
        ),
    ) -> bool:
        if not isinstance(reason, RegionSelectionFailure):
            raise TypeError("Region selection cancellation reason is invalid")
        if self._state in {
            RegionSelectionState.COMPLETED,
            RegionSelectionState.CANCELLED,
            RegionSelectionState.FAILED,
        }:
            return False
        if self._payload is not None:
            self._payload.wipe()
            self._payload = None
        self._wipe_bundle()
        self._state = RegionSelectionState.CANCELLED
        self._failure = reason
        return True

    def fail(self, reason: RegionSelectionFailure) -> bool:
        if not isinstance(reason, RegionSelectionFailure):
            raise TypeError("Region selection failure reason is invalid")
        if self._state in {
            RegionSelectionState.COMPLETED,
            RegionSelectionState.CANCELLED,
            RegionSelectionState.FAILED,
        }:
            return False
        if self._payload is not None:
            self._payload.wipe()
            self._payload = None
        self._wipe_bundle()
        self._state = RegionSelectionState.FAILED
        self._failure = reason
        return True

    def _select(
        self,
        monitor_id: str,
        region: PhysicalRegion,
        *,
        shape: SelectionShape,
        lasso_points: tuple[LassoPoint, ...] | None,
    ) -> TransientSelectionPayload:
        if self._state is not RegionSelectionState.SELECTING:
            raise HandoffSelectionError(
                "Region selection was already consumed"
            )
        if self._bundle is None:
            raise HandoffSelectionError(
                "Region capture is unavailable"
            )
        if not isinstance(region, PhysicalRegion):
            raise TypeError("Selected region is invalid")
        now = float(self._clock())
        current_monitor = self._current_monitor(monitor_id, now=now)
        frame = self._bundle.frame_for(monitor_id)
        if _monitor_identity(frame.monitor) != _monitor_identity(
            current_monitor
        ):
            self.fail(RegionSelectionFailure.DISPLAY_CHANGED)
            raise HandoffSelectionError(
                "Selected display identity changed"
            )
        if not region.inside(frame.monitor.physical):
            self.fail(RegionSelectionFailure.INVALID_SELECTION)
            raise HandoffSelectionError(
                "Selected region is outside its monitor"
            )
        if any(
            regions_intersect(region, owned)
            for owned in self._bundle.owned_window_regions
        ):
            self.fail(RegionSelectionFailure.OWNED_WINDOW_OVERLAP)
            raise HandoffSelectionError(
                "Selected region overlaps a Clicky-owned window"
            )
        try:
            image = self._image_builder(frame, region, lasso_points)
        except Exception as exc:
            self.fail(RegionSelectionFailure.CAPTURE_FAILED)
            raise HandoffSelectionError(
                "Selected image could not be built"
            ) from exc
        if not isinstance(image, BuiltSelectionImage):
            self.fail(RegionSelectionFailure.CAPTURE_FAILED)
            raise HandoffSelectionError(
                "Selected image adapter returned an invalid result"
            )
        expected_mask = (
            image.mask_sha256
            if shape is SelectionShape.ELLIPSE_MASK
            else None
        )
        if (
            shape is SelectionShape.ELLIPSE_MASK
            and expected_mask is None
        ):
            image.wipe()
            self.fail(RegionSelectionFailure.CAPTURE_FAILED)
            raise HandoffSelectionError(
                "Freehand selection has no mask evidence"
            )
        try:
            selection = capture_handoff_selection(
                selection_id=self._selection_id_factory(),
                shape=shape,
                monitor=current_monitor,
                topology_digest_value=self._bundle.topology_sha256,
                region=region,
                capture_generation=self._bundle.generation,
                capture_sha256=hashlib.sha256(image.content).hexdigest(),
                capture_byte_count=len(image.content),
                captured_at=self._bundle.captured_at,
                expires_at=self._bundle.expires_at,
                mask_sha256=expected_mask,
            )
            validate_current_selection(
                selection,
                monitor=current_monitor,
                topology_digest_value=self._bundle.topology_sha256,
                capture_generation=self._bundle.generation,
                now=now,
            )
            payload = TransientSelectionPayload(
                selection=selection,
                image=image,
            )
        except Exception:
            image.wipe()
            self.fail(RegionSelectionFailure.INVALID_SELECTION)
            raise
        self._payload = payload
        self._state = RegionSelectionState.REVIEWING
        return payload

    def _current_monitor(
        self,
        monitor_id: str,
        *,
        now: float,
    ) -> MonitorDescriptor:
        if self._bundle is None:
            raise HandoffSelectionError(
                "Region capture is unavailable"
            )
        if now >= self._bundle.expires_at:
            self.fail(RegionSelectionFailure.EXPIRED)
            raise HandoffSelectionError("Region selection expired")
        if self._generation_provider() != self._bundle.generation:
            self.fail(RegionSelectionFailure.SUPERSEDED)
            raise HandoffSelectionError(
                "Region capture generation was superseded"
            )
        try:
            current = tuple(self._topology_provider())
            current_digest = topology_digest(current)
        except Exception:
            self.fail(RegionSelectionFailure.DISPLAY_CHANGED)
            raise HandoffSelectionError(
                "Current display topology is unavailable"
            )
        if current_digest != self._bundle.topology_sha256:
            self.fail(RegionSelectionFailure.DISPLAY_CHANGED)
            raise HandoffSelectionError(
                "Display topology changed during selection"
            )
        matches = [
            item for item in current if item.stable_id == monitor_id
        ]
        if len(matches) != 1:
            self.fail(RegionSelectionFailure.DISPLAY_CHANGED)
            raise HandoffSelectionError(
                "Selected display is unavailable"
            )
        return matches[0]

    def _wipe_bundle(self) -> None:
        if self._bundle is not None:
            self._bundle.wipe()
            self._bundle = None


def sanitize_lasso(
    points: Sequence[LassoPoint],
) -> tuple[LassoPoint, ...]:
    """Validate and close one simple freehand polygon."""

    if (
        not isinstance(points, Sequence)
        or not MIN_LASSO_POINTS <= len(points) <= MAX_LASSO_POINTS
        or any(not isinstance(point, LassoPoint) for point in points)
    ):
        raise HandoffSelectionError(
            "Freehand selection point count is invalid"
        )
    clean: list[LassoPoint] = []
    for point in points:
        if not clean or point != clean[-1]:
            clean.append(point)
    if len(clean) < MIN_LASSO_POINTS:
        raise HandoffSelectionError(
            "Freehand selection has too few distinct points"
        )
    first, last = clean[0], clean[-1]
    gap = math.hypot(last.x - first.x, last.y - first.y)
    if gap > MAX_LASSO_GAP_PIXELS:
        raise HandoffSelectionError(
            "Freehand selection is not closed"
        )
    if last != first:
        clean.append(first)
    if len(clean) > MAX_LASSO_POINTS + 1:
        raise HandoffSelectionError(
            "Freehand selection point limit exceeded"
        )
    area = abs(
        sum(
            first_point.x * second_point.y
            - second_point.x * first_point.y
            for first_point, second_point in zip(clean, clean[1:])
        )
    ) / 2.0
    if area < MIN_LASSO_AREA_PIXELS:
        raise HandoffSelectionError(
            "Freehand selection area is too small"
        )
    if _has_self_intersection(tuple(clean)):
        raise HandoffSelectionError(
            "Freehand selection crosses itself"
        )
    return tuple(clean)


def lasso_bounds(points: Sequence[LassoPoint]) -> PhysicalRegion:
    if not points or any(not isinstance(point, LassoPoint) for point in points):
        raise HandoffSelectionError("Freehand selection is invalid")
    left = min(point.x for point in points)
    top = min(point.y for point in points)
    right = max(point.x for point in points)
    bottom = max(point.y for point in points)
    return PhysicalRegion(left, top, right - left, bottom - top)


def regions_intersect(first: PhysicalRegion, second: PhysicalRegion) -> bool:
    if not isinstance(first, PhysicalRegion) or not isinstance(
        second,
        PhysicalRegion,
    ):
        raise TypeError("Region intersection requires typed regions")
    return not (
        first.right <= second.left
        or second.right <= first.left
        or first.bottom <= second.top
        or second.bottom <= first.top
    )


def logical_region_to_physical(
    monitor: MonitorDescriptor,
    region: Rect,
) -> PhysicalRegion:
    """Route one logical overlay rectangle through exactly one monitor."""

    if not isinstance(monitor, MonitorDescriptor) or not isinstance(
        region,
        Rect,
    ):
        raise TypeError("Logical selection geometry is invalid")
    if (
        region.width <= 0
        or region.height <= 0
        or region.left < monitor.logical.left
        or region.top < monitor.logical.top
        or region.right > monitor.logical.right
        or region.bottom > monitor.logical.bottom
    ):
        raise HandoffSelectionError(
            "Logical selection is outside its monitor"
        )
    scale_x = monitor.physical.width / monitor.logical.width
    scale_y = monitor.physical.height / monitor.logical.height
    left = monitor.physical.left + math.floor(
        (region.left - monitor.logical.left) * scale_x
    )
    top = monitor.physical.top + math.floor(
        (region.top - monitor.logical.top) * scale_y
    )
    right = monitor.physical.left + math.ceil(
        (region.right - monitor.logical.left) * scale_x
    )
    bottom = monitor.physical.top + math.ceil(
        (region.bottom - monitor.logical.top) * scale_y
    )
    return PhysicalRegion(left, top, right - left, bottom - top)


def logical_points_to_physical(
    monitor: MonitorDescriptor,
    points: Iterable[tuple[int, int]],
) -> tuple[LassoPoint, ...]:
    if not isinstance(monitor, MonitorDescriptor):
        raise TypeError("Monitor descriptor is invalid")
    converted: list[LassoPoint] = []
    scale_x = monitor.physical.width / monitor.logical.width
    scale_y = monitor.physical.height / monitor.logical.height
    for x, y in points:
        if (
            type(x) is not int
            or type(y) is not int
            or not monitor.logical.contains(x, y)
        ):
            raise HandoffSelectionError(
                "Logical freehand point is outside its monitor"
            )
        converted.append(
            LassoPoint(
                monitor.physical.left
                + round((x - monitor.logical.left) * scale_x),
                monitor.physical.top
                + round((y - monitor.logical.top) * scale_y),
            )
        )
    return tuple(converted)


def _has_self_intersection(points: tuple[LassoPoint, ...]) -> bool:
    segments = tuple(zip(points, points[1:]))
    for first_index, first in enumerate(segments):
        for second_index in range(first_index + 1, len(segments)):
            if abs(first_index - second_index) <= 1:
                continue
            if first_index == 0 and second_index == len(segments) - 1:
                continue
            if _segments_intersect(first, segments[second_index]):
                return True
    return False


def _segments_intersect(
    first: tuple[LassoPoint, LassoPoint],
    second: tuple[LassoPoint, LassoPoint],
) -> bool:
    a, b = first
    c, d = second

    def orientation(
        first_point: LassoPoint,
        second_point: LassoPoint,
        third_point: LassoPoint,
    ) -> int:
        value = (
            (second_point.y - first_point.y)
            * (third_point.x - second_point.x)
            - (second_point.x - first_point.x)
            * (third_point.y - second_point.y)
        )
        return 0 if value == 0 else (1 if value > 0 else 2)

    def on_segment(
        first_point: LassoPoint,
        second_point: LassoPoint,
        third_point: LassoPoint,
    ) -> bool:
        return (
            min(first_point.x, third_point.x)
            <= second_point.x
            <= max(first_point.x, third_point.x)
            and min(first_point.y, third_point.y)
            <= second_point.y
            <= max(first_point.y, third_point.y)
        )

    o1 = orientation(a, b, c)
    o2 = orientation(a, b, d)
    o3 = orientation(c, d, a)
    o4 = orientation(c, d, b)
    if o1 != o2 and o3 != o4:
        return True
    return bool(
        (o1 == 0 and on_segment(a, c, b))
        or (o2 == 0 and on_segment(a, d, b))
        or (o3 == 0 and on_segment(c, a, d))
        or (o4 == 0 and on_segment(c, b, d))
    )


def _timestamp(value: object, label: str) -> None:
    if (
        type(value) not in (int, float)
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise HandoffSelectionError(f"{label} is invalid")


def _monitor_identity(
    monitor: MonitorDescriptor,
) -> tuple[object, ...]:
    """Identity fields covered by the capture/topology contract."""

    if not isinstance(monitor, MonitorDescriptor):
        raise TypeError("Monitor descriptor is invalid")
    return (
        monitor.stable_id,
        monitor.capture_index,
        (
            monitor.physical.left,
            monitor.physical.top,
            monitor.physical.width,
            monitor.physical.height,
        ),
        (
            monitor.logical.left,
            monitor.logical.top,
            monitor.logical.width,
            monitor.logical.height,
        ),
        float(monitor.dpi_x),
        float(monitor.dpi_y),
    )


__all__ = [
    "BuiltSelectionImage",
    "LassoPoint",
    "RegionCaptureBundle",
    "RegionSelectionCoordinator",
    "RegionSelectionFailure",
    "RegionSelectionState",
    "TransientMonitorFrame",
    "TransientSelectionPayload",
    "lasso_bounds",
    "logical_points_to_physical",
    "logical_region_to_physical",
    "regions_intersect",
    "sanitize_lasso",
]
