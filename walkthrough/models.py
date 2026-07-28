"""Bounded data-only models for visual walkthrough instructions."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum


MAX_STEPS = 8
MAX_SHAPES_PER_STEP = 4
MAX_TOTAL_SHAPES = 8
MAX_NARRATION_CHARS = 500
MAX_TOTAL_NARRATION_CHARS = 3_000
MAX_LABEL_CHARS = 80
MIN_STEP_TTL_SECONDS = 1.0
MAX_STEP_TTL_SECONDS = 30.0
MAX_DISPLAY_ID_CHARS = 128
_OPAQUE_REFERENCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class StepKind(str, Enum):
    TARGET = "TARGET"
    HOVER = "HOVER"
    HIGHLIGHT = "HIGHLIGHT"
    POINT = "POINT"
    SHAPE = "SHAPE"


class ShapeKind(str, Enum):
    LINE = "line"
    ARROW = "arrow"
    RECTANGLE = "rectangle"
    CIRCLE = "circle"
    UNDERLINE = "underline"


class ShapeColor(str, Enum):
    BLUE = "blue"
    RED = "red"
    GREEN = "green"
    YELLOW = "yellow"
    ORANGE = "orange"
    PURPLE = "purple"
    WHITE = "white"
    CYAN = "cyan"


@dataclass(frozen=True, slots=True)
class DisplayPoint:
    """Normalized display coordinate with no mouse or action semantics."""

    display_id: str
    x: float
    y: float

    def __post_init__(self) -> None:
        _display_id(self.display_id)
        _coordinate(self.x, "x")
        _coordinate(self.y, "y")


@dataclass(frozen=True, slots=True)
class VisualTarget:
    """Read-only UIA identity and logical bounds resolved by trusted code."""

    opaque_id: str
    display_id: str
    identity_digest: str
    logical_left: float
    logical_top: float
    logical_width: float
    logical_height: float
    expires_at: float

    def __post_init__(self) -> None:
        if (
            not isinstance(self.opaque_id, str)
            or not _OPAQUE_REFERENCE_RE.fullmatch(self.opaque_id)
        ):
            raise ValueError("visual target reference is invalid")
        _display_id(self.display_id)
        if (
            not isinstance(self.identity_digest, str)
            or not _DIGEST_RE.fullmatch(self.identity_digest)
        ):
            raise ValueError("visual target identity digest is invalid")
        for name in (
            "logical_left",
            "logical_top",
            "logical_width",
            "logical_height",
            "expires_at",
        ):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError(f"visual target {name} is invalid")
        if self.logical_width <= 0 or self.logical_height <= 0:
            raise ValueError("visual target bounds are invalid")
        if self.expires_at <= 0:
            raise ValueError("visual target expiry is invalid")


@dataclass(frozen=True, slots=True)
class VisualShape:
    """One normalized overlay shape; never an input or automation request."""

    kind: ShapeKind
    points: tuple[tuple[float, float], ...]
    color: ShapeColor
    radius: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ShapeKind):
            raise TypeError("visual shape kind is invalid")
        if not isinstance(self.color, ShapeColor):
            raise TypeError("visual shape color is invalid")
        if not isinstance(self.points, tuple):
            raise TypeError("visual shape points are invalid")
        expected = 1 if self.kind is ShapeKind.CIRCLE else 2
        if len(self.points) != expected:
            raise ValueError("visual shape point count is invalid")
        for point in self.points:
            if not isinstance(point, tuple) or len(point) != 2:
                raise ValueError("visual shape point is invalid")
            _coordinate(point[0], "shape x")
            _coordinate(point[1], "shape y")
        if self.kind is ShapeKind.CIRCLE:
            if (
                type(self.radius) not in (int, float)
                or not math.isfinite(self.radius)
                or not 1.0 <= self.radius <= 250.0
            ):
                raise ValueError("visual circle radius is invalid")
        elif self.radius is not None:
            raise ValueError("only a visual circle may declare radius")


@dataclass(frozen=True, slots=True)
class WalkthroughStep:
    step_id: str
    kind: StepKind
    narration: str
    ttl_seconds: float
    label: str = ""
    target: VisualTarget | None = None
    point: DisplayPoint | None = None
    display_id: str | None = None
    shapes: tuple[VisualShape, ...] = ()
    coordinate_display_only: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.step_id, str)
            or not _OPAQUE_REFERENCE_RE.fullmatch(self.step_id)
        ):
            raise ValueError("walkthrough step id is invalid")
        if not isinstance(self.kind, StepKind):
            raise TypeError("walkthrough step kind is invalid")
        _text(self.narration, "narration", MAX_NARRATION_CHARS, required=True)
        _text(self.label, "label", MAX_LABEL_CHARS, required=False)
        if (
            type(self.ttl_seconds) not in (int, float)
            or not math.isfinite(self.ttl_seconds)
            or not MIN_STEP_TTL_SECONDS
            <= self.ttl_seconds
            <= MAX_STEP_TTL_SECONDS
        ):
            raise ValueError("walkthrough step TTL is invalid")
        if type(self.coordinate_display_only) is not bool:
            raise TypeError("coordinate authority marker is invalid")
        if not isinstance(self.shapes, tuple):
            raise TypeError("walkthrough shapes are invalid")

        target_kinds = {
            StepKind.TARGET,
            StepKind.HOVER,
            StepKind.HIGHLIGHT,
        }
        if self.kind in target_kinds:
            if (
                self.target is None
                or self.point is not None
                or self.display_id is not None
                or self.shapes
                or self.coordinate_display_only
            ):
                raise ValueError("target walkthrough step shape is invalid")
            return
        if self.kind is StepKind.POINT:
            if (
                self.shapes
                or self.display_id is not None
                or (self.target is None) == (self.point is None)
            ):
                raise ValueError("point walkthrough step requires one target")
            if self.point is not None and not self.coordinate_display_only:
                raise ValueError("coordinate point must be display-only")
            if self.target is not None and self.coordinate_display_only:
                raise ValueError("UIA target must not be marked coordinate-only")
            return
        if self.kind is StepKind.SHAPE:
            if (
                self.target is not None
                or self.point is not None
                or self.display_id is None
                or not 1 <= len(self.shapes) <= MAX_SHAPES_PER_STEP
                or not self.coordinate_display_only
            ):
                raise ValueError("shape walkthrough step is invalid")
            _display_id(self.display_id)
            if any(
                not isinstance(shape, VisualShape) for shape in self.shapes
            ):
                raise TypeError("walkthrough shape entry is invalid")
            return
        raise ValueError("unsupported walkthrough step kind")


@dataclass(frozen=True, slots=True)
class Walkthrough:
    protocol_version: int
    walkthrough_id: str
    created_at: float
    steps: tuple[WalkthroughStep, ...]

    def __post_init__(self) -> None:
        if self.protocol_version != 1:
            raise ValueError("walkthrough protocol version is invalid")
        if (
            not isinstance(self.walkthrough_id, str)
            or not _OPAQUE_REFERENCE_RE.fullmatch(self.walkthrough_id)
        ):
            raise ValueError("walkthrough id is invalid")
        if (
            type(self.created_at) not in (int, float)
            or not math.isfinite(self.created_at)
            or self.created_at <= 0
        ):
            raise ValueError("walkthrough creation time is invalid")
        if (
            not isinstance(self.steps, tuple)
            or not 1 <= len(self.steps) <= MAX_STEPS
            or any(not isinstance(step, WalkthroughStep) for step in self.steps)
        ):
            raise ValueError("walkthrough steps are invalid")
        if len({step.step_id for step in self.steps}) != len(self.steps):
            raise ValueError("walkthrough step ids must be unique")
        if (
            sum(len(step.narration) for step in self.steps)
            > MAX_TOTAL_NARRATION_CHARS
        ):
            raise ValueError("walkthrough narration is too large")
        if (
            sum(len(step.shapes) for step in self.steps)
            > MAX_TOTAL_SHAPES
        ):
            raise ValueError("walkthrough contains too many shapes")


def _coordinate(value: float, name: str) -> None:
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or not 0.0 <= value <= 1_000.0
    ):
        raise ValueError(f"visual {name} coordinate is invalid")


def _display_id(value: str) -> None:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_DISPLAY_ID_CHARS
        or not value.isprintable()
        or value.strip() != value
    ):
        raise ValueError("visual display id is invalid")


def _text(
    value: str,
    name: str,
    limit: int,
    *,
    required: bool,
) -> None:
    if (
        not isinstance(value, str)
        or len(value) > limit
        or not value.isprintable()
        or value.strip() != value
        or (required and not value)
    ):
        raise ValueError(f"walkthrough {name} is invalid")
