"""Atomic parser for the strict visual-walkthrough response envelope."""

from __future__ import annotations

import json
import math
import time
from typing import Protocol

from walkthrough.models import (
    DisplayPoint,
    ShapeColor,
    ShapeKind,
    StepKind,
    VisualShape,
    VisualTarget,
    Walkthrough,
    WalkthroughStep,
)


SCHEMA_ID = "clicky.visual_walkthrough"
PROTOCOL_VERSION = 1
MAX_PAYLOAD_BYTES = 16 * 1024
_ROOT_KEYS = frozenset({"schema", "version", "walkthrough_id", "steps"})
_COMMON_STEP_KEYS = frozenset(
    {"step_id", "type", "narration", "ttl_seconds"}
)
_TARGET_STEP_KEYS = _COMMON_STEP_KEYS | {"target_ref", "label"}
_POINT_TARGET_KEYS = _COMMON_STEP_KEYS | {"target_ref", "label"}
_POINT_COORDINATE_KEYS = _COMMON_STEP_KEYS | {
    "display_ref",
    "point",
    "label",
    "coordinate_display_only",
}
_SHAPE_STEP_KEYS = _COMMON_STEP_KEYS | {
    "display_ref",
    "shapes",
    "coordinate_display_only",
}


class WalkthroughProtocolError(ValueError):
    """The complete walkthrough must be discarded without rendering."""


class WalkthroughTargetGuard(Protocol):
    """Resolve and revalidate read-only UIA identities without action access."""

    def resolve(self, opaque_reference: str) -> VisualTarget | None: ...

    def revalidate(self, target: VisualTarget) -> bool: ...


class WalkthroughProtocolParser:
    def __init__(
        self,
        target_guard: WalkthroughTargetGuard,
        *,
        clock=time.monotonic,
    ) -> None:
        if not callable(getattr(target_guard, "resolve", None)):
            raise TypeError("walkthrough target resolver is required")
        if not callable(getattr(target_guard, "revalidate", None)):
            raise TypeError("walkthrough target revalidator is required")
        if not callable(clock):
            raise TypeError("walkthrough clock is required")
        self._targets = target_guard
        self._clock = clock

    def parse(
        self,
        payload: str | bytes,
        *,
        known_displays: frozenset[str],
    ) -> Walkthrough:
        """Validate the whole response or raise before any step can render."""

        raw = _payload_bytes(payload)
        if len(raw) > MAX_PAYLOAD_BYTES:
            raise WalkthroughProtocolError("walkthrough payload is too large")
        displays = _known_displays(known_displays)
        try:
            parsed = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_number,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise WalkthroughProtocolError(
                "walkthrough payload is not strict JSON"
            ) from exc
        root = _mapping(parsed, "walkthrough root")
        _exact_keys(root, _ROOT_KEYS, "walkthrough root")
        if root["schema"] != SCHEMA_ID:
            raise WalkthroughProtocolError("walkthrough schema is unsupported")
        if type(root["version"]) is not int or root["version"] != 1:
            raise WalkthroughProtocolError(
                "walkthrough version is unsupported"
            )
        walkthrough_id = _string(root["walkthrough_id"], "walkthrough id")
        raw_steps = root["steps"]
        if not isinstance(raw_steps, list) or not raw_steps:
            raise WalkthroughProtocolError("walkthrough steps are invalid")

        now = float(self._clock())
        if not math.isfinite(now) or now <= 0:
            raise WalkthroughProtocolError("walkthrough clock is invalid")
        steps = []
        semantic_steps = set()
        for raw_step in raw_steps:
            step_mapping = _mapping(raw_step, "walkthrough step")
            semantic = _semantic_step(step_mapping)
            if semantic in semantic_steps:
                raise WalkthroughProtocolError(
                    "walkthrough contains a duplicate step"
                )
            semantic_steps.add(semantic)
            steps.append(
                self._parse_step(
                    step_mapping,
                    displays=displays,
                    now=now,
                )
            )
        try:
            return Walkthrough(
                protocol_version=PROTOCOL_VERSION,
                walkthrough_id=walkthrough_id,
                created_at=now,
                steps=tuple(steps),
            )
        except (TypeError, ValueError) as exc:
            raise WalkthroughProtocolError(str(exc)) from exc

    def _parse_step(
        self,
        raw: dict,
        *,
        displays: frozenset[str],
        now: float,
    ) -> WalkthroughStep:
        kind_raw = raw.get("type")
        try:
            kind = StepKind(kind_raw)
        except (TypeError, ValueError) as exc:
            raise WalkthroughProtocolError(
                "walkthrough step type is unsupported"
            ) from exc
        step_id = _string(raw.get("step_id"), "walkthrough step id")
        narration = _string(
            raw.get("narration"),
            "walkthrough narration",
        )
        ttl = _number(raw.get("ttl_seconds"), "walkthrough step TTL")
        common = {
            "step_id": step_id,
            "kind": kind,
            "narration": narration,
            "ttl_seconds": ttl,
        }

        if kind in {
            StepKind.TARGET,
            StepKind.HOVER,
            StepKind.HIGHLIGHT,
        }:
            _allowed_keys(
                raw,
                required=_COMMON_STEP_KEYS | {"target_ref"},
                allowed=_TARGET_STEP_KEYS,
                context="target walkthrough step",
            )
            return self._target_step(
                raw,
                common=common,
                displays=displays,
                now=now,
            )

        if kind is StepKind.POINT:
            target_ref = raw.get("target_ref")
            if target_ref is not None:
                _allowed_keys(
                    raw,
                    required=_COMMON_STEP_KEYS | {"target_ref"},
                    allowed=_POINT_TARGET_KEYS,
                    context="target point step",
                )
                return self._target_step(
                    raw,
                    common=common,
                    displays=displays,
                    now=now,
                )
            _exact_keys(raw, _POINT_COORDINATE_KEYS, "coordinate point step")
            _display_only(raw)
            display_id = _known_display(raw["display_ref"], displays)
            point = _point(raw["point"], display_id)
            return _build_step(
                **common,
                label=_optional_string(
                    raw.get("label"),
                    "walkthrough point label",
                ),
                point=point,
                coordinate_display_only=True,
            )

        if kind is StepKind.SHAPE:
            _exact_keys(raw, _SHAPE_STEP_KEYS, "shape walkthrough step")
            _display_only(raw)
            display_id = _known_display(raw["display_ref"], displays)
            shape_rows = raw["shapes"]
            if not isinstance(shape_rows, list) or not shape_rows:
                raise WalkthroughProtocolError(
                    "walkthrough shapes are invalid"
                )
            shapes = tuple(_shape(row) for row in shape_rows)
            return _build_step(
                **common,
                display_id=display_id,
                shapes=shapes,
                coordinate_display_only=True,
            )
        raise WalkthroughProtocolError("walkthrough step type is unsupported")

    def _target_step(
        self,
        raw: dict,
        *,
        common: dict,
        displays: frozenset[str],
        now: float,
    ) -> WalkthroughStep:
        reference = _string(raw["target_ref"], "visual target reference")
        try:
            target = self._targets.resolve(reference)
        except Exception as exc:
            raise WalkthroughProtocolError(
                "visual target resolution failed"
            ) from exc
        if not isinstance(target, VisualTarget) or target.opaque_id != reference:
            raise WalkthroughProtocolError("visual target is unavailable")
        if target.display_id not in displays:
            raise WalkthroughProtocolError(
                "visual target display is unavailable"
            )
        if target.expires_at <= now:
            raise WalkthroughProtocolError("visual target is stale")
        try:
            current = self._targets.revalidate(target)
        except Exception as exc:
            raise WalkthroughProtocolError(
                "visual target revalidation failed"
            ) from exc
        if current is not True:
            raise WalkthroughProtocolError("visual target is stale")
        return _build_step(
            **common,
            label=_optional_string(
                raw.get("label"),
                "walkthrough target label",
            ),
            target=target,
        )


def _build_step(**values) -> WalkthroughStep:
    try:
        return WalkthroughStep(**values)
    except (TypeError, ValueError) as exc:
        raise WalkthroughProtocolError(str(exc)) from exc


def _shape(value: object) -> VisualShape:
    raw = _mapping(value, "visual shape")
    kind_raw = raw.get("kind")
    try:
        kind = ShapeKind(kind_raw)
    except (TypeError, ValueError) as exc:
        raise WalkthroughProtocolError("visual shape kind is unsupported") from exc
    required = frozenset({"kind", "points", "color"})
    allowed = required | ({"radius"} if kind is ShapeKind.CIRCLE else set())
    _exact_keys(raw, frozenset(allowed), "visual shape")
    points_raw = raw["points"]
    if not isinstance(points_raw, list):
        raise WalkthroughProtocolError("visual shape points are invalid")
    points = tuple(_coordinate_pair(point) for point in points_raw)
    try:
        color = ShapeColor(raw["color"])
    except (TypeError, ValueError) as exc:
        raise WalkthroughProtocolError("visual shape color is unsupported") from exc
    radius = (
        _number(raw["radius"], "visual circle radius")
        if kind is ShapeKind.CIRCLE
        else None
    )
    try:
        return VisualShape(kind, points, color, radius)
    except (TypeError, ValueError) as exc:
        raise WalkthroughProtocolError(str(exc)) from exc


def _point(value: object, display_id: str) -> DisplayPoint:
    x, y = _coordinate_pair(value)
    try:
        return DisplayPoint(display_id, x, y)
    except (TypeError, ValueError) as exc:
        raise WalkthroughProtocolError(str(exc)) from exc


def _coordinate_pair(value: object) -> tuple[float, float]:
    if not isinstance(value, list) or len(value) != 2:
        raise WalkthroughProtocolError("visual coordinate pair is invalid")
    return (
        _number(value[0], "visual x coordinate"),
        _number(value[1], "visual y coordinate"),
    )


def _display_only(raw: dict) -> None:
    if raw.get("coordinate_display_only") is not True:
        raise WalkthroughProtocolError(
            "coordinate instruction lacks display-only marker"
        )


def _known_display(value: object, displays: frozenset[str]) -> str:
    display_id = _string(value, "visual display reference")
    if display_id not in displays:
        raise WalkthroughProtocolError("visual display is unavailable")
    return display_id


def _known_displays(value: frozenset[str]) -> frozenset[str]:
    if not isinstance(value, frozenset) or not value:
        raise WalkthroughProtocolError("known display set is invalid")
    for display_id in value:
        if (
            not isinstance(display_id, str)
            or not display_id
            or len(display_id) > 128
            or not display_id.isprintable()
            or display_id.strip() != display_id
        ):
            raise WalkthroughProtocolError("known display id is invalid")
    return value


def _payload_bytes(payload: str | bytes) -> bytes:
    if isinstance(payload, str):
        return payload.encode("utf-8")
    if isinstance(payload, bytes):
        return payload
    raise WalkthroughProtocolError("walkthrough payload type is invalid")


def _reject_duplicate_keys(pairs) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str):
    raise ValueError(f"non-finite JSON number: {value}")


def _mapping(value: object, context: str) -> dict:
    if not isinstance(value, dict):
        raise WalkthroughProtocolError(f"{context} is invalid")
    return value


def _exact_keys(value: dict, expected: frozenset[str], context: str) -> None:
    if frozenset(value) != expected:
        raise WalkthroughProtocolError(f"{context} shape is invalid")


def _allowed_keys(
    value: dict,
    *,
    required: frozenset[str],
    allowed: frozenset[str],
    context: str,
) -> None:
    keys = frozenset(value)
    if not required <= keys or not keys <= allowed:
        raise WalkthroughProtocolError(f"{context} shape is invalid")


def _string(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise WalkthroughProtocolError(f"{context} is invalid")
    return value


def _optional_string(value: object, context: str) -> str:
    if value is None:
        return ""
    return _string(value, context)


def _number(value: object, context: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise WalkthroughProtocolError(f"{context} is invalid")
    return float(value)


def _semantic_step(value: dict) -> str:
    copy = dict(value)
    copy.pop("step_id", None)
    try:
        return json.dumps(
            copy,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise WalkthroughProtocolError(
            "walkthrough step cannot be canonicalized"
        ) from exc


__all__ = [
    "MAX_PAYLOAD_BYTES",
    "PROTOCOL_VERSION",
    "SCHEMA_ID",
    "WalkthroughProtocolError",
    "WalkthroughProtocolParser",
    "WalkthroughTargetGuard",
]
