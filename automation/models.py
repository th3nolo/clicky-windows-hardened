"""Immutable identities for a future allowlisted UI Automation action.

These contracts deliberately contain no action executor. They describe the
security-relevant target captured by a trusted Windows inspector so later
highlight, approval, revalidation, and execution stages can bind to one exact
control without falling back to coordinates.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum


MAX_TARGET_TEXT_CHARS = 256
MAX_AUTOMATION_ID_CHARS = 512
MAX_RUNTIME_ID_PARTS = 64
MAX_COORDINATE_MAGNITUDE = 10_000_000.0
MAX_PROCESS_START_TIME_NS = 2**63 - 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DesktopActionKind(str, Enum):
    """The complete V1 semantic action vocabulary.

    Raw mouse and keyboard input are intentionally absent.
    """

    FOCUS = "focus"
    INVOKE = "invoke"
    SELECT = "select"
    TOGGLE = "toggle"
    EXPAND = "expand"
    COLLAPSE = "collapse"
    SCROLL = "scroll"
    SET_VALUE = "set_value"


class AutomationPattern(str, Enum):
    """UIA patterns that may back one V1 semantic action."""

    INVOKE = "InvokePattern"
    SELECTION_ITEM = "SelectionItemPattern"
    TOGGLE = "TogglePattern"
    EXPAND_COLLAPSE = "ExpandCollapsePattern"
    SCROLL = "ScrollPattern"
    VALUE = "ValuePattern"


@dataclass(frozen=True, slots=True)
class DesktopBounds:
    """UIA bounding rectangle in physical desktop coordinates."""

    left: float
    top: float
    width: float
    height: float

    def __post_init__(self) -> None:
        values = (self.left, self.top, self.width, self.height)
        if any(
            type(value) not in (int, float)
            or not math.isfinite(value)
            or abs(value) > MAX_COORDINATE_MAGNITUDE
            for value in values
        ):
            raise ValueError("Desktop target bounds are invalid")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("Desktop target bounds must have positive size")

    @property
    def identity_key(self) -> tuple[float, float, float, float]:
        return (
            float(self.left),
            float(self.top),
            float(self.width),
            float(self.height),
        )


@dataclass(frozen=True, slots=True)
class DesktopTarget:
    """Security-relevant identity captured without reading a control value."""

    process_id: int
    process_start_time_ns: int
    application_name: str
    application_identity: str
    top_level_hwnd: int
    foreground_hwnd: int
    runtime_id: tuple[int, ...]
    control_type: str
    framework_id: str
    automation_id: str
    control_name: str = field(repr=False)
    bounds: DesktopBounds
    supported_patterns: frozenset[AutomationPattern]
    enabled: bool
    offscreen: bool
    control_element: bool
    password: bool
    protected: bool
    clicky_process_id: int
    clicky_integrity: int | None
    target_integrity: int | None
    desktop_name: str

    def __post_init__(self) -> None:
        _positive_int(self.process_id, "Target process ID")
        _positive_int(self.clicky_process_id, "Clicky process ID")
        _positive_int(self.top_level_hwnd, "Top-level window handle")
        _positive_int(self.foreground_hwnd, "Foreground window handle")
        if (
            type(self.process_start_time_ns) is not int
            or not 0 < self.process_start_time_ns <= MAX_PROCESS_START_TIME_NS
        ):
            raise ValueError("Target process start time is invalid")
        _bounded_text(
            self.application_name,
            MAX_TARGET_TEXT_CHARS,
            "Application name",
        )
        _bounded_text(
            self.control_type,
            MAX_TARGET_TEXT_CHARS,
            "Control type",
        )
        _bounded_text(
            self.framework_id,
            MAX_TARGET_TEXT_CHARS,
            "Framework ID",
            allow_empty=True,
        )
        _bounded_text(
            self.automation_id,
            MAX_AUTOMATION_ID_CHARS,
            "Automation ID",
            allow_empty=True,
        )
        _bounded_text(
            self.control_name,
            MAX_TARGET_TEXT_CHARS,
            "Control name",
            allow_empty=True,
        )
        _bounded_text(
            self.desktop_name,
            MAX_TARGET_TEXT_CHARS,
            "Desktop name",
        )
        if not _SHA256.fullmatch(self.application_identity):
            raise ValueError("Application identity must be a SHA-256 digest")
        _runtime_id(self.runtime_id)
        if not isinstance(self.bounds, DesktopBounds):
            raise TypeError("Desktop target bounds are invalid")
        if not isinstance(self.supported_patterns, frozenset) or any(
            not isinstance(pattern, AutomationPattern)
            for pattern in self.supported_patterns
        ):
            raise TypeError("Supported patterns must be a frozen pattern set")
        for value in (
            self.enabled,
            self.offscreen,
            self.control_element,
            self.password,
            self.protected,
        ):
            if type(value) is not bool:
                raise TypeError("Desktop target policy flags must be booleans")
        for value in (self.clicky_integrity, self.target_integrity):
            if value is not None and (type(value) is not int or value < 0):
                raise TypeError(
                    "Process integrity must be non-negative or unknown"
                )

    @property
    def identity_key(self) -> tuple[object, ...]:
        """Stable control identity, excluding mutable presentation state."""

        return (
            self.process_id,
            self.process_start_time_ns,
            self.application_identity,
            self.top_level_hwnd,
            self.runtime_id,
            self.control_type,
            self.framework_id,
            self.automation_id,
        )

    @property
    def presentation_key(self) -> tuple[object, ...]:
        """State that must be revalidated but may legitimately move."""

        return (
            self.application_name,
            self.control_name,
            self.foreground_hwnd,
            self.bounds.identity_key,
            self.supported_patterns,
            self.enabled,
            self.offscreen,
            self.control_element,
            self.password,
            self.protected,
            self.clicky_integrity,
            self.target_integrity,
            self.desktop_name.casefold(),
        )

    @property
    def identity_digest(self) -> str:
        """Canonical digest for highlight, approval, and action binding."""

        return hashlib.sha256(
            _canonical_json(
                {
                    "application_identity": self.application_identity,
                    "automation_id": self.automation_id,
                    "control_type": self.control_type,
                    "framework_id": self.framework_id,
                    "process_id": self.process_id,
                    "process_start_time_ns": self.process_start_time_ns,
                    "runtime_id": list(self.runtime_id),
                    "top_level_hwnd": self.top_level_hwnd,
                }
            )
        ).hexdigest()

    @property
    def review_digest(self) -> str:
        """Digest of exact identity plus the state shown before execution."""

        return hashlib.sha256(
            _canonical_json(
                {
                    "application_name": self.application_name,
                    "bounds": list(self.bounds.identity_key),
                    "clicky_integrity": self.clicky_integrity,
                    "control_name": self.control_name,
                    "control_element": self.control_element,
                    "desktop_name": self.desktop_name.casefold(),
                    "enabled": self.enabled,
                    "foreground_hwnd": self.foreground_hwnd,
                    "identity_digest": self.identity_digest,
                    "offscreen": self.offscreen,
                    "password": self.password,
                    "patterns": sorted(
                        pattern.value for pattern in self.supported_patterns
                    ),
                    "protected": self.protected,
                    "target_integrity": self.target_integrity,
                }
            )
        ).hexdigest()


def required_pattern(
    action: DesktopActionKind,
) -> AutomationPattern | None:
    """Return the semantic UIA pattern for an action.

    Focus uses UIA focus semantics and therefore has no pattern requirement.
    """

    if not isinstance(action, DesktopActionKind):
        raise TypeError("Desktop action kind is invalid")
    return {
        DesktopActionKind.FOCUS: None,
        DesktopActionKind.INVOKE: AutomationPattern.INVOKE,
        DesktopActionKind.SELECT: AutomationPattern.SELECTION_ITEM,
        DesktopActionKind.TOGGLE: AutomationPattern.TOGGLE,
        DesktopActionKind.EXPAND: AutomationPattern.EXPAND_COLLAPSE,
        DesktopActionKind.COLLAPSE: AutomationPattern.EXPAND_COLLAPSE,
        DesktopActionKind.SCROLL: AutomationPattern.SCROLL,
        DesktopActionKind.SET_VALUE: AutomationPattern.VALUE,
    }[action]


def _runtime_id(value: tuple[int, ...]) -> None:
    if (
        not isinstance(value, tuple)
        or not 1 <= len(value) <= MAX_RUNTIME_ID_PARTS
        or any(type(part) is not int for part in value)
    ):
        raise ValueError("UI Automation runtime ID is invalid")


def _positive_int(value: int, label: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} is invalid")


def _bounded_text(
    value: str,
    limit: int,
    label: str,
    *,
    allow_empty: bool = False,
) -> None:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > limit
        or not value.isprintable()
    ):
        raise ValueError(f"{label} must be bounded printable text")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


__all__ = [
    "MAX_RUNTIME_ID_PARTS",
    "MAX_TARGET_TEXT_CHARS",
    "AutomationPattern",
    "DesktopActionKind",
    "DesktopBounds",
    "DesktopTarget",
    "required_pattern",
]
