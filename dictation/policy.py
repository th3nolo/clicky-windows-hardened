"""Fail-closed policy and identity checks for a dictation text target."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


MAX_TARGET_TEXT_CHARS = 256
MAX_RUNTIME_ID_PARTS = 64
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE_SURFACE_RE = re.compile(
    r"\b("
    r"password|passcode|credential|secret|sign[\s-]*in|log[\s-]*in|"
    r"authentication|authenticator|one[\s-]*time|otp|payment|checkout|"
    r"billing|credit[\s-]*card|debit[\s-]*card|card[\s-]*number|cvv|"
    r"bank(?:ing)?|wire[\s-]*transfer|security[\s-]*(?:setting|center)|"
    r"windows[\s-]*security|credential[\s-]*manager|administrator|"
    r"user[\s-]*account[\s-]*control|uac|registry[\s-]*editor|"
    r"local[\s-]*security[\s-]*policy|group[\s-]*policy"
    r")\b",
    re.IGNORECASE,
)


class TargetStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"


class TargetReason(str, Enum):
    ALLOWED = "allowed"
    INSPECTOR_ERROR = "inspector_error"
    NO_FOCUSED_CONTROL = "no_focused_control"
    INVALID_IDENTITY = "invalid_identity"
    CLICKY_SURFACE = "clicky_surface"
    SECURE_DESKTOP = "secure_desktop"
    DISABLED = "disabled"
    READ_ONLY = "read_only"
    PASSWORD = "password"
    PROTECTED = "protected"
    NOT_EDITABLE = "not_editable"
    SENSITIVE_SURFACE = "sensitive_surface"
    ELEVATION_UNKNOWN = "elevation_unknown"
    ELEVATION_MISMATCH = "elevation_mismatch"
    ADMINISTRATOR_SURFACE = "administrator_surface"
    FOCUS_CHANGED = "focus_changed"
    IDENTITY_CHANGED = "identity_changed"
    POLICY_CHANGED = "policy_changed"


class ElevationRelation(str, Enum):
    SAME = "same"
    CLICKY_HIGHER = "clicky_higher"
    TARGET_HIGHER = "target_higher"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TargetDescriptor:
    """Security-relevant UIA/Win32 identity captured without target contents."""

    process_id: int
    application_name: str
    application_identity: str
    top_level_hwnd: int
    runtime_id: tuple[int, ...]
    control_type: str
    framework_id: str
    editable: bool
    enabled: bool
    read_only: bool | None
    password: bool
    protected: bool
    has_keyboard_focus: bool
    foreground_hwnd: int
    focused_runtime_id: tuple[int, ...]
    clicky_process_id: int
    clicky_integrity: int | None
    target_integrity: int | None
    desktop_name: str
    sensitive_surface: bool = False

    def __post_init__(self) -> None:
        bounded_text = (
            self.application_name,
            self.control_type,
            self.framework_id,
            self.desktop_name,
        )
        if any(
            not isinstance(value, str)
            or len(value) > MAX_TARGET_TEXT_CHARS
            or not value.isprintable()
            for value in bounded_text
        ):
            raise ValueError("Target metadata must be bounded printable text")
        if (
            not isinstance(self.process_id, int)
            or self.process_id <= 0
            or not isinstance(self.clicky_process_id, int)
            or self.clicky_process_id <= 0
            or not isinstance(self.top_level_hwnd, int)
            or self.top_level_hwnd <= 0
            or not isinstance(self.foreground_hwnd, int)
            or self.foreground_hwnd <= 0
        ):
            raise ValueError("Target process and window identity is invalid")
        if not _SHA256_RE.fullmatch(self.application_identity):
            raise ValueError("Application identity must be a SHA-256 digest")
        _validate_runtime_id(self.runtime_id)
        _validate_runtime_id(self.focused_runtime_id)
        for value in (
            self.editable,
            self.enabled,
            self.password,
            self.protected,
            self.has_keyboard_focus,
            self.sensitive_surface,
        ):
            if type(value) is not bool:
                raise TypeError("Target policy flags must be booleans")
        if self.read_only is not None and type(self.read_only) is not bool:
            raise TypeError("Target read-only state must be boolean or unknown")
        for value in (self.clicky_integrity, self.target_integrity):
            if value is not None and (type(value) is not int or value < 0):
                raise TypeError(
                    "Process integrity level must be non-negative or unknown"
                )

    @property
    def identity_key(self) -> tuple[object, ...]:
        return (
            self.process_id,
            self.application_identity,
            self.top_level_hwnd,
            self.runtime_id,
            self.control_type,
            self.framework_id,
        )

    @property
    def focus_key(self) -> tuple[object, ...]:
        return (
            self.foreground_hwnd,
            self.focused_runtime_id,
        )

    @property
    def policy_key(self) -> tuple[object, ...]:
        return (
            self.editable,
            self.enabled,
            self.read_only,
            self.password,
            self.protected,
            self.has_keyboard_focus,
            self.clicky_integrity,
            self.target_integrity,
            self.desktop_name.casefold(),
            self.sensitive_surface,
        )

    @property
    def elevation_relation(self) -> ElevationRelation:
        if self.clicky_integrity is None or self.target_integrity is None:
            return ElevationRelation.UNKNOWN
        if self.clicky_integrity == self.target_integrity:
            return ElevationRelation.SAME
        if self.clicky_integrity > self.target_integrity:
            return ElevationRelation.CLICKY_HIGHER
        return ElevationRelation.TARGET_HIGHER


@dataclass(frozen=True, slots=True)
class TargetLease:
    descriptor: TargetDescriptor = field(repr=False)

    @property
    def application_name(self) -> str:
        return self.descriptor.application_name


@dataclass(frozen=True, slots=True)
class TargetDecision:
    status: TargetStatus
    reason: TargetReason
    lease: TargetLease | None = field(default=None, repr=False)
    changed_fields: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.status is TargetStatus.ALLOWED and self.lease is not None


@dataclass(frozen=True, slots=True)
class TargetDiagnostics:
    """Content-free data safe for local diagnostics and user-visible results."""

    status: TargetStatus
    reason: TargetReason
    application_name: str | None
    control_type: str | None
    framework_id: str | None
    changed_fields: tuple[str, ...]


def diagnostics(decision: TargetDecision) -> TargetDiagnostics:
    descriptor = decision.lease.descriptor if decision.lease else None
    return TargetDiagnostics(
        status=decision.status,
        reason=decision.reason,
        application_name=(
            descriptor.application_name if descriptor is not None else None
        ),
        control_type=(
            descriptor.control_type if descriptor is not None else None
        ),
        framework_id=(
            descriptor.framework_id if descriptor is not None else None
        ),
        changed_fields=decision.changed_fields,
    )


class SecureTargetPolicy:
    """Accept ordinary editable targets and reject sensitive authority."""

    def evaluate(self, descriptor: TargetDescriptor) -> TargetDecision:
        reason = self._blocked_reason(descriptor)
        lease = TargetLease(descriptor)
        if reason is None:
            return TargetDecision(
                TargetStatus.ALLOWED,
                TargetReason.ALLOWED,
                lease,
            )
        return TargetDecision(TargetStatus.BLOCKED, reason, lease)

    def revalidate(
        self,
        lease: TargetLease,
        current: TargetDescriptor,
    ) -> TargetDecision:
        current_decision = self.evaluate(current)
        if not current_decision.allowed:
            return TargetDecision(
                current_decision.status,
                current_decision.reason,
                current_decision.lease,
                ("policy",),
            )

        captured = lease.descriptor
        if captured.focus_key != current.focus_key:
            return TargetDecision(
                TargetStatus.BLOCKED,
                TargetReason.FOCUS_CHANGED,
                current_decision.lease,
                ("focus",),
            )
        if captured.identity_key != current.identity_key:
            return TargetDecision(
                TargetStatus.BLOCKED,
                TargetReason.IDENTITY_CHANGED,
                current_decision.lease,
                ("identity",),
            )
        if captured.policy_key != current.policy_key:
            return TargetDecision(
                TargetStatus.BLOCKED,
                TargetReason.POLICY_CHANGED,
                current_decision.lease,
                ("policy",),
            )
        return current_decision

    @staticmethod
    def _blocked_reason(
        descriptor: TargetDescriptor,
    ) -> TargetReason | None:
        if descriptor.process_id == descriptor.clicky_process_id:
            return TargetReason.CLICKY_SURFACE
        if descriptor.desktop_name.casefold() != "default":
            return TargetReason.SECURE_DESKTOP
        if (
            descriptor.foreground_hwnd != descriptor.top_level_hwnd
            or descriptor.focused_runtime_id != descriptor.runtime_id
            or not descriptor.has_keyboard_focus
        ):
            return TargetReason.NO_FOCUSED_CONTROL
        if not descriptor.enabled:
            return TargetReason.DISABLED
        if descriptor.password:
            return TargetReason.PASSWORD
        if descriptor.protected:
            return TargetReason.PROTECTED
        if descriptor.read_only is None or descriptor.read_only:
            return TargetReason.READ_ONLY
        if not descriptor.editable:
            return TargetReason.NOT_EDITABLE
        if descriptor.elevation_relation is ElevationRelation.UNKNOWN:
            return TargetReason.ELEVATION_UNKNOWN
        if descriptor.elevation_relation is not ElevationRelation.SAME:
            return TargetReason.ELEVATION_MISMATCH
        if (
            descriptor.target_integrity is not None
            and descriptor.target_integrity >= 0x3000
        ):
            return TargetReason.ADMINISTRATOR_SURFACE
        if descriptor.sensitive_surface:
            return TargetReason.SENSITIVE_SURFACE
        return None


def blocked_result_code(reason: TargetReason) -> str:
    return f"blocked_{reason.value}"


def user_visible_reason(reason: TargetReason) -> str:
    messages = {
        TargetReason.FOCUS_CHANGED: "The destination changed before insertion.",
        TargetReason.IDENTITY_CHANGED: "The destination identity changed.",
        TargetReason.POLICY_CHANGED: "The destination is no longer permitted.",
        TargetReason.NO_FOCUSED_CONTROL: "No stable editable destination is focused.",
        TargetReason.DISABLED: "The focused field is disabled.",
        TargetReason.READ_ONLY: "The focused field is read-only or cannot be verified.",
        TargetReason.PASSWORD: "Dictation is blocked for password fields.",
        TargetReason.PROTECTED: "Dictation is blocked for protected fields.",
        TargetReason.SENSITIVE_SURFACE: "Dictation is blocked on this sensitive surface.",
        TargetReason.ELEVATION_UNKNOWN: "The destination security level could not be verified.",
        TargetReason.ELEVATION_MISMATCH: "Clicky and the destination have different security levels.",
        TargetReason.ADMINISTRATOR_SURFACE: "Dictation is blocked on administrator surfaces.",
        TargetReason.SECURE_DESKTOP: "Dictation is blocked on the secure desktop.",
        TargetReason.CLICKY_SURFACE: "Choose a destination outside Clicky.",
        TargetReason.NOT_EDITABLE: "The focused control is not an editable text field.",
        TargetReason.INSPECTOR_ERROR: "The destination could not be verified.",
        TargetReason.INVALID_IDENTITY: "The destination identity is invalid.",
        TargetReason.ALLOWED: "The destination is ready.",
    }
    return messages[reason]


def unavailable_decision(
    reason: TargetReason = TargetReason.INSPECTOR_ERROR,
) -> TargetDecision:
    return TargetDecision(TargetStatus.UNAVAILABLE, reason)


def classify_sensitive_surface(hints: tuple[str, ...]) -> bool:
    """Classify transient UI labels without retaining or logging their text."""
    return any(
        isinstance(hint, str)
        and len(hint) <= MAX_TARGET_TEXT_CHARS
        and _SENSITIVE_SURFACE_RE.search(hint)
        for hint in hints
    )


def _validate_runtime_id(runtime_id: tuple[int, ...]) -> None:
    if (
        not isinstance(runtime_id, tuple)
        or not 1 <= len(runtime_id) <= MAX_RUNTIME_ID_PARTS
        or any(type(part) is not int for part in runtime_id)
    ):
        raise ValueError("UI Automation runtime ID is invalid")
