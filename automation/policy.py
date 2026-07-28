"""Fail-closed target and denial policy for desktop automation.

The policy consumes bounded transient UIA labels, returns category-only
diagnostics, and never records a control's current ValuePattern value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from automation.models import (
    MAX_TARGET_TEXT_CHARS,
    DesktopActionKind,
    DesktopTarget,
    required_pattern,
)


MAX_SURFACE_HINTS = 16
MAX_TOTAL_HINT_CHARS = 2_048
ADMINISTRATOR_INTEGRITY = 0x3000


class DesktopSurfaceRisk(str, Enum):
    CREDENTIAL = "credential"
    TWO_FACTOR_AUTHENTICATION = "two_factor_authentication"
    PAYMENT_OR_PURCHASE = "payment_or_purchase"
    SECURITY_SETTINGS = "security_settings"
    ADMINISTRATOR_PROMPT = "administrator_prompt"
    ACCOUNT_CHANGE = "account_change"
    DESTRUCTIVE_DELETION = "destructive_deletion"


class DesktopPolicyStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"


class DesktopPolicyReason(str, Enum):
    ALLOWED = "allowed"
    INSPECTOR_ERROR = "inspector_error"
    INVALID_SURFACE_HINTS = "invalid_surface_hints"
    CLICKY_SURFACE = "clicky_surface"
    SECURE_DESKTOP = "secure_desktop"
    BACKGROUND_WINDOW = "background_window"
    DISABLED = "disabled"
    OFFSCREEN = "offscreen"
    NOT_CONTROL_ELEMENT = "not_control_element"
    PASSWORD = "password"
    PROTECTED = "protected"
    ELEVATION_UNKNOWN = "elevation_unknown"
    ELEVATION_MISMATCH = "elevation_mismatch"
    ADMINISTRATOR_SURFACE = "administrator_surface"
    UNSUPPORTED_PATTERN = "unsupported_pattern"
    CREDENTIAL = DesktopSurfaceRisk.CREDENTIAL.value
    TWO_FACTOR_AUTHENTICATION = (
        DesktopSurfaceRisk.TWO_FACTOR_AUTHENTICATION.value
    )
    PAYMENT_OR_PURCHASE = DesktopSurfaceRisk.PAYMENT_OR_PURCHASE.value
    SECURITY_SETTINGS = DesktopSurfaceRisk.SECURITY_SETTINGS.value
    ADMINISTRATOR_PROMPT = DesktopSurfaceRisk.ADMINISTRATOR_PROMPT.value
    ACCOUNT_CHANGE = DesktopSurfaceRisk.ACCOUNT_CHANGE.value
    DESTRUCTIVE_DELETION = DesktopSurfaceRisk.DESTRUCTIVE_DELETION.value
    IDENTITY_CHANGED = "identity_changed"
    PRESENTATION_CHANGED = "presentation_changed"
    POLICY_CHANGED = "policy_changed"


_RISK_PATTERNS: tuple[tuple[DesktopSurfaceRisk, re.Pattern[str]], ...] = (
    (
        DesktopSurfaceRisk.TWO_FACTOR_AUTHENTICATION,
        re.compile(
            r"\b("
            r"2fa|two[\s-]*factor|multi[\s-]*factor|mfa|"
            r"one[\s-]*time(?:\s+(?:password|passcode|code))?|otp|"
            r"authenticator|verification[\s-]*code|security[\s-]*code"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        DesktopSurfaceRisk.CREDENTIAL,
        re.compile(
            r"\b("
            r"password|passphrase|passcode|pin|credential|secret|"
            r"private[\s-]*key|recovery[\s-]*(?:key|phrase)|seed[\s-]*phrase|"
            r"sign[\s-]*in|log[\s-]*in|authentication"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        DesktopSurfaceRisk.PAYMENT_OR_PURCHASE,
        re.compile(
            r"\b("
            r"payment|purchase|checkout|buy[\s-]*now|place[\s-]*order|"
            r"billing|credit[\s-]*card|debit[\s-]*card|card[\s-]*number|"
            r"cvv|bank(?:ing)?|wire[\s-]*transfer|send[\s-]*money|"
            r"confirm[\s-]*(?:order|transaction|transfer)"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        DesktopSurfaceRisk.SECURITY_SETTINGS,
        re.compile(
            r"\b("
            r"security[\s-]*(?:setting|center|policy)|windows[\s-]*security|"
            r"credential[\s-]*manager|firewall|antivirus|defender|"
            r"bitlocker|registry[\s-]*editor|group[\s-]*policy|"
            r"local[\s-]*security[\s-]*policy"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        DesktopSurfaceRisk.ADMINISTRATOR_PROMPT,
        re.compile(
            r"\b("
            r"administrator|admin[\s-]*approval|"
            r"user[\s-]*account[\s-]*control|uac|"
            r"allow[\s-]*this[\s-]*app[\s-]*to[\s-]*make[\s-]*changes"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        DesktopSurfaceRisk.ACCOUNT_CHANGE,
        re.compile(
            r"\b("
            r"delete[\s-]*(?:my[\s-]*)?account|close[\s-]*account|"
            r"change[\s-]*(?:email|password|username|account)|"
            r"remove[\s-]*(?:account|user)|add[\s-]*(?:account|user)|"
            r"manage[\s-]*(?:account|users)|sign[\s-]*out[\s-]*everywhere"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        DesktopSurfaceRisk.DESTRUCTIVE_DELETION,
        re.compile(
            r"\b("
            r"delete[\s-]*(?:permanently|forever)|permanent[\s-]*delete|"
            r"empty[\s-]*(?:recycle[\s-]*bin|trash)|erase[\s-]*all|"
            r"remove[\s-]*all|factory[\s-]*reset|format[\s-]*(?:disk|drive)"
            r")\b",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class DesktopTargetLease:
    """One policy-approved capture, without authority to act."""

    target: DesktopTarget = field(repr=False)
    risks: frozenset[DesktopSurfaceRisk]

    def __post_init__(self) -> None:
        if not isinstance(self.target, DesktopTarget):
            raise TypeError("Desktop target lease is invalid")
        if not isinstance(self.risks, frozenset) or any(
            not isinstance(risk, DesktopSurfaceRisk) for risk in self.risks
        ):
            raise TypeError("Desktop target lease risks are invalid")


@dataclass(frozen=True, slots=True)
class DesktopPolicyDecision:
    status: DesktopPolicyStatus
    reason: DesktopPolicyReason
    risks: frozenset[DesktopSurfaceRisk] = frozenset()
    lease: DesktopTargetLease | None = field(default=None, repr=False)
    changed_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, DesktopPolicyStatus):
            raise TypeError("Desktop policy status is invalid")
        if not isinstance(self.reason, DesktopPolicyReason):
            raise TypeError("Desktop policy reason is invalid")
        if not isinstance(self.risks, frozenset) or any(
            not isinstance(risk, DesktopSurfaceRisk) for risk in self.risks
        ):
            raise TypeError("Desktop policy risks are invalid")
        if self.lease is not None and not isinstance(
            self.lease,
            DesktopTargetLease,
        ):
            raise TypeError("Desktop target lease is invalid")
        if not isinstance(self.changed_fields, tuple) or any(
            field_name not in {"identity", "presentation", "policy"}
            for field_name in self.changed_fields
        ):
            raise TypeError("Desktop policy changed fields are invalid")

    @property
    def allowed(self) -> bool:
        return (
            self.status is DesktopPolicyStatus.ALLOWED
            and self.reason is DesktopPolicyReason.ALLOWED
            and self.lease is not None
        )


class SafeDesktopTargetPolicy:
    """Allow only an ordinary same-integrity foreground UIA control."""

    def evaluate(
        self,
        target: DesktopTarget,
        *,
        action: DesktopActionKind,
        surface_hints: tuple[str, ...],
    ) -> DesktopPolicyDecision:
        if not isinstance(target, DesktopTarget):
            raise TypeError("Desktop target is invalid")
        if not isinstance(action, DesktopActionKind):
            raise TypeError("Desktop action kind is invalid")
        try:
            risks = classify_surface_risks(surface_hints)
        except (TypeError, ValueError):
            return DesktopPolicyDecision(
                DesktopPolicyStatus.BLOCKED,
                DesktopPolicyReason.INVALID_SURFACE_HINTS,
            )
        lease = DesktopTargetLease(target=target, risks=risks)
        reason = self._blocked_reason(target, action=action, risks=risks)
        if reason is None:
            return DesktopPolicyDecision(
                DesktopPolicyStatus.ALLOWED,
                DesktopPolicyReason.ALLOWED,
                risks,
                lease,
            )
        return DesktopPolicyDecision(
            DesktopPolicyStatus.BLOCKED,
            reason,
            risks,
            lease,
        )

    def revalidate(
        self,
        lease: DesktopTargetLease,
        current: DesktopTarget,
        *,
        action: DesktopActionKind,
        surface_hints: tuple[str, ...],
    ) -> DesktopPolicyDecision:
        if not isinstance(lease, DesktopTargetLease):
            raise TypeError("Desktop target lease is invalid")
        current_decision = self.evaluate(
            current,
            action=action,
            surface_hints=surface_hints,
        )
        if not current_decision.allowed:
            return DesktopPolicyDecision(
                current_decision.status,
                current_decision.reason,
                current_decision.risks,
                current_decision.lease,
                ("policy",),
            )
        captured = lease.target
        if captured.identity_key != current.identity_key:
            return DesktopPolicyDecision(
                DesktopPolicyStatus.BLOCKED,
                DesktopPolicyReason.IDENTITY_CHANGED,
                current_decision.risks,
                current_decision.lease,
                ("identity",),
            )
        if captured.presentation_key != current.presentation_key:
            return DesktopPolicyDecision(
                DesktopPolicyStatus.BLOCKED,
                DesktopPolicyReason.PRESENTATION_CHANGED,
                current_decision.risks,
                current_decision.lease,
                ("presentation",),
            )
        if lease.risks != current_decision.risks:
            return DesktopPolicyDecision(
                DesktopPolicyStatus.BLOCKED,
                DesktopPolicyReason.POLICY_CHANGED,
                current_decision.risks,
                current_decision.lease,
                ("policy",),
            )
        return current_decision

    @staticmethod
    def _blocked_reason(
        target: DesktopTarget,
        *,
        action: DesktopActionKind,
        risks: frozenset[DesktopSurfaceRisk],
    ) -> DesktopPolicyReason | None:
        if target.process_id == target.clicky_process_id:
            return DesktopPolicyReason.CLICKY_SURFACE
        if target.desktop_name.casefold() != "default":
            return DesktopPolicyReason.SECURE_DESKTOP
        if target.foreground_hwnd != target.top_level_hwnd:
            return DesktopPolicyReason.BACKGROUND_WINDOW
        if not target.enabled:
            return DesktopPolicyReason.DISABLED
        if target.offscreen:
            return DesktopPolicyReason.OFFSCREEN
        if not target.control_element:
            return DesktopPolicyReason.NOT_CONTROL_ELEMENT
        if target.password:
            return DesktopPolicyReason.PASSWORD
        if target.protected:
            return DesktopPolicyReason.PROTECTED
        if target.clicky_integrity is None or target.target_integrity is None:
            return DesktopPolicyReason.ELEVATION_UNKNOWN
        if target.clicky_integrity != target.target_integrity:
            return DesktopPolicyReason.ELEVATION_MISMATCH
        if target.target_integrity >= ADMINISTRATOR_INTEGRITY:
            return DesktopPolicyReason.ADMINISTRATOR_SURFACE
        if risks:
            return DesktopPolicyReason(
                min(risks, key=lambda risk: risk.value).value
            )
        pattern = required_pattern(action)
        if pattern is not None and pattern not in target.supported_patterns:
            return DesktopPolicyReason.UNSUPPORTED_PATTERN
        return None


def classify_surface_risks(
    hints: tuple[str, ...],
) -> frozenset[DesktopSurfaceRisk]:
    """Classify bounded UIA labels without retaining their text."""

    if not isinstance(hints, tuple) or len(hints) > MAX_SURFACE_HINTS:
        raise TypeError("Desktop surface hints must be a bounded tuple")
    if (
        sum(len(hint) for hint in hints if isinstance(hint, str))
        > MAX_TOTAL_HINT_CHARS
    ):
        raise ValueError("Desktop surface hints are too large")
    for hint in hints:
        if (
            not isinstance(hint, str)
            or len(hint) > MAX_TARGET_TEXT_CHARS
            or "\x00" in hint
            or (hint and not hint.isprintable())
        ):
            raise ValueError("Desktop surface hint is invalid")
    return frozenset(
        risk
        for risk, pattern in _RISK_PATTERNS
        if any(pattern.search(hint) for hint in hints)
    )


def user_visible_reason(reason: DesktopPolicyReason) -> str:
    messages = {
        DesktopPolicyReason.ALLOWED: "The desktop target is eligible for review.",
        DesktopPolicyReason.INSPECTOR_ERROR: (
            "The desktop target could not be inspected."
        ),
        DesktopPolicyReason.INVALID_SURFACE_HINTS: (
            "The desktop surface could not be classified safely."
        ),
        DesktopPolicyReason.CLICKY_SURFACE: (
            "Desktop automation cannot target Clicky itself."
        ),
        DesktopPolicyReason.SECURE_DESKTOP: (
            "Desktop automation is blocked on the secure desktop."
        ),
        DesktopPolicyReason.BACKGROUND_WINDOW: (
            "The selected control is no longer in the foreground window."
        ),
        DesktopPolicyReason.DISABLED: "The selected control is disabled.",
        DesktopPolicyReason.OFFSCREEN: "The selected control is off screen.",
        DesktopPolicyReason.NOT_CONTROL_ELEMENT: (
            "The selected item is not an actionable UI Automation control."
        ),
        DesktopPolicyReason.PASSWORD: (
            "Desktop automation is blocked for password controls."
        ),
        DesktopPolicyReason.PROTECTED: (
            "Desktop automation is blocked for protected controls."
        ),
        DesktopPolicyReason.ELEVATION_UNKNOWN: (
            "The target security level could not be verified."
        ),
        DesktopPolicyReason.ELEVATION_MISMATCH: (
            "Clicky and the target have different security levels."
        ),
        DesktopPolicyReason.ADMINISTRATOR_SURFACE: (
            "Desktop automation is blocked on administrator surfaces."
        ),
        DesktopPolicyReason.UNSUPPORTED_PATTERN: (
            "The selected control does not support the requested safe action."
        ),
        DesktopPolicyReason.CREDENTIAL: (
            "Desktop automation is blocked on credential surfaces."
        ),
        DesktopPolicyReason.TWO_FACTOR_AUTHENTICATION: (
            "Desktop automation is blocked for two-factor authentication."
        ),
        DesktopPolicyReason.PAYMENT_OR_PURCHASE: (
            "Desktop automation is blocked for payments and purchases."
        ),
        DesktopPolicyReason.SECURITY_SETTINGS: (
            "Desktop automation is blocked for security settings."
        ),
        DesktopPolicyReason.ADMINISTRATOR_PROMPT: (
            "Desktop automation is blocked for administrator prompts."
        ),
        DesktopPolicyReason.ACCOUNT_CHANGE: (
            "Desktop automation is blocked for account changes."
        ),
        DesktopPolicyReason.DESTRUCTIVE_DELETION: (
            "Desktop automation is blocked for destructive deletion."
        ),
        DesktopPolicyReason.IDENTITY_CHANGED: (
            "The desktop target identity changed before the action."
        ),
        DesktopPolicyReason.PRESENTATION_CHANGED: (
            "The desktop target moved or changed before the action."
        ),
        DesktopPolicyReason.POLICY_CHANGED: (
            "The desktop target is no longer permitted."
        ),
    }
    if not isinstance(reason, DesktopPolicyReason):
        raise TypeError("Desktop policy reason is invalid")
    return messages[reason]


def unavailable_decision() -> DesktopPolicyDecision:
    return DesktopPolicyDecision(
        DesktopPolicyStatus.UNAVAILABLE,
        DesktopPolicyReason.INSPECTOR_ERROR,
    )


__all__ = [
    "ADMINISTRATOR_INTEGRITY",
    "DesktopPolicyDecision",
    "DesktopPolicyReason",
    "DesktopPolicyStatus",
    "DesktopSurfaceRisk",
    "DesktopTargetLease",
    "SafeDesktopTargetPolicy",
    "classify_surface_risks",
    "unavailable_decision",
    "user_visible_reason",
]
