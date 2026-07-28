"""Permissioned desktop-automation contracts.

The package exposes policy and immutable target identity only. Importing it
does not inspect the desktop or perform an action.
"""

from automation.models import (
    MAX_RUNTIME_ID_PARTS,
    MAX_TARGET_TEXT_CHARS,
    AutomationPattern,
    DesktopActionKind,
    DesktopBounds,
    DesktopTarget,
)
from automation.policy import (
    DesktopPolicyDecision,
    DesktopPolicyReason,
    DesktopPolicyStatus,
    DesktopSurfaceRisk,
    SafeDesktopTargetPolicy,
    classify_surface_risks,
    user_visible_reason,
)

__all__ = [
    "MAX_RUNTIME_ID_PARTS",
    "MAX_TARGET_TEXT_CHARS",
    "AutomationPattern",
    "DesktopActionKind",
    "DesktopBounds",
    "DesktopPolicyDecision",
    "DesktopPolicyReason",
    "DesktopPolicyStatus",
    "DesktopSurfaceRisk",
    "DesktopTarget",
    "SafeDesktopTargetPolicy",
    "classify_surface_risks",
    "user_visible_reason",
]
