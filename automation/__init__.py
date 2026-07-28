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
from automation.review import (
    DesktopHighlightRequest,
    DesktopReviewLease,
    DesktopReviewResult,
    DesktopReviewStatus,
    DesktopTargetReviewController,
)
from automation.stop import (
    AutomationRunLease,
    AutomationStopController,
    GlobalAutomationStopHotkey,
)
from automation.targeting import (
    DesktopObservation,
    DesktopTargetGuard,
    WindowsDesktopTargetInspector,
)

__all__ = [
    "MAX_RUNTIME_ID_PARTS",
    "MAX_TARGET_TEXT_CHARS",
    "AutomationPattern",
    "DesktopActionKind",
    "DesktopBounds",
    "DesktopHighlightRequest",
    "DesktopObservation",
    "DesktopPolicyDecision",
    "DesktopPolicyReason",
    "DesktopPolicyStatus",
    "DesktopSurfaceRisk",
    "DesktopTarget",
    "DesktopTargetGuard",
    "DesktopTargetReviewController",
    "DesktopReviewLease",
    "DesktopReviewResult",
    "DesktopReviewStatus",
    "AutomationRunLease",
    "AutomationStopController",
    "GlobalAutomationStopHotkey",
    "SafeDesktopTargetPolicy",
    "WindowsDesktopTargetInspector",
    "classify_surface_risks",
    "user_visible_reason",
]
