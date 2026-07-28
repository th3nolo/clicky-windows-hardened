"""Permissioned desktop-automation contracts.

Importing this package does not inspect the desktop or perform an action.
Execution requires the explicit broker and its one-shot worker path.
"""

from automation.action_approval import build_desktop_action_approval
from automation.action_broker import DesktopActionBroker
from automation.action_models import (
    DesktopActionEvidence,
    DesktopActionReceipt,
    DesktopActionRequest,
    DesktopActionStatus,
    InvokePostcondition,
    ScrollAmount,
    ToggleGoal,
)
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
from automation.task_center import (
    DesktopAutomationTaskController,
    PreparedDesktopAction,
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
    "DesktopActionBroker",
    "DesktopActionEvidence",
    "DesktopActionKind",
    "DesktopActionReceipt",
    "DesktopActionRequest",
    "DesktopActionStatus",
    "DesktopAutomationTaskController",
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
    "InvokePostcondition",
    "PreparedDesktopAction",
    "SafeDesktopTargetPolicy",
    "ScrollAmount",
    "ToggleGoal",
    "WindowsDesktopTargetInspector",
    "build_desktop_action_approval",
    "classify_surface_risks",
    "user_visible_reason",
]
