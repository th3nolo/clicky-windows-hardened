"""Typed contracts for explicit, non-authorizing screen-region handoff."""

from handoff.models import (
    HandoffDataClass,
    HandoffDestination,
    HandoffIntent,
    HandoffReview,
    HandoffSelection,
    HandoffSelectionError,
    MonitorSnapshot,
    PhysicalRegion,
    SelectionShape,
    build_handoff_intent,
    build_handoff_review,
    capture_handoff_selection,
    required_capabilities,
    topology_digest,
    validate_current_selection,
)

__all__ = [
    "HandoffDataClass",
    "HandoffDestination",
    "HandoffIntent",
    "HandoffReview",
    "HandoffSelection",
    "HandoffSelectionError",
    "MonitorSnapshot",
    "PhysicalRegion",
    "SelectionShape",
    "build_handoff_intent",
    "build_handoff_review",
    "capture_handoff_selection",
    "required_capabilities",
    "topology_digest",
    "validate_current_selection",
]
