"""Exact requests and truthful outcomes for allowlisted UIA actions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

from automation.models import DesktopActionKind
from capability_registry import CapabilityId


MAX_SIMPLE_VALUE_CHARS = 256
MAX_RESULT_CODE_CHARS = 96
MAX_EVIDENCE_VALUE_CHARS = 128
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ToggleGoal(str, Enum):
    OFF = "off"
    ON = "on"


class ScrollAmount(str, Enum):
    NO_AMOUNT = "no_amount"
    LARGE_DECREMENT = "large_decrement"
    SMALL_DECREMENT = "small_decrement"
    SMALL_INCREMENT = "small_increment"
    LARGE_INCREMENT = "large_increment"


class InvokePostcondition(str, Enum):
    FOREGROUND_WINDOW_CHANGED = "foreground_window_changed"
    TARGET_DISABLED = "target_disabled"
    TARGET_OFFSCREEN = "target_offscreen"
    TARGET_DISAPPEARED = "target_disappeared"
    FOCUS_CHANGED = "focus_changed"


class DesktopActionStatus(str, Enum):
    VERIFIED_SUCCEEDED = "verified_succeeded"
    FAILED_BEFORE_ACTION = "failed_before_action"
    FAILED_VERIFICATION = "failed_verification"
    OUTCOME_UNKNOWN = "outcome_unknown"
    CANCELLED_BEFORE_ACTION = "cancelled_before_action"


@dataclass(frozen=True, slots=True)
class DesktopActionRequest:
    """One exact semantic action; irrelevant parameters are rejected."""

    run_id: str
    call_id: str
    review_id: str
    target_identity_digest: str
    target_review_digest: str
    action: DesktopActionKind
    invoke_postcondition: InvokePostcondition | None = None
    toggle_goal: ToggleGoal | None = None
    horizontal_scroll: ScrollAmount | None = None
    vertical_scroll: ScrollAmount | None = None
    value: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _token(self.run_id, "Desktop action run ID")
        _token(self.call_id, "Desktop action call ID")
        _sha256(self.review_id, "Desktop action review ID")
        _sha256(
            self.target_identity_digest,
            "Desktop target identity digest",
        )
        _sha256(
            self.target_review_digest,
            "Desktop target review digest",
        )
        if not isinstance(self.action, DesktopActionKind):
            raise TypeError("Desktop action kind is invalid")
        self._validate_parameters()

    def _validate_parameters(self) -> None:
        if self.action is DesktopActionKind.INVOKE:
            if not isinstance(
                self.invoke_postcondition,
                InvokePostcondition,
            ):
                raise ValueError(
                    "Invoke requires one explicit postcondition"
                )
        elif self.invoke_postcondition is not None:
            raise ValueError("Invoke postcondition belongs only to invoke")

        if self.action is DesktopActionKind.TOGGLE:
            if not isinstance(self.toggle_goal, ToggleGoal):
                raise ValueError("Toggle requires one explicit goal")
        elif self.toggle_goal is not None:
            raise ValueError("Toggle goal belongs only to toggle")

        if self.action is DesktopActionKind.SCROLL:
            if not isinstance(self.horizontal_scroll, ScrollAmount) or not (
                isinstance(self.vertical_scroll, ScrollAmount)
            ):
                raise ValueError(
                    "Scroll requires exact horizontal and vertical amounts"
                )
            if (
                self.horizontal_scroll is ScrollAmount.NO_AMOUNT
                and self.vertical_scroll is ScrollAmount.NO_AMOUNT
            ):
                raise ValueError("Scroll must change at least one axis")
        elif (
            self.horizontal_scroll is not None
            or self.vertical_scroll is not None
        ):
            raise ValueError("Scroll amounts belong only to scroll")

        if self.action is DesktopActionKind.SET_VALUE:
            if (
                not isinstance(self.value, str)
                or not 1 <= len(self.value) <= MAX_SIMPLE_VALUE_CHARS
                or "\x00" in self.value
                or "\r" in self.value
                or "\n" in self.value
                or not self.value.isprintable()
            ):
                raise ValueError(
                    "Set-value text must be bounded printable single-line text"
                )
            from automation.policy import classify_surface_risks

            if classify_surface_risks((self.value,)):
                raise ValueError(
                    "Set-value text is classified as sensitive"
                )
        elif self.value is not None:
            raise ValueError("A value belongs only to set-value")

    @property
    def tool_name(self) -> str:
        return f"desktop.{self.action.value}"

    @property
    def value_sha256(self) -> str | None:
        if self.value is None:
            return None
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()

    @property
    def arguments_digest(self) -> str:
        return hashlib.sha256(_canonical_json(self.to_payload())).hexdigest()

    @property
    def action_digest(self) -> str:
        return desktop_action_digest(
            run_id=self.run_id,
            call_id=self.call_id,
            arguments_digest=self.arguments_digest,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "action": self.action.value,
            "call_id": self.call_id,
            "horizontal_scroll": (
                self.horizontal_scroll.value
                if self.horizontal_scroll is not None
                else None
            ),
            "invoke_postcondition": (
                self.invoke_postcondition.value
                if self.invoke_postcondition is not None
                else None
            ),
            "review_id": self.review_id,
            "run_id": self.run_id,
            "target_identity_digest": self.target_identity_digest,
            "target_review_digest": self.target_review_digest,
            "toggle_goal": (
                self.toggle_goal.value
                if self.toggle_goal is not None
                else None
            ),
            "value": self.value,
            "vertical_scroll": (
                self.vertical_scroll.value
                if self.vertical_scroll is not None
                else None
            ),
        }

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, object],
    ) -> DesktopActionRequest:
        expected = {
            "action",
            "call_id",
            "horizontal_scroll",
            "invoke_postcondition",
            "review_id",
            "run_id",
            "target_identity_digest",
            "target_review_digest",
            "toggle_goal",
            "value",
            "vertical_scroll",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise ValueError("Desktop action payload shape is invalid")
        return cls(
            run_id=_required_str(payload["run_id"]),
            call_id=_required_str(payload["call_id"]),
            review_id=_required_str(payload["review_id"]),
            target_identity_digest=_required_str(
                payload["target_identity_digest"]
            ),
            target_review_digest=_required_str(
                payload["target_review_digest"]
            ),
            action=DesktopActionKind(_required_str(payload["action"])),
            invoke_postcondition=_optional_enum(
                payload["invoke_postcondition"],
                InvokePostcondition,
            ),
            toggle_goal=_optional_enum(
                payload["toggle_goal"],
                ToggleGoal,
            ),
            horizontal_scroll=_optional_enum(
                payload["horizontal_scroll"],
                ScrollAmount,
            ),
            vertical_scroll=_optional_enum(
                payload["vertical_scroll"],
                ScrollAmount,
            ),
            value=_optional_str(payload["value"]),
        )


@dataclass(frozen=True, slots=True)
class DesktopActionEvidence:
    property_name: str
    before: str
    after: str

    def __post_init__(self) -> None:
        _token(self.property_name, "Desktop evidence property")
        for value in (self.before, self.after):
            if (
                not isinstance(value, str)
                or len(value) > MAX_EVIDENCE_VALUE_CHARS
                or "\x00" in value
                or (value and not value.isprintable())
            ):
                raise ValueError("Desktop evidence value is invalid")

    def to_payload(self) -> dict[str, str]:
        return {
            "after": self.after,
            "before": self.before,
            "property_name": self.property_name,
        }

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, object],
    ) -> DesktopActionEvidence:
        if not isinstance(payload, Mapping) or set(payload) != {
            "after",
            "before",
            "property_name",
        }:
            raise ValueError("Desktop action evidence shape is invalid")
        return cls(
            property_name=_required_str(payload["property_name"]),
            before=_required_str(payload["before"], allow_empty=True),
            after=_required_str(payload["after"], allow_empty=True),
        )


@dataclass(frozen=True, slots=True)
class DesktopActionReceipt:
    status: DesktopActionStatus
    result_code: str
    action_started: bool
    target_identity_digest: str
    evidence: DesktopActionEvidence | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, DesktopActionStatus):
            raise TypeError("Desktop action status is invalid")
        _token(
            self.result_code,
            "Desktop action result code",
            maximum=MAX_RESULT_CODE_CHARS,
        )
        if type(self.action_started) is not bool:
            raise TypeError("Desktop action started state is invalid")
        _sha256(
            self.target_identity_digest,
            "Desktop action target identity",
        )
        if self.evidence is not None and not isinstance(
            self.evidence,
            DesktopActionEvidence,
        ):
            raise TypeError("Desktop action evidence is invalid")
        if self.status is DesktopActionStatus.VERIFIED_SUCCEEDED:
            if not self.action_started or self.evidence is None:
                raise ValueError(
                    "Verified desktop action requires observed evidence"
                )
        if (
            self.status is DesktopActionStatus.FAILED_VERIFICATION
            and (not self.action_started or self.evidence is None)
        ):
            raise ValueError(
                "Failed verification requires observed post-state"
            )
        if self.status in {
            DesktopActionStatus.FAILED_BEFORE_ACTION,
            DesktopActionStatus.CANCELLED_BEFORE_ACTION,
        } and self.action_started:
            raise ValueError("Pre-action result cannot claim action started")
        if self.status in {
            DesktopActionStatus.FAILED_BEFORE_ACTION,
            DesktopActionStatus.CANCELLED_BEFORE_ACTION,
            DesktopActionStatus.OUTCOME_UNKNOWN,
        } and self.evidence is not None:
            raise ValueError(
                "Unverified desktop result cannot expose evidence"
            )
        if (
            self.status is DesktopActionStatus.OUTCOME_UNKNOWN
            and not self.action_started
        ):
            raise ValueError("Unknown outcome requires a started action")

    @property
    def verified(self) -> bool:
        return self.status is DesktopActionStatus.VERIFIED_SUCCEEDED

    def to_payload(self) -> dict[str, object]:
        return {
            "action_started": self.action_started,
            "evidence": (
                self.evidence.to_payload()
                if self.evidence is not None
                else None
            ),
            "result_code": self.result_code,
            "status": self.status.value,
            "target_identity_digest": self.target_identity_digest,
        }

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, object],
    ) -> DesktopActionReceipt:
        if not isinstance(payload, Mapping) or set(payload) != {
            "action_started",
            "evidence",
            "result_code",
            "status",
            "target_identity_digest",
        }:
            raise ValueError("Desktop action receipt shape is invalid")
        evidence_payload = payload["evidence"]
        evidence = (
            DesktopActionEvidence.from_payload(evidence_payload)
            if isinstance(evidence_payload, Mapping)
            else None
        )
        if evidence_payload is not None and evidence is None:
            raise ValueError("Desktop action receipt evidence is invalid")
        return cls(
            status=DesktopActionStatus(_required_str(payload["status"])),
            result_code=_required_str(payload["result_code"]),
            action_started=_required_bool(payload["action_started"]),
            target_identity_digest=_required_str(
                payload["target_identity_digest"]
            ),
            evidence=evidence,
        )


def desktop_action_digest(
    *,
    run_id: str,
    call_id: str,
    arguments_digest: str,
) -> str:
    _token(run_id, "Desktop action run ID")
    _token(call_id, "Desktop action call ID")
    _sha256(arguments_digest, "Desktop action arguments")
    return hashlib.sha256(
        _canonical_json(
            {
                "arguments_digest": arguments_digest,
                "call_id": call_id,
                "capability": CapabilityId.DESKTOP_UIA_ACTION.value,
                "run_id": run_id,
                "schema_version": 1,
            }
        )
    ).hexdigest()


def _token(
    value: object,
    label: str,
    *,
    maximum: int = 128,
) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or _TOKEN.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be SHA-256")
    return value


def _required_str(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ValueError("Desktop action payload text is invalid")
    return value


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    return _required_str(value)


def _required_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("Desktop action payload boolean is invalid")
    return value


def _optional_enum(value: object, enum_type):
    if value is None:
        return None
    return enum_type(_required_str(value))


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


__all__ = [
    "DesktopActionEvidence",
    "DesktopActionReceipt",
    "DesktopActionRequest",
    "DesktopActionStatus",
    "InvokePostcondition",
    "ScrollAmount",
    "ToggleGoal",
    "desktop_action_digest",
]
