"""Bounded authenticated pipe protocol for the trusted UIA worker."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Mapping

from automation.action_models import (
    DesktopActionReceipt,
    DesktopActionRequest,
)
from automation.models import (
    AutomationPattern,
    DesktopBounds,
    DesktopTarget,
)


MAX_WORKER_FRAME_BYTES = 32 * 1024
WORKER_AUTH_KEY_BYTES = 32
_HEX_32_BYTES = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class UiaWorkerCommand:
    nonce: str
    authentication_key: bytes = field(repr=False)
    target: DesktopTarget
    request: DesktopActionRequest = field(repr=False)

    def __post_init__(self) -> None:
        _hex_digest(self.nonce, "UIA worker nonce")
        if (
            not isinstance(self.authentication_key, bytes)
            or len(self.authentication_key) != WORKER_AUTH_KEY_BYTES
        ):
            raise ValueError("UIA worker authentication key is invalid")
        if not isinstance(self.target, DesktopTarget):
            raise TypeError("UIA worker target is invalid")
        if not isinstance(self.request, DesktopActionRequest):
            raise TypeError("UIA worker request is invalid")


def encode_worker_command(command: UiaWorkerCommand) -> bytes:
    if not isinstance(command, UiaWorkerCommand):
        raise TypeError("UIA worker command is invalid")
    payload = {
        "authentication_key": command.authentication_key.hex(),
        "nonce": command.nonce,
        "request": command.request.to_payload(),
        "schema_version": 1,
        "target": _target_payload(command.target),
    }
    return _frame(payload)


def decode_worker_command(frame: bytes) -> UiaWorkerCommand:
    payload = _unframe(frame)
    if set(payload) != {
        "authentication_key",
        "nonce",
        "request",
        "schema_version",
        "target",
    } or payload["schema_version"] != 1:
        raise ValueError("UIA worker command shape is invalid")
    authentication_key = _decode_hex_key(payload["authentication_key"])
    nonce = _required_str(payload["nonce"])
    _hex_digest(nonce, "UIA worker nonce")
    target_payload = payload["target"]
    request_payload = payload["request"]
    if not isinstance(target_payload, Mapping) or not isinstance(
        request_payload,
        Mapping,
    ):
        raise ValueError("UIA worker command payload is invalid")
    return UiaWorkerCommand(
        nonce=nonce,
        authentication_key=authentication_key,
        target=_target_from_payload(target_payload),
        request=DesktopActionRequest.from_payload(request_payload),
    )


def encode_worker_receipt(
    *,
    nonce: str,
    authentication_key: bytes,
    receipt: DesktopActionReceipt,
) -> bytes:
    _hex_digest(nonce, "UIA worker nonce")
    if (
        not isinstance(authentication_key, bytes)
        or len(authentication_key) != WORKER_AUTH_KEY_BYTES
    ):
        raise ValueError("UIA worker authentication key is invalid")
    if not isinstance(receipt, DesktopActionReceipt):
        raise TypeError("UIA worker receipt is invalid")
    body = {
        "nonce": nonce,
        "receipt": receipt.to_payload(),
        "schema_version": 1,
    }
    mac = hmac.new(
        authentication_key,
        _canonical_json(body),
        hashlib.sha256,
    ).hexdigest()
    return _frame({**body, "mac": mac})


def decode_worker_receipt(
    frame: bytes,
    *,
    nonce: str,
    authentication_key: bytes,
) -> DesktopActionReceipt:
    _hex_digest(nonce, "UIA worker nonce")
    if (
        not isinstance(authentication_key, bytes)
        or len(authentication_key) != WORKER_AUTH_KEY_BYTES
    ):
        raise ValueError("UIA worker authentication key is invalid")
    payload = _unframe(frame)
    if set(payload) != {
        "mac",
        "nonce",
        "receipt",
        "schema_version",
    } or payload["schema_version"] != 1:
        raise ValueError("UIA worker receipt shape is invalid")
    if payload["nonce"] != nonce:
        raise ValueError("UIA worker receipt nonce does not match")
    mac = _required_str(payload["mac"])
    _hex_digest(mac, "UIA worker response MAC")
    body = {
        "nonce": payload["nonce"],
        "receipt": payload["receipt"],
        "schema_version": 1,
    }
    expected = hmac.new(
        authentication_key,
        _canonical_json(body),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("UIA worker response authentication failed")
    receipt_payload = payload["receipt"]
    if not isinstance(receipt_payload, Mapping):
        raise ValueError("UIA worker receipt payload is invalid")
    return DesktopActionReceipt.from_payload(receipt_payload)


def _target_payload(target: DesktopTarget) -> dict[str, object]:
    return {
        "application_identity": target.application_identity,
        "application_name": target.application_name,
        "automation_id": target.automation_id,
        "bounds": {
            "height": target.bounds.height,
            "left": target.bounds.left,
            "top": target.bounds.top,
            "width": target.bounds.width,
        },
        "clicky_integrity": target.clicky_integrity,
        "clicky_process_id": target.clicky_process_id,
        "control_element": target.control_element,
        "control_name": target.control_name,
        "control_type": target.control_type,
        "desktop_name": target.desktop_name,
        "enabled": target.enabled,
        "foreground_hwnd": target.foreground_hwnd,
        "framework_id": target.framework_id,
        "offscreen": target.offscreen,
        "password": target.password,
        "process_id": target.process_id,
        "process_start_time_ns": target.process_start_time_ns,
        "protected": target.protected,
        "runtime_id": list(target.runtime_id),
        "supported_patterns": sorted(
            pattern.value for pattern in target.supported_patterns
        ),
        "target_integrity": target.target_integrity,
        "top_level_hwnd": target.top_level_hwnd,
    }


def _target_from_payload(payload: Mapping[str, object]) -> DesktopTarget:
    expected = {
        "application_identity",
        "application_name",
        "automation_id",
        "bounds",
        "clicky_integrity",
        "clicky_process_id",
        "control_element",
        "control_name",
        "control_type",
        "desktop_name",
        "enabled",
        "foreground_hwnd",
        "framework_id",
        "offscreen",
        "password",
        "process_id",
        "process_start_time_ns",
        "protected",
        "runtime_id",
        "supported_patterns",
        "target_integrity",
        "top_level_hwnd",
    }
    if set(payload) != expected:
        raise ValueError("UIA worker target shape is invalid")
    bounds_payload = payload["bounds"]
    runtime_id = payload["runtime_id"]
    patterns = payload["supported_patterns"]
    if (
        not isinstance(bounds_payload, Mapping)
        or set(bounds_payload) != {"height", "left", "top", "width"}
        or not isinstance(runtime_id, list)
        or not isinstance(patterns, list)
    ):
        raise ValueError("UIA worker target collections are invalid")
    return DesktopTarget(
        process_id=_required_int(payload["process_id"]),
        process_start_time_ns=_required_int(
            payload["process_start_time_ns"]
        ),
        application_name=_required_str(payload["application_name"]),
        application_identity=_required_str(
            payload["application_identity"]
        ),
        top_level_hwnd=_required_int(payload["top_level_hwnd"]),
        foreground_hwnd=_required_int(payload["foreground_hwnd"]),
        runtime_id=tuple(_required_int(value) for value in runtime_id),
        control_type=_required_str(payload["control_type"]),
        framework_id=_required_str(
            payload["framework_id"],
            allow_empty=True,
        ),
        automation_id=_required_str(
            payload["automation_id"],
            allow_empty=True,
        ),
        control_name=_required_str(
            payload["control_name"],
            allow_empty=True,
        ),
        bounds=DesktopBounds(
            left=_required_number(bounds_payload["left"]),
            top=_required_number(bounds_payload["top"]),
            width=_required_number(bounds_payload["width"]),
            height=_required_number(bounds_payload["height"]),
        ),
        supported_patterns=frozenset(
            AutomationPattern(_required_str(value)) for value in patterns
        ),
        enabled=_required_bool(payload["enabled"]),
        offscreen=_required_bool(payload["offscreen"]),
        control_element=_required_bool(payload["control_element"]),
        password=_required_bool(payload["password"]),
        protected=_required_bool(payload["protected"]),
        clicky_process_id=_required_int(payload["clicky_process_id"]),
        clicky_integrity=_optional_int(payload["clicky_integrity"]),
        target_integrity=_optional_int(payload["target_integrity"]),
        desktop_name=_required_str(payload["desktop_name"]),
    )


def _frame(payload: object) -> bytes:
    encoded = _canonical_json(payload) + b"\n"
    if len(encoded) > MAX_WORKER_FRAME_BYTES:
        raise ValueError("UIA worker frame exceeds the size limit")
    return encoded


def _unframe(frame: bytes) -> dict[str, object]:
    if (
        not isinstance(frame, bytes)
        or not frame.endswith(b"\n")
        or not 1 < len(frame) <= MAX_WORKER_FRAME_BYTES
        or b"\n" in frame[:-1]
    ):
        raise ValueError("UIA worker frame is invalid")
    try:
        value = json.loads(
            frame[:-1].decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("UIA worker frame JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("UIA worker frame root is invalid")
    return value


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("UIA worker JSON has a duplicate key")
        value[key] = item
    return value


def _decode_hex_key(value: object) -> bytes:
    text = _required_str(value)
    if not _HEX_32_BYTES.fullmatch(text):
        raise ValueError("UIA worker authentication key is invalid")
    return bytes.fromhex(text)


def _hex_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEX_32_BYTES.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return value


def _required_str(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ValueError("UIA worker text is invalid")
    return value


def _required_int(value: object) -> int:
    if type(value) is not int:
        raise ValueError("UIA worker integer is invalid")
    return value


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    return _required_int(value)


def _required_number(value: object) -> float:
    if type(value) not in (int, float):
        raise ValueError("UIA worker number is invalid")
    return float(value)


def _required_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("UIA worker boolean is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


__all__ = [
    "MAX_WORKER_FRAME_BYTES",
    "UiaWorkerCommand",
    "decode_worker_command",
    "decode_worker_receipt",
    "encode_worker_command",
    "encode_worker_receipt",
]
