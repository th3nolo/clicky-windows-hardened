"""Authenticated, bounded JSON-line protocol for the task fault boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import BinaryIO


PROTOCOL_VERSION = 1
BOOTSTRAP_MAX_BYTES = 2_048
PROTOCOL_KEY_BYTES = 32
MAX_JSON_DEPTH = 5
MAX_JSON_ITEMS = 64
MAX_JSON_STRING_CHARS = 8_192
_SESSION_ID = re.compile(r"^[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MESSAGE_TYPE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_PAYLOAD_KEY = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")


class ProtocolError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ProtocolMessage:
    message_type: str
    payload: dict[str, object]
    sequence: int


@dataclass(frozen=True, slots=True)
class WorkerBootstrap:
    key: bytes
    session_id: str
    run_id: str
    max_frame_bytes: int
    max_messages: int

    def __post_init__(self) -> None:
        if not isinstance(self.key, bytes) or len(self.key) != PROTOCOL_KEY_BYTES:
            raise ValueError("Worker protocol key is invalid")
        if (
            not isinstance(self.session_id, str)
            or _SESSION_ID.fullmatch(self.session_id) is None
        ):
            raise ValueError("Worker protocol session is invalid")
        if (
            not isinstance(self.run_id, str)
            or _RUN_ID.fullmatch(self.run_id) is None
        ):
            raise ValueError("Worker protocol run ID is invalid")
        if (
            type(self.max_frame_bytes) is not int
            or not 1_024 <= self.max_frame_bytes <= 64 * 1024
        ):
            raise ValueError("Worker protocol frame limit is invalid")
        if (
            type(self.max_messages) is not int
            or not 1 <= self.max_messages <= 256
        ):
            raise ValueError("Worker protocol message limit is invalid")

    def encode(self) -> bytes:
        payload = {
            "key": base64.b64encode(self.key).decode("ascii"),
            "max_frame_bytes": self.max_frame_bytes,
            "max_messages": self.max_messages,
            "protocol": PROTOCOL_VERSION,
            "run_id": self.run_id,
            "session_id": self.session_id,
        }
        encoded = _canonical_json(payload) + b"\n"
        if len(encoded) > BOOTSTRAP_MAX_BYTES:
            raise ProtocolError("Worker bootstrap exceeds its limit")
        return encoded

    @classmethod
    def read(cls, stream: BinaryIO) -> WorkerBootstrap:
        line = stream.readline(BOOTSTRAP_MAX_BYTES + 1)
        if (
            not line
            or len(line) > BOOTSTRAP_MAX_BYTES
            or not line.endswith(b"\n")
        ):
            raise ProtocolError("Worker bootstrap frame is invalid")
        try:
            payload = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProtocolError("Worker bootstrap JSON is invalid") from None
        if (
            not isinstance(payload, dict)
            or set(payload)
            != {
                "key",
                "max_frame_bytes",
                "max_messages",
                "protocol",
                "run_id",
                "session_id",
            }
            or type(payload["protocol"]) is not int
            or payload["protocol"] != PROTOCOL_VERSION
        ):
            raise ProtocolError("Worker bootstrap schema is invalid")
        try:
            key = base64.b64decode(payload["key"], validate=True)
        except (TypeError, ValueError, binascii.Error):
            raise ProtocolError("Worker bootstrap key is invalid") from None
        try:
            return cls(
                key=key,
                session_id=payload["session_id"],
                run_id=payload["run_id"],
                max_frame_bytes=payload["max_frame_bytes"],
                max_messages=payload["max_messages"],
            )
        except (TypeError, ValueError) as exc:
            raise ProtocolError("Worker bootstrap values are invalid") from exc


class ProtocolSession:
    """Directional sequence and HMAC state for one anonymous pipe pair."""

    def __init__(
        self,
        bootstrap: WorkerBootstrap,
        *,
        send_direction: str,
        receive_direction: str,
    ) -> None:
        if send_direction == receive_direction or {
            send_direction,
            receive_direction,
        } != {"host_to_worker", "worker_to_host"}:
            raise ValueError("Worker protocol directions are invalid")
        self._bootstrap = bootstrap
        self._send_direction = send_direction
        self._receive_direction = receive_direction
        self._send_sequence = 0
        self._receive_sequence = 0

    def encode(
        self,
        message_type: str,
        payload: dict[str, object],
    ) -> bytes:
        if self._send_sequence >= self._bootstrap.max_messages:
            raise ProtocolError("Worker protocol message limit reached")
        _validate_message_type(message_type)
        _validate_json(payload)
        envelope = {
            "direction": self._send_direction,
            "payload": payload,
            "protocol": PROTOCOL_VERSION,
            "run_id": self._bootstrap.run_id,
            "sequence": self._send_sequence,
            "session_id": self._bootstrap.session_id,
            "type": message_type,
        }
        canonical = _canonical_json(envelope)
        signed = dict(envelope)
        signed["mac"] = hmac.new(
            self._bootstrap.key,
            canonical,
            hashlib.sha256,
        ).hexdigest()
        encoded = _canonical_json(signed) + b"\n"
        if len(encoded) > self._bootstrap.max_frame_bytes:
            raise ProtocolError("Worker protocol frame exceeds its limit")
        self._send_sequence += 1
        return encoded

    def decode(self, line: bytes) -> ProtocolMessage:
        if self._receive_sequence >= self._bootstrap.max_messages:
            raise ProtocolError("Worker protocol message limit reached")
        if (
            not isinstance(line, bytes)
            or not line
            or len(line) > self._bootstrap.max_frame_bytes
            or not line.endswith(b"\n")
        ):
            raise ProtocolError("Worker protocol frame is invalid")
        try:
            envelope = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProtocolError("Worker protocol JSON is invalid") from None
        expected_keys = {
            "direction",
            "mac",
            "payload",
            "protocol",
            "run_id",
            "sequence",
            "session_id",
            "type",
        }
        if not isinstance(envelope, dict) or set(envelope) != expected_keys:
            raise ProtocolError("Worker protocol schema is invalid")
        mac = envelope.pop("mac")
        if (
            not isinstance(mac, str)
            or len(mac) != 64
            or envelope["direction"] != self._receive_direction
            or type(envelope["protocol"]) is not int
            or envelope["protocol"] != PROTOCOL_VERSION
            or envelope["run_id"] != self._bootstrap.run_id
            or envelope["session_id"] != self._bootstrap.session_id
            or type(envelope["sequence"]) is not int
            or envelope["sequence"] != self._receive_sequence
        ):
            raise ProtocolError(
                "Worker protocol identity or sequence is invalid"
            )
        expected_mac = hmac.new(
            self._bootstrap.key,
            _canonical_json(envelope),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ProtocolError("Worker protocol authentication failed")
        _validate_message_type(envelope["type"])
        _validate_json(envelope["payload"])
        if not isinstance(envelope["payload"], dict):
            raise ProtocolError("Worker protocol payload must be an object")
        message = ProtocolMessage(
            message_type=envelope["type"],
            payload=envelope["payload"],
            sequence=envelope["sequence"],
        )
        self._receive_sequence += 1
        return message


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ProtocolError("Worker protocol value is not JSON") from None


def _validate_message_type(value: object) -> str:
    if (
        not isinstance(value, str)
        or _MESSAGE_TYPE.fullmatch(value) is None
    ):
        raise ProtocolError("Worker protocol message type is invalid")
    return value


def _validate_json(value: object, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ProtocolError("Worker protocol payload is too deeply nested")
    if value is None or type(value) in {bool, int}:
        if type(value) is int and not -(2**63) <= value <= 2**63 - 1:
            raise ProtocolError("Worker protocol integer is out of range")
        return
    if isinstance(value, float):
        raise ProtocolError("Worker protocol floats are not accepted")
    if isinstance(value, str):
        if (
            len(value) > MAX_JSON_STRING_CHARS
            or any(
                ord(character) < 32 and character not in "\n\t"
                for character in value
            )
        ):
            raise ProtocolError("Worker protocol string is invalid")
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_ITEMS:
            raise ProtocolError("Worker protocol list is too large")
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_ITEMS:
            raise ProtocolError("Worker protocol object is too large")
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or _PAYLOAD_KEY.fullmatch(key) is None
            ):
                raise ProtocolError("Worker protocol object key is invalid")
            _validate_json(item, depth=depth + 1)
        return
    raise ProtocolError("Worker protocol payload type is invalid")
