"""Typed, token-safe contracts for connected-account adapters.

This module performs no network access and owns no provider endpoints.  It
defines the exact identities, semantic scopes, call evidence, revocation
outcomes, and secret container future OAuth and connector adapters must use.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Generic, Protocol, TypeVar, runtime_checkable

from capability_registry import (
    AccountAuthorization,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
    require_capability,
)


MAX_SECRET_BYTES = 16 * 1024
MAX_PROVIDER_REQUEST_ID_CHARS = 256
MAX_OPERATION_ID_CHARS = 128
MAX_CONNECTOR_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_RATE_LIMIT_SECONDS = 24 * 60 * 60
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_OPERATION_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
ConnectorOutput = TypeVar("ConnectorOutput")


class ConnectorProviderId(str, Enum):
    GOOGLE = "google"
    NOTION = "notion"


PROVIDER_CONNECTORS = MappingProxyType(
    {
        ConnectorProviderId.GOOGLE: frozenset(
            {
                ConnectorId.GMAIL,
                ConnectorId.GOOGLE_CALENDAR,
                ConnectorId.GOOGLE_DOCS,
                ConnectorId.GOOGLE_DRIVE,
                ConnectorId.GOOGLE_SHEETS,
                ConnectorId.GOOGLE_SLIDES,
            }
        ),
        ConnectorProviderId.NOTION: frozenset({ConnectorId.NOTION}),
    }
)

if frozenset(
    connector
    for connectors in PROVIDER_CONNECTORS.values()
    for connector in connectors
) != frozenset(ConnectorId):
    raise RuntimeError("Connector providers do not cover every connector")


class ConnectionHealth(str, Enum):
    CONNECTED = "connected"
    REAUTHENTICATION_REQUIRED = "reauthentication_required"
    REVOKED = "revoked"
    DISCONNECTED = "disconnected"


class OAuthTokenType(str, Enum):
    BEARER = "Bearer"


class RevocationStatus(str, Enum):
    REVOKED = "revoked"
    ALREADY_INVALID = "already_invalid"
    UNSUPPORTED = "unsupported"


class ConnectorError(RuntimeError):
    """Base connector error whose messages must never contain credentials."""


class ConnectorAuthorizationError(ConnectorError):
    pass


class ConnectorDisconnectedError(ConnectorAuthorizationError):
    pass


class ConnectorTokenExpiredError(ConnectorAuthorizationError):
    pass


class ConnectorTokenRevokedError(ConnectorAuthorizationError):
    pass


class ConnectorInvalidGrantError(ConnectorAuthorizationError):
    pass


class ConnectorRequestError(ConnectorError):
    pass


class ConnectorResponseError(ConnectorError):
    pass


class ConnectorRevocationError(ConnectorError):
    pass


class ConnectorRateLimitError(ConnectorError):
    def __init__(self, retry_after_seconds: int) -> None:
        if (
            type(retry_after_seconds) is not int
            or not 0 <= retry_after_seconds <= MAX_RATE_LIMIT_SECONDS
        ):
            raise ValueError("Connector retry delay is invalid")
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Connector provider rate limit is active")


class SecretValue:
    """Best-effort wipeable bounded token bytes with redacted display."""

    __slots__ = ("_buffer", "_closed")

    def __init__(self, value: bytes) -> None:
        if (
            not isinstance(value, bytes)
            or not value
            or len(value) > MAX_SECRET_BYTES
            or b"\x00" in value
        ):
            raise ValueError("Secret value is invalid or exceeds its limit")
        self._buffer = bytearray(value)
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    def reveal(self) -> bytes:
        if self._closed:
            raise ConnectorAuthorizationError(
                "Connector credential is no longer available"
            )
        return bytes(self._buffer)

    def copy(self) -> SecretValue:
        return SecretValue(self.reveal())

    def close(self) -> None:
        if self._closed:
            return
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._buffer.clear()
        self._closed = True

    def __enter__(self) -> SecretValue:
        if self._closed:
            raise ConnectorAuthorizationError(
                "Connector credential is no longer available"
            )
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def __reduce__(self):
        raise TypeError("Connector credentials cannot be serialized")

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True, slots=True)
class ConnectedAccount:
    """Provider/account identity and semantic authority without credentials."""

    provider: ConnectorProviderId
    authorization: AccountAuthorization
    connected_at: float
    updated_at: float
    health: ConnectionHealth = ConnectionHealth.CONNECTED

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ConnectorProviderId):
            raise TypeError("Connected-account provider is invalid")
        if not isinstance(self.authorization, AccountAuthorization):
            raise TypeError(
                "Connected account requires typed account authorization"
            )
        if (
            self.authorization.connector
            not in PROVIDER_CONNECTORS[self.provider]
        ):
            raise ValueError(
                "Connected-account provider does not own this connector"
            )
        _timestamp(self.connected_at, "Connection time")
        _timestamp(self.updated_at, "Connection update time")
        if self.updated_at < self.connected_at:
            raise ValueError(
                "Connection update time precedes connection time"
            )
        if not isinstance(self.health, ConnectionHealth):
            raise TypeError("Connected-account health is invalid")

    @property
    def authorization_id(self) -> str:
        return self.authorization.authorization_id

    @property
    def connector(self) -> ConnectorId:
        return self.authorization.connector

    @property
    def account_reference(self) -> str:
        return self.authorization.account_reference

    @property
    def capabilities(self) -> frozenset[CapabilityId]:
        return self.authorization.capabilities

    @property
    def oauth_scopes(self) -> frozenset[OAuthScopeId]:
        return self.authorization.oauth_scopes

    def allows(self, capability: CapabilityId) -> bool:
        return (
            self.health is ConnectionHealth.CONNECTED
            and self.authorization.allows(capability)
        )


@dataclass(frozen=True, slots=True)
class OAuthTokenSet:
    """One token response; secret values are redacted and explicitly wipeable."""

    access_token: SecretValue = field(repr=False)
    refresh_token: SecretValue | None = field(default=None, repr=False)
    token_type: OAuthTokenType = OAuthTokenType.BEARER
    oauth_scopes: frozenset[OAuthScopeId] = field(default_factory=frozenset)
    issued_at: float = 0.0
    access_expires_at: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.access_token, SecretValue):
            raise TypeError("OAuth access token must use SecretValue")
        if self.refresh_token is not None and not isinstance(
            self.refresh_token,
            SecretValue,
        ):
            raise TypeError("OAuth refresh token must use SecretValue")
        if not isinstance(self.token_type, OAuthTokenType):
            raise TypeError("OAuth token type is invalid")
        _oauth_scopes(self.oauth_scopes)
        _timestamp(self.issued_at, "OAuth issue time")
        _timestamp(self.access_expires_at, "OAuth expiry time")
        if self.access_expires_at <= self.issued_at:
            raise ValueError("OAuth access token expiry is invalid")

    def close(self) -> None:
        self.access_token.close()
        if self.refresh_token is not None:
            self.refresh_token.close()

    def __enter__(self) -> OAuthTokenSet:
        if self.access_token.closed:
            raise ConnectorAuthorizationError(
                "OAuth token set is no longer available"
            )
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()


@runtime_checkable
class ConnectorOperationRequest(Protocol):
    """Provider-specific request objects implement this sealed metadata view."""

    @property
    def connector(self) -> ConnectorId: ...

    @property
    def capability(self) -> CapabilityId: ...

    @property
    def operation_id(self) -> str: ...

    @property
    def request_digest(self) -> str: ...

    @property
    def idempotency_key(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class ConnectorCall:
    """One broker-authorized connector call, never an OAuth credential."""

    call_id: str
    run_id: str
    authorization_id: str
    connector: ConnectorId
    capability: CapabilityId
    operation_id: str
    request_digest: str
    maximum_response_bytes: int
    idempotency_key: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.call_id, "Connector call ID"),
            (self.run_id, "Connector run ID"),
            (self.authorization_id, "Connector authorization ID"),
        ):
            _opaque_id(value, label)
        if not isinstance(self.connector, ConnectorId):
            raise TypeError("Connector call connector is invalid")
        if not isinstance(self.capability, CapabilityId):
            raise TypeError("Connector call capability is invalid")
        definition = require_capability(self.capability)
        if definition.connector is not self.connector:
            raise ValueError(
                "Connector call capability belongs to another connector"
            )
        _operation_id(self.operation_id)
        _sha256(self.request_digest, "Connector request digest")
        if (
            type(self.maximum_response_bytes) is not int
            or not 1
            <= self.maximum_response_bytes
            <= MAX_CONNECTOR_RESPONSE_BYTES
        ):
            raise ValueError("Connector response limit is invalid")
        if self.idempotency_key is not None:
            _idempotency_key(self.idempotency_key)


@dataclass(frozen=True, slots=True)
class ConnectorCallResult:
    """Content-free provider evidence for one typed connector response."""

    call_id: str
    run_id: str
    operation_id: str
    http_status: int
    response_digest: str
    response_bytes: int
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        _opaque_id(self.call_id, "Connector result call ID")
        _opaque_id(self.run_id, "Connector result run ID")
        _operation_id(self.operation_id)
        if (
            type(self.http_status) is not int
            or not 200 <= self.http_status <= 299
        ):
            raise ValueError(
                "Successful connector result needs a 2xx status"
            )
        _sha256(self.response_digest, "Connector response digest")
        if (
            type(self.response_bytes) is not int
            or not 0 <= self.response_bytes <= MAX_CONNECTOR_RESPONSE_BYTES
        ):
            raise ValueError("Connector response size is invalid")
        if self.provider_request_id is not None:
            _bounded_provider_request_id(self.provider_request_id)


@dataclass(frozen=True, slots=True)
class ConnectorExecution(Generic[ConnectorOutput]):
    """Provider evidence plus one provider-specific, already-validated output."""

    result: ConnectorCallResult
    output: ConnectorOutput

    def __post_init__(self) -> None:
        if not isinstance(self.result, ConnectorCallResult):
            raise TypeError("Connector execution requires call evidence")
        if self.output is None:
            raise TypeError("Connector execution requires typed output")


@dataclass(frozen=True, slots=True)
class ConnectorRevocationRequest:
    authorization_id: str
    provider: ConnectorProviderId
    connector: ConnectorId
    account_reference: str

    def __post_init__(self) -> None:
        _opaque_id(
            self.authorization_id,
            "Revocation authorization ID",
        )
        if not isinstance(self.provider, ConnectorProviderId):
            raise TypeError("Revocation provider is invalid")
        if not isinstance(self.connector, ConnectorId):
            raise TypeError("Revocation connector is invalid")
        if self.connector not in PROVIDER_CONNECTORS[self.provider]:
            raise ValueError(
                "Revocation provider does not own this connector"
            )
        _opaque_id(self.account_reference, "Revocation account reference")


@dataclass(frozen=True, slots=True)
class ConnectorRevocationResult:
    authorization_id: str
    status: RevocationStatus
    provider_request_id: str | None
    completed_at: float

    def __post_init__(self) -> None:
        _opaque_id(
            self.authorization_id,
            "Revocation result authorization ID",
        )
        if not isinstance(self.status, RevocationStatus):
            raise TypeError("Revocation status is invalid")
        if self.provider_request_id is not None:
            _bounded_provider_request_id(self.provider_request_id)
        _timestamp(self.completed_at, "Revocation completion time")


@runtime_checkable
class ConnectorAdapter(Protocol):
    """Provider adapters receive typed requests and only scoped token leases."""

    @property
    def provider(self) -> ConnectorProviderId: ...

    @property
    def connector(self) -> ConnectorId: ...

    async def execute(
        self,
        call: ConnectorCall,
        request: ConnectorOperationRequest,
        access_token: SecretValue,
    ) -> ConnectorExecution[object]: ...

    async def revoke(
        self,
        request: ConnectorRevocationRequest,
        refresh_token: SecretValue,
    ) -> ConnectorRevocationResult: ...


def provider_for_connector(
    connector: ConnectorId,
) -> ConnectorProviderId:
    if not isinstance(connector, ConnectorId):
        raise TypeError("Connector ID is invalid")
    matches = tuple(
        provider
        for provider, connectors in PROVIDER_CONNECTORS.items()
        if connector in connectors
    )
    if len(matches) != 1:
        raise RuntimeError("Connector provider mapping is ambiguous")
    return matches[0]


def validate_connector_authority(
    call: ConnectorCall,
    account: ConnectedAccount,
    request: ConnectorOperationRequest,
) -> None:
    """Require exact call, account, and typed-request identity before I/O."""

    if not isinstance(call, ConnectorCall):
        raise TypeError("Connector authority requires a typed call")
    if not isinstance(account, ConnectedAccount):
        raise TypeError("Connector authority requires a connected account")
    if not isinstance(request, ConnectorOperationRequest):
        raise TypeError("Connector authority requires a typed request")
    if account.health is ConnectionHealth.DISCONNECTED:
        raise ConnectorDisconnectedError(
            "Connected account is disconnected"
        )
    if account.health is ConnectionHealth.REVOKED:
        raise ConnectorTokenRevokedError(
            "Connected-account authorization was revoked"
        )
    if account.health is ConnectionHealth.REAUTHENTICATION_REQUIRED:
        raise ConnectorInvalidGrantError(
            "Connected account requires authorization"
        )
    if (
        call.authorization_id != account.authorization_id
        or call.connector is not account.connector
        or call.capability is not request.capability
        or call.connector is not request.connector
        or call.operation_id != request.operation_id
        or call.request_digest != request.request_digest
        or call.idempotency_key != request.idempotency_key
        or not account.allows(call.capability)
    ):
        raise ConnectorAuthorizationError(
            "Connector call lacks exact account authority"
        )


def _oauth_scopes(
    value: object,
) -> frozenset[OAuthScopeId]:
    if (
        not isinstance(value, frozenset)
        or not value
        or any(not isinstance(scope, OAuthScopeId) for scope in value)
    ):
        raise TypeError("OAuth scopes must be a non-empty frozenset")
    return value


def _opaque_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value.strip() != value
        or _OPAQUE_ID.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _operation_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_OPERATION_ID_CHARS
        or _OPERATION_ID.fullmatch(value) is None
    ):
        raise ValueError("Connector operation ID is invalid")
    return value


def _idempotency_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or _IDEMPOTENCY_KEY.fullmatch(value) is None
    ):
        raise ValueError("Connector idempotency key is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be SHA-256")
    return value


def _bounded_provider_request_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_PROVIDER_REQUEST_ID_CHARS
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ValueError("Provider request ID is invalid")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError(f"{label} is invalid")
    return float(value)


__all__ = [
    "ConnectedAccount",
    "ConnectionHealth",
    "ConnectorAdapter",
    "ConnectorAuthorizationError",
    "ConnectorCall",
    "ConnectorCallResult",
    "ConnectorDisconnectedError",
    "ConnectorError",
    "ConnectorExecution",
    "ConnectorInvalidGrantError",
    "ConnectorOperationRequest",
    "ConnectorProviderId",
    "ConnectorRateLimitError",
    "ConnectorRequestError",
    "ConnectorResponseError",
    "ConnectorRevocationError",
    "ConnectorRevocationRequest",
    "ConnectorRevocationResult",
    "ConnectorTokenExpiredError",
    "ConnectorTokenRevokedError",
    "OAuthTokenSet",
    "OAuthTokenType",
    "PROVIDER_CONNECTORS",
    "RevocationStatus",
    "SecretValue",
    "provider_for_connector",
    "validate_connector_authority",
]
