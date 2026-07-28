"""Token-safe connected-account lifecycle above desktop OAuth.

The service returns non-secret account metadata only.  OAuth credentials stay
inside the broker, token store, and memory cache; UI and task code never
receive a token value.
"""

from __future__ import annotations

import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from capability_registry import (
    AccountAuthorization,
    CAPABILITY_REGISTRY,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
    require_oauth_scope,
)
from connectors.base import (
    ConnectedAccount,
    ConnectionHealth,
    ConnectorAuthorizationError,
    ConnectorError,
    ConnectorProviderId,
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    ConnectorTokenExpiredError,
    OAuthTokenSet,
    PROVIDER_CONNECTORS,
    RevocationStatus,
    SecretValue,
    provider_for_connector,
)
from connectors.oauth import (
    OAUTH_PROVIDER_POLICIES,
    OAuthAuthorizationSession,
    OAuthClientRegistration,
    OAuthConsentSummary,
    OAuthDesktopAvailability,
    OAuthProviderUnavailableError,
    OAuthTokenClient,
    describe_authorization,
    prepare_authorization,
)
from connectors.token_store import (
    AccessTokenCache,
    AccessTokenLease,
    AccessTokenMetadata,
    ConnectorTokenNotFoundError,
    ConnectorTokenStorageError,
    RefreshTokenStore,
)


GOOGLE_OAUTH_CLIENT_ID_ENV = "CLICKY_GOOGLE_OAUTH_CLIENT_ID"
MAX_ACCOUNT_AUTHORIZATION_SECONDS = 5 * 60
MAX_NEW_ID_ATTEMPTS = 3
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ConnectedAccountServiceError(ConnectorError):
    """Content-free account lifecycle failure."""


class AccountConnectionAvailability(str, Enum):
    READY = "ready"
    MISSING_PUBLIC_CLIENT_REGISTRATION = (
        "missing_public_client_registration"
    )
    CONFIDENTIAL_BROKER_REQUIRED = "confidential_broker_required"


class AccountConnectionStatus(str, Enum):
    CONNECTED = "connected"
    RECONNECTED = "reconnected"
    REVOKED_AND_DISCONNECTED = "revoked_and_disconnected"
    LOCAL_TOKEN_DELETED = "local_token_deleted"


@dataclass(frozen=True, slots=True)
class AccountConnectRequest:
    connector: ConnectorId
    capabilities: frozenset[CapabilityId]

    def __post_init__(self) -> None:
        if not isinstance(self.connector, ConnectorId):
            raise TypeError("Account connection connector is invalid")
        if (
            not isinstance(self.capabilities, frozenset)
            or not self.capabilities
            or len(self.capabilities) > 32
            or any(
                not isinstance(capability, CapabilityId)
                for capability in self.capabilities
            )
        ):
            raise TypeError(
                "Account connection requires exact capabilities"
            )
        for capability in self.capabilities:
            definition = CAPABILITY_REGISTRY[capability]
            if definition.connector is not self.connector:
                raise ValueError(
                    "Account connection contains another connector capability"
                )

    @property
    def provider(self) -> ConnectorProviderId:
        return provider_for_connector(self.connector)

    @property
    def oauth_scopes(self) -> frozenset[OAuthScopeId]:
        return frozenset(
            require_oauth_scope(capability)
            for capability in self.capabilities
        )


@dataclass(frozen=True, slots=True)
class AccountConnectionResult:
    status: AccountConnectionStatus
    account: ConnectedAccount

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, AccountConnectionStatus)
            or self.status
            not in {
                AccountConnectionStatus.CONNECTED,
                AccountConnectionStatus.RECONNECTED,
            }
        ):
            raise ValueError("Account connection result status is invalid")
        if not isinstance(self.account, ConnectedAccount):
            raise TypeError("Account connection result is invalid")


@dataclass(frozen=True, slots=True)
class AccountDisconnectResult:
    status: AccountConnectionStatus
    authorization_id: str
    provider: ConnectorProviderId
    connector: ConnectorId
    provider_revocation_status: RevocationStatus | None
    local_token_deleted: bool
    completed_at: float

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, AccountConnectionStatus)
            or self.status
            not in {
                AccountConnectionStatus.REVOKED_AND_DISCONNECTED,
                AccountConnectionStatus.LOCAL_TOKEN_DELETED,
            }
        ):
            raise ValueError("Account disconnect result status is invalid")
        if (
            not isinstance(self.authorization_id, str)
            or _OPAQUE_ID.fullmatch(self.authorization_id) is None
        ):
            raise ValueError("Account disconnect authorization ID is invalid")
        if not isinstance(self.provider, ConnectorProviderId):
            raise TypeError("Account disconnect provider is invalid")
        if not isinstance(self.connector, ConnectorId):
            raise TypeError("Account disconnect connector is invalid")
        if self.connector not in PROVIDER_CONNECTORS[self.provider]:
            raise ValueError(
                "Account disconnect provider does not own connector"
            )
        if self.status is AccountConnectionStatus.REVOKED_AND_DISCONNECTED:
            if not isinstance(
                self.provider_revocation_status,
                RevocationStatus,
            ):
                raise TypeError("Provider revocation evidence is required")
        elif self.provider_revocation_status is not None:
            raise ValueError("Local-only deletion has no revocation evidence")
        if self.local_token_deleted is not True:
            raise ValueError("Account disconnect must delete the local token")
        if (
            not isinstance(self.completed_at, (int, float))
            or isinstance(self.completed_at, bool)
            or not math.isfinite(float(self.completed_at))
            or self.completed_at < 0
        ):
            raise ValueError("Account disconnect time is invalid")


class AccountOAuthBroker(Protocol):
    def availability(
        self,
        provider: ConnectorProviderId,
    ) -> AccountConnectionAvailability: ...

    def describe(
        self,
        request: AccountConnectRequest,
    ) -> OAuthConsentSummary: ...

    def authorize(
        self,
        request: AccountConnectRequest,
    ) -> OAuthTokenSet: ...

    def refresh(
        self,
        account: ConnectedAccount,
        refresh_token: SecretValue,
    ) -> OAuthTokenSet: ...

    def revoke(
        self,
        request: ConnectorRevocationRequest,
        refresh_token: SecretValue,
    ) -> ConnectorRevocationResult: ...


class DesktopOAuthBroker:
    """System-browser OAuth broker with fixed, public client registrations."""

    def __init__(
        self,
        registrations: Mapping[
            ConnectorProviderId, OAuthClientRegistration
        ] | None = None,
        *,
        token_client: OAuthTokenClient | None = None,
        browser_opener: Callable[[str], object] | None = None,
        callback_timeout_seconds: float = 120.0,
        _session_factory: Callable[..., OAuthAuthorizationSession] = (
            prepare_authorization
        ),
    ) -> None:
        registrations = (
            registrations
            if registrations is not None
            else {}
        )
        checked: dict[ConnectorProviderId, OAuthClientRegistration] = {}
        for provider, registration in registrations.items():
            if (
                not isinstance(provider, ConnectorProviderId)
                or not isinstance(registration, OAuthClientRegistration)
                or registration.provider is not provider
            ):
                raise TypeError("OAuth client registration mapping is invalid")
            if (
                OAUTH_PROVIDER_POLICIES[provider].availability
                is not OAuthDesktopAvailability.READY
            ):
                raise OAuthProviderUnavailableError(
                    "OAuth provider requires a reviewed confidential broker"
                )
            checked[provider] = registration
        if not isinstance(token_client, (OAuthTokenClient, type(None))):
            if not (
                callable(getattr(token_client, "exchange", None))
                and callable(getattr(token_client, "revoke", None))
            ):
                raise TypeError("Desktop OAuth token client is invalid")
        if browser_opener is not None and not callable(browser_opener):
            raise TypeError("Desktop OAuth browser opener is invalid")
        if not callable(_session_factory):
            raise TypeError("Desktop OAuth session factory is invalid")
        if (
            not isinstance(callback_timeout_seconds, (int, float))
            or isinstance(callback_timeout_seconds, bool)
            or not math.isfinite(float(callback_timeout_seconds))
            or not 0.01
            <= float(callback_timeout_seconds)
            <= MAX_ACCOUNT_AUTHORIZATION_SECONDS
        ):
            raise ValueError("Desktop OAuth callback timeout is invalid")
        self._registrations = MappingProxyType(checked)
        self._token_client = (
            token_client
            if token_client is not None
            else OAuthTokenClient()
        )
        self._browser_opener = browser_opener
        self._callback_timeout = float(callback_timeout_seconds)
        self._session_factory = _session_factory

    def availability(
        self,
        provider: ConnectorProviderId,
    ) -> AccountConnectionAvailability:
        if not isinstance(provider, ConnectorProviderId):
            raise TypeError("Connected-account provider is invalid")
        policy = OAUTH_PROVIDER_POLICIES[provider]
        if (
            policy.availability
            is OAuthDesktopAvailability.CONFIDENTIAL_BROKER_REQUIRED
        ):
            return (
                AccountConnectionAvailability.CONFIDENTIAL_BROKER_REQUIRED
            )
        if provider not in self._registrations:
            return (
                AccountConnectionAvailability
                .MISSING_PUBLIC_CLIENT_REGISTRATION
            )
        return AccountConnectionAvailability.READY

    def describe(
        self,
        request: AccountConnectRequest,
    ) -> OAuthConsentSummary:
        if not isinstance(request, AccountConnectRequest):
            raise TypeError("Account connection request is invalid")
        registration = self._require_registration(request.provider)
        return describe_authorization(
            registration,
            request.connector,
            request.capabilities,
        )

    def authorize(
        self,
        request: AccountConnectRequest,
    ) -> OAuthTokenSet:
        if not isinstance(request, AccountConnectRequest):
            raise TypeError("Account connection request is invalid")
        registration = self._require_registration(request.provider)
        session = self._session_factory(
            registration,
            request.connector,
            request.capabilities,
        )
        authorization = None
        try:
            if self._browser_opener is None:
                session.open_system_browser()
            else:
                session.open_system_browser(self._browser_opener)
            authorization = session.wait_for_callback(
                timeout_seconds=self._callback_timeout,
            )
            return self._token_client.exchange(
                registration,
                authorization,
            )
        finally:
            if authorization is not None:
                authorization.close()
            session.close()

    def revoke(
        self,
        request: ConnectorRevocationRequest,
        refresh_token: SecretValue,
    ) -> ConnectorRevocationResult:
        if not isinstance(request, ConnectorRevocationRequest):
            raise TypeError("Connected-account revocation request is invalid")
        policy = OAUTH_PROVIDER_POLICIES[request.provider]
        if (
            policy.availability
            is not OAuthDesktopAvailability.READY
            or policy.revocation_endpoint is None
        ):
            raise OAuthProviderUnavailableError(
                "OAuth provider revocation requires a reviewed broker"
            )
        return self._token_client.revoke(
            request.provider,
            request,
            refresh_token,
        )

    def refresh(
        self,
        account: ConnectedAccount,
        refresh_token: SecretValue,
    ) -> OAuthTokenSet:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Connected-account refresh account is invalid")
        registration = self._require_registration(account.provider)
        if not callable(getattr(self._token_client, "refresh", None)):
            raise ConnectorAuthorizationError(
                "OAuth token refresh is unavailable"
            )
        return self._token_client.refresh(
            registration,
            account.oauth_scopes,
            refresh_token,
        )

    def _require_registration(
        self,
        provider: ConnectorProviderId,
    ) -> OAuthClientRegistration:
        availability = self.availability(provider)
        if availability is not AccountConnectionAvailability.READY:
            if (
                availability
                is AccountConnectionAvailability.CONFIDENTIAL_BROKER_REQUIRED
            ):
                raise OAuthProviderUnavailableError(
                    "OAuth provider requires a reviewed confidential broker"
                )
            raise OAuthProviderUnavailableError(
                "OAuth public client registration is not configured"
            )
        return self._registrations[provider]


class ConnectedAccountService:
    """Atomic account connection, reconnection, revocation, and deletion."""

    def __init__(
        self,
        *,
        token_store: RefreshTokenStore | None = None,
        access_tokens: AccessTokenCache | None = None,
        oauth: AccountOAuthBroker | None = None,
        _clock: Callable[[], float] = time.time,
        _id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        self._token_store = (
            token_store
            if token_store is not None
            else RefreshTokenStore()
        )
        self._access_tokens = (
            access_tokens
            if access_tokens is not None
            else AccessTokenCache()
        )
        self._oauth = (
            oauth
            if oauth is not None
            else DesktopOAuthBroker(load_public_oauth_registrations())
        )
        if not all(
            callable(getattr(self._oauth, name, None))
            for name in (
                "availability",
                "describe",
                "authorize",
                "revoke",
            )
        ):
            raise TypeError("Connected-account OAuth broker is invalid")
        if not callable(_clock) or not callable(_id_factory):
            raise TypeError("Connected-account clock and ID factory are invalid")
        self._clock = _clock
        self._id_factory = _id_factory
        self._lock = threading.RLock()

    def list_accounts(self) -> tuple[ConnectedAccount, ...]:
        return tuple(
            metadata.account
            for metadata in self._token_store.list_metadata()
        )

    def get_account(self, authorization_id: str) -> ConnectedAccount:
        """Return non-secret account authority for one opaque selection."""

        metadata = self._token_store.get_metadata(authorization_id)
        if metadata is None:
            raise ConnectorTokenNotFoundError(
                "Connected account was not found"
            )
        return metadata.account

    def lease_access_token(
        self,
        authorization_id: str,
        capability: CapabilityId,
    ) -> AccessTokenLease:
        """Lease a scoped token, refreshing behind the broker when required."""

        if not isinstance(capability, CapabilityId):
            raise TypeError("Connector access capability is invalid")
        with self._lock:
            account = self.get_account(authorization_id)
            if not account.allows(capability):
                raise ConnectorAuthorizationError(
                    "Connected account lacks the requested capability"
                )
            required_scopes = frozenset({require_oauth_scope(capability)})
            try:
                return self._access_tokens.lease(
                    authorization_id,
                    required_scopes=required_scopes,
                )
            except (
                ConnectorTokenExpiredError,
                ConnectorTokenNotFoundError,
            ):
                pass

            with self._token_store.lease(authorization_id) as refresh_lease:
                if not callable(getattr(self._oauth, "refresh", None)):
                    raise ConnectorAuthorizationError(
                        "OAuth token refresh is unavailable"
                    )
                tokens = self._oauth.refresh(account, refresh_lease.token)
            if not isinstance(tokens, OAuthTokenSet):
                raise TypeError("OAuth broker returned an invalid token set")
            try:
                if tokens.oauth_scopes != account.oauth_scopes:
                    raise ConnectorAuthorizationError(
                        "Refreshed OAuth token scopes do not match the account"
                    )
                access_metadata = AccessTokenMetadata(
                    authorization_id=authorization_id,
                    oauth_scopes=tokens.oauth_scopes,
                    issued_at=tokens.issued_at,
                    expires_at=tokens.access_expires_at,
                )
                if tokens.refresh_token is not None:
                    self._token_store.put(account, tokens.refresh_token)
                self._access_tokens.put(
                    access_metadata,
                    tokens.access_token,
                )
            finally:
                tokens.close()
            return self._access_tokens.lease(
                authorization_id,
                required_scopes=required_scopes,
            )

    def availability(
        self,
        provider: ConnectorProviderId,
    ) -> AccountConnectionAvailability:
        return self._oauth.availability(provider)

    def describe_connection(
        self,
        request: AccountConnectRequest,
    ) -> OAuthConsentSummary:
        if not isinstance(request, AccountConnectRequest):
            raise TypeError("Account connection request is invalid")
        return self._oauth.describe(request)

    def connect(
        self,
        request: AccountConnectRequest,
    ) -> AccountConnectionResult:
        if not isinstance(request, AccountConnectRequest):
            raise TypeError("Account connection request is invalid")
        with self._lock:
            return self._authorize_and_store(request, existing=None)

    def reconnect(
        self,
        authorization_id: str,
    ) -> AccountConnectionResult:
        with self._lock:
            metadata = self._token_store.get_metadata(authorization_id)
            if metadata is None:
                raise ConnectorTokenNotFoundError(
                    "Connected account was not found"
                )
            account = metadata.account
            request = AccountConnectRequest(
                connector=account.connector,
                capabilities=account.capabilities,
            )
            return self._authorize_and_store(
                request,
                existing=account,
            )

    def revoke_and_disconnect(
        self,
        authorization_id: str,
    ) -> AccountDisconnectResult:
        with self._lock:
            metadata = self._token_store.get_metadata(authorization_id)
            if metadata is None:
                raise ConnectorTokenNotFoundError(
                    "Connected account was not found"
                )
            account = metadata.account
            request = ConnectorRevocationRequest(
                authorization_id=account.authorization_id,
                provider=account.provider,
                connector=account.connector,
                account_reference=account.account_reference,
            )
            with self._token_store.lease(authorization_id) as lease:
                revocation = self._oauth.revoke(request, lease.token)
            if not isinstance(revocation, ConnectorRevocationResult):
                raise TypeError(
                    "Provider returned invalid revocation evidence"
                )
            if revocation.authorization_id != authorization_id:
                raise ConnectedAccountServiceError(
                    "Provider revocation evidence did not match the account"
                )
            if not self._token_store.delete(authorization_id):
                raise ConnectorTokenStorageError(
                    "Revoked connected-account token could not be deleted"
                )
            self._access_tokens.evict(authorization_id)
            return AccountDisconnectResult(
                status=(
                    AccountConnectionStatus.REVOKED_AND_DISCONNECTED
                ),
                authorization_id=authorization_id,
                provider=account.provider,
                connector=account.connector,
                provider_revocation_status=revocation.status,
                local_token_deleted=True,
                completed_at=revocation.completed_at,
            )

    def delete_local_token(
        self,
        authorization_id: str,
    ) -> AccountDisconnectResult:
        with self._lock:
            metadata = self._token_store.get_metadata(authorization_id)
            if metadata is None:
                raise ConnectorTokenNotFoundError(
                    "Connected account was not found"
                )
            account = metadata.account
            if not self._token_store.delete(authorization_id):
                raise ConnectorTokenStorageError(
                    "Connected-account token could not be deleted"
                )
            self._access_tokens.evict(authorization_id)
            return AccountDisconnectResult(
                status=AccountConnectionStatus.LOCAL_TOKEN_DELETED,
                authorization_id=authorization_id,
                provider=account.provider,
                connector=account.connector,
                provider_revocation_status=None,
                local_token_deleted=True,
                completed_at=_timestamp(self._clock()),
            )

    def _authorize_and_store(
        self,
        request: AccountConnectRequest,
        *,
        existing: ConnectedAccount | None,
    ) -> AccountConnectionResult:
        tokens = self._oauth.authorize(request)
        if not isinstance(tokens, OAuthTokenSet):
            raise TypeError("OAuth broker returned an invalid token set")
        try:
            if (
                tokens.oauth_scopes != request.oauth_scopes
                or tokens.refresh_token is None
            ):
                raise ConnectorAuthorizationError(
                    "OAuth tokens do not match the requested account scopes"
                )
            now = _timestamp(self._clock())
            if existing is None:
                authorization_id, account_reference = self._new_identity(
                    request
                )
                connected_at = now
                status = AccountConnectionStatus.CONNECTED
            else:
                if (
                    existing.provider is not request.provider
                    or existing.connector is not request.connector
                    or existing.capabilities != request.capabilities
                ):
                    raise ConnectorAuthorizationError(
                        "Reconnect request does not match the account"
                    )
                authorization_id = existing.authorization_id
                account_reference = existing.account_reference
                connected_at = existing.connected_at
                status = AccountConnectionStatus.RECONNECTED
            account = ConnectedAccount(
                provider=request.provider,
                authorization=AccountAuthorization(
                    authorization_id=authorization_id,
                    connector=request.connector,
                    account_reference=account_reference,
                    capabilities=request.capabilities,
                    oauth_scopes=request.oauth_scopes,
                ),
                connected_at=connected_at,
                updated_at=now,
                health=ConnectionHealth.CONNECTED,
            )
            access_metadata = AccessTokenMetadata(
                authorization_id=authorization_id,
                oauth_scopes=request.oauth_scopes,
                issued_at=tokens.issued_at,
                expires_at=tokens.access_expires_at,
            )
            self._token_store.put(account, tokens.refresh_token)
            try:
                self._access_tokens.put(
                    access_metadata,
                    tokens.access_token,
                )
            except ConnectorTokenExpiredError:
                # A refresh token remains useful if an access token expires
                # between provider response and caching.
                self._access_tokens.evict(authorization_id)
            return AccountConnectionResult(
                status=status,
                account=account,
            )
        finally:
            tokens.close()

    def _new_identity(
        self,
        request: AccountConnectRequest,
    ) -> tuple[str, str]:
        for _attempt in range(MAX_NEW_ID_ATTEMPTS):
            candidate = self._id_factory()
            authorization_id = f"oauth.{candidate}"
            account_reference = f"{request.provider.value}.{candidate}"
            try:
                AccountAuthorization(
                    authorization_id=authorization_id,
                    connector=request.connector,
                    account_reference=account_reference,
                    capabilities=request.capabilities,
                    oauth_scopes=request.oauth_scopes,
                )
            except (TypeError, ValueError):
                raise ConnectedAccountServiceError(
                    "Connected-account identity source returned invalid data"
                ) from None
            if self._token_store.get_metadata(authorization_id) is None:
                return authorization_id, account_reference
        raise ConnectedAccountServiceError(
            "Could not allocate a unique connected-account identity"
        )


def _timestamp(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise ValueError("Connected-account time is invalid")
    return float(value)


def load_public_oauth_registrations(
    environ: Mapping[str, str] | None = None,
) -> Mapping[ConnectorProviderId, OAuthClientRegistration]:
    """Load public client IDs only; provider secrets are never accepted."""

    values = os.environ if environ is None else environ
    if not isinstance(values, Mapping):
        raise TypeError("OAuth public registration environment is invalid")
    client_id = values.get(GOOGLE_OAUTH_CLIENT_ID_ENV, "")
    if client_id == "":
        return MappingProxyType({})
    registration = OAuthClientRegistration(
        provider=ConnectorProviderId.GOOGLE,
        client_id=client_id,
    )
    return MappingProxyType(
        {ConnectorProviderId.GOOGLE: registration}
    )


__all__ = [
    "GOOGLE_OAUTH_CLIENT_ID_ENV",
    "AccountConnectRequest",
    "AccountConnectionAvailability",
    "AccountConnectionResult",
    "AccountConnectionStatus",
    "AccountDisconnectResult",
    "ConnectedAccountService",
    "ConnectedAccountServiceError",
    "DesktopOAuthBroker",
    "load_public_oauth_registrations",
]
