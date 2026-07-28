"""System-browser OAuth Authorization Code + PKCE for desktop connectors.

The shipped desktop flow is deliberately Google-only. Current Notion public
OAuth requires a distributable client secret and does not document PKCE, so
Notion stays unavailable until a reviewed confidential broker exists.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from capability_registry import (
    CAPABILITY_REGISTRY,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
    require_oauth_scope,
)
from connectors.base import (
    PROVIDER_CONNECTORS,
    ConnectorAuthorizationError,
    ConnectorInvalidGrantError,
    ConnectorProviderId,
    ConnectorRateLimitError,
    ConnectorRequestError,
    ConnectorResponseError,
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    ConnectorTokenRevokedError,
    OAuthTokenSet,
    OAuthTokenType,
    RevocationStatus,
    SecretValue,
)


MAX_CLIENT_ID_CHARS = 512
MAX_CALLBACK_TARGET_CHARS = 8 * 1024
MAX_AUTHORIZATION_CODE_BYTES = 4 * 1024
MAX_OAUTH_RESPONSE_BYTES = 128 * 1024
MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60
MAX_AUTHORIZATION_TIMEOUT_SECONDS = 5 * 60
MAX_PROVIDER_SCOPES = 16
MAX_PROVIDER_SCOPE_CHARS = 256
CALLBACK_PATH = "/oauth/callback"
_GOOGLE_CLIENT_ID = re.compile(
    r"^[A-Za-z0-9._-]{10,480}\.apps\.googleusercontent\.com$"
)
_BOUNDED_ASCII = re.compile(r"^[\x21-\x7e]+$")
_PROVIDER_SCOPE = re.compile(r"^https://[A-Za-z0-9./_-]+$")


def _fixed_https_endpoint(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError(f"OAuth {label} endpoint is invalid")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError(f"OAuth {label} endpoint is invalid") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"OAuth {label} endpoint is invalid")
    return value


class OAuthDesktopAvailability(str, Enum):
    READY = "ready"
    CONFIDENTIAL_BROKER_REQUIRED = "confidential_broker_required"


class OAuthSessionState(str, Enum):
    PREPARED = "prepared"
    BROWSER_OPENED = "browser_opened"
    CALLBACK_CONSUMED = "callback_consumed"
    CLOSED = "closed"


class OAuthError(ConnectorAuthorizationError):
    """Base OAuth error whose message excludes codes, state, and tokens."""


class OAuthProviderUnavailableError(OAuthError):
    pass


class OAuthBrowserError(OAuthError):
    pass


class OAuthCallbackError(OAuthError):
    pass


class OAuthAuthorizationDeniedError(OAuthCallbackError):
    pass


class OAuthAuthorizationTimeoutError(OAuthCallbackError):
    pass


@dataclass(frozen=True, slots=True)
class OAuthProviderPolicy:
    provider: ConnectorProviderId
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str | None
    availability: OAuthDesktopAvailability
    pkce_required: bool
    loopback_redirect_supported: bool

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ConnectorProviderId):
            raise TypeError("OAuth provider policy ID is invalid")
        _fixed_https_endpoint(
            self.authorization_endpoint,
            "authorization",
        )
        _fixed_https_endpoint(self.token_endpoint, "token")
        if self.revocation_endpoint is not None:
            _fixed_https_endpoint(self.revocation_endpoint, "revocation")
        if not isinstance(self.availability, OAuthDesktopAvailability):
            raise TypeError("OAuth provider availability is invalid")
        if type(self.pkce_required) is not bool:
            raise TypeError("OAuth PKCE policy must be explicit")
        if type(self.loopback_redirect_supported) is not bool:
            raise TypeError("OAuth loopback policy must be explicit")
        if self.availability is OAuthDesktopAvailability.READY and (
            not self.pkce_required or not self.loopback_redirect_supported
        ):
            raise ValueError(
                "Desktop OAuth requires PKCE and loopback redirect support"
            )


OAUTH_PROVIDER_POLICIES: Mapping[
    ConnectorProviderId, OAuthProviderPolicy
] = MappingProxyType(
    {
        ConnectorProviderId.GOOGLE: OAuthProviderPolicy(
            provider=ConnectorProviderId.GOOGLE,
            authorization_endpoint=(
                "https://accounts.google.com/o/oauth2/v2/auth"
            ),
            token_endpoint="https://oauth2.googleapis.com/token",
            revocation_endpoint="https://oauth2.googleapis.com/revoke",
            availability=OAuthDesktopAvailability.READY,
            pkce_required=True,
            loopback_redirect_supported=True,
        ),
        ConnectorProviderId.NOTION: OAuthProviderPolicy(
            provider=ConnectorProviderId.NOTION,
            authorization_endpoint=(
                "https://api.notion.com/v1/oauth/authorize"
            ),
            token_endpoint="https://api.notion.com/v1/oauth/token",
            revocation_endpoint=None,
            availability=(
                OAuthDesktopAvailability.CONFIDENTIAL_BROKER_REQUIRED
            ),
            pkce_required=False,
            loopback_redirect_supported=False,
        ),
    }
)

if set(OAUTH_PROVIDER_POLICIES) != set(ConnectorProviderId):
    raise RuntimeError("OAuth policies do not cover every connector provider")


GOOGLE_PROVIDER_SCOPES: Mapping[OAuthScopeId, str] = MappingProxyType(
    {
        OAuthScopeId.GMAIL_MESSAGES_READ: (
            "https://www.googleapis.com/auth/gmail.readonly"
        ),
        OAuthScopeId.GMAIL_DRAFTS_WRITE: (
            "https://www.googleapis.com/auth/gmail.compose"
        ),
        OAuthScopeId.CALENDAR_EVENTS_READ: (
            "https://www.googleapis.com/auth/calendar.events.freebusy"
        ),
        OAuthScopeId.CALENDAR_EVENTS_WRITE: (
            "https://www.googleapis.com/auth/calendar.events"
        ),
        OAuthScopeId.SHEETS_VALUES_READ: (
            "https://www.googleapis.com/auth/spreadsheets.readonly"
        ),
        OAuthScopeId.SHEETS_VALUES_WRITE: (
            "https://www.googleapis.com/auth/drive.file"
        ),
        OAuthScopeId.SLIDES_PRESENTATIONS_READ: (
            "https://www.googleapis.com/auth/presentations.readonly"
        ),
        OAuthScopeId.SLIDES_PRESENTATIONS_WRITE: (
            "https://www.googleapis.com/auth/drive.file"
        ),
    }
)

_GOOGLE_SEMANTIC_SCOPES = frozenset(
    scope
    for connector in PROVIDER_CONNECTORS[ConnectorProviderId.GOOGLE]
    for capability, definition in CAPABILITY_REGISTRY.items()
    if definition.connector is connector
    for scope in (require_oauth_scope(capability),)
)
if set(GOOGLE_PROVIDER_SCOPES) != set(_GOOGLE_SEMANTIC_SCOPES):
    raise RuntimeError(
        "Google provider scopes do not cover every Google capability"
    )


@dataclass(frozen=True, slots=True)
class OAuthClientRegistration:
    """A public desktop client identifier, never a client secret."""

    provider: ConnectorProviderId
    client_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ConnectorProviderId):
            raise TypeError("OAuth client provider is invalid")
        if (
            not isinstance(self.client_id, str)
            or not 10 <= len(self.client_id) <= MAX_CLIENT_ID_CHARS
            or self.client_id.strip() != self.client_id
            or _BOUNDED_ASCII.fullmatch(self.client_id) is None
        ):
            raise ValueError("OAuth client ID is invalid")
        if (
            self.provider is ConnectorProviderId.GOOGLE
            and _GOOGLE_CLIENT_ID.fullmatch(self.client_id) is None
        ):
            raise ValueError("Google desktop OAuth client ID is invalid")


@dataclass(frozen=True, slots=True)
class OAuthConsentSummary:
    """Exact non-secret authority shown before opening the system browser."""

    provider: ConnectorProviderId
    connector: ConnectorId
    capabilities: frozenset[CapabilityId]
    oauth_scopes: frozenset[OAuthScopeId]
    provider_scopes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ConnectorProviderId):
            raise TypeError("OAuth consent provider is invalid")
        if not isinstance(self.connector, ConnectorId):
            raise TypeError("OAuth consent connector is invalid")
        if self.connector not in PROVIDER_CONNECTORS[self.provider]:
            raise ValueError("OAuth provider does not own this connector")
        expected_scopes = _validate_connector_capabilities(
            self.connector,
            self.capabilities,
        )
        if self.oauth_scopes != expected_scopes:
            raise ValueError(
                "OAuth consent scopes do not match connector capabilities"
            )
        expected_provider_scopes = _provider_scopes(
            self.provider,
            expected_scopes,
        )
        if self.provider_scopes != expected_provider_scopes:
            raise ValueError(
                "OAuth provider scopes do not match semantic scopes"
            )


class OAuthAuthorizationCode:
    """Single-use code and verifier returned by the loopback callback."""

    __slots__ = (
        "provider",
        "connector",
        "oauth_scopes",
        "redirect_uri",
        "_code",
        "_code_verifier",
        "_consumed",
        "_lock",
    )

    def __init__(
        self,
        *,
        provider: ConnectorProviderId,
        connector: ConnectorId,
        oauth_scopes: frozenset[OAuthScopeId],
        redirect_uri: str,
        code: SecretValue,
        code_verifier: SecretValue,
    ) -> None:
        if not isinstance(provider, ConnectorProviderId):
            raise TypeError("OAuth code provider is invalid")
        if not isinstance(connector, ConnectorId):
            raise TypeError("OAuth code connector is invalid")
        if connector not in PROVIDER_CONNECTORS[provider]:
            raise ValueError("OAuth code provider does not own connector")
        _provider_scopes(provider, _semantic_scopes(oauth_scopes))
        _loopback_redirect_uri(redirect_uri)
        if not isinstance(code, SecretValue):
            raise TypeError("OAuth authorization code must use SecretValue")
        if not isinstance(code_verifier, SecretValue):
            raise TypeError("OAuth code verifier must use SecretValue")
        self.provider = provider
        self.connector = connector
        self.oauth_scopes = oauth_scopes
        self.redirect_uri = redirect_uri
        self._code = code
        self._code_verifier = code_verifier
        self._consumed = False
        self._lock = threading.Lock()

    def _consume_credentials(self) -> tuple[bytes, bytes]:
        with self._lock:
            if self._consumed:
                raise OAuthCallbackError(
                    "OAuth authorization code was already consumed"
                )
            self._consumed = True
            try:
                return (
                    self._code.reveal(),
                    self._code_verifier.reveal(),
                )
            finally:
                self._code.close()
                self._code_verifier.close()

    def close(self) -> None:
        with self._lock:
            self._consumed = True
            self._code.close()
            self._code_verifier.close()

    @property
    def consumed(self) -> bool:
        return self._consumed

    def __repr__(self) -> str:
        return (
            "OAuthAuthorizationCode("
            f"provider={self.provider!r}, connector={self.connector!r}, "
            f"oauth_scopes={self.oauth_scopes!r}, "
            f"redirect_uri={self.redirect_uri!r}, credentials=<redacted>)"
        )


class OAuthAuthorizationSession:
    """Prepared, system-browser-only, single-callback loopback session."""

    def __init__(
        self,
        *,
        registration: OAuthClientRegistration,
        consent: OAuthConsentSummary,
        server: _LoopbackServer,
        state: SecretValue,
        code_verifier: SecretValue,
        monotonic: Callable[[], float],
    ) -> None:
        self.registration = registration
        self.consent = consent
        self._server = server
        self._state_secret = state
        self._code_verifier = code_verifier
        self._monotonic = monotonic
        self._state = OAuthSessionState.PREPARED
        self._result: OAuthAuthorizationCode | None = None
        self._error: OAuthError | None = None
        self._lock = threading.RLock()
        host, port = server.server_address[:2]
        if host != "127.0.0.1":
            raise RuntimeError("OAuth loopback server bound an unsafe host")
        self._redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"
        server.authorization_session = self

    @property
    def state(self) -> OAuthSessionState:
        return self._state

    @property
    def redirect_uri(self) -> str:
        return self._redirect_uri

    def open_system_browser(
        self,
        opener: Callable[[str], object] = webbrowser.open_new_tab,
    ) -> None:
        if not callable(opener):
            raise TypeError("OAuth browser opener must be callable")
        with self._lock:
            if self._state is not OAuthSessionState.PREPARED:
                raise OAuthBrowserError(
                    "OAuth browser session is not prepared"
                )
            authorization_url = self._authorization_url()
            try:
                opened = opener(authorization_url)
            except Exception:
                self.close()
                raise OAuthBrowserError(
                    "The system browser could not open OAuth authorization"
                ) from None
            finally:
                authorization_url = ""
            if opened is False:
                self.close()
                raise OAuthBrowserError(
                    "The system browser refused OAuth authorization"
                )
            self._state = OAuthSessionState.BROWSER_OPENED

    def wait_for_callback(
        self,
        *,
        timeout_seconds: float = 120.0,
    ) -> OAuthAuthorizationCode:
        timeout = _timeout(timeout_seconds)
        with self._lock:
            if self._state is not OAuthSessionState.BROWSER_OPENED:
                raise OAuthCallbackError(
                    "OAuth callback wait requires an opened system browser"
                )
        deadline = self._monotonic() + timeout
        while self._result is None and self._error is None:
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                self.close()
                raise OAuthAuthorizationTimeoutError(
                    "OAuth authorization callback timed out"
                )
            self._server.timeout = min(0.25, remaining)
            self._server.handle_request()
        result = self._result
        error = self._error
        self._result = None
        self._close_server_and_secrets()
        if error is not None:
            raise error
        if result is None:
            raise OAuthCallbackError(
                "OAuth callback did not produce an authorization code"
            )
        return result

    def consume_callback_target(
        self,
        target: str,
        *,
        host_header: str,
        peer_address: str,
    ) -> OAuthAuthorizationCode:
        """Validate and consume exactly one loopback callback."""

        with self._lock:
            if self._state is not OAuthSessionState.BROWSER_OPENED:
                raise OAuthCallbackError(
                    "OAuth callback is stale or already consumed"
                )
            self._state = OAuthSessionState.CALLBACK_CONSUMED
            try:
                code = self._parse_callback(
                    target,
                    host_header=host_header,
                    peer_address=peer_address,
                )
                result = OAuthAuthorizationCode(
                    provider=self.registration.provider,
                    connector=self.consent.connector,
                    oauth_scopes=self.consent.oauth_scopes,
                    redirect_uri=self._redirect_uri,
                    code=SecretValue(code),
                    code_verifier=self._code_verifier.copy(),
                )
                self._result = result
                return result
            except OAuthError as exc:
                self._error = exc
                raise
            finally:
                self._state_secret.close()
                self._code_verifier.close()

    def close(self) -> None:
        with self._lock:
            if self._state is OAuthSessionState.CLOSED:
                return
            if self._result is not None:
                self._result.close()
            self._close_server_and_secrets()

    def _close_server_and_secrets(self) -> None:
        self._server.server_close()
        self._state_secret.close()
        self._code_verifier.close()
        self._state = OAuthSessionState.CLOSED

    def _authorization_url(self) -> str:
        policy = require_desktop_oauth_policy(
            self.registration.provider
        )
        state = self._state_secret.reveal().decode("ascii")
        verifier = self._code_verifier.reveal()
        challenge = _base64url(hashlib.sha256(verifier).digest())
        query = urllib.parse.urlencode(
            {
                "access_type": "offline",
                "client_id": self.registration.client_id,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "include_granted_scopes": "false",
                "prompt": "consent",
                "redirect_uri": self._redirect_uri,
                "response_type": "code",
                "scope": " ".join(self.consent.provider_scopes),
                "state": state,
            },
            quote_via=urllib.parse.quote,
        )
        return f"{policy.authorization_endpoint}?{query}"

    def _parse_callback(
        self,
        target: str,
        *,
        host_header: str,
        peer_address: str,
    ) -> bytes:
        if (
            not isinstance(target, str)
            or not target
            or len(target) > MAX_CALLBACK_TARGET_CHARS
        ):
            raise OAuthCallbackError("OAuth callback target is invalid")
        expected_host = urllib.parse.urlsplit(
            self._redirect_uri
        ).netloc
        if (
            host_header != expected_host
            or peer_address != "127.0.0.1"
        ):
            raise OAuthCallbackError(
                "OAuth callback did not use the bound loopback listener"
            )
        parsed = urllib.parse.urlsplit(target)
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or parsed.path != CALLBACK_PATH
        ):
            raise OAuthCallbackError("OAuth callback redirect is invalid")
        try:
            pairs = urllib.parse.parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=12,
            )
        except ValueError:
            raise OAuthCallbackError(
                "OAuth callback parameters are invalid"
            ) from None
        parameters: dict[str, str] = {}
        allowed = {
            "authuser",
            "code",
            "error",
            "error_description",
            "error_uri",
            "hd",
            "prompt",
            "scope",
            "state",
        }
        for key, value in pairs:
            if key not in allowed or key in parameters:
                raise OAuthCallbackError(
                    "OAuth callback parameters are invalid"
                )
            if len(value) > MAX_CALLBACK_TARGET_CHARS:
                raise OAuthCallbackError(
                    "OAuth callback parameter exceeds its limit"
                )
            parameters[key] = value
        received_state = _callback_ascii(
            parameters.get("state", ""),
            "OAuth callback state",
        )
        expected_state = self._state_secret.reveal()
        if not hmac.compare_digest(received_state, expected_state):
            raise OAuthCallbackError("OAuth callback state did not match")
        if "error" in parameters:
            if parameters["error"] == "access_denied":
                raise OAuthAuthorizationDeniedError(
                    "OAuth authorization was denied"
                )
            raise OAuthCallbackError(
                "OAuth provider returned an authorization error"
            )
        code = _callback_ascii(
            parameters.get("code", ""),
            "OAuth authorization code",
        )
        if (
            not code
            or len(code) > MAX_AUTHORIZATION_CODE_BYTES
            or any(value < 0x21 or value > 0x7E for value in code)
        ):
            raise OAuthCallbackError(
                "OAuth authorization code is invalid"
            )
        return code

    def __repr__(self) -> str:
        return (
            "OAuthAuthorizationSession("
            f"registration={self.registration!r}, consent={self.consent!r}, "
            f"redirect_uri={self._redirect_uri!r}, "
            f"state={self._state!r}, secrets=<redacted>)"
        )


class _LoopbackServer(HTTPServer):
    allow_reuse_address = False
    authorization_session: OAuthAuthorizationSession


class _CallbackHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        session = self.server.authorization_session
        try:
            session.consume_callback_target(
                self.path,
                host_header=self.headers.get("Host", ""),
                peer_address=self.client_address[0],
            )
            self._reply(
                200,
                b"Authorization received. Return to Clicky.",
            )
        except OAuthError:
            self._reply(
                400,
                b"Authorization failed. Return to Clicky.",
            )

    def do_POST(self) -> None:
        self._reject_method()

    def do_PUT(self) -> None:
        self._reject_method()

    def do_DELETE(self) -> None:
        self._reject_method()

    def _reject_method(self) -> None:
        session = self.server.authorization_session
        try:
            session.consume_callback_target(
                "/invalid-method",
                host_header=self.headers.get("Host", ""),
                peer_address=self.client_address[0],
            )
        except OAuthError:
            pass
        self._reply(405, b"OAuth callback requires GET.")

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def prepare_authorization(
    registration: OAuthClientRegistration,
    connector: ConnectorId,
    capabilities: frozenset[CapabilityId],
    *,
    _server_factory: Callable[
        [tuple[str, int], type[BaseHTTPRequestHandler]], _LoopbackServer
    ] = _LoopbackServer,
    _random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    _monotonic: Callable[[], float] = time.monotonic,
) -> OAuthAuthorizationSession:
    """Bind loopback first and return exact consent before browser launch."""

    if not isinstance(registration, OAuthClientRegistration):
        raise TypeError("OAuth client registration is invalid")
    policy = require_desktop_oauth_policy(registration.provider)
    if connector not in PROVIDER_CONNECTORS[registration.provider]:
        raise ValueError("OAuth provider does not own this connector")
    oauth_scopes = _validate_connector_capabilities(
        connector,
        capabilities,
    )
    consent = OAuthConsentSummary(
        provider=registration.provider,
        connector=connector,
        capabilities=capabilities,
        oauth_scopes=oauth_scopes,
        provider_scopes=_provider_scopes(
            registration.provider,
            oauth_scopes,
        ),
    )
    if not callable(_server_factory):
        raise TypeError("OAuth loopback server factory must be callable")
    if not callable(_random_bytes) or not callable(_monotonic):
        raise TypeError("OAuth entropy and clock sources must be callable")
    state = SecretValue(_base64url_bytes(_random_bytes(32)))
    verifier = SecretValue(_base64url_bytes(_random_bytes(64)))
    if not 43 <= len(verifier.reveal()) <= 128:
        state.close()
        verifier.close()
        raise OAuthError("OAuth PKCE verifier generation failed")
    try:
        server = _server_factory(
            ("127.0.0.1", 0),
            _CallbackHandler,
        )
    except Exception as exc:
        state.close()
        verifier.close()
        raise OAuthError(
            "OAuth loopback listener could not start"
        ) from exc
    try:
        return OAuthAuthorizationSession(
            registration=registration,
            consent=consent,
            server=server,
            state=state,
            code_verifier=verifier,
            monotonic=_monotonic,
        )
    except Exception:
        server.server_close()
        state.close()
        verifier.close()
        raise


@dataclass(frozen=True, slots=True)
class OAuthHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("OAuth HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("OAuth response content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_OAUTH_RESPONSE_BYTES
        ):
            raise ValueError("OAuth response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("OAuth retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError("OAuth provider request ID is invalid")


class OAuthHttpTransport(Protocol):
    def post_form(
        self,
        *,
        provider: ConnectorProviderId,
        endpoint: str,
        fields: Mapping[str, str],
    ) -> OAuthHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedOAuthHttpsTransport:
    """Bounded HTTPS POST transport with no proxies or redirects."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 15.0,
        _opener=None,
    ) -> None:
        self._timeout = _timeout(
            timeout_seconds,
            maximum=30.0,
        )
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(
                context=ssl.create_default_context()
            ),
        )

    def post_form(
        self,
        *,
        provider: ConnectorProviderId,
        endpoint: str,
        fields: Mapping[str, str],
    ) -> OAuthHttpResponse:
        policy = require_desktop_oauth_policy(provider)
        if endpoint not in {
            policy.token_endpoint,
            policy.revocation_endpoint,
        }:
            raise ConnectorRequestError(
                "OAuth request endpoint is not fixed by policy"
            )
        if (
            not isinstance(fields, Mapping)
            or not fields
            or len(fields) > 12
            or any(
                not isinstance(key, str)
                or not key
                or len(key) > 64
                or not isinstance(value, str)
                or not value
                or len(value) > 16 * 1024
                for key, value in fields.items()
            )
        ):
            raise ConnectorRequestError("OAuth request fields are invalid")
        encoded = urllib.parse.urlencode(
            fields,
            quote_via=urllib.parse.quote,
        ).encode("ascii")
        request = urllib.request.Request(
            endpoint,
            data=encoded,
            method="POST",
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Clicky-Windows-OAuth/1",
            },
        )
        try:
            try:
                response = self._opener.open(
                    request,
                    timeout=self._timeout,
                )
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                return _bounded_http_response(response)
        except ConnectorResponseError:
            raise
        except (OSError, urllib.error.URLError) as exc:
            raise ConnectorRequestError(
                "OAuth provider request failed"
            ) from exc


class OAuthTokenClient:
    """Exchange, refresh, and revoke only through fixed provider policy."""

    def __init__(
        self,
        transport: OAuthHttpTransport | None = None,
        *,
        _clock: Callable[[], float] = time.time,
    ) -> None:
        candidate = transport or FixedOAuthHttpsTransport()
        if not callable(getattr(candidate, "post_form", None)):
            raise TypeError("OAuth token client requires an HTTP transport")
        if not callable(_clock):
            raise TypeError("OAuth token client clock must be callable")
        self._transport = candidate
        self._clock = _clock

    def exchange(
        self,
        registration: OAuthClientRegistration,
        authorization: OAuthAuthorizationCode,
    ) -> OAuthTokenSet:
        self._validate_registration_authorization(
            registration,
            authorization,
        )
        code_bytes, verifier_bytes = authorization._consume_credentials()
        try:
            fields = {
                "client_id": registration.client_id,
                "code": code_bytes.decode("ascii"),
                "code_verifier": verifier_bytes.decode("ascii"),
                "grant_type": "authorization_code",
                "redirect_uri": authorization.redirect_uri,
            }
            response = self._post_token(registration.provider, fields)
            return self._parse_token_response(
                response,
                authorization.oauth_scopes,
                require_refresh_token=True,
            )
        finally:
            code_bytes = b""
            verifier_bytes = b""
            if "fields" in locals():
                fields.clear()

    def refresh(
        self,
        registration: OAuthClientRegistration,
        oauth_scopes: frozenset[OAuthScopeId],
        refresh_token: SecretValue,
    ) -> OAuthTokenSet:
        if not isinstance(registration, OAuthClientRegistration):
            raise TypeError("OAuth client registration is invalid")
        policy = require_desktop_oauth_policy(registration.provider)
        if policy.provider is not ConnectorProviderId.GOOGLE:
            raise OAuthProviderUnavailableError(
                "OAuth refresh provider is unavailable"
            )
        checked_scopes = _semantic_scopes(oauth_scopes)
        _provider_scopes(registration.provider, checked_scopes)
        if not isinstance(refresh_token, SecretValue):
            raise TypeError("OAuth refresh token must use SecretValue")
        token_bytes = refresh_token.reveal()
        try:
            fields = {
                "client_id": registration.client_id,
                "grant_type": "refresh_token",
                "refresh_token": token_bytes.decode("ascii"),
            }
            response = self._post_token(registration.provider, fields)
            return self._parse_token_response(
                response,
                checked_scopes,
                require_refresh_token=False,
            )
        finally:
            token_bytes = b""
            if "fields" in locals():
                fields.clear()

    def revoke(
        self,
        registration: OAuthClientRegistration,
        request: ConnectorRevocationRequest,
        refresh_token: SecretValue,
    ) -> ConnectorRevocationResult:
        if not isinstance(registration, OAuthClientRegistration):
            raise TypeError("OAuth client registration is invalid")
        policy = require_desktop_oauth_policy(registration.provider)
        if not isinstance(request, ConnectorRevocationRequest):
            raise TypeError("OAuth revocation request is invalid")
        if (
            request.provider is not registration.provider
            or request.connector
            not in PROVIDER_CONNECTORS[registration.provider]
        ):
            raise ConnectorAuthorizationError(
                "OAuth revocation authority does not match registration"
            )
        if policy.revocation_endpoint is None:
            return ConnectorRevocationResult(
                authorization_id=request.authorization_id,
                status=RevocationStatus.UNSUPPORTED,
                provider_request_id=None,
                completed_at=_timestamp(self._clock()),
            )
        if not isinstance(refresh_token, SecretValue):
            raise TypeError("OAuth revocation token must use SecretValue")
        token_bytes = refresh_token.reveal()
        try:
            fields = {"token": token_bytes.decode("ascii")}
            response = self._transport.post_form(
                provider=registration.provider,
                endpoint=policy.revocation_endpoint,
                fields=fields,
            )
        finally:
            token_bytes = b""
            if "fields" in locals():
                fields.clear()
        if response.status == 200:
            status = RevocationStatus.REVOKED
        elif response.status == 400:
            error = _error_code(response)
            if error not in {"invalid_token", "invalid_grant"}:
                raise ConnectorResponseError(
                    "OAuth provider rejected token revocation"
                )
            status = RevocationStatus.ALREADY_INVALID
        elif response.status == 429:
            raise ConnectorRateLimitError(
                response.retry_after_seconds or 0
            )
        else:
            raise ConnectorResponseError(
                "OAuth provider token revocation failed"
            )
        return ConnectorRevocationResult(
            authorization_id=request.authorization_id,
            status=status,
            provider_request_id=response.provider_request_id,
            completed_at=_timestamp(self._clock()),
        )

    def _post_token(
        self,
        provider: ConnectorProviderId,
        fields: Mapping[str, str],
    ) -> OAuthHttpResponse:
        policy = require_desktop_oauth_policy(provider)
        response = self._transport.post_form(
            provider=provider,
            endpoint=policy.token_endpoint,
            fields=fields,
        )
        if response.status == 429:
            raise ConnectorRateLimitError(
                response.retry_after_seconds or 0
            )
        if not 200 <= response.status <= 299:
            error = _error_code(response)
            if error == "invalid_grant":
                raise ConnectorInvalidGrantError(
                    "OAuth authorization is expired, revoked, or invalid"
                )
            if error in {"invalid_token", "unauthorized_client"}:
                raise ConnectorTokenRevokedError(
                    "OAuth credential is revoked or unauthorized"
                )
            raise ConnectorResponseError(
                "OAuth token endpoint rejected the request"
            )
        return response

    def _parse_token_response(
        self,
        response: OAuthHttpResponse,
        oauth_scopes: frozenset[OAuthScopeId],
        *,
        require_refresh_token: bool,
    ) -> OAuthTokenSet:
        payload = _json_response(response)
        access_token = _secret_ascii(
            payload.get("access_token"),
            "OAuth access token",
        )
        refresh_token: SecretValue | None = None
        try:
            refresh_value = payload.get("refresh_token")
            if require_refresh_token and refresh_value is None:
                raise ConnectorResponseError(
                    "OAuth provider did not return an offline refresh token"
                )
            refresh_token = (
                _secret_ascii(refresh_value, "OAuth refresh token")
                if refresh_value is not None
                else None
            )
            if payload.get("token_type") != OAuthTokenType.BEARER.value:
                raise ConnectorResponseError(
                    "OAuth provider returned an unsupported token type"
                )
            expires_in = payload.get("expires_in")
            if (
                type(expires_in) is not int
                or not 1 <= expires_in <= MAX_TOKEN_LIFETIME_SECONDS
            ):
                raise ConnectorResponseError(
                    "OAuth provider returned an invalid token lifetime"
                )
            expected_provider_scopes = set(
                _provider_scopes(
                    ConnectorProviderId.GOOGLE,
                    oauth_scopes,
                )
            )
            scope_value = payload.get("scope")
            if not isinstance(scope_value, str):
                raise ConnectorResponseError(
                    "OAuth provider omitted granted scopes"
                )
            granted = set(scope_value.split())
            if (
                not granted
                or len(granted) > MAX_PROVIDER_SCOPES
                or granted != expected_provider_scopes
            ):
                raise ConnectorAuthorizationError(
                    "OAuth provider granted unexpected scopes"
                )
            issued_at = _timestamp(self._clock())
            return OAuthTokenSet(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type=OAuthTokenType.BEARER,
                oauth_scopes=oauth_scopes,
                issued_at=issued_at,
                access_expires_at=issued_at + expires_in,
            )
        except Exception:
            access_token.close()
            if refresh_token is not None:
                refresh_token.close()
            raise

    @staticmethod
    def _validate_registration_authorization(
        registration: OAuthClientRegistration,
        authorization: OAuthAuthorizationCode,
    ) -> None:
        if not isinstance(registration, OAuthClientRegistration):
            raise TypeError("OAuth client registration is invalid")
        require_desktop_oauth_policy(registration.provider)
        if not isinstance(authorization, OAuthAuthorizationCode):
            raise TypeError("OAuth authorization code is invalid")
        if authorization.provider is not registration.provider:
            raise ConnectorAuthorizationError(
                "OAuth code provider does not match registration"
            )


def require_desktop_oauth_policy(
    provider: ConnectorProviderId,
) -> OAuthProviderPolicy:
    if not isinstance(provider, ConnectorProviderId):
        raise TypeError("OAuth provider is invalid")
    policy = OAUTH_PROVIDER_POLICIES[provider]
    if policy.availability is not OAuthDesktopAvailability.READY:
        raise OAuthProviderUnavailableError(
            "OAuth provider requires a reviewed confidential broker"
        )
    return policy


def _validate_connector_capabilities(
    connector: ConnectorId,
    capabilities: object,
) -> frozenset[OAuthScopeId]:
    if (
        not isinstance(capabilities, frozenset)
        or not capabilities
        or len(capabilities) > MAX_PROVIDER_SCOPES
        or any(
            not isinstance(capability, CapabilityId)
            for capability in capabilities
        )
    ):
        raise TypeError(
            "OAuth consent requires a bounded capability frozenset"
        )
    scopes: set[OAuthScopeId] = set()
    for capability in capabilities:
        definition = CAPABILITY_REGISTRY[capability]
        if definition.connector is not connector:
            raise ValueError(
                "OAuth consent contains another connector capability"
            )
        scopes.add(require_oauth_scope(capability))
    return frozenset(scopes)


def _provider_scopes(
    provider: ConnectorProviderId,
    oauth_scopes: frozenset[OAuthScopeId],
) -> tuple[str, ...]:
    checked = _semantic_scopes(oauth_scopes)
    if provider is not ConnectorProviderId.GOOGLE:
        raise OAuthProviderUnavailableError(
            "OAuth provider scopes require a confidential broker"
        )
    try:
        values = tuple(
            sorted({GOOGLE_PROVIDER_SCOPES[scope] for scope in checked})
        )
    except KeyError:
        raise ConnectorAuthorizationError(
            "OAuth semantic scope belongs to another provider"
        ) from None
    if (
        not values
        or len(values) > MAX_PROVIDER_SCOPES
        or any(
            len(value) > MAX_PROVIDER_SCOPE_CHARS
            or _PROVIDER_SCOPE.fullmatch(value) is None
            for value in values
        )
    ):
        raise RuntimeError("OAuth provider scope policy is invalid")
    return values


def _semantic_scopes(value: object) -> frozenset[OAuthScopeId]:
    if (
        not isinstance(value, frozenset)
        or not value
        or len(value) > MAX_PROVIDER_SCOPES
        or any(not isinstance(scope, OAuthScopeId) for scope in value)
    ):
        raise TypeError("OAuth semantic scopes are invalid")
    return value


def _bounded_http_response(response) -> OAuthHttpResponse:
    try:
        status = int(response.status)
        content_length = response.headers.get("Content-Length")
        if content_length is not None and (
            not content_length.isascii()
            or not content_length.isdigit()
            or int(content_length) > MAX_OAUTH_RESPONSE_BYTES
        ):
            raise ConnectorResponseError(
                "OAuth provider response exceeds its limit"
            )
        body = response.read(MAX_OAUTH_RESPONSE_BYTES + 1)
        if len(body) > MAX_OAUTH_RESPONSE_BYTES:
            raise ConnectorResponseError(
                "OAuth provider response exceeds its limit"
            )
        content_type = response.headers.get(
            "Content-Type",
            "",
        ).split(";", 1)[0].strip().lower()
        retry_after = response.headers.get("Retry-After")
        retry_seconds = (
            int(retry_after)
            if retry_after is not None
            and retry_after.isascii()
            and retry_after.isdigit()
            and int(retry_after) <= 24 * 60 * 60
            else None
        )
        request_id = response.headers.get("X-Request-Id")
        return OAuthHttpResponse(
            status=status,
            content_type=content_type,
            body=body,
            retry_after_seconds=retry_seconds,
            provider_request_id=request_id,
        )
    except ConnectorResponseError:
        raise
    except Exception as exc:
        raise ConnectorResponseError(
            "OAuth provider returned invalid HTTP metadata"
        ) from exc


def _json_response(response: OAuthHttpResponse) -> dict[str, object]:
    if response.content_type != "application/json" or not response.body:
        raise ConnectorResponseError(
            "OAuth provider returned a non-JSON response"
        )
    try:
        payload = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except ConnectorResponseError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise ConnectorResponseError(
            "OAuth provider returned malformed JSON"
        ) from None
    if not isinstance(payload, dict) or len(payload) > 32:
        raise ConnectorResponseError(
            "OAuth provider returned invalid token metadata"
        )
    return payload


def _error_code(response: OAuthHttpResponse) -> str | None:
    try:
        payload = _json_response(response)
    except ConnectorResponseError:
        return None
    error = payload.get("error")
    return (
        error
        if isinstance(error, str)
        and 1 <= len(error) <= 128
        and error.isascii()
        else None
    )


def _unique_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConnectorResponseError(
                "OAuth provider JSON contains duplicate fields"
            )
        result[key] = value
    return result


def _secret_ascii(value: object, label: str) -> SecretValue:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 16 * 1024
        or _BOUNDED_ASCII.fullmatch(value) is None
    ):
        raise ConnectorResponseError(f"{label} is invalid")
    return SecretValue(value.encode("ascii"))


def _callback_ascii(value: str, label: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError:
        raise OAuthCallbackError(f"{label} is invalid") from None


def _loopback_redirect_uri(value: object) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("OAuth loopback redirect URI is invalid")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("OAuth loopback redirect URI is invalid") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port is None
        or not 1 <= port <= 65535
        or parsed.path != CALLBACK_PATH
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("OAuth loopback redirect URI is invalid")
    return value


def _base64url(value: bytes) -> str:
    return _base64url_bytes(value).decode("ascii")


def _base64url_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise OAuthError("OAuth entropy source returned invalid bytes")
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _timeout(
    value: object,
    *,
    maximum: float = MAX_AUTHORIZATION_TIMEOUT_SECONDS,
) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.01 <= float(value) <= maximum
    ):
        raise ValueError("OAuth timeout is invalid")
    return float(value)


def _timestamp(value: object) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or value < 0
    ):
        raise ValueError("OAuth timestamp is invalid")
    return float(value)


__all__ = [
    "CALLBACK_PATH",
    "FixedOAuthHttpsTransport",
    "GOOGLE_PROVIDER_SCOPES",
    "OAUTH_PROVIDER_POLICIES",
    "OAuthAuthorizationCode",
    "OAuthAuthorizationDeniedError",
    "OAuthAuthorizationSession",
    "OAuthAuthorizationTimeoutError",
    "OAuthBrowserError",
    "OAuthCallbackError",
    "OAuthClientRegistration",
    "OAuthConsentSummary",
    "OAuthDesktopAvailability",
    "OAuthError",
    "OAuthHttpResponse",
    "OAuthHttpTransport",
    "OAuthProviderPolicy",
    "OAuthProviderUnavailableError",
    "OAuthSessionState",
    "OAuthTokenClient",
    "prepare_authorization",
    "require_desktop_oauth_policy",
]
