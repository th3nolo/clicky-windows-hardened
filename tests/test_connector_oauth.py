"""System-browser OAuth, loopback callback, and token lifecycle tests."""

from __future__ import annotations

import ast
import http.client
import json
import threading
import unittest
import urllib.parse
from pathlib import Path

from capability_registry import CapabilityId, ConnectorId, OAuthScopeId
from connectors.base import (
    ConnectorAuthorizationError,
    ConnectorInvalidGrantError,
    ConnectorProviderId,
    ConnectorRateLimitError,
    ConnectorResponseError,
    ConnectorRevocationRequest,
    ConnectorTokenRevokedError,
    RevocationStatus,
    SecretValue,
)
from connectors.oauth import (
    CALLBACK_PATH,
    GOOGLE_PROVIDER_SCOPES,
    OAUTH_PROVIDER_POLICIES,
    FixedOAuthHttpsTransport,
    OAuthAuthorizationCode,
    OAuthAuthorizationDeniedError,
    OAuthAuthorizationTimeoutError,
    OAuthBrowserError,
    OAuthCallbackError,
    OAuthClientRegistration,
    OAuthDesktopAvailability,
    OAuthError,
    OAuthHttpResponse,
    OAuthProviderUnavailableError,
    OAuthSessionState,
    OAuthTokenClient,
    prepare_authorization,
    require_desktop_oauth_policy,
)


_CLIENT_ID = (
    "123456789012-abcdefghijklmnopqrstuvwxyz"
    ".apps.googleusercontent.com"
)
_CAPABILITIES = frozenset(
    {
        CapabilityId.GMAIL_MESSAGE_READ,
        CapabilityId.GMAIL_DRAFT_WRITE,
    }
)
_SEMANTIC_SCOPES = frozenset(
    {
        OAuthScopeId.GMAIL_MESSAGES_READ,
        OAuthScopeId.GMAIL_DRAFTS_WRITE,
    }
)


class _FakeServer:
    def __init__(self, *_args) -> None:
        self.server_address = ("127.0.0.1", 43123)
        self.authorization_session = None
        self.timeout = None
        self.closed = False

    def handle_request(self) -> None:
        return

    def server_close(self) -> None:
        self.closed = True


def _fake_server_factory(*args):
    return _FakeServer(*args)


def _registration() -> OAuthClientRegistration:
    return OAuthClientRegistration(
        provider=ConnectorProviderId.GOOGLE,
        client_id=_CLIENT_ID,
    )


def _open_session():
    session = prepare_authorization(
        _registration(),
        ConnectorId.GMAIL,
        _CAPABILITIES,
        _server_factory=_fake_server_factory,
    )
    opened: list[str] = []
    session.open_system_browser(
        lambda url: opened.append(url) or True
    )
    query = urllib.parse.parse_qs(
        urllib.parse.urlsplit(opened[0]).query,
        strict_parsing=True,
    )
    return session, opened[0], query["state"][0]


def _authorization_code() -> OAuthAuthorizationCode:
    return OAuthAuthorizationCode(
        provider=ConnectorProviderId.GOOGLE,
        connector=ConnectorId.GMAIL,
        oauth_scopes=_SEMANTIC_SCOPES,
        redirect_uri=f"http://127.0.0.1:43123{CALLBACK_PATH}",
        code=SecretValue(b"authorization-code-unique"),
        code_verifier=SecretValue(b"v" * 64),
    )


def _token_body(
    *,
    access: str = "access-token-unique",
    refresh: str | None = "refresh-token-unique",
    scopes: set[str] | None = None,
) -> bytes:
    payload: dict[str, object] = {
        "access_token": access,
        "expires_in": 3600,
        "scope": " ".join(
            sorted(
                scopes
                if scopes is not None
                else {
                    GOOGLE_PROVIDER_SCOPES[scope]
                    for scope in _SEMANTIC_SCOPES
                }
            )
        ),
        "token_type": "Bearer",
    }
    if refresh is not None:
        payload["refresh_token"] = refresh
    return json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class _FakeTransport:
    def __init__(self, *responses: OAuthHttpResponse) -> None:
        self.responses = list(responses)
        self.calls: list[
            tuple[ConnectorProviderId, str, dict[str, str]]
        ] = []

    def post_form(self, *, provider, endpoint, fields):
        self.calls.append((provider, endpoint, dict(fields)))
        if not self.responses:
            raise AssertionError("unexpected OAuth request")
        return self.responses.pop(0)


class OAuthPolicyTests(unittest.TestCase):
    def test_provider_endpoints_are_fixed_and_notion_stays_broker_gated(self):
        self.assertEqual(
            set(OAUTH_PROVIDER_POLICIES),
            set(ConnectorProviderId),
        )
        google = OAUTH_PROVIDER_POLICIES[ConnectorProviderId.GOOGLE]
        self.assertEqual(
            google.authorization_endpoint,
            "https://accounts.google.com/o/oauth2/v2/auth",
        )
        self.assertEqual(
            google.token_endpoint,
            "https://oauth2.googleapis.com/token",
        )
        self.assertEqual(
            google.revocation_endpoint,
            "https://oauth2.googleapis.com/revoke",
        )
        self.assertTrue(google.pkce_required)
        self.assertTrue(google.loopback_redirect_supported)

        notion = OAUTH_PROVIDER_POLICIES[ConnectorProviderId.NOTION]
        self.assertEqual(
            notion.availability,
            OAuthDesktopAvailability.CONFIDENTIAL_BROKER_REQUIRED,
        )
        with self.assertRaisesRegex(
            OAuthProviderUnavailableError,
            "confidential broker",
        ):
            require_desktop_oauth_policy(ConnectorProviderId.NOTION)

    def test_notion_fails_before_binding_or_opening_any_listener(self):
        registration = OAuthClientRegistration(
            provider=ConnectorProviderId.NOTION,
            client_id="notion-client-id",
        )
        called = False

        def server_factory(*_args):
            nonlocal called
            called = True
            raise AssertionError

        with self.assertRaises(OAuthProviderUnavailableError):
            prepare_authorization(
                registration,
                ConnectorId.NOTION,
                frozenset({CapabilityId.NOTION_PAGE_READ}),
                _server_factory=server_factory,
            )
        self.assertFalse(called)

    def test_google_scope_mapping_uses_narrow_reviewed_provider_scopes(self):
        self.assertEqual(
            GOOGLE_PROVIDER_SCOPES[
                OAuthScopeId.DRIVE_SELECTED_FILE_READ
            ],
            "https://www.googleapis.com/auth/drive.file",
        )
        self.assertEqual(
            GOOGLE_PROVIDER_SCOPES[
                OAuthScopeId.CALENDAR_EVENTS_READ
            ],
            "https://www.googleapis.com/auth/calendar.events.freebusy",
        )
        self.assertEqual(
            GOOGLE_PROVIDER_SCOPES[
                OAuthScopeId.SHEETS_VALUES_WRITE
            ],
            "https://www.googleapis.com/auth/drive.file",
        )
        self.assertEqual(
            GOOGLE_PROVIDER_SCOPES[
                OAuthScopeId.SLIDES_PRESENTATIONS_WRITE
            ],
            "https://www.googleapis.com/auth/drive.file",
        )
        values = set(GOOGLE_PROVIDER_SCOPES.values())
        self.assertNotIn("https://mail.google.com/", values)
        self.assertNotIn(
            "https://www.googleapis.com/auth/gmail.send",
            values,
        )


class OAuthAuthorizationSessionTests(unittest.TestCase):
    def test_consent_is_exact_before_system_browser_and_url_uses_pkce(self):
        session = prepare_authorization(
            _registration(),
            ConnectorId.GMAIL,
            _CAPABILITIES,
            _server_factory=_fake_server_factory,
            _random_bytes=lambda size: b"x" * size,
        )
        self.assertEqual(session.state, OAuthSessionState.PREPARED)
        self.assertEqual(session.consent.capabilities, _CAPABILITIES)
        self.assertEqual(
            session.consent.oauth_scopes,
            _SEMANTIC_SCOPES,
        )
        self.assertTrue(
            session.redirect_uri.startswith(
                f"http://127.0.0.1:"
            )
        )
        opened: list[str] = []
        session.open_system_browser(
            lambda url: opened.append(url) or True
        )
        parsed = urllib.parse.urlsplit(opened[0])
        query = urllib.parse.parse_qs(
            parsed.query,
            strict_parsing=True,
        )
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            OAUTH_PROVIDER_POLICIES[
                ConnectorProviderId.GOOGLE
            ].authorization_endpoint,
        )
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["access_type"], ["offline"])
        self.assertEqual(query["include_granted_scopes"], ["false"])
        self.assertEqual(query["prompt"], ["consent"])
        self.assertEqual(query["redirect_uri"], [session.redirect_uri])
        self.assertEqual(
            set(query["scope"][0].split()),
            set(session.consent.provider_scopes),
        )
        self.assertNotIn(query["state"][0], repr(session))
        self.assertNotIn(query["code_challenge"][0], repr(session))
        session.close()

    def test_callback_is_state_bound_single_use_and_content_redacted(self):
        session, _url, state = _open_session()
        host = urllib.parse.urlsplit(session.redirect_uri).netloc
        result = session.consume_callback_target(
            f"{CALLBACK_PATH}?code=code-secret-1&state={state}",
            host_header=host,
            peer_address="127.0.0.1",
        )
        self.assertNotIn("code-secret-1", repr(result))
        self.assertEqual(session.state, OAuthSessionState.CALLBACK_CONSUMED)
        with self.assertRaisesRegex(OAuthCallbackError, "stale|consumed"):
            session.consume_callback_target(
                f"{CALLBACK_PATH}?code=code-secret-2&state={state}",
                host_header=host,
                peer_address="127.0.0.1",
            )
        session.close()
        self.assertTrue(result.consumed)

    def test_mismatch_denial_duplicates_and_non_ascii_fail_closed(self):
        cases = (
            ("code=ok&state=wrong", OAuthCallbackError),
            (
                "error=access_denied&state={state}",
                OAuthAuthorizationDeniedError,
            ),
            ("code=one&code=two&state={state}", OAuthCallbackError),
            ("code=%C3%A9&state={state}", OAuthCallbackError),
        )
        for query_template, error_type in cases:
            session, _url, state = _open_session()
            host = urllib.parse.urlsplit(session.redirect_uri).netloc
            query = query_template.format(state=state)
            with self.subTest(query=query), self.assertRaises(error_type):
                session.consume_callback_target(
                    f"{CALLBACK_PATH}?{query}",
                    host_header=host,
                    peer_address="127.0.0.1",
                )
            with self.assertRaises(OAuthCallbackError):
                session.consume_callback_target(
                    f"{CALLBACK_PATH}?code=late&state={state}",
                    host_header=host,
                    peer_address="127.0.0.1",
                )
            session.close()

    def test_wrong_path_host_or_peer_consumes_the_session(self):
        changes = (
            ("/wrong", None, "127.0.0.1"),
            (CALLBACK_PATH, "localhost:1", "127.0.0.1"),
            (CALLBACK_PATH, None, "127.0.0.2"),
        )
        for path, host_override, peer in changes:
            session, _url, state = _open_session()
            host = (
                host_override
                or urllib.parse.urlsplit(session.redirect_uri).netloc
            )
            with self.subTest(path=path, host=host, peer=peer), self.assertRaises(
                OAuthCallbackError
            ):
                session.consume_callback_target(
                    f"{path}?code=code&state={state}",
                    host_header=host,
                    peer_address=peer,
                )
            session.close()

    def test_actual_bound_loopback_callback_returns_static_safe_page(self):
        try:
            session = prepare_authorization(
                _registration(),
                ConnectorId.GMAIL,
                _CAPABILITIES,
            )
        except OAuthError as exc:
            if isinstance(exc.__cause__, PermissionError):
                self.skipTest("Loopback sockets unavailable in this sandbox")
            raise
        opened: list[str] = []
        session.open_system_browser(
            lambda url: opened.append(url) or True
        )
        state = urllib.parse.parse_qs(
            urllib.parse.urlsplit(opened[0]).query
        )["state"][0]
        parsed = urllib.parse.urlsplit(session.redirect_uri)
        observed: list[tuple[int, bytes]] = []

        def callback():
            connection = http.client.HTTPConnection(
                "127.0.0.1",
                parsed.port,
                timeout=2,
            )
            connection.request(
                "GET",
                f"{CALLBACK_PATH}?code=loopback-code&state={state}",
                headers={"Host": parsed.netloc},
            )
            response = connection.getresponse()
            observed.append((response.status, response.read()))
            connection.close()

        thread = threading.Thread(target=callback)
        thread.start()
        result = session.wait_for_callback(timeout_seconds=2)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            observed,
            [(200, b"Authorization received. Return to Clicky.")],
        )
        self.assertNotIn(b"loopback-code", observed[0][1])
        self.assertNotIn(state.encode(), observed[0][1])
        self.assertFalse(result.consumed)
        result.close()

    def test_browser_failure_and_timeout_close_all_session_authority(self):
        session = prepare_authorization(
            _registration(),
            ConnectorId.GMAIL,
            _CAPABILITIES,
            _server_factory=_fake_server_factory,
        )
        with self.assertRaises(OAuthBrowserError):
            session.open_system_browser(lambda _url: False)
        self.assertEqual(session.state, OAuthSessionState.CLOSED)

        session = prepare_authorization(
            _registration(),
            ConnectorId.GMAIL,
            _CAPABILITIES,
            _server_factory=_fake_server_factory,
        )

        def leaking_opener(url):
            raise RuntimeError(url)

        with self.assertRaises(OAuthBrowserError) as caught:
            session.open_system_browser(leaking_opener)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("state=", str(caught.exception))
        self.assertEqual(session.state, OAuthSessionState.CLOSED)

        session = prepare_authorization(
            _registration(),
            ConnectorId.GMAIL,
            _CAPABILITIES,
            _server_factory=_fake_server_factory,
        )
        session.open_system_browser(lambda _url: True)
        with self.assertRaises(OAuthAuthorizationTimeoutError):
            session.wait_for_callback(timeout_seconds=0.02)
        self.assertEqual(session.state, OAuthSessionState.CLOSED)

    def test_cross_connector_capability_fails_before_browser(self):
        with self.assertRaisesRegex(ValueError, "another connector"):
            prepare_authorization(
                _registration(),
                ConnectorId.GMAIL,
                frozenset({CapabilityId.CALENDAR_EVENT_READ}),
            )


class OAuthTokenClientTests(unittest.TestCase):
    def _response(
        self,
        *,
        status: int = 200,
        body: bytes | None = None,
        retry_after: int | None = None,
    ) -> OAuthHttpResponse:
        return OAuthHttpResponse(
            status=status,
            content_type="application/json",
            body=body if body is not None else _token_body(),
            retry_after_seconds=retry_after,
            provider_request_id="request-1",
        )

    def test_exchange_is_single_use_pkce_bound_and_returns_redacted_tokens(self):
        transport = _FakeTransport(self._response())
        client = OAuthTokenClient(transport, _clock=lambda: 100.0)
        authorization = _authorization_code()
        tokens = client.exchange(_registration(), authorization)

        self.assertTrue(authorization.consumed)
        self.assertEqual(tokens.issued_at, 100.0)
        self.assertEqual(tokens.access_expires_at, 3700.0)
        self.assertEqual(tokens.oauth_scopes, _SEMANTIC_SCOPES)
        self.assertEqual(tokens.access_token.reveal(), b"access-token-unique")
        self.assertEqual(
            tokens.refresh_token.reveal(),
            b"refresh-token-unique",
        )
        self.assertNotIn("access-token-unique", repr(tokens))
        self.assertNotIn("refresh-token-unique", repr(tokens))
        provider, endpoint, fields = transport.calls[0]
        self.assertEqual(provider, ConnectorProviderId.GOOGLE)
        self.assertEqual(
            endpoint,
            "https://oauth2.googleapis.com/token",
        )
        self.assertEqual(fields["grant_type"], "authorization_code")
        self.assertEqual(fields["code"], "authorization-code-unique")
        self.assertEqual(fields["code_verifier"], "v" * 64)
        with self.assertRaises(OAuthCallbackError):
            client.exchange(_registration(), authorization)
        tokens.close()

    def test_scope_expansion_missing_refresh_and_bad_json_fail_closed(self):
        extra = {
            GOOGLE_PROVIDER_SCOPES[scope]
            for scope in _SEMANTIC_SCOPES
        } | {"https://www.googleapis.com/auth/calendar.events"}
        cases = (
            self._response(body=_token_body(scopes=extra)),
            self._response(body=_token_body(refresh=None)),
            self._response(body=b'{"access_token":"one","access_token":"two"}'),
            OAuthHttpResponse(
                status=200,
                content_type="text/html",
                body=b"<html></html>",
            ),
        )
        for response in cases:
            with self.subTest(response=response), self.assertRaises(
                (ConnectorAuthorizationError, ConnectorResponseError)
            ):
                OAuthTokenClient(
                    _FakeTransport(response),
                    _clock=lambda: 100.0,
                ).exchange(_registration(), _authorization_code())

        malformed = self._response(
            body=b'{"access_token":"must-not-leak"',
        )
        with self.assertRaises(ConnectorResponseError) as caught:
            OAuthTokenClient(_FakeTransport(malformed)).exchange(
                _registration(),
                _authorization_code(),
            )
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("must-not-leak", str(caught.exception))

    def test_invalid_grant_revoked_and_rate_limit_are_explicit(self):
        cases = (
            (
                self._response(
                    status=400,
                    body=b'{"error":"invalid_grant"}',
                ),
                ConnectorInvalidGrantError,
            ),
            (
                self._response(
                    status=401,
                    body=b'{"error":"invalid_token"}',
                ),
                ConnectorTokenRevokedError,
            ),
        )
        for response, error_type in cases:
            with self.subTest(error=error_type), self.assertRaises(error_type):
                OAuthTokenClient(_FakeTransport(response)).exchange(
                    _registration(),
                    _authorization_code(),
                )
        with self.assertRaises(ConnectorRateLimitError) as caught:
            OAuthTokenClient(
                _FakeTransport(
                    self._response(
                        status=429,
                        body=b'{"error":"rate_limit"}',
                        retry_after=30,
                    )
                )
            ).exchange(_registration(), _authorization_code())
        self.assertEqual(caught.exception.retry_after_seconds, 30)

    def test_cross_provider_scope_fails_before_refresh_transport(self):
        transport = _FakeTransport(self._response())
        refresh_token = SecretValue(b"refresh-token")
        try:
            with self.assertRaises(ConnectorAuthorizationError):
                OAuthTokenClient(transport).refresh(
                    _registration(),
                    frozenset({OAuthScopeId.NOTION_PAGES_READ}),
                    refresh_token,
                )
        finally:
            refresh_token.close()
        self.assertEqual(transport.calls, [])

    def test_refresh_keeps_input_secret_and_accepts_rotated_refresh_token(self):
        transport = _FakeTransport(
            self._response(
                body=_token_body(
                    access="access-rotated",
                    refresh="refresh-rotated",
                )
            )
        )
        input_refresh = SecretValue(b"refresh-original")
        tokens = OAuthTokenClient(
            transport,
            _clock=lambda: 500.0,
        ).refresh(
            _registration(),
            _SEMANTIC_SCOPES,
            input_refresh,
        )
        self.assertFalse(input_refresh.closed)
        self.assertEqual(
            tokens.refresh_token.reveal(),
            b"refresh-rotated",
        )
        self.assertEqual(
            transport.calls[0][2],
            {
                "client_id": _CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": "refresh-original",
            },
        )
        tokens.close()
        input_refresh.close()

    def test_revocation_is_fixed_typed_and_already_invalid_is_successful(self):
        request = ConnectorRevocationRequest(
            authorization_id="auth-1",
            provider=ConnectorProviderId.GOOGLE,
            connector=ConnectorId.GMAIL,
            account_reference="account-opaque-1",
        )
        for response, status in (
            (
                OAuthHttpResponse(
                    status=200,
                    content_type="",
                    body=b"",
                    provider_request_id="request-1",
                ),
                RevocationStatus.REVOKED,
            ),
            (
                self._response(
                    status=400,
                    body=b'{"error":"invalid_token"}',
                ),
                RevocationStatus.ALREADY_INVALID,
            ),
        ):
            transport = _FakeTransport(response)
            refresh_token = SecretValue(b"refresh-revoke")
            try:
                result = OAuthTokenClient(
                    transport,
                    _clock=lambda: 900.0,
                ).revoke(
                    _registration(),
                    request,
                    refresh_token,
                )
            finally:
                refresh_token.close()
            self.assertEqual(result.status, status)
            self.assertEqual(result.completed_at, 900.0)
            self.assertEqual(
                transport.calls[0][1],
                "https://oauth2.googleapis.com/revoke",
            )

        transport = _FakeTransport(
            OAuthHttpResponse(
                status=200,
                content_type="",
                body=b"",
            )
        )
        refresh_token = SecretValue(b"refresh-without-registration")
        try:
            result = OAuthTokenClient(transport).revoke(
                ConnectorProviderId.GOOGLE,
                request,
                refresh_token,
            )
        finally:
            refresh_token.close()
        self.assertEqual(result.status, RevocationStatus.REVOKED)
        self.assertEqual(
            transport.calls[0][1],
            "https://oauth2.googleapis.com/revoke",
        )

        unused = SecretValue(b"unused")
        try:
            with self.assertRaises(TypeError):
                OAuthTokenClient(_FakeTransport()).revoke(
                    object(),
                    request,
                    unused,
                )
        finally:
            unused.close()

    def test_default_transport_rejects_non_policy_endpoint_before_network(self):
        class NoNetwork:
            def open(self, *_args, **_kwargs):
                raise AssertionError("network must not be reached")

        transport = FixedOAuthHttpsTransport(_opener=NoNetwork())
        with self.assertRaisesRegex(
            Exception,
            "not fixed",
        ):
            transport.post_form(
                provider=ConnectorProviderId.GOOGLE,
                endpoint="https://example.com/token",
                fields={"grant_type": "authorization_code"},
            )


class OAuthSourceBoundaryTests(unittest.TestCase):
    def test_http_response_repr_redacts_provider_body(self):
        response = OAuthHttpResponse(
            status=200,
            content_type="application/json",
            body=b'{"access_token":"must-not-appear"}',
        )
        representation = repr(response)
        self.assertNotIn("must-not-appear", representation)
        self.assertNotIn("access_token", representation)

    def test_oauth_layer_has_no_embedded_webview_logging_or_consumer_paths(self):
        source = Path("connectors/oauth.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue(
            {
                "logging",
                "subprocess",
                "PyQt6",
                "httpx",
                "requests",
                "aiohttp",
                "config",
                "tasks",
            }.isdisjoint(imported_roots)
        )
        for forbidden in (
            "qwebengine",
            "webview",
            "conversation",
            "task_worker",
            "preferences",
            "client_secret",
        ):
            self.assertNotIn(forbidden, source.casefold())
        self.assertIn("webbrowser.open_new_tab", source)
        self.assertIn("urllib.request.ProxyHandler({})", source)
        self.assertIn("allow_reuse_address = False", source)


if __name__ == "__main__":
    unittest.main()
