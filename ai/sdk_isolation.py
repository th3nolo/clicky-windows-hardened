"""Construct provider SDK clients without ambient credentials or headers.

The locked SDKs merge *_CUSTOM_HEADERS even with explicit credentials and an
explicit endpoint. Their public ``default_headers={}`` argument does not opt
out. Replace that instance-local header mapping before exposing a new client;
never clear process environment shared with other providers or threads. Tests
exercise real SDK request serialization, so SDK upgrades must preserve this
private ``_custom_headers`` contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from anthropic import AsyncAnthropic
    from openai import AsyncOpenAI


def _require_explicit_identity(api_key: str, base_url: str) -> None:
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("An explicit provider credential is required")
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("An explicit provider endpoint is required")


def _http_client(timeout: float | httpx.Timeout) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        trust_env=False, follow_redirects=False, timeout=timeout,
    )


def create_openai_client(
    *, api_key: str, base_url: str,
    http_client: httpx.AsyncClient | None = None,
    max_retries: int = 0,
    timeout: float | httpx.Timeout = 120.0,
    default_headers: Mapping[str, str] | None = None,
) -> AsyncOpenAI:
    """Keep only the caller's endpoint, key and explicitly supplied headers.

    Local OpenAI-compatible servers remain supported: callers supply their
    existing URL and a non-secret placeholder credential when no key is needed.
    An explicitly supplied HTTP client retains its caller-owned transport.
    """
    from openai import AsyncOpenAI

    _require_explicit_identity(api_key, base_url)
    client = AsyncOpenAI(
        api_key=api_key, base_url=base_url,
        # Non-None values suppress SDK environment defaults during construction.
        admin_api_key="", organization="", project="", webhook_secret="",
        http_client=http_client if http_client is not None else _http_client(timeout),
        timeout=timeout, max_retries=max_retries,
    )
    client._custom_headers = dict(default_headers or {})
    # None suppresses these headers/auth methods on actual requests.
    client.admin_api_key = None
    client.organization = None
    client.project = None
    client.webhook_secret = None
    return client


def create_anthropic_client(
    *, api_key: str, base_url: str,
    http_client: httpx.AsyncClient | None = None,
    max_retries: int = 0,
    timeout: float | httpx.Timeout = 120.0,
    default_headers: Mapping[str, str] | None = None,
) -> AsyncAnthropic:
    """Use explicit static Anthropic credentials, without ambient profiles."""
    from anthropic import AsyncAnthropic

    _require_explicit_identity(api_key, base_url)
    client = AsyncAnthropic(
        api_key=api_key, base_url=base_url, webhook_key="",
        http_client=http_client if http_client is not None else _http_client(timeout),
        timeout=timeout, max_retries=max_retries,
    )
    client._custom_headers = dict(default_headers or {})
    client.webhook_key = None
    return client
