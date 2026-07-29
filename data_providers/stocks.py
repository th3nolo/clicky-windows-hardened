"""License-gated end-of-day quotes from one reviewed Alpha Vantage endpoint."""

from __future__ import annotations

import json
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Mapping, Protocol

from connectors.base import SecretValue


ALPHA_VANTAGE_ENDPOINT = "https://www.alphavantage.co/query"
ALPHA_VANTAGE_SOURCE = "Alpha Vantage"
MARKET_DATA_NOTICE = "Informational only — not investment advice."
MAX_MARKET_RESPONSE_BYTES = 256 * 1024
MAX_SYMBOL_CHARS = 32
END_OF_DAY_MAX_AGE = timedelta(days=4)
_SYMBOL_RE = re.compile(r"^[A-Z0-9][A-Z0-9.-]*$")
_UTC = timezone.utc


class MarketDataError(RuntimeError):
    pass


class MarketDataDisabledError(MarketDataError):
    pass


class MarketDataRateLimitError(MarketDataError):
    pass


@dataclass(frozen=True, slots=True)
class StockQuoteRequest:
    symbol: str
    user_initiated: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.symbol, str)
            or not self.symbol
            or len(self.symbol) > MAX_SYMBOL_CHARS
            or _SYMBOL_RE.fullmatch(self.symbol) is None
        ):
            raise ValueError("Market symbol is invalid")
        if self.user_initiated is not True:
            raise ValueError("Market quote must be an explicit user action")


@dataclass(frozen=True, slots=True)
class StockQuote:
    symbol: str
    price: Decimal
    change: Decimal
    change_percent: Decimal
    as_of_date: date
    retrieved_at: datetime
    stale_after: datetime
    source: str = ALPHA_VANTAGE_SOURCE
    freshness: str = "end_of_day"
    currency: None = None
    notice: str = MARKET_DATA_NOTICE

    def __post_init__(self) -> None:
        if _SYMBOL_RE.fullmatch(self.symbol) is None:
            raise ValueError("Market quote symbol is invalid")
        if not self.price.is_finite() or self.price < 0:
            raise ValueError("Market quote price is invalid")
        if not self.change.is_finite() or not self.change_percent.is_finite():
            raise ValueError("Market quote change is invalid")
        if (
            self.retrieved_at.tzinfo is None
            or self.stale_after.tzinfo is None
        ):
            raise ValueError("Market quote timestamps must be timezone-aware")
        if self.source != ALPHA_VANTAGE_SOURCE:
            raise ValueError("Market quote source is invalid")
        if self.freshness != "end_of_day":
            raise ValueError("Unverified realtime freshness is not allowed")
        if self.notice != MARKET_DATA_NOTICE:
            raise ValueError("Market data informational notice is required")

    def is_stale(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise TypeError("Market quote comparison time must be timezone-aware")
        return now.astimezone(_UTC) > self.stale_after.astimezone(_UTC)


@dataclass(frozen=True, slots=True)
class MarketHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)


class MarketHttpTransport(Protocol):
    def quote(
        self,
        *,
        endpoint: str,
        query: Mapping[str, str],
        maximum_response_bytes: int,
    ) -> MarketHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedAlphaVantageHttpsTransport:
    """Fixed endpoint with no proxy, redirect, entitlement, or trading path."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        _opener=None,
    ) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0.01 <= float(timeout_seconds) <= 30.0
        ):
            raise ValueError("Market data request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def quote(
        self,
        *,
        endpoint: str,
        query: Mapping[str, str],
        maximum_response_bytes: int,
    ) -> MarketHttpResponse:
        if endpoint != ALPHA_VANTAGE_ENDPOINT:
            raise MarketDataError("Market data endpoint is not fixed by policy")
        if (
            not isinstance(query, Mapping)
            or set(query) != {"apikey", "function", "symbol"}
            or query.get("function") != "GLOBAL_QUOTE"
        ):
            raise MarketDataError("Market data query is not fixed by policy")
        if (
            type(maximum_response_bytes) is not int
            or not 1 <= maximum_response_bytes <= MAX_MARKET_RESPONSE_BYTES
        ):
            raise ValueError("Market response limit is invalid")
        url = endpoint + "?" + urllib.parse.urlencode(sorted(query.items()))
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "User-Agent": "Clicky-Windows-Stock-Cards/1",
            },
        )
        try:
            try:
                response = self._opener.open(request, timeout=self._timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body = response.read(maximum_response_bytes + 1)
                if len(body) > maximum_response_bytes:
                    raise MarketDataError("Market response exceeds its bound")
                return MarketHttpResponse(
                    status=response.status,
                    content_type=response.headers.get("Content-Type", ""),
                    body=body,
                )
        except MarketDataError:
            raise
        except (OSError, urllib.error.URLError) as exc:
            raise MarketDataError("Market data provider request failed") from exc


class AlphaVantageEndOfDayProvider:
    """Read-only quotes; network stays off until licensing is confirmed."""

    def __init__(
        self,
        *,
        api_key: SecretValue,
        feature_enabled: bool,
        market_data_consent: bool,
        license_confirmed: bool,
        transport: MarketHttpTransport | None = None,
    ) -> None:
        if not isinstance(api_key, SecretValue):
            raise TypeError("Market data API key must use SecretValue")
        self._api_key = api_key
        self._enabled = feature_enabled is True
        self._consent = market_data_consent is True
        self._license_confirmed = license_confirmed is True
        self._transport = transport or FixedAlphaVantageHttpsTransport()

    def quote(
        self,
        request: StockQuoteRequest,
        *,
        now: datetime | None = None,
    ) -> StockQuote:
        if not self._enabled or not self._consent:
            raise MarketDataDisabledError(
                "External market data is disabled or not consented"
            )
        if not self._license_confirmed:
            raise MarketDataDisabledError(
                "Market data licensing has not been confirmed"
            )
        if not isinstance(request, StockQuoteRequest):
            raise TypeError("Market quote request is invalid")
        key_bytes = self._api_key.reveal()
        try:
            try:
                key = key_bytes.decode("ascii")
            except UnicodeDecodeError as exc:
                raise MarketDataError("Market API key encoding is invalid") from exc
            response = self._transport.quote(
                endpoint=ALPHA_VANTAGE_ENDPOINT,
                query={
                    "apikey": key,
                    "function": "GLOBAL_QUOTE",
                    "symbol": request.symbol,
                },
                maximum_response_bytes=MAX_MARKET_RESPONSE_BYTES,
            )
        finally:
            key_bytes = b""
            if "key" in locals():
                key = ""
        return _parse_quote(response, request, now=now)


def _parse_quote(
    response: MarketHttpResponse,
    request: StockQuoteRequest,
    *,
    now: datetime | None,
) -> StockQuote:
    if not isinstance(response, MarketHttpResponse):
        raise TypeError("Market data response is invalid")
    if response.status == 429:
        raise MarketDataRateLimitError("Market data rate limit is active")
    if not 200 <= response.status <= 299:
        raise MarketDataError("Market data provider returned an error")
    if response.content_type.partition(";")[0].strip().casefold() != "application/json":
        raise MarketDataError("Market data response is not JSON")
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MarketDataError("Market data response is invalid") from exc
    if not isinstance(payload, dict):
        raise MarketDataError("Market data response shape is invalid")
    if "Note" in payload or "Information" in payload:
        raise MarketDataRateLimitError(
            "Market data provider quota or entitlement is unavailable"
        )
    if set(payload) != {"Global Quote"} or not isinstance(
        payload["Global Quote"],
        dict,
    ):
        raise MarketDataError("Market data response shape is invalid")
    quote = payload["Global Quote"]
    required = {
        "01. symbol",
        "05. price",
        "07. latest trading day",
        "09. change",
        "10. change percent",
    }
    if not required.issubset(quote):
        raise MarketDataError("Market quote is missing required fields")
    if quote["01. symbol"] != request.symbol:
        raise MarketDataError("Market quote symbol does not match the request")
    try:
        price = Decimal(quote["05. price"])
        change = Decimal(quote["09. change"])
        percent_text = quote["10. change percent"]
        if not isinstance(percent_text, str) or not percent_text.endswith("%"):
            raise ValueError
        change_percent = Decimal(percent_text[:-1])
        as_of = date.fromisoformat(quote["07. latest trading day"])
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise MarketDataError("Market quote fields are invalid") from exc
    current = now or datetime.now(_UTC)
    if current.tzinfo is None:
        raise TypeError("Market retrieval time must be timezone-aware")
    current = current.astimezone(_UTC)
    as_of_end = datetime.combine(as_of, time.max, tzinfo=_UTC)
    if as_of > current.date():
        raise MarketDataError("Market quote trading date is in the future")
    # Keep already-stale data representable so the UI can label it honestly.
    # Retrieval time must never refresh an old trading date.
    stale_after = as_of_end + END_OF_DAY_MAX_AGE
    try:
        return StockQuote(
            symbol=request.symbol,
            price=price,
            change=change,
            change_percent=change_percent,
            as_of_date=as_of,
            retrieved_at=current,
            stale_after=stale_after,
        )
    except ValueError as exc:
        raise MarketDataError("Market quote fields are invalid") from exc


__all__ = [
    "ALPHA_VANTAGE_ENDPOINT",
    "ALPHA_VANTAGE_SOURCE",
    "MARKET_DATA_NOTICE",
    "AlphaVantageEndOfDayProvider",
    "FixedAlphaVantageHttpsTransport",
    "MarketDataDisabledError",
    "MarketDataError",
    "MarketDataRateLimitError",
    "StockQuote",
    "StockQuoteRequest",
]
