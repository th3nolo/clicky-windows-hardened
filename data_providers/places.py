"""User-triggered place search through a reviewed self-hosted Nominatim."""

from __future__ import annotations

import hashlib
import json
import math
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Mapping, Protocol


MAX_PLACE_QUERY_CHARS = 256
MAX_PLACE_RESULTS = 5
MAX_PLACE_RESPONSE_BYTES = 256 * 1024
MIN_REQUEST_INTERVAL_SECONDS = 1.0
PLACE_CACHE_TTL = timedelta(hours=6)
PLACE_RESULT_TTL = timedelta(hours=24)
OSM_ATTRIBUTION = "© OpenStreetMap contributors, ODbL"
NOMINATIM_SOURCE_LABEL = "OpenStreetMap / Nominatim"
_PUBLIC_NOMINATIM_HOST = "nominatim.openstreetmap.org"
_UTC = timezone.utc

# A distributable build must add its reviewed, self-hosted or contracted
# endpoint through a source-reviewed build change. The public OSMF endpoint is
# deliberately not a product default.
REVIEWED_NOMINATIM_ENDPOINTS: Mapping[str, str] = MappingProxyType({})


class PlaceProviderError(RuntimeError):
    pass


class PlaceProviderDisabledError(PlaceProviderError):
    pass


class PlaceProviderRateLimitError(PlaceProviderError):
    pass


@dataclass(frozen=True, slots=True)
class ReviewedNominatimEndpoint:
    endpoint_id: str
    search_url: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.endpoint_id, str)
            or not self.endpoint_id
            or len(self.endpoint_id) > 64
            or not self.endpoint_id.replace("-", "").replace("_", "").isalnum()
        ):
            raise ValueError("Reviewed place endpoint ID is invalid")
        parsed = urllib.parse.urlsplit(self.search_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.endswith("/search")
            or parsed.hostname.casefold() == _PUBLIC_NOMINATIM_HOST
        ):
            raise ValueError(
                "Place endpoint must be a fixed private HTTPS Nominatim search"
            )


@dataclass(frozen=True, slots=True)
class PlaceSearchRequest:
    query: str = field(repr=False)
    limit: int = MAX_PLACE_RESULTS
    user_initiated: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.query, str)
            or not self.query
            or len(self.query) > MAX_PLACE_QUERY_CHARS
            or self.query.strip() != self.query
            or "\x00" in self.query
            or not self.query.isprintable()
        ):
            raise ValueError("Place query is invalid")
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_PLACE_RESULTS:
            raise ValueError("Place result limit is invalid")
        if self.user_initiated is not True:
            raise ValueError(
                "Place search must be an explicit user action; autocomplete is disabled"
            )


@dataclass(frozen=True, slots=True)
class PlaceResult:
    display_name: str
    latitude: Decimal
    longitude: Decimal
    category: str
    place_type: str
    source: str
    attribution: str
    retrieved_at: datetime
    fresh_until: datetime

    def __post_init__(self) -> None:
        if (
            not isinstance(self.display_name, str)
            or not self.display_name
            or len(self.display_name) > 512
            or not self.display_name.isprintable()
        ):
            raise ValueError("Place display name is invalid")
        if not Decimal("-90") <= self.latitude <= Decimal("90"):
            raise ValueError("Place latitude is invalid")
        if not Decimal("-180") <= self.longitude <= Decimal("180"):
            raise ValueError("Place longitude is invalid")
        for value, label, maximum in (
            (self.category, "Place category", 128),
            (self.place_type, "Place type", 128),
        ):
            if (
                not isinstance(value, str)
                or not value
                or len(value) > maximum
                or not value.isprintable()
            ):
                raise ValueError(f"{label} is invalid")
        if self.source != NOMINATIM_SOURCE_LABEL:
            raise ValueError("Place source label is invalid")
        if self.attribution != OSM_ATTRIBUTION:
            raise ValueError("Place attribution is required")
        if (
            self.retrieved_at.tzinfo is None
            or self.fresh_until.tzinfo is None
            or self.fresh_until <= self.retrieved_at
        ):
            raise ValueError("Place freshness window is invalid")


@dataclass(frozen=True, slots=True)
class PlaceHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)


class PlaceHttpTransport(Protocol):
    def search(
        self,
        *,
        endpoint: ReviewedNominatimEndpoint,
        query: Mapping[str, str],
        maximum_response_bytes: int,
    ) -> PlaceHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedNominatimHttpsTransport:
    """No proxies, redirects, endpoint override, or background autocomplete."""

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
            raise ValueError("Place request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def search(
        self,
        *,
        endpoint: ReviewedNominatimEndpoint,
        query: Mapping[str, str],
        maximum_response_bytes: int,
    ) -> PlaceHttpResponse:
        if not isinstance(endpoint, ReviewedNominatimEndpoint):
            raise TypeError("Reviewed place endpoint is required")
        expected_keys = {
            "addressdetails",
            "format",
            "limit",
            "q",
        }
        if (
            not isinstance(query, Mapping)
            or set(query) != expected_keys
            or query.get("format") != "jsonv2"
            or query.get("addressdetails") != "0"
        ):
            raise PlaceProviderError("Place request query is not fixed by policy")
        if (
            type(maximum_response_bytes) is not int
            or not 1 <= maximum_response_bytes <= MAX_PLACE_RESPONSE_BYTES
        ):
            raise ValueError("Place response limit is invalid")
        url = endpoint.search_url + "?" + urllib.parse.urlencode(sorted(query.items()))
        parsed = urllib.parse.urlsplit(url)
        endpoint_parsed = urllib.parse.urlsplit(endpoint.search_url)
        if (
            parsed.scheme != endpoint_parsed.scheme
            or parsed.hostname != endpoint_parsed.hostname
            or parsed.port != endpoint_parsed.port
            or parsed.path != endpoint_parsed.path
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise PlaceProviderError("Place request left its reviewed endpoint")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "User-Agent": "Clicky-Windows-Place-Cards/1",
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
                    raise PlaceProviderError("Place response exceeds its bound")
                return PlaceHttpResponse(
                    status=response.status,
                    content_type=response.headers.get("Content-Type", ""),
                    body=body,
                )
        except PlaceProviderError:
            raise
        except (OSError, urllib.error.URLError) as exc:
            raise PlaceProviderError("Place provider request failed") from exc


class NominatimPlaceProvider:
    """One reviewed deployment endpoint, explicit search, bounded local cache."""

    def __init__(
        self,
        endpoint_id: str,
        *,
        feature_enabled: bool,
        external_search_consent: bool,
        endpoints: Mapping[str, str] = REVIEWED_NOMINATIM_ENDPOINTS,
        transport: PlaceHttpTransport | None = None,
        monotonic=time.monotonic,
    ) -> None:
        url = endpoints.get(endpoint_id)
        if url is None:
            raise PlaceProviderDisabledError(
                "No reviewed Nominatim endpoint is configured"
            )
        self._endpoint = ReviewedNominatimEndpoint(endpoint_id, url)
        self._enabled = feature_enabled is True
        self._consent = external_search_consent is True
        self._transport = transport or FixedNominatimHttpsTransport()
        self._monotonic = monotonic
        self._last_request_at: float | None = None
        self._cache: dict[str, tuple[float, tuple[PlaceResult, ...]]] = {}
        self._lock = threading.RLock()

    def search(
        self,
        request: PlaceSearchRequest,
        *,
        now: datetime | None = None,
    ) -> tuple[PlaceResult, ...]:
        if not self._enabled or not self._consent:
            raise PlaceProviderDisabledError(
                "External place search is disabled or not consented"
            )
        if not isinstance(request, PlaceSearchRequest):
            raise TypeError("Place search request is invalid")
        cache_key = hashlib.sha256(
            request.query.casefold().encode("utf-8")
            + b"\x00"
            + str(request.limit).encode("ascii")
        ).hexdigest()
        current_tick = float(self._monotonic())
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None and current_tick - cached[0] <= (
                PLACE_CACHE_TTL.total_seconds()
            ):
                return cached[1]
            if (
                self._last_request_at is not None
                and current_tick - self._last_request_at
                < MIN_REQUEST_INTERVAL_SECONDS
            ):
                raise PlaceProviderRateLimitError(
                    "Place search is limited to one provider request per second"
                )
            self._last_request_at = current_tick
        response = self._transport.search(
            endpoint=self._endpoint,
            query=MappingProxyType(
                {
                    "addressdetails": "0",
                    "format": "jsonv2",
                    "limit": str(request.limit),
                    "q": request.query,
                }
            ),
            maximum_response_bytes=MAX_PLACE_RESPONSE_BYTES,
        )
        results = _parse_results(response, request, now=now)
        with self._lock:
            self._cache[cache_key] = (current_tick, results)
        return results


def _parse_results(
    response: PlaceHttpResponse,
    request: PlaceSearchRequest,
    *,
    now: datetime | None,
) -> tuple[PlaceResult, ...]:
    if not isinstance(response, PlaceHttpResponse):
        raise TypeError("Place response is invalid")
    if response.status == 429:
        raise PlaceProviderRateLimitError("Place provider rate limit is active")
    if not 200 <= response.status <= 299:
        raise PlaceProviderError("Place provider returned an error")
    if response.content_type.partition(";")[0].strip().casefold() != "application/json":
        raise PlaceProviderError("Place provider response is not JSON")
    try:
        values = json.loads(response.body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PlaceProviderError("Place provider response is invalid") from exc
    if not isinstance(values, list) or len(values) > request.limit:
        raise PlaceProviderError("Place provider result count is invalid")
    current = now or datetime.now(_UTC)
    if current.tzinfo is None:
        raise TypeError("Place retrieval time must be timezone-aware")
    current = current.astimezone(_UTC)
    results: list[PlaceResult] = []
    for value in values:
        if not isinstance(value, dict):
            raise PlaceProviderError("Place provider result is invalid")
        try:
            display_name = value["display_name"]
            latitude = Decimal(value["lat"])
            longitude = Decimal(value["lon"])
            category = value.get("category") or value.get("class") or "place"
            place_type = value.get("type") or "place"
        except (KeyError, InvalidOperation, TypeError) as exc:
            raise PlaceProviderError("Place provider result is invalid") from exc
        try:
            results.append(
                PlaceResult(
                    display_name=display_name,
                    latitude=latitude,
                    longitude=longitude,
                    category=category,
                    place_type=place_type,
                    source=NOMINATIM_SOURCE_LABEL,
                    attribution=OSM_ATTRIBUTION,
                    retrieved_at=current,
                    fresh_until=current + PLACE_RESULT_TTL,
                )
            )
        except ValueError as exc:
            raise PlaceProviderError("Place provider result is invalid") from exc
    return tuple(results)


__all__ = [
    "NOMINATIM_SOURCE_LABEL",
    "OSM_ATTRIBUTION",
    "REVIEWED_NOMINATIM_ENDPOINTS",
    "FixedNominatimHttpsTransport",
    "NominatimPlaceProvider",
    "PlaceProviderDisabledError",
    "PlaceProviderError",
    "PlaceProviderRateLimitError",
    "PlaceResult",
    "PlaceSearchRequest",
    "ReviewedNominatimEndpoint",
]
