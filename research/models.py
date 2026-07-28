"""Typed research records with mandatory field-level public evidence.

The models are deliberately independent of model providers and network
clients. They accept only bounded immutable values, canonicalize public URLs,
and reject duplicate entities before any record can count toward a result.
"""

from __future__ import annotations

import ipaddress
import json
import posixpath
import re
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


MAX_URL_CHARS = 4_096
MAX_FIELD_ID_CHARS = 96
MAX_FIELD_VALUE_CHARS = 4_096
MAX_ENTITY_CHARS = 512
MAX_RATIONALE_CHARS = 2_000
MAX_RESEARCH_ROWS = 100
MAX_FIELDS_PER_RECORD = 32
MAX_SOURCES_PER_FIELD = 8
MAX_SOURCES_PER_RECORD = 64
MAX_TOTAL_SOURCES = 2_048
MAX_RESEARCH_BYTES = 8 * 1024 * 1024
_FIELD_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_INVALID_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_CONTROL = re.compile(r"[\x00-\x20\x7f]")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
)
_RESERVED_FIELD_IDS = frozenset({"entity", "public_url", "rationale"})


class ResearchValidationError(ValueError):
    """A record, URL, or batch is not safe and complete enough to use."""


class DuplicateResearchRecordError(ResearchValidationError):
    """Two records identify the same canonical public URL."""


def canonicalize_public_url(
    value: str,
    *,
    require_https: bool = False,
) -> str:
    """Return a stable public HTTP(S) URL without credentials or fragments.

    This performs syntax and literal-address checks. Network callers must also
    retain the hardened DNS, redirect, and connected-peer checks in
    ``ai.web_search`` immediately before and after connecting.
    """

    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_URL_CHARS
        or _CONTROL.search(value) is not None
        or "\\" in value
    ):
        raise ResearchValidationError("Research URL is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ResearchValidationError("Research URL is invalid") from exc
    scheme = parsed.scheme.lower()
    allowed_schemes = {"https"} if require_https else {"http", "https"}
    if scheme not in allowed_schemes:
        raise ResearchValidationError("Research URL scheme is not permitted")
    if (
        not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ResearchValidationError(
            "Research URL authority is not permitted"
        )
    raw_host = parsed.hostname
    if raw_host.endswith("."):
        raise ResearchValidationError(
            "Research URL trailing-dot hosts are not permitted"
        )
    try:
        host = raw_host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ResearchValidationError(
            "Research URL hostname is invalid"
        ) from exc
    if (
        host == "localhost"
        or host.endswith(_BLOCKED_HOST_SUFFIXES)
        or len(host) > 253
    ):
        raise ResearchValidationError(
            "Research URL hostname is not public"
        )
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_public_address(literal):
            raise ResearchValidationError(
                "Research URL address is not public"
            )
        canonical_host = f"[{host}]" if literal.version == 6 else host
    else:
        labels = host.split(".")
        if (
            len(labels) < 2
            or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels)
        ):
            raise ResearchValidationError(
                "Research URL hostname is invalid"
            )
        canonical_host = host
    resolved_port = port or (443 if scheme == "https" else 80)
    if not 1 <= resolved_port <= 65_535:
        raise ResearchValidationError("Research URL port is invalid")
    default_port = 443 if scheme == "https" else 80
    authority = canonical_host
    if resolved_port != default_port:
        authority = f"{canonical_host}:{resolved_port}"

    path = _canonical_path(parsed.path)
    query = _canonical_query(parsed.query)
    canonical = urlunsplit((scheme, authority, path, query, ""))
    if len(canonical) > MAX_URL_CHARS:
        raise ResearchValidationError("Canonical research URL is too long")
    return canonical


def _is_public_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return address.is_global and not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _normalize_percent_escapes(value: str) -> str:
    if _INVALID_PERCENT.search(value) is not None:
        raise ResearchValidationError("Research URL escape is invalid")

    def replace(match: re.Match[str]) -> str:
        byte = int(match.group(1), 16)
        character = chr(byte)
        return character if character in _UNRESERVED else f"%{byte:02X}"

    return _PERCENT_ESCAPE.sub(replace, value)


def _canonical_path(value: str) -> str:
    normalized = _normalize_percent_escapes(value or "/")
    if _CONTROL.search(normalized) is not None:
        raise ResearchValidationError("Research URL path is invalid")
    had_trailing_slash = normalized.endswith("/")
    normalized = posixpath.normpath(normalized)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if normalized == "//":
        normalized = "/"
    if had_trailing_slash and normalized != "/":
        normalized += "/"
    return normalized


def _canonical_query(value: str) -> str:
    normalized = _normalize_percent_escapes(value)
    if _CONTROL.search(normalized) is not None:
        raise ResearchValidationError("Research URL query is invalid")
    pairs = parse_qsl(
        normalized,
        keep_blank_values=True,
        strict_parsing=False,
    )
    pairs.sort()
    return urlencode(pairs, doseq=True)


@dataclass(frozen=True, slots=True)
class ResearchValue:
    """One factual value and the public sources that support it."""

    value: str = field(repr=False)
    source_urls: tuple[str, ...]

    def __post_init__(self) -> None:
        normalized_value = _bounded_text(
            self.value,
            maximum=MAX_FIELD_VALUE_CHARS,
            label="Research value",
        )
        if (
            not isinstance(self.source_urls, tuple)
            or not 1 <= len(self.source_urls) <= MAX_SOURCES_PER_FIELD
        ):
            raise ResearchValidationError(
                "Every research value needs bounded source evidence"
            )
        sources = tuple(
            canonicalize_public_url(source)
            for source in self.source_urls
        )
        if len(sources) != len(set(sources)):
            raise ResearchValidationError(
                "Research value sources must be unique"
            )
        object.__setattr__(self, "value", normalized_value)
        object.__setattr__(self, "source_urls", sources)


@dataclass(frozen=True, slots=True)
class ResearchField:
    """One requested attribute with field-local evidence."""

    field_id: str
    value: ResearchValue

    def __post_init__(self) -> None:
        if (
            not isinstance(self.field_id, str)
            or len(self.field_id) > MAX_FIELD_ID_CHARS
            or _FIELD_ID.fullmatch(self.field_id) is None
            or self.field_id in _RESERVED_FIELD_IDS
        ):
            raise ResearchValidationError("Research field ID is invalid")
        if not isinstance(self.value, ResearchValue):
            raise TypeError("Research field value must be typed")


@dataclass(frozen=True, slots=True)
class ResearchRecord:
    """One source-backed entity suitable for a reviewed local artifact."""

    entity: ResearchValue
    public_url: ResearchValue
    requested_fields: tuple[ResearchField, ...]
    rationale: ResearchValue
    retrieved_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.entity, ResearchValue):
            raise TypeError("Research entity must be typed")
        if len(self.entity.value) > MAX_ENTITY_CHARS:
            raise ResearchValidationError("Research entity is too long")
        if not isinstance(self.public_url, ResearchValue):
            raise TypeError("Research public URL must be typed")
        canonical_public_url = canonicalize_public_url(
            self.public_url.value
        )
        if (
            not isinstance(self.requested_fields, tuple)
            or len(self.requested_fields) > MAX_FIELDS_PER_RECORD
            or any(
                not isinstance(item, ResearchField)
                for item in self.requested_fields
            )
        ):
            raise ResearchValidationError(
                "Research requested fields are invalid"
            )
        field_ids = tuple(item.field_id for item in self.requested_fields)
        if len(field_ids) != len(set(field_ids)):
            raise ResearchValidationError(
                "Research requested field IDs must be unique"
            )
        if not isinstance(self.rationale, ResearchValue):
            raise TypeError("Research rationale must be typed")
        if len(self.rationale.value) > MAX_RATIONALE_CHARS:
            raise ResearchValidationError("Research rationale is too long")
        if (
            not isinstance(self.retrieved_at, datetime)
            or self.retrieved_at.tzinfo is None
            or self.retrieved_at.utcoffset() is None
        ):
            raise ResearchValidationError(
                "Research retrieval time must be timezone-aware"
            )
        if len(self.all_source_urls) > MAX_SOURCES_PER_RECORD:
            raise ResearchValidationError(
                "Research record has too many source references"
            )
        object.__setattr__(
            self,
            "public_url",
            ResearchValue(
                canonical_public_url,
                self.public_url.source_urls,
            ),
        )

    @property
    def canonical_public_url(self) -> str:
        return self.public_url.value

    @property
    def all_source_urls(self) -> tuple[str, ...]:
        sources: list[str] = []
        values = (
            self.entity,
            self.public_url,
            *(item.value for item in self.requested_fields),
            self.rationale,
        )
        for value in values:
            sources.extend(value.source_urls)
        return tuple(dict.fromkeys(sources))

    def canonical_payload(self) -> dict[str, object]:
        return {
            "entity": _value_payload(self.entity),
            "public_url": _value_payload(self.public_url),
            "rationale": _value_payload(self.rationale),
            "requested_fields": [
                {
                    "field_id": item.field_id,
                    **_value_payload(item.value),
                }
                for item in self.requested_fields
            ],
            "retrieved_at": self.retrieved_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class ResearchLimits:
    """Reviewed ceilings for one structured research result."""

    max_rows: int
    max_fields_per_record: int
    max_sources_per_record: int
    max_total_sources: int
    max_output_bytes: int

    def __post_init__(self) -> None:
        _bounded_integer(
            self.max_rows,
            1,
            MAX_RESEARCH_ROWS,
            "Research row limit",
        )
        _bounded_integer(
            self.max_fields_per_record,
            0,
            MAX_FIELDS_PER_RECORD,
            "Research field limit",
        )
        _bounded_integer(
            self.max_sources_per_record,
            1,
            MAX_SOURCES_PER_RECORD,
            "Research per-record source limit",
        )
        _bounded_integer(
            self.max_total_sources,
            1,
            MAX_TOTAL_SOURCES,
            "Research total source limit",
        )
        _bounded_integer(
            self.max_output_bytes,
            1,
            MAX_RESEARCH_BYTES,
            "Research output limit",
        )


@dataclass(frozen=True, slots=True)
class ResearchBatch:
    """A bounded, canonical-URL-unique collection of research records."""

    records: tuple[ResearchRecord, ...]
    limits: ResearchLimits

    def __post_init__(self) -> None:
        if not isinstance(self.limits, ResearchLimits):
            raise TypeError("Research batch limits must be typed")
        if (
            not isinstance(self.records, tuple)
            or any(not isinstance(item, ResearchRecord) for item in self.records)
        ):
            raise TypeError("Research batch records must be a tuple")
        if len(self.records) > self.limits.max_rows:
            raise ResearchValidationError("Research row limit exceeded")
        canonical_urls = tuple(
            item.canonical_public_url for item in self.records
        )
        if len(canonical_urls) != len(set(canonical_urls)):
            raise DuplicateResearchRecordError(
                "Duplicate canonical research URL"
            )
        for record in self.records:
            if (
                len(record.requested_fields)
                > self.limits.max_fields_per_record
            ):
                raise ResearchValidationError(
                    "Research per-record field limit exceeded"
                )
            if (
                len(record.all_source_urls)
                > self.limits.max_sources_per_record
            ):
                raise ResearchValidationError(
                    "Research per-record source limit exceeded"
                )
        total_sources = len(
            {
                source
                for record in self.records
                for source in record.all_source_urls
            }
        )
        if total_sources > self.limits.max_total_sources:
            raise ResearchValidationError(
                "Research total source limit exceeded"
            )
        if self.output_bytes > self.limits.max_output_bytes:
            raise ResearchValidationError(
                "Research structured output limit exceeded"
            )

    @property
    def output_bytes(self) -> int:
        payload = [
            record.canonical_payload()
            for record in self.records
        ]
        return len(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )


def _value_payload(value: ResearchValue) -> dict[str, object]:
    return {
        "source_urls": list(value.source_urls),
        "value": value.value,
    }


def _bounded_text(value: object, *, maximum: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ResearchValidationError(f"{label} is invalid")
    return value.strip()


def _bounded_integer(
    value: object,
    minimum: int,
    maximum: int,
    label: str,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResearchValidationError(f"{label} is invalid")


__all__ = [
    "DuplicateResearchRecordError",
    "ResearchBatch",
    "ResearchField",
    "ResearchLimits",
    "ResearchRecord",
    "ResearchValidationError",
    "ResearchValue",
    "canonicalize_public_url",
]
