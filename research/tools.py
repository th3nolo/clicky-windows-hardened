"""Research-specific adapters for the trusted task tool broker.

This module does not grant network authority. ``TaskToolBroker`` remains the
authorization boundary and installs this adapter behind its pre-authorized
``web.search`` and ``web.fetch`` operations. The adapter adds conservative
physical-request accounting and accepts only inspectable public HTTPS sources.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from research.models import (
    ResearchValidationError,
    canonicalize_public_url,
)


MAX_RESEARCH_REQUESTS = 64
MAX_RESEARCH_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RESEARCH_SEARCH_RESULTS = 5
MAX_RESEARCH_SEARCH_SOURCES = 64
MAX_RESEARCH_FETCH_CHARS = 5_500
MAX_SEARCH_QUERY_CHARS = 2_048
MAX_SEARCH_TITLE_CHARS = 512
MAX_SEARCH_EXCERPT_CHARS = 5_500
_RESULT_HEADER = re.compile(r"^\[(\d+)\]\s+(.+)$")


class ResearchToolError(RuntimeError):
    """A bounded research adapter rejected an operation or response."""


class ResearchToolLimitError(ResearchToolError):
    """A reviewed network, source, or response ceiling would be exceeded."""


SearchAdapter = Callable[[str, int], Awaitable[str]]
FetchAdapter = Callable[[str, int], Awaitable[str]]


@dataclass(frozen=True, slots=True)
class ResearchToolLimits:
    max_requests: int
    max_response_bytes: int
    max_sources: int = MAX_RESEARCH_SEARCH_SOURCES
    max_results_per_search: int = MAX_RESEARCH_SEARCH_RESULTS
    max_fetch_chars: int = MAX_RESEARCH_FETCH_CHARS

    def __post_init__(self) -> None:
        _bounded_integer(
            self.max_requests,
            1,
            MAX_RESEARCH_REQUESTS,
            "Research request limit",
        )
        _bounded_integer(
            self.max_response_bytes,
            1,
            MAX_RESEARCH_RESPONSE_BYTES,
            "Research response-byte limit",
        )
        _bounded_integer(
            self.max_sources,
            1,
            MAX_RESEARCH_SEARCH_SOURCES,
            "Research source limit",
        )
        _bounded_integer(
            self.max_results_per_search,
            1,
            MAX_RESEARCH_SEARCH_RESULTS,
            "Research result limit",
        )
        _bounded_integer(
            self.max_fetch_chars,
            1,
            MAX_RESEARCH_FETCH_CHARS,
            "Research fetch limit",
        )


@dataclass(frozen=True, slots=True)
class ResearchSearchHit:
    title: str
    public_url: str
    excerpt: str = field(repr=False)
    retrieved_at: datetime

    def __post_init__(self) -> None:
        title = _bounded_text(
            self.title,
            maximum=MAX_SEARCH_TITLE_CHARS,
            label="Research result title",
        )
        public_url = canonicalize_public_url(
            self.public_url,
            require_https=True,
        )
        if (
            not isinstance(self.excerpt, str)
            or len(self.excerpt) > MAX_SEARCH_EXCERPT_CHARS
            or "\x00" in self.excerpt
        ):
            raise ResearchValidationError(
                "Research result excerpt is invalid"
            )
        if (
            not isinstance(self.retrieved_at, datetime)
            or self.retrieved_at.tzinfo is None
            or self.retrieved_at.utcoffset() is None
        ):
            raise ResearchValidationError(
                "Research result time must be timezone-aware"
            )
        object.__setattr__(self, "title", title)
        object.__setattr__(self, "public_url", public_url)


@dataclass(frozen=True, slots=True)
class ResearchToolSnapshot:
    physical_requests_charged: int
    response_bytes_consumed: int
    unique_sources_observed: int

    def __post_init__(self) -> None:
        for value in (
            self.physical_requests_charged,
            self.response_bytes_consumed,
            self.unique_sources_observed,
        ):
            if type(value) is not int or value < 0:
                raise ValueError("Research tool snapshot is invalid")


class BoundedResearchToolAdapter:
    """Sanitize search/fetch data behind one already-authorized broker run."""

    def __init__(
        self,
        limits: ResearchToolLimits,
        *,
        search_adapter: SearchAdapter | None = None,
        fetch_adapter: FetchAdapter | None = None,
    ) -> None:
        if not isinstance(limits, ResearchToolLimits):
            raise TypeError("Research tool limits must be typed")
        self._limits = limits
        self._search_adapter = search_adapter or _existing_bounded_search
        self._fetch_adapter = fetch_adapter or _existing_bounded_fetch
        self._requests = 0
        self._response_bytes = 0
        self._sources: set[str] = set()

    @property
    def snapshot(self) -> ResearchToolSnapshot:
        return ResearchToolSnapshot(
            physical_requests_charged=self._requests,
            response_bytes_consumed=self._response_bytes,
            unique_sources_observed=len(self._sources),
        )

    async def search(self, query: str, max_results: int) -> str:
        """Return only normalized source-cited results from bounded search."""

        query = _bounded_text(
            query,
            maximum=MAX_SEARCH_QUERY_CHARS,
            label="Research search query",
        )
        _bounded_integer(
            max_results,
            1,
            self._limits.max_results_per_search,
            "Research result count",
        )
        # The free path expands to at most two search requests and then fetches
        # at most ``max_results`` pages. Tavily uses fewer requests, so this is
        # a conservative charge that never undercounts the existing path.
        self._charge_requests(2 + max_results)
        raw = await self._search_adapter(query, max_results)
        self._charge_response(raw)
        hits = _parse_cited_search_results(
            raw,
            maximum=max_results,
            retrieved_at=datetime.now(timezone.utc),
        )
        accepted: list[ResearchSearchHit] = []
        for hit in hits:
            if hit.public_url in self._sources:
                continue
            if len(self._sources) >= self._limits.max_sources:
                raise ResearchToolLimitError(
                    "Research source limit reached"
                )
            self._sources.add(hit.public_url)
            accepted.append(hit)
        return _render_cited_search_results(tuple(accepted))

    async def fetch(self, url: str, max_chars: int) -> str:
        """Fetch one normalized public HTTPS source through the existing path."""

        _bounded_integer(
            max_chars,
            1,
            self._limits.max_fetch_chars,
            "Research fetch character count",
        )
        canonical_url = canonicalize_public_url(
            url,
            require_https=True,
        )
        if (
            canonical_url not in self._sources
            and len(self._sources) >= self._limits.max_sources
        ):
            raise ResearchToolLimitError("Research source limit reached")
        self._charge_requests(1)
        raw = await self._fetch_adapter(canonical_url, max_chars)
        if not isinstance(raw, str) or len(raw) > max_chars:
            raise ResearchToolError(
                "Research fetch returned an invalid bounded response"
            )
        self._charge_response(raw)
        self._sources.add(canonical_url)
        return raw

    def _charge_requests(self, amount: int) -> None:
        if self._requests + amount > self._limits.max_requests:
            raise ResearchToolLimitError("Research request limit reached")
        self._requests += amount

    def _charge_response(self, value: object) -> None:
        if not isinstance(value, str):
            raise ResearchToolError("Research response must be text")
        size = len(value.encode("utf-8"))
        if self._response_bytes + size > self._limits.max_response_bytes:
            raise ResearchToolLimitError(
                "Research response-byte limit reached"
            )
        self._response_bytes += size


async def _existing_bounded_search(query: str, max_results: int) -> str:
    from ai.web_search import search

    return await search(
        query,
        max_results,
        allow_provider_fallback=False,
    )


async def _existing_bounded_fetch(url: str, max_chars: int) -> str:
    from ai.web_search import fetch

    return await fetch(url, max_chars)


def _parse_cited_search_results(
    raw: str,
    *,
    maximum: int,
    retrieved_at: datetime,
) -> tuple[ResearchSearchHit, ...]:
    if not isinstance(raw, str):
        raise ResearchToolError("Research search response must be text")
    hits: list[ResearchSearchHit] = []
    header: tuple[str, str] | None = None
    excerpt_lines: list[str] = []

    def append_current() -> None:
        if header is None or len(hits) >= maximum:
            return
        title, url = header
        try:
            hit = ResearchSearchHit(
                title=title,
                public_url=url,
                excerpt="\n".join(excerpt_lines).strip(),
                retrieved_at=retrieved_at,
            )
        except ResearchValidationError:
            return
        if hit.public_url not in {
            existing.public_url for existing in hits
        }:
            hits.append(hit)

    for line in raw.splitlines():
        match = _RESULT_HEADER.match(line.strip())
        if match is not None and " — " in match.group(2):
            append_current()
            title, url = match.group(2).rsplit(" — ", 1)
            header = (title, url)
            excerpt_lines = []
            continue
        if header is not None:
            consumed = sum(len(item) for item in excerpt_lines)
            consumed += max(0, len(excerpt_lines) - 1)
            remaining = MAX_SEARCH_EXCERPT_CHARS - consumed
            if remaining > 0:
                excerpt_lines.append(line[:remaining])
    append_current()
    return tuple(hits)


def _render_cited_search_results(
    hits: tuple[ResearchSearchHit, ...],
) -> str:
    parts = []
    for index, hit in enumerate(hits, 1):
        body = hit.excerpt.strip()
        parts.append(
            f"[{index}] {hit.title} — {hit.public_url}"
            + (f"\n{body}" if body else "")
        )
    return "\n\n".join(parts)


def cited_source_urls(value: str) -> tuple[str, ...]:
    """Extract only normalized cited HTTPS result URLs from brokered search."""

    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_RESEARCH_RESPONSE_BYTES
    ):
        raise ResearchToolError(
            "Cited research context is invalid"
        )
    hits = _parse_cited_search_results(
        value,
        maximum=MAX_RESEARCH_SEARCH_SOURCES,
        retrieved_at=datetime.now(timezone.utc),
    )
    return tuple(hit.public_url for hit in hits)


def _bounded_text(value: object, *, maximum: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ResearchToolError(f"{label} is invalid")
    return value.strip()


def _bounded_integer(
    value: object,
    minimum: int,
    maximum: int,
    label: str,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResearchToolError(f"{label} is invalid")


__all__ = [
    "BoundedResearchToolAdapter",
    "ResearchSearchHit",
    "ResearchToolError",
    "ResearchToolLimitError",
    "ResearchToolLimits",
    "ResearchToolSnapshot",
    "cited_source_urls",
]
