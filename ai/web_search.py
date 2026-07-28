"""
Real-time web search for Clicky — tutor-grade grounding layer.

Strategy (free path, no API key required):
  1. Expand the user's question into 1-2 focused sub-queries.
  2. Hit DuckDuckGo HTML search for each to collect top result URLs.
  3. Fetch the top pages concurrently and strip to plain text.
  4. Assemble a compact, source-cited context block for the LLM.

If TAVILY_API_KEY is set, Tavily's deep-search is used instead (higher
signal-to-noise, faster, cleaner summaries).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from html import unescape
from typing import List, Tuple
from urllib.parse import unquote, urljoin, urlparse, parse_qs

import httpx

from config import cfg


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
MAX_PAGES = 3
PAGE_CHAR_BUDGET = 1400            # per-page excerpt size
OVERALL_CHAR_BUDGET = 5500         # cap on the whole context block
FETCH_TIMEOUT = 6.0
MAX_REDIRECTS = 4
MAX_PAGE_BYTES = 1_000_000
MAX_SEARCH_BYTES = 512_000
MAX_TAVILY_BYTES = 2_000_000

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_TEXT_TYPES = _HTML_TYPES | {"text/plain"}
_JSON_TYPES = {"application/json"}
_BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


def _is_public_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_global and not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


# ── Public API ────────────────────────────────────────────────────────────────

async def search(
    query: str,
    max_results: int = MAX_PAGES,
    *,
    allow_provider_fallback: bool = True,
) -> str:
    """Return source-cited context, optionally refusing provider fallback."""
    query = query.strip()
    if not query:
        return ""
    if type(allow_provider_fallback) is not bool:
        raise TypeError("search fallback policy must be explicit")

    if cfg.search_provider() == "tavily":
        try:
            return await _tavily(query, max_results)
        except Exception:
            if not allow_provider_fallback:
                raise
            pass  # legacy interactive path falls through to the free provider

    return await _free_deep_search(query, max_results)


async def fetch(url: str, max_chars: int = PAGE_CHAR_BUDGET) -> str:
    """Fetch one public HTTPS text resource through the hardened request path."""
    if type(max_chars) is not int or not 1 <= max_chars <= OVERALL_CHAR_BUDGET:
        raise ValueError("fetch character limit is invalid")
    async with httpx.AsyncClient(
        timeout=FETCH_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
        trust_env=False,
    ) as client:
        raw, content_type = await _bounded_request(
            client,
            url,
            allowed_types=_TEXT_TYPES,
            max_bytes=MAX_PAGE_BYTES,
        )
    return _truncate(
        _html_to_text(_decode_text(raw, content_type)),
        max_chars,
    )


def build_search_context(results: str) -> str:
    if not results.strip():
        return ""
    return (
        "\n\n[Web Search Results — ground factual / recent claims in these. "
        "Cite source numbers like [1] when you use them.]\n"
        + results
        + "\n[End of search results]\n"
    )


# ── Tavily (premium path) ─────────────────────────────────────────────────────

async def _tavily(query: str, max_results: int) -> str:
    url = "https://api.tavily.com/search"
    payload = {
        "api_key": cfg.tavily_api_key,
        "query": query,
        "search_depth": "advanced",
        "max_results": max_results,
        "include_answer": True,
        "include_raw_content": True,
    }
    async with httpx.AsyncClient(
        timeout=12,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        raw, _ = await _bounded_request(
            client,
            url,
            method="POST",
            json_body=payload,
            allowed_types=_JSON_TYPES,
            max_bytes=MAX_TAVILY_BYTES,
            allow_redirects=False,
        )
        data = json.loads(raw.decode("utf-8"))

    parts: list[str] = []
    if data.get("answer"):
        parts.append(f"Summary: {data['answer']}")

    for i, result in enumerate(data.get("results", []), 1):
        title = result.get("title", "").strip()
        url_str = result.get("url", "")
        body = (result.get("raw_content") or result.get("content") or "").strip()
        body = body[:PAGE_CHAR_BUDGET]
        parts.append(f"[{i}] {title} — {url_str}\n{body}")

    return _truncate("\n\n".join(parts), OVERALL_CHAR_BUDGET)


# ── Free deep search: DuckDuckGo HTML + page fetch ────────────────────────────

async def _free_deep_search(query: str, max_results: int) -> str:
    sub_queries = _expand_query(query)

    seen: set[str] = set()
    hits: list[Tuple[str, str]] = []   # (title, url)

    async with httpx.AsyncClient(
        timeout=FETCH_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
        trust_env=False,
    ) as client:
        search_tasks = [_ddg_html_search(client, q) for q in sub_queries]
        search_results = await asyncio.gather(*search_tasks, return_exceptions=True)

        for result in search_results:
            if isinstance(result, Exception):
                continue
            for title, url in result:
                if url in seen:
                    continue
                seen.add(url)
                hits.append((title, url))
                if len(hits) >= max_results * 2:
                    break
            if len(hits) >= max_results * 2:
                break

        hits = hits[:max_results]
        if not hits:
            return ""

        fetch_tasks = [_fetch_text(client, url) for _, url in hits]
        pages = await asyncio.gather(*fetch_tasks, return_exceptions=True)

    parts: list[str] = []
    for i, ((title, url), page) in enumerate(zip(hits, pages), 1):
        body = "" if isinstance(page, Exception) else page
        body = (body or "").strip()[:PAGE_CHAR_BUDGET]
        if not body:
            continue
        parts.append(f"[{i}] {title} — {url}\n{body}")

    return _truncate("\n\n".join(parts), OVERALL_CHAR_BUDGET)


# ── Query expansion ───────────────────────────────────────────────────────────

_STOPWORDS = {
    "what", "whats", "what's", "how", "why", "when", "where", "who",
    "is", "are", "the", "a", "an", "of", "on", "in", "to", "for",
    "do", "does", "i", "you", "me", "this", "that", "please", "tell",
    "explain", "clicky", "hey",
}


def _expand_query(query: str) -> list[str]:
    """Produce 1-2 focused queries: the original + one stripped/reformulated."""
    from datetime import datetime
    base = query.strip()
    queries = [base]

    tokens = re.findall(r"[A-Za-z0-9\-']+", base.lower())
    keywords = [t for t in tokens if t not in _STOPWORDS and len(t) > 1]

    # For recency-sensitive questions ("best X", "top X", "who is X now",
    # "latest X", "current X") append the current year so DDG surfaces
    # fresh results instead of evergreen pages.
    RECENCY_RE = re.compile(
        r"\b(best|top|greatest|popular|trending|latest|current|"
        r"now|today|2024|2025|2026)\b", re.IGNORECASE
    )
    WHO_IS_RE = re.compile(r"\b(who\s+is|who\s+are|what\s+is\s+the\s+best|"
                           r"what\s+are\s+the\s+top)\b", re.IGNORECASE)
    year = str(datetime.now().year)

    if RECENCY_RE.search(base) or WHO_IS_RE.search(base):
        # Build a tight keyword query + year for the freshest hits
        kw_year = " ".join(keywords)
        if year not in kw_year:
            kw_year = kw_year + " " + year
        if kw_year.strip() != base.lower():
            queries.append(kw_year.strip())
    elif keywords and len(keywords) < len(tokens):
        kw = " ".join(keywords)
        if kw and kw != base.lower():
            queries.append(kw)

    return queries[:2]


# ── DuckDuckGo HTML scraper ───────────────────────────────────────────────────

_DDG_URL = "https://html.duckduckgo.com/html/"
_RESULT_LINK_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)


async def _ddg_html_search(client: httpx.AsyncClient, query: str) -> list[Tuple[str, str]]:
    """Search DuckDuckGo through the bounded, validated fetch path."""
    try:
        raw, content_type = await _bounded_request(
            client,
            _DDG_URL,
            method="POST",
            form_data={"q": query, "kl": "us-en"},
            allowed_types=_HTML_TYPES,
            max_bytes=MAX_SEARCH_BYTES,
        )
        html = _decode_text(raw, content_type)
    except Exception:
        return []

    out: list[Tuple[str, str]] = []
    for match in _RESULT_LINK_RE.finditer(html):
        url = _normalize_ddg_url(match.group(1))
        title = _html_to_text(match.group(2)).strip()
        if url and title:
            out.append((title, url))
            if len(out) >= 4:
                break
    return out


def _normalize_ddg_url(href: str) -> str:
    """DDG wraps real URLs in /l/?uddg=<encoded>. Unwrap them."""
    if href.startswith("//"):
        href = "https:" + href
    if "duckduckgo.com/l/" in href or href.startswith("/l/"):
        try:
            qs = parse_qs(urlparse(href).query)
            target = qs.get("uddg", [""])[0]
            if target:
                return unquote(target)
        except Exception:
            return ""
    if href.startswith("http"):
        return href
    return ""



def _parse_public_https_url(url: str) -> tuple[str, int]:
    """Return a normalized hostname and port, rejecting unsafe URL syntax."""
    if not isinstance(url, str) or not url or len(url) > 4096:
        raise ValueError("invalid URL")
    try:
        parsed = urlparse(url)
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("invalid URL") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("only HTTPS URLs are permitted")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("URL has no hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not permitted")
    if parsed.hostname.endswith("."):
        raise ValueError("trailing-dot hostnames are not permitted")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("invalid hostname") from exc
    if host == "localhost" or host.endswith(_BLOCKED_HOST_SUFFIXES):
        raise ValueError("local hostnames are not permitted")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not _is_public_address(literal):
        raise ValueError("non-public IP addresses are not permitted")
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return host, port


async def _validate_public_https_url(url: str) -> None:
    """Reject URLs whose syntax or DNS answers could reach a local network."""
    host, port = _parse_public_https_url(url)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return
    try:
        answers = await asyncio.wait_for(
            asyncio.to_thread(
                socket.getaddrinfo, host, port, type=socket.SOCK_STREAM
            ),
            timeout=FETCH_TIMEOUT,
        )
    except (OSError, UnicodeError, TimeoutError) as exc:
        raise ValueError("hostname could not be resolved safely") from exc
    addresses = {answer[4][0].split("%", 1)[0] for answer in answers}
    if not addresses:
        raise ValueError("hostname has no addresses")
    for address in addresses:
        try:
            resolved = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("DNS returned an invalid address") from exc
        if not _is_public_address(resolved):
            raise ValueError("DNS returned a non-public address")


def _validate_connected_peer(response) -> None:
    """Verify the socket peer selected by HTTPX is globally routable."""
    try:
        network_stream = response.extensions["network_stream"]
        server_addr = network_stream.get_extra_info("server_addr")
        address = server_addr[0] if isinstance(server_addr, tuple) else server_addr
        if not isinstance(address, str):
            raise ValueError("missing connected peer address")
        peer = ipaddress.ip_address(address.split("%", 1)[0])
    except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
        raise ValueError("connected peer could not be verified") from exc
    if not _is_public_address(peer):
        raise ValueError("connection reached a non-public address")


def _content_type(headers) -> str:
    raw = headers.get("content-type", "")
    return raw.split(";", 1)[0].strip().lower()


def _decode_text(raw: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"\bcharset\s*=\s*[\"']?([^;\"'\s]+)", content_type, re.I)
    if match:
        candidate = match.group(1).strip().lower()
        if candidate in {"utf-8", "utf8", "us-ascii", "iso-8859-1", "latin-1"}:
            charset = candidate
    return raw.decode(charset, errors="replace")


async def _bounded_request(
    client: httpx.AsyncClient,
    url: str,
    *,
    method: str = "GET",
    form_data: dict | None = None,
    json_body: dict | None = None,
    allowed_types: set[str],
    max_bytes: int,
    allow_redirects: bool = True,
) -> tuple[bytes, str]:
    """Fetch only after URL, redirect, type, and decoded-size checks."""
    current = url
    current_method = method.upper()
    for redirect_count in range(MAX_REDIRECTS + 1):
        await _validate_public_https_url(current)
        async with client.stream(
            current_method,
            current,
            data=form_data if current_method != "GET" else None,
            json=json_body if current_method != "GET" else None,
            follow_redirects=False,
        ) as response:
            # DNS can change between validation and connection. Verify the
            # actual socket peer before processing redirects, headers, or body.
            _validate_connected_peer(response)
            if response.status_code in _REDIRECT_STATUSES:
                if not allow_redirects or redirect_count >= MAX_REDIRECTS:
                    raise ValueError("redirect refused")
                location = response.headers.get("location")
                if not location:
                    raise ValueError("redirect has no destination")
                current = urljoin(current, location)
                if current_method != "GET" and response.status_code in {307, 308}:
                    raise ValueError("request-body redirect refused")
                if response.status_code in {301, 302, 303}:
                    current_method = "GET"
                    form_data = None
                    json_body = None
                continue
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            if _content_type(response.headers) not in allowed_types:
                raise ValueError("response content type is not permitted")
            declared = response.headers.get("content-length")
            if declared:
                try:
                    declared_size = int(declared)
                except ValueError as exc:
                    raise ValueError("invalid content length") from exc
                if declared_size < 0 or declared_size > max_bytes:
                    raise ValueError("response is too large")
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise ValueError("response exceeded byte limit")
                chunks.append(chunk)
            return b"".join(chunks), content_type
    raise ValueError("too many redirects")

# ── Page fetch + text extraction ──────────────────────────────────────────────

_SCRIPT_STYLE_RE = re.compile(r"<(script|style|noscript)\b[^>]*>.*?</\1>",
                              re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


async def _fetch_text(client: httpx.AsyncClient, url: str) -> str:
    try:
        raw, content_type = await _bounded_request(
            client,
            url,
            allowed_types=_TEXT_TYPES,
            max_bytes=MAX_PAGE_BYTES,
        )
        return _html_to_text(_decode_text(raw, content_type))
    except Exception:
        return ""


def _html_to_text(html: str) -> str:
    html = _SCRIPT_STYLE_RE.sub(" ", html)

    # Prefer <main> or <article> if present; otherwise whole body
    body_match = re.search(
        r"<(article|main)\b[^>]*>(.*?)</\1>", html, re.IGNORECASE | re.DOTALL,
    )
    if body_match:
        core = body_match.group(2)
    else:
        body_match = re.search(r"<body\b[^>]*>(.*?)</body>",
                               html, re.IGNORECASE | re.DOTALL)
        core = body_match.group(1) if body_match else html

    text = _TAG_RE.sub(" ", core)
    text = unescape(text)
    text = _WS_RE.sub(" ", text).strip()
    return text


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
