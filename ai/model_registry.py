"""
Live model discovery and caching for reviewed direct cloud providers.

The original providers expose these model-list endpoints:
  • Anthropic:  GET /v1/models                    (key in x-api-key)
  • OpenAI:     GET /v1/models                    (key in Authorization)
  • Gemini:     GET /v1beta/models                (key in x-goog-api-key)

Cached per-provider to %LOCALAPPDATA%\\Clicky\\models_<provider>.json with a
30-day TTL — long enough that you don't refetch constantly, short enough
that new model releases land within a month without manual refresh.

Kimi Code, MiniMax Token Plan, DeepSeek, and Qwen use the fixed endpoints in
provider_catalog.py. GitHub Copilot has its own implementation in
github_copilot_provider.py because its flow is more complex.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx

from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS
from config import cfg


CACHE_TTL_SECONDS = 30 * 24 * 60 * 60   # 30 days
MAX_MODEL_RESPONSE_BYTES = 1024 * 1024


# Curated fallback lists — used when the live endpoint is unreachable AND
# the on-disk cache is empty. Reasonable defaults so Clicky still works
# offline / on first run before refresh completes.
_FALLBACKS: dict[str, list[dict]] = {
    "claude": [
        {"id": "claude-sonnet-4-6",          "label": "Claude Sonnet 4.6", "vision": True},
        {"id": "claude-opus-4-7",            "label": "Claude Opus 4.7",   "vision": True},
        {"id": "claude-haiku-4-5-20251001",  "label": "Claude Haiku 4.5",  "vision": True},
    ],
    "openai": [
        {"id": "gpt-4o",        "label": "GPT-4o",       "vision": True},
        {"id": "gpt-4o-mini",   "label": "GPT-4o mini",  "vision": True},
        {"id": "gpt-4-turbo",   "label": "GPT-4 Turbo",  "vision": True},
    ],
    "gemini": [
        {"id": "gemini-2.5-flash", "label": "Gemini 2.5 Flash", "vision": True},
        {"id": "gemini-2.5-pro",   "label": "Gemini 2.5 Pro",   "vision": True},
        {"id": "gemini-2.0-flash", "label": "Gemini 2.0 Flash", "vision": True},
    ],
    "kimi_code": [
        {
            "id": "kimi-for-coding",
            "label": "Kimi for Coding",
            "vision": False,
        },
        {
            "id": "kimi-for-coding-highspeed",
            "label": "Kimi for Coding High-Speed",
            "vision": False,
        },
        {"id": "k3", "label": "Kimi K3", "vision": False},
    ],
    "minimax_plan": [
        {"id": "MiniMax-M2.7", "label": "MiniMax M2.7", "vision": False},
        {
            "id": "MiniMax-M2.7-highspeed",
            "label": "MiniMax M2.7 High-Speed",
            "vision": False,
        },
    ],
    "deepseek": [
        {"id": "deepseek-chat", "label": "DeepSeek Chat", "vision": False},
        {
            "id": "deepseek-reasoner",
            "label": "DeepSeek Reasoner",
            "vision": False,
        },
    ],
    "qwen": [
        {"id": "qwen3.5-plus", "label": "Qwen 3.5 Plus", "vision": True},
        {
            "id": "qwen3-coder-next",
            "label": "Qwen 3 Coder Next",
            "vision": False,
        },
        {
            "id": "qwen3-coder-plus",
            "label": "Qwen 3 Coder Plus",
            "vision": False,
        },
    ],
    "codex_agent": [
        {
            "id": "codex-default",
            "label": "Codex plan default",
            "vision": True,
        },
    ],
    "qwen_code_agent": [
        {
            "id": "qwen3.7-plus",
            "label": "Qwen 3.7 Plus",
            "vision": True,
        },
        {"id": "qwen3.6-plus", "label": "Qwen 3.6 Plus", "vision": True},
        {"id": "qwen3.5-plus", "label": "Qwen 3.5 Plus", "vision": True},
        {
            "id": "qwen3-max-2026-01-23",
            "label": "Qwen 3 Max (2026-01-23)",
            "vision": False,
        },
        {
            "id": "qwen3-coder-next",
            "label": "Qwen 3 Coder Next",
            "vision": False,
        },
        {
            "id": "qwen3-coder-plus",
            "label": "Qwen 3 Coder Plus",
            "vision": False,
        },
    ],
}


def _data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = Path(base) / "Clicky"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_path(provider: str) -> Path:
    return _data_dir() / f"models_{provider}.json"


# ─── Per-provider live fetchers ───────────────────────────────────────────────

async def _fetch_claude() -> list[dict]:
    if not cfg.anthropic_api_key:
        return []
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            "https://api.anthropic.com/v1/models",
            headers={
                "x-api-key": cfg.anthropic_api_key,
                "anthropic-version": "2023-06-01",
            },
        )
    r.raise_for_status()
    data = r.json().get("data", [])
    out = []
    for m in data:
        mid = m.get("id") or m.get("name")
        if not mid:
            continue
        # All current Claude models are vision-capable; future ones likely too.
        out.append({
            "id": mid,
            "label": m.get("display_name") or mid,
            "vision": True,
        })
    # Newest first (Anthropic returns newest first already, but be defensive)
    out.sort(key=lambda m: m["id"], reverse=True)
    return out


async def _fetch_openai() -> list[dict]:
    if not cfg.openai_api_key:
        return []
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {cfg.openai_api_key}"},
        )
    r.raise_for_status()
    data = r.json().get("data", [])
    out = []
    # Filter to chat-completion-capable models. OpenAI's /v1/models returns
    # everything (embeddings, TTS, image-gen, audio, etc.) so we whitelist by
    # known prefixes. Vision flag is true for the gpt-4o family + o3-vision.
    chat_prefixes = ("gpt-4", "gpt-5", "o1", "o3", "o4", "chatgpt-")
    # Models that match a chat prefix but are NOT chat-completion models —
    # picking one of these makes Clicky silently stop responding (e.g.
    # "chatgpt-image-latest" generates images, it can't hold a conversation).
    non_chat_markers = ("image", "audio", "realtime", "tts", "transcribe",
                        "embed", "moderation", "dall", "instruct", "codex")
    vision_prefixes = ("gpt-4o", "gpt-4-turbo", "gpt-4-vision", "gpt-5",
                       "o1-", "o3-", "o4-")
    seen = set()
    for m in data:
        mid = m.get("id")
        if not mid or mid in seen:
            continue
        if not mid.startswith(chat_prefixes):
            continue
        if any(marker in mid for marker in non_chat_markers):
            continue
        # Skip dated snapshots — they're noise. Keep only the alias forms.
        if any(c.isdigit() and "-" in mid[mid.index(c):] for c in mid if False):
            pass
        # Drop fine-tune / preview-snapshot variants like ".../2024-08-06"
        if mid.count("-") >= 4 and any(seg.isdigit() for seg in mid.split("-")):
            continue
        seen.add(mid)
        out.append({
            "id": mid,
            "label": mid,
            "vision": mid.startswith(vision_prefixes),
        })
    out.sort(key=lambda m: m["id"])
    return out


async def _fetch_gemini() -> list[dict]:
    if not cfg.google_api_key:
        return []
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            headers={"x-goog-api-key": cfg.google_api_key},
        )
    r.raise_for_status()
    data = r.json().get("models", [])
    out = []
    for m in data:
        # Names look like "models/gemini-2.5-flash" — strip the prefix
        full = m.get("name", "")
        mid = full.replace("models/", "")
        methods = m.get("supportedGenerationMethods", [])
        if "generateContent" not in methods:
            continue   # skip embedding-only / TTS-only models
        if not mid:
            continue
        out.append({
            "id": mid,
            "label": m.get("displayName") or mid,
            # All Gemini 1.5+ models accept images as input
            "vision": "vision" in mid or "gemini-1.5" in mid or "gemini-2" in mid
                      or "gemini-3" in mid,
        })
    # Sort: newer first (rough heuristic — versions in name)
    out.sort(key=lambda m: m["id"], reverse=True)
    return out


def _compatible_vision(provider: str, model_id: str) -> bool:
    if provider == "qwen":
        return model_id.startswith(("qwen3.5-plus", "qwen3.6-plus", "qwen3.7-plus"))
    return False


async def _fetch_openai_compatible(provider: str) -> list[dict]:
    spec = OPENAI_COMPATIBLE_SPECS[provider]
    api_key = getattr(cfg, spec.credential_attribute, None)
    if not api_key:
        return []
    url = f"{spec.base_url.rstrip('/')}/models"
    async with httpx.AsyncClient(
        timeout=15,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        async with client.stream(
            "GET",
            url,
            headers={"Authorization": f"Bearer {api_key}"},
        ) as response:
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_MODEL_RESPONSE_BYTES:
                    raise ValueError("Provider model response exceeds size limit")
    payload = json.loads(bytes(body))
    data = payload.get("data", []) if isinstance(payload, dict) else []
    out = []
    for record in data:
        if not isinstance(record, dict):
            continue
        model_id = record.get("id")
        if not isinstance(model_id, str):
            continue
        out.append({
            "id": model_id,
            "label": model_id,
            "vision": _compatible_vision(provider, model_id),
        })
    return out


async def _fetch_kimi_code() -> list[dict]:
    return await _fetch_openai_compatible("kimi_code")


async def _fetch_minimax_plan() -> list[dict]:
    return await _fetch_openai_compatible("minimax_plan")


async def _fetch_deepseek() -> list[dict]:
    return await _fetch_openai_compatible("deepseek")


async def _fetch_qwen() -> list[dict]:
    return await _fetch_openai_compatible("qwen")


_FETCHERS = {
    "claude":  _fetch_claude,
    "openai":  _fetch_openai,
    "gemini":  _fetch_gemini,
    "kimi_code": _fetch_kimi_code,
    "minimax_plan": _fetch_minimax_plan,
    "deepseek": _fetch_deepseek,
    "qwen": _fetch_qwen,
}


# ─── Public API ───────────────────────────────────────────────────────────────

def cached_models(provider: str) -> list[dict]:
    """Read on-disk cache, falling back to a curated list if missing."""
    from ai.model_selection import normalized_model_records

    p = _cache_path(provider)
    if p.exists():
        try:
            blob = json.loads(p.read_text())
            ms = normalized_model_records(blob.get("models", []))
            if ms:
                return ms
        except Exception:
            pass
    return normalized_model_records(_FALLBACKS.get(provider, []))


def cache_is_stale(provider: str, ttl: int = CACHE_TTL_SECONDS) -> bool:
    p = _cache_path(provider)
    if not p.exists():
        return True
    try:
        blob = json.loads(p.read_text())
        return (time.time() - float(blob.get("fetched_at", 0))) > ttl
    except Exception:
        return True


async def refresh(provider: str) -> list[dict]:
    """Fetch live + write to cache. Returns the new model list (raises on error)."""
    fetcher = _FETCHERS.get(provider)
    if not fetcher:
        raise ValueError(f"No live model fetcher for provider '{provider}'")
    models = await fetcher()
    if not models:
        # No key → no models. Don't overwrite cache with empty list.
        return cached_models(provider)
    blob = {"fetched_at": time.time(), "models": models}
    _cache_path(provider).write_text(json.dumps(blob, indent=2))
    return models


async def refresh_all_stale() -> dict[str, int]:
    """Refresh every provider whose cache is stale. Returns counts per provider."""
    results = {}
    for provider in _FETCHERS:
        if cache_is_stale(provider):
            try:
                ms = await refresh(provider)
                results[provider] = len(ms)
            except Exception as e:
                results[provider] = -1   # signals failure
    return results


def model_ids(provider: str) -> list[str]:
    return [m["id"] for m in cached_models(provider)]


def best_default(provider: str) -> Optional[str]:
    """Pick only the provider's reviewed safe default."""
    from ai.model_selection import resolve_model

    return resolve_model(provider, cached_models(provider), "").model_id


# ─── CLI: `python -m ai.model_registry [show|refresh] [provider]` ─────────────

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) >= 2 else "show"
    target = sys.argv[2] if len(sys.argv) >= 3 else None

    if cmd == "show":
        for prov in (target,) if target else _FETCHERS:
            stale = "stale" if cache_is_stale(prov) else "fresh"
            print(f"\n[{prov}] {stale}")
            for m in cached_models(prov):
                v = "👁" if m.get("vision") else "  "
                print(f"  {v} {m['id']}")
    elif cmd == "refresh":
        async def _run():
            for prov in (target,) if target else _FETCHERS:
                try:
                    ms = await refresh(prov)
                    print(f"[{prov}] refreshed {len(ms)} models")
                except Exception as e:
                    print(f"[{prov}] FAILED: {e}")
        asyncio.run(_run())
    else:
        providers = "|".join(_FETCHERS)
        print(f"Usage: python -m ai.model_registry [show|refresh] [{providers}]")
