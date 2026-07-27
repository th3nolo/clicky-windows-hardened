"""Validated per-provider model restoration and conservative fallbacks."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping


MAX_MODEL_ID_LENGTH = 256
MAX_MODEL_CHOICES = 256
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_REVIEWED_LOW_COST_DEFAULTS = {
    "claude": ("claude-haiku-4-5-20251001",),
    "openai": ("gpt-4o-mini",),
    "gemini": ("gemini-2.5-flash", "gemini-2.0-flash"),
}


@dataclass(frozen=True, slots=True)
class ModelResolution:
    model_id: str | None
    status: str
    previous_model: str = ""


def valid_model_id(value: object) -> bool:
    return isinstance(value, str) and bool(_MODEL_ID.fullmatch(value))


def normalized_model_records(
    records: Iterable[Mapping[str, object]],
) -> list[dict]:
    """Return a bounded, de-duplicated copy of provider model metadata."""

    normalized = []
    seen = set()
    for record in records:
        if len(normalized) >= MAX_MODEL_CHOICES or not isinstance(record, Mapping):
            break
        model_id = record.get("id")
        if not valid_model_id(model_id) or model_id in seen:
            continue
        seen.add(model_id)
        normalized.append(
            {
                "id": model_id,
                "label": (
                    record.get("label")
                    if isinstance(record.get("label"), str)
                    and len(record["label"]) <= MAX_MODEL_ID_LENGTH
                    else model_id
                ),
                "vision": bool(record.get("vision", False)),
                "multiplier": _safe_multiplier(record.get("multiplier")),
            }
        )
    return normalized


def _safe_multiplier(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    if numeric < 0 or numeric > 1000:
        return None
    return numeric


def resolve_model(
    provider: str,
    records: Iterable[Mapping[str, object]],
    saved_model: str,
) -> ModelResolution:
    """Restore a valid saved model or choose only a reviewed cheap/free one."""

    models = normalized_model_records(records)
    model_ids = {model["id"] for model in models}
    saved = saved_model if valid_model_id(saved_model) else ""
    if saved and saved in model_ids:
        return ModelResolution(saved, "restored")

    fallback = None
    if provider == "copilot":
        free = [
            model
            for model in models
            if model["multiplier"] == 0
        ]
        free.sort(key=lambda model: (not model["vision"], model["id"]))
        fallback = free[0]["id"] if free else None
    else:
        fallback = next(
            (
                model_id
                for model_id in _REVIEWED_LOW_COST_DEFAULTS.get(provider, ())
                if model_id in model_ids
            ),
            None,
        )

    if fallback:
        return ModelResolution(
            fallback,
            "stale-fallback" if saved else "default",
            saved,
        )
    return ModelResolution(
        None,
        "selection-required",
        saved,
    )


def model_is_available(
    model_id: str,
    records: Iterable[Mapping[str, object]],
) -> bool:
    if not valid_model_id(model_id):
        return False
    return any(
        record["id"] == model_id
        for record in normalized_model_records(records)
    )
