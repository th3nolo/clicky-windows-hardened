"""Validate explicit Clicky-owned endpoint configuration without doing I/O."""

from urllib.parse import urlsplit


def provider_endpoint(value: str, *, default: str) -> str:
    if not value:
        return default
    if any(char.isspace() or ord(char) < 32 or 127 <= ord(char) <= 159 for char in value) or "\\" in value:
        raise ValueError("Provider endpoint must be an HTTP(S) URL without whitespace or controls")
    try:
        parts = urlsplit(value)
        valid = (
            parts.scheme in {"http", "https"}
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and not parts.netloc.endswith(":")
            and "?" not in value
            and "#" not in value
        )
        # Accessing port validates malformed/non-numeric/out-of-range values.
        parts.port
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Provider endpoint requires an HTTP(S) host and no credentials, query or fragment")
    return value.rstrip("/")


def router_vision_models(endpoint: str, value: str) -> dict[str, tuple[str, ...]]:
    """Bind an operator's bounded model declaration to one explicit router."""
    from ai.model_selection import MAX_MODEL_CHOICES, valid_model_id

    if not value:
        return {}
    if not endpoint or len(value) > 64 * 1024:
        raise ValueError("Custom vision models require an explicit Clicky router endpoint")
    models = tuple(dict.fromkeys(item.strip() for item in value.split(",")))
    if len(models) > MAX_MODEL_CHOICES or not all(valid_model_id(item) for item in models):
        raise ValueError("Custom vision models must be a bounded comma-separated list of model IDs")
    return {provider_endpoint(endpoint, default=""): models}
