"""Read-only Ollama detection and immutable model identity checks.

The hardened Windows build never downloads, launches, or pulls anything. Ollama
and each configured model must already be running locally, and every model must
match a caller-configured SHA-256 digest before the provider is usable.
"""

from __future__ import annotations

import hmac
import json
import re
import shutil
import sys
from typing import List, Optional

import httpx

from config import cfg


OLLAMA_DOWNLOAD_PAGE = "https://ollama.com/download/windows"
DEFAULT_TEXT_MODEL = "llama3.2:3b"
DEFAULT_VISION_MODEL = "qwen2.5vl:3b"
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_MAX_TAGS_RESPONSE_BYTES = 1024 * 1024


class OllamaIdentityError(RuntimeError):
    """Raised when local Ollama state lacks an immutable configured identity."""


def _tags_response(timeout: float = 3.0) -> dict:
    """Read bounded JSON metadata directly from loopback without env proxies."""
    base = cfg.ollama_host.rstrip("/")
    chunks: list[bytes] = []
    total = 0
    with httpx.Client(
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        with client.stream("GET", f"{base}/api/tags") as response:
            response.raise_for_status()
            content_type = response.headers.get("content-type", "").lower()
            if not content_type.startswith("application/json"):
                raise OllamaIdentityError(
                    "Ollama returned a non-JSON model metadata response."
                )
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > _MAX_TAGS_RESPONSE_BYTES:
                    raise OllamaIdentityError(
                        "Ollama model metadata exceeded the safe response limit."
                    )
                chunks.append(chunk)
    try:
        data = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OllamaIdentityError("Ollama returned invalid JSON metadata.") from exc
    if not isinstance(data, dict):
        raise OllamaIdentityError("Ollama returned invalid model metadata.")
    return data


def is_ollama_running(timeout: float = 1.5) -> bool:
    """Return True if the fixed local Ollama HTTP server is reachable."""
    try:
        _tags_response(timeout)
        return True
    except Exception:
        return False


def is_ollama_installed() -> bool:
    """Return True if an ollama executable is already present on PATH."""
    return shutil.which("ollama") is not None


def list_installed_model_metadata() -> List[dict[str, str]]:
    """Return local model names and immutable digests from Ollama /api/tags."""
    try:
        raw_models = _tags_response().get("models", [])
    except Exception:
        return []
    if not isinstance(raw_models, list):
        return []
    models: List[dict[str, str]] = []
    for item in raw_models:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("model")
        digest = item.get("digest")
        if isinstance(name, str) and isinstance(digest, str):
            models.append({"name": name, "digest": digest})
    return models


def list_installed_models() -> List[str]:
    """Return names for locally present models; retained for model pickers."""
    return [item["name"] for item in list_installed_model_metadata()]


def _canonical_model_tag(name: str) -> str:
    return name if ":" in name else f"{name}:latest"


def _configured_digest(value: str, variable_name: str) -> str:
    digest = (value or "").strip()
    if not digest:
        raise OllamaIdentityError(
            f"{variable_name} is required. Inspect exact local digests with "
            "'python -m ai.ollama_bootstrap status', then set the 64-character "
            "SHA-256 value in the process environment."
        )
    if not _SHA256.fullmatch(digest):
        raise OllamaIdentityError(
            f"{variable_name} must contain exactly 64 hexadecimal characters."
        )
    return digest.lower()


def _metadata_digest(value: str) -> Optional[str]:
    digest = (value or "").strip()
    if digest.lower().startswith("sha256:"):
        digest = digest[7:]
    if not _SHA256.fullmatch(digest):
        return None
    return digest.lower()


def require_model_identity(
    name: str,
    expected_digest: str,
    *,
    variable_name: str,
    metadata: Optional[List[dict[str, str]]] = None,
) -> None:
    """Require an exact local tag and digest using constant-time comparison."""
    expected = _configured_digest(expected_digest, variable_name)
    canonical_name = _canonical_model_tag((name or "").strip())
    if not name:
        raise OllamaIdentityError("An Ollama model name must be configured.")
    available = metadata if metadata is not None else list_installed_model_metadata()
    for item in available:
        if _canonical_model_tag(item.get("name", "")) != canonical_name:
            continue
        actual = _metadata_digest(item.get("digest", ""))
        if actual is not None and hmac.compare_digest(actual, expected):
            return
        raise OllamaIdentityError(
            f"Digest mismatch for local Ollama model {name!r}. Refusing to use "
            f"it because it does not match {variable_name}."
        )
    raise OllamaIdentityError(
        f"Ollama model {name!r} with the configured immutable digest is not "
        "present on the local server."
    )


def is_model_installed(name: str, expected_digest: str, variable_name: str) -> bool:
    """Return True only when both the exact local tag and digest match."""
    try:
        require_model_identity(
            name, expected_digest, variable_name=variable_name
        )
        return True
    except OllamaIdentityError:
        return False


def require_configured_model_identities() -> None:
    """Require both configured Ollama models before enabling the provider."""
    metadata = list_installed_model_metadata()
    require_model_identity(
        cfg.ollama_text_model,
        cfg.ollama_text_model_digest,
        variable_name="OLLAMA_TEXT_MODEL_DIGEST",
        metadata=metadata,
    )
    require_model_identity(
        cfg.ollama_vision_model,
        cfg.ollama_vision_model_digest,
        variable_name="OLLAMA_VISION_MODEL_DIGEST",
        metadata=metadata,
    )


def installation_guidance() -> str:
    return (
        "Clicky does not download or execute Ollama. Download Ollama yourself "
        f"from {OLLAMA_DOWNLOAD_PAGE}, verify the Windows installer publisher, "
        "install it, start Ollama, and then re-run this check."
    )


def model_guidance(name: str, digest: str, variable_name: str) -> str:
    try:
        _configured_digest(digest, variable_name)
    except OllamaIdentityError as exc:
        return str(exc)
    return (
        f"No local {name!r} model matches {variable_name}. Clicky will not "
        "download or accept a mutable tag alone. Provision and review the model "
        "separately, inspect its full digest with 'python -m "
        "ai.ollama_bootstrap status', and update the expected digest."
    )


def _cli() -> None:
    args = sys.argv[1:]
    if not args:
        print("Usage: python -m ai.ollama_bootstrap [status|guide [model]|diag]")
        return

    cmd = args[0].lower()
    if cmd == "status":
        print(f"Ollama binary on PATH:  {is_ollama_installed()}")
        print(f"Ollama server running:  {is_ollama_running()}")
        if is_ollama_running():
            models = list_installed_model_metadata()
            print(f"Installed models ({len(models)}):")
            for model in models:
                print(f"  - {model['name']}  digest={model['digest']}")
        return

    if cmd == "guide":
        if len(args) > 1:
            print(
                "Provision the model separately, inspect its exact digest with "
                "the status command, and configure that 64-hex digest."
            )
        else:
            print(installation_guidance())
        return

    if cmd == "diag":
        print("--- Clicky Ollama diagnostics ---")
        print(f"Configured host:          {cfg.ollama_host}")
        print(f"Configured text model:    {cfg.ollama_text_model}")
        print(f"Configured vision model:  {cfg.ollama_vision_model}")
        print(f"Binary on PATH:           {is_ollama_installed()}")
        print(f"Server reachable:         {is_ollama_running()}")
        if is_ollama_running():
            models = list_installed_model_metadata()
            for model in models:
                print(f"Installed: {model['name']}  digest={model['digest']}")
            print(
                "Text identity verified:   "
                f"{is_model_installed(cfg.ollama_text_model, cfg.ollama_text_model_digest, 'OLLAMA_TEXT_MODEL_DIGEST')}"
            )
            print(
                "Vision identity verified: "
                f"{is_model_installed(cfg.ollama_vision_model, cfg.ollama_vision_model_digest, 'OLLAMA_VISION_MODEL_DIGEST')}"
            )
        return

    print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    _cli()
