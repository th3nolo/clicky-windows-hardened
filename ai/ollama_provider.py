import asyncio
import base64
import json
from typing import AsyncIterator, List

import httpx

from ai.base_provider import BaseLLMProvider, Message
from ai.ollama_models_registry import is_vision_capable
from config import cfg

_ALLOWED_CHAT_CONTENT_TYPES = frozenset({
    "application/json",
    "application/ndjson",
    "application/x-ndjson",
})
_MAX_CHAT_STREAM_BYTES = 8 * 1024 * 1024
_MAX_CHAT_RECORD_BYTES = 1024 * 1024
_MAX_CHAT_DECODED_CHARS = 2 * 1024 * 1024


def _decode_chat_record(record: bytes) -> tuple[str, bool]:
    """Decode one bounded Ollama JSON record or fail closed."""
    if len(record) > _MAX_CHAT_RECORD_BYTES:
        raise RuntimeError("Ollama chat record exceeded the safe size limit.")
    record = record.strip()
    if not record:
        return "", False
    try:
        data = json.loads(record.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Ollama returned an invalid chat stream record.") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Ollama returned a non-object chat stream record.")
    if error := data.get("error"):
        raise RuntimeError(f"Ollama chat failed: {str(error)[:512]}")
    message = data.get("message", {})
    if not isinstance(message, dict):
        raise RuntimeError("Ollama returned an invalid message object.")
    content = message.get("content", "")
    if not isinstance(content, str):
        raise RuntimeError("Ollama returned non-text message content.")
    done = data.get("done", False)
    if not isinstance(done, bool):
        raise RuntimeError("Ollama returned an invalid completion marker.")
    return content, done


class OllamaProvider(BaseLLMProvider):
    """
    Streams responses from a local Ollama instance.

    Auto-picks the right model per call:
        • Screenshots present → cfg.get_ollama_model("vision")
        • No screenshots      → cfg.get_ollama_model("text")

    A caller may still pass an explicit `model=` to override that choice
    (e.g. the panel's manual model dropdown).
    """

    def __init__(self):
        self._base = cfg.ollama_host.rstrip("/")
        # Kept for backward compat with old code paths reading self._model
        self._model = cfg.ollama_model

    def _pick_model(self, has_screenshots: bool) -> str:
        return cfg.get_ollama_model("vision" if has_screenshots else "text")

    @staticmethod
    def _expected_identity(chosen: str, has_screenshots: bool) -> tuple[str, str]:
        """Return the configured digest for an allowed exact model selection."""
        vision = cfg.ollama_vision_model
        text = cfg.ollama_text_model
        if chosen == vision and chosen == text:
            if has_screenshots:
                return cfg.ollama_vision_model_digest, "OLLAMA_VISION_MODEL_DIGEST"
            return cfg.ollama_text_model_digest, "OLLAMA_TEXT_MODEL_DIGEST"
        if chosen == vision:
            return cfg.ollama_vision_model_digest, "OLLAMA_VISION_MODEL_DIGEST"
        if chosen == text:
            return cfg.ollama_text_model_digest, "OLLAMA_TEXT_MODEL_DIGEST"
        raise RuntimeError(
            "Ollama model overrides must exactly match a configured, digest-pinned "
            "vision or text model."
        )

    async def stream_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncIterator[str]:
        # Resolution order:
        #   1. explicit `model=` arg (panel override)
        #   2. cfg vision/text slot based on attachment kind
        if model:
            chosen = model
        else:
            chosen = self._pick_model(bool(screenshots_b64))

        messages = [{"role": "system", "content": system_prompt}]

        for msg in history:
            messages.append({"role": msg.role, "content": msg.content})

        # Ollama passes images as base64 strings inside the message
        user_msg: dict = {"role": "user", "content": user_text}
        if screenshots_b64:
            user_msg["images"] = screenshots_b64
        messages.append(user_msg)

        payload = {
            "model": chosen,
            "messages": messages,
            "stream": True,
            "options": {"num_predict": 1024},
        }

        # Re-fetch and verify the chosen tag/digest immediately before every
        # generation request so a model replaced during this process is rejected.
        expected_digest, digest_variable = self._expected_identity(
            chosen, bool(screenshots_b64)
        )
        from ai.ollama_bootstrap import require_model_identity
        await asyncio.to_thread(
            require_model_identity,
            chosen,
            expected_digest,
            variable_name=digest_variable,
        )

        async with httpx.AsyncClient(
            timeout=120,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            async with client.stream(
                "POST",
                f"{self._base}/api/chat",
                json=payload,
            ) as response:
                if response.status_code == 404:
                    # Surface a useful error when the chosen model isn't
                    # installed locally — students hit this constantly.
                    raise RuntimeError(
                        f"Ollama doesn't have '{chosen}' installed. "
                        "Provision the reviewed model outside Clicky, configure "
                        "its exact digest, or select another pinned local model."
                    )
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type not in _ALLOWED_CHAT_CONTENT_TYPES:
                    raise RuntimeError(
                        "Ollama returned an unsupported chat response content type."
                    )
                content_encoding = response.headers.get(
                    "content-encoding", "identity"
                ).strip().lower()
                if content_encoding not in {"", "identity"}:
                    raise RuntimeError(
                        "Ollama returned compressed chat data; refusing an "
                        "unbounded decoded stream."
                    )

                raw_total = 0
                decoded_total = 0
                buffer = bytearray()
                async for raw_chunk in response.aiter_bytes():
                    raw_total += len(raw_chunk)
                    if raw_total > _MAX_CHAT_STREAM_BYTES:
                        raise RuntimeError(
                            "Ollama chat stream exceeded the safe total size limit."
                        )
                    buffer.extend(raw_chunk)
                    while True:
                        newline = buffer.find(b"\n")
                        if newline < 0:
                            if len(buffer) > _MAX_CHAT_RECORD_BYTES:
                                raise RuntimeError(
                                    "Ollama chat record exceeded the safe size limit."
                                )
                            break
                        if newline > _MAX_CHAT_RECORD_BYTES:
                            raise RuntimeError(
                                "Ollama chat record exceeded the safe size limit."
                            )
                        record = bytes(buffer[:newline])
                        del buffer[: newline + 1]
                        content, done = _decode_chat_record(record)
                        decoded_total += len(content)
                        if decoded_total > _MAX_CHAT_DECODED_CHARS:
                            raise RuntimeError(
                                "Ollama decoded chat output exceeded the safe limit."
                            )
                        if content:
                            yield content
                        if done:
                            return

                if buffer:
                    content, done = _decode_chat_record(bytes(buffer))
                    decoded_total += len(content)
                    if decoded_total > _MAX_CHAT_DECODED_CHARS:
                        raise RuntimeError(
                            "Ollama decoded chat output exceeded the safe limit."
                        )
                    if content:
                        yield content
                    if done:
                        return
                raise RuntimeError(
                    "Ollama chat stream ended without a completion marker."
                )

    async def health_check(self) -> bool:
        from ai.ollama_bootstrap import is_ollama_running

        return await asyncio.to_thread(is_ollama_running, 3.0)

    async def list_models(self) -> List[str]:
        """Return names from the bounded, proxy-free local metadata reader."""
        from ai.ollama_bootstrap import list_installed_models

        return await asyncio.to_thread(list_installed_models)

    async def list_models_classified(self) -> dict[str, list[str]]:
        """Installed models split into {'vision': [...], 'text': [...]}.

        Heuristic-based — see ollama_models_registry.is_vision_capable().
        """
        names = await self.list_models()
        out: dict[str, list[str]] = {"vision": [], "text": []}
        for n in names:
            if is_vision_capable(n):
                out["vision"].append(n)
            else:
                out["text"].append(n)
        out["vision"].sort()
        out["text"].sort()
        return out
