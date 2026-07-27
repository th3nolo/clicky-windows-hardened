"""Fixed-endpoint OpenAI-compatible cloud providers."""

from __future__ import annotations

from typing import AsyncIterator, List

import httpx
from openai import AsyncOpenAI

from ai.base_provider import BaseLLMProvider, Message
from ai.model_selection import valid_model_id
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS
from config import cfg


MAX_OUTPUT_TOKENS = 1024
MAX_USER_TEXT_CHARS = 64 * 1024
MAX_SYSTEM_PROMPT_CHARS = 128 * 1024
MAX_HISTORY_MESSAGES = 20
MAX_HISTORY_MESSAGE_CHARS = 64 * 1024
MAX_SCREENSHOTS = 16
MAX_IMAGE_B64_CHARS = 12 * 1024 * 1024
MAX_TOTAL_IMAGE_B64_CHARS = 64 * 1024 * 1024


def _bounded_text(value: str, *, label: str, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"{label} exceeds Clicky's reviewed size limit")
    return value


def _messages(
    user_text: str,
    screenshots_b64: List[str],
    history: List[Message],
    system_prompt: str,
) -> list[dict]:
    user_text = _bounded_text(
        user_text, label="User request", limit=MAX_USER_TEXT_CHARS
    )
    system_prompt = _bounded_text(
        system_prompt, label="System prompt", limit=MAX_SYSTEM_PROMPT_CHARS
    )
    if len(history) > MAX_HISTORY_MESSAGES:
        history = history[-MAX_HISTORY_MESSAGES:]
    messages: list[dict] = [{"role": "system", "content": system_prompt}]
    for message in history:
        if message.role not in {"user", "assistant"}:
            continue
        content = _bounded_text(
            message.content,
            label="Conversation message",
            limit=MAX_HISTORY_MESSAGE_CHARS,
        )
        messages.append({"role": message.role, "content": content})

    if len(screenshots_b64) > MAX_SCREENSHOTS:
        raise ValueError("Too many screenshots for one provider request")
    total_image_chars = 0
    content: list[dict] = []
    for image_b64 in screenshots_b64:
        if not isinstance(image_b64, str) or len(image_b64) > MAX_IMAGE_B64_CHARS:
            raise ValueError("Screenshot exceeds Clicky's reviewed size limit")
        total_image_chars += len(image_b64)
        if total_image_chars > MAX_TOTAL_IMAGE_B64_CHARS:
            raise ValueError("Combined screenshots exceed Clicky's reviewed size limit")
        content.append({
            "type": "image_url",
            "image_url": {
                "url": f"data:image/jpeg;base64,{image_b64}",
                "detail": "high",
            },
        })
    content.append({"type": "text", "text": user_text})
    messages.append({"role": "user", "content": content})
    return messages


class OpenAICompatibleProvider(BaseLLMProvider):
    """A reviewed provider selected only from the fixed catalog."""

    def __init__(self, provider_id: str):
        try:
            self._spec = OPENAI_COMPATIBLE_SPECS[provider_id]
        except KeyError as exc:
            raise ValueError("Unknown OpenAI-compatible provider") from exc
        api_key = getattr(cfg, self._spec.credential_attribute, None)
        if not api_key:
            raise RuntimeError(
                f"{self._spec.label} is unavailable because its process "
                "environment API key is missing."
            )
        http_client = httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(120.0, connect=15.0),
        )
        self._client = AsyncOpenAI(
            api_key=api_key,
            base_url=self._spec.base_url,
            http_client=http_client,
            max_retries=0,
        )

    async def stream_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncIterator[str]:
        if not model or not valid_model_id(model):
            raise ValueError(
                f"Select a validated {self._spec.label} model before sending."
            )
        stream = await self._client.chat.completions.create(
            model=model,
            messages=_messages(
                user_text,
                screenshots_b64,
                history,
                system_prompt,
            ),
            max_tokens=MAX_OUTPUT_TOKENS,
            stream=True,
        )
        try:
            async for chunk in stream:
                if not chunk.choices:
                    continue
                content = chunk.choices[0].delta.content
                if isinstance(content, str) and content:
                    yield content
        finally:
            close = getattr(stream, "close", None)
            if close is not None:
                await close()

    async def health_check(self) -> bool:
        try:
            await self._client.models.list()
            return True
        except Exception:
            return False
