"""Fixed-endpoint OpenAI-compatible cloud providers."""

from __future__ import annotations

import base64
from typing import AsyncGenerator, List
from contextlib import aclosing

import httpx

from ai.base_provider import BaseLLMProvider, Message
from ai.model_selection import valid_model_id
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS, supports_video
from ai.sdk_isolation import create_openai_client
from ai.video_input import VideoInput
from config import cfg


MAX_OUTPUT_TOKENS = 1024
MUSE_OUTPUT_TOKENS = 4096
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
        self._client = create_openai_client(
            api_key=api_key,
            base_url=self._spec.base_url,
            timeout=httpx.Timeout(120.0, connect=15.0),
            max_retries=0,
        )

    async def stream_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncGenerator[str, None]:
        messages = _messages(user_text, screenshots_b64, history, system_prompt)
        async with aclosing(self._stream_messages(messages, model)) as stream:
            async for delta in stream:
                yield delta

    async def stream_video_response(
        self, user_text: str, video: VideoInput, history: List[Message],
        system_prompt: str, model: str | None = None,
    ) -> AsyncGenerator[str, None]:
        if not supports_video(self._spec.provider_id, model):
            raise ValueError("Select a supported Muse video-and-audio model")
        messages = _messages(user_text, [], history, system_prompt)
        messages[-1]["content"].append({
            "type": "video_url", "video_url": {"url": video.data_url},
        })
        async with aclosing(self._stream_messages(messages, model)) as stream:
            async for delta in stream:
                yield delta

    async def stream_multimodal_response(
        self, user_text: str, screenshots_b64: List[str], video: VideoInput,
        audio_b64: str, history: List[Message], system_prompt: str,
        model: str | None = None,
        timeline_frames: list[tuple[float, str]] | None = None,
    ) -> AsyncGenerator[str, None]:
        """Original Tutor context plus explicit speech audio and screen video."""
        if self._spec.provider_id != "openrouter" or model != "meta/muse-spark-1.3-contributor":
            raise ValueError("Voice/video Tutor requires the selected OpenRouter Muse Spark 1.3 model")
        if not isinstance(video, VideoInput) or not isinstance(audio_b64, str) or not 1 <= len(audio_b64) <= 2 * 1024 * 1024:
            raise ValueError("Voice/video Tutor media is invalid")
        try:
            audio = base64.b64decode(audio_b64, validate=True)
        except ValueError:
            raise ValueError("Voice/video Tutor audio is invalid") from None
        if not audio:
            raise ValueError("Voice/video Tutor audio is empty")
        messages = _messages(user_text, screenshots_b64, history, system_prompt)
        messages[-1]["content"].extend([
            {"type": "video_url", "video_url": {"url": video.data_url}},
            {"type": "input_audio", "input_audio": {"data": audio_b64, "format": "mp3"}},
        ])
        timeline_frames = timeline_frames or []
        if len(timeline_frames) > 8 or len(timeline_frames) + len(screenshots_b64) > MAX_SCREENSHOTS:
            raise ValueError("Too many timeline frames")
        previous_time = -1.0
        for seconds, frame in timeline_frames:
            if type(seconds) not in (float, int) or not previous_time <= seconds <= 61 or seconds < 0:
                raise ValueError("Invalid timeline timestamp")
            previous_time = seconds
            _bounded_text(frame, label="Timeline frame", limit=2 * 1024 * 1024)
            messages[-1]["content"].extend([
                {"type": "text", "text": f"RECORDED HISTORY at {seconds:.2f}s. This is a past video frame, not a current screen or a pointing coordinate map."},
                {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{frame}", "detail": "high"}},
            ])
        import logging
        video_bytes = len(video.data) * 3 // 4 - (len(video.data) - len(video.data.rstrip("=")))
        logging.getLogger("clicky.media").info(
            "dispatching model=%s video/mp4_bytes=%s audio/mp3_bytes=%s screenshots=%s timeline_frames=%s transcript_chars=%s history_messages=%s",
            model, video_bytes, len(audio), len(screenshots_b64), len(timeline_frames), len(user_text), len(history),
        )
        async with aclosing(self._stream_messages(messages, model)) as stream:
            async for delta in stream:
                yield delta

    async def _stream_messages(
        self, messages: list[dict], model: str | None,
    ) -> AsyncGenerator[str, None]:
        if not model or not valid_model_id(model):
            raise ValueError(
                f"Select a validated {self._spec.label} model before sending."
            )
        routing: dict = {}
        if self._spec.provider_id == "openrouter":
            provider_options: dict[str, bool | str] = {"allow_fallbacks": False}
            if getattr(cfg, "openrouter_private_routing", False) is True:
                provider_options.update(zdr=True, data_collection="deny")
            routing = {"extra_body": {"provider": provider_options}}
        stream = await self._client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=(MUSE_OUTPUT_TOKENS
                        if supports_video(self._spec.provider_id, model)
                        else MAX_OUTPUT_TOKENS),
            stream=True,
            **routing,
        )
        received_text = False
        try:
            async for chunk in stream:
                if not chunk.choices:
                    continue
                content = chunk.choices[0].delta.content
                if isinstance(content, str) and content:
                    received_text = received_text or bool(content.strip())
                    yield content
            if not received_text:
                raise RuntimeError(
                    f"{self._spec.label} returned no answer text. Try again or "
                    "choose another model in the panel."
                )
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
