"""Fixed-endpoint OpenAI-compatible cloud providers."""

import base64
import asyncio
from contextlib import aclosing, contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
import logging
import math
import sys
import time
from collections.abc import Callable, Mapping
from typing import AsyncGenerator, List

import httpx

from ai.base_provider import BaseLLMProvider, Message
from ai.model_selection import valid_model_id
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS, supports_video
from ai.sdk_isolation import create_openai_client
from ai.video_input import VideoInput
from config import cfg


MAX_OUTPUT_TOKENS = 1024
MUSE_OUTPUT_TOKENS = 4096
# Drawing commands contain explicit point/control geometry. Keep this larger
# allowance scoped to the drawing entry point; ordinary Tutor responses and
# media calls retain their existing budgets.
DRAWING_OUTPUT_TOKENS = 16384
MAX_USER_TEXT_CHARS = 64 * 1024
MAX_SYSTEM_PROMPT_CHARS = 128 * 1024
MAX_HISTORY_MESSAGES = 20
MAX_HISTORY_MESSAGE_CHARS = 64 * 1024
MAX_SCREENSHOTS = 16
MAX_IMAGE_B64_CHARS = 12 * 1024 * 1024
MAX_TOTAL_IMAGE_B64_CHARS = 64 * 1024 * 1024
MAX_GENERATION_ID_CHARS = 256
MAX_USAGE_CONTEXT_CHARS = 128


_usage_log = logging.getLogger("clicky.usage")
_usage_context: ContextVar[tuple[str | None, str | None]] = ContextVar(
    "clicky_provider_usage_context", default=(None, None)
)


@dataclass(frozen=True, slots=True)
class ProviderUsageTelemetry:
    """Privacy-safe metadata reported for one streamed provider response."""

    provider_id: str
    model: str
    status: str
    generation_id: str | None
    task_id: str | None
    purpose: str | None
    input_tokens: int | float | None
    output_tokens: int | float | None
    reasoning_tokens: int | float | None
    cache_tokens: int | float | None
    cost: int | float | None
    latency_ms: int
    ttft_ms: int | None
    screenshot_count: int
    video_count: int
    audio_count: int
    timeline_frame_count: int


UsageTelemetryCallback = Callable[[ProviderUsageTelemetry], None]


def _bounded_usage_context(value: str | None) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAX_USAGE_CONTEXT_CHARS:
        return None
    if any(
        not (character.isascii() and (character.isalnum() or character in "-_.:"))
        for character in value
    ):
        return None
    return value


@contextmanager
def usage_telemetry_context(*, task_id: str | None = None, purpose: str | None = None):
    """Attach bounded identifier metadata, never request content, to usage."""
    token = _usage_context.set((
        _bounded_usage_context(task_id),
        _bounded_usage_context(purpose),
    ))
    try:
        yield
    finally:
        _usage_context.reset(token)


def _field(value: object, name: str) -> object | None:
    """Read one documented response field without serializing request data."""
    if isinstance(value, Mapping):
        return value.get(name)
    return getattr(value, name, None)


def _number(value: object) -> int | float | None:
    """Accept only finite provider-supplied numeric telemetry values."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _usage_number(usage: object, *names: str) -> int | float | None:
    for name in names:
        value = _number(_field(usage, name))
        if value is not None:
            return value
    return None


def _usage_detail_number(
    usage: object,
    detail_names: tuple[str, ...],
    value_names: tuple[str, ...],
) -> int | float | None:
    for detail_name in detail_names:
        details = _field(usage, detail_name)
        if details is None:
            continue
        for value_name in value_names:
            value = _number(_field(details, value_name))
            if value is not None:
                return value
    return None


def _generation_id(chunk: object) -> str | None:
    value = _field(chunk, "id")
    if not isinstance(value, str) or not value or len(value) > MAX_GENERATION_ID_CHARS:
        return None
    if any(character.isspace() and character not in {" "} for character in value):
        return None
    return value


class StreamOutputTruncatedError(RuntimeError):
    """The provider stopped a streamed response at its output-token limit."""

    finish_reason = "length"

    def __init__(self, provider_label: str, max_tokens: int):
        self.max_tokens = max_tokens
        super().__init__(
            f"{provider_label} output was truncated by the provider "
            f"(finish_reason=length; max_tokens={max_tokens})."
        )


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

    def __init__(
        self,
        provider_id: str,
        *,
        usage_callback: UsageTelemetryCallback | None = None,
    ):
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
        # The callback receives only ProviderUsageTelemetry. It deliberately
        # has no access to request messages, media bytes, or credentials.
        self._usage_callback = usage_callback

    async def stream_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncGenerator[str, None]:
        messages = _messages(user_text, screenshots_b64, history, system_prompt)
        async with aclosing(self._stream_messages(
            messages,
            model,
            media_counts=(len(screenshots_b64), 0, 0, 0),
        )) as stream:
            async for delta in stream:
                yield delta

    async def stream_drawing_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncGenerator[str, None]:
        """Stream a notebook drawing command with a scoped larger allowance."""
        messages = _messages(user_text, screenshots_b64, history, system_prompt)
        async with aclosing(
            self._stream_messages(
                messages,
                model,
                max_tokens=DRAWING_OUTPUT_TOKENS,
                media_counts=(len(screenshots_b64), 0, 0, 0),
            )
        ) as stream:
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
        async with aclosing(self._stream_messages(
            messages,
            model,
            media_counts=(0, 1, 0, 0),
        )) as stream:
            async for delta in stream:
                yield delta

    async def stream_multimodal_response(
        self, user_text: str, screenshots_b64: List[str], video: VideoInput | None,
        audio_b64: str, history: List[Message], system_prompt: str,
        model: str | None = None,
        timeline_frames: list[tuple[float, str]] | None = None,
    ) -> AsyncGenerator[str, None]:
        """Original Tutor context plus explicit speech audio and screen video."""
        if self._spec.provider_id != "openrouter" or model != "meta/muse-spark-1.3-contributor":
            raise ValueError("Voice/video Tutor requires the selected OpenRouter Muse Spark 1.3 model")
        if (
            (video is not None and not isinstance(video, VideoInput))
            or not isinstance(audio_b64, str)
            or not 1 <= len(audio_b64) <= 2 * 1024 * 1024
        ):
            raise ValueError("Voice/video Tutor media is invalid")
        try:
            audio = base64.b64decode(audio_b64, validate=True)
        except ValueError:
            raise ValueError("Voice/video Tutor audio is invalid") from None
        if not audio:
            raise ValueError("Voice/video Tutor audio is empty")
        messages = _messages(user_text, screenshots_b64, history, system_prompt)
        if video is not None:
            messages[-1]["content"].append({
                "type": "video_url", "video_url": {"url": video.data_url},
            })
        messages[-1]["content"].append({
            "type": "input_audio",
            "input_audio": {"data": audio_b64, "format": "mp3"},
        })
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
        video_bytes = (
            len(video.data) * 3 // 4 - (len(video.data) - len(video.data.rstrip("=")))
            if video is not None else 0
        )
        logging.getLogger("clicky.media").info(
            "dispatching model=%s video/mp4_bytes=%s audio/mp3_bytes=%s screenshots=%s timeline_frames=%s transcript_chars=%s history_messages=%s",
            model, video_bytes, len(audio), len(screenshots_b64), len(timeline_frames), len(user_text), len(history),
        )
        async with aclosing(self._stream_messages(
            messages,
            model,
            media_counts=(
                len(screenshots_b64),
                int(video is not None),
                1,
                len(timeline_frames),
            ),
        )) as stream:
            async for delta in stream:
                yield delta

    async def _stream_messages(
        self,
        messages: list[dict],
        model: str | None,
        *,
        max_tokens: int | None = None,
        media_counts: tuple[int, int, int, int] = (0, 0, 0, 0),
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
        effective_max_tokens = (
            max_tokens
            if max_tokens is not None
            else (
                MUSE_OUTPUT_TOKENS
                if supports_video(self._spec.provider_id, model)
                else MAX_OUTPUT_TOKENS
            )
        )
        # Live accounting showed a bounded lesson plan exhausting all 4096
        # completion tokens in reasoning before producing any usable JSON.
        # Muse supports effort selection (reasoning itself is mandatory).
        # Scope this policy to notebook phases; ordinary conversation is unchanged.
        _, request_purpose = _usage_context.get()
        if (self._spec.provider_id == "openrouter"
                and model == "meta/muse-spark-1.3-contributor"
                and request_purpose in {"lesson_plan", "drawing_plan", "output_verification"}):
            routing["extra_body"]["reasoning"] = {
                "effort": "low" if request_purpose == "drawing_plan" else "minimal"
            }
            if request_purpose in {"lesson_plan", "output_verification"}:
                effective_max_tokens = max(effective_max_tokens, 8192)
        started_at = time.monotonic()
        stream = None
        received_text = False
        finish_reason = None
        generation_id = None
        first_text_at: float | None = None
        final_usage = None
        status = "aborted"
        try:
            stream = await self._client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=effective_max_tokens,
                stream=True,
                stream_options={"include_usage": True},
                **routing,
            )
            async for chunk in stream:
                generation_id = _generation_id(chunk) or generation_id
                usage = _field(chunk, "usage")
                # OpenAI-compatible APIs commonly send final usage in a chunk
                # with an empty choices list. Read it before skipping that chunk.
                if usage is not None:
                    final_usage = usage
                choices = _field(chunk, "choices")
                if not isinstance(choices, (list, tuple)) or not choices:
                    continue
                choice = choices[0]
                choice_finish_reason = _field(choice, "finish_reason")
                if choice_finish_reason is not None:
                    finish_reason = choice_finish_reason
                content = _field(_field(choice, "delta"), "content")
                if isinstance(content, str) and content:
                    received_text = received_text or bool(content.strip())
                    if first_text_at is None:
                        first_text_at = time.monotonic()
                    yield content
            if finish_reason == "length":
                raise StreamOutputTruncatedError(
                    self._spec.label,
                    effective_max_tokens,
                )
            if not received_text:
                raise RuntimeError(
                    f"{self._spec.label} returned no answer text. Try again or "
                    "choose another model in the panel."
                )
            status = "completed"
        except asyncio.CancelledError:
            status = "cancelled"
            raise
        except Exception:
            status = "failed"
            raise
        finally:
            active_exception = sys.exc_info()[0] is not None
            close = getattr(stream, "close", None)
            close_error = None
            if close is not None:
                try:
                    await close()
                except Exception as exc:
                    if active_exception:
                        try:
                            _usage_log.warning("provider_stream_close_failed")
                        except Exception:
                            pass
                    else:
                        status = "failed"
                        close_error = exc
            self._report_usage(
                usage=final_usage,
                model=model,
                status=status,
                generation_id=generation_id,
                started_at=started_at,
                first_text_at=first_text_at,
                media_counts=media_counts,
            )
            if close_error is not None:
                raise close_error

    def _report_usage(
        self,
        *,
        usage: object | None,
        model: str,
        status: str,
        generation_id: str | None,
        started_at: float,
        first_text_at: float | None,
        media_counts: tuple[int, int, int, int],
    ) -> None:
        """Report bounded provider metadata without retaining request content."""
        now = time.monotonic()
        task_id, purpose = _usage_context.get()
        input_tokens = _usage_number(usage, "prompt_tokens", "input_tokens")
        output_tokens = _usage_number(usage, "completion_tokens", "output_tokens")
        reasoning_tokens = _usage_number(usage, "reasoning_tokens")
        if reasoning_tokens is None:
            reasoning_tokens = _usage_detail_number(
                usage,
                ("completion_tokens_details", "output_tokens_details"),
                ("reasoning_tokens",),
            )
        cache_tokens = _usage_number(
            usage,
            "cached_tokens",
            "cache_read_tokens",
            "cache_read_input_tokens",
        )
        if cache_tokens is None:
            cache_tokens = _usage_detail_number(
                usage,
                ("prompt_tokens_details", "input_tokens_details"),
                ("cached_tokens", "cache_read_tokens", "cache_read_input_tokens"),
            )
        telemetry = ProviderUsageTelemetry(
            provider_id=self._spec.provider_id,
            model=model,
            status=status,
            generation_id=generation_id,
            task_id=task_id,
            purpose=purpose,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            reasoning_tokens=reasoning_tokens,
            cache_tokens=cache_tokens,
            cost=_usage_number(usage, "cost", "total_cost"),
            latency_ms=max(0, int((now - started_at) * 1000)),
            ttft_ms=(
                max(0, int((first_text_at - started_at) * 1000))
                if first_text_at is not None else None
            ),
            screenshot_count=media_counts[0],
            video_count=media_counts[1],
            audio_count=media_counts[2],
            timeline_frame_count=media_counts[3],
        )
        try:
            _usage_log.info(
                "provider_usage provider=%s model=%s status=%s generation_id=%s "
                "task_id=%s purpose=%s "
                "input_tokens=%s output_tokens=%s reasoning_tokens=%s "
                "cache_tokens=%s cost=%s latency_ms=%s ttft_ms=%s "
                "screenshots=%s videos=%s audio=%s timeline_frames=%s",
                telemetry.provider_id,
                telemetry.model,
                telemetry.status,
                telemetry.generation_id,
                telemetry.task_id,
                telemetry.purpose,
                telemetry.input_tokens,
                telemetry.output_tokens,
                telemetry.reasoning_tokens,
                telemetry.cache_tokens,
                telemetry.cost,
                telemetry.latency_ms,
                telemetry.ttft_ms,
                telemetry.screenshot_count,
                telemetry.video_count,
                telemetry.audio_count,
                telemetry.timeline_frame_count,
                extra={"clicky_usage": asdict(telemetry)},
            )
        except Exception:
            pass
        callback = getattr(self, "_usage_callback", None)
        if callback is not None:
            try:
                callback(telemetry)
            except Exception:
                # Telemetry observers must never affect a Tutor response, and
                # exception text could contain caller-provided private content.
                try:
                    _usage_log.warning("provider_usage_callback_failed")
                except Exception:
                    pass

    async def health_check(self) -> bool:
        try:
            await self._client.models.list()
            return True
        except Exception:
            return False
