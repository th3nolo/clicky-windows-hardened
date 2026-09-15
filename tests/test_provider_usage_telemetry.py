"""Offline checks for privacy-safe OpenAI-compatible stream usage telemetry."""

from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from ai.openai_compatible_provider import (
    OpenAICompatibleProvider,
    usage_telemetry_context,
)
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS


class ChunkStream:
    def __init__(self, chunks: list[object]):
        self._chunks = iter(chunks)
        self.close = AsyncMock()

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._chunks)
        except StopIteration as exc:
            raise StopAsyncIteration from exc


class BlockingStream:
    def __init__(self):
        self.entered = asyncio.Event()
        self.close = AsyncMock()

    def __aiter__(self):
        return self

    async def __anext__(self):
        self.entered.set()
        await asyncio.Event().wait()


class ProviderUsageTelemetryTests(unittest.IsolatedAsyncioTestCase):
    def make_provider(self, chunks: list[object], callback=None):
        provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
        provider._spec = OPENAI_COMPATIBLE_SPECS["openrouter"]
        provider._usage_callback = callback
        self.stream = ChunkStream(chunks)
        self.create = AsyncMock(return_value=self.stream)
        provider._client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=self.create),
            )
        )
        return provider

    async def test_usage_only_final_chunk_reports_complete_safe_metadata(self):
        observed = []
        provider = self.make_provider([
            SimpleNamespace(
                id="gen-safe-123",
                choices=[SimpleNamespace(
                    delta=SimpleNamespace(content="A private answer"),
                    finish_reason=None,
                )],
            ),
            SimpleNamespace(
                id="gen-safe-123",
                choices=[],
                usage={
                    "prompt_tokens": 101,
                    "completion_tokens": 37,
                    "completion_tokens_details": {"reasoning_tokens": 11},
                    "prompt_tokens_details": {"cached_tokens": 19},
                    "cost": 0.0025,
                },
            ),
        ], observed.append)

        with patch("ai.openai_compatible_provider.time.monotonic", side_effect=[
            10.0, 10.025, 10.160,
        ]), self.assertLogs("clicky.usage", level="INFO") as logged, usage_telemetry_context(
            task_id="turn-42", purpose="tutor-response"
        ):
            output = [
                chunk async for chunk in provider._stream_messages(
                    [{"role": "user", "content": "private prompt and media bytes"}],
                    "deepseek-chat",
                    media_counts=(2, 1, 1, 3),
                )
            ]

        self.assertEqual(output, ["A private answer"])
        self.assertEqual(len(observed), 1)
        telemetry = observed[0]
        self.assertEqual(telemetry.provider_id, "openrouter")
        self.assertEqual(telemetry.model, "deepseek-chat")
        self.assertEqual(telemetry.status, "completed")
        self.assertEqual(telemetry.generation_id, "gen-safe-123")
        self.assertEqual(telemetry.task_id, "turn-42")
        self.assertEqual(telemetry.purpose, "tutor-response")
        self.assertEqual(telemetry.input_tokens, 101)
        self.assertEqual(telemetry.output_tokens, 37)
        self.assertEqual(telemetry.reasoning_tokens, 11)
        self.assertEqual(telemetry.cache_tokens, 19)
        self.assertEqual(telemetry.cost, 0.0025)
        self.assertEqual(telemetry.latency_ms, 160)
        self.assertEqual(telemetry.ttft_ms, 25)
        self.assertEqual(
            (
                telemetry.screenshot_count,
                telemetry.video_count,
                telemetry.audio_count,
                telemetry.timeline_frame_count,
            ),
            (2, 1, 1, 3),
        )
        self.assertEqual(
            self.create.call_args.kwargs["stream_options"],
            {"include_usage": True},
        )
        self.assertEqual(logged.records[0].clicky_usage["generation_id"], "gen-safe-123")
        self.assertEqual(logged.records[0].clicky_usage["input_tokens"], 101)
        self.assertNotIn("private prompt", repr(logged.records[0].clicky_usage))
        log_text = "\n".join(logged.output)
        self.assertNotIn("private prompt", log_text)
        self.assertNotIn("media bytes", log_text)
        self.assertNotIn("A private answer", log_text)
        self.stream.close.assert_awaited_once()

    async def test_attribute_usage_aliases_are_normalized_without_text(self):
        observed = []
        usage = SimpleNamespace(
            input_tokens=210,
            output_tokens=55,
            output_tokens_details=SimpleNamespace(reasoning_tokens=13),
            input_tokens_details=SimpleNamespace(cache_read_input_tokens=21),
            total_cost=0.01,
        )
        provider = self.make_provider([
            SimpleNamespace(
                id="gen-attribute-usage",
                choices=[SimpleNamespace(
                    delta=SimpleNamespace(content="answer"),
                    finish_reason="stop",
                )],
            ),
            SimpleNamespace(choices=[], usage=usage),
        ], observed.append)

        output = [
            chunk async for chunk in provider._stream_messages(
                [], "deepseek-chat"
            )
        ]

        self.assertEqual(output, ["answer"])
        telemetry = observed[0]
        self.assertEqual(telemetry.generation_id, "gen-attribute-usage")
        self.assertEqual(telemetry.status, "completed")
        self.assertEqual(telemetry.input_tokens, 210)
        self.assertEqual(telemetry.output_tokens, 55)
        self.assertEqual(telemetry.reasoning_tokens, 13)
        self.assertEqual(telemetry.cache_tokens, 21)
        self.assertEqual(telemetry.cost, 0.01)

    async def test_callback_failure_and_unbounded_generation_id_do_not_expose_content(self):
        def failing_callback(_telemetry):
            raise RuntimeError("private callback secret")

        provider = self.make_provider([
            SimpleNamespace(
                id="private-generation-id" * 30,
                choices=[SimpleNamespace(
                    delta=SimpleNamespace(content="private answer"),
                    finish_reason=None,
                )],
            ),
            SimpleNamespace(choices=[], usage={"prompt_tokens": 1}),
        ], failing_callback)

        with self.assertLogs("clicky.usage", level="WARNING") as logged:
            output = [
                chunk async for chunk in provider._stream_messages(
                    [{"role": "user", "content": "private prompt"}],
                    "deepseek-chat",
                )
            ]

        self.assertEqual(output, ["private answer"])
        self.assertEqual(logged.output, [
            "WARNING:clicky.usage:provider_usage_callback_failed",
        ])
        self.assertNotIn("private callback secret", "\n".join(logged.output))
        self.assertNotIn("private prompt", "\n".join(logged.output))

    async def test_failed_request_reports_unknown_usage_without_exception_text(self):
        observed = []
        provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
        provider._spec = OPENAI_COMPATIBLE_SPECS["openrouter"]
        provider._usage_callback = observed.append
        create = AsyncMock(side_effect=RuntimeError("private transport secret"))
        provider._client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
        )

        with self.assertLogs("clicky.usage", level="INFO") as logged:
            with self.assertRaisesRegex(RuntimeError, "private transport secret"):
                _ = [chunk async for chunk in provider._stream_messages(
                    [{"role": "user", "content": "private prompt"}],
                    "deepseek-chat",
                )]

        self.assertEqual(len(observed), 1)
        telemetry = observed[0]
        self.assertEqual(telemetry.status, "failed")
        self.assertIsNone(telemetry.input_tokens)
        self.assertIsNone(telemetry.output_tokens)
        self.assertNotIn("private transport secret", "\n".join(logged.output))
        self.assertNotIn("private prompt", "\n".join(logged.output))

    async def test_cancelled_request_reports_unknown_usage_and_closes_stream(self):
        observed = []
        provider = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
        provider._spec = OPENAI_COMPATIBLE_SPECS["openrouter"]
        provider._usage_callback = observed.append
        stream = BlockingStream()
        create = AsyncMock(return_value=stream)
        provider._client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
        )

        response = provider._stream_messages([], "deepseek-chat")
        task = asyncio.create_task(anext(response))
        await stream.entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertEqual(len(observed), 1)
        telemetry = observed[0]
        self.assertEqual(telemetry.status, "cancelled")
        self.assertIsNone(telemetry.input_tokens)
        self.assertIsNone(telemetry.cost)
        stream.close.assert_awaited_once()

    async def test_early_generator_close_reports_aborted_request_once(self):
        observed = []
        provider = self.make_provider([
            SimpleNamespace(
                id="gen-partial",
                choices=[SimpleNamespace(
                    delta=SimpleNamespace(content="partial answer"),
                    finish_reason=None,
                )],
            ),
        ], observed.append)

        response = provider._stream_messages([], "deepseek-chat")
        self.assertEqual(await anext(response), "partial answer")
        await response.aclose()

        self.assertEqual(len(observed), 1)
        telemetry = observed[0]
        self.assertEqual(telemetry.status, "aborted")
        self.assertEqual(telemetry.generation_id, "gen-partial")
        self.assertIsNone(telemetry.input_tokens)
        self.stream.close.assert_awaited_once()

    async def test_close_failure_does_not_obscure_the_transport_failure(self):
        observed = []
        provider = self.make_provider([], observed.append)
        self.stream.close.side_effect = RuntimeError("private close secret")

        with self.assertLogs("clicky.usage", level="INFO") as logged:
            with self.assertRaisesRegex(RuntimeError, "returned no answer text"):
                _ = [chunk async for chunk in provider._stream_messages(
                    [{"role": "user", "content": "private prompt"}],
                    "deepseek-chat",
                )]

        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].status, "failed")
        self.assertNotIn("private close secret", "\n".join(logged.output))
        self.assertNotIn("private prompt", "\n".join(logged.output))

    async def test_multimodal_screenshot_audio_request_allows_no_video(self):
        observed = []
        provider = self.make_provider([
            SimpleNamespace(
                id="gen-screenshot-audio",
                choices=[SimpleNamespace(
                    delta=SimpleNamespace(content="answer"),
                    finish_reason=None,
                )],
            ),
            SimpleNamespace(choices=[], usage={"prompt_tokens": 8}),
        ], observed.append)

        output = [chunk async for chunk in provider.stream_multimodal_response(
            "private spoken text",
            ["private-screenshot-bytes"],
            None,
            base64.b64encode(b"synthetic-mp3").decode("ascii"),
            [],
            "private system prompt",
            "meta/muse-spark-1.3-contributor",
            timeline_frames=[(0.0, "private-frame-bytes")],
        )]

        self.assertEqual(output, ["answer"])
        parts = self.create.call_args.kwargs["messages"][-1]["content"]
        self.assertNotIn("video_url", [part["type"] for part in parts])
        self.assertEqual(
            [part["type"] for part in parts],
            ["image_url", "text", "input_audio", "text", "image_url"],
        )
        telemetry = observed[0]
        self.assertEqual(
            (
                telemetry.screenshot_count,
                telemetry.video_count,
                telemetry.audio_count,
                telemetry.timeline_frame_count,
            ),
            (1, 0, 1, 1),
        )

    async def test_muse_reasoning_policy_is_scoped_to_notebook_phases(self):
        cases = {
            "lesson_plan": (8192, "minimal"),
            "output_verification": (8192, "minimal"),
            "drawing_plan": (16384, "low"),
        }
        model = "meta/muse-spark-1.3-contributor"
        for purpose, (expected_max_tokens, expected_effort) in cases.items():
            with self.subTest(purpose=purpose):
                provider = self.make_provider([
                    SimpleNamespace(choices=[SimpleNamespace(
                        delta=SimpleNamespace(content="answer"),
                        finish_reason="stop",
                    )]),
                ])
                with usage_telemetry_context(purpose=purpose):
                    if purpose == "drawing_plan":
                        output = [
                            chunk async for chunk in provider.stream_drawing_response(
                                "private drawing prompt", [], [], "private system", model,
                            )
                        ]
                    else:
                        output = [
                            chunk async for chunk in provider._stream_messages(
                                [], model
                            )
                        ]

                self.assertEqual(output, ["answer"])
                request = self.create.call_args.kwargs
                self.assertEqual(request["max_tokens"], expected_max_tokens)
                self.assertEqual(
                    request["extra_body"]["reasoning"],
                    {"effort": expected_effort},
                )
                self.assertFalse(request["extra_body"]["provider"]["allow_fallbacks"])
                self.assertEqual(request["stream_options"], {"include_usage": True})
                self.assertNotIn("fallback", request)

    async def test_muse_conversation_keeps_its_existing_request_shape(self):
        provider = self.make_provider([
            SimpleNamespace(choices=[SimpleNamespace(
                delta=SimpleNamespace(content="answer"),
                finish_reason="stop",
            )]),
        ])

        output = [
            chunk async for chunk in provider.stream_response(
                "private conversation", [], [], "private system",
                "meta/muse-spark-1.3-contributor",
            )
        ]

        self.assertEqual(output, ["answer"])
        request = self.create.call_args.kwargs
        self.assertEqual(request["max_tokens"], 4096)
        self.assertEqual(
            request["extra_body"],
            {"provider": {"allow_fallbacks": False}},
        )
        self.assertEqual(request["stream_options"], {"include_usage": True})
        self.assertNotIn("reasoning", request)
        self.assertNotIn("fallback", request)


if __name__ == "__main__":
    unittest.main()
