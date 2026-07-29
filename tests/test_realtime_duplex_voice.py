"""Deterministic contracts for the hard-off OpenAI Realtime voice path."""

from __future__ import annotations

import asyncio
import base64
import json
import types
import unittest
from unittest import mock

import aiohttp
from yarl import URL

from audio.realtime import openai_realtime as realtime
from audio.realtime.base import (
    DuplexConsentError,
    DuplexError,
    DuplexProtocolError,
    DuplexState,
)


def text_message(payload: dict):
    return types.SimpleNamespace(
        type=aiohttp.WSMsgType.TEXT,
        data=json.dumps(payload),
    )


class FakeWebSocket:
    def __init__(self, *, url: str = realtime.OPENAI_REALTIME_URL, history=()):
        self._response = types.SimpleNamespace(
            url=URL(url),
            history=history,
        )
        self.messages: asyncio.Queue = asyncio.Queue()
        self.sent_json: list[dict] = []
        self.closed = False

    async def send_json(self, value):
        self.sent_json.append(value)
        if value.get("type") == "session.update":
            await self.messages.put(
                text_message(
                    {"type": "session.updated", "session": value["session"]}
                )
            )

    async def receive(self):
        return await self.messages.get()

    async def close(self):
        self.closed = True


class FakeClientSession:
    instances: list["FakeClientSession"] = []
    next_websocket: FakeWebSocket | None = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.connect_calls: list[tuple[str, dict]] = []
        self.websocket = self.next_websocket or FakeWebSocket()
        self.closed = False
        type(self).instances.append(self)

    async def ws_connect(self, url, **kwargs):
        self.connect_calls.append((url, kwargs))
        return self.websocket

    async def close(self):
        self.closed = True


class OpenAIRealtimeSessionTests(unittest.TestCase):
    def setUp(self):
        FakeClientSession.instances = []
        FakeClientSession.next_websocket = None

    def run_session(self, exercise):
        async def run():
            loop = asyncio.get_running_loop()
            with mock.patch.object(
                realtime.aiohttp,
                "ClientSession",
                FakeClientSession,
            ):
                return await exercise(loop)

        return asyncio.run(run())

    @staticmethod
    def new_session(loop, **changes):
        values = {
            "api_key": "secret-value",
            "feature_enabled": True,
            "microphone_consent": True,
            "cloud_stt_consent": True,
            "cloud_tts_consent": True,
            "loop": loop,
        }
        values.update(changes)
        return realtime.OpenAIRealtimeSession(**values)

    def test_fixed_protocol_streams_bounded_pcm_and_reports_usage(self):
        audio: list[bytes] = []
        transcripts: list[str] = []

        async def exercise(loop):
            session = self.new_session(
                loop,
                on_audio=audio.append,
                on_transcript=transcripts.append,
            )
            await session.open()
            websocket = FakeClientSession.instances[0].websocket
            session.send_frame(bytes(960))
            await asyncio.sleep(0)
            await websocket.messages.put(
                text_message(
                    {
                        "type": "response.created",
                        "response": {"id": "resp_reviewed"},
                    }
                )
            )
            await websocket.messages.put(
                text_message(
                    {
                        "type": "response.output_audio.delta",
                        "delta": base64.b64encode(bytes(480)).decode("ascii"),
                    }
                )
            )
            await websocket.messages.put(
                text_message(
                    {
                        "type": "response.output_audio_transcript.delta",
                        "delta": "Hello",
                    }
                )
            )
            await websocket.messages.put(
                text_message(
                    {
                        "type": "response.done",
                        "response": {
                            "id": "resp_reviewed",
                            "usage": {"total_tokens": 42},
                        },
                    }
                )
            )
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            await session.close()
            return session, FakeClientSession.instances[0]

        session, client = self.run_session(exercise)
        self.assertEqual(session.state, DuplexState.CLOSED)
        self.assertEqual(audio, [bytes(480)])
        self.assertEqual(transcripts, ["Hello"])
        self.assertEqual(session.usage.input_bytes, 1_440)
        self.assertEqual(session.usage.output_bytes, 480)
        self.assertEqual(session.usage.responses, 1)
        self.assertEqual(session.usage.total_tokens, 42)

        self.assertFalse(client.kwargs["trust_env"])
        self.assertIsInstance(client.kwargs["cookie_jar"], aiohttp.DummyCookieJar)
        self.assertEqual(len(client.connect_calls), 1)
        url, kwargs = client.connect_calls[0]
        self.assertEqual(url, realtime.OPENAI_REALTIME_URL)
        self.assertEqual(
            kwargs["headers"],
            {"Authorization": "Bearer secret-value"},
        )
        self.assertNotIn("secret-value", url)
        self.assertIsNone(kwargs["proxy"])
        self.assertEqual(kwargs["compress"], 0)

        session_update = client.websocket.sent_json[0]
        self.assertEqual(session_update["type"], "session.update")
        configured = session_update["session"]
        self.assertEqual(configured["model"], realtime.OPENAI_REALTIME_MODEL)
        self.assertTrue(
            configured["audio"]["input"]["turn_detection"][
                "interrupt_response"
            ]
        )
        append = next(
            event
            for event in client.websocket.sent_json
            if event["type"] == "input_audio_buffer.append"
        )
        self.assertEqual(len(base64.b64decode(append["audio"])), 1_440)
        self.assertTrue(client.websocket.closed)
        self.assertTrue(client.closed)

    def test_all_independent_permissions_and_feature_flag_are_required(self):
        cases = (
            {"feature_enabled": False},
            {"microphone_consent": False},
            {"cloud_stt_consent": False},
            {"cloud_tts_consent": False},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                FakeClientSession.instances = []

                async def exercise(loop):
                    session = self.new_session(loop, **changes)
                    with self.assertRaises(DuplexConsentError):
                        await session.open()
                    return session

                session = self.run_session(exercise)
                self.assertEqual(session.state, DuplexState.FAILED)
                self.assertEqual(FakeClientSession.instances, [])

    def test_changed_session_configuration_is_rejected(self):
        class ChangedSessionWebSocket(FakeWebSocket):
            async def send_json(self, value):
                self.sent_json.append(value)
                if value.get("type") == "session.update":
                    changed = dict(value["session"])
                    changed["model"] = "unreviewed-model"
                    await self.messages.put(
                        text_message(
                            {"type": "session.updated", "session": changed}
                        )
                    )

        FakeClientSession.next_websocket = ChangedSessionWebSocket()

        async def exercise(loop):
            session = self.new_session(loop)
            with self.assertRaises(DuplexProtocolError):
                await session.open()
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, DuplexState.FAILED)

    def test_explicit_interrupt_cancels_only_the_current_response(self):
        barge_ins: list[str] = []

        async def exercise(loop):
            session = self.new_session(
                loop,
                on_barge_in=lambda: barge_ins.append("stopped-local-output"),
            )
            await session.open()
            websocket = FakeClientSession.instances[0].websocket
            await websocket.messages.put(
                text_message(
                    {
                        "type": "response.created",
                        "response": {"id": "resp_active"},
                    }
                )
            )
            await asyncio.sleep(0)
            await session.interrupt()
            await session.interrupt()
            self.assertEqual(session.state, DuplexState.OPEN)
            await session.cancel()
            return websocket

        websocket = self.run_session(exercise)
        cancels = [
            event
            for event in websocket.sent_json
            if event["type"] == "response.cancel"
        ]
        self.assertEqual(
            cancels,
            [{"type": "response.cancel", "response_id": "resp_active"}],
        )
        self.assertEqual(barge_ins, ["stopped-local-output"])

    def test_server_vad_barge_in_suppresses_late_audio_after_cancel(self):
        audio: list[bytes] = []
        barge_ins: list[str] = []

        async def exercise(loop):
            session = self.new_session(
                loop,
                on_audio=audio.append,
                on_barge_in=lambda: barge_ins.append("barge-in"),
            )
            await session.open()
            websocket = FakeClientSession.instances[0].websocket
            await websocket.messages.put(
                text_message(
                    {
                        "type": "input_audio_buffer.speech_started",
                        "audio_start_ms": 10,
                    }
                )
            )
            await asyncio.sleep(0)
            await session.cancel()
            await websocket.messages.put(
                text_message(
                    {
                        "type": "response.output_audio.delta",
                        "delta": base64.b64encode(bytes(480)).decode("ascii"),
                    }
                )
            )
            await asyncio.sleep(0)
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, DuplexState.CANCELED)
        self.assertEqual(barge_ins, ["barge-in"])
        self.assertEqual(audio, [])

    def test_disconnect_fails_once_and_never_reconnects(self):
        errors: list[str] = []

        async def exercise(loop):
            session = self.new_session(loop, on_error=errors.append)
            await session.open()
            websocket = FakeClientSession.instances[0].websocket
            await websocket.messages.put(
                types.SimpleNamespace(type=aiohttp.WSMsgType.CLOSE, data=None)
            )
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            with self.assertRaises(DuplexError):
                await session.close()
            return session, FakeClientSession.instances[0]

        session, client = self.run_session(exercise)
        self.assertEqual(session.state, DuplexState.FAILED)
        self.assertEqual(len(client.connect_calls), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("disconnected", errors[0])

    def test_endpoint_query_is_part_of_the_reviewed_boundary(self):
        FakeClientSession.next_websocket = FakeWebSocket(
            url="wss://api.openai.com/v1/realtime?model=unreviewed"
        )

        async def exercise(loop):
            session = self.new_session(loop)
            with self.assertRaises(DuplexError):
                await session.open()
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, DuplexState.FAILED)
        self.assertEqual(len(FakeClientSession.instances[0].connect_calls), 1)


if __name__ == "__main__":
    unittest.main()
