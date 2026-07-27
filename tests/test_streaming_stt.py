"""Contract and transport regressions for bounded live transcription."""

from __future__ import annotations

import asyncio
import types
import unittest
from unittest import mock

import aiohttp
from yarl import URL

from audio.stt import deepgram_streaming as deepgram
from audio.stt.streaming import (
    StreamingSTTCapacityError,
    StreamingSTTConsentError,
    StreamingSTTError,
    StreamingSTTProtocolError,
    StreamingSTTState,
)


def result_message(
    transcript: str,
    *,
    is_final: bool = False,
    from_finalize: bool = False,
):
    return types.SimpleNamespace(
        type=aiohttp.WSMsgType.TEXT,
        data=(
            '{"type":"Results","is_final":'
            + ("true" if is_final else "false")
            + ',"from_finalize":'
            + ("true" if from_finalize else "false")
            + ',"channel":{"alternatives":[{"transcript":'
            + repr(transcript).replace("'", '"')
            + "}]}}"
        ),
    )


class FakeWebSocket:
    def __init__(self, *, history=(), finalize_result="hello world"):
        self._response = types.SimpleNamespace(
            url=URL(deepgram.DEEPGRAM_STREAMING_URL),
            history=history,
        )
        self.closed = False
        self.sent_bytes: list[bytes] = []
        self.sent_json: list[dict] = []
        self.messages: asyncio.Queue = asyncio.Queue()
        self.finalize_result = finalize_result

    async def send_bytes(self, value):
        self.sent_bytes.append(value)

    async def send_json(self, value):
        self.sent_json.append(value)
        if value == {"type": "Finalize"} and self.finalize_result is not None:
            await self.messages.put(
                result_message(
                    self.finalize_result,
                    is_final=True,
                    from_finalize=True,
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
        self.closed = False
        self.connect_calls: list[tuple[str, dict]] = []
        self.websocket = self.next_websocket or FakeWebSocket()
        type(self).instances.append(self)

    async def ws_connect(self, url, **kwargs):
        self.connect_calls.append((url, kwargs))
        return self.websocket

    async def close(self):
        self.closed = True


class DeepgramStreamingTests(unittest.TestCase):
    def setUp(self):
        FakeClientSession.instances = []
        FakeClientSession.next_websocket = None

    def run_session(self, exercise):
        async def run():
            loop = asyncio.get_running_loop()
            with mock.patch.object(
                deepgram.aiohttp, "ClientSession", FakeClientSession
            ):
                return await exercise(loop)

        return asyncio.run(run())

    def test_streams_frames_and_returns_one_final_transcript(self):
        partials: list[str] = []
        finals: list[str] = []

        async def exercise(loop):
            session = deepgram.DeepgramStreamingSession(
                api_key="secret-value",
                cloud_consent=True,
                loop=loop,
                vocabulary=("Clicky", " clicky ", "Nova"),
                on_partial=partials.append,
                on_final=finals.append,
            )
            session.send_frame(bytes(960))
            await session.open()
            client = FakeClientSession.instances[0]
            await client.websocket.messages.put(result_message("hello"))
            await asyncio.sleep(0)
            transcript = await session.finalize()
            return session, client, transcript

        session, client, transcript = self.run_session(exercise)
        self.assertEqual(transcript, "hello world")
        self.assertEqual(finals, ["hello world"])
        self.assertEqual(partials, ["hello"])
        self.assertEqual(client.websocket.sent_bytes, [bytes(960)])
        self.assertEqual(
            client.websocket.sent_json,
            [{"type": "Finalize"}, {"type": "CloseStream"}],
        )
        self.assertEqual(session.state, StreamingSTTState.CLOSED)

        self.assertFalse(client.kwargs["trust_env"])
        self.assertIsInstance(client.kwargs["cookie_jar"], aiohttp.DummyCookieJar)
        self.assertEqual(len(client.connect_calls), 1)
        url, kwargs = client.connect_calls[0]
        self.assertEqual(url, deepgram.DEEPGRAM_STREAMING_URL)
        self.assertEqual(kwargs["headers"], {"Authorization": "Token secret-value"})
        self.assertNotIn("secret-value", str(kwargs["params"]))
        self.assertEqual(
            [value for key, value in kwargs["params"] if key == "keywords"],
            ["Clicky", "Nova"],
        )
        self.assertIsNone(kwargs["proxy"])
        self.assertEqual(kwargs["compress"], 0)

    def test_cloud_consent_is_checked_before_client_creation(self):
        async def exercise(loop):
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=False,
                loop=loop,
            )
            with self.assertRaises(StreamingSTTConsentError):
                await session.open()
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.FAILED)
        self.assertEqual(FakeClientSession.instances, [])

    def test_cancel_suppresses_late_transcripts_and_is_idempotent(self):
        partials: list[str] = []

        async def exercise(loop):
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=True,
                loop=loop,
                on_partial=partials.append,
            )
            await session.open()
            websocket = FakeClientSession.instances[0].websocket
            await session.cancel()
            await websocket.messages.put(result_message("stale"))
            await asyncio.sleep(0)
            await session.cancel()
            return session, websocket

        session, websocket = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.CANCELED)
        self.assertTrue(websocket.closed)
        self.assertEqual(partials, [])

    def test_disconnect_is_explicit_and_never_reconnects(self):
        errors: list[str] = []

        async def exercise(loop):
            websocket = FakeWebSocket(finalize_result=None)
            FakeClientSession.next_websocket = websocket
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=True,
                loop=loop,
                on_error=errors.append,
            )
            await session.open()
            await websocket.messages.put(
                types.SimpleNamespace(type=aiohttp.WSMsgType.CLOSE, data=None)
            )
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            with self.assertRaises(StreamingSTTError):
                await session.finalize()
            return session, FakeClientSession.instances[0]

        session, client = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.FAILED)
        self.assertEqual(len(client.connect_calls), 1)
        self.assertTrue(client.closed)
        self.assertEqual(len(errors), 1)
        self.assertIn("disconnected", errors[0])

    def test_provider_error_is_explicit(self):
        async def exercise(loop):
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=True,
                loop=loop,
            )
            await session.open()
            websocket = FakeClientSession.instances[0].websocket
            await websocket.messages.put(
                types.SimpleNamespace(
                    type=aiohttp.WSMsgType.TEXT,
                    data='{"type":"Error","description":"do not expose me"}',
                )
            )
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            with self.assertRaisesRegex(StreamingSTTError, "rejected"):
                await session.finalize()
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.FAILED)

    def test_finalize_timeout_is_explicit(self):
        async def exercise(loop):
            FakeClientSession.next_websocket = FakeWebSocket(finalize_result=None)
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=True,
                loop=loop,
            )
            await session.open()
            with (
                mock.patch.object(deepgram, "FINALIZE_TIMEOUT_SECONDS", 0.01),
                self.assertRaisesRegex(StreamingSTTError, "timed out"),
            ):
                await session.finalize()
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.FAILED)

    def test_redirected_connection_is_rejected(self):
        async def exercise(loop):
            FakeClientSession.next_websocket = FakeWebSocket(history=(object(),))
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=True,
                loop=loop,
            )
            with self.assertRaises(StreamingSTTProtocolError):
                await session.open()
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.FAILED)
        self.assertTrue(FakeClientSession.instances[0].closed)

    def test_frame_rate_overflow_fails_closed(self):
        async def exercise(loop):
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=True,
                loop=loop,
            )
            for _ in range(deepgram.MAX_FRAMES_PER_SECOND + 1):
                session.send_frame(bytes(960))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.FAILED)
        self.assertIsInstance(session._failure, StreamingSTTCapacityError)

    def test_queue_overflow_fails_closed(self):
        async def exercise(loop):
            session = deepgram.DeepgramStreamingSession(
                api_key="secret",
                cloud_consent=True,
                loop=loop,
            )
            with mock.patch.object(deepgram, "MAX_FRAMES_PER_SECOND", 1_000):
                for _ in range(deepgram.MAX_QUEUE_FRAMES + 1):
                    session.send_frame(bytes(960))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return session

        session = self.run_session(exercise)
        self.assertEqual(session.state, StreamingSTTState.FAILED)
        self.assertIsInstance(session._failure, StreamingSTTCapacityError)

    def test_vocabulary_is_sanitized_deduplicated_and_bounded(self):
        terms = [" Clicky ", "clicky", "two\n words", "x" * 65, "\x00bad"]
        terms.extend(f"term-{index}" for index in range(100))
        clean = deepgram.sanitize_vocabulary(terms)
        self.assertEqual(clean[:2], ("Clicky", "two words"))
        self.assertLessEqual(len(clean), 64)
        self.assertTrue(all(0 < len(term) <= 64 for term in clean))


if __name__ == "__main__":
    unittest.main()
