"""Exercise the typed notebook worker through its actual JSONL pipe."""

import asyncio
import importlib.util
import json
import queue
import subprocess
import sys
import threading
import types
import unittest
from collections.abc import AsyncGenerator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from pydantic import ValidationError

from ai.base_provider import BaseLLMProvider
from clicky_core.commands import COMMANDS, Submit
from clicky_core.provider import ClickyProvider
from clicky_core.worker import Worker
from clicky_core.transport import MAX_LINE_BYTES
from tests.notebook_worker_runner import TestProvider

ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = {
    "scope": "notebook",
    "notebook_id": "libreta-ñ",
    "page_id": "page-2",
    "revision": 7,
}


class WorkerProcess:
    def __init__(self):
        # Exercise real transport with a test-only provider and no external calls.
        self.process = subprocess.Popen(
            [sys.executable, "-m", "tests.notebook_worker_runner"],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.output = queue.Queue()
        self.errors = []
        self.readers = [
            threading.Thread(target=self._read_output, daemon=True),
            threading.Thread(target=self._read_errors, daemon=True),
        ]
        for reader in self.readers:
            reader.start()

    def _read_output(self):
        for line in self.process.stdout:
            self.output.put(line)
        self.output.put(None)

    def _read_errors(self):
        for line in self.process.stderr:
            self.errors.append(line)

    def send(self, *commands):
        self.raw(
            b"".join(
                (json.dumps(command, ensure_ascii=False) + "\n").encode("utf-8")
                for command in commands
            )
        )

    def raw(self, data):
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def event(self, timeout=3):
        try:
            line = self.output.get(timeout=timeout)
        except queue.Empty as exc:
            raise AssertionError("Worker produced no event before timeout") from exc
        if line is None:
            raise AssertionError(f"Unexpected worker EOF: {self.errors!r}")
        event = json.loads(line)
        if event.get("protocol_version") != 1:
            raise AssertionError(f"Invalid protocol envelope: {event!r}")
        if "request_id" not in event or "type" not in event:
            raise AssertionError(f"Missing protocol envelope fields: {event!r}")
        return event

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=3)
        for reader in self.readers:
            reader.join(timeout=3)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()


def command(kind, request_id="request-1", **fields):
    return {"protocol_version": 1, "request_id": request_id, "type": kind, **fields}


def submit(turn="turn-1", request="submit-1", context=None):
    return command(
        "submit",
        request,
        turn_id=turn,
        text="¿Por qué x² = 4?",
        context=NOTEBOOK.copy() if context is None else context,
    )


class NotebookWorkerTests(unittest.TestCase):
    def setUp(self):
        self.worker = WorkerProcess()
        self.addCleanup(self.worker.close)

    def assert_event(self, event_type, request_id, **fields):
        event = self.worker.event()
        self.assertEqual(event["type"], event_type, event)
        self.assertEqual(event["request_id"], request_id, event)
        for key, value in fields.items():
            self.assertEqual(event.get(key), value, event)
        return event

    def finish_turn(self, request, turn, context):
        parts = []
        while True:
            event = self.worker.event()
            self.assertEqual(event["request_id"], request, event)
            self.assertEqual(event.get("turn_id"), turn, event)
            self.assertEqual(event.get("context"), context, event)
            if event["type"] == "done":
                self.assertEqual(event.get("status"), "completed", event)
                break
            self.assertEqual(event["type"], "text_delta", event)
            parts.append(event["delta"])
        self.assertIn("[Test]", "".join(parts))

    def test_capabilities_are_honest_and_startup_has_no_ready_event(self):
        with self.assertRaises(queue.Empty):
            self.worker.output.get(timeout=0.15)
        self.worker.send(command("capabilities"))
        event = self.assert_event("capabilities", "request-1")
        self.assertEqual(event["provider"], "test")
        self.assertEqual(event["inputs"], ["text"])
        self.assertIs(event["audio_in_video"], False)
        self.assertIs(event["tts"], False)

    def test_notebook_and_desktop_turns_preserve_exact_context(self):
        for context in (NOTEBOOK, {"scope": "desktop"}):
            with self.subTest(context=context):
                self.worker.send(submit(context=context))
                self.assert_event(
                    "state",
                    "submit-1",
                    status="processing",
                    turn_id="turn-1",
                    context=context,
                )
                self.finish_turn("submit-1", "turn-1", context)

    def test_cancel_then_new_turn_never_leaks_previous_output(self):
        self.worker.send(
            submit(),
            command("cancel", "cancel-1", turn_id="turn-1"),
            submit("turn-2", "submit-2", {"scope": "desktop"}),
        )
        self.assert_event("state", "submit-1", status="processing")
        self.assert_event(
            "done",
            "submit-1",
            status="cancelled",
            turn_id="turn-1",
            context=NOTEBOOK,
        )
        self.assert_event("ack", "cancel-1", status="cancelled")
        self.assert_event("state", "submit-2", status="processing")
        self.finish_turn("submit-2", "turn-2", {"scope": "desktop"})
        # A round trip after completion also detects queued output from turn-1.
        self.worker.send(command("capabilities", "after-cancel"))
        self.assert_event("capabilities", "after-cancel")

    def test_busy_and_mismatched_cancel_leave_active_turn_intact(self):
        self.worker.send(
            submit(),
            submit("turn-2", "submit-2"),
            command("cancel", "wrong-cancel", turn_id="not-active"),
        )
        self.assert_event("state", "submit-1", status="processing")
        self.assert_event("error", "submit-2", code="busy")
        self.assert_event("error", "wrong-cancel", code="turn_not_active")
        self.finish_turn("submit-1", "turn-1", NOTEBOOK)

    def test_invalid_requests_report_errors_and_worker_recovers(self):
        invalid = [
            b"{broken\n",
            b"[]\n",
            b"null\n",
            b"\xff\n",
            b'{"type":"shutdown","type":"capabilities"}\n',
            b'{"revision":NaN}\n',
            json.dumps(command("unknown")).encode() + b"\n",
        ]
        bad_commands = [
            {**command("capabilities"), "protocol_version": True},
            {**command("capabilities"), "protocol_version": 1.0},
            command("capabilities", "   "),
            {**command("capabilities"), "protocol_version": 2},
            command("capabilities", 12),
            command("capabilities", "r" * 129),
            {**submit(), "turn_id": "t" * 129},
            {**submit(), "text": ""},
            {**submit(), "text": "   "},
            {**submit(), "text": "x" * 8001},
            {**submit(), "text": ["not text"]},
            {**submit(), "video_path": "private-recording.mp4"},
            submit(context={**NOTEBOOK, "revision": True}),
            submit(context={**NOTEBOOK, "revision": -1}),
            submit(context={**NOTEBOOK, "revision": 1.5}),
            submit(context={"scope": "notebook"}),
            submit(context={"scope": "desktop", "page_id": "extra"}),
            submit(context={**NOTEBOOK, "capture_path": "other-app.png"}),
            submit(context={"scope": "all"}),
            {**submit(), "context": None},
        ]
        invalid.extend((json.dumps(item) + "\n").encode() for item in bad_commands)
        for payload in invalid:
            with self.subTest(payload=payload[:100]):
                self.worker.raw(payload)
                event = self.worker.event()
                self.assertEqual(event["type"], "error", event)
                self.assertEqual(event.get("code"), "invalid_request", event)
        self.worker.send(submit())
        self.assert_event("state", "submit-1", status="processing")
        self.finish_turn("submit-1", "turn-1", NOTEBOOK)

    def test_shutdown_exits_without_waiting_for_parent_to_close_stdin(self):
        self.worker.send(command("shutdown", "stop"))
        self.assert_event("ack", "stop", status="shutdown")
        self.assertFalse(self.worker.process.stdin.closed)
        self.assertEqual(self.worker.process.wait(timeout=3), 0)

    def test_eof_exits(self):
        self.worker.process.stdin.close()
        self.assertEqual(self.worker.process.wait(timeout=3), 0)

    def test_shutdown_cancels_active_turn_before_acknowledging(self):
        self.worker.send(submit(), command("shutdown", "stop"))
        self.assert_event("state", "submit-1", status="processing")
        self.assert_event("done", "submit-1", status="cancelled")
        self.assert_event("ack", "stop", status="shutdown")
        self.assertEqual(self.worker.process.wait(timeout=3), 0)
        self.assertIsNone(self.worker.output.get(timeout=3))

    def test_oversized_unterminated_line_is_bounded_and_fatal(self):
        # No newline: readline() without a bound would wait for more input.
        self.worker.raw(b"x" * (MAX_LINE_BYTES + 1))
        event = self.worker.event()
        self.assertEqual(event["type"], "error", event)
        self.assertEqual(event.get("code"), "invalid_request", event)
        self.worker.process.wait(timeout=3)


class TypedWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_validated_context_is_detached_and_immutable(self):
        raw = submit()
        parsed = COMMANDS.validate_python(raw)
        self.assertIsInstance(parsed, Submit)
        raw["context"]["page_id"] = "changed-after-validation"
        self.assertEqual(parsed.context.page_id, "page-2")
        with self.assertRaises(ValidationError):
            parsed.context.page_id = "mutated"

    async def test_stopped_worker_does_not_start_a_turn(self):
        events = []
        worker = Worker(TestProvider(), events.append)
        worker.close()
        worker.receive(submit())
        self.assertEqual(events[-1]["code"], "worker_stopped")
        self.assertIsNone(worker.active)
        self.assertFalse(worker.tasks)

    async def test_invalid_request_preserves_only_a_valid_correlation_id(self):
        events = []
        worker = Worker(TestProvider(), events.append)
        for request_id, expected in (("valid", "valid"), (123, None), (" ", None)):
            worker.receive(command("unsupported", request_id, secret="never echo this"))
            self.assertEqual(events[-1]["request_id"], expected)
            self.assertNotIn("never echo this", json.dumps(events[-1]))

    async def test_started_provider_is_closed_after_cancel_and_cannot_emit_stale_text(
        self,
    ):
        started = asyncio.Event()
        closed = asyncio.Event()
        events = []

        class Provider:
            name = "test"
            video_enabled = False

            async def generate(self, request: Submit) -> AsyncGenerator[str, None]:
                if request.turn_id == "turn-2":
                    yield "new response"
                    return
                try:
                    yield "first response"
                    started.set()
                    try:
                        await asyncio.Event().wait()
                    except asyncio.CancelledError:
                        yield "stale response"
                finally:
                    closed.set()

        worker = Worker(Provider(), events.append)
        self.addCleanup(worker.close)
        worker.receive(submit())
        # This in-memory provider has no suspension before setting started.
        # Hand off to the already queued worker instead of timing CI scheduling.
        await asyncio.sleep(0)
        self.assertTrue(started.is_set(), events)
        worker.receive(command("cancel", "cancel-1", turn_id="turn-1"))
        worker.receive(submit("turn-2", "submit-2"))
        tasks = tuple(worker.tasks)
        await asyncio.sleep(0)
        self.assertTrue(all(task.done() for task in tasks), events)
        for task in tasks:
            task.result()
        self.assertTrue(closed.is_set())
        self.assertNotIn("stale response", json.dumps(events))
        done = [event for event in events if event["type"] == "done"]
        self.assertEqual(
            [(event["turn_id"], event["status"]) for event in done],
            [("turn-1", "cancelled"), ("turn-2", "completed")],
        )

    async def test_provider_failure_completes_once_and_next_turn_succeeds(self):
        events = []

        class Provider:
            name = "test"
            video_enabled = False

            async def generate(self, request: Submit) -> AsyncGenerator[str, None]:
                if request.turn_id == "turn-1":
                    raise RuntimeError("private provider details")
                yield "recovered"

        worker = Worker(Provider(), events.append)
        worker.receive(submit())
        await asyncio.wait_for(asyncio.gather(*worker.tasks), timeout=1)
        self.assertEqual(events[-2]["code"], "provider_error")
        self.assertEqual(events[-1]["status"], "failed")
        self.assertNotIn("private provider details", json.dumps(events))
        worker.receive(submit("turn-2", "submit-2"))
        await asyncio.wait_for(asyncio.gather(*worker.tasks), timeout=1)
        self.assertEqual(events[-1]["status"], "completed")
        self.assertEqual(len([e for e in events if e["type"] == "done"]), 2)

    async def test_openai_backend_closes_network_stream_on_early_exit(self):
        spec = importlib.util.spec_from_file_location(
            "notebook_openai_provider", ROOT / "ai" / "openai_provider.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.create_openai_client = Mock()
        stream = MagicMock()
        stream.__aiter__.return_value = iter(
            [
                types.SimpleNamespace(
                    choices=[
                        types.SimpleNamespace(
                            delta=types.SimpleNamespace(content="partial")
                        )
                    ]
                )
            ]
        )
        stream.close = AsyncMock()
        provider = module.OpenAIProvider()
        provider._client.chat.completions.create = AsyncMock(return_value=stream)
        response = provider.stream_response(
            "question", [], [], "hint", model="chosen-model"
        )
        self.assertEqual(await anext(response), "partial")
        await response.aclose()
        stream.close.assert_awaited_once()

    async def test_adapter_streams_existing_backend_with_explicit_model(self):
        async def chunks():
            yield "first"
            yield "second"

        backend = Mock(spec=BaseLLMProvider)
        backend.stream_response.return_value = chunks()
        provider = ClickyProvider("configured-provider", "chosen-model", backend)
        parsed = Submit.model_validate(submit())
        self.assertEqual(
            [chunk async for chunk in provider.generate(parsed)], ["first", "second"]
        )
        arguments = backend.stream_response.call_args.kwargs
        self.assertEqual(arguments["user_text"], parsed.text)
        self.assertEqual(arguments["model"], "chosen-model")
        self.assertEqual(arguments["screenshots_b64"], [])
        self.assertEqual(arguments["history"], [])


if __name__ == "__main__":
    unittest.main()
