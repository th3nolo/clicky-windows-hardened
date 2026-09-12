"""Exercise the dependency-free notebook worker through its actual JSONL pipe."""

import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK = {
    "scope": "notebook",
    "notebook_id": "libreta-ñ",
    "page_id": "page-2",
    "revision": 7,
}


class WorkerProcess:
    def __init__(self):
        # -S excludes site packages: starting the worker must not require Qt,
        # microphone libraries, credentials, or installed model SDKs.
        self.process = subprocess.Popen(
            [sys.executable, "-S", "-m", "clicky_core"],
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
        self.raw(b"".join(
            (json.dumps(command, ensure_ascii=False) + "\n").encode("utf-8")
            for command in commands
        ))

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
        "submit", request, turn_id=turn, text="¿Por qué x² = 4?",
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
        self.assertIn("[Demo]", "".join(parts))

    def test_capabilities_are_honest_and_startup_has_no_ready_event(self):
        with self.assertRaises(queue.Empty):
            self.worker.output.get(timeout=0.15)
        self.worker.send(command("capabilities"))
        event = self.assert_event("capabilities", "request-1")
        self.assertEqual(event["provider"], "demo")
        self.assertEqual(event["inputs"], ["text"])
        self.assertIs(event["audio_in_video"], False)
        self.assertIs(event["tts"], False)

    def test_notebook_and_desktop_turns_preserve_exact_context(self):
        for context in (NOTEBOOK, {"scope": "desktop"}):
            with self.subTest(context=context):
                self.worker.send(submit(context=context))
                self.assert_event(
                    "state", "submit-1", status="processing",
                    turn_id="turn-1", context=context,
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
            "done", "submit-1", status="cancelled",
            turn_id="turn-1", context=NOTEBOOK,
        )
        self.assert_event("ack", "cancel-1", status="cancelled")
        self.assert_event("state", "submit-2", status="processing")
        self.finish_turn("submit-2", "turn-2", {"scope": "desktop"})
        # A round trip after completion also detects queued output from turn-1.
        self.worker.send(command("capabilities", "after-cancel"))
        self.assert_event("capabilities", "after-cancel")

    def test_busy_and_mismatched_cancel_leave_active_turn_intact(self):
        self.worker.send(
            submit(), submit("turn-2", "submit-2"),
            command("cancel", "wrong-cancel", turn_id="not-active"),
        )
        self.assert_event("state", "submit-1", status="processing")
        self.assert_event("error", "submit-2", code="busy")
        self.assert_event("error", "wrong-cancel", code="turn_not_active")
        self.finish_turn("submit-1", "turn-1", NOTEBOOK)

    def test_invalid_requests_report_errors_and_worker_recovers(self):
        invalid = [
            b"{broken\n", b"[]\n", b"null\n", b"\xff\n",
            json.dumps(command("unknown")).encode() + b"\n",
        ]
        bad_commands = [
            {**command("capabilities"), "protocol_version": True},
            {**command("capabilities"), "protocol_version": 2},
            command("capabilities", 12),
            command("capabilities", "r" * 129),
            {**submit(), "turn_id": "t" * 129},
            {**submit(), "text": ""},
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
        self.worker.raw(b"x" * 65537)
        event = self.worker.event()
        self.assertEqual(event["type"], "error", event)
        self.assertEqual(event.get("code"), "invalid_request", event)
        self.worker.process.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
