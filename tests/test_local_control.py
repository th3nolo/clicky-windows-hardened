"""Standard-library coverage for the opt-in loopback control API."""

from __future__ import annotations

import concurrent.futures
import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from automation.local_control import HOST, LocalControlService


class LocalControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.endpoint = Path(self.directory.name) / "endpoint.json"
        self.submissions: list[tuple[str, int | None]] = []
        self.cancelled: list[str] = []

        def schedule(callback):
            future: concurrent.futures.Future[object] = concurrent.futures.Future()
            try:
                future.set_result(callback())
            except BaseException as error:
                future.set_exception(error)
            return future

        def submit(text: str, pid: int | None) -> str:
            self.submissions.append((text, pid))
            return str(len(self.submissions))

        self.service = LocalControlService(
            submit=submit, cancel=lambda task_id: self.cancelled.append(task_id) is None,
            schedule=schedule, endpoint_file=self.endpoint, enabled=True, event_capacity=8,
        )
        self.service.start()
        self.discovery = json.loads(self.endpoint.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.service.stop()
        self.directory.cleanup()

    def request(self, method: str, path: str, body: dict | None = None, *, origin: str | None = None, host: str | None = None, token: str | None = None, include_token: bool = True):
        raw = json.dumps(body).encode() if body is not None else None
        connection = HTTPConnection(HOST, self.discovery["port"])
        headers = {"Host": host or f"{HOST}:{self.discovery['port']}"}
        if include_token:
            headers["Authorization"] = f"Bearer {token if token is not None else self.discovery['token']}"
        if origin:
            headers["Origin"] = origin
        if raw is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, raw, headers)
        response = connection.getresponse()
        payload = json.loads(response.read().decode())
        connection.close()
        return response.status, payload

    def test_submit_is_idempotent_and_emits_bounded_structured_events(self) -> None:
        body = {"text": "Explain this", "notebook_pid": 77, "request_id": "request-1"}
        status, first = self.request("POST", "/v1/submit", body)
        self.assertEqual(status, 202)
        self.assertEqual(first["task_id"], "1")
        status, repeated = self.request("POST", "/v1/submit", body)
        self.assertEqual(status, 202)
        self.assertEqual(repeated["task_id"], "1")
        self.assertEqual(self.submissions, [("Explain this", 77)])
        self.service.record_progress("1", {"phase": "planned"})
        self.service.record_response("1", "Visible answer")
        status, events = self.request("GET", "/v1/events?task_id=1&cursor=0")
        self.assertEqual(status, 200)
        self.assertEqual([item["kind"] for item in events["events"]], ["submitted", "progress", "response"])
        self.assertEqual(events["next_cursor"], 3)

    def test_rejects_browser_origin_wrong_host_and_oversized_question(self) -> None:
        body = {"text": "x", "notebook_pid": 1, "request_id": "request-2"}
        self.assertEqual(self.request("POST", "/v1/submit", body, include_token=False)[0], 401)
        self.assertEqual(self.request("POST", "/v1/submit", body, token="wrong-token")[0], 401)
        self.assertEqual(self.request("POST", "/v1/submit", body, origin="http://evil.test")[0], 403)
        self.assertEqual(self.request("POST", "/v1/submit", body, host="localhost:1")[0], 403)
        body["text"] = "x" * 4097
        self.assertEqual(self.request("POST", "/v1/submit", body)[0], 400)

    def test_only_current_active_task_can_be_cancelled(self) -> None:
        _, task = self.request("POST", "/v1/submit", {"text": "cancel me", "notebook_pid": 9, "request_id": "request-3"})
        status, cancelled = self.request("POST", "/v1/cancel", {"task_id": task["task_id"]})
        self.assertEqual(status, 200)
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(self.cancelled, ["1"])
        self.assertEqual(self.request("POST", "/v1/cancel", {"task_id": "1"})[0], 400)

    def test_concurrent_same_request_id_submits_once(self) -> None:
        started = threading.Event()
        release = threading.Event()
        calls: list[str] = []

        def submit(text: str, _pid: int | None) -> str:
            calls.append(text)
            started.set()
            self.assertTrue(release.wait(timeout=2))
            return "parallel-1"

        service = LocalControlService(
            submit=submit, cancel=None, schedule=lambda callback: callback(),
            endpoint_file=Path(self.directory.name) / "parallel.json", enabled=False,
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(service.submit_task, text="once", notebook_pid=1, request_id="parallel-request")
            self.assertTrue(started.wait(timeout=1))
            second = pool.submit(service.submit_task, text="once", notebook_pid=1, request_id="parallel-request")
            release.set()
            self.assertEqual(first.result(timeout=2)["task_id"], "parallel-1")
            self.assertEqual(second.result(timeout=2)["task_id"], "parallel-1")
        self.assertEqual(calls, ["once"])

    def test_event_page_stays_below_cli_response_limit_and_paused_is_visible(self) -> None:
        _, task = self.request("POST", "/v1/submit", {"text": "observe", "notebook_pid": 4, "request_id": "request-4"})
        self.service.set_status(task["task_id"], "paused", reason="learner_interrupted")
        for _ in range(8):
            self.service.record_response(task["task_id"], "x" * 4096)
        status, events = self.request("GET", f"/v1/events?task_id={task['task_id']}&cursor=0")
        self.assertEqual(status, 200)
        self.assertEqual(events["status"], "paused")
        self.assertLessEqual(len(json.dumps(events, ensure_ascii=False).encode("utf-8")), 16 * 1024)

    def test_disabled_service_never_binds_a_port(self) -> None:
        disabled = LocalControlService(
            submit=lambda _text, _pid: "1", cancel=None, schedule=lambda callback: callback(),
            endpoint_file=Path(self.directory.name) / "disabled.json", enabled=False,
        )
        with self.assertRaisesRegex(ValueError, "disabled"):
            disabled.start()
        self.assertFalse(disabled.started)

    def test_live_discovery_owner_is_not_overwritten_or_unlinked(self) -> None:
        contender = LocalControlService(
            submit=lambda _text, _pid: "2", cancel=None, schedule=lambda callback: callback(),
            endpoint_file=self.endpoint, enabled=True,
        )
        with self.assertRaisesRegex(ValueError, "already owns"):
            contender.start()
        self.assertEqual(json.loads(self.endpoint.read_text(encoding="utf-8"))["token"], self.discovery["token"])
        replacement = {"version": 1, "host": HOST, "port": 1, "token": "replacement"}
        self.endpoint.write_text(json.dumps(replacement), encoding="utf-8")
        self.service.stop()
        self.assertEqual(json.loads(self.endpoint.read_text(encoding="utf-8")), replacement)


if __name__ == "__main__":
    unittest.main()
