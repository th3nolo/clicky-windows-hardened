"""Opt-in, loopback-only control API for a running Clicky process.

This module deliberately has no Qt import.  The application supplies a small
adapter which schedules every manager call onto the Qt thread; HTTP worker
threads only validate requests and wait for that adapter's result.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit


HOST = "127.0.0.1"
MAX_BODY_BYTES = 16 * 1024
MAX_TEXT_CHARS = 4 * 1024
MAX_EVENT_CAPACITY = 256
MAX_EVENT_PAYLOAD_BYTES = 8 * 1024
MAX_REQUEST_ID_CHARS = 128
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ACTIVE_STATUSES = frozenset({"queued", "active", "running", "cancelling"})
_PAUSED_STATUSES = frozenset({"paused"})
_TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})
_KNOWN_STATUSES = _ACTIVE_STATUSES | _PAUSED_STATUSES | _TERMINAL_STATUSES


class LocalControlError(ValueError):
    """The caller supplied an invalid local-control value."""


class LocalControlBusy(RuntimeError):
    """Clicky already has a task that cannot run concurrently."""


def default_endpoint_file() -> Path:
    """Return a per-user, non-roaming discovery location.

    The bearer token is intentionally kept in this local file rather than a
    command-line flag, environment variable, or HTTP response.
    """
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
    return root / "Clicky" / "local-control.json"


def _bounded_value(value: Any, *, depth: int = 0) -> Any:
    """Make callback data JSON safe and bounded before it reaches the CLI."""
    if depth > 5:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:MAX_TEXT_CHARS]
    if isinstance(value, Mapping):
        return {str(key)[:96]: _bounded_value(item, depth=depth + 1)
                for key, item in list(value.items())[:32]}
    if isinstance(value, (list, tuple)):
        return [_bounded_value(item, depth=depth + 1) for item in value[:32]]
    return str(value)[:MAX_TEXT_CHARS]


def _identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise LocalControlError(f"{field_name} must be a short safe identifier")
    return value


def _notebook_pid(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value <= 0:
        raise LocalControlError("notebook_pid must be a positive integer")
    return value


def _task_id(value: object) -> str:
    if isinstance(value, int) and value >= 0:
        return str(value)
    if isinstance(value, str) and 1 <= len(value) <= MAX_REQUEST_ID_CHARS:
        return value
    raise LocalControlError("submitter returned an invalid task ID")


@dataclass(slots=True)
class _Task:
    task_id: str
    request_id: str
    notebook_pid: int | None
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    fields: dict[str, Any] = field(default_factory=dict)
    events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=MAX_EVENT_CAPACITY))


@dataclass(slots=True)
class _Request:
    text: str
    notebook_pid: int | None
    completion: concurrent.futures.Future[dict[str, object]] = field(default_factory=concurrent.futures.Future)
    task_id: str | None = None


class LocalControlService:
    """A bearer-protected HTTP server with an intentionally narrow task API.

    ``schedule`` receives a zero-argument callback and may return either its
    result or a ``concurrent.futures.Future``.  Clicky's Qt adapter should
    enqueue that callback with a queued Qt signal/timer and return a Future.
    This is the only route by which ``submit``, ``cancel`` and ``status`` run.
    """

    def __init__(
        self,
        *,
        submit: Callable[[str, int | None], object],
        cancel: Callable[[str], bool] | None,
        schedule: Callable[[Callable[[], object]], object],
        status: Callable[[str], Mapping[str, object] | None] | None = None,
        endpoint_file: str | Path | None = None,
        enabled: bool = False,
        event_capacity: int = MAX_EVENT_CAPACITY,
        max_tasks: int = 128,
    ) -> None:
        if event_capacity < 8 or event_capacity > 2048:
            raise ValueError("event_capacity must be between 8 and 2048")
        if max_tasks < 8 or max_tasks > 4096:
            raise ValueError("max_tasks must be between 8 and 4096")
        self._submit = submit
        self._cancel = cancel
        self._schedule = schedule
        self._status_provider = status
        self._endpoint_file = Path(endpoint_file) if endpoint_file is not None else default_endpoint_file()
        self._enabled = bool(enabled)
        self._event_capacity = event_capacity
        self._max_tasks = max_tasks
        self._lock = threading.RLock()
        self._tasks: dict[str, _Task] = {}
        self._requests: dict[str, _Request] = {}
        self._next_event = 1
        self._token: str | None = None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def endpoint_file(self) -> Path:
        return self._endpoint_file

    @property
    def started(self) -> bool:
        return self._server is not None

    def start(self) -> Path:
        """Bind an ephemeral port only when the caller explicitly enabled it."""
        if not self._enabled:
            raise LocalControlError("local control is disabled")
        with self._lock:
            if self._server is not None:
                return self._endpoint_file
            service = self

            class Handler(_Handler):
                control_service = service

            server = ThreadingHTTPServer((HOST, 0), Handler)
            server.daemon_threads = True
            server.allow_reuse_address = False
            if self._endpoint_file.exists() and self._endpoint_is_live():
                server.server_close()
                raise LocalControlError("a live local-control endpoint already owns this discovery file")
            self._server = server
            self._token = secrets.token_urlsafe(32)
            try:
                self._write_endpoint_file(server.server_address[1])
            except Exception:
                server.server_close()
                self._server = None
                self._token = None
                raise
            self._thread = threading.Thread(
                target=server.serve_forever, name="clicky-local-control", daemon=True
            )
            self._thread.start()
        return self._endpoint_file

    def stop(self) -> None:
        with self._lock:
            server, thread, token = self._server, self._thread, self._token
            self._server = None
            self._thread = None
            self._token = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2)
        self._remove_endpoint_file(token)

    def _endpoint_is_live(self) -> bool:
        try:
            endpoint = _load_endpoint(self._endpoint_file)
            connection = HTTPConnection(HOST, int(endpoint["port"]), timeout=0.25)
            try:
                connection.request("GET", "/v1/status?task_id=probe", headers={
                    "Host": f"{HOST}:{endpoint['port']}",
                    "Authorization": f"Bearer {endpoint['token']}",
                })
                connection.getresponse().read(1)
                return True
            finally:
                connection.close()
        except (OSError, ValueError, LocalControlError):
            return False

    def _remove_endpoint_file(self, token: str | None) -> None:
        if token is None:
            return
        try:
            current = json.loads(self._endpoint_file.read_text(encoding="utf-8"))
            if not isinstance(current, dict) or not secrets.compare_digest(str(current.get("token", "")), token):
                return
            self._endpoint_file.unlink(missing_ok=True)
        except (OSError, json.JSONDecodeError):
            return

    def _write_endpoint_file(self, port: int) -> None:
        parent = self._endpoint_file.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps({"version": 1, "host": HOST, "port": port, "token": self._token}, separators=(",", ":"))
        fd, temporary_name = tempfile.mkstemp(prefix=".local-control-", suffix=".tmp", dir=parent)
        temporary = Path(temporary_name)
        try:
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self._endpoint_file)
            try:
                os.chmod(self._endpoint_file, 0o600)
            except OSError:
                pass
        finally:
            if temporary.exists():
                temporary.unlink(missing_ok=True)

    def _call_on_root(self, callback: Callable[[], object]) -> object:
        result = self._schedule(callback)
        if isinstance(result, concurrent.futures.Future) or hasattr(result, "result"):
            return result.result(timeout=10)  # type: ignore[union-attr]
        return result

    def submit_task(self, *, text: object, notebook_pid: object, request_id: object) -> dict[str, object]:
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARS:
            raise LocalControlError("text must be non-empty and at most 4096 characters")
        pid = _notebook_pid(notebook_pid)
        request = _identifier(request_id, "request_id")
        normalized_text = text.strip()
        with self._lock:
            existing = self._requests.get(request)
            if existing is not None:
                if existing.text != normalized_text or existing.notebook_pid != pid:
                    raise LocalControlError("request_id was already used for different input")
                completion = existing.completion
                owner = False
            else:
                self._evict_terminal_locked()
                if len(self._requests) >= self._max_tasks:
                    raise LocalControlBusy("local control task history is full")
                completion = concurrent.futures.Future()
                self._requests[request] = _Request(normalized_text, pid, completion)
                owner = True
            if not owner:
                # An in-flight duplicate waits for the original scheduled Qt
                # submission.  It cannot submit a second notebook mutation.
                pass
            if owner and any(task.status in _ACTIVE_STATUSES for task in self._tasks.values()):
                completion.set_exception(LocalControlBusy("another Clicky task is active"))
                del self._requests[request]
                raise LocalControlBusy("another Clicky task is active")
        if not owner:
            return completion.result(timeout=11)
        try:
            outcome = self._call_on_root(lambda: self._submit(normalized_text, pid))
        except Exception as error:
            # The root callback may have started a task and timed out before it
            # could report an ID.  Retain this request as outcome-unknown so a
            # retry cannot replay a possibly-mutating notebook operation.
            unknown = LocalControlError("submission outcome is unknown; do not retry this request_id")
            completion.set_exception(unknown)
            raise unknown from error
        try:
            if isinstance(outcome, Mapping):
                if outcome.get("status") == "rejected" or outcome.get("error"):
                    message = str(outcome.get("error", "Clicky rejected the task"))
                    if outcome.get("busy"):
                        raise LocalControlBusy(message)
                    raise LocalControlError(message)
                if outcome.get("busy"):
                    raise LocalControlBusy("another Clicky task is active")
                identifier = outcome.get("task_id", outcome.get("taskID"))
                initial_status = str(outcome.get("status", "active"))
                extra = {str(key): value for key, value in outcome.items() if key not in {"task_id", "taskID", "status"}}
            else:
                identifier, initial_status, extra = outcome, "active", {}
            task_id = _task_id(identifier)
            if initial_status not in _KNOWN_STATUSES:
                initial_status = "active"
            with self._lock:
                # The root-side submitter is authoritative; keep duplicate IDs safe.
                task = self._tasks.get(task_id)
                if task is None:
                    task = _Task(task_id=task_id, request_id=request, notebook_pid=pid,
                                 status=initial_status,
                                 events=deque(maxlen=self._event_capacity))
                    self._tasks[task_id] = task
                task.fields.update(_bounded_value(extra))
                self._requests[request].task_id = task_id
                self._append_event(task, "submitted", {"status": task.status, "notebook_pid": pid})
                public = self._public_task(task)
                completion.set_result(public)
                return public
        except Exception as error:
            if not completion.done():
                completion.set_exception(error)
            raise

    def _evict_terminal_locked(self) -> None:
        while len(self._requests) >= self._max_tasks:
            removable = [task for task in self._tasks.values() if task.status in _TERMINAL_STATUSES | _PAUSED_STATUSES]
            if not removable:
                return
            oldest = min(removable, key=lambda task: task.updated_at)
            self._tasks.pop(oldest.task_id, None)
            self._requests.pop(oldest.request_id, None)

    def set_status(self, task_id: object, status: object, **fields: object) -> None:
        identifier = _task_id(task_id)
        if not isinstance(status, str) or status not in _KNOWN_STATUSES:
            raise LocalControlError("invalid task status")
        with self._lock:
            task = self._tasks.get(identifier)
            if task is None:
                return
            task.status = status
            task.updated_at = time.time()
            task.fields.update(_bounded_value(fields))
            self._append_event(task, "status", {"status": status, **fields})

    def record_event(self, task_id: object, kind: object, payload: Mapping[str, object] | None = None) -> None:
        identifier = _task_id(task_id)
        if not isinstance(kind, str) or not _REQUEST_ID.fullmatch(kind):
            raise LocalControlError("event kind must be a short safe identifier")
        with self._lock:
            task = self._tasks.get(identifier)
            if task is not None:
                self._append_event(task, kind, payload or {})

    def record_progress(self, task_id: object, progress: Mapping[str, object]) -> None:
        self.record_event(task_id, "progress", progress)

    def record_plan(self, task_id: object, plan: Mapping[str, object]) -> None:
        """Expose a bounded, user-visible action plan, never internal reasoning."""
        self.record_event(task_id, "plan", plan)

    def record_response(self, task_id: object, response: object) -> None:
        self.record_event(task_id, "response", {"text": response})

    def record_tool_receipt(self, task_id: object, receipt: Mapping[str, object]) -> None:
        self.record_event(task_id, "tool_receipt", receipt)

    def record_error(self, task_id: object, error: object) -> None:
        self.record_event(task_id, "error", {"message": error})

    def record_token_usage(self, task_id: object, usage: Mapping[str, object]) -> None:
        self.record_event(task_id, "token_usage", usage)

    def _append_event(self, task: _Task, kind: str, payload: Mapping[str, object]) -> None:
        safe_payload = _bounded_value(payload)
        encoded = json.dumps(safe_payload, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
            safe_payload = {"message": "event payload truncated"}
        event = {"sequence": self._next_event, "at": time.time(), "kind": kind, "payload": safe_payload}
        self._next_event += 1
        task.events.append(event)
        task.updated_at = event["at"]

    def cancel_task(self, task_id: object) -> dict[str, object]:
        identifier = _task_id(task_id)
        with self._lock:
            task = self._tasks.get(identifier)
            if task is None or task.status not in _ACTIVE_STATUSES:
                raise LocalControlError("task is not an active task")
            if self._cancel is None:
                raise LocalControlError("task cancellation is unavailable")
            task.status = "cancelling"
            self._append_event(task, "status", {"status": "cancelling"})
        accepted = bool(self._call_on_root(lambda: self._cancel(identifier)))
        with self._lock:
            task = self._tasks.get(identifier)
            if task is not None:
                task.status = "cancelled" if accepted else "active"
                self._append_event(task, "cancelled" if accepted else "cancel_rejected", {})
                return self._public_task(task)
        raise LocalControlError("task disappeared while cancelling")

    def get_status(self, task_id: object) -> dict[str, object]:
        identifier = _task_id(task_id)
        with self._lock:
            task = self._tasks.get(identifier)
            if task is None:
                raise LocalControlError("unknown task")
        if self._status_provider is not None:
            observed = self._call_on_root(lambda: self._status_provider(identifier))
            if isinstance(observed, Mapping) and "status" in observed:
                self.set_status(identifier, observed["status"], **{str(k): v for k, v in observed.items() if k != "status"})
        with self._lock:
            return self._public_task(self._tasks[identifier])

    def get_events(self, task_id: object, cursor: object = 0) -> dict[str, object]:
        identifier = _task_id(task_id)
        if type(cursor) is not int or cursor < 0:
            raise LocalControlError("cursor must be a non-negative integer")
        with self._lock:
            task = self._tasks.get(identifier)
            if task is None:
                raise LocalControlError("unknown task")
            events: list[dict[str, Any]] = []
            used = 160
            for event in task.events:
                if event["sequence"] <= cursor:
                    continue
                event_size = len(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                if events and used + event_size > MAX_BODY_BYTES - 256:
                    break
                if event_size > MAX_BODY_BYTES - 256:
                    continue
                events.append(event)
                used += event_size
            next_cursor = events[-1]["sequence"] if events else cursor
            return {"task_id": identifier, "cursor": cursor, "next_cursor": next_cursor,
                    "events": events, "status": task.status}

    @staticmethod
    def _public_task(task: _Task) -> dict[str, object]:
        return {"task_id": task.task_id, "request_id": task.request_id,
                "notebook_pid": task.notebook_pid, "status": task.status,
                "created_at": task.created_at, "updated_at": task.updated_at,
                "details": _bounded_value(task.fields)}


class _Handler(BaseHTTPRequestHandler):
    control_service: LocalControlService
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        # Authorization headers and task contents must never enter stdout/stderr.
        return

    def _reject_bad_origin(self) -> bool:
        server = self.control_service._server
        expected_host = f"{HOST}:{server.server_address[1]}" if server else ""
        if self.headers.get("Host") != expected_host or self.headers.get("Origin"):
            self._send(403, {"error": "browser and non-loopback origins are rejected"})
            return True
        authorization = self.headers.get("Authorization", "")
        expected = f"Bearer {self.control_service._token}"
        if not secrets.compare_digest(authorization, expected):
            self._send(401, {"error": "authorization required"})
            return True
        return False

    def _body(self) -> dict[str, object] | None:
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(413, {"error": "request body is too large"})
            return None
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(400, {"error": "body must be a JSON object"})
            return None
        if not isinstance(value, dict):
            self._send(400, {"error": "body must be a JSON object"})
            return None
        return value

    def _send(self, status: int, payload: Mapping[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        if self._reject_bad_origin():
            return
        body = self._body()
        if body is None:
            return
        try:
            if self.path == "/v1/submit":
                self._send(202, self.control_service.submit_task(
                    text=body.get("text"), notebook_pid=body.get("notebook_pid"), request_id=body.get("request_id")
                ))
            elif self.path == "/v1/cancel":
                self._send(200, self.control_service.cancel_task(body.get("task_id")))
            else:
                self._send(404, {"error": "unknown endpoint"})
        except LocalControlBusy as error:
            self._send(409, {"error": str(error), "busy": True})
        except (LocalControlError, TimeoutError, concurrent.futures.TimeoutError) as error:
            self._send(400, {"error": str(error)})
        except Exception:
            self._send(500, {"error": "local control request failed"})

    def do_GET(self) -> None:  # noqa: N802
        if self._reject_bad_origin():
            return
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        task_id = query.get("task_id", [None])[0]
        try:
            if parsed.path == "/v1/status":
                self._send(200, self.control_service.get_status(task_id))
            elif parsed.path == "/v1/events":
                raw_cursor = query.get("cursor", ["0"])[0]
                self._send(200, self.control_service.get_events(task_id, int(raw_cursor)))
            else:
                self._send(404, {"error": "unknown endpoint"})
        except (LocalControlError, ValueError, TimeoutError, concurrent.futures.TimeoutError) as error:
            self._send(400, {"error": str(error)})
        except Exception:
            self._send(500, {"error": "local control request failed"})


def _load_endpoint(path: str | Path) -> dict[str, object]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LocalControlError("local control endpoint file cannot be read") from error
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise LocalControlError("local control endpoint file is invalid")
    if payload.get("host") != HOST or type(payload.get("port")) is not int or not isinstance(payload.get("token"), str):
        raise LocalControlError("local control endpoint file is invalid")
    return payload


def _cli_request(endpoint_file: str | Path, method: str, path: str, body: Mapping[str, object] | None = None) -> dict[str, object]:
    endpoint = _load_endpoint(endpoint_file)
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
    connection = HTTPConnection(HOST, int(endpoint["port"]), timeout=15)
    try:
        connection.request(method, path, body=raw, headers={
            "Host": f"{HOST}:{endpoint['port']}",
            "Authorization": f"Bearer {endpoint['token']}",
            "Content-Type": "application/json",
        })
        response = connection.getresponse()
        data = response.read(MAX_BODY_BYTES + 1)
        if len(data) > MAX_BODY_BYTES:
            raise LocalControlError("local control response is too large")
        parsed = json.loads(data.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise LocalControlError("local control response is invalid")
        if response.status >= 400:
            raise LocalControlError(str(parsed.get("error", f"HTTP {response.status}")))
        return parsed
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Control an opted-in local Clicky instance")
    parser.add_argument("--endpoint-file", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    submit = commands.add_parser("submit")
    submit.add_argument("--text-file", required=True, type=Path)
    submit.add_argument("--notebook-pid", required=True, type=int)
    submit.add_argument("--request-id", default=None)
    status = commands.add_parser("status")
    status.add_argument("--task-id", required=True)
    events = commands.add_parser("events")
    events.add_argument("--task-id", required=True)
    events.add_argument("--cursor", type=int, default=0)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("--task-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "submit":
            text = args.text_file.read_text(encoding="utf-8")
            result = _cli_request(args.endpoint_file, "POST", "/v1/submit", {
                "text": text, "notebook_pid": args.notebook_pid,
                "request_id": args.request_id or uuid.uuid4().hex,
            })
        elif args.command == "status":
            result = _cli_request(args.endpoint_file, "GET", f"/v1/status?task_id={args.task_id}")
        elif args.command == "events":
            result = _cli_request(args.endpoint_file, "GET", f"/v1/events?task_id={args.task_id}&cursor={args.cursor}")
        else:
            result = _cli_request(args.endpoint_file, "POST", "/v1/cancel", {"task_id": args.task_id})
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, LocalControlError) as error:
        print(f"local-control: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
