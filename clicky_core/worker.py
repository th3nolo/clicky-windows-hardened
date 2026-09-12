"""Versioned JSONL worker. The bundled provider is an explicit text-only demo."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
import json
import os
import queue
import sys
import threading
from typing import Any, Protocol

from turn_coordinator import TurnCoordinator, TurnSession

MAX_LINE_BYTES = 65536


class ReasoningProvider(Protocol):
    def generate(self, text: str, context: dict[str, Any]) -> AsyncIterator[str]: ...


class DemoProvider:
    """Exercise transport and cancellation without pretending to provide AI."""

    async def generate(self, text: str, context: dict[str, Any]) -> AsyncIterator[str]:
        await asyncio.sleep(0.1)
        yield f"[Demo] Received: {text}\nNo AI reasoning, video or speech is enabled."


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 128


def validate_command(raw: Any) -> dict[str, Any]:
    """Validate the complete command before changing any state."""
    if not isinstance(raw, dict):
        raise ValueError("Command must be a JSON object")
    if type(raw.get("protocol_version")) is not int or raw["protocol_version"] != 1:
        raise ValueError("protocol_version must be 1")
    if not _identifier(raw.get("request_id")):
        raise ValueError("request_id must be a nonempty string of at most 128 characters")
    kind = raw.get("type")
    if kind not in ("capabilities", "submit", "cancel", "shutdown"):
        raise ValueError("Unsupported command type")
    fields = {"protocol_version", "request_id", "type"}
    if kind in ("submit", "cancel"):
        fields.add("turn_id")
        if not _identifier(raw.get("turn_id")):
            raise ValueError("turn_id must be a nonempty string of at most 128 characters")
    if kind == "submit":
        fields.update(("text", "context"))
        text = raw.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > 8000:
            raise ValueError("text must be a nonempty string of at most 8000 characters")
        context = raw.get("context")
        if not isinstance(context, dict) or context.get("scope") not in ("notebook", "desktop"):
            raise ValueError("context.scope must be notebook or desktop")
        expected = {"scope"}
        if context["scope"] == "notebook":
            expected.update(("notebook_id", "page_id", "revision"))
            if not all(_identifier(context.get(key)) for key in ("notebook_id", "page_id")):
                raise ValueError("Notebook context requires notebook_id and page_id")
            if type(context.get("revision")) is not int or context["revision"] < 0:
                raise ValueError("revision must be a nonnegative integer")
        if set(context) != expected:
            raise ValueError("Unsupported or missing context fields")
    if set(raw) != fields:
        raise ValueError("Unsupported or missing command fields")
    return raw


def _write_event(event: dict[str, Any]) -> None:
    # ASCII escapes keep JSONL valid even on Windows consoles with legacy encodings.
    print(json.dumps(event, ensure_ascii=True), flush=True)


@dataclass(frozen=True)
class ActiveTurn:
    session: TurnSession
    request_id: str
    turn_id: str
    context: dict[str, Any]


class Worker:
    """Single-event-loop owner of provider tasks and their correlated events."""

    def __init__(self, provider: ReasoningProvider | None = None,
                 emit: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.provider = provider if provider is not None else DemoProvider()
        self.emit = emit if emit is not None else _write_event
        self.coordinator = TurnCoordinator()
        self.active: ActiveTurn | None = None
        self.tasks: set[asyncio.Task] = set()
        self.stopped = False

    def event(self, request_id: str | None, kind: str, **fields: Any) -> None:
        self.emit({"protocol_version": 1, "request_id": request_id, "type": kind, **fields})

    def error(self, request_id: str | None, code: str, message: str) -> None:
        self.event(request_id, "error", code=code, message=message)

    def turn_event(self, turn: ActiveTurn, kind: str, **fields: Any) -> None:
        self.event(turn.request_id, kind, turn_id=turn.turn_id,
                   context=dict(turn.context), **fields)

    def cancel_active(self) -> None:
        turn = self.active
        if turn is not None:
            self.active = None
            self.coordinator.cancel(turn.session)
            self.turn_event(turn, "done", status="cancelled")

    def handle(self, raw: Any) -> None:
        request_id = raw.get("request_id") if isinstance(raw, dict) else None
        if not _identifier(request_id):
            request_id = None
        try:
            command = validate_command(raw)
        except ValueError as exc:
            self.error(request_id, "invalid_request", str(exc))
            return
        if self.stopped:
            self.error(request_id, "worker_stopped", "Worker has shut down")
            return
        kind = command["type"]
        if kind == "capabilities":
            self.event(request_id, "capabilities", provider="demo", inputs=["text"],
                       audio_in_video=False, tts=False)
        elif kind == "shutdown":
            self.close()
            self.event(request_id, "ack", status="shutdown")
        elif kind == "cancel":
            if self.active is None or self.active.turn_id != command["turn_id"]:
                self.error(request_id, "turn_not_active", "Requested turn is not active")
                return
            self.cancel_active()
            self.event(request_id, "ack", status="cancelled")
        else:
            session = self.coordinator.start_processing()
            if session is None:
                self.error(request_id, "busy", "Another turn is active")
                return
            turn = ActiveTurn(session, request_id, command["turn_id"], dict(command["context"]))
            self.active = turn
            self.turn_event(turn, "state", status="processing")
            task = asyncio.create_task(self._respond(turn, command["text"]))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            self.coordinator.bind_task(session, task)

    async def _respond(self, turn: ActiveTurn, text: str) -> None:
        try:
            async for delta in self.provider.generate(text, dict(turn.context)):
                if not self.coordinator.is_current(turn.session):
                    return
                if not isinstance(delta, str):
                    raise TypeError("Provider deltas must be text")
                self.turn_event(turn, "text_delta", delta=delta)
            if self.coordinator.complete(turn.session):
                self.active = None
                self.turn_event(turn, "done", status="completed")
        except asyncio.CancelledError:
            # The command handler emits the single cancellation event before any ack.
            raise
        except Exception:
            if self.coordinator.complete(turn.session):
                self.active = None
                self.turn_event(turn, "error", code="provider_error", message="Provider failed")
                self.turn_event(turn, "done", status="failed")

    def close(self) -> None:
        self.stopped = True
        self.cancel_active()


def _read_stdin(incoming: queue.Queue) -> None:
    """A daemon reader can block on Windows stdin without preventing shutdown."""
    try:
        pending = bytearray()
        while True:
            # Avoid buffered stdin: its lock can abort Python during finalization
            # when shutdown is requested while the parent still holds the pipe open.
            chunk = os.read(sys.stdin.fileno(), min(4096, MAX_LINE_BYTES + 1 - len(pending)))
            if not chunk:
                if pending:
                    incoming.put(bytes(pending))
                incoming.put(b"")
                return
            pending.extend(chunk)
            while (end := pending.find(b"\n")) >= 0:
                if end + 1 > MAX_LINE_BYTES:
                    incoming.put(ValueError("Input line exceeds 65536 bytes"))
                    return
                incoming.put(bytes(pending[:end + 1]))
                del pending[:end + 1]
            if len(pending) > MAX_LINE_BYTES:
                incoming.put(ValueError("Input line exceeds 65536 bytes"))
                return
    except Exception:
        incoming.put(ValueError("Failed to read stdin"))


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


async def run() -> None:
    incoming: queue.Queue = queue.Queue(maxsize=16)
    threading.Thread(target=_read_stdin, args=(incoming,), daemon=True).start()
    worker = Worker()
    try:
        while not worker.stopped:
            try:
                line = incoming.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.01)
                continue
            if isinstance(line, Exception):
                worker.error(None, "invalid_request", str(line))
                break
            if not line:
                break
            try:
                raw = json.loads(line.decode("utf-8"), object_pairs_hook=_strict_object,
                                 parse_constant=_reject_constant)
            except (ValueError, UnicodeError, RecursionError):
                worker.error(None, "invalid_request", "Invalid JSON command")
            else:
                worker.handle(raw)
            # Give provider/cancellation tasks time even when commands arrive in bulk.
            await asyncio.sleep(0)
    finally:
        worker.close()
        if worker.tasks:
            await asyncio.gather(*worker.tasks, return_exceptions=True)


def main() -> None:
    try:
        asyncio.run(run())
    except (BrokenPipeError, KeyboardInterrupt):
        pass
