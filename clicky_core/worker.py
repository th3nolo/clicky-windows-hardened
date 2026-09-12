"""Typed JSONL transport and turn ownership for injected reasoning providers."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator, Callable
from contextlib import aclosing
from dataclasses import dataclass
from typing import Literal, Protocol, assert_never

from pydantic import JsonValue, ValidationError

from clicky_core.commands import (
    COMMANDS,
    IDENTIFIERS,
    Cancel,
    Capabilities,
    Command,
    Shutdown,
    Submit,
)
from clicky_core.transport import stdin_lines
from turn_coordinator import TurnCoordinator, TurnSession

EventKind = Literal["capabilities", "ack", "error", "state", "text_delta", "done"]


class ReasoningProvider(Protocol):
    @property
    def video_enabled(self) -> bool: ...

    @property
    def name(self) -> str: ...

    def generate(self, command: Submit) -> AsyncGenerator[str, None]: ...


def _write_event(event: dict[str, JsonValue]) -> None:
    # ASCII escapes keep JSONL valid even on Windows consoles with legacy encodings.
    print(json.dumps(event, ensure_ascii=True), flush=True)


@dataclass(frozen=True, slots=True)
class ActiveTurn:
    session: TurnSession
    command: Submit


class Worker:
    """Single-event-loop owner of provider tasks and their correlated events."""

    def __init__(
        self,
        provider: ReasoningProvider,
        emit: Callable[[dict[str, JsonValue]], None] | None = None,
    ) -> None:
        self.provider = provider
        self.emit = emit if emit is not None else _write_event
        self.coordinator = TurnCoordinator()
        self.active: ActiveTurn | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.stopped = False

    def event(
        self, request_id: str | None, kind: EventKind, **fields: JsonValue
    ) -> None:
        self.emit(
            {"protocol_version": 1, "request_id": request_id, "type": kind, **fields}
        )

    def error(self, request_id: str | None, code: str, message: str) -> None:
        self.event(request_id, "error", code=code, message=message)

    def turn_event(
        self, turn: ActiveTurn, kind: EventKind, **fields: JsonValue
    ) -> None:
        command = turn.command
        self.event(
            command.request_id,
            kind,
            turn_id=command.turn_id,
            context=command.context.model_dump(mode="json"),
            **fields,
        )

    def cancel_active(self) -> None:
        turn = self.active
        if turn is not None:
            self.active = None
            self.coordinator.cancel(turn.session)
            self.turn_event(turn, "done", status="cancelled")

    def receive(self, raw: object) -> None:
        """Validate untrusted input before entering the typed command handler."""
        try:
            command = COMMANDS.validate_python(raw)
        except ValidationError:
            self.error(_request_id(raw), "invalid_request", "Invalid command fields")
            return
        self.handle(command)

    def handle(self, command: Command) -> None:
        if self.stopped:
            self.error(command.request_id, "worker_stopped", "Worker has shut down")
            return
        match command:
            case Capabilities():
                self.event(
                    command.request_id,
                    "capabilities",
                    provider=self.provider.name,
                    inputs=["text", "video"] if self.provider.video_enabled else ["text"],
                    audio_in_video=self.provider.video_enabled,
                    tts=False,
                )
            case Shutdown():
                self.close()
                self.event(command.request_id, "ack", status="shutdown")
            case Cancel():
                self._cancel(command)
            case Submit():
                self._submit(command)
            case _:
                assert_never(command)

    def _cancel(self, command: Cancel) -> None:
        if self.active is None or self.active.command.turn_id != command.turn_id:
            self.error(
                command.request_id, "turn_not_active", "Requested turn is not active"
            )
            return
        self.cancel_active()
        self.event(command.request_id, "ack", status="cancelled")

    def _submit(self, command: Submit) -> None:
        session = self.coordinator.start_processing()
        if session is None:
            self.error(command.request_id, "busy", "Another turn is active")
            return
        turn = ActiveTurn(session, command)
        self.active = turn
        self.turn_event(turn, "state", status="processing")
        task = asyncio.create_task(self._respond(turn))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        self.coordinator.bind_task(session, task)

    async def _respond(self, turn: ActiveTurn) -> None:
        try:
            async with aclosing(self.provider.generate(turn.command)) as stream:
                async for delta in stream:
                    if not self.coordinator.is_current(turn.session):
                        return
                    self.turn_event(turn, "text_delta", delta=delta)
        except Exception:
            # Unexpected provider failures are contained at this task boundary.
            # CancelledError propagates; cancellation already owns its done event.
            self._finish(turn, failed=True)
        else:
            self._finish(turn)

    def _finish(self, turn: ActiveTurn, *, failed: bool = False) -> None:
        if not self.coordinator.complete(turn.session):
            return
        self.active = None
        if failed:
            self.turn_event(
                turn, "error", code="provider_error", message="Provider failed"
            )
        self.turn_event(turn, "done", status="failed" if failed else "completed")

    def receive_line(self, line: bytes) -> None:
        try:
            raw: object = json.loads(
                line.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except (ValueError, UnicodeError, RecursionError):
            self.error(None, "invalid_request", "Invalid JSON command")
        else:
            self.receive(raw)

    def close(self) -> None:
        self.stopped = True
        self.cancel_active()


def _request_id(raw: object) -> str | None:
    match raw:
        case {"request_id": value}:
            try:
                return IDENTIFIERS.validate_python(value, strict=True)
            except ValidationError:
                return None
        case _:
            return None


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


async def run(provider: ReasoningProvider) -> None:
    worker = Worker(provider)
    try:
        async with aclosing(stdin_lines()) as lines:
            async for line in lines:
                worker.receive_line(line)
                if worker.stopped:
                    break
    except ValueError as exc:
        worker.error(None, "invalid_request", str(exc))
    finally:
        worker.close()
        await asyncio.gather(*worker.tasks, return_exceptions=True)
