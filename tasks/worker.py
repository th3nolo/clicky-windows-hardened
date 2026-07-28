"""Minimal task worker process.

The initial worker only proves the authenticated fault boundary. It has no
model, shell, connector, browser, desktop, or arbitrary filesystem tool.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

if __package__:
    from tasks.protocol import (
        ProtocolError,
        ProtocolSession,
        WorkerBootstrap,
    )
else:
    worker_directory = str(Path(__file__).resolve().parent)
    if worker_directory not in sys.path:
        sys.path.insert(0, worker_directory)
    from protocol import (  # type: ignore[no-redef]
        ProtocolError,
        ProtocolSession,
        WorkerBootstrap,
    )


def run_worker() -> int:
    if os.environ.get("CLICKY_TASK_WORKER") != "1":
        return 2
    input_stream = sys.stdin.buffer
    output_stream = sys.stdout.buffer
    try:
        bootstrap = WorkerBootstrap.read(input_stream)
        session = ProtocolSession(
            bootstrap,
            send_direction="worker_to_host",
            receive_direction="host_to_worker",
        )
        started = _read_message(
            input_stream,
            session,
            bootstrap.max_frame_bytes,
        )
        if started.message_type != "start" or started.payload != {}:
            raise ProtocolError("Worker requires an empty start request")
        _write_message(output_stream, session, "ready", {})

        for _ in range(bootstrap.max_messages - 1):
            message = _read_message(
                input_stream,
                session,
                bootstrap.max_frame_bytes,
            )
            if message.message_type == "ping":
                if set(message.payload) != {"nonce"}:
                    raise ProtocolError("Worker ping payload is invalid")
                _write_message(
                    output_stream,
                    session,
                    "pong",
                    {"nonce": message.payload["nonce"]},
                )
                continue
            if message.message_type == "shutdown":
                if message.payload:
                    raise ProtocolError("Worker shutdown payload is invalid")
                _write_message(output_stream, session, "stopped", {})
                return 0
            raise ProtocolError("Worker message type is not available")
        raise ProtocolError("Worker protocol message limit reached")
    except (BrokenPipeError, EOFError, OSError, ProtocolError):
        return 2


def _read_message(
    stream,
    session: ProtocolSession,
    maximum: int,
):
    line = stream.readline(maximum + 1)
    if not line:
        raise EOFError("Worker protocol input closed")
    return session.decode(line)


def _write_message(
    stream,
    session: ProtocolSession,
    message_type: str,
    payload: dict[str, object],
) -> None:
    stream.write(session.encode(message_type, payload))
    stream.flush()


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    return run_worker()


if __name__ == "__main__":
    raise SystemExit(main())
