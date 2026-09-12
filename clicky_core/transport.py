"""Bounded, event-driven stdin for Windows and POSIX child processes."""

import asyncio
import os
import sys
import threading
from ai.video_input import MAX_VIDEO_B64
from collections.abc import AsyncGenerator, Callable
from concurrent.futures import CancelledError
from contextlib import suppress

MAX_LINE_BYTES = MAX_VIDEO_B64 + 65536
InputItem = bytes | ValueError | None


def _read_stdin(deliver: Callable[[InputItem], None]) -> None:
    try:
        # Own the buffer: a blocked reader must never hold sys.stdin's lock
        # during interpreter shutdown. The duplicate also leaves stdin owned
        # by the host. readline's bound includes the terminating newline.
        with os.fdopen(os.dup(sys.stdin.fileno()), "rb") as source:
            while line := source.readline(MAX_LINE_BYTES + 1):
                if len(line) > MAX_LINE_BYTES:
                    raise ValueError("Input line exceeds the video request limit")
                deliver(line)
    except (OSError, ValueError):
        deliver(ValueError("Input could not be read within the video request limit"))
    else:
        deliver(None)


async def stdin_lines() -> AsyncGenerator[bytes, None]:
    loop = asyncio.get_running_loop()
    incoming: asyncio.Queue[InputItem] = asyncio.Queue(maxsize=2)
    stopped = threading.Event()

    def deliver(item: InputItem) -> None:
        if stopped.is_set():
            raise CancelledError
        put = incoming.put(item)
        try:
            future = asyncio.run_coroutine_threadsafe(put, loop)
        except RuntimeError:
            put.close()
            raise CancelledError from None
        future.result()  # Bounded backpressure; never blocks the event loop.

    def read() -> None:
        with suppress(CancelledError):
            _read_stdin(deliver)

    # Windows stdin cannot reliably use asyncio's POSIX pipe transport.
    # A dedicated daemon can remain blocked when the parent keeps stdin open.
    threading.Thread(target=read, daemon=True).start()
    try:
        while (item := await incoming.get()) is not None:
            if isinstance(item, ValueError):
                raise item
            yield item
    finally:
        stopped.set()
        # Release the single producer if it is awaiting space during shutdown.
        while not incoming.empty():
            incoming.get_nowait()
