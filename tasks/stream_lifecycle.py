"""Await cleanup of task-owned iterators without replacing a primary failure."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TypeVar


T = TypeVar("T")


async def _close_if_supported(stream: object) -> None:
    close = getattr(stream, "aclose", None)
    if callable(close):
        await close()


@asynccontextmanager
async def owned_stream(stream: AsyncIterator[T]) -> AsyncIterator[AsyncIterator[T]]:
    """Own one close attempt; generic iterators need not implement aclose."""
    try:
        yield stream
    except BaseException:
        # Validation, upstream failure and cancellation retain their identity.
        try:
            await _close_if_supported(stream)
        except BaseException:
            pass
        raise
    else:
        # A cleanup-only failure must not turn into a successful tool result.
        await _close_if_supported(stream)
