"""Subprocess fixture; fake reasoning is confined to tests."""

import asyncio
from collections.abc import AsyncGenerator

from clicky_core.commands import Submit
from clicky_core.worker import run


class TestProvider:
    name = "test"

    async def generate(self, command: Submit) -> AsyncGenerator[str, None]:
        await asyncio.sleep(0.1)
        yield f"[Test] {command.text}"


if __name__ == "__main__":
    asyncio.run(run(TestProvider()))
