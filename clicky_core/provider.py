"""Reuse Clicky's existing inference providers without desktop UI dependencies."""

from collections.abc import AsyncGenerator
from dataclasses import dataclass

from ai.base_provider import BaseLLMProvider
from clicky_core.commands import Submit


@dataclass(frozen=True, slots=True)
class ClickyProvider:
    name: str
    model: str
    backend: BaseLLMProvider

    def generate(self, command: Submit) -> AsyncGenerator[str, None]:
        return self.backend.stream_response(
            user_text=command.text,
            screenshots_b64=[],
            history=[],
            system_prompt="Help the learner reason about mathematics. Give a concise hint first.",
            model=self.model,
        )
