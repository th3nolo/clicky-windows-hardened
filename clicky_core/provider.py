"""Reuse Clicky's existing inference providers without desktop UI dependencies."""

from collections.abc import AsyncGenerator
from dataclasses import dataclass

from ai.base_provider import BaseLLMProvider
from clicky_core.commands import Submit
from ai.provider_catalog import supports_video


@dataclass(frozen=True, slots=True)
class ClickyProvider:
    name: str
    model: str
    backend: BaseLLMProvider

    @property
    def video_enabled(self) -> bool:
        return supports_video(self.name, self.model)

    def generate(self, command: Submit) -> AsyncGenerator[str, None]:
        if command.video is not None:
            if not self.video_enabled:
                raise ValueError("Selected notebook provider does not accept video")
            return self.backend.stream_video_response(
                user_text=command.text, video=command.video, history=[],
                system_prompt="Help the learner reason about mathematics using the supplied screen video and spoken instructions. Give a concise hint first.",
                model=self.model,
            )
        return self.backend.stream_response(
            user_text=command.text,
            screenshots_b64=[],
            history=[],
            system_prompt="Help the learner reason about mathematics. Give a concise hint first.",
            model=self.model,
        )
