from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncGenerator, List, TYPE_CHECKING
from dataclasses import dataclass
if TYPE_CHECKING:
    from ai.video_input import VideoInput


@dataclass
class Message:
    role: str   # "user" or "assistant"
    content: str


class BaseLLMProvider(ABC):
    """All LLM providers implement this interface."""

    def stream_video_response(
        self, user_text: str, video: VideoInput, history: List[Message],
        system_prompt: str, model: str | None = None,
    ) -> AsyncGenerator[str, None]:
        raise ValueError("The selected provider does not support video input")

    @abstractmethod
    def stream_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncGenerator[str, None]:
        """Yields text chunks as they stream in."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Returns True if the provider is reachable."""
        ...
