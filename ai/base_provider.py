from abc import ABC, abstractmethod
from typing import AsyncGenerator, List
from dataclasses import dataclass


@dataclass
class Message:
    role: str   # "user" or "assistant"
    content: str


class BaseLLMProvider(ABC):
    """All LLM providers implement this interface."""

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
