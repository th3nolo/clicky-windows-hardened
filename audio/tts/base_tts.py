from abc import ABC, abstractmethod


class BaseTTS(ABC):

    @abstractmethod
    async def speak(self, text: str) -> None:
        """Synthesize and play audio for the given text."""
        ...


class DisabledTTSProvider(BaseTTS):
    """No-op provider used until cloud speech permission is granted."""

    async def speak(self, text: str) -> None:
        return None
