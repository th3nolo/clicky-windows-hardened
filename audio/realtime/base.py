"""Provider-neutral lifecycle for one bounded duplex voice session."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable


AudioCallback = Callable[[bytes], None]
EventCallback = Callable[[], None]
TextCallback = Callable[[str], None]


class DuplexState(Enum):
    NEW = auto()
    OPENING = auto()
    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()
    CANCELED = auto()
    FAILED = auto()


class DuplexError(RuntimeError):
    """Base error for an explicitly failed duplex session."""


class DuplexConsentError(DuplexError):
    """One or more independent voice permissions were not granted."""


class DuplexProtocolError(DuplexError):
    """The provider left the reviewed protocol or returned invalid data."""


class DuplexCapacityError(DuplexError):
    """A reviewed audio, queue, duration, response, or usage bound was reached."""


@dataclass(frozen=True)
class DuplexUsage:
    input_bytes: int = 0
    output_bytes: int = 0
    responses: int = 0
    total_tokens: int = 0


class DuplexSession(ABC):
    """One owner for one live microphone-to-model-to-speaker exchange."""

    @property
    @abstractmethod
    def state(self) -> DuplexState:
        ...

    @property
    @abstractmethod
    def usage(self) -> DuplexUsage:
        ...

    @abstractmethod
    async def open(self) -> None:
        """Open exactly one fixed provider connection."""

    @abstractmethod
    def send_frame(self, pcm16_frame: bytes) -> None:
        """Admit one bounded mono PCM16 frame without blocking the audio thread."""

    @abstractmethod
    async def interrupt(self) -> None:
        """Stop the current response while keeping the conversation session open."""

    @abstractmethod
    async def close(self) -> None:
        """Flush admitted input and close without reconnecting or falling back."""

    @abstractmethod
    async def cancel(self) -> None:
        """Stop promptly and suppress all later audio or transcript callbacks."""
