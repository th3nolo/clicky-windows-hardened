"""Provider-neutral lifecycle for live speech-to-text sessions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Callable


TranscriptCallback = Callable[[str], None]
ErrorCallback = Callable[[str], None]


class StreamingSTTState(Enum):
    NEW = auto()
    OPENING = auto()
    OPEN = auto()
    FINALIZING = auto()
    CLOSED = auto()
    CANCELED = auto()
    FAILED = auto()


class StreamingSTTError(RuntimeError):
    """Base error for an explicitly failed live transcription session."""


class StreamingSTTConsentError(StreamingSTTError):
    """Cloud speech was requested without the independent user permission."""


class StreamingSTTProtocolError(StreamingSTTError):
    """The provider sent an invalid or unexpectedly large message."""


class StreamingSTTCapacityError(StreamingSTTError):
    """Audio exceeded a reviewed frame, rate, queue, or duration bound."""


class StreamingSTTSession(ABC):
    """One owner for one live microphone-to-transcript exchange."""

    @property
    @abstractmethod
    def state(self) -> StreamingSTTState:
        ...

    @abstractmethod
    async def open(self) -> None:
        """Open the fixed provider connection."""

    @abstractmethod
    def send_frame(self, pcm16_frame: bytes) -> None:
        """Admit one bounded mono PCM16 frame without blocking the audio thread."""

    @abstractmethod
    async def finalize(self) -> str:
        """Flush accepted frames, request a final result, and close."""

    @abstractmethod
    async def cancel(self) -> None:
        """Stop promptly and guarantee that no later transcript callback runs."""
