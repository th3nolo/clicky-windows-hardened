"""Content-safe evidence for one completed Global Dictation run."""

from __future__ import annotations

from dataclasses import dataclass, field

from dictation.insertion import InsertionResult


MAX_STT_PROVIDER_CHARS = 64


@dataclass(frozen=True, slots=True)
class DictationRunOutcome:
    """Final STT and insertion metadata without retaining transcript text."""

    run_id: str
    stt_provider: str
    insertion: InsertionResult = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.run_id, str)
            or not self.run_id
            or not self.run_id.isprintable()
        ):
            raise ValueError("Dictation outcome run ID is invalid")
        if (
            not isinstance(self.stt_provider, str)
            or not self.stt_provider
            or len(self.stt_provider) > MAX_STT_PROVIDER_CHARS
            or not self.stt_provider.isprintable()
        ):
            raise ValueError("Dictation outcome STT provider is invalid")
        if not isinstance(self.insertion, InsertionResult):
            raise TypeError("Dictation outcome requires an insertion result")

    @property
    def application_name(self) -> str | None:
        return self.insertion.application_name

    @property
    def result_code(self) -> str:
        return self.insertion.result_code
