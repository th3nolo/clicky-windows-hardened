"""Provider-neutral contracts for one bounded presentation specification.

The trusted task broker validates an adopted JSON artifact into these immutable
models before a provider adapter receives any authority.  The models contain no
credentials, endpoints, provider SDK objects, or executable content.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field


SLIDE_SPEC_SCHEMA_VERSION = 1
MAX_SLIDES_PROVIDER_REQUESTS = 6
MAX_SLIDES_SOURCE_BYTES = 64 * 1024
MAX_SLIDES = 10
MAX_PRESENTATION_TITLE_CHARS = 200
MAX_SLIDE_TITLE_CHARS = 160
MAX_SLIDE_TEXT_CHARS = 1_600
MAX_SLIDES_IDEMPOTENCY_KEY_CHARS = 128
MAX_SLIDES_PREVIEW_CHARS = 20 * 1024
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SlideSpecificationValidationError(ValueError):
    """The local artifact is not a bounded inert slide specification."""


def validate_slides_idempotency_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_SLIDES_IDEMPOTENCY_KEY_CHARS
        or _IDEMPOTENCY_KEY.fullmatch(value) is None
    ):
        raise ValueError("Google Slides idempotency key is invalid")
    return value


def validate_presentation_title(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > MAX_PRESENTATION_TITLE_CHARS
        or "\r" in value
        or "\n" in value
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ValueError("Presentation title is invalid")
    return value


def _validated_slide_title(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > MAX_SLIDE_TITLE_CHARS
        or "\r" in value
        or "\n" in value
        or "\x00" in value
        or not value.isprintable()
    ):
        raise SlideSpecificationValidationError("Slide title is invalid")
    return value


def _validated_slide_text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > MAX_SLIDE_TEXT_CHARS
        or "\r" in value
        or "\n" in value
        or "\x00" in value
        or not value.isprintable()
    ):
        raise SlideSpecificationValidationError("Slide text is invalid")
    return value


@dataclass(frozen=True, slots=True)
class SlideContent:
    """One text-only slide; links, images, charts, and actions are unavailable."""

    title: str
    text: str = field(repr=False)

    def __post_init__(self) -> None:
        _validated_slide_title(self.title)
        _validated_slide_text(self.text)


@dataclass(frozen=True, slots=True)
class ValidatedSlideSpecification:
    """Exact immutable content revalidated from an adopted JSON artifact."""

    title: str
    slides: tuple[SlideContent, ...]
    source_sha256: str
    source_bytes: int
    schema_version: int = SLIDE_SPEC_SCHEMA_VERSION

    def __post_init__(self) -> None:
        validate_presentation_title(self.title)
        if (
            not isinstance(self.slides, tuple)
            or not 1 <= len(self.slides) <= MAX_SLIDES
            or any(not isinstance(slide, SlideContent) for slide in self.slides)
        ):
            raise SlideSpecificationValidationError(
                "Presentation slides are invalid"
            )
        if (
            not isinstance(self.source_sha256, str)
            or _SHA256.fullmatch(self.source_sha256) is None
        ):
            raise SlideSpecificationValidationError(
                "Presentation source digest is invalid"
            )
        if (
            type(self.source_bytes) is not int
            or not 1 <= self.source_bytes <= MAX_SLIDES_SOURCE_BYTES
        ):
            raise SlideSpecificationValidationError(
                "Presentation source size is invalid"
            )
        if (
            type(self.schema_version) is not int
            or self.schema_version != SLIDE_SPEC_SCHEMA_VERSION
        ):
            raise SlideSpecificationValidationError(
                "Presentation schema version is invalid"
            )
        if len(
            _preview_json(
                {
                    "destination_account_authorization_id": "a" * 128,
                    "idempotency_key_sha256": "0" * 64,
                    "schema_version": self.schema_version,
                    "slide_count": self.slide_count,
                    "slides": [
                        {"text": slide.text, "title": slide.title}
                        for slide in self.slides
                    ],
                    "source_bytes": self.source_bytes,
                    "source_sha256": self.source_sha256,
                    "title": self.title,
                }
            )
        ) > MAX_SLIDES_PREVIEW_CHARS:
            raise SlideSpecificationValidationError(
                "Presentation approval preview exceeds its limit"
            )

    @property
    def slide_count(self) -> int:
        return len(self.slides)

    @property
    def slide_titles(self) -> tuple[str, ...]:
        return tuple(slide.title for slide in self.slides)

    def preview_text(
        self,
        *,
        authorization_id: str,
        idempotency_key: str,
    ) -> str:
        if (
            not isinstance(authorization_id, str)
            or not authorization_id
            or len(authorization_id) > 128
            or "\x00" in authorization_id
            or not authorization_id.isprintable()
        ):
            raise ValueError(
                "Google Slides account authorization ID is invalid"
            )
        validate_slides_idempotency_key(idempotency_key)
        preview = _preview_json(
            {
                "destination_account_authorization_id": authorization_id,
                "idempotency_key_sha256": hashlib.sha256(
                    idempotency_key.encode("utf-8")
                ).hexdigest(),
                "schema_version": self.schema_version,
                "slide_count": self.slide_count,
                "slides": [
                    {"text": slide.text, "title": slide.title}
                    for slide in self.slides
                ],
                "source_bytes": self.source_bytes,
                "source_sha256": self.source_sha256,
                "title": self.title,
            }
        )
        if len(preview) > MAX_SLIDES_PREVIEW_CHARS:
            raise SlideSpecificationValidationError(
                "Presentation approval preview exceeds its limit"
            )
        return preview


def parse_validated_slide_specification(
    content: bytes,
    *,
    expected_sha256: str,
) -> ValidatedSlideSpecification:
    """Strictly parse one exact adopted text-only presentation artifact."""

    if (
        not isinstance(content, bytes)
        or not 1 <= len(content) <= MAX_SLIDES_SOURCE_BYTES
        or not isinstance(expected_sha256, str)
        or _SHA256.fullmatch(expected_sha256) is None
        or hashlib.sha256(content).hexdigest() != expected_sha256
    ):
        raise SlideSpecificationValidationError(
            "Presentation source identity is invalid"
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SlideSpecificationValidationError(
            "Presentation source must be UTF-8 JSON"
        ) from exc
    if not text or text.startswith("\ufeff") or "\x00" in text:
        raise SlideSpecificationValidationError(
            "Presentation source text is invalid"
        )
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise SlideSpecificationValidationError(
            "Presentation source JSON is malformed"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "slides", "title"}
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != SLIDE_SPEC_SCHEMA_VERSION
        or not isinstance(payload.get("slides"), list)
        or not 1 <= len(payload["slides"]) <= MAX_SLIDES
    ):
        raise SlideSpecificationValidationError(
            "Presentation source shape is invalid"
        )
    try:
        title = validate_presentation_title(payload["title"])
        slides = tuple(
            _parse_slide(item) for item in payload["slides"]
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, SlideSpecificationValidationError):
            raise
        raise SlideSpecificationValidationError(
            "Presentation source values are invalid"
        ) from exc
    return ValidatedSlideSpecification(
        title=title,
        slides=slides,
        source_sha256=expected_sha256,
        source_bytes=len(content),
    )


def _parse_slide(value: object) -> SlideContent:
    if not isinstance(value, dict) or set(value) != {"text", "title"}:
        raise SlideSpecificationValidationError(
            "Presentation slide shape is invalid"
        )
    return SlideContent(
        title=_validated_slide_title(value["title"]),
        text=_validated_slide_text(value["text"]),
    )


def _reject_duplicate_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate presentation JSON field")
        output[key] = value
    return output


def _reject_json_constant(_value: str):
    raise ValueError("Presentation JSON constants are invalid")


def _preview_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise SlideSpecificationValidationError(
            "Presentation preview is invalid"
        ) from exc


__all__ = [
    "MAX_PRESENTATION_TITLE_CHARS",
    "MAX_SLIDES",
    "MAX_SLIDES_IDEMPOTENCY_KEY_CHARS",
    "MAX_SLIDES_PREVIEW_CHARS",
    "MAX_SLIDES_PROVIDER_REQUESTS",
    "MAX_SLIDES_SOURCE_BYTES",
    "MAX_SLIDE_TEXT_CHARS",
    "MAX_SLIDE_TITLE_CHARS",
    "SLIDE_SPEC_SCHEMA_VERSION",
    "SlideContent",
    "SlideSpecificationValidationError",
    "ValidatedSlideSpecification",
    "parse_validated_slide_specification",
    "validate_presentation_title",
    "validate_slides_idempotency_key",
]
