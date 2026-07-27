"""Typed, bounded values for Screen-Aware Compose."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from ai.model_selection import valid_model_id
from ai.provider_catalog import ALL_PROVIDER_IDS
from dictation.policy import TargetLease
from feature_gates import ActionCapability, RunCapabilityGrant


MAX_INSTRUCTION_CHARS = 8_192
MAX_DRAFT_CHARS = 16_384
DEFAULT_DRAFT_CHARS = 2_000
MAX_SCREENSHOTS = 4
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
MAX_COMBINED_SCREENSHOT_BYTES = 12 * 1024 * 1024
MAX_SCREENSHOT_ID_CHARS = 96
MAX_STYLE_PROFILE_ID_CHARS = 64
MAX_RESPONSE_LANGUAGE_CHARS = 16
MAX_APPLICATION_NAME_CHARS = 256
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_LANGUAGE = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")


def _bounded_identifier(value: object, *, maximum: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not value.isprintable()
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ComposeProviderSelection:
    provider_id: str
    model_id: str

    def __post_init__(self) -> None:
        if self.provider_id not in ALL_PROVIDER_IDS:
            raise ValueError("Compose provider is not reviewed")
        if not valid_model_id(self.model_id):
            raise ValueError("Compose model ID is invalid")


@dataclass(frozen=True, slots=True)
class ComposeScreenshot:
    """One explicitly authorized JPEG without exposing its pixels in repr."""

    screenshot_id: str
    label: str
    width: int
    height: int
    base64_jpeg: str = field(repr=False)
    byte_count: int = field(init=False)

    def __post_init__(self) -> None:
        _bounded_identifier(
            self.screenshot_id,
            maximum=MAX_SCREENSHOT_ID_CHARS,
            label="Screenshot ID",
        )
        if (
            not isinstance(self.label, str)
            or not self.label
            or len(self.label) > 256
            or not self.label.isprintable()
        ):
            raise ValueError("Screenshot label is invalid")
        if (
            type(self.width) is not int
            or type(self.height) is not int
            or not 1 <= self.width <= 8_192
            or not 1 <= self.height <= 8_192
        ):
            raise ValueError("Screenshot dimensions are invalid")
        if not isinstance(self.base64_jpeg, str):
            raise TypeError("Screenshot payload must be base64 text")
        try:
            payload = base64.b64decode(
                self.base64_jpeg,
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Screenshot payload is not valid base64") from exc
        if (
            not payload.startswith(b"\xff\xd8\xff")
            or not payload.endswith(b"\xff\xd9")
            or len(payload) > MAX_SCREENSHOT_BYTES
        ):
            raise ValueError("Screenshot payload is not a bounded JPEG")
        object.__setattr__(self, "byte_count", len(payload))


@dataclass(frozen=True, slots=True)
class ComposeInvocation:
    """Explicit user invocation before any screenshot capture occurs."""

    run_id: str
    grant: RunCapabilityGrant
    instruction: str = field(repr=False)
    target: TargetLease = field(repr=False)
    authorized_screenshot_ids: tuple[str, ...]
    provider: ComposeProviderSelection
    response_language: str = "en"
    style_profile_id: str | None = None
    max_output_chars: int = DEFAULT_DRAFT_CHARS

    def __post_init__(self) -> None:
        if not isinstance(self.grant, RunCapabilityGrant):
            raise TypeError("Compose invocation requires a run grant")
        if self.grant.run_id != self.run_id:
            raise ValueError("Compose run grant does not match the invocation")
        if (
            not isinstance(self.instruction, str)
            or not self.instruction.strip()
            or len(self.instruction) > MAX_INSTRUCTION_CHARS
            or any(
                ord(character) < 32 and character not in "\n\t"
                for character in self.instruction
            )
        ):
            raise ValueError("Compose instruction is invalid")
        if not isinstance(self.target, TargetLease):
            raise TypeError("Compose invocation requires a target lease")
        _validate_screenshot_ids(self.authorized_screenshot_ids)
        if not isinstance(self.provider, ComposeProviderSelection):
            raise TypeError("Compose invocation requires a provider selection")
        _validate_response_language(self.response_language)
        _validate_profile_id(self.style_profile_id)
        _validate_output_limit(self.max_output_chars)


@dataclass(frozen=True, slots=True)
class ComposeRequest:
    """Authorized provider request plus the remembered destination lease."""

    run_id: str
    grant: RunCapabilityGrant
    instruction: str = field(repr=False)
    target: TargetLease = field(repr=False)
    screenshots: tuple[ComposeScreenshot, ...] = field(repr=False)
    provider: ComposeProviderSelection
    response_language: str
    style_profile_id: str | None
    max_output_chars: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.screenshots, tuple)
            or not self.screenshots
            or any(
                not isinstance(screenshot, ComposeScreenshot)
                for screenshot in self.screenshots
            )
        ):
            raise TypeError("Compose screenshots must be a non-empty tuple")
        invocation = ComposeInvocation(
            run_id=self.run_id,
            grant=self.grant,
            instruction=self.instruction,
            target=self.target,
            authorized_screenshot_ids=tuple(
                screenshot.screenshot_id
                for screenshot in self.screenshots
            ),
            provider=self.provider,
            response_language=self.response_language,
            style_profile_id=self.style_profile_id,
            max_output_chars=self.max_output_chars,
        )
        del invocation
        if sum(
            screenshot.byte_count for screenshot in self.screenshots
        ) > MAX_COMBINED_SCREENSHOT_BYTES:
            raise ValueError("Compose screenshots exceed the combined limit")

    @property
    def destination_application(self) -> str:
        return self.target.application_name

    @property
    def destination_identity(self) -> str:
        return self.target.descriptor.application_identity

    @property
    def target_type(self) -> str:
        descriptor = self.target.descriptor
        return f"{descriptor.framework_id}:{descriptor.control_type}"


@dataclass(frozen=True, slots=True)
class DraftProvenance:
    run_id: str
    provider_id: str
    model_id: str
    destination_application: str
    destination_identity: str
    target_type: str
    screenshot_ids: tuple[str, ...]
    response_language: str
    style_profile_id: str | None
    max_output_chars: int

    def __post_init__(self) -> None:
        _bounded_identifier(
            self.run_id,
            maximum=128,
            label="Draft run ID",
        )
        ComposeProviderSelection(self.provider_id, self.model_id)
        if (
            not isinstance(self.destination_application, str)
            or not self.destination_application
            or len(self.destination_application) > MAX_APPLICATION_NAME_CHARS
            or not self.destination_application.isprintable()
        ):
            raise ValueError("Draft destination application is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.destination_identity):
            raise ValueError("Draft destination identity is invalid")
        if (
            not isinstance(self.target_type, str)
            or not self.target_type
            or len(self.target_type) > 256
            or not self.target_type.isprintable()
        ):
            raise ValueError("Draft target type is invalid")
        _validate_screenshot_ids(self.screenshot_ids)
        _validate_response_language(self.response_language)
        _validate_profile_id(self.style_profile_id)
        _validate_output_limit(self.max_output_chars)


@dataclass(frozen=True, slots=True)
class Draft:
    """Plain draft text plus provenance; it has no action authority."""

    text: str = field(repr=False)
    provenance: DraftProvenance

    def __post_init__(self) -> None:
        if (
            not isinstance(self.text, str)
            or not self.text.strip()
            or len(self.text) > self.provenance.max_output_chars
            or any(
                ord(character) < 32 and character not in "\n\t"
                for character in self.text
            )
        ):
            raise ValueError("Draft text is empty, invalid, or exceeds its limit")

    @property
    def character_count(self) -> int:
        return len(self.text)


def validate_draft_review_context(
    draft: Draft,
    target: TargetLease,
    grant: RunCapabilityGrant,
) -> None:
    """Validate preview context without creating insertion authority."""

    if not isinstance(draft, Draft):
        raise TypeError("Draft review requires a compose draft")
    if not isinstance(target, TargetLease):
        raise TypeError("Draft review requires a target lease")
    if not isinstance(grant, RunCapabilityGrant):
        raise TypeError("Draft review requires a run grant")
    if (
        grant.run_id != draft.provenance.run_id
        or ActionCapability.SCREEN_AWARE_COMPOSE
        not in grant.capabilities
    ):
        raise ValueError("Draft review requires the matching compose run grant")
    descriptor = target.descriptor
    provenance = draft.provenance
    target_type = f"{descriptor.framework_id}:{descriptor.control_type}"
    if (
        descriptor.application_name != provenance.destination_application
        or descriptor.application_identity != provenance.destination_identity
        or target_type != provenance.target_type
    ):
        raise ValueError("Draft review destination does not match the draft")


@dataclass(frozen=True, slots=True)
class DraftInsertionApproval:
    """One explicit preview approval bound to the remembered destination."""

    draft: Draft = field(repr=False)
    target: TargetLease = field(repr=False)
    grant: RunCapabilityGrant = field(repr=False)

    def __post_init__(self) -> None:
        validate_draft_review_context(
            self.draft,
            self.target,
            self.grant,
        )

    @property
    def run_id(self) -> str:
        return self.draft.provenance.run_id


def _validate_screenshot_ids(values: object) -> tuple[str, ...]:
    if (
        not isinstance(values, tuple)
        or not values
        or len(values) > MAX_SCREENSHOTS
    ):
        raise ValueError("Compose requires one to four authorized screenshots")
    checked = tuple(
        _bounded_identifier(
            value,
            maximum=MAX_SCREENSHOT_ID_CHARS,
            label="Screenshot ID",
        )
        for value in values
    )
    if len(set(checked)) != len(checked):
        raise ValueError("Authorized screenshot IDs must be unique")
    return checked


def _validate_response_language(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_RESPONSE_LANGUAGE_CHARS
        or _LANGUAGE.fullmatch(value) is None
    ):
        raise ValueError("Compose response language is invalid")
    return value


def _validate_profile_id(value: object) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > MAX_STYLE_PROFILE_ID_CHARS
        or _PROFILE_ID.fullmatch(value) is None
    ):
        raise ValueError("Compose style profile ID is invalid")
    return value


def _validate_output_limit(value: object) -> int:
    if (
        type(value) is not int
        or not 1 <= value <= MAX_DRAFT_CHARS
    ):
        raise ValueError("Compose output limit is invalid")
    return value
