"""Fail-closed privacy permission checks shared by runtime and UI code."""

from __future__ import annotations

from typing import Protocol


PRIVACY_NOTICE_VERSION = 3


class PrivacyConfiguration(Protocol):
    privacy_consent_version: int
    microphone_consent: bool
    cloud_stt_consent: bool
    cloud_tts_consent: bool
    screen_capture_consent: bool
    coding_agent_consent: bool


def notice_accepted(config: PrivacyConfiguration) -> bool:
    return config.privacy_consent_version == PRIVACY_NOTICE_VERSION


def microphone_allowed(config: PrivacyConfiguration) -> bool:
    return notice_accepted(config) and config.microphone_consent is True


def cloud_stt_allowed(config: PrivacyConfiguration) -> bool:
    return notice_accepted(config) and config.cloud_stt_consent is True


def cloud_tts_allowed(config: PrivacyConfiguration) -> bool:
    return notice_accepted(config) and config.cloud_tts_consent is True


def screen_capture_allowed(config: PrivacyConfiguration) -> bool:
    return notice_accepted(config) and config.screen_capture_consent is True


def coding_agent_allowed(config: PrivacyConfiguration) -> bool:
    return notice_accepted(config) and config.coding_agent_consent is True
