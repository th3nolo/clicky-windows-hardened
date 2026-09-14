"""Construct OpenAI speech clients with the shared credential and transport policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai.provider_endpoints import OPENAI_BASE_URL
from ai.sdk_isolation import create_openai_client
from audio.openai_credentials import openai_speech_api_key

if TYPE_CHECKING:
    from openai import AsyncOpenAI
    from config import Config


def create_openai_speech_client(config: Config) -> AsyncOpenAI:
    return create_openai_client(
        api_key=openai_speech_api_key(
            speech_key=getattr(config, "openai_speech_api_key", None),
            chat_key=config.openai_api_key,
            chat_base_url=getattr(config, "openai_base_url", ""),
        ),
        base_url=OPENAI_BASE_URL,
        timeout=600.0,
        max_retries=2,
    )
