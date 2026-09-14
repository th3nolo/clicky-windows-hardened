"""Small synthetic fixtures shared by provider and privacy boundary tests.

Importing this module uses only the standard library. Tests retain their own
responses and assertions; HTTPX is loaded only when constructing a mock client.
"""

import importlib.util
from pathlib import Path
import sys
import types
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    """Load fresh real config; callers must scope environment and preferences."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, {name: module}):
        spec.loader.exec_module(module)
    return module


def load_subject(relative: str, config: types.SimpleNamespace):
    """Load provider code with synthetic config and inert audio I/O only."""
    name = "provider_test_" + relative.replace("/", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    subject = importlib.util.module_from_spec(spec)
    config_stub = types.ModuleType("config")
    config_stub.cfg = config
    capture_stub = types.ModuleType("audio.capture")
    capture_stub.pcm16_to_wav = lambda *_: b"synthetic-wav"
    playback_stub = types.ModuleType("audio.playback")
    playback_stub.play_mp3_async = mock.AsyncMock()
    with mock.patch.dict(sys.modules, {
        "config": config_stub,
        "audio.capture": capture_stub,
        "audio.playback": playback_stub,
        name: subject,
    }):
        spec.loader.exec_module(subject)
    return subject


def configuration(**overrides):
    from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS

    values = {
        "openai_api_key": "explicit-openai",
        "openai_speech_api_key": None,
        "openai_base_url": "",
        "anthropic_api_key": "explicit-anthropic",
        "google_api_key": "explicit-gemini",
        "lmstudio_host": "http://127.0.0.1:54321/custom/v1",
        "lmstudio_model": "qwen-local",
    }
    values.update({spec.credential_attribute: "explicit-" + provider
                   for provider, spec in OPENAI_COMPATIBLE_SPECS.items()})
    values.update(overrides)
    return types.SimpleNamespace(**values)


def mock_client_factory(respond, options=None):
    """Capture the real client before patching, without altering its options."""
    import httpx

    client_type = httpx.AsyncClient

    def create(**kwargs):
        if options is not None:
            options.append(kwargs)
        return client_type(**kwargs, transport=httpx.MockTransport(respond))

    return create
