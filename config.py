import json
import os
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from privacy_controls import PRIVACY_NOTICE_VERSION


_PREFERENCES_VERSION = 1
_MAX_PREFERENCES_BYTES = 64 * 1024
_PREFERENCE_STRING_LIMITS = {
    "active_llm": 32,
    "claude_model": 256,
    "openai_default_model": 256,
    "gemini_model": 256,
    "copilot_model": 256,
    "kimi_code_model": 256,
    "minimax_plan_model": 256,
    "deepseek_model": 256,
    "qwen_model": 256,
    "codex_agent_model": 256,
    "qwen_code_agent_model": 256,
    "ollama_model": 256,
    "ollama_vision_model": 256,
    "ollama_text_model": 256,
    "lmstudio_model": 256,
    "whisper_model": 256,
    "whisper_language": 16,
    "response_language": 16,
    "custom_instructions": 32 * 1024,
    "elevenlabs_voice_id": 256,
    "hotkey": 128,
    "stt_provider": 32,
}
_PREFERENCE_BOOL_KEYS = {
    "journal_enabled",
    "web_search_enabled",
    "microphone_consent",
    "cloud_stt_consent",
    "cloud_tts_consent",
    "screen_capture_consent",
    "coding_agent_consent",
}
_PREFERENCE_STRING_LIST_LIMITS = {
    "transcription_vocabulary": (63, 64),
}
_PREFERENCES_LOCK = threading.Lock()


def _preferences_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    directory = base / "Clicky"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _preferences_path() -> Path:
    return _preferences_dir() / "preferences.json"


def _sanitize_preferences(values) -> dict:
    if not isinstance(values, dict):
        return {}
    clean = {}
    for key, limit in _PREFERENCE_STRING_LIMITS.items():
        value = values.get(key)
        if isinstance(value, str) and len(value) <= limit:
            clean[key] = value
    for key in _PREFERENCE_BOOL_KEYS:
        value = values.get(key)
        if isinstance(value, bool):
            clean[key] = value
    for key, (count_limit, item_limit) in _PREFERENCE_STRING_LIST_LIMITS.items():
        value = values.get(key)
        if isinstance(value, list):
            candidates = [
                item
                for item in value[:count_limit]
                if isinstance(item, str) and len(item) <= item_limit
            ]
            if key == "transcription_vocabulary":
                from audio.stt.vocabulary import sanitize_user_terms

                clean[key] = list(sanitize_user_terms(candidates))
    notice_version = values.get("privacy_consent_version")
    if (
        isinstance(notice_version, int)
        and not isinstance(notice_version, bool)
        and 0 <= notice_version <= PRIVACY_NOTICE_VERSION
    ):
        clean["privacy_consent_version"] = notice_version
    mic = values.get("mic_device_index")
    if mic is None or (isinstance(mic, int) and not isinstance(mic, bool) and 0 <= mic <= 4096):
        clean["mic_device_index"] = mic
    return clean


def _load_preferences() -> dict:
    path = _preferences_path()
    try:
        if path.is_symlink() or path.stat().st_size > _MAX_PREFERENCES_BYTES:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("version") != _PREFERENCES_VERSION:
            return {}
        return _sanitize_preferences(payload.get("preferences"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}


def _save_preferences(**updates) -> None:
    """Atomically persist allowlisted non-secret settings only."""
    global _PREFERENCES
    with _PREFERENCES_LOCK:
        candidate = dict(_PREFERENCES)
        candidate.update(updates)
        clean = _sanitize_preferences(candidate)
        path = _preferences_path()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="preferences.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            payload = {"version": _PREFERENCES_VERSION, "preferences": clean}
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _PREFERENCES = clean
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _preference(name: str, default):
    return _PREFERENCES.get(name, default)


_PREFERENCES = _load_preferences()


DEFAULT_SYSTEM_PROMPT = """You are Clicky, a VISUAL AI tutor running on Windows. You live
next to the user's cursor. Your job is to *show*, not just tell.

{{CONTEXT}}

HARD RULES (never break):
  1. LOCATE QUESTIONS ("where is X", "how do I click Y", "show me X", "find X"):
     Point at it and explain in ONE sentence. If it's not visible, say so
     plainly instead of guessing.

  2. MULTI-STEP TASKS (export, install, configure, setup, etc.):
     Describe ONLY the next single step, then end with "Say 'next' when
     ready." Never dump a numbered list of 5 steps in one response.

  3. VISION: describe only what is ACTUALLY in the screenshot. Trust your
     eyes over the user's words.

  4. WEB SEARCH: when search results appear, use them as your primary
     source and give a direct answer — never say "I don't know" if the
     results contain real facts. Today is {{TODAY}}.

  5. PUBLIC figures, celebrities, companies, products — answer freely.
     Never refuse with "I can't identify people" — these are public figures
     with public information available.

STYLE: warm, concise, teacher-y. 1-2 sentences per step. No markdown bullets
unless genuinely listing options."""


# Technical rules Clicky needs to actually draw on screen and point at
# elements correctly. Always appended after the user-editable prompt above
# — kept separate because breaking this syntax breaks pointing/drawing, and
# most users have no reason to touch it.
_TECHNICAL_RULES = """

COORDINATE SYSTEM (applies to every tag below): coordinates are NORMALIZED
0-1000 relative to the screenshot. x=0 is the LEFT edge, x=1000 the RIGHT
edge; y=0 is the TOP, y=1000 the BOTTOM. The exact centre of the screen is
500,500. Sizes/radii use the same scale (100 = 10% of screen width).

POINTING: when you need to point at something, emit EXACTLY ONE tag
[POINT:x,y:label:screenN] using normalized coordinates and a 1-3 word label,
where N is the exact screen number in the current SCREEN MAP. Never invent a
screen number or substitute screen1 when another screen is active. Use any
DETECTED ELEMENT coordinate provided above verbatim if given.

DRAWING TAGS (coords normalized 0-1000, trailing :color always optional):
  [LINE:x1,y1->x2,y2:color]         straight line
  [ARROW:x1,y1->x2,y2:color]        line with arrowhead (points at x2,y2)
  [CIRCLE:x,y,r:label:color]        ring; label optional
  [RECT:x1,y1,x2,y2:color]          rectangle by opposite corners
  [POLY:x1,y1 x2,y2 x3,y3:color]    closed shape, 3+ points (triangles!)
  [TEXT:x,y:content:color:size]     text; size s|m|l (default m)
  [ANGLE:x,y,s,rot:color]           right-angle marker at corner (x,y)
  [CLEAR]                           wipe all drawings
Colors: blue red green yellow orange purple white cyan (default blue).
For real UI elements use anchors instead of guessing coordinates:
  [CIRCLE:@Save button]  [UNDERLINE:@File menu]  — resolved pixel-perfectly.

TEACHING WITH DRAWINGS: when explaining something visible on screen (a
figure, chart, diagram, equation, code), draw ON it — trace edges, label
parts, add helper lines — interleaving tags with your spoken words in the
order a teacher draws on a whiteboard. Place TEXT next to what it names,
never covering it. Use up to ~10 shapes for a full lesson, 1-2 for a quick
highlight.

ACCURACY DISCIPLINE: if DETECTED FIGURES are listed above, copy those
vertex numbers into your tags EXACTLY. Only estimate coordinates for things
not listed. When estimating: fix the figure's bounding box first, derive
every endpoint from it, and reuse IDENTICAL numbers for shared vertices.

NARRATION SYNC: Clicky speaks your response sentence by sentence and draws
each sentence's tags WHILE saying that sentence — put every tag immediately
after the words that describe it, spread across the lesson (1-2 tags per
sentence), never dump all tags at the start or end."""


@dataclass
class Config:
    # Secrets are accepted from the process environment only. Clicky never
    # reads .env files or writes provider credentials to disk.
    anthropic_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY") or None
    )
    openai_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("OPENAI_API_KEY") or None
    )
    google_api_key: Optional[str] = field(default_factory=lambda: (
        os.environ.get("GOOGLE_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or None
    ))
    deepgram_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("DEEPGRAM_API_KEY") or None
    )
    elevenlabs_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("ELEVENLABS_API_KEY") or None
    )
    tavily_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("TAVILY_API_KEY") or None
    )
    kimi_code_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("KIMI_CODE_API_KEY") or None
    )
    minimax_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("MINIMAX_API_KEY") or None
    )
    deepseek_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("DEEPSEEK_API_KEY") or None
    )
    dashscope_api_key: Optional[str] = field(
        default_factory=lambda: os.environ.get("DASHSCOPE_API_KEY") or None
    )
    qwen_coding_plan_api_key: Optional[str] = field(
        default_factory=lambda: (
            os.environ.get("BAILIAN_CODING_PLAN_API_KEY") or None
        )
    )

    # Network endpoints are fixed in the hardened build. In particular, an
    # editable local file cannot redirect a provider API key to another host.
    openai_base_url: str = ""
    ollama_host: str = "http://127.0.0.1:11434"
    lmstudio_host: str = "http://127.0.0.1:1234/v1"

    # Non-secret preferences come only from the allowlisted LocalAppData JSON.
    active_llm: str = field(default_factory=lambda: _preference("active_llm", ""))
    openai_default_model: str = field(
        default_factory=lambda: _preference("openai_default_model", "")
    )
    claude_model: str = field(
        default_factory=lambda: _preference("claude_model", "")
    )
    gemini_model: str = field(
        default_factory=lambda: _preference("gemini_model", "")
    )
    copilot_model: str = field(
        default_factory=lambda: _preference("copilot_model", "")
    )
    kimi_code_model: str = field(
        default_factory=lambda: _preference("kimi_code_model", "")
    )
    minimax_plan_model: str = field(
        default_factory=lambda: _preference("minimax_plan_model", "")
    )
    deepseek_model: str = field(
        default_factory=lambda: _preference("deepseek_model", "")
    )
    qwen_model: str = field(
        default_factory=lambda: _preference("qwen_model", "")
    )
    codex_agent_model: str = field(
        default_factory=lambda: _preference("codex_agent_model", "")
    )
    qwen_code_agent_model: str = field(
        default_factory=lambda: _preference("qwen_code_agent_model", "")
    )
    ollama_model: str = field(
        default_factory=lambda: _preference("ollama_model", "llama3.2-vision")
    )
    ollama_vision_model: str = field(
        default_factory=lambda: _preference("ollama_vision_model", "llama3.2-vision")
    )
    ollama_text_model: str = field(
        default_factory=lambda: _preference("ollama_text_model", "llama3.2:3b")
    )
    # Immutable Ollama identities are process-environment security inputs, not
    # persisted preferences. Values must be exact 64-hex digests from /api/tags.
    ollama_vision_model_digest: str = field(default_factory=lambda: (
        os.environ.get("OLLAMA_VISION_MODEL_DIGEST", "").strip()
    ))
    ollama_text_model_digest: str = field(default_factory=lambda: (
        os.environ.get("OLLAMA_TEXT_MODEL_DIGEST", "").strip()
    ))
    lmstudio_model: str = field(
        default_factory=lambda: _preference("lmstudio_model", "")
    )
    whisper_model: str = field(
        default_factory=lambda: _preference("whisper_model", "base")
    )
    whisper_model_sha256: str = field(default_factory=lambda: (
        os.environ.get("WHISPER_MODEL_SHA256", "").strip()
    ))
    whispercpp_model_sha256: str = field(default_factory=lambda: (
        os.environ.get("WHISPERCPP_MODEL_SHA256", "").strip()
    ))
    clicky_wake_model_sha256: str = field(default_factory=lambda: (
        os.environ.get("CLICKY_WAKE_MODEL_SHA256", "").strip()
    ))
    whisper_language: str = field(
        default_factory=lambda: _preference("whisper_language", "")
    )
    mic_device_index: Optional[int] = field(
        default_factory=lambda: _preference("mic_device_index", None)
    )
    response_language: str = field(
        default_factory=lambda: _preference("response_language", "")
    )
    custom_instructions: str = field(
        default_factory=lambda: _preference("custom_instructions", DEFAULT_SYSTEM_PROMPT)
    )
    elevenlabs_voice_id: str = field(
        default_factory=lambda: _preference("elevenlabs_voice_id", "")
    )
    hotkey: str = field(default_factory=lambda: _preference("hotkey", "ctrl+win"))
    journal_enabled: bool = field(
        default_factory=lambda: bool(_preference("journal_enabled", False))
    )
    web_search_enabled: bool = field(
        default_factory=lambda: bool(_preference("web_search_enabled", False))
    )
    privacy_consent_version: int = field(
        default_factory=lambda: int(_preference("privacy_consent_version", 0))
    )
    microphone_consent: bool = field(
        default_factory=lambda: bool(_preference("microphone_consent", False))
    )
    cloud_stt_consent: bool = field(
        default_factory=lambda: bool(_preference("cloud_stt_consent", False))
    )
    cloud_tts_consent: bool = field(
        default_factory=lambda: bool(_preference("cloud_tts_consent", False))
    )
    screen_capture_consent: bool = field(
        default_factory=lambda: bool(_preference("screen_capture_consent", False))
    )
    coding_agent_consent: bool = field(
        default_factory=lambda: bool(_preference("coding_agent_consent", False))
    )
    stt_provider_preference: str = field(
        default_factory=lambda: _preference("stt_provider", "")
    )
    transcription_vocabulary: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            _preference("transcription_vocabulary", [])
        )
    )

    def llm_provider(self) -> str:
        """Returns the active LLM provider (runtime override > priority chain).

        Priority chain: Claude > OpenAI > GitHub Copilot > Gemini > Ollama.
        """
        if self.active_llm in self.available_llm_providers():
            return self.active_llm
        if self.anthropic_api_key:
            return "claude"
        if self.openai_api_key:
            return "openai"
        try:
            from ai.github_copilot_provider import is_authenticated as _gh_ok
            if _gh_ok():
                return "copilot"
        except Exception:
            pass
        if self.google_api_key:
            return "gemini"
        return "ollama"

    def available_llm_providers(self) -> list[str]:
        """All providers the user can switch to right now."""
        out = []
        if self.anthropic_api_key:
            out.append("claude")
        if self.openai_api_key:
            out.append("openai")
        try:
            from ai.github_copilot_provider import is_authenticated as _gh_ok
            if _gh_ok():
                out.append("copilot")
        except Exception:
            pass
        if self.google_api_key:
            out.append("gemini")
        if self.kimi_code_api_key:
            out.append("kimi_code")
        if self.minimax_api_key:
            out.append("minimax_plan")
        if self.deepseek_api_key:
            out.append("deepseek")
        if self.dashscope_api_key:
            out.append("qwen")
        from privacy_controls import coding_agent_allowed

        if coding_agent_allowed(self):
            if shutil.which("codex"):
                out.append("codex_agent")
            if self.qwen_coding_plan_api_key and shutil.which("qwen"):
                out.append("qwen_code_agent")
        out.append("ollama")     # always available if the daemon is running
        out.append("lmstudio")   # always available if the local server is running
        return out

    def set_active_llm(self, name: str) -> None:
        """Switch providers and persist only the provider name."""
        normalized = (name or "").strip().lower()
        from ai.provider_catalog import ALL_PROVIDER_IDS

        if normalized not in ALL_PROVIDER_IDS:
            return
        self.active_llm = normalized
        _save_preferences(active_llm=normalized)

    def selected_model(self, provider: str) -> str:
        attributes = {
            "claude": "claude_model",
            "openai": "openai_default_model",
            "gemini": "gemini_model",
            "copilot": "copilot_model",
            "kimi_code": "kimi_code_model",
            "minimax_plan": "minimax_plan_model",
            "deepseek": "deepseek_model",
            "qwen": "qwen_model",
            "codex_agent": "codex_agent_model",
            "qwen_code_agent": "qwen_code_agent_model",
            "ollama": "ollama_model",
            "lmstudio": "lmstudio_model",
        }
        attribute = attributes.get((provider or "").strip().lower())
        if attribute is None:
            return ""
        value = getattr(self, attribute, "")
        from ai.model_selection import valid_model_id

        return value if valid_model_id(value) else ""

    def set_selected_model(self, provider: str, model_id: str) -> None:
        provider = (provider or "").strip().lower()
        attributes = {
            "claude": ("claude_model", "claude_model"),
            "openai": ("openai_default_model", "openai_default_model"),
            "gemini": ("gemini_model", "gemini_model"),
            "copilot": ("copilot_model", "copilot_model"),
            "kimi_code": ("kimi_code_model", "kimi_code_model"),
            "minimax_plan": ("minimax_plan_model", "minimax_plan_model"),
            "deepseek": ("deepseek_model", "deepseek_model"),
            "qwen": ("qwen_model", "qwen_model"),
            "codex_agent": ("codex_agent_model", "codex_agent_model"),
            "qwen_code_agent": (
                "qwen_code_agent_model",
                "qwen_code_agent_model",
            ),
            "ollama": ("ollama_model", "ollama_model"),
            "lmstudio": ("lmstudio_model", "lmstudio_model"),
        }
        target = attributes.get(provider)
        from ai.model_selection import valid_model_id

        if target is None or not valid_model_id(model_id):
            raise ValueError("Invalid provider model selection")
        attribute, preference = target
        setattr(self, attribute, model_id)
        _save_preferences(**{preference: model_id})

    def stt_provider(self) -> str:
        forced = self.stt_provider_preference.strip().lower()
        if forced in (
            "deepgram",
            "deepgram_batch",
            "openai",
            "whisper_cpp",
            "faster_whisper",
        ):
            return forced
        if self.deepgram_api_key:
            return "deepgram"
        if self.openai_api_key:
            return "openai"
        # Prefer whisper.cpp (GPU-accelerated, same engine as Handy) when the
        # pywhispercpp package is installed; otherwise fall back to faster-whisper.
        try:
            import pywhispercpp  # noqa: F401
            return "whisper_cpp"
        except ImportError:
            return "faster_whisper"

    def available_stt_providers(self) -> list[str]:
        """Return explicit live, cloud-batch, and local-batch choices."""
        providers: list[str] = []
        if self.deepgram_api_key:
            providers.extend(("deepgram", "deepgram_batch"))
        if self.openai_api_key:
            providers.append("openai")
        providers.extend(("whisper_cpp", "faster_whisper"))
        return providers

    def set_stt_provider(self, name: str) -> None:
        normalized = (name or "").strip().lower()
        if normalized not in self.available_stt_providers():
            raise ValueError(
                "The selected speech provider is unavailable; configure its "
                "credential or choose a local provider."
            )
        self.stt_provider_preference = normalized
        _save_preferences(stt_provider=normalized)

    def set_transcription_vocabulary(self, terms) -> tuple[str, ...]:
        from audio.stt.vocabulary import validate_user_terms

        approved = validate_user_terms(terms)
        self.transcription_vocabulary = approved
        _save_preferences(transcription_vocabulary=list(approved))
        return approved

    def tts_provider(self) -> str:
        if self.elevenlabs_api_key:
            return "elevenlabs"
        if self.openai_api_key:
            return "openai"
        return "edge_tts"

    def search_provider(self) -> str:
        if self.tavily_api_key:
            return "tavily"
        return "duckduckgo"

    def describe(self) -> dict:
        """Human-readable summary of active providers for the setup panel."""
        return {
            "llm": self.llm_provider(),
            "stt": self.stt_provider(),
            "stt_mode": (
                "live"
                if self.stt_provider() == "deepgram"
                else "cloud batch"
                if self.stt_provider() in ("deepgram_batch", "openai")
                else "local batch"
            ),
            "tts": self.tts_provider(),
            "search": self.search_provider(),
            "ollama_model": self.ollama_model,
            "ollama_vision_model": self.get_ollama_model("vision"),
            "ollama_text_model":   self.get_ollama_model("text"),
            "lmstudio_host": self.lmstudio_host,
            "lmstudio_model": self.lmstudio_model or "(auto — whatever's loaded)",
        }

    # ── Ollama runtime model selection ───────────────────────────────────

    def get_ollama_model(self, kind: str = "vision") -> str:
        """Return the persisted vision or text Ollama model."""
        return self.ollama_vision_model if kind == "vision" else self.ollama_text_model

    def set_ollama_model(self, kind: str, name: str) -> None:
        if kind not in ("vision", "text"):
            return
        normalized = (name or "").strip()[:256]
        if kind == "vision":
            self.ollama_vision_model = normalized
            _save_preferences(ollama_vision_model=normalized)
        else:
            self.ollama_text_model = normalized
            _save_preferences(ollama_text_model=normalized)

    def set_custom_instructions(self, text: str) -> None:
        value = (text or "").strip()[: 32 * 1024]
        self.custom_instructions = value
        _save_preferences(custom_instructions=value)

    def set_response_language(self, code: str) -> None:
        value = (code or "").strip()[:16]
        self.response_language = value
        _save_preferences(response_language=value)

    def set_mic_device_index(self, device_index: Optional[int]) -> None:
        value = device_index if isinstance(device_index, int) and 0 <= device_index <= 4096 else None
        self.mic_device_index = value
        _save_preferences(mic_device_index=value)

    def set_journal_enabled(self, enabled: bool) -> None:
        self.journal_enabled = bool(enabled)
        _save_preferences(journal_enabled=self.journal_enabled)

    def set_web_search_enabled(self, enabled: bool) -> None:
        self.web_search_enabled = bool(enabled)
        _save_preferences(web_search_enabled=self.web_search_enabled)

    def set_privacy_permissions(
        self,
        *,
        microphone: bool,
        cloud_stt: bool = False,
        cloud_tts: bool,
        screen_capture: bool,
        coding_agent: bool = False,
        notice_version: int,
    ) -> None:
        """Atomically persist explicit privacy choices for the current notice."""
        if notice_version != PRIVACY_NOTICE_VERSION:
            raise ValueError("Unsupported privacy notice version")
        if not all(
            isinstance(value, bool)
            for value in (
                microphone,
                cloud_stt,
                cloud_tts,
                screen_capture,
                coding_agent,
            )
        ):
            raise TypeError("Privacy permissions must be booleans")
        _save_preferences(
            privacy_consent_version=notice_version,
            microphone_consent=microphone,
            cloud_stt_consent=cloud_stt,
            cloud_tts_consent=cloud_tts,
            screen_capture_consent=screen_capture,
            coding_agent_consent=coding_agent,
        )
        self.privacy_consent_version = notice_version
        self.microphone_consent = microphone
        self.cloud_stt_consent = cloud_stt
        self.cloud_tts_consent = cloud_tts
        self.screen_capture_consent = screen_capture
        self.coding_agent_consent = coding_agent


# Singleton
cfg = Config()
