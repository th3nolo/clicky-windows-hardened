"""
Central state machine for Clicky Windows.

Orchestrates:
  hotkey / wake-word → ambient listener capture → STT → screen capture
  → web search → (optional Claude Computer Use pointing) → LLM → TTS
"""

import asyncio
import concurrent.futures
import logging
import math
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from config import cfg
from ai.base_provider import BaseLLMProvider, Message
from audio.ambient_listener import AmbientListener
from audio.tts.base_tts import DisabledTTSProvider
from privacy_controls import (
    cloud_stt_allowed,
    cloud_tts_allowed,
    microphone_allowed,
    screen_capture_allowed,
)
from screen.capture import capture_all_screens
from screen.topology import (
    MonitorTopologyError,
    format_screen_context,
    requested_screen_index,
    select_monitor,
)
from ui.panel import AppState
from turn_coordinator import TurnCoordinator, TurnPhase, TurnSession
from tutor import (
    active_window_title, app_key,
    is_locate, is_multistep, is_next, is_stop, is_sensitive_window,
    is_repeat, is_journal_today, is_journal_week, is_quiz_review,
    is_identity_question,
)
from tutor_features import (
    journal, pdf_context, ocr, code_mode, lesson_recorder,
    multilang, workflow_capture, collab,
)
import skills as skills_pkg

_log = logging.getLogger("clicky.manager")


def _require_local_ollama(timeout: float = 2.0) -> None:
    """Require an already-running loopback Ollama server; never start a process."""
    from http.client import HTTPConnection
    from urllib.parse import urlsplit

    try:
        parsed = urlsplit(cfg.ollama_host.rstrip("/"))
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("the Ollama endpoint is not a plain HTTP loopback URL")
        port = parsed.port or 11434
        path = (parsed.path.rstrip("/") or "") + "/api/tags"
        host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
        connection = HTTPConnection(host, port, timeout=timeout)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            response.read(1)
            if response.status != 200:
                raise OSError(f"health endpoint returned HTTP {response.status}")
        finally:
            connection.close()
    except Exception as exc:
        raise RuntimeError(
            "Local Ollama is unavailable. The hardened build never starts "
            "external executables; install and start Ollama yourself, then "
            "retry after its local server is ready."
        ) from exc


def _build_system_prompt(
    window_title: str = "",
    lesson_step: int = 0,
    total_steps: int = 0,
    quiz_mode: bool = False,
    detected_coord: Optional[tuple] = None,
    code_active: bool = False,
    language_code: str = "en",
    extra: str = "",
) -> str:
    today = datetime.now().strftime("%A, %B %d, %Y")
    ctx_lines = [f"TODAY'S DATE: {today}."]
    if window_title:
        ctx_lines.append(f'ACTIVE WINDOW: "{window_title}"')
    if detected_coord:
        x, y, label, screen_index = detected_coord
        ctx_lines.append(
            f"DETECTED ELEMENT (pre-computed by the pointing engine — use "
            f"this coordinate verbatim in your [POINT] tag): x={x}, y={y}, "
            f"label='{label}', screen={screen_index}. "
            f"(Already normalized 0-1000.)"
        )
    if total_steps > 1:
        ctx_lines.append(
            f"LESSON PROGRESS: step {lesson_step + 1} of {total_steps}. "
            "Explain ONLY this step, then end with \"Say 'next' when ready.\""
        )

    # ── Quiz mode: dominant prompt that completely replaces normal behaviour ──
    if quiz_mode:
        return f"""You are Clicky, an interactive QUIZ TUTOR. The user has
turned on Quiz Mode and wants to be tested, NOT explained to.

{chr(10).join(ctx_lines)}

ABSOLUTE QUIZ RULES (override everything else):
  • NEVER answer the user's question directly. NEVER point at UI elements.
    NEVER emit [POINT:...] tags. NEVER explain how things work.
  • If the user is greeting / starting ("hello", "what's on my screen", "begin",
    "quiz me", anything), START the quiz: ask ONE short, specific question
    about what's visible on screen — name a button, recognise an icon, predict
    what a click would do, identify the active app, etc.
  • If the user's last message looks like an ANSWER (a noun, a short phrase, a
    yes/no), evaluate it in ≤1 sentence ("Correct!" / "Close — actually..."),
    then immediately ask the NEXT question.
  • Questions should be progressively harder. Vary topic across UI literacy,
    keyboard shortcuts, what's currently visible, predicting outcomes.
  • Keep it warm and encouraging. Never lecture.
  • Format every turn as:  <one-line evaluation if applicable>  <one question>

STYLE: short, friendly, never more than 2 sentences. End every turn with a
question mark.""" + extra

    from config import _TECHNICAL_RULES
    base = cfg.custom_instructions.strip()
    base = base.replace("{{CONTEXT}}", chr(10).join(ctx_lines))
    base = base.replace("{{TODAY}}", today)
    return base + _TECHNICAL_RULES + _code_addendum(code_active) + _lang_addendum(language_code) + extra


def _code_addendum(active: bool) -> str:
    if not active:
        return ""
    from tutor_features.code_mode import code_system_prompt_addendum
    return code_system_prompt_addendum()


def _lang_addendum(code: str) -> str:
    from tutor_features.multilang import language_directive
    return language_directive(code)


def _guess_label(transcript: str) -> str:
    """Extract a 1-3 word label from a locate query for the speech bubble.
       'where is the search bar' → 'search bar' """
    t = transcript.lower().strip().rstrip("?.!")
    for kw in ("where is the ", "where's the ", "show me the ",
              "find the ", "locate the ", "click the ", "click on the ",
              "how do i click ", "how do i find ", "how do i open ",
              "point at the ", "point to the ", "highlight the "):
        if kw in t:
            tail = t.split(kw, 1)[1]
            words = tail.split()
            return " ".join(words[:3]) or "here"
    return "right here!"


def _split_steps(text: str) -> list[str]:
    """Parse a numbered list out of an LLM response. Returns [] if not a list."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    steps = []
    for ln in lines:
        m = re.match(r"^(?:\d+[\).]|[-*])\s+(.+)$", ln)
        if m:
            steps.append(m.group(1).strip())
    return steps


def _speakable(text: str) -> str:
    """Make LLM text safe for TTS: models emit LaTeX ("\\( a \\)",
    "\\[ a^2 + b^2 = c^2 \\]") and markdown that edge-tts reads aloud
    verbatim as gibberish. Convert to spoken math / plain words."""
    t = text
    t = re.sub(r'\\(?:left|right)\b', '', t)
    t = re.sub(r'\\sqrt\s*\{([^{}]*)\}', r'the square root of \1', t)
    t = re.sub(r'\\frac\s*\{([^{}]*)\}\s*\{([^{}]*)\}', r'\1 over \2', t)
    t = (t.replace('\\times', ' times ').replace('\\cdot', ' times ')
          .replace('\\pi', ' pi ').replace('\\theta', ' theta ')
          .replace('\\alpha', ' alpha ').replace('\\beta', ' beta '))
    t = re.sub(r'\\[\[\(\]\)]', '', t)              # \( \) \[ \] delimiters
    t = re.sub(r'\^\s*\{?2\}?', ' squared', t)
    t = re.sub(r'\^\s*\{?3\}?', ' cubed', t)
    t = re.sub(r'\^\s*\{?(\d+)\}?', r' to the power \1', t)
    t = t.replace('²', ' squared').replace('³', ' cubed')
    t = re.sub(r'\\[a-zA-Z]+', ' ', t)              # any leftover \commands
    t = re.sub(r'[{}]', '', t)
    t = re.sub(r'[*_#`]+', '', t)                   # markdown emphasis/headers
    t = re.sub(r'\s+', ' ', t).strip()
    return t


POINT_RE = re.compile(r'\[POINT:(\d+),(\d+):([^:\]]+):screen(\d+)\]')
# A partial "[POINT..." prefix that hasn't closed yet — hold it back from display
# until the next chunk so we never leak a half tag.
POINT_PARTIAL_RE = re.compile(r'\[(?:P|PO|POI|POIN|POINT|POINT:[^\]]*)?$')

# ── Teaching / drawing tags ──────────────────────────────────────────────────
# ALL coordinates are normalized 0-1000 relative to the screenshot the model
# saw (x: 0=left edge, 1000=right edge; y: 0=top, 1000=bottom). The manager
# converts to logical screen pixels via _denorm(). Trailing :color is optional
# on every shape.
_C = r'(?::([a-z]+))?'                       # optional trailing color group
LINE_RE      = re.compile(r'\[LINE:(\d+),(\d+)->(\d+),(\d+)' + _C + r'\]')
ARROW_RE     = re.compile(r'\[ARROW:(\d+),(\d+)->(\d+),(\d+)' + _C + r'\]')
CIRCLE_RE    = re.compile(r'\[CIRCLE:(\d+),(\d+),(\d+)(?::([^:\]]*))?' + _C + r'\]')
RECT_RE      = re.compile(r'\[RECT:(\d+),(\d+),(\d+),(\d+)' + _C + r'\]')
POLY_RE      = re.compile(r'\[POLY:((?:\d+,\d+[ ]*)+)' + _C + r'\]')
TEXT_RE      = re.compile(r'\[TEXT:(\d+),(\d+):([^:\]]+)' + _C + r'(?::(s|m|l))?\]')
ANGLE_RE     = re.compile(r'\[ANGLE:(\d+),(\d+),(\d+)(?:,(-?\d+))?' + _C + r'\]')
UNDERLINE_RE = re.compile(r'\[UNDERLINE:(\d+),(\d+),(\d+)' + _C + r'\]')
LABEL_RE     = re.compile(r'\[LABEL:(\d+),(\d+):([^:\]]+)' + _C + r'\]')
CLEAR_RE     = re.compile(r'\[CLEAR\]')
# Anchor forms — element resolved by name via the hybrid pointer (UIA), so
# the model never guesses coordinates for real UI: [CIRCLE:@Save button]
CIRCLE_AT_RE    = re.compile(r'\[CIRCLE:@([^:\]]+?)' + _C + r'\]')
UNDERLINE_AT_RE = re.compile(r'\[UNDERLINE:@([^:\]]+?)' + _C + r'\]')

ANY_TAG_RE   = re.compile(
    r'\[(?:POINT|ARROW|CIRCLE|UNDERLINE|LABEL|LINE|RECT|POLY|TEXT|ANGLE|CLEAR)'
    r'(?::[^\]]*)?\]'
)
ANY_PARTIAL_RE = re.compile(r'\[[A-Z]{0,9}(?::[^\]]*)?$')

# Questions that ask Clicky to locate / click UI elements — triggers the
# Computer Use element locator when Claude is the provider.
POINT_TRIGGER_RE = re.compile(
    r"\b(where\s+(is|do|can)|how\s+do\s+i\s+(click|find|open|access|use)|"
    r"point\s+(at|to)|show\s+me\s+(the|where)|click\s+(the|on)|find\s+the)\b",
    re.IGNORECASE,
)


class CompanionManager(QObject):
    """Thread-safe signals for Qt UI updates from async/audio threads."""

    sig_state_changed       = pyqtSignal(object)          # AppState
    sig_response_chunk      = pyqtSignal(str)
    sig_response_done       = pyqtSignal(str)
    sig_transcript_begin    = pyqtSignal(int)
    sig_transcript_partial  = pyqtSignal(int, str)
    sig_transcript_final    = pyqtSignal(int, str)
    sig_transcript_end      = pyqtSignal(int)
    sig_audio_level         = pyqtSignal(float)
    sig_point_at            = pyqtSignal(float, float, str)
    sig_point_hold          = pyqtSignal(bool)            # True → dwell forever until release
    sig_point_release       = pyqtSignal()                # end dwell + fly buddy back
    sig_error               = pyqtSignal(str)
    sig_copilot_models_done = pyqtSignal(int)             # arg = model count
    sig_models_refreshed    = pyqtSignal(str, int)        # (provider, count)
    sig_ollama_models       = pyqtSignal(dict)            # {"vision": [...], "text": [...]}
    sig_arrow               = pyqtSignal(float, float, float, float)
    sig_circle              = pyqtSignal(float, float, float)
    sig_underline           = pyqtSignal(float, float, float)
    sig_label               = pyqtSignal(float, float, str)
    sig_draw                = pyqtSignal(dict)            # generic teaching shape → overlay
    sig_clear_drawings      = pyqtSignal()                # wipe all teaching shapes
    sig_recording_state     = pyqtSignal(bool, str)       # (is_recording, output_dir)

    def __init__(self):
        super().__init__()
        self._state: AppState = AppState.IDLE
        self._history: List[Message] = []
        self._current_model: Optional[str] = None
        self._web_search_enabled = bool(cfg.web_search_enabled)
        self._turns = TurnCoordinator()
        self._input_lock = threading.RLock()
        self._pressed_session: TurnSession | None = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Providers (lazy)
        self._llm: Optional[BaseLLMProvider] = None
        self._stt = None
        self._streaming_stt: dict[int, object] = {}
        self._streaming_open: dict[int, concurrent.futures.Future] = {}
        self._tts = None
        self._privacy_tts_notice_emitted = False

        # Per-app memory: { window_title: [Message, ...] }
        self._app_memory: dict[str, List[Message]] = {}
        # Screenshots from the current turn — needed to map the LLM's
        # normalized 0-1000 tag coordinates back to logical screen pixels.
        self._screens_ctx: list = []
        self._active_screen_index: int | None = None
        # Figures detected on screen this turn (normalized vertices) — used
        # for prompt injection and for snapping sloppy stroke endpoints.
        self._figures_ctx: list = []
        # Current lesson: sequence of pending steps for multi-step tutorials
        self._lesson_steps: list[str] = []
        self._lesson_step_idx: int = 0
        # Toggles
        self._slow_mode = False
        self._quiz_mode = False
        self._privacy_guard = True
        self._code_mode_auto = True       # auto-detect IDE windows
        self._multilang = True             # auto-reply in user's language
        self._journal_enabled = bool(cfg.journal_enabled)  # opt-in Q&A storage
        self._ocr_enabled = True           # use Tesseract for fine print
        self._last_response = ""           # for "say it again" voice command
        self._attached_docs: list[tuple[str, str]] = []   # (filename, text)

        # Optional subsystems (lazy-init to keep startup fast)
        self._recorder: Optional[lesson_recorder.LessonRecorder] = None
        self._collab: Optional[collab.CollabSession] = None
        self._workflow: Optional[workflow_capture.WorkflowCapture] = None

        # Load bundled skills plus hash-approved user extensions.
        try:
            skills_pkg.load_all()
        except Exception:
            pass

        # Always-on ambient listener
        self._listener = AmbientListener(
            on_level=self._handle_level,
            on_wake=self._handle_wake,
            device=cfg.mic_device_index,
            on_error=self.sig_error.emit,
        )

        # Background asyncio loop
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if microphone_allowed(cfg):
            try:
                self._listener.start()
            except Exception as e:
                self.sig_error.emit(f"Mic error: {e}")
        # Sleep/wake watchdog — restarts mic + loop after system resume
        self._start_sleep_watchdog()
        # On startup, refresh any stale model cache in the background.
        # 30-day TTL means this is a once-a-month no-op for most launches.
        self._submit(self._refresh_stale_models())

    async def _refresh_stale_models(self):
        try:
            from ai.model_registry import refresh_all_stale
            results = await refresh_all_stale()
            for prov, count in results.items():
                if count > 0:
                    self.sig_models_refreshed.emit(prov, count)
        except Exception:
            pass   # silent — not user-facing on startup

    def shutdown(self):
        with self._input_lock:
            self._pressed_session = None
            self._turns.cancel_active(self._set_idle_state)
        # Kill any audio that was playing when the user clicked Quit
        try:
            from audio.playback import stop_audio
            stop_audio()
        except Exception:
            pass
        self._listener.stop()
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

    def _run_loop(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_forever()
        finally:
            pending = tuple(asyncio.all_tasks(self._loop))
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            self._loop.close()

    # ── Sleep/wake watchdog ───────────────────────────────────────────────────

    def _start_sleep_watchdog(self):
        """Background thread that detects system resume after sleep/hibernate
        and restarts the mic stream + asyncio loop so the panel stays live."""
        def _watch():
            HEARTBEAT = 5.0          # check every 5 s
            DRIFT_THRESHOLD = 15.0   # if we wake and >15 s have passed, resume occurred
            last_tick = time.monotonic()
            while True:
                time.sleep(HEARTBEAT)
                now = time.monotonic()
                drift = now - last_tick - HEARTBEAT
                last_tick = now
                if drift > DRIFT_THRESHOLD:
                    # System was sleeping — restart subsystems
                    self._on_system_resume()

        t = threading.Thread(target=_watch, daemon=True)
        t.start()

    def _on_system_resume(self):
        """Called automatically after the laptop wakes from sleep."""
        with self._input_lock:
            self._pressed_session = None
            self._turns.cancel_active(self._set_idle_state)
        # 1. Restart the mic stream (sounddevice handles become stale on resume)
        try:
            self._listener.stop()
        except Exception:
            pass
        time.sleep(1.0)   # give Windows audio stack time to reinit
        if microphone_allowed(cfg):
            try:
                self._listener.start()
            except Exception as e:
                self.sig_error.emit(f"Mic restart after sleep failed: {e}")

        # 2. If the asyncio loop thread died, restart it
        if not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()

        # 3. Reset state to IDLE so the panel shows the correct status
        self._set_idle_state()

    def _submit(self, coro, session: TurnSession | None = None):
        if not self._loop:
            coro.close()
            if session is not None and self._turns.is_current(session):
                self._turns.cancel_active(self._set_idle_state)
            return None
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        if session is not None:
            self._turns.bind_task(session, fut)

        def _observe(f):
            try:
                f.result()
            except concurrent.futures.CancelledError:
                return
            except Exception as e:
                # A swallowed exception here used to leave the UI stuck on
                # "Listening..." forever (GitHub issue #6). Surface it and
                # always return to idle.
                if session is not None and not self._turns.is_current(session):
                    return
                _log.exception("background task failed: %s", e)
                try:
                    if session is None:
                        self.sig_error.emit(str(e))
                        self._set_idle_state()
                    else:
                        self._emit_turn_signal(session, self.sig_error, str(e))
                        self._finish_turn(session)
                except Exception:
                    pass
            finally:
                if session is not None:
                    self._turns.unbind_cancel(session, "turn-task")
        fut.add_done_callback(_observe)
        return fut

    # ── Provider lazy init ────────────────────────────────────────────────────

    def _get_llm(self) -> BaseLLMProvider:
        if self._llm is None:
            provider = cfg.llm_provider()
            if provider == "ollama":
                _require_local_ollama()
            from ai.provider_factory import create_llm_provider

            self._llm = create_llm_provider(provider)
        return self._llm

    def _get_stt(self):
        if self._stt is None:
            provider = cfg.stt_provider()
            if provider == "deepgram":
                raise RuntimeError(
                    "Deepgram live mode requires an active streaming session; "
                    "Clicky will not silently fall back to batch transcription."
                )
            if provider == "deepgram_batch":
                from audio.stt.deepgram_stt import DeepgramSTT
                self._stt = DeepgramSTT(
                    vocabulary=cfg.transcription_vocabulary
                )
            elif provider == "openai":
                from audio.stt.openai_stt import OpenAISTT
                self._stt = OpenAISTT()
            elif provider == "whisper_cpp":
                from audio.stt.whisper_cpp_stt import WhisperCppSTT
                self._stt = WhisperCppSTT()
            else:
                from audio.stt.faster_whisper_stt import FasterWhisperSTT
                self._stt = FasterWhisperSTT()
        return self._stt

    def _new_streaming_stt(self, session: TurnSession):
        if cfg.stt_provider() != "deepgram":
            return None
        if not cloud_stt_allowed(cfg):
            raise PermissionError(
                "Deepgram live transcription is disabled until cloud "
                "speech-to-text permission is granted in Privacy permissions."
            )
        if self._loop is None or not self._loop.is_running():
            raise RuntimeError(
                "The live transcription worker is still starting. Try again."
            )
        from audio.stt.deepgram_streaming import DeepgramStreamingSession

        stream = DeepgramStreamingSession(
            api_key=cfg.deepgram_api_key,
            cloud_consent=True,
            loop=self._loop,
            vocabulary=cfg.transcription_vocabulary,
            on_partial=lambda text: self._emit_turn_signal(
                session,
                self.sig_transcript_partial,
                session.sequence,
                text,
            ),
        )
        self._streaming_stt[session.sequence] = stream
        open_future = asyncio.run_coroutine_threadsafe(stream.open(), self._loop)
        self._streaming_open[session.sequence] = open_future
        self._turns.bind_task(
            session,
            open_future,
            name="streaming-open",
        )
        self._turns.bind_cancel(
            session,
            "streaming-stt",
            lambda: self._cancel_streaming_stt(session.sequence),
        )
        return stream

    def _cancel_streaming_stt(self, sequence: int) -> None:
        open_future = self._streaming_open.pop(sequence, None)
        if open_future is not None and not open_future.done():
            open_future.cancel()
        stream = self._streaming_stt.pop(sequence, None)
        loop = self._loop
        if stream is None or loop is None or not loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(stream.cancel(), loop)
        except RuntimeError:
            pass

    async def _finalize_streaming_stt(self, session: TurnSession) -> str:
        stream = self._streaming_stt.get(session.sequence)
        if stream is None:
            raise RuntimeError("The live transcription session is unavailable.")
        open_future = self._streaming_open.get(session.sequence)
        try:
            if open_future is not None:
                await asyncio.wrap_future(open_future)
            if not self._turns.is_current(session):
                raise asyncio.CancelledError
            return await stream.finalize()
        finally:
            self._streaming_open.pop(session.sequence, None)
            self._streaming_stt.pop(session.sequence, None)
            self._turns.unbind_cancel(session, "streaming-open")
            self._turns.unbind_cancel(session, "streaming-stt")

    def _get_tts(self):
        if not cloud_tts_allowed(cfg):
            if not isinstance(self._tts, DisabledTTSProvider):
                self._tts = DisabledTTSProvider()
            if not self._privacy_tts_notice_emitted:
                self.sig_error.emit(
                    "Speech output is disabled until cloud text-to-speech "
                    "permission is granted in Privacy permissions."
                )
                self._privacy_tts_notice_emitted = True
            return self._tts
        if self._tts is None or isinstance(self._tts, DisabledTTSProvider):
            provider = cfg.tts_provider()
            if provider == "elevenlabs":
                from audio.tts.elevenlabs_provider import ElevenLabsProvider
                self._tts = ElevenLabsProvider()
            elif provider == "openai":
                from audio.tts.openai_tts_provider import OpenAITTSProvider
                self._tts = OpenAITTSProvider()
            else:
                from audio.tts.edge_tts_provider import EdgeTTSProvider
                self._tts = EdgeTTSProvider()
        return self._tts

    # ── Input sources ─────────────────────────────────────────────────────────

    def on_hotkey_press(self):
        with self._input_lock:
            if (
                self._pressed_session is not None
                and self._turns.is_current(self._pressed_session)
            ):
                return
            session = self._turns.start_capture()
            if session is None:
                return
            if self._begin_capture(session):
                self._pressed_session = session
            else:
                self._finish_turn(session)

    def on_hotkey_release(self):
        with self._input_lock:
            session = self._pressed_session
            self._pressed_session = None
            if session is None or not self._turns.release_capture(session):
                return
            self._emit_state(AppState.THINKING, session)
            self._submit(self._end_capture_and_process(session), session)

    def _handle_wake(self):
        """Triggered from ambient listener when wake-word is detected."""
        with self._input_lock:
            if self._turns.active is not None:
                return
            session = self._turns.start_capture()
            if session is None:
                return
            if not self._begin_capture(session):
                self._finish_turn(session)
                return
            self._submit(self._auto_stop_after_pause(session), session)

    def _handle_level(self, rms: float):
        try:
            self.sig_audio_level.emit(rms)
        except Exception:
            pass   # never crash the sounddevice audio thread

    # ── Capture flow ──────────────────────────────────────────────────────────

    def _begin_capture(self, session: TurnSession) -> bool:
        if not microphone_allowed(cfg):
            self._emit_turn_signal(session, self.sig_error,
                "Microphone access is disabled. Open Setup & Diagnostics → "
                "Privacy permissions to enable it."
            )
            return False
        provider = cfg.stt_provider()
        if (
            provider in ("deepgram", "deepgram_batch", "openai")
            and not cloud_stt_allowed(cfg)
        ):
            self._emit_turn_signal(
                session,
                self.sig_error,
                "The selected cloud speech provider is disabled until cloud "
                "speech-to-text permission is granted in Privacy permissions. "
                "Clicky did not send microphone audio.",
            )
            return False
        try:
            streaming = self._new_streaming_stt(session)
        except Exception as exc:
            self._emit_turn_signal(session, self.sig_error, str(exc))
            return False
        try:
            started = self._listener.start_recording(
                session.sequence,
                on_frame=streaming.send_frame if streaming is not None else None,
            )
        except Exception as e:
            self._cancel_streaming_stt(session.sequence)
            _log.exception("mic start failed")
            self._emit_turn_signal(session, self.sig_error,
                f"Couldn't open the microphone: {e}\n"
                "Check Tray → Setup & Diagnostics → Microphone."
            )
            return False
        if not started:
            self._cancel_streaming_stt(session.sequence)
            return False
        self._turns.bind_cancel(
            session,
            "recording",
            lambda: self._listener.cancel_recording(session.sequence),
        )
        self._turns.bind_cancel(session, "playback", self._cancel_outputs)
        self._turns.bind_cancel(
            session,
            "transcript-ui",
            lambda: self.sig_transcript_end.emit(session.sequence),
        )
        self.sig_transcript_begin.emit(session.sequence)
        self._emit_state(AppState.LISTENING, session)
        return self._turns.is_current(session)

    async def _auto_stop_after_pause(self, session: TurnSession):
        """When triggered by wake word, wait for user to finish speaking."""
        import time
        max_total_s = 10.0
        start_t = time.monotonic()
        while (
            self._turns.is_current(session)
            and self._turns.phase is TurnPhase.CAPTURING
        ):
            await asyncio.sleep(0.15)
            if time.monotonic() - start_t > max_total_s:
                break
        if not self._turns.release_capture(session):
            return
        self._emit_state(AppState.THINKING, session)
        await self._end_capture_and_process(session)

    async def _end_capture_and_process(self, session: TurnSession):
        if not self._turns.is_current(session):
            return
        try:
            pcm = self._listener.stop_recording(session.sequence)
            self._turns.unbind_cancel(session, "recording")
        except Exception as e:
            _log.exception("mic stop failed")
            self._emit_turn_signal(
                session, self.sig_error, f"Microphone capture failed: {e}"
            )
            self._finish_turn(session)
            return
        if pcm is None or not self._turns.is_current(session):
            return
        _log.info("captured %.1fs of audio", len(pcm) / 32000)
        if len(pcm) < 3200:  # < 0.1s of audio — ignore
            self._finish_turn(session)
            return

        pointing_held = False  # track whether we told overlay to hold dwell
        side_tasks: list[asyncio.Task] = []

        try:
            # 1. Transcribe — bounded so a hung/loading local STT model can
            # never freeze the UI on "Thinking..." forever
            if session.sequence in self._streaming_stt:
                transcript = await asyncio.wait_for(
                    self._finalize_streaming_stt(session),
                    timeout=25,
                )
            else:
                transcript = await asyncio.wait_for(
                    self._get_stt().transcribe(pcm), timeout=90,
                )
            if not self._turns.is_current(session):
                return
            _log.info("voice transcription completed (provider=%s)",
                      cfg.stt_provider())
            if not transcript.strip():
                return
            self._emit_turn_signal(
                session,
                self.sig_transcript_final,
                session.sequence,
                transcript,
            )

            # ── Voice commands — short-circuit before LLM ──
            if is_stop(transcript):
                self.stop()
                return

            title = active_window_title()
            ak = app_key(title)

            if is_next(transcript) and self._lesson_steps:
                await self._advance_lesson_step(ak, session)
                return

            # "say it again" — replay the last response without a new LLM call
            if is_repeat(transcript) and self._last_response:
                self._emit_turn_signal(
                    session, self.sig_response_chunk, self._last_response
                )
                self._emit_turn_signal(
                    session, self.sig_response_done, self._last_response
                )
                self._emit_state(AppState.SPEAKING, session)
                try:
                    await self._get_tts().speak(self._last_response)
                except Exception:
                    pass
                return

            # Journal voice queries — answered locally, no LLM call needed
            if is_journal_today(transcript):
                msg = journal.summarise(journal.entries_today(),
                                        "Here's what you asked about today:\n")
                await self._reply_local(msg, session)
                return
            if is_journal_week(transcript):
                msg = journal.summarise(journal.entries_this_week(),
                                        "Here's the past week:\n")
                await self._reply_local(msg, session)
                return
            if is_quiz_review(transcript):
                await self._spaced_review(session)
                return

            # User-created skills (run BEFORE the LLM, like built-ins above)
            try:
                skill = skills_pkg.match(transcript)
                if skill:
                    msg = await skill["handler"](self, transcript)
                    if not self._turns.is_current(session):
                        return
                    if msg:
                        await self._reply_local(msg, session)
                    return
            except Exception as e:
                self._emit_turn_signal(session, self.sig_error, f"Skill error: {e}")

            if not self._current_model:
                self._emit_turn_signal(
                    session,
                    self.sig_error,
                    "No validated model is selected for "
                    f"{cfg.llm_provider()}. Choose one in the Model dropdown. "
                    "Clicky did not send the request.",
                )
                return

            # 2. Screen capture — skipped if sensitive window (password manager etc.)
            #
            # ALSO skipped for "who is X" / "tell me about X" identity questions:
            # OpenAI + Claude refuse to identify people in screenshots even when
            # the answer is in their training data ("Sorry I can't identify the
            # person in images"). Stripping the screenshot lets the LLM answer
            # from training data + web search instead, which is what the user
            # actually wants when they ask "who is MrBeast" while on YouTube.
            sensitive = self._privacy_guard and is_sensitive_window(title)
            identity_q = is_identity_question(transcript)
            screen_permission = screen_capture_allowed(cfg)
            if sensitive or identity_q or not screen_permission:
                screenshots = []
                images_b64 = []
            else:
                screenshots = capture_all_screens()
            if not self._turns.is_current(session):
                return
            active_shot = None
            if screenshots:
                requested_index = requested_screen_index(transcript)
                selected_monitor = select_monitor(
                    [screenshot.descriptor() for screenshot in screenshots],
                    requested_index,
                )
                active_shot = next(
                    screenshot
                    for screenshot in screenshots
                    if screenshot.stable_id == selected_monitor.stable_id
                )
                self._active_screen_index = active_shot.index
            else:
                self._active_screen_index = None
            if not (sensitive or identity_q or not screen_permission):
                images_b64 = [s.base64_jpeg for s in screenshots]
            # Fresh question → wipe the previous lesson's drawings and remember
            # this turn's screenshots for coordinate mapping.
            self._screens_ctx = screenshots
            self._emit_turn_signal(session, self.sig_clear_drawings)

            # Local figure detection (OpenCV) — finds triangles/rects/circles
            # with EXACT normalized vertices so any LLM (even small Ollama
            # models) can draw on them accurately by echoing the numbers.
            self._figures_ctx = []
            fig_extra = ""
            if active_shot is not None:
                try:
                    from ai.figure_detector import detect_figures, figures_prompt
                    self._figures_ctx = await asyncio.to_thread(
                        detect_figures, active_shot.base64_jpeg,
                    )
                    fig_extra = (
                        f"\nFIGURE SCREEN: screen{active_shot.index} "
                        f"[{active_shot.stable_id}]\n"
                        + figures_prompt(self._figures_ctx)
                    )
                    if not self._turns.is_current(session):
                        return
                except Exception:
                    self._figures_ctx = []

            # 3. Parallel side-work: web search + element locator
            #
            # Pointing now works for EVERY provider:
            #   • If ANTHROPIC_API_KEY is set → use Claude Computer Use
            #     (~5px accuracy, gold standard).
            #   • Otherwise → universal grid-based locator with the active
            #     vision LLM (Copilot GPT-4o, OpenAI, Gemini, Ollama llava).
            #     ~25-50px accuracy. Good enough for buttons/menus/icons.
            locate_triggered = is_locate(transcript)
            multistep = is_multistep(transcript)

            search_task = None
            locate_task = None
            if self._web_search_enabled:
                from ai.web_search import search
                search_task = asyncio.create_task(search(transcript))
                side_tasks.append(search_task)

            if active_shot is not None and locate_triggered:
                shot = active_shot
                # Pointing accuracy upgrade: try the hybrid pointer first.
                # Tier 1 (UIA tree) is ~5ms and pixel-perfect; tier 2 (OCR)
                # handles canvas apps. Falls through to the vision LLM grid
                # below only when both whiff.
                try:
                    from ai.hybrid_pointer import find_target as _hybrid_find
                    target = _hybrid_find(
                        transcript,
                        screenshot=shot,
                        llm_provider=self._get_llm(),
                        # The manager owns the non-blocking async vision fallback.
                        skip_vision=True,
                    )
                except Exception:
                    target = None

                if not self._turns.is_current(session):
                    return
                if target is not None and target.source in ("uia", "ocr"):
                    # The hybrid pointer returns Qt logical coordinates for the
                    # explicitly selected monitor.
                    from types import SimpleNamespace
                    _pt = SimpleNamespace(x=target.x, y=target.y)
                    async def _ready(pt=_pt):
                        return pt
                    locate_task = asyncio.create_task(_ready())
                    side_tasks.append(locate_task)
                elif cfg.anthropic_api_key:
                    # Path A — Anthropic Computer Use (best accuracy)
                    from ai.element_locator import detect_element
                    locate_task = asyncio.create_task(detect_element(
                        screenshot_jpeg_b64=shot.base64_jpeg,
                        original_width=shot.width,
                        original_height=shot.height,
                        physical_width=shot.physical_width,
                        physical_height=shot.physical_height,
                        physical_left=shot.physical_left,
                        physical_top=shot.physical_top,
                        dpi_scale=shot.dpi_scale,
                        logical_left=shot.logical_left,
                        logical_top=shot.logical_top,
                        logical_width=shot.logical_width,
                        logical_height=shot.logical_height,
                        screen_index=shot.index,
                        user_question=transcript,
                    ))
                    side_tasks.append(locate_task)
                else:
                    # Path B — Universal grid locator (any vision LLM)
                    try:
                        from ai.universal_locator import detect_element_universal
                        llm = self._get_llm()
                        locate_task = asyncio.create_task(detect_element_universal(
                            llm=llm,
                            screenshot_jpeg_b64=shot.base64_jpeg,
                            original_width=shot.width,
                            original_height=shot.height,
                            physical_width=shot.physical_width,
                            physical_height=shot.physical_height,
                            physical_left=shot.physical_left,
                            physical_top=shot.physical_top,
                            dpi_scale=shot.dpi_scale,
                            logical_left=shot.logical_left,
                            logical_top=shot.logical_top,
                            logical_width=shot.logical_width,
                            logical_height=shot.logical_height,
                            screen_index=shot.index,
                            user_question=transcript,
                            model=self._current_model,
                        ))
                        side_tasks.append(locate_task)
                    except Exception:
                        # Universal locator should never crash the main flow
                        locate_task = None

            search_results = ""
            if search_task:
                try:
                    search_results = await search_task or ""
                except Exception:
                    search_results = ""
                if not self._turns.is_current(session):
                    return

            detected = None
            detected_coord = None
            if locate_task:
                try:
                    detected = await locate_task
                except Exception:
                    detected = None
                if not self._turns.is_current(session):
                    return
            if detected:
                # Short label guess — first noun phrase after "the"/"where"
                label = _guess_label(transcript)
                # Prompt wants NORMALIZED 0-1000 coords (the model echoes them
                # into [POINT:...] which _parse_points denormalizes back).
                ndx, ndy = self._norm(
                    detected.x, detected.y, active_shot.index
                )
                detected_coord = (
                    ndx,
                    ndy,
                    label,
                    active_shot.index,
                )
                # Fire the overlay NOW so the buddy flies over while the LLM
                # still thinks. Hold dwell until TTS completes.
                self._emit_turn_signal(session, self.sig_point_hold, True)
                pointing_held = True
                self._emit_turn_signal(
                    session, self.sig_point_at,
                    float(detected.x), float(detected.y), label
                )

            # ── Per-turn enrichment: code mode, language, OCR, attached docs ──
            code_active = self._code_mode_auto and code_mode.is_code_window(title)
            if cfg.response_language:
                lang_code = cfg.response_language   # user-forced — always wins
            else:
                lang_code = (multilang.detect_language(transcript)
                             if self._multilang else "en")

            # OCR fallback for fine print (only if user actually asks to read)
            ocr_extra = ""
            if (
                self._ocr_enabled
                and active_shot is not None
                and ocr.needs_ocr(transcript)
            ):
                try:
                    import base64
                    jpeg = base64.b64decode(active_shot.base64_jpeg)
                    txt = ocr.run_ocr(jpeg)
                    if txt:
                        ocr_extra = ocr.format_for_prompt(txt)
                except Exception:
                    pass

            # Attached documents (drag-dropped PDFs etc.)
            doc_extra = ""
            for fname, text in self._attached_docs:
                doc_extra += pdf_context.format_for_prompt(fname, text)

            # 4. Build system prompt with all context
            system = _build_system_prompt(
                window_title=title,
                lesson_step=self._lesson_step_idx,
                total_steps=len(self._lesson_steps),
                quiz_mode=self._quiz_mode,
                detected_coord=detected_coord,
                code_active=code_active,
                language_code=lang_code,
                extra=(
                    ocr_extra
                    + doc_extra
                    + fig_extra
                    + format_screen_context(
                        [screenshot.descriptor() for screenshot in screenshots]
                    )
                ),
            )
            if sensitive:
                system += (
                    "\n\nPRIVACY GUARD: the user's active window looks sensitive "
                    "(password manager, banking, login). I did NOT take a "
                    "screenshot. Answer from memory only, and tell the user you "
                    "skipped the screenshot for safety.\n"
                )
            elif not screen_permission:
                system += (
                    "\n\nSCREEN CAPTURE DISABLED: the user has not granted screen "
                    "capture permission. No screenshot was taken. Answer without "
                    "visual context and do not imply that you can see the screen.\n"
                )
            if search_results:
                from ai.web_search import build_search_context
                system += build_search_context(search_results)

            # Use per-app history so context doesn't bleed between apps
            history = self._app_memory.setdefault(ak, [])

            provider_images = images_b64
            provider = cfg.llm_provider()
            try:
                from ai.model_selection import model_supports_vision
                from ai.provider_catalog import REGISTRY_MODEL_PROVIDERS

                if provider in REGISTRY_MODEL_PROVIDERS:
                    from ai.model_registry import cached_models

                    supports_vision = model_supports_vision(
                        self._current_model,
                        cached_models(provider),
                    )
                elif provider == "copilot":
                    from ai.github_copilot_provider import cached_models

                    supports_vision = model_supports_vision(
                        self._current_model,
                        cached_models(),
                    )
                else:
                    supports_vision = True
            except Exception:
                supports_vision = False
            if not supports_vision:
                provider_images = []
                system += (
                    "\n\nSELECTED MODEL HAS NO VALIDATED IMAGE INPUT: Clicky did "
                    "not send screenshot pixels to this model. Use only the "
                    "textual screen map, OCR, and detected-figure context above; "
                    "do not claim direct visual inspection.\n"
                )

            # 5. Stream LLM — buffer partial [POINT:...] tags so they never leak
            full_response = ""
            display_buf = ""
            async for chunk in self._get_llm().stream_response(
                user_text=transcript,
                screenshots_b64=provider_images,
                history=history,
                system_prompt=system,
                model=self._current_model,
            ):
                if not self._turns.is_current(session):
                    return
                full_response += chunk
                display_buf += chunk
                self._parse_points(display_buf, session)
                display_buf = ANY_TAG_RE.sub("", display_buf)
                m = ANY_PARTIAL_RE.search(display_buf)
                if m:
                    flush = display_buf[: m.start()]
                    display_buf = display_buf[m.start():]
                else:
                    flush = display_buf
                    display_buf = ""
                if flush:
                    self._emit_turn_signal(session, self.sig_response_chunk, flush)
            if display_buf:
                self._emit_turn_signal(
                    session,
                    self.sig_response_chunk,
                    ANY_TAG_RE.sub("", display_buf),
                )
            if not self._turns.is_current(session):
                return

            # 6. Update per-app history
            history.append(Message(role="user", content=transcript))
            history.append(Message(role="assistant", content=full_response))
            self._app_memory[ak] = history[-20:]

            # Multistep: parse numbered steps for later "next" invocations
            if multistep and not self._lesson_steps:
                steps = _split_steps(full_response)
                if len(steps) > 1:
                    self._lesson_steps = steps
                    self._lesson_step_idx = 0

            clean = ANY_TAG_RE.sub("", full_response).strip()
            self._emit_turn_signal(session, self.sig_response_done, clean)
            self._last_response = clean   # for "say it again"

            # Log to knowledge journal (skipped in quiz mode — those Q&As aren't
            # study material)
            if self._journal_enabled and not self._quiz_mode:
                try:
                    journal.log_qa(
                        question=transcript, answer=clean,
                        app_key=ak, window_title=title,
                        provider=cfg.llm_provider(),
                        model=self._current_model or "",
                        enabled=self._journal_enabled,
                    )
                except Exception:
                    pass

            # Lesson recorder gets the Q&A in transcript.md
            if self._recorder and self._recorder.is_recording:
                self._recorder.log_question(transcript)
                self._recorder.log_answer(clean)

            # Live-collab broadcast
            if self._collab and self._collab.code:
                try:
                    await self._collab.send({
                        "type": "qa", "q": transcript, "a": clean,
                    })
                except Exception:
                    pass

            # 7. TTS — hold the point visible while we speak. Switch voice
            # to match the user's language for multilingual mode.
            if not self._turns.is_current(session):
                return
            if self._multilang and lang_code != "en":
                try:
                    tts = self._get_tts()
                    if hasattr(tts, "set_voice"):
                        tts.set_voice(multilang.voice_for(lang_code))
                except Exception:
                    pass
            self._turns.set_phase(session, TurnPhase.SPEAKING)
            self._emit_state(AppState.SPEAKING, session)
            try:
                await self._play_lesson(full_response, clean, session)
            except asyncio.CancelledError:
                raise

        except Exception as e:
            self._emit_turn_signal(session, self.sig_error, str(e))

        finally:
            for task in side_tasks:
                if not task.done():
                    task.cancel()
            if pointing_held:
                self._emit_turn_signal(session, self.sig_point_release)
            self._finish_turn(session)

    async def _reply_local(self, msg: str, session: TurnSession):
        """Show + speak a message that doesn't need an LLM round-trip."""
        self._emit_turn_signal(session, self.sig_response_chunk, msg)
        self._emit_turn_signal(session, self.sig_response_done, msg)
        self._last_response = msg
        self._turns.set_phase(session, TurnPhase.SPEAKING)
        self._emit_state(AppState.SPEAKING, session)
        try:
            await self._get_tts().speak(msg)
        except Exception:
            pass

    async def _spaced_review(self, session: TurnSession):
        """SR-style review: pick due entries from the journal, ask one back."""
        due = journal.due_for_review(limit=1)
        if not due:
            await self._reply_local(
                "Nothing due for review right now — keep learning, I'll quiz "
                "you in a few days.",
                session,
            )
            return
        entry = due[0]
        msg = f"Review: {entry['question']}"
        # Mark "correct" optimistically — a real implementation would wait for
        # the user's answer and grade it. Stubbed: reschedule based on streak.
        try:
            journal.mark_reviewed(int(entry["id"]), correct=True)
        except Exception:
            pass
        await self._reply_local(msg, session)

    async def _advance_lesson_step(self, ak: str, session: TurnSession):
        """User said 'next' — re-render the stored next lesson step via TTS,
        no new LLM round-trip needed."""
        self._lesson_step_idx += 1
        if self._lesson_step_idx >= len(self._lesson_steps):
            msg = "That's the last step — you're done!"
            self._lesson_steps = []
            self._lesson_step_idx = 0
        else:
            step = self._lesson_steps[self._lesson_step_idx]
            total = len(self._lesson_steps)
            msg = f"Step {self._lesson_step_idx + 1} of {total}: {step}"

        self._emit_turn_signal(session, self.sig_response_chunk, msg)
        self._emit_turn_signal(session, self.sig_response_done, msg)
        self._turns.set_phase(session, TurnPhase.SPEAKING)
        self._emit_state(AppState.SPEAKING, session)
        try:
            await self._get_tts().speak(msg)
        except Exception:
            pass

    # ── Coordinate mapping ────────────────────────────────────────────────────
    #
    # The LLM emits NORMALIZED 0-1000 coordinates relative to the screenshot
    # it saw. The overlay draws in LOGICAL screen pixels. These helpers convert
    # between the two using the ScreenShot metadata captured this turn.

    def _shot(self, screen_idx: int | None = None):
        requested = (
            self._active_screen_index if screen_idx is None else screen_idx
        )
        for s in self._screens_ctx:
            if s.index == requested:
                return s
        return None

    def _denorm(
        self,
        nx: float,
        ny: float,
        screen_idx: int | None = None,
    ):
        """Normalized 0-1000 (screenshot space) → logical screen pixels."""
        shot = self._shot(screen_idx)
        if shot is None:
            raise MonitorTopologyError(
                f"unknown screen number {screen_idx}"
            )
        log_w = shot.logical_width or (
            shot.physical_width / max(shot.dpi_scale, 1.0)
        )
        log_h = shot.logical_height or (
            shot.physical_height / max(shot.dpi_scale, 1.0)
        )
        # Legacy safety: values beyond 1000 are raw pixels in the downscaled
        # JPEG the model saw — scale by the JPEG dimensions instead.
        bx = 1000.0 if (nx <= 1000 and ny <= 1000) else float(max(shot.width, 1))
        by = 1000.0 if (nx <= 1000 and ny <= 1000) else float(max(shot.height, 1))
        x = shot.logical_left + (nx / bx) * log_w
        y = shot.logical_top + (ny / by) * log_h
        return x, y

    def _denorm_len(
        self,
        n: float,
        screen_idx: int | None = None,
    ) -> float:
        """Normalized length (0-1000 x-units) → logical pixels."""
        shot = self._shot(screen_idx)
        if shot is None:
            raise MonitorTopologyError(
                f"unknown screen number {screen_idx}"
            )
        log_w = shot.logical_width or (
            shot.physical_width / max(shot.dpi_scale, 1.0)
        )
        return (n / 1000.0) * log_w

    def _norm(
        self,
        x: float,
        y: float,
        screen_idx: int | None = None,
    ):
        """Logical screen pixels → normalized 0-1000 (for prompt injection)."""
        shot = self._shot(screen_idx)
        if shot is None:
            raise MonitorTopologyError(
                f"unknown screen number {screen_idx}"
            )
        log_w = shot.logical_width or (
            shot.physical_width / max(shot.dpi_scale, 1.0)
        )
        log_h = shot.logical_height or (
            shot.physical_height / max(shot.dpi_scale, 1.0)
        )
        nx = (x - shot.logical_left) / max(log_w, 1) * 1000
        ny = (y - shot.logical_top) / max(log_h, 1) * 1000
        return int(round(nx)), int(round(ny))

    def _resolve_anchor(self, name: str):
        """Resolve '@element name' → logical bbox via UIA (fast tier only)."""
        try:
            from ai.hybrid_pointer import find_target
            shot = self._shot()
            if shot is None:
                return None
            t = find_target(
                name,
                screenshot=shot,
                skip_ocr=True,
                skip_vision=True,
            )
            if t is None:
                return None
            return t.bbox
        except Exception:
            return None

    def _parse_points(self, text: str, session: TurnSession):
        """Live-during-stream tags: pointing and board-clear only. Drawing
        tags are deferred and played back in sync with narration."""
        for match in POINT_RE.finditer(text):
            x, y, label, scr = match.groups()
            lx, ly = self._denorm(float(x), float(y), int(scr))
            self._emit_turn_signal(
                session, self.sig_point_at, lx, ly, label.strip()
            )
        if CLEAR_RE.search(text):
            self._emit_turn_signal(session, self.sig_clear_drawings)

    # ── Vertex snapping (figure-detector assisted accuracy) ─────────────────

    def _snap_pt(self, nx: float, ny: float, thresh: float = 35.0):
        """Snap a normalized point to the nearest detected-figure vertex."""
        best, bd = None, thresh
        for fig in self._figures_ctx:
            for (vx, vy) in fig.vertices:
                d = math.hypot(nx - vx, ny - vy)
                if d < bd:
                    bd, best = d, (float(vx), float(vy))
        return best if best is not None else (nx, ny)

    def _angle_rot_for_vertex(self, nx: float, ny: float):
        """Rotation (deg) that puts a right-angle marker INSIDE the detected
        polygon at vertex (nx,ny), aligned with its two edges. None if the
        point is not a detected vertex."""
        for fig in self._figures_ctx:
            verts = fig.vertices
            if len(verts) < 3:
                continue
            for i, (vx, vy) in enumerate(verts):
                if math.hypot(nx - vx, ny - vy) > 6:
                    continue
                P = self._denorm(vx, vy)
                A = self._denorm(*verts[i - 1])
                B = self._denorm(*verts[(i + 1) % len(verts)])
                a1 = math.degrees(math.atan2(A[1] - P[1], A[0] - P[0]))
                a2 = math.degrees(math.atan2(B[1] - P[1], B[0] - P[0]))
                rot = a1
                # Marker spans [rot, rot+90]; flip if the second edge sits on
                # the other side so the square lies between the two edges.
                if (a2 - rot) % 360 > 180:
                    rot -= 90
                return rot
        return None

    # ── Drawing-tag extraction (deferred, order-preserving) ──────────────────

    def _shape_from_tag(self, tag: str):
        m = CIRCLE_AT_RE.fullmatch(tag)
        if m:
            name, color = m.groups()
            bbox = self._resolve_anchor(name.strip())
            if not bbox:
                return None
            l, t, r, b = bbox
            return {"kind": "circle", "x": (l + r) / 2, "y": (t + b) / 2,
                    "r": max(r - l, b - t) / 2 + 10, "label": "",
                    "color": color or "blue"}
        m = UNDERLINE_AT_RE.fullmatch(tag)
        if m:
            name, color = m.groups()
            bbox = self._resolve_anchor(name.strip())
            if not bbox:
                return None
            l, t, r, b = bbox
            return {"kind": "underline", "x": l, "y": b + 3, "w": r - l,
                    "color": color or "blue"}
        m = LINE_RE.fullmatch(tag) or ARROW_RE.fullmatch(tag)
        if m:
            kind = "line" if tag.startswith("[LINE") else "arrow"
            x1, y1, x2, y2, color = m.groups()
            n1 = self._snap_pt(float(x1), float(y1))
            n2 = self._snap_pt(float(x2), float(y2))
            return {"kind": kind, "pts": [self._denorm(*n1), self._denorm(*n2)],
                    "color": color or "blue"}
        m = CIRCLE_RE.fullmatch(tag)
        if m:
            x, y, r, label, color = m.groups()
            cx, cy = self._denorm(float(x), float(y))
            return {"kind": "circle", "x": cx, "y": cy,
                    "r": max(12.0, self._denorm_len(float(r))),
                    "label": (label or "").strip(), "color": color or "blue"}
        m = RECT_RE.fullmatch(tag)
        if m:
            x1, y1, x2, y2, color = m.groups()
            p1 = self._denorm(*self._snap_pt(float(x1), float(y1)))
            p2 = self._denorm(*self._snap_pt(float(x2), float(y2)))
            return {"kind": "rect", "x1": p1[0], "y1": p1[1],
                    "x2": p2[0], "y2": p2[1], "color": color or "blue"}
        m = POLY_RE.fullmatch(tag)
        if m:
            pts_str, color = m.groups()
            pts = [self._denorm(*self._snap_pt(float(a), float(b)))
                   for a, b in re.findall(r'(\d+),(\d+)', pts_str)]
            if len(pts) < 3:
                return None
            return {"kind": "poly", "pts": pts, "color": color or "blue"}
        m = TEXT_RE.fullmatch(tag)
        if m:
            x, y, content, color, size = m.groups()
            lx, ly = self._denorm(float(x), float(y))
            return {"kind": "text", "x": lx, "y": ly, "text": content.strip(),
                    "color": color or "blue", "size": size or "m"}
        m = ANGLE_RE.fullmatch(tag)
        if m:
            x, y, s, rot, color = m.groups()
            nx, ny = self._snap_pt(float(x), float(y))
            auto_rot = self._angle_rot_for_vertex(nx, ny)
            lx, ly = self._denorm(nx, ny)
            return {"kind": "angle", "x": lx, "y": ly,
                    "s": max(10.0, self._denorm_len(float(s))),
                    "rot": auto_rot if auto_rot is not None else float(rot or 0),
                    "color": color or "blue"}
        m = UNDERLINE_RE.fullmatch(tag)
        if m:
            x, y, w, color = m.groups()
            lx, ly = self._denorm(float(x), float(y))
            return {"kind": "underline", "x": lx, "y": ly,
                    "w": max(8.0, self._denorm_len(float(w))),
                    "color": color or "blue"}
        m = LABEL_RE.fullmatch(tag)
        if m:
            x, y, txt, color = m.groups()
            lx, ly = self._denorm(float(x), float(y))
            return {"kind": "text", "x": lx, "y": ly, "text": txt.strip(),
                    "color": color or "blue", "size": "s"}
        return None

    def _extract_shapes(self, text: str) -> list:
        """All drawing shapes in a piece of text, in document order."""
        shapes = []
        for m in ANY_TAG_RE.finditer(text):
            try:
                sh = self._shape_from_tag(m.group(0))
            except Exception:
                sh = None
            if sh:
                shapes.append(sh)
        return shapes

    # ── Teacher-style narrated playback ──────────────────────────────────────

    def _segment_lesson(self, full_response: str) -> list:
        """Split a response into (sentence, [shapes]) pairs, preserving which
        sentence each drawing tag belongs to."""
        tags: list[str] = []

        def _stash(m):
            tags.append(m.group(0))
            return f"\x00{len(tags) - 1}\x00"

        masked = ANY_TAG_RE.sub(_stash, full_response)
        parts = re.split(r'(?<=[.!?])\s+', masked)
        out = []
        for part in parts:
            ids = [int(i) for i in re.findall(r'\x00(\d+)\x00', part)]
            shapes = self._extract_shapes("".join(tags[i] for i in ids))
            clean = re.sub(r'\s+', ' ', re.sub(r'\x00\d+\x00', ' ', part)).strip()
            if clean or shapes:
                out.append((clean, shapes))
        return out

    async def _play_lesson(
        self,
        full_response: str,
        clean: str,
        session: TurnSession,
    ):
        """Narrate sentence by sentence, drawing each sentence's shapes as it
        is spoken — the cadence of a teacher at a whiteboard. Falls back to
        plain TTS when the response contains no drawings."""
        segments = self._segment_lesson(full_response)
        if not any(shapes for _, shapes in segments):
            await self._get_tts().speak(_speakable(clean))
            return

        try:
            from ui.overlay import (
                _shape_length, STROKE_SPEED_PX_S,
                SHAPE_DRAW_MIN_S, SHAPE_DRAW_MAX_S, SHAPE_GAP_SECONDS,
            )
        except Exception:
            _shape_length = None

        draw_end = time.monotonic()
        for text, shapes in segments:
            if not self._turns.is_current(session):
                return
            draw_end = max(draw_end, time.monotonic())
            for sh in shapes:
                self._emit_turn_signal(session, self.sig_draw, sh)
                if _shape_length is not None:
                    dur = _shape_length(sh) / STROKE_SPEED_PX_S
                    dur = max(SHAPE_DRAW_MIN_S, min(SHAPE_DRAW_MAX_S, dur))
                    draw_end += dur + SHAPE_GAP_SECONDS
                else:
                    draw_end += 1.0
            if text:
                try:
                    await self._get_tts().speak(_speakable(text))
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
            # A real teacher finishes the stroke before the next sentence —
            # wait out any drawing time the narration didn't cover.
            remaining = draw_end - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(min(remaining, 4.0) + 0.1)

    def _emit_state(
        self,
        state: AppState,
        session: TurnSession | None = None,
    ) -> bool:
        if session is not None:
            ran, _ = self._turns.run_if_current(
                session, self._set_state, state
            )
            return ran
        self._set_state(state)
        return True

    def _set_state(self, state: AppState) -> None:
        self._state = state
        self.sig_state_changed.emit(state)

    def _set_idle_state(self) -> None:
        self._set_state(AppState.IDLE)

    def _emit_turn_signal(self, session, signal, *args) -> bool:
        ran, _ = self._turns.run_if_current(session, signal.emit, *args)
        return ran

    def _finish_turn(self, session: TurnSession) -> bool:
        self._cancel_streaming_stt(session.sequence)

        def finish_ui() -> None:
            self.sig_transcript_end.emit(session.sequence)
            self._set_idle_state()

        return self._turns.complete(session, finish_ui)

    def _cancel_outputs(self) -> None:
        try:
            from audio.playback import stop_audio
            stop_audio()
        except Exception:
            pass
        tts = self._tts
        if tts and hasattr(tts, "stop"):
            try:
                tts.stop()
            except Exception:
                pass

    # ── Settings ──────────────────────────────────────────────────────────────

    def set_model(self, model: str):
        from ai.model_selection import model_is_available, valid_model_id

        provider = cfg.llm_provider()
        from ai.provider_catalog import REGISTRY_MODEL_PROVIDERS

        if provider in REGISTRY_MODEL_PROVIDERS:
            from ai.model_registry import cached_models

            valid = model_is_available(model, cached_models(provider))
        elif provider == "copilot":
            from ai.github_copilot_provider import cached_models

            valid = model_is_available(model, cached_models())
        else:
            valid = valid_model_id(model)
        if not valid:
            self._current_model = None
            if model:
                self.sig_error.emit(
                    f"The selected {provider} model is unavailable. "
                    "Choose a listed model before asking Clicky."
                )
            return False
        try:
            cfg.set_selected_model(provider, model)
        except (OSError, ValueError) as exc:
            self._current_model = None
            self.sig_error.emit(f"Could not save the {provider} model: {exc}")
            return False
        self._current_model = model
        return True

    def set_active_provider(self, name: str):
        """Switch the active provider and refresh only its reviewed model source."""
        cfg.set_active_llm(name)
        self._llm = None           # force re-init on next query
        self._current_model = None
        # If switching to Copilot and the cached model list is stale (or
        # missing), refresh it in the background so the panel shows the
        # *current* set of models GitHub offers — not stale hardcoded ones.
        if name == "copilot":
            try:
                from ai.github_copilot_provider import cache_is_stale
                if cache_is_stale():
                    self._submit(self._refresh_copilot_models())
            except Exception:
                pass
        else:
            try:
                from ai.provider_catalog import REFRESHABLE_MODEL_PROVIDERS
                from ai.model_registry import cache_is_stale as _stale

                if name in REFRESHABLE_MODEL_PROVIDERS and _stale(name):
                    self._submit(self._refresh_one_model_list(name))
            except Exception:
                pass
        if name == "ollama":
            # Surface installed models in the tray immediately
            self.refresh_ollama_models()

    async def _refresh_one_model_list(self, provider: str):
        try:
            from ai.model_registry import refresh
            ms = await refresh(provider)
            self.sig_models_refreshed.emit(provider, len(ms))
        except Exception as e:
            self.sig_error.emit(f"{provider} model refresh failed: {e}")

    def refresh_copilot_models(self):
        """Public — bound to the tray 'Refresh Copilot models' action."""
        self._submit(self._refresh_copilot_models())

    async def _refresh_copilot_models(self):
        try:
            from ai.github_copilot_provider import refresh_models_to_cache
            models = await refresh_models_to_cache()
            self.sig_copilot_models_done.emit(len(models))
        except Exception as e:
            self.sig_error.emit(f"Copilot model refresh failed: {e}")

    # ── Ollama model management ──────────────────────────────────────────────

    def refresh_ollama_models(self):
        """Public — kick off async poll of /api/tags. Result via sig_ollama_models."""
        self._submit(self._refresh_ollama_models())

    async def _refresh_ollama_models(self):
        try:
            _require_local_ollama()
            from ai import ollama_bootstrap
            ollama_bootstrap.require_configured_model_identities()
            from ai.ollama_provider import OllamaProvider
            classified = await OllamaProvider().list_models_classified()
            self.sig_ollama_models.emit(classified)
        except Exception as e:
            self.sig_error.emit(f"Ollama model list failed: {e}")

    def set_ollama_model(self, kind: str, name: str):
        """Tray callback — update the active vision/text model. No restart needed."""
        cfg.set_ollama_model(kind, name)
        # Force the provider instance to re-read cfg on next call
        if cfg.llm_provider() == "ollama":
            self._llm = None

    def set_custom_instructions(self, text: str):
        """Persist non-secret instructions in the LocalAppData preferences."""
        try:
            cfg.set_custom_instructions(text)
        except Exception as exc:
            self.sig_error.emit(f"Could not save instructions: {exc}")

    def set_response_language(self, code: str):
        """Pin Clicky's reply language (empty means auto-detect)."""
        try:
            cfg.set_response_language(code)
        except Exception as exc:
            self.sig_error.emit(f"Could not save language setting: {exc}")

    def set_mic_device(self, device_index: int):
        """Tray callback — switch input device without restarting the app."""
        try:
            cfg.set_mic_device_index(device_index if device_index >= 0 else None)
        except Exception as exc:
            self.sig_error.emit(f"Could not save microphone setting: {exc}")
        with self._input_lock:
            self._pressed_session = None
            self._turns.cancel_active(self._set_idle_state)
        try:
            self._listener.stop()
        except Exception:
            pass
        from audio.ambient_listener import AmbientListener
        self._listener = AmbientListener(
            on_level=self._handle_level,
            on_wake=self._handle_wake,
            device=cfg.mic_device_index,
            on_error=self.sig_error.emit,
        )
        if microphone_allowed(cfg):
            try:
                self._listener.start()
            except Exception as e:
                self.sig_error.emit(f"Could not start mic: {e}")

    def set_stt_provider(self, name: str) -> bool:
        """Switch live/cloud-batch/local transcription explicitly."""
        try:
            cfg.set_stt_provider(name)
        except (OSError, ValueError) as exc:
            self.sig_error.emit(f"Could not change speech input mode: {exc}")
            return False
        with self._input_lock:
            self._pressed_session = None
            self._turns.cancel_active(self._set_idle_state)
        self._stt = None
        return True

    def set_transcription_vocabulary(self, terms) -> tuple[str, ...] | None:
        try:
            approved = cfg.set_transcription_vocabulary(terms)
        except (OSError, ValueError) as exc:
            self.sig_error.emit(f"Could not save transcription vocabulary: {exc}")
            return None
        # Batch providers retain constructor settings, so discard the cached
        # instance. An active live session keeps the immutable vocabulary it
        # opened with; the next capture receives the newly approved terms.
        self._stt = None
        return approved

    def refresh_privacy_permissions(self) -> None:
        """Apply persisted choices immediately without restarting Clicky."""
        with self._input_lock:
            self._pressed_session = None
            self._turns.cancel_active(self._set_idle_state)
        self._tts = None
        self._privacy_tts_notice_emitted = False
        if microphone_allowed(cfg):
            try:
                self._listener.start()
            except Exception as exc:
                self.sig_error.emit(f"Could not start mic: {exc}")
        else:
            self._listener.stop()
            self._listener.cancel_recording()

    def set_web_search(self, enabled: bool):
        self._web_search_enabled = bool(enabled)
        try:
            cfg.set_web_search_enabled(self._web_search_enabled)
        except Exception as exc:
            self.sig_error.emit(f"Could not save web search setting: {exc}")

    def set_wake_word(self, enabled: bool):
        if enabled and not microphone_allowed(cfg):
            self._listener.set_wake_word_enabled(False)
            self.sig_error.emit(
                "Wake-word listening requires microphone permission."
            )
            return
        self._listener.set_wake_word_enabled(enabled)

    def set_slow_mode(self, enabled: bool):
        self._slow_mode = enabled

    def set_quiz_mode(self, enabled: bool):
        was = self._quiz_mode
        self._quiz_mode = enabled
        if enabled and not was:
            # Kick off the first question immediately so the user doesn't
            # have to ask "begin quiz". Uses the active screen as context.
            session = self._turns.start_processing()
            if session is not None:
                self._turns.bind_cancel(session, "playback", self._cancel_outputs)
                self._emit_state(AppState.THINKING, session)
                self._submit(self._kickoff_quiz(session), session)

    async def _kickoff_quiz(self, session: TurnSession):
        """Called when quiz mode flips ON — generates the first question
        without waiting for a user utterance."""
        if not self._turns.is_current(session):
            return
        if not self._current_model:
            self._emit_turn_signal(
                session,
                self.sig_error,
                "Quiz Mode needs a validated model selection. Choose one in "
                "the Model dropdown.",
            )
            self._finish_turn(session)
            return
        if not screen_capture_allowed(cfg):
            self._emit_turn_signal(session, self.sig_error,
                "Quiz Mode needs screen capture permission. Open Setup & "
                "Diagnostics → Privacy permissions."
            )
            self._finish_turn(session)
            return
        try:
            screenshots = capture_all_screens()
            if not self._turns.is_current(session):
                return
            images_b64 = [s.base64_jpeg for s in screenshots]
            selected_monitor = select_monitor(
                [screenshot.descriptor() for screenshot in screenshots]
            )
            self._active_screen_index = selected_monitor.index
            title = active_window_title()
            system = _build_system_prompt(
                window_title=title,
                quiz_mode=True,
                extra=format_screen_context(
                    [screenshot.descriptor() for screenshot in screenshots]
                ),
            )
            ak = app_key(title)
            history = self._app_memory.setdefault(ak, [])

            full = ""
            async for chunk in self._get_llm().stream_response(
                user_text="(quiz mode just enabled — start the quiz now)",
                screenshots_b64=images_b64,
                history=history,
                system_prompt=system,
                model=self._current_model,
            ):
                if not self._turns.is_current(session):
                    return
                full += chunk
                self._emit_turn_signal(session, self.sig_response_chunk, chunk)
            self._emit_turn_signal(session, self.sig_response_done, full)
            self._turns.set_phase(session, TurnPhase.SPEAKING)
            self._emit_state(AppState.SPEAKING, session)
            try:
                await self._get_tts().speak(full)
            except Exception:
                pass
        except Exception as e:
            self._emit_turn_signal(
                session, self.sig_error, f"Quiz start failed: {e}"
            )
        finally:
            self._finish_turn(session)

    def set_privacy_guard(self, enabled: bool):
        self._privacy_guard = enabled

    @property
    def slow_mode(self) -> bool:  return self._slow_mode
    @property
    def quiz_mode(self) -> bool:  return self._quiz_mode
    @property
    def privacy_guard(self) -> bool:  return self._privacy_guard

    def clear_history(self):
        self._history = []
        self._app_memory.clear()
        self._lesson_steps = []
        self._lesson_step_idx = 0

    # ── Attached documents (drag-drop on panel) ──────────────────────────────

    def attach_document(self, path: str) -> bool:
        text = pdf_context.extract_text(path)
        if not text.strip():
            return False
        from pathlib import Path
        self._attached_docs.append((Path(path).name, text))
        # Cap context — most recent 3 docs
        self._attached_docs = self._attached_docs[-3:]
        return True

    def clear_attachments(self):
        self._attached_docs = []

    # ── Lesson recording ─────────────────────────────────────────────────────

    def start_recording(self) -> Optional[str]:
        if self._recorder is None:
            self._recorder = lesson_recorder.LessonRecorder(
                on_error=self.sig_error.emit
            )
        out = self._recorder.start()
        if out:
            self.sig_recording_state.emit(True, str(out))
            return str(out)
        return None

    def stop_recording(self) -> Optional[str]:
        if not self._recorder or not self._recorder.is_recording:
            return None
        out = self._recorder.stop()
        self.sig_recording_state.emit(False, str(out) if out else "")
        return str(out) if out else None

    @property
    def is_recording(self) -> bool:
        return bool(self._recorder and self._recorder.is_recording)

    # ── Workflow capture (record clicks/keystrokes) ──────────────────────────

    def workflow_start(self) -> bool:
        if self._workflow is None:
            self._workflow = workflow_capture.WorkflowCapture()
        return self._workflow.start()

    def workflow_stop(self) -> str:
        if not self._workflow:
            return ""
        events = self._workflow.stop()
        return self._workflow.summarise() if events else ""

    # ── Live collaboration ───────────────────────────────────────────────────

    def collab_start_host(self):
        """Live-session host. Disabled — see tutor_features/collab.py."""
        self.sig_error.emit(
            "Live Session: not available in this build. "
            "Requires a WebRTC signalling server (planned for a future release)."
        )

    def collab_join(self, code: str):
        """Live-session join. Disabled — see tutor_features/collab.py."""
        self.sig_error.emit(
            "Live Session: not available in this build. "
            "Requires a WebRTC signalling server (planned for a future release)."
        )

    # ── Voice picker (ElevenLabs / Edge) ─────────────────────────────────────

    def set_tts_voice(self, voice: str):
        try:
            tts = self._get_tts()
            if hasattr(tts, "set_voice"):
                tts.set_voice(voice)
        except Exception:
            pass

    # ── Toggle setters for the rest of the new features ──────────────────────

    def set_code_mode_auto(self, enabled: bool):
        self._code_mode_auto = enabled

    def set_multilang(self, enabled: bool):
        self._multilang = enabled

    def set_journal(self, enabled: bool):
        self._journal_enabled = bool(enabled)
        try:
            cfg.set_journal_enabled(self._journal_enabled)
        except Exception as exc:
            self.sig_error.emit(f"Could not save journal setting: {exc}")

    def set_ocr_enabled(self, enabled: bool):
        self._ocr_enabled = enabled

    # ── Stop / cancel ─────────────────────────────────────────────────────────

    def stop(self):
        """Cancel the current owned turn and all of its resources. Bound to Esc."""
        with self._input_lock:
            self._pressed_session = None
            self._turns.cancel_active(self._set_idle_state)
        # Clear any stored lesson so "stop" really means "back to zero"
        self._lesson_steps = []
        self._lesson_step_idx = 0
