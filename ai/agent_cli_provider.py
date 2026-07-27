"""Bounded adapters for already-installed official coding-agent CLIs.

The adapters never install an executable, copy a cached login token, place
prompts on a command line, or inherit unrelated provider secrets. Each request
uses a fresh temporary working directory and terminates its owned process on
turn cancellation.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import AsyncIterator, List

from ai.base_provider import BaseLLMProvider, Message
from ai.model_selection import valid_model_id
from ai.provider_catalog import AGENT_PROVIDER_EXECUTABLES, provider_label
from config import cfg
from privacy_controls import coding_agent_allowed


MAX_AGENT_RUNTIME_SECONDS = 150
MAX_AGENT_LINE_BYTES = 1024 * 1024
MAX_AGENT_STDOUT_BYTES = 8 * 1024 * 1024
MAX_AGENT_STDERR_BYTES = 1024 * 1024
MAX_PROMPT_CHARS = 512 * 1024
MAX_HISTORY_MESSAGES = 20
MAX_SCREENSHOTS = 16
MAX_IMAGE_BYTES = 12 * 1024 * 1024
MAX_TOTAL_IMAGE_BYTES = 64 * 1024 * 1024
QWEN_CODING_PLAN_BASE_URL = "https://coding-intl.dashscope.aliyuncs.com/v1"


def executable_path(provider_id: str) -> str | None:
    executable = AGENT_PROVIDER_EXECUTABLES.get(provider_id)
    if executable is None:
        return None
    candidate = shutil.which(executable)
    if not candidate:
        return None
    try:
        path = Path(candidate).resolve(strict=True)
    except OSError:
        return None
    return str(path) if path.is_file() else None


def _bounded_prompt(
    user_text: str,
    history: List[Message],
    system_prompt: str,
) -> str:
    if not isinstance(user_text, str) or not isinstance(system_prompt, str):
        raise ValueError("Agent prompts must be text")
    sections = [
        system_prompt,
        (
            "\nCODING AGENT BOUNDARY: Answer only from the supplied prompt and "
            "attached images. Do not inspect unrelated local files, run shell "
            "commands, modify files, contact tools, or claim an action occurred."
        ),
        "\nCONVERSATION:",
    ]
    for message in history[-MAX_HISTORY_MESSAGES:]:
        if message.role not in {"user", "assistant"}:
            continue
        sections.append(f"\n{message.role.upper()}:\n{message.content}")
    sections.append(f"\nUSER:\n{user_text}")
    prompt = "".join(sections)
    if len(prompt) > MAX_PROMPT_CHARS:
        raise ValueError("Agent prompt exceeds Clicky's reviewed size limit")
    return prompt


def _write_images(directory: Path, screenshots_b64: List[str]) -> list[Path]:
    if len(screenshots_b64) > MAX_SCREENSHOTS:
        raise ValueError("Too many screenshots for one coding-agent request")
    paths = []
    total = 0
    for index, encoded in enumerate(screenshots_b64):
        if not isinstance(encoded, str):
            raise ValueError("Screenshot payload must be base64 text")
        try:
            image = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Screenshot payload is not valid base64") from exc
        if len(image) > MAX_IMAGE_BYTES:
            raise ValueError("Screenshot exceeds Clicky's reviewed size limit")
        total += len(image)
        if total > MAX_TOTAL_IMAGE_BYTES:
            raise ValueError("Combined screenshots exceed Clicky's reviewed size limit")
        path = directory / f"screen-{index + 1}.jpg"
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(image)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        paths.append(path)
    return paths


def _agent_environment(provider_id: str, model: str) -> dict[str, str]:
    allowed = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "HOME",
        "LANG",
        "LC_ALL",
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed
    }
    if provider_id == "codex_agent":
        for key in ("CODEX_HOME", "CODEX_ACCESS_TOKEN"):
            value = os.environ.get(key)
            if value:
                environment[key] = value
    elif provider_id == "qwen_code_agent":
        key = cfg.qwen_coding_plan_api_key
        if not key:
            raise RuntimeError(
                "Qwen Code requires BAILIAN_CODING_PLAN_API_KEY in Clicky's "
                "process environment."
            )
        environment.update({
            "BAILIAN_CODING_PLAN_API_KEY": key,
            "OPENAI_BASE_URL": QWEN_CODING_PLAN_BASE_URL,
            "OPENAI_MODEL": model,
            "QWEN_MODEL": model,
            "QWEN_CODE_SAFE_MODE": "true",
        })
    return environment


async def _drain_stderr(
    stream: asyncio.StreamReader,
    overflow: asyncio.Event,
) -> None:
    total = 0
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            return
        total += len(chunk)
        if total > MAX_AGENT_STDERR_BYTES:
            overflow.set()


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=3)
        return
    except asyncio.TimeoutError:
        pass
    try:
        process.kill()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=3)
    except asyncio.TimeoutError:
        return


def _codex_text(event: dict) -> str:
    if event.get("type") != "item.completed":
        return ""
    item = event.get("item")
    if not isinstance(item, dict) or item.get("type") != "agent_message":
        return ""
    text = item.get("text")
    return text if isinstance(text, str) else ""


def _qwen_delta(event: dict) -> str:
    nested = event.get("event")
    if not isinstance(nested, dict):
        nested = event
    if nested.get("type") != "content_block_delta":
        return ""
    delta = nested.get("delta")
    if not isinstance(delta, dict):
        return ""
    text = delta.get("text")
    return text if isinstance(text, str) else ""


def _qwen_final(event: dict) -> str:
    if event.get("type") != "result" or event.get("subtype") != "success":
        return ""
    result = event.get("result")
    return result if isinstance(result, str) else ""


class AgentCLIProvider(BaseLLMProvider):
    def __init__(self, provider_id: str):
        if provider_id not in AGENT_PROVIDER_EXECUTABLES:
            raise ValueError("Unknown coding-agent provider")
        if not coding_agent_allowed(cfg):
            raise PermissionError(
                "Coding-agent execution is disabled in Privacy permissions."
            )
        executable = executable_path(provider_id)
        if executable is None:
            raise RuntimeError(
                f"{provider_label(provider_id)} is not installed on PATH. "
                "Clicky will not install or start an installer for it."
            )
        self._provider_id = provider_id
        self._executable = executable

    def _command(
        self,
        directory: Path,
        image_paths: list[Path],
        model: str,
    ) -> list[str]:
        if self._provider_id == "codex_agent":
            command = [
                self._executable,
                "exec",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "--color",
                "never",
                "--json",
                "-C",
                str(directory),
            ]
            if model != "codex-default":
                command.extend(("--model", model))
            for image_path in image_paths:
                command.extend(("--image", str(image_path)))
            command.append("-")
            return command
        return [
            self._executable,
            "--output-format",
            "stream-json",
            "--include-partial-messages",
            "--input-format",
            "text",
            "--safe-mode",
            "--approval-mode",
            "plan",
            "--max-session-turns",
            "4",
            "--max-tool-calls",
            "1",
            "--max-wall-time",
            "120s",
            "--exclude-tools",
            "agent,shell,write,edit",
            "--model",
            model,
        ]

    async def stream_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncIterator[str]:
        if not model or not valid_model_id(model):
            raise ValueError("Select a validated coding-agent model first")
        if self._provider_id == "codex_agent" and model != "codex-default":
            raise ValueError("Unsupported Codex agent model selection")
        prompt = _bounded_prompt(user_text, history, system_prompt)
        process = None
        stderr_task = None
        with tempfile.TemporaryDirectory(prefix="clicky-agent-") as temporary:
            directory = Path(temporary)
            try:
                directory.chmod(0o700)
            except OSError:
                pass
            image_paths = _write_images(directory, screenshots_b64)
            if self._provider_id == "qwen_code_agent" and image_paths:
                references = "\n".join(f"@{{{path}}}" for path in image_paths)
                prompt += (
                    "\n\nSCREEN IMAGES supplied by the user for this turn:\n"
                    f"{references}"
                )
            command = self._command(directory, image_paths, model)
            kwargs = {}
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=directory,
                    env=_agent_environment(self._provider_id, model),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    limit=MAX_AGENT_LINE_BYTES + 1,
                    **kwargs,
                )
                assert process.stdin and process.stdout and process.stderr
                process.stdin.write(prompt.encode("utf-8"))
                await process.stdin.drain()
                process.stdin.close()
                overflow = asyncio.Event()
                stderr_task = asyncio.create_task(
                    _drain_stderr(process.stderr, overflow)
                )
                total_stdout = 0
                yielded = False
                async with asyncio.timeout(MAX_AGENT_RUNTIME_SECONDS):
                    while True:
                        if overflow.is_set():
                            raise RuntimeError(
                                "Coding agent exceeded its diagnostic-output limit"
                            )
                        try:
                            line = await asyncio.wait_for(
                                process.stdout.readline(),
                                timeout=0.5,
                            )
                        except asyncio.TimeoutError:
                            if process.returncode is not None:
                                break
                            continue
                        if not line:
                            break
                        total_stdout += len(line)
                        if total_stdout > MAX_AGENT_STDOUT_BYTES:
                            raise RuntimeError(
                                "Coding agent exceeded its response-output limit"
                            )
                        try:
                            event = json.loads(line)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            continue
                        if not isinstance(event, dict):
                            continue
                        if self._provider_id == "codex_agent":
                            text = _codex_text(event)
                        else:
                            text = _qwen_delta(event)
                            if not text and not yielded:
                                text = _qwen_final(event)
                        if text:
                            yielded = True
                            yield text
                    return_code = await asyncio.wait_for(
                        process.wait(),
                        timeout=5,
                    )
                    await stderr_task
                if overflow.is_set():
                    raise RuntimeError(
                        "Coding agent exceeded its diagnostic-output limit"
                    )
                if return_code != 0:
                    raise RuntimeError(
                        f"{provider_label(self._provider_id)} exited with "
                        f"status {return_code}; run its login/doctor command "
                        "manually. Clicky did not expose its diagnostic output."
                    )
                if not yielded:
                    raise RuntimeError(
                        f"{provider_label(self._provider_id)} returned no "
                        "assistant message."
                    )
            except asyncio.CancelledError:
                if process is not None:
                    await _terminate(process)
                raise
            except TimeoutError as exc:
                if process is not None:
                    await _terminate(process)
                raise TimeoutError("Coding agent exceeded its runtime limit") from exc
            except Exception:
                if process is not None:
                    await _terminate(process)
                raise
            finally:
                if stderr_task is not None:
                    if not stderr_task.done():
                        stderr_task.cancel()
                    with contextlib.suppress(
                        asyncio.CancelledError,
                        Exception,
                    ):
                        await stderr_task

    async def health_check(self) -> bool:
        return executable_path(self._provider_id) is not None
