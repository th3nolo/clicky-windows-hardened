from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from automation.action_models import (
    DesktopActionEvidence,
    DesktopActionReceipt,
    DesktopActionRequest,
    DesktopActionStatus,
    ScrollAmount,
)
from automation.action_process import (
    UiaWorkerError,
    UiaWorkerTimeout,
    WindowsUiaWorkerHandle,
    WindowsUiaWorkerLauncher,
    _WindowsActionJob,
    _worker_command,
    _worker_environment,
)
from automation import uia_actions, uia_worker
from automation.action_protocol import (
    MAX_WORKER_FRAME_BYTES,
    UiaWorkerCommand,
    decode_worker_command,
    decode_worker_receipt,
    encode_worker_command,
    encode_worker_receipt,
)
from automation.models import (
    AutomationPattern,
    DesktopActionKind,
    DesktopBounds,
    DesktopTarget,
)


APP_DIGEST = hashlib.sha256(b"app").hexdigest()


def target() -> DesktopTarget:
    return DesktopTarget(
        process_id=42,
        process_start_time_ns=123,
        application_name="Editor",
        application_identity=APP_DIGEST,
        top_level_hwnd=100,
        foreground_hwnd=100,
        runtime_id=(42, 1),
        control_type="EditControl",
        framework_id="Win32",
        automation_id="editor",
        control_name="Editor",
        bounds=DesktopBounds(1, 2, 300, 40),
        supported_patterns=frozenset({AutomationPattern.VALUE}),
        enabled=True,
        offscreen=False,
        control_element=True,
        password=False,
        protected=False,
        clicky_process_id=99,
        clicky_integrity=0x2000,
        target_integrity=0x2000,
        desktop_name="Default",
    )


def request(value: str = "private exact value") -> DesktopActionRequest:
    current = target()
    return DesktopActionRequest(
        run_id="desktop-run",
        call_id="call-set-value",
        review_id="a" * 64,
        target_identity_digest=current.identity_digest,
        target_review_digest=current.review_digest,
        action=DesktopActionKind.SET_VALUE,
        value=value,
    )


def receipt() -> DesktopActionReceipt:
    return DesktopActionReceipt(
        status=DesktopActionStatus.VERIFIED_SUCCEEDED,
        result_code="uia_postcondition_verified",
        action_started=True,
        target_identity_digest=target().identity_digest,
        evidence=DesktopActionEvidence(
            "value.sha256",
            "b" * 64,
            "c" * 64,
        ),
    )


class DesktopActionProtocolTests(unittest.TestCase):
    def test_action_schema_rejects_irrelevant_or_ambiguous_arguments(self):
        current = target()
        common = {
            "run_id": "desktop-run",
            "call_id": "call-invalid",
            "review_id": "a" * 64,
            "target_identity_digest": current.identity_digest,
            "target_review_digest": current.review_digest,
        }
        cases = (
            {
                **common,
                "action": DesktopActionKind.FOCUS,
                "value": "irrelevant",
            },
            {
                **common,
                "action": DesktopActionKind.INVOKE,
            },
            {
                **common,
                "action": DesktopActionKind.SCROLL,
                "horizontal_scroll": ScrollAmount.NO_AMOUNT,
                "vertical_scroll": ScrollAmount.NO_AMOUNT,
            },
            {
                **common,
                "action": DesktopActionKind.SET_VALUE,
                "value": "multiple\nlines",
            },
            {
                **common,
                "action": DesktopActionKind.SET_VALUE,
                "value": "enter the private key here",
            },
        )
        for values in cases:
            with self.subTest(action=values["action"]):
                with self.assertRaises(ValueError):
                    DesktopActionRequest(**values)

    def test_receipt_schema_rejects_contradictory_outcomes(self):
        common = {
            "result_code": "synthetic",
            "target_identity_digest": target().identity_digest,
        }
        with self.assertRaises(ValueError):
            DesktopActionReceipt(
                status=DesktopActionStatus.VERIFIED_SUCCEEDED,
                action_started=False,
                **common,
            )
        with self.assertRaises(ValueError):
            DesktopActionReceipt(
                status=DesktopActionStatus.FAILED_VERIFICATION,
                action_started=True,
                **common,
            )
        with self.assertRaises(ValueError):
            DesktopActionReceipt(
                status=DesktopActionStatus.OUTCOME_UNKNOWN,
                action_started=False,
                **common,
            )

    def test_command_and_authenticated_receipt_round_trip(self):
        key = b"k" * 32
        nonce = "d" * 64
        command = UiaWorkerCommand(nonce, key, target(), request())
        decoded = decode_worker_command(encode_worker_command(command))
        self.assertEqual(decoded, command)

        response = encode_worker_receipt(
            nonce=nonce,
            authentication_key=key,
            receipt=receipt(),
        )
        self.assertEqual(
            decode_worker_receipt(
                response,
                nonce=nonce,
                authentication_key=key,
            ),
            receipt(),
        )

    def test_receipt_rejects_tamper_wrong_nonce_and_wrong_key(self):
        key = b"k" * 32
        nonce = "d" * 64
        response = encode_worker_receipt(
            nonce=nonce,
            authentication_key=key,
            receipt=receipt(),
        )
        payload = json.loads(response)
        payload["receipt"]["result_code"] = "forged_success"
        tampered = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
        )
        for candidate_nonce, candidate_key, frame in (
            (nonce, key, tampered),
            ("e" * 64, key, response),
            (nonce, b"x" * 32, response),
        ):
            with self.subTest(nonce=candidate_nonce, key=candidate_key[:1]):
                with self.assertRaises(ValueError):
                    decode_worker_receipt(
                        frame,
                        nonce=candidate_nonce,
                        authentication_key=candidate_key,
                    )

    def test_protocol_rejects_duplicate_keys_multiple_frames_and_oversize(self):
        with self.assertRaises(ValueError):
            decode_worker_command(
                b'{"nonce":"a","nonce":"b"}\n'
            )
        with self.assertRaises(ValueError):
            decode_worker_command(b"{}\n{}\n")
        with self.assertRaises(ValueError):
            decode_worker_command(b"x" * MAX_WORKER_FRAME_BYTES + b"\n")

    def test_sensitive_value_and_key_are_hidden_from_reprs(self):
        raw = "private exact value"
        key = b"k" * 32
        command = UiaWorkerCommand("d" * 64, key, target(), request(raw))
        self.assertNotIn(raw, repr(command))
        self.assertNotIn(raw, repr(command.request))
        self.assertNotIn(key.hex(), repr(command))

    def test_worker_environment_has_no_ambient_secrets_or_network_config(self):
        source_environment = {
            "SYSTEMROOT": "C:\\Windows",
            "TEMP": "C:\\Temp",
            "TMP": "C:\\Temp",
            "PATH": "secret-path",
            "PYTHONPATH": "secret-python",
            "HTTP_PROXY": "http://proxy",
            "API_KEY": "secret",
        }
        with mock.patch.dict(os.environ, source_environment, clear=True):
            with mock.patch(
                "automation.action_process.Path.is_absolute",
                return_value=True,
            ):
                environment = _worker_environment()
        self.assertEqual(
            set(environment),
            {
                "CLICKY_DESKTOP_UIA_WORKER",
                "SYSTEMROOT",
                "WINDIR",
                "TEMP",
                "TMP",
            },
        )
        self.assertNotIn("PATH", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("API_KEY", environment)

    def test_job_boundary_is_single_process_and_intentionally_allows_uia(self):
        source = inspect.getsource(_WindowsActionJob)
        launcher_source = inspect.getsource(WindowsUiaWorkerLauncher)
        self.assertIn("_JOB_OBJECT_LIMIT_ACTIVE_PROCESS", source)
        self.assertIn("ActiveProcessLimit = 1", source)
        self.assertIn("_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", source)
        self.assertNotIn("JOB_OBJECT_UILIMIT", source)
        self.assertIn("shell=False", launcher_source)

    def test_worker_route_precedes_qt_and_is_packaged(self):
        root = Path(__file__).resolve().parents[1]
        main_source = (root / "main.py").read_text(encoding="utf-8")
        spec_source = (root / "clicky.spec").read_text(encoding="utf-8")
        self.assertLess(
            main_source.index("--desktop-uia-worker"),
            main_source.index("from PyQt6"),
        )
        self.assertIn('"automation.uia_worker"', spec_source)
        self.assertIn('"automation.uia_actions"', spec_source)

    def test_source_worker_uses_base_runtime_and_isolated_exact_paths(self):
        command = _worker_command()
        self.assertEqual(
            command[0],
            str(
                Path(
                    getattr(sys, "_base_executable", sys.executable)
                ).resolve(strict=True)
            ),
        )
        self.assertEqual(command[1:4], ["-I", "-B", "-c"])
        self.assertEqual(len(command), 7)
        self.assertEqual(
            Path(command[5]),
            Path(__file__).resolve().parents[1],
        )
        self.assertTrue(Path(command[6]).is_dir())

    def test_executor_has_no_raw_input_coordinate_or_retry_fallback(self):
        source = inspect.getsource(uia_actions).casefold()
        worker_source = inspect.getsource(uia_worker).casefold()
        for forbidden in (
            "sendinput",
            "mouse_event",
            "keybd_event",
            "setcursorpos",
            "pyautogui",
            "clipboard",
            "sleep(",
            "retry",
        ):
            self.assertNotIn(forbidden, source)
        for forbidden in (
            "logging",
            "requests",
            "httpx",
            "socket",
            "subprocess",
        ):
            self.assertNotIn(forbidden, worker_source)

    def test_worker_handle_exchanges_once_and_closes_job(self):
        boundary = _FakeBoundary()
        process = _FakeProcess(stdout=b"{}\n")
        handle = WindowsUiaWorkerHandle(
            process,
            boundary,
            timeout_seconds=1.0,
        )
        self.assertEqual(handle.exchange(b'{"request":1}\n'), b"{}\n")
        self.assertTrue(handle.request_sent)
        self.assertEqual(process.wait_calls, 1)
        with self.assertRaisesRegex(UiaWorkerError, "not available"):
            handle.exchange(b'{"request":1}\n')
        handle.close()
        self.assertEqual(boundary.closed, 1)

    def test_worker_timeout_terminates_job_and_stays_post_send(self):
        boundary = _FakeBoundary()
        process = _FakeProcess(stdout=b"", timeout_once=True)
        handle = WindowsUiaWorkerHandle(
            process,
            boundary,
            timeout_seconds=1.0,
        )
        with self.assertRaises(UiaWorkerTimeout):
            handle.exchange(b'{"request":1}\n')
        self.assertTrue(handle.request_sent)
        self.assertEqual(boundary.terminated, 1)
        handle.close()


class _RecordingInput(io.BytesIO):
    def close(self) -> None:
        self.closed_by_host = True


class _FakeProcess:
    def __init__(
        self,
        *,
        stdout: bytes,
        stderr: bytes = b"",
        timeout_once: bool = False,
    ) -> None:
        self.stdin = _RecordingInput()
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.timeout_once = timeout_once
        self.wait_calls = 0

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.timeout_once:
            self.timeout_once = False
            raise subprocess.TimeoutExpired("synthetic", timeout)
        return 0


class _FakeBoundary:
    def __init__(self) -> None:
        self.terminated = 0
        self.closed = 0

    def terminate(self) -> None:
        self.terminated += 1

    def close(self) -> None:
        self.closed += 1


if __name__ == "__main__":
    unittest.main()
