"""Authenticated task worker, workspace, and process-boundary tests."""

from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from capability_registry import CapabilityGrant, CapabilityId
from tasks.coordinator import (
    TaskWorkerCoordinator,
    TaskWorkerError,
    TaskWorkerLimitError,
    TaskWorkspace,
    TaskWorkspaceError,
    _WindowsJob,
)
from tasks.models import TaskLimits, TaskRun, TaskSpec
import tasks.policy as task_policy
from tasks.policy import WorkerPolicy, worker_environment
from tasks.protocol import (
    PROTOCOL_KEY_BYTES,
    ProtocolError,
    ProtocolSession,
    WorkerBootstrap,
)


DIGEST = "a" * 64
ROOT = Path(__file__).resolve().parents[1]


def run_fixture(run_id: str = "task-worker-1") -> TaskRun:
    return TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.test",
            skill_version="1.0.0",
            goal="Exercise the trusted worker boundary.",
            input_digest=DIGEST,
            requested_result="A protocol acknowledgement.",
            verifier_step_id="verify",
            verifier_id="worker-boundary-v1",
            limits=TaskLimits(
                runtime_seconds=30,
                max_tool_calls=4,
                max_network_requests=0,
                max_output_bytes=1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset({CapabilityId.TASK_AGENT_RUN}),
        ),
    )


def policy(**overrides) -> WorkerPolicy:
    values = {
        "runtime_seconds": 30,
        "memory_bytes": 64 * 1024 * 1024,
        "protocol_output_bytes": 64 * 1024,
        "diagnostic_bytes": 16 * 1024,
        "workspace_bytes": 1024,
        "workspace_files": 8,
        "max_child_processes": 0,
    }
    values.update(overrides)
    return WorkerPolicy(**values)


class TaskProtocolTests(unittest.TestCase):
    def bootstrap(self, **overrides) -> WorkerBootstrap:
        values = {
            "key": b"k" * PROTOCOL_KEY_BYTES,
            "session_id": "1" * 32,
            "run_id": "task-worker-1",
            "max_frame_bytes": 4096,
            "max_messages": 8,
        }
        values.update(overrides)
        return WorkerBootstrap(**values)

    def sessions(self, **overrides):
        bootstrap = self.bootstrap(**overrides)
        host = ProtocolSession(
            bootstrap,
            send_direction="host_to_worker",
            receive_direction="worker_to_host",
        )
        worker = ProtocolSession(
            bootstrap,
            send_direction="worker_to_host",
            receive_direction="host_to_worker",
        )
        return host, worker

    def test_bootstrap_and_signed_directional_round_trip(self):
        bootstrap = self.bootstrap()
        decoded = WorkerBootstrap.read(io.BytesIO(bootstrap.encode()))
        self.assertEqual(decoded, bootstrap)
        host, worker = self.sessions()
        request = worker.decode(host.encode("ping", {"nonce": "one"}))
        self.assertEqual(request.message_type, "ping")
        response = host.decode(
            worker.encode("pong", {"nonce": request.payload["nonce"]})
        )
        self.assertEqual(response.payload, {"nonce": "one"})

    def test_tamper_replay_reflection_and_wrong_key_fail(self):
        host, worker = self.sessions()
        original = host.encode("ping", {"nonce": "one"})
        tampered = json.loads(original)
        tampered["payload"]["nonce"] = "changed"
        tampered_bytes = (
            json.dumps(
                tampered,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        with self.assertRaisesRegex(ProtocolError, "authentication"):
            worker.decode(tampered_bytes)

        host, worker = self.sessions()
        frame = host.encode("ping", {"nonce": "one"})
        worker.decode(frame)
        with self.assertRaisesRegex(ProtocolError, "sequence"):
            worker.decode(frame)

        host, _ = self.sessions()
        reflected = host.encode("ping", {"nonce": "one"})
        with self.assertRaisesRegex(ProtocolError, "identity"):
            host.decode(reflected)

        host, _ = self.sessions()
        _, wrong_worker = self.sessions(key=b"z" * PROTOCOL_KEY_BYTES)
        with self.assertRaisesRegex(ProtocolError, "authentication"):
            wrong_worker.decode(host.encode("ping", {"nonce": "one"}))

    def test_frames_payloads_and_message_counts_are_bounded(self):
        host, _ = self.sessions(max_messages=1)
        host.encode("ping", {"nonce": "one"})
        with self.assertRaisesRegex(ProtocolError, "message limit"):
            host.encode("ping", {"nonce": "two"})

        host, _ = self.sessions(max_frame_bytes=1024)
        with self.assertRaisesRegex(ProtocolError, "frame"):
            host.encode("ping", {"nonce": "x" * 900})

        host, _ = self.sessions()
        with self.assertRaisesRegex(ProtocolError, "floats"):
            host.encode("ping", {"nonce": 1.5})
        with self.assertRaisesRegex(ProtocolError, "key"):
            host.encode("ping", {"UPPER": "no"})


class TaskWorkerPolicyTests(unittest.TestCase):
    def test_policy_derives_every_resource_ceiling(self):
        task_limits = TaskLimits(
            runtime_seconds=120,
            max_tool_calls=8,
            max_network_requests=2,
            max_output_bytes=2 * 1024 * 1024,
        )
        derived = WorkerPolicy.from_task_limits(task_limits)
        self.assertEqual(derived.runtime_seconds, 120)
        self.assertEqual(derived.max_child_processes, 0)
        self.assertGreaterEqual(
            derived.workspace_bytes,
            task_limits.max_output_bytes,
        )
        self.assertLessEqual(
            derived.protocol_output_bytes,
            8 * 1024 * 1024,
        )

    def test_worker_environment_is_rebuilt_without_ambient_secrets(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {
                "SYSTEMROOT": r"C:\Windows",
                "PATH": r"C:\attacker",
                "OPENAI_API_KEY": "private-openai",
                "ANTHROPIC_API_KEY": "private-anthropic",
                "BAILIAN_CODING_PLAN_API_KEY": "private-qwen",
                "CODEX_HOME": r"C:\private-codex",
                "GOOGLE_TOKEN": "private-google",
                "USERPROFILE": r"C:\Users\Private",
            },
            clear=True,
        ), mock.patch.object(
            task_policy,
            "_windows_directory",
            return_value=r"C:\Windows",
        ):
            environment = worker_environment(Path(temporary).absolute())
        self.assertEqual(environment["SYSTEMROOT"], r"C:\Windows")
        self.assertEqual(environment["CLICKY_TASK_WORKER"], "1")
        self.assertEqual(environment["TEMP"], str(Path(temporary).absolute()))
        for forbidden in (
            "PATH",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "BAILIAN_CODING_PLAN_API_KEY",
            "CODEX_HOME",
            "GOOGLE_TOKEN",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "HOME",
        ):
            self.assertNotIn(forbidden, environment)

    def test_workspace_size_file_count_links_and_cleanup_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).absolute() / "task-root"
            workspace = TaskWorkspace.create(
                "task-worker-1",
                policy(workspace_bytes=8, workspace_files=2),
                root=root,
            )
            (workspace.path / "first.txt").write_bytes(b"1234")
            self.assertEqual(workspace.verify(), (1, 4))
            (workspace.path / "second.txt").write_bytes(b"56789")
            with self.assertRaisesRegex(TaskWorkerLimitError, "size"):
                workspace.verify()
            workspace.cleanup()
            self.assertFalse(workspace.path.exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).absolute() / "task-root"
            workspace = TaskWorkspace.create(
                "task-worker-2",
                policy(),
                root=root,
            )
            target = Path(temporary) / "outside.txt"
            target.write_text("outside", encoding="utf-8")
            link = workspace.path / "linked.txt"
            try:
                link.symlink_to(target)
            except OSError:
                workspace.cleanup()
                self.skipTest("symlinks are unavailable")
            with self.assertRaisesRegex(TaskWorkspaceError, "links"):
                workspace.verify()
            workspace.cleanup()
            self.assertEqual(target.read_text(encoding="utf-8"), "outside")

    def test_worker_source_exposes_no_tools_or_dynamic_execution(self):
        source = (ROOT / "tasks" / "worker.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            {
                "subprocess",
                "socket",
                "urllib",
                "requests",
                "httpx",
                "shutil",
                "ctypes",
            }.isdisjoint(imports)
        )
        direct_calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            {"eval", "exec", "compile", "__import__"}.isdisjoint(
                direct_calls
            )
        )

    def test_windows_job_source_declares_every_fail_closed_limit(self):
        source = (
            ROOT / "tasks" / "coordinator.py"
        ).read_text(encoding="utf-8")
        for required in (
            "_JOB_OBJECT_LIMIT_JOB_TIME",
            "_JOB_OBJECT_LIMIT_ACTIVE_PROCESS",
            "_JOB_OBJECT_LIMIT_PROCESS_MEMORY",
            "_JOB_OBJECT_LIMIT_JOB_MEMORY",
            "_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE",
            "CREATE_SUSPENDED",
            "workspace.verify()",
            "protocol_output_bytes",
            "diagnostic_bytes",
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)",
        ):
            self.assertIn(required, source)
        self.assertIn("not a complete sandbox", source)


class TaskWorkerCoordinatorTests(unittest.TestCase):
    def test_real_worker_handshake_ping_and_graceful_shutdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = run_fixture()
            run.start()
            root = Path(temporary).absolute() / "task-runs"
            handle = TaskWorkerCoordinator(
                workspace_root=root
            ).start(run)
            workspace = handle.workspace.path
            self.assertEqual(handle.ping("bounded-nonce"), "bounded-nonce")
            handle.shutdown()
            self.assertFalse(workspace.exists())
            self.assertIsNotNone(handle.process.returncode)

    def test_cancellation_rejects_late_results_and_removes_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = run_fixture("task-worker-cancel")
            run.start()
            handle = TaskWorkerCoordinator(
                workspace_root=(
                    Path(temporary).absolute() / "task-runs"
                )
            ).start(run)
            workspace = handle.workspace.path
            handle.cancel()
            self.assertFalse(workspace.exists())
            with self.assertRaisesRegex(TaskWorkerError, "rejects|not active"):
                handle.ping("late")

    def test_wall_time_limit_terminates_and_cleans_the_worker(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = run_fixture("task-worker-timeout")
            run.start()
            limited = policy(
                runtime_seconds=1,
                workspace_bytes=16 * 1024 * 1024,
                workspace_files=1024,
            )
            with mock.patch.object(
                WorkerPolicy,
                "from_task_limits",
                return_value=limited,
            ):
                handle = TaskWorkerCoordinator(
                    workspace_root=(
                        Path(temporary).absolute() / "task-runs"
                    )
                ).start(run)
            workspace = handle.workspace.path
            deadline = time.monotonic() + 5
            while workspace.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(workspace.exists())
            self.assertFalse(handle.active)
            with self.assertRaises(TaskWorkerError):
                handle.ping("late")

    def test_worker_is_not_exposed_by_the_hard_off_application_path(self):
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")
        before_entrypoint = main_source.split(
            'if __name__ == "__main__":',
            1,
        )[0]
        self.assertNotIn("TaskWorkerCoordinator", before_entrypoint)
        self.assertIn('sys.argv[1] == "--task-worker"', main_source)
        self.assertLess(
            main_source.index('sys.argv[1] == "--task-worker"'),
            main_source.index("from PyQt6.QtWidgets import QApplication"),
        )
        self.assertIn(
            "build_feature_available(ActionCapability.TASK_AGENT)",
            main_source,
        )


@unittest.skipUnless(os.name == "nt", "Windows Job Object test")
class WindowsTaskJobTests(unittest.TestCase):
    def test_job_termination_kills_the_complete_process_tree(self):
        helper = Path(__file__).with_name("task_job_tree_helper.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "spawn-now"
            child_pid_file = root / "child.pid"
            parent = subprocess.Popen(
                [
                    sys.executable,
                    str(helper),
                    "parent",
                    str(marker),
                    str(child_pid_file),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0x08000000,
                ),
                close_fds=True,
            )
            job = _WindowsJob(policy(max_child_processes=1))
            try:
                job.assign_existing(parent)
                marker.write_text("go", encoding="ascii")
                deadline = time.monotonic() + 10
                while (
                    not child_pid_file.exists()
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                self.assertTrue(child_pid_file.exists())
                child_pid = int(child_pid_file.read_text(encoding="ascii"))
                self.assertTrue(_windows_pid_running(child_pid))

                job.terminate()
                parent.wait(timeout=5)
                deadline = time.monotonic() + 5
                while (
                    _windows_pid_running(child_pid)
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                self.assertFalse(_windows_pid_running(child_pid))
            finally:
                try:
                    job.terminate()
                except Exception:
                    pass
                job.close()
                if parent.poll() is None:
                    parent.kill()
                parent.wait(timeout=5)


def _windows_pid_running(process_id: int) -> bool:
    if os.name != "nt":
        return False
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    open_process.restype = wintypes.HANDLE
    handle = open_process(0x00100000, False, process_id)
    if not handle:
        return False
    try:
        wait = kernel32.WaitForSingleObject
        wait.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        wait.restype = wintypes.DWORD
        return wait(handle, 0) == 0x00000102
    finally:
        kernel32.CloseHandle(handle)


if __name__ == "__main__":
    unittest.main()
