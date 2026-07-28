"""Adversarial source tests for isolated workspace staging and verification."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from capability_registry import CapabilityGrant, CapabilityId
from tasks.models import (
    ApprovalRequest,
    TaskLimits,
    TaskRun,
    TaskSpec,
    ToolCall,
)
from workspace_coding.broker import WorkspaceBroker, WorkspaceBrokerError
from workspace_coding.models import (
    CommandProfile,
    GitWorkspaceIdentity,
    VerificationReceipt,
    WorkspaceCommandRequest,
    WorkspaceDeleteRequest,
    WorkspaceMkdirRequest,
    WorkspaceReadRequest,
    WorkspaceWriteRequest,
    workspace_action_digest,
)
from workspace_coding.paths import (
    WorkspacePathError,
    denied_workspace_path,
    validate_relative_workspace_path,
)
from workspace_coding.sandbox import (
    SANDBOX_LOGON_COMMAND,
    SandboxConfigurationError,
    generate_sandbox_configuration,
    verify_isolated_result,
)
from workspace_coding.snapshot import (
    WorkspaceSnapshot,
    WorkspaceSnapshotError,
    create_isolated_snapshot,
    inspect_selected_git_workspace,
    scan_workspace,
)


def _identity(
    root: Path | None = None,
    *,
    dirty: bool = True,
) -> GitWorkspaceIdentity:
    final_path_sha256 = (
        hashlib.sha256(
            os.path.normcase(str(root.resolve(strict=True))).encode("utf-8")
        ).hexdigest()
        if root is not None
        else "1" * 64
    )
    return GitWorkspaceIdentity(
        repository_id="repo.synthetic",
        final_path_sha256=final_path_sha256,
        head_commit="2" * 40,
        branch="feature/synthetic",
        status_sha256="3" * 64,
        git_executable_sha256="4" * 64,
        dirty=dirty,
    )


def _run(run_id: str = "run.workspace-1") -> TaskRun:
    run = TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.workspace_coding",
            skill_version="1.0.0",
            goal="Modify one isolated synthetic workspace.",
            input_digest="5" * 64,
            requested_result="Reviewable isolated changes.",
            verifier_step_id="verify",
            verifier_id="workspace-result-v1",
            limits=TaskLimits(
                runtime_seconds=900,
                max_tool_calls=16,
                max_network_requests=0,
                max_output_bytes=16 * 1024 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.WORKSPACE_READ,
                    CapabilityId.WORKSPACE_WRITE,
                    CapabilityId.WORKSPACE_COMMAND,
                }
            ),
        ),
    )
    run.start()
    return run


def _call(
    run: TaskRun,
    *,
    call_id: str,
    tool_name: str,
    capability: CapabilityId,
    arguments_digest: str,
) -> ToolCall:
    action_digest = None
    if capability in {
        CapabilityId.WORKSPACE_WRITE,
        CapabilityId.WORKSPACE_COMMAND,
    }:
        action_digest = workspace_action_digest(
            run_id=run.run_id,
            call_id=call_id,
            capability=capability,
            arguments_digest=arguments_digest,
        )
    return ToolCall(
        call_id=call_id,
        run_id=run.run_id,
        step_id=call_id.replace(".", "-"),
        tool_name=tool_name,
        capability=capability,
        arguments_digest=arguments_digest,
        action_digest=action_digest,
    )


def _approve(run: TaskRun, call: ToolCall) -> None:
    assert call.action_digest is not None
    request = ApprovalRequest(
        approval_id="approval-" + call.call_id,
        run_id=run.run_id,
        call_id=call.call_id,
        capability=call.capability,
        action_digest=call.action_digest,
        reason="Approve this exact isolated synthetic operation.",
        preview_digests=("6" * 64,),
        expires_at=100.0,
    )
    run.request_approval(call, request, now=1.0)
    run.approve(
        request.approval_id,
        request.action_digest,
        now=2.0,
    )


class WorkspacePathPolicyTests(unittest.TestCase):
    def test_accepts_only_canonical_relative_windows_paths(self):
        self.assertEqual(
            validate_relative_workspace_path("src/module/file.py"),
            "src/module/file.py",
        )
        invalid = (
            "",
            "/rooted",
            "C:/drive",
            r"src\file.py",
            "src/../file.py",
            "src/./file.py",
            "src/file.py:stream",
            "src/CON.txt",
            "src/trailing.",
            "src/trailing ",
            "//server/share",
            "src/\x00name",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(WorkspacePathError):
                    validate_relative_workspace_path(value)

    def test_secret_and_git_paths_are_denied_without_content(self):
        expected = {
            ".git/config": "git_metadata",
            "config/.env": "credential_path",
            "config/.env.example": "credential_path",
            "keys/id_ed25519": "credential_path",
            "keys/signing.pfx": "credential_path",
            "packages/.npmrc": "credential_path",
        }
        for path, category in expected.items():
            with self.subTest(path=path):
                self.assertEqual(denied_workspace_path(path), category)
        self.assertIsNone(denied_workspace_path("src/config.py"))


class WorkspaceSelectionTests(unittest.TestCase):
    def test_git_identity_uses_reviewed_binary_and_hardened_read_only_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).absolute()
            (root / ".git").mkdir()
            git = root / "reviewed-git.exe"
            git.write_bytes(b"reviewed synthetic git")
            expected_git_sha = hashlib.sha256(git.read_bytes()).hexdigest()
            calls = []

            def runner(command, cwd, environment):
                calls.append((command, cwd, environment))
                joined = " ".join(command)
                if "config --local --get core.hooksPath" in joined:
                    return 0, b"NUL\n", b""
                if "rev-parse --absolute-git-dir" in joined:
                    return 0, str(root / ".git").encode() + b"\n", b""
                if "for-each-ref" in joined:
                    return 0, b"", b""
                if "rev-parse --verify HEAD^{commit}" in joined:
                    return 0, b"a" * 40 + b"\n", b""
                if "symbolic-ref" in joined:
                    return 0, b"feature/synthetic\n", b""
                if "status --porcelain=v2" in joined:
                    return 0, b"# branch.head feature/synthetic\n? new.py\n", b""
                if "rev-parse --show-toplevel" in joined:
                    return 0, str(root).encode() + b"\n", b""
                raise AssertionError(f"unexpected Git call: {joined}")

            identity = inspect_selected_git_workspace(
                root,
                git_executable=git,
                expected_git_sha256=expected_git_sha,
                _runner=runner,
                _require_windows_volume=False,
            )
            expected_root = root.resolve(strict=True)

        self.assertTrue(identity.dirty)
        self.assertEqual(identity.branch, "feature/synthetic")
        self.assertEqual(identity.head_commit, "a" * 40)
        self.assertGreaterEqual(len(calls), 7)
        for command, cwd, environment in calls:
            self.assertEqual(cwd, expected_root)
            self.assertIn("--no-replace-objects", command)
            self.assertIn("core.hooksPath=NUL", command)
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "NUL")
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertNotIn("PATH", environment)
            self.assertNotIn("CODEX_HOME", environment)

    def test_wrong_git_identity_fails_before_first_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).absolute()
            (root / ".git").mkdir()
            git = root / "git.exe"
            git.write_bytes(b"wrong")
            calls = []

            with self.assertRaisesRegex(
                WorkspaceSnapshotError,
                "reviewed identity",
            ):
                inspect_selected_git_workspace(
                    root,
                    git_executable=git,
                    expected_git_sha256="0" * 64,
                    _runner=lambda *args: calls.append(args),
                    _require_windows_volume=False,
                )
        self.assertEqual(calls, [])


class WorkspaceSnapshotTests(unittest.TestCase):
    def test_dirty_and_untracked_bytes_are_copied_without_git_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).absolute()
            source = base / "selected"
            source.mkdir()
            (source / ".git").mkdir()
            (source / ".git" / "config").write_text(
                "remote secret metadata",
                encoding="utf-8",
            )
            (source / "tracked.py").write_text(
                "dirty user change\n",
                encoding="utf-8",
            )
            (source / "new.txt").write_text(
                "untracked user file\n",
                encoding="utf-8",
            )
            (source / "empty").mkdir()
            tasks = base / "tasks"
            revalidations = []

            def revalidate(path):
                revalidations.append(path)
                return _identity(path)

            snapshot = create_isolated_snapshot(
                source,
                tasks,
                run_id="run.workspace-1",
                identity=_identity(source),
                revalidate_identity=revalidate,
            )

            self.assertEqual(
                (snapshot.workspace_root / "tracked.py").read_text(),
                "dirty user change\n",
            )
            self.assertEqual(
                (snapshot.workspace_root / "new.txt").read_text(),
                "untracked user file\n",
            )
            self.assertTrue((snapshot.workspace_root / "empty").is_dir())
            self.assertFalse((snapshot.workspace_root / ".git").exists())
            self.assertTrue(snapshot.identity.dirty)
            self.assertEqual(len(snapshot.baseline_manifest.files), 2)
            self.assertEqual(
                revalidations,
                [
                    source.resolve(strict=True),
                    source.resolve(strict=True),
                ],
            )

    def test_changed_git_identity_cleans_the_incomplete_staging_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).absolute()
            source = base / "selected"
            source.mkdir()
            (source / ".git").mkdir()
            (source / "source.py").write_text("source", encoding="utf-8")
            tasks = base / "tasks"
            original = _identity(source)
            calls = []

            def revalidate(path):
                calls.append(path)
                if len(calls) == 1:
                    return original
                return GitWorkspaceIdentity(
                    repository_id=original.repository_id,
                    final_path_sha256=original.final_path_sha256,
                    head_commit="f" * 40,
                    branch=original.branch,
                    status_sha256=original.status_sha256,
                    git_executable_sha256=(
                        original.git_executable_sha256
                    ),
                    dirty=original.dirty,
                )

            with self.assertRaisesRegex(
                WorkspaceSnapshotError,
                "Git identity changed",
            ):
                create_isolated_snapshot(
                    source,
                    tasks,
                    run_id="run.workspace-race",
                    identity=original,
                    revalidate_identity=revalidate,
                )

            self.assertEqual(len(calls), 2)
            self.assertEqual(list(tasks.iterdir()), [])

    def test_secret_link_hardlink_nested_git_and_overlap_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).absolute()
            source = base / "selected"
            source.mkdir()
            (source / ".git").mkdir()
            tasks = base / "tasks"
            (source / ".env").write_text("SECRET=value", encoding="utf-8")
            with self.assertRaisesRegex(
                WorkspaceSnapshotError,
                "denied credential_path",
            ):
                create_isolated_snapshot(
                    source,
                    tasks,
                    run_id="run.workspace-secret",
                    identity=_identity(source),
                    revalidate_identity=lambda path: _identity(path),
                )
            (source / ".env").unlink()
            nested = source / "nested"
            nested.mkdir()
            (nested / ".git").mkdir()
            with self.assertRaisesRegex(
                WorkspaceSnapshotError,
                "denied git_metadata",
            ):
                create_isolated_snapshot(
                    source,
                    tasks,
                    run_id="run.workspace-nested",
                    identity=_identity(source),
                    revalidate_identity=lambda path: _identity(path),
                )
            (nested / ".git").rmdir()
            linked = source / "linked.txt"
            target = source / "target.txt"
            target.write_text("target", encoding="utf-8")
            try:
                linked.symlink_to(target)
            except OSError:
                self.skipTest("Symbolic links are unavailable")
            with self.assertRaisesRegex(
                WorkspaceSnapshotError,
                "links and reparse",
            ):
                create_isolated_snapshot(
                    source,
                    tasks,
                    run_id="run.workspace-link",
                    identity=_identity(source),
                    revalidate_identity=lambda path: _identity(path),
                )
            linked.unlink()
            hard = source / "hard.txt"
            try:
                os.link(target, hard)
            except OSError:
                self.skipTest("Hard links are unavailable")
            with self.assertRaisesRegex(
                WorkspacePathError,
                "unlinked regular",
            ):
                create_isolated_snapshot(
                    source,
                    tasks,
                    run_id="run.workspace-hard",
                    identity=_identity(source),
                    revalidate_identity=lambda path: _identity(path),
                )
            hard.unlink()
            with self.assertRaisesRegex(
                WorkspaceSnapshotError,
                "cannot overlap",
            ):
                create_isolated_snapshot(
                    source,
                    source / "task-output",
                    run_id="run.workspace-overlap",
                    identity=_identity(source),
                    revalidate_identity=lambda path: _identity(path),
                )
            self.assertFalse((source / "task-output").exists())


class SandboxConfigurationTests(unittest.TestCase):
    def test_exact_two_mapping_configuration_disables_host_channels(self):
        configuration = generate_sandbox_configuration(
            input_host_path=r"C:\ClickyTasks\run-1\input",
            task_host_path=r"C:\ClickyTasks\run-1\task",
        )
        root = ET.fromstring(configuration.xml_bytes)

        self.assertEqual(root.findtext("Networking"), "Disable")
        self.assertEqual(root.findtext("vGPU"), "Disable")
        self.assertEqual(root.findtext("AudioInput"), "Disable")
        self.assertEqual(root.findtext("VideoInput"), "Disable")
        self.assertEqual(root.findtext("PrinterRedirection"), "Disable")
        self.assertEqual(root.findtext("ClipboardRedirection"), "Disable")
        self.assertEqual(root.findtext("ProtectedClient"), "Enable")
        mappings = root.findall("./MappedFolders/MappedFolder")
        self.assertEqual(len(mappings), 2)
        self.assertEqual(mappings[0].findtext("ReadOnly"), "true")
        self.assertEqual(mappings[1].findtext("ReadOnly"), "false")
        self.assertEqual(
            root.findtext("./LogonCommand/Command"),
            SANDBOX_LOGON_COMMAND,
        )
        xml_text = configuration.xml_bytes.decode("utf-8")
        self.assertNotIn("Default", xml_text)
        self.assertNotIn("USERPROFILE", xml_text)

    def test_noncanonical_or_overlapping_mappings_fail(self):
        cases = (
            (r"\\server\input", r"C:\task"),
            (r"C:\root\..\input", r"C:\task"),
            (r"C:\root", r"C:\root\task"),
            ("relative", r"C:\task"),
        )
        for input_path, task_path in cases:
            with self.subTest(input_path=input_path, task_path=task_path):
                with self.assertRaises(SandboxConfigurationError):
                    generate_sandbox_configuration(
                        input_host_path=input_path,
                        task_host_path=task_path,
                    )


class WorkspaceBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "source.py").write_bytes(b"before\n")
        self.run = _run()
        self.baseline, _ = scan_workspace(
            self.workspace,
            run_id=self.run.run_id,
            repository_identity_digest=_identity().identity_digest,
        )

    def _broker(self, **kwargs) -> WorkspaceBroker:
        return WorkspaceBroker(
            self.run,
            self.workspace,
            self.baseline,
            **kwargs,
        )

    def test_read_requires_exact_run_grant_path_and_digest(self):
        request = WorkspaceReadRequest(
            relative_path="source.py",
            expected_sha256=hashlib.sha256(b"before\n").hexdigest(),
        )
        call = _call(
            self.run,
            call_id="read.1",
            tool_name="workspace.read",
            capability=CapabilityId.WORKSPACE_READ,
            arguments_digest=request.arguments_digest,
        )
        broker = self._broker()

        self.assertEqual(broker.read(call, request), b"before\n")
        with self.assertRaisesRegex(
            WorkspaceBrokerError,
            "not_authorized",
        ):
            broker.read(call, request)

    def test_write_mkdir_delete_require_one_use_exact_approval(self):
        broker = self._broker()
        mkdir = WorkspaceMkdirRequest(relative_path="new")
        mkdir_call = _call(
            self.run,
            call_id="mkdir.1",
            tool_name="workspace.mkdir",
            capability=CapabilityId.WORKSPACE_WRITE,
            arguments_digest=mkdir.arguments_digest,
        )
        with self.assertRaisesRegex(
            WorkspaceBrokerError,
            "not_authorized",
        ):
            broker.mkdir(mkdir_call, mkdir)
        _approve(self.run, mkdir_call)
        broker.mkdir(mkdir_call, mkdir)

        write = WorkspaceWriteRequest(
            relative_path="new/result.py",
            content=b"created\n",
            expected_prior_sha256=None,
        )
        write_call = _call(
            self.run,
            call_id="write.1",
            tool_name="workspace.write",
            capability=CapabilityId.WORKSPACE_WRITE,
            arguments_digest=write.arguments_digest,
        )
        _approve(self.run, write_call)
        record = broker.write(write_call, write)
        self.assertEqual(record.sha256, write.content_sha256)

        replace = WorkspaceWriteRequest(
            relative_path="source.py",
            content=b"after\n",
            expected_prior_sha256=hashlib.sha256(b"before\n").hexdigest(),
        )
        replace_call = _call(
            self.run,
            call_id="write.2",
            tool_name="workspace.write",
            capability=CapabilityId.WORKSPACE_WRITE,
            arguments_digest=replace.arguments_digest,
        )
        _approve(self.run, replace_call)
        broker.write(replace_call, replace)
        self.assertEqual(
            (self.workspace / "source.py").read_bytes(),
            b"after\n",
        )

        delete = WorkspaceDeleteRequest(
            relative_path="new/result.py",
            expected_sha256=write.content_sha256,
        )
        delete_call = _call(
            self.run,
            call_id="delete.1",
            tool_name="workspace.delete",
            capability=CapabilityId.WORKSPACE_WRITE,
            arguments_digest=delete.arguments_digest,
        )
        _approve(self.run, delete_call)
        broker.delete(delete_call, delete)
        self.assertFalse((self.workspace / "new/result.py").exists())

    def test_stale_write_and_denied_path_fail_without_overwrite(self):
        broker = self._broker()
        stale = WorkspaceWriteRequest(
            relative_path="source.py",
            content=b"after\n",
            expected_prior_sha256="7" * 64,
        )
        call = _call(
            self.run,
            call_id="write.stale",
            tool_name="workspace.write",
            capability=CapabilityId.WORKSPACE_WRITE,
            arguments_digest=stale.arguments_digest,
        )
        _approve(self.run, call)
        with self.assertRaisesRegex(
            WorkspaceBrokerError,
            "identity_changed",
        ):
            broker.write(call, stale)
        self.assertEqual(
            (self.workspace / "source.py").read_bytes(),
            b"before\n",
        )

        denied = WorkspaceWriteRequest(
            relative_path=".env",
            content=b"SECRET=value",
            expected_prior_sha256=None,
        )
        denied_call = _call(
            self.run,
            call_id="write.denied",
            tool_name="workspace.write",
            capability=CapabilityId.WORKSPACE_WRITE,
            arguments_digest=denied.arguments_digest,
        )
        _approve(self.run, denied_call)
        with self.assertRaisesRegex(WorkspaceBrokerError, "path_denied"):
            broker.write(denied_call, denied)
        self.assertFalse((self.workspace / ".env").exists())

    def test_command_is_profile_bound_offline_and_cannot_mutate_staging(self):
        runtime = self.root / "runtime"
        runtime.mkdir()
        executable = runtime / "python.exe"
        executable.write_bytes(b"reviewed runtime")
        profile = CommandProfile(
            profile_id="python.unittest",
            executable_relative_path="python.exe",
            executable_sha256=hashlib.sha256(
                executable.read_bytes()
            ).hexdigest(),
            fixed_arguments=("-I", "-S", "-m", "unittest"),
            allow_selectors=True,
            runs_candidate_code=True,
        )
        captured = []

        def launcher(**values):
            captured.append(values)
            return 0, b"3 tests passed\n", 0.25

        broker = self._broker(
            runtime_root=runtime,
            command_profiles=(profile,),
            command_launcher=launcher,
        )
        staging_digest = broker.current_manifest().manifest_digest
        request = WorkspaceCommandRequest(
            profile_id=profile.profile_id,
            profile_digest=profile.profile_digest,
            staging_manifest_digest=staging_digest,
            selectors=("tests.test_safe",),
        )
        call = _call(
            self.run,
            call_id="command.1",
            tool_name="workspace.command",
            capability=CapabilityId.WORKSPACE_COMMAND,
            arguments_digest=request.arguments_digest,
        )
        _approve(self.run, call)

        receipt = broker.command(call, request)

        self.assertTrue(receipt.succeeded)
        self.assertEqual(receipt.staging_manifest_digest, staging_digest)
        self.assertEqual(
            captured[0]["arguments"],
            ("-I", "-S", "-m", "unittest", "tests.test_safe"),
        )
        environment = captured[0]["environment"]
        self.assertNotIn("HOME", environment)
        self.assertNotIn("USERPROFILE", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "NUL")
        self.assertEqual(environment["PIP_CONFIG_FILE"], "NUL")

        with self.assertRaisesRegex(ValueError, "install dependencies"):
            CommandProfile(
                profile_id="python.install",
                executable_relative_path="python.exe",
                executable_sha256=profile.executable_sha256,
                fixed_arguments=("install", "package"),
                allow_selectors=False,
                runs_candidate_code=True,
            )
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            CommandProfile(
                profile_id="shell.verify",
                executable_relative_path="cmd.exe",
                executable_sha256=profile.executable_sha256,
                fixed_arguments=("/c", "test"),
                allow_selectors=False,
                runs_candidate_code=True,
            )
        with self.assertRaisesRegex(ValueError, "not canonical"):
            WorkspaceCommandRequest(
                profile_id=profile.profile_id,
                profile_digest=profile.profile_digest,
                staging_manifest_digest=staging_digest,
                selectors=("../outside",),
            )
        for selector in (
            "@response-file",
            "--config=outside",
            "tests/safe.py",
            r"tests\safe.py",
        ):
            with self.subTest(selector=selector):
                with self.assertRaisesRegex(
                    ValueError,
                    "not canonical|selectors are invalid",
                ):
                    WorkspaceCommandRequest(
                        profile_id=profile.profile_id,
                        profile_digest=profile.profile_digest,
                        staging_manifest_digest=staging_digest,
                        selectors=(selector,),
                    )

    def test_command_mutation_is_never_verification_success(self):
        runtime = self.root / "runtime"
        runtime.mkdir()
        executable = runtime / "tool.exe"
        executable.write_bytes(b"reviewed tool")
        profile = CommandProfile(
            profile_id="safe.verify",
            executable_relative_path="tool.exe",
            executable_sha256=hashlib.sha256(
                executable.read_bytes()
            ).hexdigest(),
            fixed_arguments=("--verify",),
            allow_selectors=False,
            runs_candidate_code=True,
        )

        def launcher(**_values):
            (self.workspace / "source.py").write_bytes(b"mutated by test")
            return 0, b"claimed success", 0.1

        broker = self._broker(
            runtime_root=runtime,
            command_profiles=(profile,),
            command_launcher=launcher,
        )
        request = WorkspaceCommandRequest(
            profile_id=profile.profile_id,
            profile_digest=profile.profile_digest,
            staging_manifest_digest=(
                broker.current_manifest().manifest_digest
            ),
        )
        call = _call(
            self.run,
            call_id="command.mutates",
            tool_name="workspace.command",
            capability=CapabilityId.WORKSPACE_COMMAND,
            arguments_digest=request.arguments_digest,
        )
        _approve(self.run, call)
        with self.assertRaisesRegex(
            WorkspaceBrokerError,
            "changed_staging",
        ):
            broker.command(call, request)


class WorkspaceResultVerificationTests(unittest.TestCase):
    def test_changes_and_success_are_bound_to_same_final_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).absolute()
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "modified.txt").write_bytes(b"before")
            (workspace / "deleted.txt").write_bytes(b"delete")
            baseline, _ = scan_workspace(
                workspace,
                run_id="run.result-1",
                repository_identity_digest=_identity().identity_digest,
            )
            snapshot = WorkspaceSnapshot(
                identity=_identity(),
                source_root=workspace,
                task_root=root,
                workspace_root=workspace,
                baseline_manifest=baseline,
            )
            (workspace / "modified.txt").write_bytes(b"after")
            (workspace / "deleted.txt").unlink()
            (workspace / "added.txt").write_bytes(b"added")
            final, _ = scan_workspace(
                workspace,
                run_id=baseline.run_id,
                repository_identity_digest=(
                    baseline.repository_identity_digest
                ),
            )
            receipt = VerificationReceipt(
                profile_id="python.unittest",
                profile_digest="8" * 64,
                staging_manifest_digest=final.manifest_digest,
                arguments_digest="9" * 64,
                exit_code=0,
                output_sha256="a" * 64,
                output_bytes=10,
                duration_seconds=0.5,
                succeeded=True,
            )

            result = verify_isolated_result(
                snapshot=snapshot,
                verifications=(receipt,),
            )

        self.assertEqual(result.state, "awaiting_review")
        self.assertEqual(
            [(item.relative_path, item.kind.value) for item in result.changes],
            [
                ("added.txt", "added"),
                ("deleted.txt", "deleted"),
                ("modified.txt", "modified"),
            ],
        )

    def test_failed_missing_stale_and_cancelled_verification_never_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).absolute()
            (workspace / "source.txt").write_bytes(b"content")
            baseline, _ = scan_workspace(
                workspace,
                run_id="run.result-2",
                repository_identity_digest=_identity().identity_digest,
            )
            snapshot = WorkspaceSnapshot(
                identity=_identity(),
                source_root=workspace,
                task_root=workspace.parent,
                workspace_root=workspace,
                baseline_manifest=baseline,
            )
            failed = VerificationReceipt(
                profile_id="python.unittest",
                profile_digest="b" * 64,
                staging_manifest_digest=baseline.manifest_digest,
                arguments_digest="c" * 64,
                exit_code=1,
                output_sha256="d" * 64,
                output_bytes=5,
                duration_seconds=0.2,
                succeeded=False,
            )
            failure = verify_isolated_result(
                snapshot=snapshot,
                verifications=(failed,),
            )
            missing = verify_isolated_result(
                snapshot=snapshot,
                verifications=(),
            )
            cancelled = verify_isolated_result(
                snapshot=snapshot,
                verifications=(),
                cancelled=True,
            )

        self.assertEqual(failure.state, "failed")
        self.assertEqual(missing.state, "partial")
        self.assertEqual(cancelled.state, "cancelled")
        for result in (failure, missing, cancelled):
            self.assertNotEqual(result.state, "awaiting_review")


if __name__ == "__main__":
    unittest.main()
