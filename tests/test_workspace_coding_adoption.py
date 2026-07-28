"""Adversarial tests for exact workspace diff review and host adoption."""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from capability_registry import CapabilityGrant, CapabilityId
from tasks.models import (
    ApprovalRequest,
    TaskLimits,
    TaskRun,
    TaskSpec,
    ToolCall,
)
from ui.workspace_diff_review import build_workspace_diff_review_view
from workspace_coding.adoption import (
    WorkspaceAdopter,
    WorkspaceAdoptionChoice,
    WorkspaceAdoptionError,
    WorkspaceAdoptionRequest,
    WorkspaceReviewFormat,
    build_workspace_diff_review,
    workspace_adoption_action_digest,
)
from workspace_coding.file_protection import capture_file_protection
from workspace_coding.models import (
    GitWorkspaceIdentity,
    VerificationReceipt,
)
from workspace_coding.sandbox import verify_isolated_result
from workspace_coding.snapshot import create_isolated_snapshot, scan_workspace


def _identity(
    root: Path,
    *,
    status: str = "1",
    dirty: bool = True,
) -> GitWorkspaceIdentity:
    resolved = root.resolve(strict=True)
    return GitWorkspaceIdentity(
        repository_id="repo.adoption-synthetic",
        final_path_sha256=hashlib.sha256(
            os.path.normcase(str(resolved)).encode("utf-8")
        ).hexdigest(),
        head_commit="2" * 40,
        branch="feature/adoption",
        status_sha256=status * 64,
        git_executable_sha256="4" * 64,
        dirty=dirty,
    )


def _run(run_id: str) -> TaskRun:
    run = TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.workspace_coding",
            skill_version="1.0.0",
            goal="Review and adopt one synthetic isolated change set.",
            input_digest="5" * 64,
            requested_result="Exact reviewed workspace changes.",
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
                    CapabilityId.WORKSPACE_APPLY,
                }
            ),
        ),
    )
    run.start()
    return run


class _Fixture:
    def __init__(self, base: Path, *, run_id: str) -> None:
        self.base = base
        self.source = base / "selected"
        self.tasks = base / "tasks"
        self.transactions = base / "transactions"
        self.source.mkdir()
        self.transactions.mkdir()
        (self.source / ".git").mkdir()
        (self.source / ".git" / "config").write_bytes(b"git authority")
        (self.source / "binary.bin").write_bytes(b"\x00before")
        (self.source / "deleted.txt").write_bytes(b"delete me\n")
        (self.source / "modified.txt").write_bytes(b"before\n")
        self.identity = _identity(self.source)
        self.snapshot = create_isolated_snapshot(
            self.source,
            self.tasks,
            run_id=run_id,
            identity=self.identity,
            revalidate_identity=lambda _path: self.identity,
        )
        workspace = self.snapshot.workspace_root
        (workspace / "binary.bin").write_bytes(b"\x00after")
        (workspace / "deleted.txt").unlink()
        (workspace / "modified.txt").write_bytes(b"after\n")
        (workspace / "nested").mkdir()
        (workspace / "nested" / "added.txt").write_bytes(b"added\n")
        final, _ = scan_workspace(
            workspace,
            run_id=run_id,
            repository_identity_digest=self.identity.identity_digest,
        )
        verification = VerificationReceipt(
            profile_id="python.unittest",
            profile_digest="6" * 64,
            staging_manifest_digest=final.manifest_digest,
            arguments_digest="7" * 64,
            exit_code=0,
            output_sha256="8" * 64,
            output_bytes=12,
            duration_seconds=0.25,
            succeeded=True,
        )
        self.result = verify_isolated_result(
            snapshot=self.snapshot,
            verifications=(verification,),
        )
        self.review = build_workspace_diff_review(
            self.snapshot,
            self.result,
            revalidate_identity=self.revalidate,
        )

    def source_matches_final(self) -> bool:
        return (
            (self.source / "binary.bin").read_bytes() == b"\x00after"
            and not (self.source / "deleted.txt").exists()
            and (self.source / "modified.txt").read_bytes() == b"after\n"
            and (
                self.source / "nested" / "added.txt"
            ).read_bytes()
            == b"added\n"
        )

    def revalidate(self, _path: Path) -> GitWorkspaceIdentity:
        if self.source_matches_final():
            return replace(
                self.identity,
                status_sha256="9" * 64,
                dirty=True,
            )
        return self.identity

    def request(
        self,
        choice: WorkspaceAdoptionChoice,
    ) -> WorkspaceAdoptionRequest:
        return WorkspaceAdoptionRequest(
            choice=choice,
            review_digest=self.review.review_digest,
            diff_sha256=self.review.diff_sha256,
            result_digest=self.result.result_digest,
            repository_identity_digest=self.identity.identity_digest,
            baseline_manifest_digest=(
                self.snapshot.baseline_manifest.manifest_digest
            ),
            final_manifest_digest=(
                self.result.final_manifest.manifest_digest
            ),
        )

    def call(
        self,
        run: TaskRun,
        request: WorkspaceAdoptionRequest,
        *,
        call_id: str,
    ) -> ToolCall:
        return ToolCall(
            call_id=call_id,
            run_id=run.run_id,
            step_id=call_id.replace(".", "-"),
            tool_name=(
                "workspace.apply"
                if request.choice is WorkspaceAdoptionChoice.APPLY
                else "workspace.discard"
            ),
            capability=CapabilityId.WORKSPACE_APPLY,
            arguments_digest=request.arguments_digest,
            action_digest=workspace_adoption_action_digest(
                run_id=run.run_id,
                call_id=call_id,
                arguments_digest=request.arguments_digest,
            ),
        )

    def approve(
        self,
        run: TaskRun,
        call: ToolCall,
    ) -> None:
        assert call.action_digest is not None
        approval = ApprovalRequest(
            approval_id="approval-" + call.call_id,
            run_id=run.run_id,
            call_id=call.call_id,
            capability=CapabilityId.WORKSPACE_APPLY,
            action_digest=call.action_digest,
            reason="Apply or discard this exact reviewed change set.",
            preview_digests=(
                self.review.review_digest,
                self.review.diff_sha256,
            ),
            expires_at=100.0,
        )
        run.request_approval(call, approval, now=1.0)
        run.approve(
            approval.approval_id,
            approval.action_digest,
            now=2.0,
        )

    def adopter(self, run: TaskRun) -> WorkspaceAdopter:
        return WorkspaceAdopter(
            run,
            self.snapshot,
            self.result,
            self.review,
            revalidate_identity=self.revalidate,
            transaction_parent=self.transactions,
        )


class WorkspaceDiffReviewTests(unittest.TestCase):
    def test_review_is_host_derived_exact_bounded_and_binary_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.review-1",
            )
            review = fixture.review
            second = build_workspace_diff_review(
                fixture.snapshot,
                fixture.result,
                revalidate_identity=fixture.revalidate,
            )
            view = build_workspace_diff_review_view(
                fixture.snapshot,
                fixture.result,
                review,
            )
            expected_source = fixture.source.resolve(strict=True)

        self.assertEqual(review.review_digest, second.review_digest)
        self.assertEqual(review.diff_sha256, second.diff_sha256)
        self.assertEqual(
            [item.change.relative_path for item in review.entries],
            [
                "binary.bin",
                "deleted.txt",
                "modified.txt",
                "nested/added.txt",
            ],
        )
        by_path = {
            item.change.relative_path: item
            for item in review.entries
        }
        self.assertIs(
            by_path["binary.bin"].review_format,
            WorkspaceReviewFormat.BINARY_IDENTITY,
        )
        self.assertIs(
            by_path["modified.txt"].review_format,
            WorkspaceReviewFormat.UNIFIED_TEXT,
        )
        rendered = review.diff_utf8.decode("utf-8")
        self.assertIn('"relative_path":"binary.bin"', rendered)
        self.assertIn(
            "Apply is bound to the exact byte counts and SHA-256",
            rendered,
        )
        self.assertIn("--- a/modified.txt", rendered)
        self.assertIn("+++ b/modified.txt", rendered)
        self.assertIn("-before", rendered)
        self.assertIn("+after", rendered)
        self.assertNotIn("git authority", rendered)
        self.assertEqual(view.selected_path, expected_source)
        self.assertEqual(
            view.changed_paths,
            tuple(
                item.change.relative_path
                for item in review.entries
            ),
        )
        self.assertEqual(view.diff_sha256, review.diff_sha256)
        self.assertEqual(view.apply_label, "Apply exact changes")
        self.assertEqual(
            view.discard_label,
            "Discard isolated changes",
        )
        self.assertEqual(len(view.verification_rows), 1)
        self.assertTrue(view.verification_rows[0].succeeded)


class WorkspaceAdoptionTests(unittest.TestCase):
    def test_apply_requires_exact_one_use_approval_and_reaches_final_manifest(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.apply-1",
            )
            run = _run("run.apply-1")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.1")
            adopter = fixture.adopter(run)
            protection_before = capture_file_protection(
                fixture.source / "modified.txt"
            )

            with self.assertRaisesRegex(
                WorkspaceAdoptionError,
                "not_authorized",
            ):
                adopter.apply(call, request)
            fixture.approve(run, call)
            receipt = adopter.apply(call, request)

            self.assertTrue(fixture.source_matches_final())
            self.assertEqual(
                (fixture.source / ".git" / "config").read_bytes(),
                b"git authority",
            )
            final, _ = scan_workspace(
                fixture.source,
                run_id=fixture.snapshot.baseline_manifest.run_id,
                repository_identity_digest=(
                    fixture.snapshot.baseline_manifest
                    .repository_identity_digest
                ),
            )
            self.assertEqual(
                final.manifest_digest,
                fixture.result.final_manifest.manifest_digest,
            )
            self.assertEqual(receipt.state, "applied")
            self.assertFalse(receipt.journal_cleanup_pending)
            self.assertEqual(
                capture_file_protection(
                    fixture.source / "modified.txt"
                ),
                protection_before,
            )
            self.assertEqual(
                receipt.original_manifest_digest,
                fixture.result.final_manifest.manifest_digest,
            )
            self.assertEqual(list(fixture.transactions.iterdir()), [])

    def test_stale_original_or_tampered_isolated_result_never_applies(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).absolute()
            fixture = _Fixture(base, run_id="run.stale-1")
            (fixture.source / "modified.txt").write_bytes(b"user edit\n")
            run = _run("run.stale-1")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.stale")
            fixture.approve(run, call)

            with self.assertRaisesRegex(
                WorkspaceAdoptionError,
                "original_bytes_changed",
            ):
                fixture.adopter(run).apply(call, request)
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"user edit\n",
            )
            self.assertEqual(list(fixture.transactions.iterdir()), [])

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).absolute()
            fixture = _Fixture(base, run_id="run.tamper-1")
            (
                fixture.snapshot.workspace_root / "modified.txt"
            ).write_bytes(b"tampered\n")
            run = _run("run.tamper-1")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.tamper")
            fixture.approve(run, call)

            with self.assertRaisesRegex(
                WorkspaceAdoptionError,
                "isolated_result_changed",
            ):
                fixture.adopter(run).apply(call, request)
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"before\n",
            )

    def test_mid_apply_failure_rolls_back_every_original_byte(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.rollback-1",
            )
            run = _run("run.rollback-1")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.rollback")
            fixture.approve(run, call)
            adopter = fixture.adopter(run)
            from workspace_coding import adoption as adoption_module
            deleted_protection = capture_file_protection(
                fixture.source / "deleted.txt"
            )

            real_replace = adoption_module._atomic_replace
            calls = 0

            def fail_second(
                destination,
                content,
                *,
                protection,
                suffix,
            ):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise WorkspaceAdoptionError("synthetic_failure")
                return real_replace(
                    destination,
                    content,
                    protection=protection,
                    suffix=suffix,
                )

            with mock.patch.object(
                adoption_module,
                "_atomic_replace",
                side_effect=fail_second,
            ):
                with self.assertRaisesRegex(
                    WorkspaceAdoptionError,
                    "failed_rolled_back",
                ):
                    adopter.apply(call, request)

            self.assertEqual(
                (fixture.source / "binary.bin").read_bytes(),
                b"\x00before",
            )
            self.assertEqual(
                (fixture.source / "deleted.txt").read_bytes(),
                b"delete me\n",
            )
            self.assertEqual(
                capture_file_protection(
                    fixture.source / "deleted.txt"
                ),
                deleted_protection,
            )
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"before\n",
            )
            self.assertFalse((fixture.source / "nested").exists())
            self.assertEqual(list(fixture.transactions.iterdir()), [])

    def test_cleanup_and_rollback_failures_preserve_truthful_journal_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.cleanup-1",
            )
            run = _run("run.cleanup-1")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.cleanup")
            fixture.approve(run, call)
            from workspace_coding import adoption as adoption_module

            with mock.patch.object(
                adoption_module,
                "_remove_tree_without_following_links",
                side_effect=OSError("synthetic cleanup failure"),
            ):
                receipt = fixture.adopter(run).apply(call, request)

            self.assertEqual(receipt.state, "applied")
            self.assertTrue(receipt.journal_cleanup_pending)
            self.assertTrue(fixture.source_matches_final())
            transaction_roots = list(fixture.transactions.iterdir())
            self.assertEqual(len(transaction_roots), 1)
            self.assertTrue(
                (transaction_roots[0] / "journal.json").is_file()
            )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.rollback-fails",
            )
            run = _run("run.rollback-fails")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.rollback-fails")
            fixture.approve(run, call)
            from workspace_coding import adoption as adoption_module

            with (
                mock.patch.object(
                    adoption_module,
                    "_apply_change",
                    side_effect=WorkspaceAdoptionError(
                        "synthetic apply failure"
                    ),
                ),
                mock.patch.object(
                    adoption_module,
                    "_rollback",
                    side_effect=WorkspaceAdoptionError(
                        "synthetic rollback failure"
                    ),
                ),
            ):
                with self.assertRaisesRegex(
                    WorkspaceAdoptionError,
                    "rollback_failed_journal_preserved",
                ):
                    fixture.adopter(run).apply(call, request)

            transaction_roots = list(fixture.transactions.iterdir())
            self.assertEqual(len(transaction_roots), 1)
            self.assertTrue(
                (transaction_roots[0] / "journal.json").is_file()
            )
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"before\n",
            )

    def test_cancellation_during_apply_rolls_back_and_cancelled_run_cannot_adopt(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.cancel-1",
            )
            run = _run("run.cancel-1")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.cancel")
            fixture.approve(run, call)
            probes = 0

            def cancelled():
                nonlocal probes
                probes += 1
                return probes >= 3

            with self.assertRaisesRegex(
                WorkspaceAdoptionError,
                "failed_rolled_back",
            ):
                fixture.adopter(run).apply(
                    call,
                    request,
                    cancelled=cancelled,
                )
            self.assertEqual(
                (fixture.source / "binary.bin").read_bytes(),
                b"\x00before",
            )
            self.assertEqual(list(fixture.transactions.iterdir()), [])

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.cancel-2",
            )
            run = _run("run.cancel-2")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.cancelled")
            fixture.approve(run, call)
            run.cancel()
            with self.assertRaisesRegex(
                WorkspaceAdoptionError,
                "not_authorized",
            ):
                fixture.adopter(run).apply(call, request)
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"before\n",
            )

    def test_discard_removes_only_isolated_task_even_if_original_changed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.discard-1",
            )
            (fixture.source / "modified.txt").write_bytes(b"user edit\n")
            run = _run("run.discard-1")
            request = fixture.request(WorkspaceAdoptionChoice.DISCARD)
            call = fixture.call(run, request, call_id="discard.1")
            fixture.approve(run, call)

            receipt = fixture.adopter(run).discard(call, request)

            self.assertEqual(receipt.state, "discarded")
            self.assertIsNone(receipt.source_identity_before)
            self.assertIsNone(receipt.source_identity_after)
            self.assertIsNone(receipt.original_manifest_digest)
            self.assertFalse(fixture.snapshot.task_root.exists())
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"user edit\n",
            )
            self.assertTrue((fixture.source / ".git").is_dir())
            self.assertEqual(list(fixture.transactions.iterdir()), [])

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.discard-tampered",
            )
            (
                fixture.snapshot.workspace_root / "modified.txt"
            ).write_bytes(b"tampered after review\n")
            run = _run("run.discard-tampered")
            request = fixture.request(WorkspaceAdoptionChoice.DISCARD)
            call = fixture.call(run, request, call_id="discard.tampered")
            fixture.approve(run, call)

            receipt = fixture.adopter(run).discard(call, request)

            self.assertEqual(receipt.state, "discarded")
            self.assertFalse(fixture.snapshot.task_root.exists())
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"before\n",
            )

    def test_overlapping_transaction_parent_is_rejected_without_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.overlap-1",
            )
            run = _run("run.overlap-1")
            request = fixture.request(WorkspaceAdoptionChoice.APPLY)
            call = fixture.call(run, request, call_id="apply.overlap")
            fixture.approve(run, call)
            invalid = fixture.source / "transaction-output"
            adopter = WorkspaceAdopter(
                run,
                fixture.snapshot,
                fixture.result,
                fixture.review,
                revalidate_identity=fixture.revalidate,
                transaction_parent=invalid,
            )

            with self.assertRaisesRegex(
                WorkspaceAdoptionError,
                "roots_overlap",
            ):
                adopter.apply(call, request)

            self.assertFalse(invalid.exists())
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"before\n",
            )

    def test_wrong_choice_digest_or_tool_never_reaches_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(
                Path(temporary).absolute(),
                run_id="run.wrong-1",
            )
            run = _run("run.wrong-1")
            apply_request = fixture.request(
                WorkspaceAdoptionChoice.APPLY
            )
            discard_request = fixture.request(
                WorkspaceAdoptionChoice.DISCARD
            )
            call = fixture.call(
                run,
                apply_request,
                call_id="apply.wrong",
            )
            fixture.approve(run, call)

            with self.assertRaisesRegex(
                WorkspaceAdoptionError,
                "request_mismatch|not_authorized",
            ):
                fixture.adopter(run).discard(call, discard_request)
            self.assertEqual(
                (fixture.source / "modified.txt").read_bytes(),
                b"before\n",
            )


if __name__ == "__main__":
    unittest.main()
