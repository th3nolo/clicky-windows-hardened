import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from automation.lesson_plan import LessonComponent, LessonPlan, LessonPlanMode, PageGeometry, PageRegion
from automation.teaching_resume import (
    ResumeError,
    ResumeReconciliationRequired,
    ResumeRevisionMismatch,
    RevisionStatus,
    SourceImageReference,
    TeachingResumeStore,
)
from automation.teaching_task import PageIdentity, TeachingTaskJournal


TARGET_DIGEST = "b" * 64


def receipt(status: str) -> dict[str, object]:
    return {
        "status": status,
        "result_code": "native_readback",
        "action_started": status not in {"failed_before_action", "cancelled_before_action"},
        "target_identity_digest": TARGET_DIGEST,
        "evidence": (
            {"property_name": "revision", "before": "REV-0", "after": "REV-1"}
            if status in {"verified_succeeded", "failed_verification"}
            else None
        ),
    }


class TeachingResumeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.resume_root = root / "resume"
        self.journal_root = root / "journals"
        self.store = TeachingResumeStore(self.resume_root, journal_root=self.journal_root)
        self.task_id = "teach-1"
        self.target = PageIdentity("notebook-1", "page-1", "REV-1")
        self.journal = TeachingTaskJournal.create(
            task_id=self.task_id,
            source_page=PageIdentity("notebook-1", "source-1", "REV-0"),
            target_page=self.target,
            required_components=("heading", "readback"),
            store_path=self.journal_root / "teach-1.json",
        )
        self.plan = LessonPlan(
            mode=LessonPlanMode.TEACHING,
            page_geometry=PageGeometry(500, 500, 1000, 1000, PageRegion(0, 0, 500, 500)),
            target_is_new_page=False,
            components=(
                LessonComponent(
                    "heading",
                    PageRegion(10, 10, 100, 30),
                    required_labels=("Rows",),
                    required_objects=("heading",),
                ),
            ),
        )
        payload = b"approved-local-source-image"
        digest = hashlib.sha256(payload).hexdigest()
        self.artifact = self.resume_root / "artifacts" / self.task_id / f"source-{digest}.jpg"
        self.artifact.parent.mkdir(parents=True)
        self.artifact.write_bytes(payload)
        self.reference = SourceImageReference(
            artifact_id=f"sha256:{digest}",
            sha256=digest,
            relative_path=f"artifacts/{self.task_id}/source-{digest}.jpg",
            mime_type="image/jpeg",
            byte_length=len(payload),
            role="source_full_page",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def save(self) -> None:
        self.store.save_plan(
            task_journal=self.journal,
            plan=self.plan,
            original_question="Continue explaining the visible row labels.",
            source_image_references=(self.reference,),
        )

    def test_explicit_exact_resume_preserves_plan_question_refs_and_operation_ids(self) -> None:
        self.journal.record_operation("heading", "draw-heading-1", receipt=receipt("verified_succeeded"))
        self.journal.mark_paused("learner_interrupted")
        self.save()

        candidates = self.store.discover(self.target)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].task_id, self.task_id)
        self.assertEqual(candidates[0].revision_status, RevisionStatus.UNCHANGED)

        with self.assertRaisesRegex(ResumeError, "explicit"):
            self.store.load_for_resume(self.task_id, self.target)
        loaded = self.store.load_for_resume(self.task_id, self.target, explicit=True)
        self.assertEqual(loaded.plan, self.plan)
        self.assertEqual(loaded.original_question, "Continue explaining the visible row labels.")
        self.assertEqual(loaded.source_image_references, (self.reference,))
        self.assertIn("draw-heading-1", loaded.journal.snapshot()["components"]["heading"]["operations"])
        self.assertEqual(loaded.journal.snapshot()["required_components"], ["heading", "readback"])
        self.assertEqual(loaded.resume().snapshot()["state"], "active")

        manifest = json.loads((self.resume_root / "teach-1.manifest.json").read_text(encoding="utf-8"))
        rendered = json.dumps(manifest)
        self.assertNotIn("Continue explaining", rendered)
        self.assertNotIn("approved-local-source-image", rendered)
        self.assertEqual(manifest["target_page"]["revision"], "REV-1")

    def test_discovery_reports_changed_revision_but_load_requires_exact_unless_reconciliation(self) -> None:
        self.journal.mark_paused("learner_interrupted")
        self.save()
        changed = PageIdentity("notebook-1", "page-1", "REV-2")
        candidates = self.store.discover(changed)
        self.assertEqual(candidates[0].revision_status, RevisionStatus.CHANGED)
        with self.assertRaises(ResumeRevisionMismatch):
            self.store.load_for_resume(self.task_id, changed, explicit=True)
        reconciliation = self.store.load_for_resume(
            self.task_id, changed, explicit=True, reconciliation=True
        )
        self.assertEqual(reconciliation.revision_status, RevisionStatus.CHANGED)
        with self.assertRaises(ResumeRevisionMismatch):
            reconciliation.resume()
        self.assertEqual(reconciliation.begin_reconciliation().snapshot()["target_page"], changed.to_payload())
        self.assertEqual(reconciliation.revision_status, RevisionStatus.UNCHANGED)
        with self.assertRaisesRegex(ResumeError, "notebook or page"):
            self.store.load_for_resume(
                self.task_id, PageIdentity("other-notebook", "page-1", "REV-1"), explicit=True
            )

    def test_unknown_native_receipt_blocks_resume_until_journal_reconciliation(self) -> None:
        self.journal.record_operation("heading", "draw-heading-1", receipt=receipt("outcome_unknown"))
        self.journal.mark_paused("native_outcome_unknown")
        self.save()
        loaded = self.store.load_for_resume(self.task_id, self.target, explicit=True)
        self.assertEqual(loaded.pending_reconciliation_operations(), (("heading", "draw-heading-1"),))
        with self.assertRaises(ResumeReconciliationRequired):
            loaded.resume()

        loaded.journal.resume()
        loaded.journal.resolve_operation(
            "heading",
            "draw-heading-1",
            receipt=receipt("verified_succeeded"),
            verifier_id="native-readback",
            verifier_evidence={"target_revision": "REV-1", "visible": True},
        )
        loaded.journal.mark_paused("reconciled_for_continue")
        self.assertEqual(loaded.resume().snapshot()["state"], "active")

    def test_references_are_task_scoped_digest_checked_and_never_base64_in_checkpoint(self) -> None:
        with self.assertRaisesRegex(ResumeError, "outside its task-owned"):
            self.store.save_plan(
                task_journal=self.journal,
                plan=self.plan,
                original_question="Continue the lesson.",
                source_image_references=(
                    {
                        **self.reference.to_payload(),
                        "relative_path": "artifacts/other-task/source.jpg",
                    },
                ),
            )
        self.artifact.write_bytes(b"x" * self.reference.byte_length)
        with self.assertRaisesRegex(ResumeError, "digest"):
            self.save()
        self.artifact.write_bytes(b"approved-local-source-image")
        self.save()
        refs = json.loads((self.resume_root / "teach-1.refs.json").read_text(encoding="utf-8"))
        serialized = json.dumps(refs)
        self.assertNotIn("approved-local-source-image", serialized)
        self.assertNotIn("base64", serialized.casefold())

    def test_immutable_resume_inputs_cannot_overwrite_existing_task_artifacts(self) -> None:
        self.save()
        changed_plan = LessonPlan(
            mode=LessonPlanMode.TEACHING,
            page_geometry=PageGeometry(500, 500, 1000, 1000, PageRegion(0, 0, 500, 500)),
            target_is_new_page=False,
            components=(LessonComponent("heading", PageRegion(10, 10, 100, 30), required_labels=("Columns",)),),
        )
        with self.assertRaisesRegex(ResumeError, "different content"):
            self.store.save_plan(
                task_journal=self.journal,
                plan=changed_plan,
                original_question="Continue explaining the visible row labels.",
                source_image_references=(self.reference,),
            )
        with self.assertRaisesRegex(ResumeError, "different content"):
            self.store.save_plan(
                task_journal=self.journal,
                plan=self.plan,
                original_question="A changed question should never overwrite the saved question.",
                source_image_references=(self.reference,),
            )


if __name__ == "__main__":
    unittest.main()
