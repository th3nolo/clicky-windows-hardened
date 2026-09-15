import json
import tempfile
import unittest
from pathlib import Path

from automation.teaching_task import (
    CompletionRejected,
    PageIdentity,
    TaskState,
    TeachingTaskError,
    TeachingTaskJournal,
)


TARGET_DIGEST = "a" * 64


def page(page_id: str, revision: str | int = 7) -> PageIdentity:
    return PageIdentity("notebook-1", page_id, revision)


def receipt(status: str) -> dict[str, object]:
    action_started = status not in {"failed_before_action", "cancelled_before_action"}
    evidence = (
        {"property_name": "revision", "before": "7", "after": "8"}
        if status in {"verified_succeeded", "failed_verification"}
        else None
    )
    return {
        "status": status,
        "result_code": "page_readback",
        "action_started": action_started,
        "target_identity_digest": TARGET_DIGEST,
        "evidence": evidence,
    }


class TeachingTaskJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "task.json"
        self.journal_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create(self, components=("write", "readback")) -> TeachingTaskJournal:
        path = self.path if self.journal_index == 0 else self.path.with_name(
            f"task-{self.journal_index}.json"
        )
        self.journal_index += 1
        return TeachingTaskJournal.create(
            task_id="teach-1",
            source_page=page("source-page"),
            target_page=page("target-page", 8),
            required_components=components,
            store_path=path,
        )

    def test_persists_and_restarts_only_after_all_declared_components_are_verified(self) -> None:
        journal = self.create()
        journal.record_operation("write", "draw-1", receipt=receipt("verified_succeeded"))
        journal.verify_component(
            "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8, "visible": True}
        )
        journal.verify_component(
            "readback", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8, "complete": True}
        )
        journal.complete()

        restarted = TeachingTaskJournal.load(self.path)
        snapshot = restarted.snapshot()
        self.assertEqual(snapshot["state"], TaskState.COMPLETED.value)
        self.assertEqual(snapshot["source_page"], page("source-page").to_payload())
        self.assertEqual(snapshot["target_page"], page("target-page", 8).to_payload())
        self.assertEqual(snapshot["components"]["write"]["operations"]["draw-1"]["receipt"]["status"], "verified_succeeded")
        self.assertFalse(list(self.path.parent.glob(".task.json.*")))

    def test_create_never_overwrites_an_existing_task_checkpoint(self) -> None:
        self.create(("write",))
        with self.assertRaisesRegex(TeachingTaskError, "already exists"):
            TeachingTaskJournal.create(
                task_id="teach-1",
                source_page=page("source-page"),
                target_page=page("target-page", 8),
                required_components=("write",),
                store_path=self.path,
            )

    def test_target_page_rebind_and_revision_checkpoint_are_idempotent(self) -> None:
        journal = self.create(("write",))
        target = page("new-page", 0)
        journal.set_target_page(target)
        journal.set_target_page(target)
        journal.set_target_page(page("new-page", 2))
        restarted = TeachingTaskJournal.load(self.path)
        self.assertEqual(restarted.snapshot()["target_page"], page("new-page", 2).to_payload())

    def test_opaque_target_revision_is_preserved_and_stale_evidence_cannot_complete(self) -> None:
        opaque = "0E1246E64AF2B67E822A9A2ED70BC344F77BA290F454F4962CF15650AB597F30"
        journal = TeachingTaskJournal.create(
            task_id="teach-opaque",
            source_page=page("source-page", opaque),
            target_page=page("target-page", opaque),
            required_components=("write",),
            store_path=self.path,
        )
        journal.record_operation("write", "draw-1", receipt=receipt("verified_succeeded"))
        with self.assertRaisesRegex(CompletionRejected, "target revision"):
            journal.verify_component(
                "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": "stale"}
            )
        journal.verify_component(
            "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": opaque}
        )
        journal.set_target_page(page("target-page", "F" * 64))
        with self.assertRaises(CompletionRejected):
            journal.complete()
        self.assertEqual(TeachingTaskJournal.load(self.path).snapshot()["target_page"]["revision"], "F" * 64)

    def test_unknown_mutation_needs_explicit_resolution_before_component_verification(self) -> None:
        journal = self.create(("write",))
        journal.record_operation("write", "draw-1", receipt=receipt("outcome_unknown"))

        with self.assertRaisesRegex(CompletionRejected, "unknown"):
            journal.verify_component(
                "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8}
            )

        journal.resolve_operation(
            "write",
            "draw-1",
            receipt=receipt("verified_succeeded"),
            verifier_id="fresh-readback",
            verifier_evidence={"target_revision": 8, "visible": True},
        )
        journal.verify_component(
            "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8, "visible": True}
        )
        journal.complete()
        operation = TeachingTaskJournal.load(self.path).snapshot()["components"]["write"]["operations"]["draw-1"]
        self.assertEqual(operation["receipt"]["status"], "outcome_unknown")
        self.assertEqual(operation["resolution"]["receipt"]["status"], "verified_succeeded")

    def test_false_completion_is_rejected_for_unverified_pending_and_failed_components(self) -> None:
        journal = self.create()
        with self.assertRaisesRegex(CompletionRejected, "write"):
            journal.complete()

        journal.record_operation("write", "draw-1")
        with self.assertRaisesRegex(CompletionRejected, "pending"):
            journal.verify_component(
                "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8}
            )
        with self.assertRaises(CompletionRejected):
            journal.complete()

        failed = self.create(("write",))
        failed.record_operation("write", "draw-1", receipt=receipt("failed_verification"))
        with self.assertRaisesRegex(CompletionRejected, "no verified"):
            failed.verify_component(
                "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8}
            )
        with self.assertRaises(CompletionRejected):
            failed.complete()

    def test_operation_recording_is_idempotent_but_conflicting_receipts_are_rejected(self) -> None:
        journal = self.create(("write",))
        first = journal.record_operation("write", "draw-1", receipt=receipt("verified_succeeded"))
        repeated = journal.record_operation("write", "draw-1", receipt=receipt("verified_succeeded"))
        self.assertEqual(first, repeated)
        with self.assertRaisesRegex(TeachingTaskError, "different evidence"):
            journal.record_operation("write", "draw-1", receipt=receipt("failed_verification"))

    def test_lifecycle_pause_cancel_and_unsafe_payloads_are_distinct_from_completion(self) -> None:
        journal = self.create(("write",))
        journal.mark_paused("awaiting_readback")
        with self.assertRaisesRegex(TeachingTaskError, "not active"):
            journal.complete()
        journal.resume()
        journal.cancel("user_cancelled")
        self.assertEqual(journal.snapshot()["state"], "cancelled")
        with self.assertRaisesRegex(TeachingTaskError, "not active"):
            journal.verify_component(
                "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8}
            )

        unsafe = self.create(("write",))
        unsafe_receipt = receipt("verified_succeeded")
        unsafe_receipt["image"] = "raw-image-bytes"
        with self.assertRaisesRegex(TeachingTaskError, "receipt"):
            unsafe.record_operation("write", "draw-1", receipt=unsafe_receipt)
        with self.assertRaisesRegex(TeachingTaskError, "not safe"):
            unsafe.verify_component(
                "write", verifier_id="fresh-readback", verifier_evidence={"target_revision": 8, "api_key": "never-store"}
            )
        serialized = json.loads(unsafe.store_path.read_text(encoding="utf-8"))
        self.assertNotIn("raw-image-bytes", json.dumps(serialized))


if __name__ == "__main__":
    unittest.main()
