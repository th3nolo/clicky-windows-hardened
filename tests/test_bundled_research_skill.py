"""End-to-end authority and artifact tests for the first bundled skill."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from capability_registry import CapabilityGrant, CapabilityId
from declarative_tools import DeclarativeTool
from skills.declarative_runner import (
    DeclarativeSkillRunner,
    RunnerDisposition,
    declarative_inputs_digest,
)
from skills.registry import (
    SkillEnablementStore,
    declarative_skill_invocation_allowed,
    load_bundled_declarative_skills,
    permission_review_digest,
)
from tasks.coordinator import TaskWorkspace
from tasks.models import TaskLimits, TaskRun, TaskSpec, TaskState
from tasks.policy import WorkerPolicy


SKILL_ID = "clicky.research_to_csv"
VERIFIER_ID = "research-csv-v1"
SOURCE_ONE = "https://creator.example/one"
SOURCE_TWO = "https://creator.example/two"


def _records_json(*sources: str) -> str:
    return json.dumps(
        {
            "records": [
                {
                    "entity": {
                        "value": f"Creator {index}",
                        "source_urls": [source],
                    },
                    "public_url": {
                        "value": source,
                        "source_urls": [source],
                    },
                    "rationale": {
                        "value": "Matches the public research request.",
                        "source_urls": [source],
                    },
                    "requested_fields": {},
                }
                for index, source in enumerate(sources, 1)
            ]
        },
        separators=(",", ":"),
    )


class BundledResearchSkillTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).absolute()
        self.snapshot = load_bundled_declarative_skills()
        self.entry = next(
            entry
            for entry in self.snapshot.catalog_entries
            if entry.skill_id == SKILL_ID
        )
        self.definition = self.snapshot.resolve(SKILL_ID)
        assert self.definition is not None

    def _run(self, inputs: dict[str, object], *, run_id: str) -> TaskRun:
        definition = self.definition
        return TaskRun(
            TaskSpec(
                run_id=run_id,
                skill_id=definition.skill_id,
                skill_version=definition.version,
                goal="Create a reviewed source-backed research CSV.",
                input_digest=declarative_inputs_digest(
                    definition,
                    inputs,
                ),
                requested_result="A verified local CSV artifact.",
                verifier_step_id="verify",
                verifier_id=VERIFIER_ID,
                limits=TaskLimits(
                    runtime_seconds=definition.limits.runtime_seconds,
                    max_tool_calls=definition.limits.max_tool_calls,
                    max_network_requests=(
                        definition.limits.max_network_requests
                    ),
                    max_output_bytes=definition.limits.max_output_bytes,
                ),
            ),
            CapabilityGrant(
                run_id=run_id,
                capabilities=definition.capabilities,
            ),
        )

    def _runner(
        self,
        inputs: dict[str, object],
        *,
        run_id: str,
        model_text: str,
    ) -> tuple[DeclarativeSkillRunner, TaskRun, TaskWorkspace]:
        run = self._run(inputs, run_id=run_id)
        workspace = TaskWorkspace.create(
            run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=self.root / "workspaces",
        )
        self.addCleanup(workspace.cleanup)

        async def search(query: str, maximum: int) -> str:
            self.assertEqual(query, inputs["query"])
            self.assertEqual(maximum, 5)
            return (
                f"[1] Creator one — {SOURCE_ONE}\n"
                "Public profile one.\n\n"
                f"[2] Creator two — {SOURCE_TWO}\n"
                "Public profile two."
            )

        async def model(arguments):
            self.assertIn("[1] Creator one", arguments.context)
            self.assertNotIn("[BEGIN BOUNDED", arguments.system_prompt)
            yield model_text

        runner = DeclarativeSkillRunner.create(
            self.definition,
            run,
            workspace,
            model_stream=model,
            web_search=search,
            artifact_root=self.root / "adopted",
        )
        return runner, run, workspace

    def test_bundle_is_integrity_bound_opt_in_and_has_no_external_write(self):
        definition = self.definition
        self.assertEqual(
            definition.capabilities,
            frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.WEB_SEARCH_BOUNDED,
                    CapabilityId.LOCAL_ARTIFACT_WRITE,
                }
            ),
        )
        self.assertEqual(definition.connectors, ())
        self.assertEqual(
            tuple(step.tool for step in definition.steps),
            (
                DeclarativeTool.WEB_SEARCH,
                DeclarativeTool.MODEL_GENERATE,
                DeclarativeTool.RESEARCH_CSV_RENDER,
                DeclarativeTool.ARTIFACT_WRITE,
                DeclarativeTool.VERIFY_OUTPUT,
            ),
        )
        self.assertEqual(
            hashlib.sha256(
                (
                    Path(__file__).resolve().parents[1]
                    / "skills"
                    / "declarative"
                    / self.entry.source_filename
                ).read_bytes()
            ).hexdigest(),
            self.entry.package_digest,
        )

        store = SkillEnablementStore(self.root / "enablement.json")
        self.assertFalse(
            declarative_skill_invocation_allowed(
                self.snapshot,
                store,
                SKILL_ID,
                explicit_selection=True,
            )
        )
        store.enable(
            self.entry,
            reviewed_permission_digest=permission_review_digest(
                self.entry
            ),
        )
        self.assertTrue(
            declarative_skill_invocation_allowed(
                self.snapshot,
                store,
                SKILL_ID,
                explicit_selection=True,
            )
        )
        self.assertTrue(
            declarative_skill_invocation_allowed(
                self.snapshot,
                store,
                SKILL_ID,
                explicit_selection=False,
                utterance="  Research   To CSV  ",
            )
        )
        self.assertFalse(
            declarative_skill_invocation_allowed(
                self.snapshot,
                store,
                SKILL_ID,
                explicit_selection=False,
                utterance="research these results to csv",
            )
        )

    async def test_bounded_research_waits_on_exact_validated_csv_preview(self):
        inputs = {
            "query": "public creator profiles",
            "requested_rows": 2,
        }
        runner, run, workspace = self._runner(
            inputs,
            run_id="bundled-research-complete",
            model_text=_records_json(SOURCE_ONE, SOURCE_TWO),
        )
        runner.start(inputs)

        for now in (10.0, 11.0, 12.0):
            snapshot = await runner.advance(now=now)
            self.assertEqual(snapshot.task_state, TaskState.RUNNING)
        waiting = await runner.advance(now=13.0)

        self.assertEqual(
            waiting.disposition,
            RunnerDisposition.WAITING_FOR_APPROVAL,
        )
        payload = waiting.pending_approval
        self.assertIsNotNone(payload)
        assert payload is not None
        self.assertEqual(payload.target.reference, "research-csv")
        self.assertEqual(payload.target.label, "research.csv")
        self.assertEqual(payload.preview.media_type, "text/csv")
        self.assertIn(
            "entity,entity_sources,public_url,public_url_sources,"
            "rationale,rationale_sources,retrieved_at",
            payload.preview.excerpt,
        )
        self.assertIn(SOURCE_ONE, payload.preview.excerpt)
        self.assertIn(SOURCE_TWO, payload.preview.excerpt)
        preview_bytes = payload.preview.excerpt.encode("utf-8")
        self.assertEqual(
            payload.preview.byte_count,
            len(preview_bytes),
        )
        self.assertEqual(
            payload.preview.content_sha256,
            hashlib.sha256(preview_bytes).hexdigest(),
        )
        self.assertEqual(workspace.verify(), (0, 0))

        request = payload.request
        run.approve(
            request.approval_id,
            request.action_digest,
            now=14.0,
        )
        written = await runner.advance(now=14.0)
        self.assertEqual(written.task_state, TaskState.RUNNING)
        completed = await runner.advance(now=15.0)

        self.assertEqual(
            completed.disposition,
            RunnerDisposition.COMPLETED,
        )
        self.assertEqual(len(completed.results), 5)
        self.assertEqual(len(completed.artifacts), 1)
        artifact = completed.artifacts[0]
        self.assertTrue(artifact.adopted)
        self.assertEqual(artifact.name, "research.csv")
        self.assertEqual(
            artifact.sha256,
            payload.preview.content_sha256,
        )
        adopted_files = tuple((self.root / "adopted").rglob("*.artifact"))
        self.assertEqual(len(adopted_files), 1)
        self.assertEqual(
            hashlib.sha256(adopted_files[0].read_bytes()).hexdigest(),
            artifact.sha256,
        )

    async def test_shortfall_or_invented_source_never_reaches_approval(self):
        inputs = {
            "query": "public creator profiles",
            "requested_rows": 2,
        }
        short_runner, short_run, short_workspace = self._runner(
            inputs,
            run_id="bundled-research-shortfall",
            model_text=_records_json(SOURCE_ONE),
        )
        short_runner.start(inputs)
        for now in (20.0, 21.0, 22.0):
            short = await short_runner.advance(now=now)
        self.assertEqual(short.task_state, TaskState.FAILED)
        self.assertEqual(
            short.results[-1].error_code,
            "research_csv_row_shortfall",
        )
        self.assertIsNone(short.pending_approval)
        self.assertEqual(short.artifacts, ())
        self.assertEqual(short_workspace.verify(), (0, 0))
        self.assertEqual(
            short_run.result_code,
            "research_csv_row_shortfall",
        )

        invented_runner, invented_run, invented_workspace = self._runner(
            inputs,
            run_id="bundled-research-invented",
            model_text=_records_json(
                "https://invented.example/profile",
                SOURCE_TWO,
            ),
        )
        invented_runner.start(inputs)
        for now in (30.0, 31.0, 32.0):
            invented = await invented_runner.advance(now=now)
        self.assertEqual(invented.task_state, TaskState.FAILED)
        self.assertEqual(
            invented.results[-1].error_code,
            "research_csv_render_failed",
        )
        self.assertIsNone(invented.pending_approval)
        self.assertEqual(invented.artifacts, ())
        self.assertEqual(invented_workspace.verify(), (0, 0))
        self.assertEqual(
            invented_run.result_code,
            "research_csv_render_failed",
        )


if __name__ == "__main__":
    unittest.main()
