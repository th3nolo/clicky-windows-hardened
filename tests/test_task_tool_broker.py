"""Trusted task tool-broker authority, quota, and artifact tests."""

from __future__ import annotations

import ast
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from capability_registry import (
    CapabilityGrant,
    CapabilityId,
    require_capability,
)
from declarative_tools import (
    INITIAL_TASK_BROKER_TOOLS,
    TOOL_CAPABILITIES,
    DeclarativeTool,
)
from tasks.coordinator import TaskWorkspace
from tasks.models import (
    ApprovalRequest,
    TaskLimits,
    TaskRun,
    TaskSpec,
    TaskState,
    ToolCall,
    ToolResultStatus,
)
from tasks.policy import WorkerPolicy
from tasks.tool_broker import (
    ArtifactReadArguments,
    ArtifactWriteArguments,
    DeclaredToolStep,
    ModelGenerateArguments,
    ResearchCsvRenderArguments,
    TaskToolBroker,
    TaskToolBrokerLimitError,
    TaskToolBrokerValidationError,
    VerifyOutputArguments,
    WebFetchArguments,
    WebSearchArguments,
    broker_action_digest,
    broker_arguments_digest,
)


DIGEST = "a" * 64
ROOT = Path(__file__).resolve().parents[1]
VERIFIER_ID = "artifact-postcondition-v1"


def declared_step(
    step_id: str,
    tool: DeclarativeTool,
    *,
    depends_on: tuple[str, ...] = (),
    output_id: str | None = None,
) -> DeclaredToolStep:
    capability = TOOL_CAPABILITIES[tool]
    approval_id = (
        f"approve-{step_id}"
        if require_capability(capability).action_approval_required
        else None
    )
    return DeclaredToolStep(
        skill_id="clicky.test",
        skill_version="1.0.0",
        step_id=step_id,
        tool=tool,
        capability=capability,
        output_id=output_id or f"{step_id}-output",
        depends_on=depends_on,
        approval_id=approval_id,
    )


def call_for(
    step: DeclaredToolStep,
    arguments,
    *,
    call_id: str | None = None,
    run_id: str = "task-broker-1",
) -> ToolCall:
    resolved_call_id = call_id or f"call-{step.step_id}"
    action_digest = None
    if require_capability(step.capability).action_approval_required:
        action_digest = broker_action_digest(
            call_id=resolved_call_id,
            run_id=run_id,
            step_id=step.step_id,
            tool=step.tool,
            capability=step.capability,
            arguments=arguments,
        )
    return ToolCall(
        call_id=resolved_call_id,
        run_id=run_id,
        step_id=step.step_id,
        tool_name=step.tool.value,
        capability=step.capability,
        arguments_digest=broker_arguments_digest(arguments),
        action_digest=action_digest,
    )


class TaskToolBrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.adapter_calls = {
            "model": 0,
            "search": 0,
            "fetch": 0,
        }

    def create_broker(
        self,
        steps: tuple[DeclaredToolStep, ...],
        *,
        run_id: str = "task-broker-1",
        max_tool_calls: int = 16,
        max_network_requests: int = 4,
        max_output_bytes: int = 64 * 1024,
        model_text: str = "bounded model response",
        search_text: str = "[1] bounded search result",
        fetch_text: str = "bounded fetched page",
        use_default_web: bool = False,
    ) -> tuple[TaskToolBroker, TaskRun, TaskWorkspace]:
        limits = TaskLimits(
            runtime_seconds=60,
            max_tool_calls=max_tool_calls,
            max_network_requests=max_network_requests,
            max_output_bytes=max_output_bytes,
        )
        capabilities = {
            CapabilityId.TASK_AGENT_RUN,
            *(step.capability for step in steps),
        }
        run = TaskRun(
            TaskSpec(
                run_id=run_id,
                skill_id="clicky.test",
                skill_version="1.0.0",
                goal="Exercise one exact declared broker workflow.",
                input_digest=DIGEST,
                requested_result="A verified inert task artifact.",
                verifier_step_id="verify",
                verifier_id=VERIFIER_ID,
                limits=limits,
            ),
            CapabilityGrant(
                run_id=run_id,
                capabilities=frozenset(capabilities),
            ),
        )
        run.start()
        workspace = TaskWorkspace.create(
            run_id,
            WorkerPolicy.from_task_limits(limits),
            root=Path(self.temporary.name).absolute() / "task-workspaces",
        )
        self.addCleanup(workspace.cleanup)

        async def model_stream(arguments):
            self.adapter_calls["model"] += 1
            yield model_text

        async def web_search(query, max_results):
            self.adapter_calls["search"] += 1
            return search_text

        async def web_fetch(url, max_chars):
            self.adapter_calls["fetch"] += 1
            return fetch_text

        web_adapters = (
            {}
            if use_default_web
            else {
                "web_search": web_search,
                "web_fetch": web_fetch,
            }
        )
        broker = TaskToolBroker(
            run,
            workspace,
            steps,
            model_stream=model_stream,
            artifact_root=(
                Path(self.temporary.name).absolute() / "adopted-artifacts"
            ),
            **web_adapters,
        )
        return broker, run, workspace

    def approve(
        self,
        run: TaskRun,
        call: ToolCall,
        *,
        now: float = 10.0,
    ) -> None:
        request = ApprovalRequest(
            approval_id=f"approval-{call.call_id}",
            run_id=run.run_id,
            call_id=call.call_id,
            capability=call.capability,
            action_digest=call.action_digest,
            reason="Write this exact inert artifact.",
            preview_digests=(call.arguments_digest,),
            expires_at=now + 60,
        )
        run.request_approval(call, request, now=now)
        run.approve(
            request.approval_id,
            request.action_digest,
            now=now + 1,
        )

    async def test_model_output_is_text_and_cannot_invoke_host_tools(self):
        model_step = declared_step(
            "generate",
            DeclarativeTool.MODEL_GENERATE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("generate",),
        )
        model_text = (
            '{"tool":"artifact.write","arguments":{"name":"payload.exe"}}'
        )
        broker, _, workspace = self.create_broker(
            (model_step, verify_step),
            model_text=model_text,
        )
        arguments = ModelGenerateArguments(
            prompt="Return a draft.",
            system_prompt="Return text only.",
        )
        result = await broker.execute(
            call_for(model_step, arguments),
            arguments,
        )
        self.assertEqual(result.result.status, ToolResultStatus.SUCCEEDED)
        self.assertEqual(result.text, model_text)
        self.assertEqual(self.adapter_calls["model"], 1)
        self.assertEqual(workspace.verify(), (0, 0))

    def test_model_evidence_context_is_bounded_and_digest_bound(self):
        plain = ModelGenerateArguments(
            prompt="Return records.",
            system_prompt="Return JSON only.",
        )
        contextual = ModelGenerateArguments(
            prompt="Return records.",
            system_prompt="Return JSON only.",
            context=(
                "[1] Public profile — "
                "https://creator.example/one\nPublic evidence."
            ),
        )

        self.assertNotEqual(
            broker_arguments_digest(plain),
            broker_arguments_digest(contextual),
        )

    async def test_wrong_schema_digest_and_step_fail_before_adapter(self):
        model_step = declared_step(
            "generate",
            DeclarativeTool.MODEL_GENERATE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("generate",),
        )
        broker, _, _ = self.create_broker((model_step, verify_step))
        arguments = ModelGenerateArguments(
            prompt="Return a draft.",
            system_prompt="Return text only.",
        )
        call = call_for(model_step, arguments)

        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "arguments",
        ):
            await broker.execute(call, object())
        self.assertEqual(self.adapter_calls["model"], 0)

        wrong_digest = ToolCall(
            call_id=call.call_id,
            run_id=call.run_id,
            step_id=call.step_id,
            tool_name=call.tool_name,
            capability=call.capability,
            arguments_digest="0" * 64,
        )
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "digest",
        ):
            await broker.execute(wrong_digest, arguments)
        self.assertEqual(self.adapter_calls["model"], 0)

        wrong_tool = ToolCall(
            call_id=call.call_id,
            run_id=call.run_id,
            step_id=call.step_id,
            tool_name=DeclarativeTool.WEB_SEARCH.value,
            capability=CapabilityId.WEB_SEARCH_BOUNDED,
            arguments_digest=call.arguments_digest,
        )
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "declared step",
        ):
            await broker.execute(wrong_tool, arguments)
        self.assertEqual(self.adapter_calls["model"], 0)

    async def test_dependency_order_and_duplicate_calls_fail_closed(self):
        first_step = declared_step(
            "first",
            DeclarativeTool.MODEL_GENERATE,
        )
        second_step = declared_step(
            "second",
            DeclarativeTool.MODEL_GENERATE,
            depends_on=("first",),
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("second",),
        )
        broker, _, _ = self.create_broker(
            (first_step, second_step, verify_step)
        )
        arguments = ModelGenerateArguments(
            prompt="Return a draft.",
            system_prompt="Return text only.",
        )
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "dependencies",
        ):
            await broker.execute(
                call_for(second_step, arguments),
                arguments,
            )
        first_call = call_for(first_step, arguments)
        result = await broker.execute(first_call, arguments)
        self.assertEqual(result.result.status, ToolResultStatus.SUCCEEDED)
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "consumed|completed",
        ):
            await broker.execute(first_call, arguments)
        self.assertEqual(self.adapter_calls["model"], 1)

    async def test_artifact_write_requires_exact_one_use_approval(self):
        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        broker, run, workspace = self.create_broker(
            (write_step, verify_step)
        )
        arguments = ArtifactWriteArguments(
            artifact_id="report",
            name="report.md",
            media_type="text/markdown",
            content=b"# Verified report\n",
        )
        call = call_for(write_step, arguments)
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "authority",
        ):
            await broker.execute(call, arguments)
        self.assertEqual(workspace.verify(), (0, 0))

        self.approve(run, call)
        result = await broker.execute(call, arguments)
        self.assertEqual(result.result.status, ToolResultStatus.SUCCEEDED)
        self.assertIsNone(result.artifact)
        self.assertEqual(
            result.pending_artifact.sha256,
            hashlib.sha256(arguments.content).hexdigest(),
        )
        self.assertGreater(workspace.verify()[0], 0)

        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "consumed|completed",
        ):
            await broker.execute(call, arguments)

    async def test_rejected_exact_preview_payload_produces_no_write(self):
        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        broker, run, workspace = self.create_broker(
            (write_step, verify_step)
        )
        arguments = ArtifactWriteArguments(
            artifact_id="reviewed-report",
            name="reviewed-report.md",
            media_type="text/markdown",
            content=b"# Exact preview\nSensitive bounded body.\n",
        )
        call = call_for(write_step, arguments)
        payload = broker.approval_payload(
            call,
            arguments,
            approval_id="approval-reviewed-report",
            reason="Review the exact target and content.",
            expires_at=100.0,
        )
        self.assertEqual(payload.target.reference, "reviewed-report")
        self.assertEqual(payload.target.label, "reviewed-report.md")
        self.assertEqual(
            payload.preview.content_sha256,
            hashlib.sha256(arguments.content).hexdigest(),
        )
        self.assertEqual(
            payload.request.preview_digests,
            (
                payload.target.target_digest,
                payload.preview.preview_digest,
            ),
        )
        run.request_approval(call, payload.request, now=10.0)
        run.reject_approval(
            payload.request.approval_id,
            payload.request.action_digest,
            now=11.0,
        )
        self.assertEqual(run.state, TaskState.FAILED)
        self.assertEqual(run.result_code, "approval_rejected")
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "not running",
        ):
            await broker.execute(call, arguments)
        self.assertEqual(workspace.verify(), (0, 0))
        self.assertFalse(
            (
                Path(self.temporary.name).absolute()
                / "adopted-artifacts"
            ).exists()
        )

    async def test_expired_approval_produces_no_write(self):
        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        broker, run, workspace = self.create_broker(
            (write_step, verify_step)
        )
        arguments = ArtifactWriteArguments(
            artifact_id="expired-report",
            name="expired-report.txt",
            media_type="text/plain",
            content=b"Never write this expired action.",
        )
        call = call_for(write_step, arguments)
        payload = broker.approval_payload(
            call,
            arguments,
            approval_id="approval-expired-report",
            reason="Review before expiry.",
            expires_at=20.0,
        )
        run.request_approval(call, payload.request, now=10.0)
        run.expire_approval(now=21.0)
        self.assertEqual(run.state, TaskState.EXPIRED)
        self.assertEqual(run.result_code, "approval_expired")
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "not running",
        ):
            await broker.execute(call, arguments)
        self.assertEqual(workspace.verify(), (0, 0))

    async def test_partial_output_is_labeled_never_promoted_and_cancelled(self):
        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        broker, run, workspace = self.create_broker(
            (write_step, verify_step)
        )
        arguments = ArtifactWriteArguments(
            artifact_id="partial-report",
            name="partial-report.md",
            media_type="text/markdown",
            content=b"# Partial\nOnly one of five requested records.\n",
            complete=False,
            partial_reason="source_request_limit_reached",
        )
        call = call_for(write_step, arguments)
        self.approve(run, call)
        partial = await broker.execute(call, arguments)
        self.assertEqual(partial.result.status, ToolResultStatus.PARTIAL)
        self.assertEqual(partial.result.error_code, "partial_output")
        self.assertFalse(partial.pending_artifact.complete)
        self.assertIsNone(partial.artifact)

        verify_arguments = VerifyOutputArguments(
            verifier_id=VERIFIER_ID,
            artifact_id="partial-report",
            expected_sha256=hashlib.sha256(arguments.content).hexdigest(),
        )
        with self.assertRaisesRegex(
            TaskToolBrokerValidationError,
            "dependencies",
        ):
            await broker.execute(
                call_for(verify_step, verify_arguments),
                verify_arguments,
            )
        broker.cancel()
        self.assertEqual(run.state, TaskState.CANCELLED)
        self.assertEqual(workspace.verify(), (0, 0))
        self.assertFalse(
            (
                Path(self.temporary.name).absolute()
                / "adopted-artifacts"
            ).exists()
        )

    async def test_artifact_write_read_verify_and_completion(self):
        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        read_step = declared_step(
            "read",
            DeclarativeTool.ARTIFACT_READ,
            depends_on=("verify",),
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        broker, run, _ = self.create_broker(
            (write_step, verify_step, read_step)
        )
        content = b"# Sources\n\nEvidence-backed result.\n"
        write_arguments = ArtifactWriteArguments(
            artifact_id="research-report",
            name="research-report.md",
            media_type="text/markdown",
            content=content,
        )
        write_call = call_for(write_step, write_arguments)
        self.approve(run, write_call)
        written = await broker.execute(write_call, write_arguments)
        self.assertEqual(written.result.status, ToolResultStatus.SUCCEEDED)

        verify_arguments = VerifyOutputArguments(
            verifier_id=VERIFIER_ID,
            artifact_id="research-report",
            expected_sha256=hashlib.sha256(content).hexdigest(),
            expected_media_type="text/markdown",
            minimum_bytes=16,
            maximum_bytes=1024,
            required_utf8_substrings=("# Sources", "Evidence-backed"),
        )
        verified = await broker.execute(
            call_for(verify_step, verify_arguments),
            verify_arguments,
        )
        self.assertTrue(verified.result.is_successful_verification)
        self.assertTrue(verified.artifact.adopted)
        self.assertEqual(
            verified.artifact.verification_result_id,
            verified.result.result_id,
        )

        read_arguments = ArtifactReadArguments(
            artifact_id="research-report"
        )
        read = await broker.execute(
            call_for(read_step, read_arguments),
            read_arguments,
        )
        self.assertEqual(read.content, content)
        self.assertEqual(read.artifact.artifact_id, "research-report")
        run.complete(verified.result)
        self.assertEqual(run.state, TaskState.COMPLETED)

    async def test_failed_postcondition_cannot_complete_task(self):
        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        broker, run, _ = self.create_broker(
            (write_step, verify_step)
        )
        write_arguments = ArtifactWriteArguments(
            artifact_id="report",
            name="report.txt",
            media_type="text/plain",
            content=b"actual",
        )
        write_call = call_for(write_step, write_arguments)
        self.approve(run, write_call)
        await broker.execute(write_call, write_arguments)

        verify_arguments = VerifyOutputArguments(
            verifier_id=VERIFIER_ID,
            artifact_id="report",
            expected_sha256=hashlib.sha256(b"different").hexdigest(),
        )
        verified = await broker.execute(
            call_for(verify_step, verify_arguments),
            verify_arguments,
        )
        self.assertFalse(verified.result.postcondition_met)
        self.assertFalse(verified.result.is_successful_verification)
        with self.assertRaisesRegex(ValueError, "declared verifier"):
            run.complete(verified.result)
        self.assertEqual(run.state, TaskState.RUNNING)

    async def test_research_csv_is_adopted_only_at_exact_unique_row_count(self):
        from research.csv_artifact import (
            ResearchCsvSchema,
            render_research_csv,
        )
        from tests.test_research_csv import batch, record

        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        broker, run, _ = self.create_broker(
            (write_step, verify_step)
        )
        schema = ResearchCsvSchema(("audience",))
        rendered = render_research_csv(
            batch(record("one")),
            schema,
            requested_rows=1,
        )
        write_arguments = ArtifactWriteArguments(
            artifact_id="research-csv",
            name="research.csv",
            media_type="text/csv",
            content=rendered.content,
        )
        write_call = call_for(write_step, write_arguments)
        self.approve(run, write_call)
        await broker.execute(write_call, write_arguments)
        verify_arguments = VerifyOutputArguments(
            verifier_id=VERIFIER_ID,
            artifact_id="research-csv",
            expected_sha256=rendered.sha256,
            expected_media_type="text/csv",
            maximum_bytes=64 * 1024,
            research_csv_field_ids=("audience",),
            research_csv_requested_rows=1,
        )
        verified = await broker.execute(
            call_for(verify_step, verify_arguments),
            verify_arguments,
        )
        self.assertTrue(verified.result.is_successful_verification)
        self.assertIsNotNone(verified.artifact)

        short_broker, short_run, short_workspace = self.create_broker(
            (write_step, verify_step),
            run_id="task-broker-shortfall",
        )
        short_write_call = call_for(
            write_step,
            write_arguments,
            run_id=short_run.run_id,
        )
        self.approve(short_run, short_write_call)
        await short_broker.execute(
            short_write_call,
            write_arguments,
        )
        short_verify_arguments = VerifyOutputArguments(
            verifier_id=VERIFIER_ID,
            artifact_id="research-csv",
            expected_sha256=rendered.sha256,
            expected_media_type="text/csv",
            maximum_bytes=64 * 1024,
            research_csv_field_ids=("audience",),
            research_csv_requested_rows=2,
        )
        short = await short_broker.execute(
            call_for(
                verify_step,
                short_verify_arguments,
                run_id=short_run.run_id,
            ),
            short_verify_arguments,
        )
        self.assertEqual(short.result.status, ToolResultStatus.PARTIAL)
        self.assertEqual(
            short.result.error_code,
            "research_csv_row_shortfall",
        )
        self.assertFalse(short.result.postcondition_met)
        self.assertIsNone(short.artifact)
        self.assertGreater(short_workspace.verify()[0], 0)
        short_broker.cancel()
        self.assertEqual(short_run.state, TaskState.CANCELLED)
        self.assertEqual(short_workspace.verify(), (0, 0))

    async def test_research_csv_renderer_binds_records_to_observed_sources(self):
        render_step = declared_step(
            "render",
            DeclarativeTool.RESEARCH_CSV_RENDER,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("render",),
        )
        broker, _, _ = self.create_broker((render_step, verify_step))
        source = "https://creator.example/one"
        arguments = ResearchCsvRenderArguments(
            records_json=json.dumps(
                {
                    "records": [
                        {
                            "entity": {
                                "value": "Creator one",
                                "source_urls": [source],
                            },
                            "public_url": {
                                "value": source,
                                "source_urls": [source],
                            },
                            "rationale": {
                                "value": "Matches the request.",
                                "source_urls": [source],
                            },
                            "requested_fields": {},
                        }
                    ]
                }
            ),
            source_context=(
                f"[1] Creator one — {source}\nPublic evidence."
            ),
            requested_rows=1,
            field_ids=(),
            maximum_output_bytes=64 * 1024,
        )

        result = await broker.execute(
            call_for(render_step, arguments),
            arguments,
        )

        self.assertEqual(result.result.status, ToolResultStatus.SUCCEEDED)
        self.assertIn("Creator one", result.text)
        self.assertEqual(
            result.result.output_digest,
            hashlib.sha256(result.text.encode("utf-8")).hexdigest(),
        )

    async def test_research_csv_renderer_never_pads_or_accepts_new_sources(self):
        render_step = declared_step(
            "render",
            DeclarativeTool.RESEARCH_CSV_RENDER,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("render",),
        )
        source = "https://creator.example/one"
        broker, _, _ = self.create_broker((render_step, verify_step))
        shortfall = ResearchCsvRenderArguments(
            records_json=json.dumps({"records": []}),
            source_context=f"[1] Creator one — {source}",
            requested_rows=2,
            field_ids=(),
            maximum_output_bytes=64 * 1024,
        )
        short = await broker.execute(
            call_for(render_step, shortfall),
            shortfall,
        )
        self.assertEqual(short.result.status, ToolResultStatus.PARTIAL)
        self.assertEqual(
            short.result.error_code,
            "research_csv_row_shortfall",
        )
        self.assertEqual(short.text.count("\n"), 1)

        rejected_broker, _, _ = self.create_broker(
            (render_step, verify_step),
            run_id="task-broker-invented-source",
        )
        invented = ResearchCsvRenderArguments(
            records_json=json.dumps(
                {
                    "records": [
                        {
                            "entity": {
                                "value": "Invented",
                                "source_urls": [
                                    "https://invented.example/profile"
                                ],
                            },
                            "public_url": {
                                "value": source,
                                "source_urls": [source],
                            },
                            "rationale": {
                                "value": "Invented rationale",
                                "source_urls": [source],
                            },
                            "requested_fields": {},
                        }
                    ]
                }
            ),
            source_context=f"[1] Creator one — {source}",
            requested_rows=1,
            field_ids=(),
            maximum_output_bytes=64 * 1024,
        )
        rejected = await rejected_broker.execute(
            call_for(
                render_step,
                invented,
                run_id="task-broker-invented-source",
            ),
            invented,
        )
        self.assertEqual(rejected.result.status, ToolResultStatus.FAILED)
        self.assertEqual(
            rejected.result.error_code,
            "research_csv_render_failed",
        )
        self.assertIsNone(rejected.text)

    async def test_artifact_tampering_returns_bounded_typed_failure(self):
        write_step = declared_step(
            "write",
            DeclarativeTool.ARTIFACT_WRITE,
        )
        read_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("write",),
        )
        verify_step = declared_step(
            "read",
            DeclarativeTool.ARTIFACT_READ,
            depends_on=("verify",),
        )
        broker, run, workspace = self.create_broker(
            (write_step, read_step, verify_step)
        )
        write_arguments = ArtifactWriteArguments(
            artifact_id="report",
            name="report.txt",
            media_type="text/plain",
            content=b"trusted",
        )
        write_call = call_for(write_step, write_arguments)
        self.approve(run, write_call)
        await broker.execute(write_call, write_arguments)
        artifact_path = next(
            (workspace.path / "pending-artifacts").glob("*.artifact")
        )
        artifact_path.write_bytes(b"altered")

        read_arguments = VerifyOutputArguments(
            verifier_id=VERIFIER_ID,
            artifact_id="report",
            expected_sha256=hashlib.sha256(b"trusted").hexdigest(),
        )
        result = await broker.execute(
            call_for(read_step, read_arguments),
            read_arguments,
        )
        self.assertEqual(result.result.status, ToolResultStatus.FAILED)
        self.assertEqual(
            result.result.error_code,
            "artifact_verification_input_failed",
        )
        self.assertEqual(result.result.output_bytes, 0)
        self.assertIsNone(result.content)

    async def test_network_quota_is_checked_before_second_side_effect(self):
        first_step = declared_step(
            "search-one",
            DeclarativeTool.WEB_SEARCH,
        )
        second_step = declared_step(
            "search-two",
            DeclarativeTool.WEB_SEARCH,
            depends_on=("search-one",),
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("search-two",),
        )
        broker, _, _ = self.create_broker(
            (first_step, second_step, verify_step),
            max_network_requests=1,
        )
        first_arguments = WebSearchArguments(query="first query")
        first = await broker.execute(
            call_for(first_step, first_arguments),
            first_arguments,
        )
        self.assertEqual(first.result.status, ToolResultStatus.SUCCEEDED)

        second_arguments = WebSearchArguments(query="second query")
        with self.assertRaisesRegex(
            TaskToolBrokerLimitError,
            "network",
        ):
            await broker.execute(
                call_for(second_step, second_arguments),
                second_arguments,
            )
        self.assertEqual(self.adapter_calls["search"], 1)

    async def test_web_fetch_is_typed_bounded_and_declared(self):
        fetch_step = declared_step(
            "fetch",
            DeclarativeTool.WEB_FETCH,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("fetch",),
        )
        broker, _, _ = self.create_broker((fetch_step, verify_step))
        arguments = WebFetchArguments(
            url="https://example.com/evidence",
            max_chars=512,
        )
        result = await broker.execute(
            call_for(fetch_step, arguments),
            arguments,
        )
        self.assertEqual(result.result.status, ToolResultStatus.SUCCEEDED)
        self.assertEqual(result.text, "bounded fetched page")
        self.assertEqual(self.adapter_calls["fetch"], 1)

    async def test_default_web_adapter_sanitizes_research_sources(self):
        search_step = declared_step(
            "search",
            DeclarativeTool.WEB_SEARCH,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("search",),
        )
        calls = 0

        async def bounded_search(_query: str, _max_results: int) -> str:
            nonlocal calls
            calls += 1
            return (
                "[1] Public — https://EXAMPLE.com:443/source#one\n"
                "Public evidence.\n\n"
                "[2] Private — https://127.0.0.1/admin\n"
                "Unsafe evidence."
            )

        with mock.patch(
            "research.tools._existing_bounded_search",
            new=bounded_search,
        ):
            broker, _, _ = self.create_broker(
                (search_step, verify_step),
                max_network_requests=8,
                use_default_web=True,
            )
        arguments = WebSearchArguments(
            query="bounded public evidence",
            max_results=2,
        )
        result = await broker.execute(
            call_for(search_step, arguments),
            arguments,
        )
        self.assertEqual(result.result.status, ToolResultStatus.SUCCEEDED)
        self.assertEqual(
            result.text,
            "[1] Public — https://example.com/source\nPublic evidence.",
        )
        self.assertEqual(calls, 1)

    async def test_provider_output_limit_returns_no_partial_text(self):
        model_step = declared_step(
            "generate",
            DeclarativeTool.MODEL_GENERATE,
        )
        verify_step = declared_step(
            "verify",
            DeclarativeTool.VERIFY_OUTPUT,
            depends_on=("generate",),
        )
        broker, _, _ = self.create_broker(
            (model_step, verify_step),
            max_output_bytes=16,
            model_text="x" * 32,
        )
        arguments = ModelGenerateArguments(
            prompt="Return a draft.",
            system_prompt="Return text only.",
        )
        result = await broker.execute(
            call_for(model_step, arguments),
            arguments,
        )
        self.assertEqual(result.result.status, ToolResultStatus.FAILED)
        self.assertEqual(result.result.error_code, "broker_limit_exceeded")
        self.assertEqual(result.result.output_bytes, 0)
        self.assertIsNone(result.text)

    def test_unknown_active_and_malformed_artifacts_fail_during_parsing(self):
        for name, media_type, content in (
            ("../report.txt", "text/plain", b"text"),
            ("payload.exe", "text/plain", b"text"),
            ("report.html", "text/html", b"<script>x</script>"),
            ("report.json", "application/json", b"{bad"),
        ):
            with self.subTest(name=name, media_type=media_type):
                with self.assertRaises((TypeError, ValueError)):
                    ArtifactWriteArguments(
                        artifact_id="report",
                        name=name,
                        media_type=media_type,
                        content=content,
                    )
        with self.assertRaises(ValueError):
            ArtifactReadArguments(artifact_id="../outside")
        with self.assertRaisesRegex(ValueError, "postcondition"):
            VerifyOutputArguments(
                verifier_id=VERIFIER_ID,
                artifact_id="report",
            )

    def test_shared_vocabulary_excludes_powerful_initial_tools(self):
        self.assertEqual(
            set(INITIAL_TASK_BROKER_TOOLS),
            {
                DeclarativeTool.MODEL_GENERATE,
                DeclarativeTool.WEB_SEARCH,
                DeclarativeTool.WEB_FETCH,
                DeclarativeTool.RESEARCH_CSV_RENDER,
                DeclarativeTool.ARTIFACT_READ,
                DeclarativeTool.ARTIFACT_WRITE,
                DeclarativeTool.CONNECTOR_READ,
                DeclarativeTool.VERIFY_OUTPUT,
            },
        )
        self.assertNotIn(
            DeclarativeTool.CONNECTOR_WRITE,
            INITIAL_TASK_BROKER_TOOLS,
        )
        schema_source = (ROOT / "skills" / "schema.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "from declarative_tools import DeclarativeTool, TOOL_CAPABILITIES",
            schema_source,
        )
        self.assertNotIn("class DeclarativeTool", schema_source)

    def test_broker_source_has_no_dynamic_or_powerful_host_execution_path(self):
        source = (ROOT / "tasks" / "tool_broker.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported_roots = set()
        called_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".", 1)[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
        self.assertTrue(
            {
                "subprocess",
                "connectors",
                "browser",
                "desktop",
                "uiautomation",
            }.isdisjoint(imported_roots)
        )
        self.assertTrue({"eval", "exec", "compile"}.isdisjoint(called_names))
        self.assertNotIn("shell", source.lower())
