"""Task grants, approval preview, and token tests for Slides export."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from capability_registry import (
    AccountAuthorization,
    CapabilityGrant,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
)
from connectors.base import (
    ConnectedAccount,
    ConnectionHealth,
    ConnectorCallResult,
    ConnectorExecution,
    ConnectorProviderId,
    SecretValue,
)
from connectors.google_slides import (
    GOOGLE_SLIDES_EXPORT_OPERATION_ID,
    GoogleSlidesExportResult,
)
from connectors.task_bridge import GoogleSlidesConnectorWriteBroker
from declarative_tools import DeclarativeTool
from slides_contracts import parse_validated_slide_specification
from tasks.coordinator import TaskWorkspace
from tasks.models import (
    Artifact,
    TaskLimits,
    TaskRun,
    TaskSpec,
    TaskState,
    ToolCall,
    ToolResultStatus,
)
from tasks.policy import WorkerPolicy
from tasks.tool_broker import (
    ConnectorReadOutput,
    DeclaredToolStep,
    ResolvedSlidesExportArguments,
    SlidesExportArguments,
    TaskToolBroker,
    TaskToolBrokerLimitError,
    TaskToolBrokerValidationError,
    broker_action_digest,
    broker_arguments_digest,
)


SOURCE = (
    b'{"schema_version":1,"slides":['
    b'{"text":"First body","title":"First"},'
    b'{"text":"Second body","title":"Second"}'
    b'],"title":"Reviewed deck"}'
)
SOURCE_SHA256 = hashlib.sha256(SOURCE).hexdigest()


def _run(*, max_network_requests: int = 6) -> TaskRun:
    run_id = f"run-slides-{max_network_requests}"
    run = TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.slides_export",
            skill_version="1.0.0",
            goal="Export one verified local presentation specification.",
            input_digest="a" * 64,
            requested_result="Verified presentation receipt.",
            verifier_step_id="verify",
            verifier_id="slides-output-v1",
            limits=TaskLimits(
                runtime_seconds=60,
                max_tool_calls=4,
                max_network_requests=max_network_requests,
                max_output_bytes=2 * 1024 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.LOCAL_ARTIFACT_READ,
                    CapabilityId.SLIDES_PRESENTATION_WRITE,
                }
            ),
        ),
    )
    run.start()
    return run


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.slides-one",
            connector=ConnectorId.GOOGLE_SLIDES,
            account_reference="google.slides-one",
            capabilities=frozenset(
                {CapabilityId.SLIDES_PRESENTATION_WRITE}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.SLIDES_PRESENTATIONS_WRITE}
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _artifact() -> Artifact:
    return Artifact(
        artifact_id="presentation-spec",
        run_id="run-presentation-source",
        source_call_id="call-presentation-source",
        name="presentation.json",
        media_type="application/json",
        byte_count=len(SOURCE),
        sha256=SOURCE_SHA256,
        verification_result_id="result-presentation-verified",
        verification_evidence_digest="b" * 64,
    )


def _write_adopted(root: Path, artifact: Artifact, content: bytes) -> None:
    run_directory = (
        root
        / (
            "task-"
            + hashlib.sha256(artifact.run_id.encode("utf-8")).hexdigest()[:32]
        )
    )
    run_directory.mkdir(parents=True)
    filename = (
        hashlib.sha256(artifact.artifact_id.encode("utf-8")).hexdigest()
        + ".artifact"
    )
    (run_directory / filename).write_bytes(content)


class _Lease:
    def __init__(self) -> None:
        self.token = SecretValue(b"slides-bridge-token")

    def close(self) -> None:
        self.token.close()


class _Accounts:
    def __init__(self) -> None:
        self.account = _account()
        self.requests = []
        self.lease = None

    def get_account(self, authorization_id):
        self.requests.append(("account", authorization_id))
        return self.account

    def lease_access_token(self, authorization_id, capability):
        self.requests.append(("lease", authorization_id, capability))
        self.lease = _Lease()
        return self.lease


class _WriteAdapter:
    def __init__(self, account) -> None:
        self.account = account

    async def execute(self, call, request, token):
        if token.reveal() != b"slides-bridge-token":
            raise AssertionError("wrong token")
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=GOOGLE_SLIDES_EXPORT_OPERATION_ID,
                http_status=200,
                response_digest="c" * 64,
                response_bytes=1234,
                provider_request_id="slides-readback-request",
            ),
            output=GoogleSlidesExportResult(
                presentation_id="presentation_123",
                title=request.specification.title,
                presentation_url=(
                    "https://docs.google.com/presentation/d/"
                    "presentation_123/edit"
                ),
                slide_titles=request.specification.slide_titles,
                source_sha256=request.specification.source_sha256,
                idempotency_status="created",
                provider_request_ids=(
                    "drive-list",
                    "slides-readback",
                ),
            ),
        )


def _arguments() -> SlidesExportArguments:
    return SlidesExportArguments(
        authorization_id="oauth.slides-one",
        source_artifact_id="presentation-spec",
        source_sha256=SOURCE_SHA256,
        idempotency_key="run.slides-export-1",
        maximum_response_bytes=4096,
    )


def _tool_call(run: TaskRun, arguments: SlidesExportArguments) -> ToolCall:
    return ToolCall(
        call_id="call-slides",
        run_id=run.run_id,
        step_id="export",
        tool_name=DeclarativeTool.CONNECTOR_WRITE.value,
        capability=CapabilityId.SLIDES_PRESENTATION_WRITE,
        arguments_digest=broker_arguments_digest(arguments),
        action_digest=broker_action_digest(
            call_id="call-slides",
            run_id=run.run_id,
            step_id="export",
            tool=DeclarativeTool.CONNECTOR_WRITE,
            capability=CapabilityId.SLIDES_PRESENTATION_WRITE,
            arguments=arguments,
        ),
    )


class GoogleSlidesTaskBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_bridge_requires_resolved_spec_and_closes_scoped_token(self):
        run = _run()
        accounts = _Accounts()
        arguments = _arguments()
        resolved = ResolvedSlidesExportArguments(
            request=arguments,
            specification=parse_validated_slide_specification(
                SOURCE,
                expected_sha256=SOURCE_SHA256,
            ),
        )

        output = await GoogleSlidesConnectorWriteBroker(
            run,
            accounts,
            adapter_factory=_WriteAdapter,
        )(_tool_call(run, arguments), resolved)

        payload = json.loads(output.content)
        self.assertEqual(payload["slide_count"], 2)
        self.assertEqual(payload["slide_titles"], ["First", "Second"])
        self.assertTrue(payload["verified"])
        self.assertNotIn("First body", output.content.decode("utf-8"))
        self.assertTrue(accounts.lease.token.closed)
        self.assertEqual(
            accounts.requests[-1],
            (
                "lease",
                "oauth.slides-one",
                CapabilityId.SLIDES_PRESENTATION_WRITE,
            ),
        )


class GoogleSlidesTaskToolBrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()
        self.artifact = _artifact()
        _write_adopted(self.root / "artifacts", self.artifact, SOURCE)
        self.arguments = _arguments()

    def _broker(self, *, max_network_requests=6, connector_write=None):
        run = _run(max_network_requests=max_network_requests)
        write_step = DeclaredToolStep(
            skill_id=run.spec.skill_id,
            skill_version=run.spec.skill_version,
            step_id="export",
            tool=DeclarativeTool.CONNECTOR_WRITE,
            capability=CapabilityId.SLIDES_PRESENTATION_WRITE,
            connector=ConnectorId.GOOGLE_SLIDES,
            output_id="export_result",
            approval_id="approve-export",
        )
        verify_step = DeclaredToolStep(
            skill_id=run.spec.skill_id,
            skill_version=run.spec.skill_version,
            step_id="verify",
            tool=DeclarativeTool.VERIFY_OUTPUT,
            capability=CapabilityId.TASK_AGENT_RUN,
            output_id="verified",
            depends_on=("export",),
        )
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=self.root / f"workspaces-{max_network_requests}",
        )
        self.addCleanup(workspace.cleanup)
        broker = TaskToolBroker(
            run,
            workspace,
            (write_step, verify_step),
            connector_write=connector_write,
            artifact_root=self.root / "artifacts",
            source_artifacts=(self.artifact,),
        )
        return broker, run, _tool_call(run, self.arguments)

    async def test_exact_preview_and_approval_precede_resolved_export(self):
        received = []

        async def connector_write(_call, arguments):
            received.append(arguments)
            return ConnectorReadOutput(
                content=json.dumps(
                    {
                        "idempotency_status": "created",
                        "presentation_id": "presentation_123",
                        "presentation_url": (
                            "https://docs.google.com/presentation/d/"
                            "presentation_123/edit"
                        ),
                        "provider_request_ids": ["request-1"],
                        "slide_count": 2,
                        "slide_titles": ["First", "Second"],
                        "source_sha256": SOURCE_SHA256,
                        "title": "Reviewed deck",
                        "verified": True,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
                provider_response_digest="d" * 64,
                provider_response_bytes=4096,
                provider_request_id="slides-provider-request",
            )

        broker, run, call = self._broker(
            connector_write=connector_write
        )
        payload = broker.approval_payload(
            call,
            self.arguments,
            approval_id="approve-export",
            reason="Review exact deck content and destination.",
            expires_at=100.0,
        )
        preview = json.loads(payload.preview.excerpt)
        self.assertEqual(
            preview["destination_account_authorization_id"],
            "oauth.slides-one",
        )
        self.assertEqual(preview["title"], "Reviewed deck")
        self.assertEqual(
            preview["slides"][0],
            {"text": "First body", "title": "First"},
        )
        self.assertNotIn(
            "run.slides-export-1",
            payload.preview.excerpt,
        )
        self.assertEqual(payload.preview.content_sha256, SOURCE_SHA256)
        run.request_approval(call, payload.request, now=10.0)
        run.approve(
            payload.request.approval_id,
            payload.request.action_digest,
            now=11.0,
        )

        execution = await broker.execute(call, self.arguments)

        self.assertEqual(execution.result.status, ToolResultStatus.SUCCEEDED)
        self.assertEqual(len(received), 1)
        self.assertIsInstance(
            received[0],
            ResolvedSlidesExportArguments,
        )
        self.assertEqual(
            received[0].specification.slides[0].text,
            "First body",
        )

    async def test_six_requests_are_reserved_before_external_write(self):
        calls = []

        async def connector_write(_call, _arguments):
            calls.append(True)
            raise AssertionError("connector write must not run")

        broker, run, call = self._broker(
            max_network_requests=5,
            connector_write=connector_write,
        )
        with self.assertRaises(TaskToolBrokerLimitError):
            broker.approval_payload(
                call,
                self.arguments,
                approval_id="approve-export",
                reason="Review exact deck content and destination.",
                expires_at=100.0,
            )

        self.assertEqual(calls, [])
        self.assertEqual(run.state, TaskState.RUNNING)

    async def test_tampered_source_fails_before_approval(self):
        artifact_path = next(
            (self.root / "artifacts").rglob("*.artifact")
        )
        artifact_path.write_bytes(SOURCE + b"tampered")
        broker, _run_value, call = self._broker()

        with self.assertRaises(TaskToolBrokerValidationError):
            broker.approval_payload(
                call,
                self.arguments,
                approval_id="approve-export",
                reason="Review exact deck content and destination.",
                expires_at=100.0,
            )


@unittest.skipUnless(
    importlib.util.find_spec("pydantic") is not None,
    "Pydantic is unavailable in the dependency-free test environment",
)
class GoogleSlidesDeclarativeCallerTests(unittest.IsolatedAsyncioTestCase):
    async def test_runner_reads_source_then_waits_for_exact_external_approval(
        self,
    ):
        from skills.declarative_runner import (
            DeclarativeSkillRunner,
            RunnerDisposition,
        )
        from tests.test_declarative_skill_runner import (
            definition_payload,
            make_run,
            parsed_definition,
        )

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).absolute()
        artifact = _artifact()
        _write_adopted(root / "artifacts", artifact, SOURCE)
        payload = definition_payload()
        payload["output"] = {
            "output_type": "artifact",
            "media_type": "application/json",
            "fields": [],
        }
        payload["steps"] = [
            {
                "step_id": "read_source",
                "tool": DeclarativeTool.ARTIFACT_READ.value,
                "capability": CapabilityId.LOCAL_ARTIFACT_READ.value,
                "depends_on": [],
                "arguments": [
                    {
                        "argument_id": "artifact_id",
                        "source": "literal",
                        "reference": None,
                        "value": artifact.artifact_id,
                    }
                ],
                "output_id": "source_artifact",
                "connector": None,
                "approval_id": None,
            },
            {
                "step_id": "export",
                "tool": DeclarativeTool.CONNECTOR_WRITE.value,
                "capability": (
                    CapabilityId.SLIDES_PRESENTATION_WRITE.value
                ),
                "depends_on": ["read_source"],
                "arguments": [
                    {
                        "argument_id": "authorization_id",
                        "source": "literal",
                        "reference": None,
                        "value": "oauth.slides-one",
                    },
                    {
                        "argument_id": "source_artifact_id",
                        "source": "step_output",
                        "reference": "source_artifact",
                        "value": None,
                    },
                    {
                        "argument_id": "source_sha256",
                        "source": "literal",
                        "reference": None,
                        "value": SOURCE_SHA256,
                    },
                    {
                        "argument_id": "idempotency_key",
                        "source": "literal",
                        "reference": None,
                        "value": "runner.slides-export-1",
                    },
                ],
                "output_id": "export_result",
                "connector": ConnectorId.GOOGLE_SLIDES.value,
                "approval_id": "approve-export",
            },
            {
                "step_id": "write_receipt",
                "tool": DeclarativeTool.ARTIFACT_WRITE.value,
                "capability": CapabilityId.LOCAL_ARTIFACT_WRITE.value,
                "depends_on": ["export"],
                "arguments": [
                    {
                        "argument_id": "artifact_id",
                        "source": "literal",
                        "reference": None,
                        "value": "slides-receipt",
                    },
                    {
                        "argument_id": "name",
                        "source": "literal",
                        "reference": None,
                        "value": "slides-receipt.json",
                    },
                    {
                        "argument_id": "media_type",
                        "source": "literal",
                        "reference": None,
                        "value": "application/json",
                    },
                    {
                        "argument_id": "content",
                        "source": "step_output",
                        "reference": "export_result",
                        "value": None,
                    },
                ],
                "output_id": "receipt_artifact",
                "connector": None,
                "approval_id": "approve-receipt",
            },
            {
                "step_id": "verify",
                "tool": DeclarativeTool.VERIFY_OUTPUT.value,
                "capability": CapabilityId.TASK_AGENT_RUN.value,
                "depends_on": ["write_receipt"],
                "arguments": [
                    {
                        "argument_id": "artifact_id",
                        "source": "step_output",
                        "reference": "receipt_artifact",
                        "value": None,
                    }
                ],
                "output_id": "verified_receipt",
                "connector": None,
                "approval_id": None,
            },
        ]
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.LOCAL_ARTIFACT_READ.value,
            CapabilityId.SLIDES_PRESENTATION_WRITE.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_SLIDES.value,
                "capabilities": [
                    CapabilityId.SLIDES_PRESENTATION_WRITE.value
                ],
                "oauth_scopes": [
                    OAuthScopeId.SLIDES_PRESENTATIONS_WRITE.value
                ],
            }
        ]
        payload["approvals"] = [
            {
                "approval_id": "approve-export",
                "capability": (
                    CapabilityId.SLIDES_PRESENTATION_WRITE.value
                ),
                "reason": "Review exact presentation export.",
                "preview_references": ["step.source_artifact"],
            },
            {
                "approval_id": "approve-receipt",
                "capability": CapabilityId.LOCAL_ARTIFACT_WRITE.value,
                "reason": "Review the verified export receipt.",
                "preview_references": ["step.export_result"],
            },
        ]
        payload["limits"] = {
            "runtime_seconds": 60,
            "max_tool_calls": 4,
            "max_network_requests": 6,
            "max_output_bytes": 2 * 1024 * 1024,
        }
        definition = parsed_definition(payload)
        inputs = {"query": "export the adopted presentation"}
        run = make_run(definition, inputs)
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=root / "workspaces",
        )
        self.addCleanup(workspace.cleanup)
        received = []

        async def connector_write(_call, arguments):
            received.append(arguments)
            return ConnectorReadOutput(
                content=json.dumps(
                    {
                        "idempotency_status": "created",
                        "presentation_id": "presentation_123",
                        "presentation_url": (
                            "https://docs.google.com/presentation/d/"
                            "presentation_123/edit"
                        ),
                        "provider_request_ids": ["request-1"],
                        "slide_count": 2,
                        "slide_titles": ["First", "Second"],
                        "source_sha256": SOURCE_SHA256,
                        "title": "Reviewed deck",
                        "verified": True,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
                provider_response_digest="d" * 64,
                provider_response_bytes=2048,
                provider_request_id="slides-readback",
            )

        runner = DeclarativeSkillRunner.create(
            definition,
            run,
            workspace,
            connector_write=connector_write,
            artifact_root=root / "artifacts",
            source_artifacts=(artifact,),
        )
        runner.start(inputs)

        read = await runner.advance(now=1.0)
        self.assertEqual(read.disposition, RunnerDisposition.RUNNING)
        external_wait = await runner.advance(now=2.0)
        self.assertEqual(
            external_wait.disposition,
            RunnerDisposition.WAITING_FOR_APPROVAL,
        )
        external_preview = json.loads(
            external_wait.pending_approval.preview.excerpt
        )
        self.assertEqual(
            external_preview["slides"][0],
            {"text": "First body", "title": "First"},
        )
        external = external_wait.pending_approval.request
        run.approve(
            external.approval_id,
            external.action_digest,
            now=3.0,
        )
        external_done = await runner.advance(now=3.0)
        self.assertEqual(
            external_done.disposition,
            RunnerDisposition.RUNNING,
        )
        self.assertEqual(len(received), 1)
        self.assertIsInstance(
            received[0],
            ResolvedSlidesExportArguments,
        )
        receipt_wait = await runner.advance(now=4.0)
        self.assertEqual(
            receipt_wait.disposition,
            RunnerDisposition.WAITING_FOR_APPROVAL,
        )
        receipt = receipt_wait.pending_approval.request
        run.approve(
            receipt.approval_id,
            receipt.action_digest,
            now=5.0,
        )
        await runner.advance(now=5.0)
        completed = await runner.advance(now=6.0)

        self.assertEqual(
            completed.disposition,
            RunnerDisposition.COMPLETED,
        )
        self.assertEqual(len(completed.artifacts), 1)
        self.assertEqual(
            completed.artifacts[0].name,
            "slides-receipt.json",
        )


if __name__ == "__main__":
    unittest.main()
