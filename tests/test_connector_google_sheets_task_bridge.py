"""Task grant, adopted-artifact, approval, and token tests for Sheets."""

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
from connectors.google_sheets import (
    GOOGLE_SHEETS_EXPORT_OPERATION_ID,
    GoogleSheetsExportResult,
)
from connectors.task_bridge import GoogleSheetsConnectorWriteBroker
from declarative_tools import DeclarativeTool
from sheets_contracts import MAX_SHEETS_PROVIDER_RESPONSE_BYTES
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
    ResolvedSheetsExportArguments,
    SheetsExportArguments,
    TaskToolBroker,
    TaskToolBrokerLimitError,
    TaskToolBrokerValidationError,
    broker_action_digest,
    broker_arguments_digest,
)
SOURCE = (
    b"entity,public_url\r\n"
    b"Alpha,https://alpha.example/\r\n"
    b"Beta,https://beta.example/\r\n"
)
SOURCE_SHA256 = hashlib.sha256(SOURCE).hexdigest()


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.sheets-one",
            connector=ConnectorId.GOOGLE_SHEETS,
            account_reference="google.sheets-one",
            capabilities=frozenset(
                {CapabilityId.SHEETS_VALUES_WRITE}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.SHEETS_VALUES_WRITE}
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _run(*, max_network_requests: int = 6) -> TaskRun:
    limits = TaskLimits(
        runtime_seconds=60,
        max_tool_calls=4,
        max_network_requests=max_network_requests,
        max_output_bytes=2 * 1024 * 1024,
    )
    run = TaskRun(
        TaskSpec(
            run_id=f"run-sheets-{max_network_requests}",
            skill_id="clicky.sheets_export",
            skill_version="1.0.0",
            goal="Export one verified local table.",
            input_digest="a" * 64,
            requested_result="Verified spreadsheet receipt.",
            verifier_step_id="verify",
            verifier_id="sheets-output-v1",
            limits=limits,
        ),
        CapabilityGrant(
            run_id=f"run-sheets-{max_network_requests}",
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.LOCAL_ARTIFACT_READ,
                    CapabilityId.SHEETS_VALUES_WRITE,
                }
            ),
        ),
    )
    run.start()
    return run


def _artifact() -> Artifact:
    return Artifact(
        artifact_id="research-csv",
        run_id="run-research-source",
        source_call_id="call-research-source",
        name="research.csv",
        media_type="text/csv",
        byte_count=len(SOURCE),
        sha256=SOURCE_SHA256,
        verification_result_id="result-research-verified",
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
        self.token = SecretValue(b"sheets-bridge-token")

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
        if token.reveal() != b"sheets-bridge-token":
            raise AssertionError("wrong token")
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=GOOGLE_SHEETS_EXPORT_OPERATION_ID,
                http_status=200,
                response_digest="c" * 64,
                response_bytes=1234,
                provider_request_id="sheets-readback-request",
            ),
            output=GoogleSheetsExportResult(
                spreadsheet_id="spreadsheet_123",
                title=request.title,
                spreadsheet_url=(
                    "https://docs.google.com/spreadsheets/d/"
                    "spreadsheet_123/edit"
                ),
                columns=request.table.columns,
                row_count=request.table.data_row_count,
                column_count=request.table.column_count,
                source_sha256=request.table.source_sha256,
                idempotency_status="created",
                provider_request_ids=("drive-list", "sheets-readback"),
            ),
        )


class GoogleSheetsTaskBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_bridge_requires_resolved_table_and_leases_scoped_token(self):
        from sheets_contracts import parse_validated_sheet_csv

        run = _run()
        accounts = _Accounts()
        request = SheetsExportArguments(
            authorization_id="oauth.sheets-one",
            source_artifact_id="research-csv",
            source_sha256=SOURCE_SHA256,
            title="Reviewed research",
            idempotency_key="run.export-1",
        )
        resolved = ResolvedSheetsExportArguments(
            request=request,
            table=parse_validated_sheet_csv(
                SOURCE,
                expected_sha256=SOURCE_SHA256,
            ),
        )
        call = ToolCall(
            call_id="call-sheets",
            run_id=run.run_id,
            step_id="export",
            tool_name=DeclarativeTool.CONNECTOR_WRITE.value,
            capability=CapabilityId.SHEETS_VALUES_WRITE,
            arguments_digest=broker_arguments_digest(request),
            action_digest=broker_action_digest(
                call_id="call-sheets",
                run_id=run.run_id,
                step_id="export",
                tool=DeclarativeTool.CONNECTOR_WRITE,
                capability=CapabilityId.SHEETS_VALUES_WRITE,
                arguments=request,
            ),
        )
        bridge = GoogleSheetsConnectorWriteBroker(
            run,
            accounts,
            adapter_factory=_WriteAdapter,
        )

        output = await bridge(call, resolved)

        payload = json.loads(output.content)
        self.assertEqual(payload["row_count"], 2)
        self.assertEqual(payload["column_count"], 2)
        self.assertTrue(payload["verified"])
        self.assertNotIn("Alpha", output.content.decode("utf-8"))
        self.assertTrue(accounts.lease.token.closed)

        class _CapturingAdapter(_WriteAdapter):
            async def execute(self, connector_call, export_request, token):
                self.maximum_response_bytes = (
                    connector_call.maximum_response_bytes
                )
                return await super().execute(
                    connector_call,
                    export_request,
                    token,
                )

        captured = []

        def capturing_factory(account):
            adapter = _CapturingAdapter(account)
            captured.append(adapter)
            return adapter

        second_bridge = GoogleSheetsConnectorWriteBroker(
            run,
            accounts,
            adapter_factory=capturing_factory,
        )
        await second_bridge(call, resolved)
        self.assertEqual(
            captured[0].maximum_response_bytes,
            MAX_SHEETS_PROVIDER_RESPONSE_BYTES,
        )


class GoogleSheetsTaskToolBrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()
        self.artifact = _artifact()
        _write_adopted(self.root / "artifacts", self.artifact, SOURCE)
        self.arguments = SheetsExportArguments(
            authorization_id="oauth.sheets-one",
            source_artifact_id=self.artifact.artifact_id,
            source_sha256=self.artifact.sha256,
            title="Reviewed research",
            idempotency_key="run.export-1",
            maximum_response_bytes=4096,
        )

    def _broker(self, *, max_network_requests=6, connector_write=None):
        run = _run(max_network_requests=max_network_requests)
        limits = run.spec.limits
        write_step = DeclaredToolStep(
            skill_id=run.spec.skill_id,
            skill_version=run.spec.skill_version,
            step_id="export",
            tool=DeclarativeTool.CONNECTOR_WRITE,
            capability=CapabilityId.SHEETS_VALUES_WRITE,
            connector=ConnectorId.GOOGLE_SHEETS,
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
            WorkerPolicy.from_task_limits(limits),
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
        call = ToolCall(
            call_id="call-export",
            run_id=run.run_id,
            step_id="export",
            tool_name=DeclarativeTool.CONNECTOR_WRITE.value,
            capability=CapabilityId.SHEETS_VALUES_WRITE,
            arguments_digest=broker_arguments_digest(self.arguments),
            action_digest=broker_action_digest(
                call_id="call-export",
                run_id=run.run_id,
                step_id="export",
                tool=DeclarativeTool.CONNECTOR_WRITE,
                capability=CapabilityId.SHEETS_VALUES_WRITE,
                arguments=self.arguments,
            ),
        )
        return broker, run, call

    async def test_exact_preview_and_approval_precede_resolved_export(self):
        calls = []

        async def connector_write(call, arguments):
            calls.append((call, arguments))
            self.assertIsInstance(
                arguments,
                ResolvedSheetsExportArguments,
            )
            self.assertEqual(arguments.table.rows[0][0], "Alpha")
            return ConnectorReadOutput(
                content=(
                    b'{"column_count":2,"columns":["entity","public_url"],'
                    b'"idempotency_status":"created",'
                    b'"provider_request_ids":["request-1"],"row_count":2,'
                    b'"source_sha256":"' + SOURCE_SHA256.encode("ascii")
                    + b'","spreadsheet_id":"spreadsheet_123",'
                    b'"spreadsheet_url":"https://docs.google.com/'
                    b'spreadsheets/d/spreadsheet_123/edit",'
                    b'"title":"Reviewed research","verified":true}'
                ),
                provider_response_digest="d" * 64,
                provider_response_bytes=4096,
                provider_request_id="sheets-provider-request",
            )

        broker, run, call = self._broker(
            connector_write=connector_write
        )
        payload = broker.approval_payload(
            call,
            self.arguments,
            approval_id="approve-export",
            reason="Review the destination and verified table shape.",
            expires_at=100.0,
        )

        preview = json.loads(payload.preview.excerpt)
        self.assertEqual(
            preview["destination_account_authorization_id"],
            "oauth.sheets-one",
        )
        self.assertEqual(preview["title"], "Reviewed research")
        self.assertEqual(preview["row_count"], 2)
        self.assertEqual(
            preview["columns"],
            ["entity", "public_url"],
        )
        self.assertEqual(payload.preview.content_sha256, SOURCE_SHA256)
        self.assertNotIn("run.export-1", payload.preview.excerpt)
        self.assertNotIn("Alpha", payload.preview.excerpt)
        run.request_approval(call, payload.request, now=10.0)
        run.approve(
            payload.request.approval_id,
            payload.request.action_digest,
            now=11.0,
        )

        execution = await broker.execute(call, self.arguments)

        self.assertEqual(execution.result.status, ToolResultStatus.SUCCEEDED)
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            execution.result.provider_request_id,
            "sheets-provider-request",
        )

    async def test_six_request_budget_is_reserved_before_external_write(self):
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
                reason="Review the destination and verified table shape.",
                expires_at=100.0,
            )

        self.assertEqual(calls, [])
        self.assertEqual(run.state, TaskState.RUNNING)

    async def test_tampered_or_unverified_source_fails_before_approval(self):
        artifact_path = next(
            (self.root / "artifacts").rglob("*.artifact")
        )
        artifact_path.write_bytes(SOURCE + b"Tampered")
        broker, _run_value, call = self._broker()

        with self.assertRaises(TaskToolBrokerValidationError):
            broker.approval_payload(
                call,
                self.arguments,
                approval_id="approve-export",
                reason="Review the destination and verified table shape.",
                expires_at=100.0,
            )


@unittest.skipUnless(
    importlib.util.find_spec("pydantic") is not None,
    "Pydantic is unavailable in the dependency-free test environment",
)
class GoogleSheetsDeclarativeCallerTests(unittest.IsolatedAsyncioTestCase):
    async def test_runner_reads_adopted_source_before_external_approval(self):
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
                "capability": CapabilityId.SHEETS_VALUES_WRITE.value,
                "depends_on": ["read_source"],
                "arguments": [
                    {
                        "argument_id": "authorization_id",
                        "source": "literal",
                        "reference": None,
                        "value": "oauth.sheets-one",
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
                        "argument_id": "title",
                        "source": "literal",
                        "reference": None,
                        "value": "Reviewed research",
                    },
                    {
                        "argument_id": "idempotency_key",
                        "source": "literal",
                        "reference": None,
                        "value": "runner.export-1",
                    },
                ],
                "output_id": "export_result",
                "connector": ConnectorId.GOOGLE_SHEETS.value,
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
                        "value": "sheets-receipt",
                    },
                    {
                        "argument_id": "name",
                        "source": "literal",
                        "reference": None,
                        "value": "sheets-receipt.json",
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
            CapabilityId.SHEETS_VALUES_WRITE.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_SHEETS.value,
                "capabilities": [CapabilityId.SHEETS_VALUES_WRITE.value],
                "oauth_scopes": [OAuthScopeId.SHEETS_VALUES_WRITE.value],
            }
        ]
        payload["approvals"] = [
            {
                "approval_id": "approve-export",
                "capability": CapabilityId.SHEETS_VALUES_WRITE.value,
                "reason": "Review exact spreadsheet export.",
                "preview_references": ["step.source_artifact"],
            },
            {
                "approval_id": "approve-receipt",
                "capability": CapabilityId.LOCAL_ARTIFACT_WRITE.value,
                "reason": "Review the local verified export receipt.",
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
        inputs = {"query": "export the adopted research table"}
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
                content=(
                    b'{"column_count":2,"columns":["entity","public_url"],'
                    b'"idempotency_status":"created",'
                    b'"provider_request_ids":["request-1"],"row_count":2,'
                    b'"source_sha256":"' + SOURCE_SHA256.encode("ascii")
                    + b'","spreadsheet_id":"spreadsheet_123",'
                    b'"spreadsheet_url":"https://docs.google.com/'
                    b'spreadsheets/d/spreadsheet_123/edit",'
                    b'"title":"Reviewed research","verified":true}'
                ),
                provider_response_digest="d" * 64,
                provider_response_bytes=2048,
                provider_request_id="sheets-readback",
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
            ResolvedSheetsExportArguments,
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
            "sheets-receipt.json",
        )


if __name__ == "__main__":
    unittest.main()
