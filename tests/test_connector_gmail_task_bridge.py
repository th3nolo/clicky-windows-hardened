"""Task grant, approval, and token boundary tests for Gmail operations."""

from __future__ import annotations

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
from connectors.gmail import (
    GMAIL_CREATE_DRAFT_OPERATION_ID,
    GMAIL_SELECTED_THREAD_OPERATION_ID,
    GmailDraftResult,
    GmailMessageResult,
    GmailSelectedThreadResult,
)
from connectors.task_bridge import (
    GmailConnectorReadBroker,
    GmailConnectorWriteBroker,
)
from declarative_tools import DeclarativeTool
from tasks.coordinator import TaskWorkspace
from tasks.models import (
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
    GmailDraftArguments,
    GmailSelectedThreadArguments,
    TaskToolBroker,
    TaskToolBrokerLimitError,
    broker_action_digest,
    broker_arguments_digest,
)


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.gmail-one",
            connector=ConnectorId.GMAIL,
            account_reference="google.gmail-one",
            capabilities=frozenset(
                {
                    CapabilityId.GMAIL_MESSAGE_READ,
                    CapabilityId.GMAIL_DRAFT_WRITE,
                }
            ),
            oauth_scopes=frozenset(
                {
                    OAuthScopeId.GMAIL_MESSAGES_READ,
                    OAuthScopeId.GMAIL_DRAFTS_WRITE,
                }
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _run(
    *,
    capability: CapabilityId,
    max_network_requests: int,
) -> TaskRun:
    run = TaskRun(
        TaskSpec(
            run_id="run-gmail",
            skill_id="clicky.gmail",
            skill_version="1.0.0",
            goal="Read a selected thread or create one reviewed draft.",
            input_digest="a" * 64,
            requested_result="Exact bounded Gmail result.",
            verifier_step_id="verify",
            verifier_id="gmail-output-v1",
            limits=TaskLimits(
                runtime_seconds=60,
                max_tool_calls=4,
                max_network_requests=max_network_requests,
                max_output_bytes=1024 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id="run-gmail",
            capabilities=frozenset(
                {CapabilityId.TASK_AGENT_RUN, capability}
            ),
        ),
    )
    run.start()
    return run


class _Lease:
    def __init__(self) -> None:
        self.token = SecretValue(b"gmail-bridge-token")

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


class _ReadAdapter:
    def __init__(self, account) -> None:
        self.account = account

    async def execute(self, call, request, token):
        if token.reveal() != b"gmail-bridge-token":
            raise AssertionError("wrong token")
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=GMAIL_SELECTED_THREAD_OPERATION_ID,
                http_status=200,
                response_digest="b" * 64,
                response_bytes=321,
                provider_request_id="gmail-read-request",
            ),
            output=GmailSelectedThreadResult(
                thread_id=request.selected_thread_id,
                messages=(
                    GmailMessageResult(
                        message_id="message-1",
                        thread_id=request.selected_thread_id,
                        headers=(("subject", "Selected"),),
                        body_text="Selected body",
                        body_truncated=False,
                    ),
                ),
            ),
        )


class _WriteAdapter:
    def __init__(self, account) -> None:
        self.account = account

    async def execute(self, call, request, token):
        if token.reveal() != b"gmail-bridge-token":
            raise AssertionError("wrong token")
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=GMAIL_CREATE_DRAFT_OPERATION_ID,
                http_status=200,
                response_digest="c" * 64,
                response_bytes=654,
                provider_request_id="gmail-write-request",
            ),
            output=GmailDraftResult(
                draft_id="draft-1",
                message_id="message-1",
                thread_id="thread-1",
            ),
        )


class GmailTaskBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_bridge_requires_exact_thread_grant_and_leases_token(self):
        run = _run(
            capability=CapabilityId.GMAIL_MESSAGE_READ,
            max_network_requests=1,
        )
        accounts = _Accounts()
        arguments = GmailSelectedThreadArguments(
            authorization_id="oauth.gmail-one",
            selected_thread_id="thread-1",
            maximum_response_bytes=4096,
        )
        call = ToolCall(
            call_id="call-read",
            run_id=run.run_id,
            step_id="thread",
            tool_name=DeclarativeTool.CONNECTOR_READ.value,
            capability=CapabilityId.GMAIL_MESSAGE_READ,
            arguments_digest=broker_arguments_digest(arguments),
        )
        bridge = GmailConnectorReadBroker(
            run,
            accounts,
            adapter_factory=_ReadAdapter,
        )

        output = await bridge(call, arguments)

        self.assertEqual(
            json.loads(output.content)["thread_id"],
            "thread-1",
        )
        self.assertEqual(output.provider_request_id, "gmail-read-request")
        self.assertTrue(accounts.lease.token.closed)

    async def test_write_bridge_returns_only_verified_draft_evidence(self):
        run = _run(
            capability=CapabilityId.GMAIL_DRAFT_WRITE,
            max_network_requests=2,
        )
        accounts = _Accounts()
        arguments = GmailDraftArguments(
            authorization_id="oauth.gmail-one",
            to=("recipient@example.com",),
            cc=(),
            bcc=(),
            subject="Reviewed subject",
            body_text="Reviewed body",
            maximum_response_bytes=4096,
        )
        call = ToolCall(
            call_id="call-write",
            run_id=run.run_id,
            step_id="draft",
            tool_name=DeclarativeTool.CONNECTOR_WRITE.value,
            capability=CapabilityId.GMAIL_DRAFT_WRITE,
            arguments_digest=broker_arguments_digest(arguments),
            action_digest=broker_action_digest(
                call_id="call-write",
                run_id=run.run_id,
                step_id="draft",
                tool=DeclarativeTool.CONNECTOR_WRITE,
                capability=CapabilityId.GMAIL_DRAFT_WRITE,
                arguments=arguments,
            ),
        )
        bridge = GmailConnectorWriteBroker(
            run,
            accounts,
            adapter_factory=_WriteAdapter,
        )

        output = await bridge(call, arguments)

        self.assertEqual(
            json.loads(output.content),
            {
                "draft_id": "draft-1",
                "message_id": "message-1",
                "thread_id": "thread-1",
                "verified": True,
            },
        )
        self.assertNotIn(b"Reviewed body", output.content)
        self.assertTrue(accounts.lease.token.closed)


class GmailTaskToolBrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()
        self.arguments = GmailDraftArguments(
            authorization_id="oauth.gmail-one",
            to=("recipient@example.com",),
            cc=("copy@example.com",),
            bcc=(),
            subject="Reviewed subject",
            body_text="Reviewed body",
            maximum_response_bytes=4096,
        )

    def _broker(self, *, max_network_requests=2, connector_write=None):
        limits = TaskLimits(
            runtime_seconds=60,
            max_tool_calls=4,
            max_network_requests=max_network_requests,
            max_output_bytes=8192,
        )
        run = TaskRun(
            TaskSpec(
                run_id="run-gmail",
                skill_id="clicky.gmail",
                skill_version="1.0.0",
                goal="Create one reviewed Gmail draft.",
                input_digest="a" * 64,
                requested_result="Verified draft evidence.",
                verifier_step_id="verify",
                verifier_id="gmail-output-v1",
                limits=limits,
            ),
            CapabilityGrant(
                run_id="run-gmail",
                capabilities=frozenset(
                    {
                        CapabilityId.TASK_AGENT_RUN,
                        CapabilityId.GMAIL_DRAFT_WRITE,
                    }
                ),
            ),
        )
        run.start()
        write_step = DeclaredToolStep(
            skill_id="clicky.gmail",
            skill_version="1.0.0",
            step_id="draft",
            tool=DeclarativeTool.CONNECTOR_WRITE,
            capability=CapabilityId.GMAIL_DRAFT_WRITE,
            connector=ConnectorId.GMAIL,
            output_id="draft_result",
            approval_id="approve-draft",
        )
        verify_step = DeclaredToolStep(
            skill_id="clicky.gmail",
            skill_version="1.0.0",
            step_id="verify",
            tool=DeclarativeTool.VERIFY_OUTPUT,
            capability=CapabilityId.TASK_AGENT_RUN,
            output_id="verified",
            depends_on=("draft",),
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
        )
        call = ToolCall(
            call_id="call-draft",
            run_id=run.run_id,
            step_id="draft",
            tool_name=DeclarativeTool.CONNECTOR_WRITE.value,
            capability=CapabilityId.GMAIL_DRAFT_WRITE,
            arguments_digest=broker_arguments_digest(self.arguments),
            action_digest=broker_action_digest(
                call_id="call-draft",
                run_id=run.run_id,
                step_id="draft",
                tool=DeclarativeTool.CONNECTOR_WRITE,
                capability=CapabilityId.GMAIL_DRAFT_WRITE,
                arguments=self.arguments,
            ),
        )
        return broker, run, call

    async def test_exact_full_preview_and_approval_precede_one_draft_write(self):
        calls = []

        async def connector_write(call, arguments):
            calls.append((call, arguments))
            return ConnectorReadOutput(
                content=(
                    b'{"draft_id":"draft-1","message_id":"message-1",'
                    b'"thread_id":"thread-1","verified":true}'
                ),
                provider_response_digest="d" * 64,
                provider_response_bytes=654,
                provider_request_id="gmail-provider-request",
            )

        broker, run, call = self._broker(
            connector_write=connector_write
        )
        payload = broker.approval_payload(
            call,
            self.arguments,
            approval_id="approve-draft",
            reason="Review exact recipients, subject, and body.",
            expires_at=100.0,
        )

        self.assertEqual(payload.target.kind.value, "api_mutation")
        self.assertIn("recipient@example.com", payload.preview.excerpt)
        self.assertIn("copy@example.com", payload.preview.excerpt)
        self.assertIn("Reviewed subject", payload.preview.excerpt)
        self.assertIn("Reviewed body", payload.preview.excerpt)
        self.assertNotIn("recipient@example.com", repr(self.arguments))
        self.assertNotIn("Reviewed subject", repr(self.arguments))
        self.assertNotIn("Reviewed body", repr(self.arguments))
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
            "gmail-provider-request",
        )

    async def test_two_request_write_budget_is_enforced_before_side_effect(self):
        calls = []

        async def connector_write(_call, _arguments):
            calls.append(True)
            raise AssertionError("connector write must not run")

        broker, run, call = self._broker(
            max_network_requests=1,
            connector_write=connector_write,
        )
        with self.assertRaises(TaskToolBrokerLimitError):
            broker.approval_payload(
                call,
                self.arguments,
                approval_id="approve-draft",
                reason="Review exact recipients, subject, and body.",
                expires_at=100.0,
            )

        self.assertEqual(calls, [])
        self.assertEqual(run.state, TaskState.RUNNING)


if __name__ == "__main__":
    unittest.main()
