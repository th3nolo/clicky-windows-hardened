"""Task broker authority and quota tests for Notion read/local draft."""

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
from connectors.notion import (
    MAX_NOTION_PROVIDER_REQUESTS,
    NOTION_SELECTED_PAGE_OPERATION_ID,
    NotionPageBlock,
    NotionSelectedPageResult,
)
from connectors.task_bridge import NotionConnectorReadBroker
from declarative_tools import DeclarativeTool
from tasks.coordinator import TaskWorkspace
from tasks.models import (
    TaskLimits,
    TaskRun,
    TaskSpec,
    ToolCall,
    ToolResultStatus,
)
from tasks.policy import WorkerPolicy
from tasks.tool_broker import (
    DeclaredToolStep,
    NotionDraftRenderArguments,
    NotionSelectedPageArguments,
    TaskToolBroker,
    TaskToolBrokerLimitError,
    broker_arguments_digest,
)


PAGE_ID = "11111111-1111-4111-8111-111111111111"
BLOCK_ID = "22222222-2222-4222-8222-222222222222"


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.NOTION,
        authorization=AccountAuthorization(
            authorization_id="oauth.notion-one",
            connector=ConnectorId.NOTION,
            account_reference="notion.workspace-one",
            capabilities=frozenset({CapabilityId.NOTION_PAGE_READ}),
            oauth_scopes=frozenset({OAuthScopeId.NOTION_PAGES_READ}),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _run(*, max_network_requests: int) -> TaskRun:
    run = TaskRun(
        TaskSpec(
            run_id="run-notion",
            skill_id="clicky.notion",
            skill_version="1.0.0",
            goal="Read one selected Notion page.",
            input_digest="a" * 64,
            requested_result="Bounded selected-page content.",
            verifier_step_id="verify",
            verifier_id="notion-output-v1",
            limits=TaskLimits(
                runtime_seconds=60,
                max_tool_calls=4,
                max_network_requests=max_network_requests,
                max_output_bytes=1024 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id="run-notion",
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.NOTION_PAGE_READ,
                }
            ),
        ),
    )
    run.start()
    return run


class _Lease:
    def __init__(self) -> None:
        self.token = SecretValue(b"notion-bridge-token")

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
        if token.reveal() != b"notion-bridge-token":
            raise AssertionError("wrong token")
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=NOTION_SELECTED_PAGE_OPERATION_ID,
                http_status=200,
                response_digest="b" * 64,
                response_bytes=321,
                provider_request_id="notion-read-request",
            ),
            output=NotionSelectedPageResult(
                page_id=request.selected_page_id,
                title="Selected page",
                blocks=(
                    NotionPageBlock(
                        block_id=BLOCK_ID,
                        parent_block_id=request.selected_page_id,
                        depth=0,
                        block_type="paragraph",
                        text="Selected content",
                        has_children=False,
                    ),
                ),
                content_truncated=False,
                provider_requests=2,
            ),
        )


class NotionTaskBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_bridge_requires_exact_grant_and_closes_token_lease(self):
        run = _run(max_network_requests=MAX_NOTION_PROVIDER_REQUESTS)
        accounts = _Accounts()
        arguments = NotionSelectedPageArguments(
            authorization_id="oauth.notion-one",
            selected_page_id=PAGE_ID,
            maximum_response_bytes=4096,
        )
        call = ToolCall(
            call_id="call-read",
            run_id=run.run_id,
            step_id="page",
            tool_name=DeclarativeTool.CONNECTOR_READ.value,
            capability=CapabilityId.NOTION_PAGE_READ,
            arguments_digest=broker_arguments_digest(arguments),
        )
        bridge = NotionConnectorReadBroker(
            run,
            accounts,
            adapter_factory=_ReadAdapter,
        )

        output = await bridge(call, arguments)

        self.assertEqual(json.loads(output.content)["page_id"], PAGE_ID)
        self.assertEqual(output.provider_request_id, "notion-read-request")
        self.assertTrue(accounts.lease.token.closed)
        self.assertNotIn("Selected content", repr(arguments))


class NotionTaskToolBrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()

    def _read_broker(self, *, maximum: int, connector_read):
        run = _run(max_network_requests=maximum)
        arguments = NotionSelectedPageArguments(
            authorization_id="oauth.notion-one",
            selected_page_id=PAGE_ID,
            maximum_response_bytes=4096,
        )
        step = DeclaredToolStep(
            skill_id="clicky.notion",
            skill_version="1.0.0",
            step_id="page",
            tool=DeclarativeTool.CONNECTOR_READ,
            capability=CapabilityId.NOTION_PAGE_READ,
            connector=ConnectorId.NOTION,
            output_id="page_content",
        )
        verify_step = DeclaredToolStep(
            skill_id="clicky.notion",
            skill_version="1.0.0",
            step_id="verify",
            tool=DeclarativeTool.VERIFY_OUTPUT,
            capability=CapabilityId.TASK_AGENT_RUN,
            output_id="verified",
            depends_on=("page",),
        )
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=self.root / f"workspace-read-{maximum}",
        )
        self.addCleanup(workspace.cleanup)
        broker = TaskToolBroker(
            run,
            workspace,
            (step, verify_step),
            connector_read=connector_read,
            artifact_root=self.root / f"artifacts-read-{maximum}",
        )
        call = ToolCall(
            call_id="call-page",
            run_id=run.run_id,
            step_id="page",
            tool_name=DeclarativeTool.CONNECTOR_READ.value,
            capability=CapabilityId.NOTION_PAGE_READ,
            arguments_digest=broker_arguments_digest(arguments),
        )
        return broker, call, arguments

    async def test_reserves_full_recursive_budget_before_provider_access(self):
        calls = []

        async def connector_read(_call, _arguments):
            calls.append(True)
            raise AssertionError("provider must not run")

        broker, call, arguments = self._read_broker(
            maximum=MAX_NOTION_PROVIDER_REQUESTS - 1,
            connector_read=connector_read,
        )

        with self.assertRaises(TaskToolBrokerLimitError):
            await broker.execute(call, arguments)
        self.assertEqual(calls, [])

    async def test_local_draft_render_is_inert_and_uses_no_connector_adapter(self):
        limits = TaskLimits(
            runtime_seconds=60,
            max_tool_calls=2,
            max_network_requests=0,
            max_output_bytes=8192,
        )
        run = TaskRun(
            TaskSpec(
                run_id="run-notion-draft",
                skill_id="clicky.notion-draft",
                skill_version="1.0.0",
                goal="Render one local Notion draft.",
                input_digest="c" * 64,
                requested_result="Validated unpublished JSON.",
                verifier_step_id="verify",
                verifier_id="notion-draft-v1",
                limits=limits,
            ),
            CapabilityGrant(
                run_id="run-notion-draft",
                capabilities=frozenset({CapabilityId.TASK_AGENT_RUN}),
            ),
        )
        run.start()
        step = DeclaredToolStep(
            skill_id="clicky.notion-draft",
            skill_version="1.0.0",
            step_id="draft",
            tool=DeclarativeTool.NOTION_DRAFT_RENDER,
            capability=CapabilityId.TASK_AGENT_RUN,
            output_id="draft_json",
        )
        verify_step = DeclaredToolStep(
            skill_id="clicky.notion-draft",
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
            root=self.root / "workspace-draft",
        )
        self.addCleanup(workspace.cleanup)
        broker = TaskToolBroker(
            run,
            workspace,
            (step, verify_step),
            artifact_root=self.root / "artifacts-draft",
        )
        arguments = NotionDraftRenderArguments(
            title="Reviewed draft",
            blocks_json=json.dumps(
                [{"type": "paragraph", "text": "Local only"}]
            ),
            intended_parent_page_id=PAGE_ID,
        )
        call = ToolCall(
            call_id="call-draft",
            run_id=run.run_id,
            step_id="draft",
            tool_name=DeclarativeTool.NOTION_DRAFT_RENDER.value,
            capability=CapabilityId.TASK_AGENT_RUN,
            arguments_digest=broker_arguments_digest(arguments),
        )

        execution = await broker.execute(call, arguments)

        self.assertEqual(execution.result.status, ToolResultStatus.SUCCEEDED)
        payload = json.loads(execution.text)
        self.assertEqual(payload["state"], "local_unpublished")
        self.assertFalse(payload["publication_authorized"])
        self.assertEqual(payload["blocks"][0]["text"], "Local only")
        self.assertNotIn("Local only", repr(arguments))


if __name__ == "__main__":
    unittest.main()
