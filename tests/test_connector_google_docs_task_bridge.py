"""Task grants, exact approvals, and token boundaries for Google Docs."""

from __future__ import annotations

import hashlib
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
from connectors.google_docs import (
    GOOGLE_DOCS_CREATE_OPERATION_ID,
    GOOGLE_DOCS_READ_OPERATION_ID,
    GoogleDocsCreateResult,
)
from connectors.task_bridge import (
    GoogleDocsConnectorReadBroker,
    GoogleDocsConnectorWriteBroker,
)
from declarative_tools import DeclarativeTool
from docs_contracts import (
    GoogleDocsDocument,
    GoogleDocsParagraph,
    GoogleDocsTab,
)
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
    DocsCreateArguments,
    DocsSelectedDocumentArguments,
    TaskToolBroker,
    TaskToolBrokerLimitError,
    broker_action_digest,
    broker_arguments_digest,
)


DOCUMENT_ID = "document_123"
BODY = "Exact reviewed body\nSecond line"
BODY_SHA256 = hashlib.sha256(BODY.encode("utf-8")).hexdigest()


def _run(
    capability: CapabilityId,
    *,
    max_network_requests: int,
) -> TaskRun:
    suffix = "read" if capability is CapabilityId.DOCS_DOCUMENT_READ else "create"
    run_id = f"run-docs-{suffix}-{max_network_requests}"
    run = TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id=f"clicky.docs_{suffix}",
            skill_version="1.0.0",
            goal="Use one exact Google document.",
            input_digest="a" * 64,
            requested_result="Bounded verified Google Docs result.",
            verifier_step_id="verify",
            verifier_id=f"docs-{suffix}-v1",
            limits=TaskLimits(
                runtime_seconds=60,
                max_tool_calls=4,
                max_network_requests=max_network_requests,
                max_output_bytes=1024 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(
                {CapabilityId.TASK_AGENT_RUN, capability}
            ),
        ),
    )
    run.start()
    return run


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.docs-one",
            connector=ConnectorId.GOOGLE_DOCS,
            account_reference="google.docs-one",
            capabilities=frozenset(
                {
                    CapabilityId.DOCS_DOCUMENT_CREATE,
                    CapabilityId.DOCS_DOCUMENT_READ,
                }
            ),
            oauth_scopes=frozenset(
                {
                    OAuthScopeId.DOCS_DOCUMENT_CREATE,
                    OAuthScopeId.DOCS_SELECTED_DOCUMENT_READ,
                }
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


class _Lease:
    def __init__(self) -> None:
        self.token = SecretValue(b"docs-bridge-token")

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


def _document() -> GoogleDocsDocument:
    paragraph = GoogleDocsParagraph(
        text="Selected text",
        named_style_type="NORMAL_TEXT",
        bullet=False,
    )
    return GoogleDocsDocument(
        document_id=DOCUMENT_ID,
        title="Selected memo",
        tabs=(
            GoogleDocsTab(
                tab_id="t.0",
                title="Tab 1",
                parent_tab_id=None,
                paragraphs=(paragraph,),
                content_text="Selected text",
                content_sha256=hashlib.sha256(
                    b"Selected text"
                ).hexdigest(),
            ),
        ),
        revision_id="revision-1",
    )


class _Adapter:
    def __init__(self, account) -> None:
        self.account = account

    async def execute(self, call, request, token):
        if token.reveal() != b"docs-bridge-token":
            raise AssertionError("wrong token")
        if call.capability is CapabilityId.DOCS_DOCUMENT_READ:
            operation_id = GOOGLE_DOCS_READ_OPERATION_ID
            output = _document()
        else:
            operation_id = GOOGLE_DOCS_CREATE_OPERATION_ID
            output = GoogleDocsCreateResult(
                document_id=DOCUMENT_ID,
                document_url=(
                    f"https://docs.google.com/document/d/{DOCUMENT_ID}/edit"
                ),
                title=request.title,
                body_bytes=len(request.body_text.encode("utf-8")),
                body_sha256=request.body_sha256,
                idempotency_status="created",
                provider_request_ids=("drive-list", "docs-readback"),
            )
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=operation_id,
                http_status=200,
                response_digest="b" * 64,
                response_bytes=1024,
                provider_request_id="docs-request",
            ),
            output=output,
        )


def _read_arguments() -> DocsSelectedDocumentArguments:
    return DocsSelectedDocumentArguments(
        authorization_id="oauth.docs-one",
        selected_document_id=DOCUMENT_ID,
        maximum_response_bytes=64 * 1024,
    )


def _create_arguments() -> DocsCreateArguments:
    return DocsCreateArguments(
        authorization_id="oauth.docs-one",
        title="Reviewed memo",
        body_text=BODY,
        idempotency_key="run.docs-create-1",
        maximum_response_bytes=64 * 1024,
    )


def _call(
    run: TaskRun,
    arguments,
    capability: CapabilityId,
    *,
    approval: bool,
) -> ToolCall:
    call_id = "call-docs"
    step_id = "docs"
    tool = (
        DeclarativeTool.CONNECTOR_WRITE
        if approval
        else DeclarativeTool.CONNECTOR_READ
    )
    action_digest = (
        broker_action_digest(
            call_id=call_id,
            run_id=run.run_id,
            step_id=step_id,
            tool=tool,
            capability=capability,
            arguments=arguments,
        )
        if approval
        else None
    )
    return ToolCall(
        call_id=call_id,
        run_id=run.run_id,
        step_id=step_id,
        tool_name=tool.value,
        capability=capability,
        arguments_digest=broker_arguments_digest(arguments),
        action_digest=action_digest,
    )


class GoogleDocsTaskBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_bridge_requires_exact_grant_and_closes_token(self):
        run = _run(
            CapabilityId.DOCS_DOCUMENT_READ,
            max_network_requests=1,
        )
        arguments = _read_arguments()
        accounts = _Accounts()
        output = await GoogleDocsConnectorReadBroker(
            run,
            accounts,
            adapter_factory=_Adapter,
        )(
            _call(
                run,
                arguments,
                CapabilityId.DOCS_DOCUMENT_READ,
                approval=False,
            ),
            arguments,
        )

        rendered = json.loads(output.content)
        self.assertEqual(rendered["document_id"], DOCUMENT_ID)
        self.assertTrue(rendered["content_untrusted"])
        self.assertTrue(accounts.lease.token.closed)
        self.assertEqual(
            accounts.requests[-1][2],
            CapabilityId.DOCS_DOCUMENT_READ,
        )

    async def test_create_bridge_preserves_exact_body_and_closes_token(self):
        run = _run(
            CapabilityId.DOCS_DOCUMENT_CREATE,
            max_network_requests=6,
        )
        arguments = _create_arguments()
        accounts = _Accounts()
        output = await GoogleDocsConnectorWriteBroker(
            run,
            accounts,
            adapter_factory=_Adapter,
        )(
            _call(
                run,
                arguments,
                CapabilityId.DOCS_DOCUMENT_CREATE,
                approval=True,
            ),
            arguments,
        )

        rendered = json.loads(output.content)
        self.assertEqual(rendered["body_sha256"], BODY_SHA256)
        self.assertTrue(rendered["verified"])
        self.assertTrue(accounts.lease.token.closed)


class GoogleDocsTaskBrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()

    def _broker(self, *, max_network_requests=6, connector_write=None):
        run = _run(
            CapabilityId.DOCS_DOCUMENT_CREATE,
            max_network_requests=max_network_requests,
        )
        step = DeclaredToolStep(
            skill_id=run.spec.skill_id,
            skill_version=run.spec.skill_version,
            step_id="docs",
            tool=DeclarativeTool.CONNECTOR_WRITE,
            capability=CapabilityId.DOCS_DOCUMENT_CREATE,
            output_id="receipt",
            connector=ConnectorId.GOOGLE_DOCS,
            approval_id="approve-docs",
        )
        verify_step = DeclaredToolStep(
            skill_id=run.spec.skill_id,
            skill_version=run.spec.skill_version,
            step_id="verify",
            tool=DeclarativeTool.VERIFY_OUTPUT,
            capability=CapabilityId.TASK_AGENT_RUN,
            output_id="verified",
            depends_on=("docs",),
        )
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=self.root / f"workspace-{max_network_requests}",
        )
        self.addCleanup(workspace.cleanup)
        return (
            TaskToolBroker(
                run,
                workspace,
                (step, verify_step),
                connector_write=connector_write,
            ),
            run,
        )

    async def test_full_preview_is_bound_before_connector_write(self):
        received = []

        async def write(_call_value, arguments):
            received.append(arguments)
            content = json.dumps(
                {
                    "body_bytes": len(BODY.encode("utf-8")),
                    "body_sha256": BODY_SHA256,
                    "document_id": DOCUMENT_ID,
                    "document_url": (
                        f"https://docs.google.com/document/d/{DOCUMENT_ID}/edit"
                    ),
                    "idempotency_status": "created",
                    "provider_request_ids": ["docs-request"],
                    "title": "Reviewed memo",
                    "verified": True,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            return ConnectorReadOutput(
                content=content,
                provider_response_digest="c" * 64,
                provider_response_bytes=2048,
                provider_request_id="docs-request",
            )

        broker, run = self._broker(connector_write=write)
        arguments = _create_arguments()
        call = _call(
            run,
            arguments,
            CapabilityId.DOCS_DOCUMENT_CREATE,
            approval=True,
        )
        payload = broker.approval_payload(
            call,
            arguments,
            approval_id="approve-docs",
            reason="Review exact Google document content.",
            expires_at=100.0,
        )

        self.assertEqual(
            json.loads(payload.preview.excerpt),
            {"body_text": BODY, "title": "Reviewed memo"},
        )
        self.assertEqual(payload.preview.content_sha256, BODY_SHA256)
        self.assertNotIn(
            arguments.idempotency_key,
            payload.preview.excerpt,
        )
        run.request_approval(call, payload.request, now=10.0)
        run.approve(
            payload.request.approval_id,
            payload.request.action_digest,
            now=11.0,
        )
        execution = await broker.execute(call, arguments)

        self.assertEqual(execution.result.status, ToolResultStatus.SUCCEEDED)
        self.assertEqual(received, [arguments])

    async def test_six_requests_are_reserved_before_external_write(self):
        calls = []

        async def write(_call_value, _arguments):
            calls.append(True)
            raise AssertionError("write must not run")

        broker, run = self._broker(
            max_network_requests=5,
            connector_write=write,
        )
        arguments = _create_arguments()
        call = _call(
            run,
            arguments,
            CapabilityId.DOCS_DOCUMENT_CREATE,
            approval=True,
        )
        with self.assertRaises(TaskToolBrokerLimitError):
            broker.approval_payload(
                call,
                arguments,
                approval_id="approve-docs",
                reason="Review exact Google document content.",
                expires_at=100.0,
            )
        self.assertEqual(calls, [])
        self.assertEqual(run.state, TaskState.RUNNING)


if __name__ == "__main__":
    unittest.main()
