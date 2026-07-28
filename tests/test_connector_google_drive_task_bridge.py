"""Task-grant and token-boundary tests for selected-file Drive reads."""

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
from connectors.google_drive import (
    DRIVE_SELECTED_FILE_OPERATION_ID,
    DriveFileMetadata,
    DriveNativeExportRequiredError,
    DriveSelectedFileResult,
)
from connectors.task_bridge import DriveConnectorReadBroker
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
    DriveSelectedFileArguments,
    TaskToolBroker,
    TaskToolBrokerLimitError,
    TaskToolBrokerOperationError,
    broker_arguments_digest,
)


_FILE_ID = "1AbCdEfGhIjKlMnOpQrStUvWxYz"


def _account(
    *,
    connector: ConnectorId = ConnectorId.GOOGLE_DRIVE,
) -> ConnectedAccount:
    if connector is ConnectorId.GOOGLE_DRIVE:
        capability = CapabilityId.DRIVE_SELECTED_FILE_READ
        scope = OAuthScopeId.DRIVE_SELECTED_FILE_READ
    else:
        capability = CapabilityId.GMAIL_MESSAGE_READ
        scope = OAuthScopeId.GMAIL_MESSAGES_READ
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.drive-one",
            connector=connector,
            account_reference="google.account-one",
            capabilities=frozenset({capability}),
            oauth_scopes=frozenset({scope}),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _run(
    *,
    include_drive: bool = True,
    max_network_requests: int = 2,
    max_output_bytes: int = 8192,
) -> TaskRun:
    capabilities = {CapabilityId.TASK_AGENT_RUN}
    if include_drive:
        capabilities.add(CapabilityId.DRIVE_SELECTED_FILE_READ)
    run = TaskRun(
        TaskSpec(
            run_id="run-drive",
            skill_id="clicky.drive",
            skill_version="1.0.0",
            goal="Read one explicitly selected Drive file.",
            input_digest="a" * 64,
            requested_result="Bounded selected-file text and metadata.",
            verifier_step_id="verify",
            verifier_id="drive-output-v1",
            limits=TaskLimits(
                runtime_seconds=60,
                max_tool_calls=4,
                max_network_requests=max_network_requests,
                max_output_bytes=max_output_bytes,
            ),
        ),
        CapabilityGrant(
            run_id="run-drive",
            capabilities=frozenset(capabilities),
        ),
    )
    run.start()
    return run


class _Lease:
    def __init__(self) -> None:
        self.token = SecretValue(b"drive-bridge-token")

    def close(self) -> None:
        self.token.close()


class _Accounts:
    def __init__(
        self,
        *,
        account: ConnectedAccount | None = None,
    ) -> None:
        self.account = account or _account()
        self.requests = []
        self.lease = None

    def get_account(self, authorization_id):
        self.requests.append(("account", authorization_id))
        return self.account

    def lease_access_token(self, authorization_id, capability):
        self.requests.append(("lease", authorization_id, capability))
        self.lease = _Lease()
        return self.lease


class _DriveAdapter:
    def __init__(self, account) -> None:
        self.account = account

    async def execute(self, call, request, token):
        if token.reveal() != b"drive-bridge-token":
            raise AssertionError("wrong token")
        content = "Selected Drive text"
        encoded = content.encode("utf-8")
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=DRIVE_SELECTED_FILE_OPERATION_ID,
                http_status=200,
                response_digest="b" * 64,
                response_bytes=321,
                provider_request_id="drive-selected-file-request",
            ),
            output=DriveSelectedFileResult(
                metadata=DriveFileMetadata(
                    file_id=request.selected_file_id,
                    name="selected.txt",
                    mime_type="text/plain",
                    size_bytes=len(encoded),
                    modified_time="2026-07-28T10:11:12Z",
                ),
                content_text=content,
                content_sha256=hashlib.sha256(encoded).hexdigest(),
            ),
        )


class _NativeFileAdapter:
    def __init__(self, _account) -> None:
        pass

    async def execute(self, _call, _request, _token):
        raise DriveNativeExportRequiredError(
            "Selected Google-native file requires reviewed export"
        )


def _arguments(*, maximum_response_bytes: int = 4096):
    return DriveSelectedFileArguments(
        authorization_id="oauth.drive-one",
        selected_file_id=_FILE_ID,
        maximum_response_bytes=maximum_response_bytes,
    )


def _call(
    run: TaskRun,
    arguments: DriveSelectedFileArguments,
) -> ToolCall:
    return ToolCall(
        call_id="call-drive",
        run_id=run.run_id,
        step_id="drive",
        tool_name=DeclarativeTool.CONNECTOR_READ.value,
        capability=CapabilityId.DRIVE_SELECTED_FILE_READ,
        arguments_digest=broker_arguments_digest(arguments),
    )


class DriveConnectorReadBrokerTests(
    unittest.IsolatedAsyncioTestCase
):
    async def test_bridge_requires_exact_grant_and_returns_bounded_evidence(
        self,
    ):
        run = _run()
        accounts = _Accounts()
        arguments = _arguments()
        bridge = DriveConnectorReadBroker(
            run,
            accounts,
            adapter_factory=_DriveAdapter,
        )

        output = await bridge(_call(run, arguments), arguments)

        rendered = json.loads(output.content)
        self.assertEqual(rendered["file_id"], _FILE_ID)
        self.assertEqual(rendered["content"], "Selected Drive text")
        self.assertTrue(rendered["content_untrusted"])
        self.assertEqual(
            output.provider_request_id,
            "drive-selected-file-request",
        )
        self.assertEqual(
            accounts.requests,
            [
                ("account", "oauth.drive-one"),
                (
                    "lease",
                    "oauth.drive-one",
                    CapabilityId.DRIVE_SELECTED_FILE_READ,
                ),
            ],
        )
        self.assertTrue(accounts.lease.token.closed)
        self.assertNotIn("drive-bridge-token", repr(output))

    async def test_missing_grant_or_changed_digest_fails_before_account_access(
        self,
    ):
        arguments = _arguments()
        for run, digest in (
            (_run(include_drive=False), broker_arguments_digest(arguments)),
            (_run(), "0" * 64),
        ):
            accounts = _Accounts()
            call = _call(run, arguments)
            call = ToolCall(
                call_id=call.call_id,
                run_id=call.run_id,
                step_id=call.step_id,
                tool_name=call.tool_name,
                capability=call.capability,
                arguments_digest=digest,
            )
            bridge = DriveConnectorReadBroker(
                run,
                accounts,
                adapter_factory=_DriveAdapter,
            )
            with self.subTest(digest=digest), self.assertRaisesRegex(
                TaskToolBrokerOperationError,
                "connector_read_not_supported",
            ):
                await bridge(call, arguments)
            self.assertEqual(accounts.requests, [])

    async def test_wrong_account_does_not_fallback_to_another_google_service(
        self,
    ):
        run = _run()
        accounts = _Accounts(account=_account(connector=ConnectorId.GMAIL))
        arguments = _arguments()
        bridge = DriveConnectorReadBroker(
            run,
            accounts,
            adapter_factory=_DriveAdapter,
        )

        with self.assertRaisesRegex(
            TaskToolBrokerOperationError,
            "connector_not_authorized",
        ):
            await bridge(_call(run, arguments), arguments)
        self.assertEqual(
            accounts.requests,
            [("account", "oauth.drive-one")],
        )

    async def test_native_file_uses_stable_separate_export_error(self):
        run = _run()
        accounts = _Accounts()
        arguments = _arguments()
        bridge = DriveConnectorReadBroker(
            run,
            accounts,
            adapter_factory=_NativeFileAdapter,
        )

        with self.assertRaisesRegex(
            TaskToolBrokerOperationError,
            "drive_native_export_required",
        ):
            await bridge(_call(run, arguments), arguments)
        self.assertTrue(accounts.lease.token.closed)


class DriveTaskToolBrokerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()

    def _broker(
        self,
        *,
        max_network_requests: int = 2,
        max_output_bytes: int = 8192,
    ):
        run = _run(
            max_network_requests=max_network_requests,
            max_output_bytes=max_output_bytes,
        )
        read_step = DeclaredToolStep(
            skill_id="clicky.drive",
            skill_version="1.0.0",
            step_id="drive",
            tool=DeclarativeTool.CONNECTOR_READ,
            capability=CapabilityId.DRIVE_SELECTED_FILE_READ,
            connector=ConnectorId.GOOGLE_DRIVE,
            output_id="drive_result",
        )
        verify_step = DeclaredToolStep(
            skill_id="clicky.drive",
            skill_version="1.0.0",
            step_id="verify",
            tool=DeclarativeTool.VERIFY_OUTPUT,
            capability=CapabilityId.TASK_AGENT_RUN,
            output_id="verified",
            depends_on=("drive",),
        )
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=self.root
            / f"workspace-{max_network_requests}-{max_output_bytes}",
        )
        self.addCleanup(workspace.cleanup)
        accounts = _Accounts()
        broker = TaskToolBroker(
            run,
            workspace,
            (read_step, verify_step),
            connector_read=DriveConnectorReadBroker(
                run,
                accounts,
                adapter_factory=_DriveAdapter,
            ),
        )
        return broker, run, accounts

    async def test_broker_counts_two_provider_requests_and_returns_json(self):
        broker, run, accounts = self._broker()
        arguments = _arguments()

        result = await broker.execute(_call(run, arguments), arguments)

        self.assertEqual(result.result.status, ToolResultStatus.SUCCEEDED)
        self.assertEqual(
            json.loads(result.text)["file_id"],
            _FILE_ID,
        )
        self.assertEqual(result.provider_response_bytes, 321)
        self.assertTrue(accounts.lease.token.closed)

    async def test_broker_fails_before_provider_when_two_calls_exceed_quota(
        self,
    ):
        broker, run, accounts = self._broker(max_network_requests=1)
        arguments = _arguments()

        with self.assertRaisesRegex(
            TaskToolBrokerLimitError,
            "network-request",
        ):
            await broker.execute(_call(run, arguments), arguments)
        self.assertEqual(accounts.requests, [])


if __name__ == "__main__":
    unittest.main()
