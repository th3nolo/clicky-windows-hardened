"""Task-grant and token-boundary tests for Calendar connector reads."""

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
from connectors.google_calendar import (
    CALENDAR_AVAILABILITY_OPERATION_ID,
    CalendarAvailability,
    CalendarAvailabilityResult,
)
from connectors.task_bridge import CalendarConnectorReadBroker
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
    CalendarAvailabilityArguments,
    ConnectorReadOutput,
    DeclaredToolStep,
    TaskToolBroker,
    TaskToolBrokerOperationError,
    broker_arguments_digest,
)


TIME_MIN = "2026-07-27T12:00:00Z"
TIME_MAX = "2026-07-28T12:00:00Z"


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.calendar-one",
            connector=ConnectorId.GOOGLE_CALENDAR,
            account_reference="google.calendar-one",
            capabilities=frozenset(
                {CapabilityId.CALENDAR_EVENT_READ}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.CALENDAR_EVENTS_READ}
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _task_run(*, include_calendar: bool = True) -> TaskRun:
    capabilities = {CapabilityId.TASK_AGENT_RUN}
    if include_calendar:
        capabilities.add(CapabilityId.CALENDAR_EVENT_READ)
    run = TaskRun(
        TaskSpec(
            run_id="run-calendar",
            skill_id="clicky.calendar",
            skill_version="1.0.0",
            goal="Read selected Calendar availability.",
            input_digest="a" * 64,
            requested_result="Selected free/busy intervals only.",
            verifier_step_id="verify",
            verifier_id="calendar-output-v1",
            limits=TaskLimits(
                runtime_seconds=60,
                max_tool_calls=4,
                max_network_requests=1,
                max_output_bytes=8192,
            ),
        ),
        CapabilityGrant(
            run_id="run-calendar",
            capabilities=frozenset(capabilities),
        ),
    )
    run.start()
    return run


class _Lease:
    def __init__(self) -> None:
        self.token = SecretValue(b"bridge-access-token")

    def close(self) -> None:
        self.token.close()


class _AccountService:
    def __init__(self) -> None:
        self.account = _account()
        self.lease = None
        self.requests = []

    def get_account(self, authorization_id):
        self.requests.append(("account", authorization_id))
        return self.account

    def lease_access_token(self, authorization_id, capability):
        self.requests.append(("lease", authorization_id, capability))
        self.lease = _Lease()
        return self.lease


class _CalendarAdapter:
    def __init__(self, account) -> None:
        self.account = account
        self.calls = []

    async def execute(self, call, request, access_token):
        self.calls.append(
            (call, request, access_token.reveal())
        )
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=CALENDAR_AVAILABILITY_OPERATION_ID,
                http_status=200,
                response_digest="b" * 64,
                response_bytes=321,
                provider_request_id="provider-request-1",
            ),
            output=CalendarAvailabilityResult(
                time_min=TIME_MIN,
                time_max=TIME_MAX,
                calendars=(
                    CalendarAvailability(
                        calendar_id="primary",
                        busy=(),
                    ),
                ),
            ),
        )


class CalendarConnectorReadBrokerTests(
    unittest.IsolatedAsyncioTestCase
):
    async def test_bridge_leases_token_and_returns_content_free_evidence(self):
        accounts = _AccountService()
        adapters = []

        def adapter_factory(account):
            adapter = _CalendarAdapter(account)
            adapters.append(adapter)
            return adapter

        bridge = CalendarConnectorReadBroker(
            _task_run(),
            accounts,
            adapter_factory=adapter_factory,
        )
        arguments = CalendarAvailabilityArguments(
            authorization_id="oauth.calendar-one",
            selected_calendar_ids=("primary",),
            time_min=TIME_MIN,
            time_max=TIME_MAX,
            maximum_response_bytes=4096,
        )
        task_call = ToolCall(
            call_id="call-calendar",
            run_id="run-calendar",
            step_id="calendar",
            tool_name=DeclarativeTool.CONNECTOR_READ.value,
            capability=CapabilityId.CALENDAR_EVENT_READ,
            arguments_digest=broker_arguments_digest(arguments),
        )

        output = await bridge(task_call, arguments)

        self.assertIsInstance(output, ConnectorReadOutput)
        self.assertEqual(
            output.provider_request_id,
            "provider-request-1",
        )
        self.assertEqual(output.provider_response_bytes, 321)
        self.assertEqual(
            json.loads(output.content),
            {
                "calendars": [
                    {"busy": [], "calendar_id": "primary"}
                ],
                "time_max": TIME_MAX,
                "time_min": TIME_MIN,
            },
        )
        self.assertTrue(accounts.lease.token.closed)
        self.assertEqual(
            adapters[0].calls[0][2],
            b"bridge-access-token",
        )
        self.assertNotIn(b"bridge-access-token", output.content)
        self.assertNotIn("bridge-access-token", repr(output))

    async def test_bridge_rejects_missing_run_grant_before_account_or_token(self):
        accounts = _AccountService()
        bridge = CalendarConnectorReadBroker(
            _task_run(include_calendar=False),
            accounts,
        )
        arguments = CalendarAvailabilityArguments(
            authorization_id="oauth.calendar-one",
            selected_calendar_ids=("primary",),
            time_min=TIME_MIN,
            time_max=TIME_MAX,
            maximum_response_bytes=4096,
        )
        task_call = ToolCall(
            call_id="call-calendar",
            run_id="run-calendar",
            step_id="calendar",
            tool_name=DeclarativeTool.CONNECTOR_READ.value,
            capability=CapabilityId.CALENDAR_EVENT_READ,
            arguments_digest=broker_arguments_digest(arguments),
        )

        with self.assertRaisesRegex(
            TaskToolBrokerOperationError,
            "connector_read_not_supported",
        ):
            await bridge(task_call, arguments)

        self.assertEqual(accounts.requests, [])


class TaskBrokerCalendarReadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()
        self.arguments = CalendarAvailabilityArguments(
            authorization_id="oauth.calendar-one",
            selected_calendar_ids=("primary",),
            time_min=TIME_MIN,
            time_max=TIME_MAX,
            maximum_response_bytes=4096,
        )
        self.calendar_step = DeclaredToolStep(
            skill_id="clicky.calendar",
            skill_version="1.0.0",
            step_id="calendar",
            tool=DeclarativeTool.CONNECTOR_READ,
            capability=CapabilityId.CALENDAR_EVENT_READ,
            connector=ConnectorId.GOOGLE_CALENDAR,
            output_id="availability",
        )
        self.verify_step = DeclaredToolStep(
            skill_id="clicky.calendar",
            skill_version="1.0.0",
            step_id="verify",
            tool=DeclarativeTool.VERIFY_OUTPUT,
            capability=CapabilityId.TASK_AGENT_RUN,
            output_id="verified",
            depends_on=("calendar",),
        )

    def _broker(self, connector_read):
        limits = TaskLimits(
            runtime_seconds=60,
            max_tool_calls=4,
            max_network_requests=1,
            max_output_bytes=8192,
        )
        run = TaskRun(
            TaskSpec(
                run_id="run-calendar",
                skill_id="clicky.calendar",
                skill_version="1.0.0",
                goal="Read selected Calendar availability.",
                input_digest="a" * 64,
                requested_result="Selected free/busy intervals only.",
                verifier_step_id="verify",
                verifier_id="calendar-output-v1",
                limits=limits,
            ),
            CapabilityGrant(
                run_id="run-calendar",
                capabilities=frozenset(
                    {
                        CapabilityId.TASK_AGENT_RUN,
                        CapabilityId.CALENDAR_EVENT_READ,
                    }
                ),
            ),
        )
        run.start()
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(limits),
            root=self.root / "workspaces",
        )
        self.addCleanup(workspace.cleanup)
        return (
            TaskToolBroker(
                run,
                workspace,
                (self.calendar_step, self.verify_step),
                connector_read=connector_read,
                artifact_root=self.root / "artifacts",
            ),
            run,
        )

    def _call(self) -> ToolCall:
        return ToolCall(
            call_id="call-calendar",
            run_id="run-calendar",
            step_id="calendar",
            tool_name=DeclarativeTool.CONNECTOR_READ.value,
            capability=CapabilityId.CALENDAR_EVENT_READ,
            arguments_digest=broker_arguments_digest(self.arguments),
        )

    async def test_exact_run_grant_executes_one_bounded_connector_read(self):
        calls = []
        content = (
            b'{"calendars":[{"busy":[],"calendar_id":"primary"}],'
            b'"time_max":"2026-07-28T12:00:00Z",'
            b'"time_min":"2026-07-27T12:00:00Z"}'
        )

        async def connector_read(call, arguments):
            calls.append((call, arguments))
            return ConnectorReadOutput(
                content=content,
                provider_response_digest="b" * 64,
                provider_response_bytes=321,
                provider_request_id="provider-request-1",
            )

        broker, _run = self._broker(connector_read)
        execution = await broker.execute(self._call(), self.arguments)

        self.assertEqual(
            execution.result.status,
            ToolResultStatus.SUCCEEDED,
        )
        self.assertEqual(
            execution.result.output_digest,
            hashlib.sha256(content).hexdigest(),
        )
        self.assertEqual(
            execution.result.provider_response_digest,
            "b" * 64,
        )
        self.assertEqual(
            execution.result.provider_response_bytes,
            321,
        )
        self.assertEqual(
            execution.result.provider_request_id,
            "provider-request-1",
        )
        self.assertEqual(
            execution.provider_response_digest,
            "b" * 64,
        )
        self.assertEqual(
            execution.provider_request_id,
            "provider-request-1",
        )
        self.assertEqual(len(calls), 1)

    async def test_missing_adapter_fails_without_connector_side_effect(self):
        broker, _run = self._broker(None)

        execution = await broker.execute(self._call(), self.arguments)

        self.assertEqual(
            execution.result.status,
            ToolResultStatus.FAILED,
        )
        self.assertEqual(
            execution.result.error_code,
            "connector_read_unavailable",
        )

    async def test_cancellation_discards_late_connector_output_and_evidence(self):
        holder = {}

        async def connector_read(_call, _arguments):
            holder["broker"].cancel()
            return ConnectorReadOutput(
                content=b'{"calendars":[]}',
                provider_response_digest="b" * 64,
                provider_response_bytes=321,
                provider_request_id="late-provider-request",
            )

        broker, run = self._broker(connector_read)
        holder["broker"] = broker

        execution = await broker.execute(self._call(), self.arguments)

        self.assertEqual(run.state.value, "cancelled")
        self.assertEqual(
            execution.result.status,
            ToolResultStatus.CANCELLED,
        )
        self.assertEqual(execution.result.output_bytes, 0)
        self.assertIsNone(execution.result.provider_response_digest)
        self.assertIsNone(execution.provider_response_digest)

    def test_mismatched_connector_or_unapproved_read_operation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unavailable"):
            DeclaredToolStep(
                skill_id="clicky.calendar",
                skill_version="1.0.0",
                step_id="calendar",
                tool=DeclarativeTool.CONNECTOR_READ,
                capability=CapabilityId.GMAIL_MESSAGE_READ,
                connector=ConnectorId.GMAIL,
                output_id="messages",
            )
        with self.assertRaisesRegex(ValueError, "unavailable"):
            DeclaredToolStep(
                skill_id="clicky.calendar",
                skill_version="1.0.0",
                step_id="calendar",
                tool=DeclarativeTool.CONNECTOR_READ,
                capability=CapabilityId.CALENDAR_EVENT_READ,
                connector=ConnectorId.GMAIL,
                output_id="availability",
            )


if __name__ == "__main__":
    unittest.main()
