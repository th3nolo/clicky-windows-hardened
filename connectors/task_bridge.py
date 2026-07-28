"""Trusted connector bridge for broker-authorized task calls."""

from __future__ import annotations

import hmac
from collections.abc import Callable

from capability_registry import CapabilityId, ConnectorId
from connectors.accounts import ConnectedAccountService
from connectors.base import (
    ConnectedAccount,
    ConnectorAuthorizationError,
    ConnectorCall,
    ConnectorDisconnectedError,
    ConnectorExecution,
    ConnectorInvalidGrantError,
    ConnectorRateLimitError,
    ConnectorRequestError,
    ConnectorResponseError,
    ConnectorTokenExpiredError,
    ConnectorTokenRevokedError,
)
from connectors.google_calendar import (
    CalendarAvailabilityRequest,
    CalendarAvailabilityResult,
    GoogleCalendarAvailabilityAdapter,
)
from connectors.gmail import (
    GmailDraftOutcomeUnknownError,
    GmailDraftRequest,
    GmailDraftResult,
    GmailDraftVerificationError,
    GmailSelectedThreadRequest,
    GmailSelectedThreadResult,
    GoogleGmailAdapter,
)
from connectors.token_store import ConnectorTokenNotFoundError
from tasks.models import TaskRun, TaskState, ToolCall
from tasks.tool_broker import (
    CalendarAvailabilityArguments,
    ConnectorReadOutput,
    ConnectorWriteOutput,
    GmailDraftArguments,
    GmailSelectedThreadArguments,
    TaskToolBrokerOperationError,
    broker_arguments_digest,
)


CalendarAdapterFactory = Callable[
    [ConnectedAccount],
    GoogleCalendarAvailabilityAdapter,
]
GmailAdapterFactory = Callable[[ConnectedAccount], GoogleGmailAdapter]


class CalendarConnectorReadBroker:
    """Turn one exact task grant into one scoped free/busy provider call."""

    def __init__(
        self,
        run: TaskRun,
        account_service: ConnectedAccountService | None = None,
        *,
        adapter_factory: CalendarAdapterFactory = (
            GoogleCalendarAvailabilityAdapter
        ),
    ) -> None:
        if not isinstance(run, TaskRun):
            raise TypeError("Connector task bridge requires a TaskRun")
        service = account_service or ConnectedAccountService()
        if not isinstance(service, ConnectedAccountService):
            if not (
                callable(getattr(service, "get_account", None))
                and callable(getattr(service, "lease_access_token", None))
            ):
                raise TypeError("Connector task account service is invalid")
        if not callable(adapter_factory):
            raise TypeError("Calendar adapter factory is invalid")
        self._run = run
        self._accounts = service
        self._adapter_factory = adapter_factory

    async def __call__(
        self,
        task_call: ToolCall,
        arguments: CalendarAvailabilityArguments,
    ) -> ConnectorReadOutput:
        if (
            not isinstance(task_call, ToolCall)
            or self._run.state is not TaskState.RUNNING
            or task_call.run_id != self._run.run_id
            or not self._run.grant.allows(
                CapabilityId.TASK_AGENT_RUN
            )
            or not self._run.grant.allows(
                CapabilityId.CALENDAR_EVENT_READ
            )
            or task_call.tool_name != "connector.read"
            or task_call.capability
            is not CapabilityId.CALENDAR_EVENT_READ
            or not isinstance(arguments, CalendarAvailabilityArguments)
            or not hmac.compare_digest(
                task_call.arguments_digest,
                broker_arguments_digest(arguments),
            )
        ):
            raise TaskToolBrokerOperationError(
                "connector_read_not_supported"
            )
        try:
            request = CalendarAvailabilityRequest(
                selected_calendar_ids=arguments.selected_calendar_ids,
                time_min=arguments.time_min,
                time_max=arguments.time_max,
            )
            account = self._accounts.get_account(arguments.authorization_id)
            if account.connector is not ConnectorId.GOOGLE_CALENDAR:
                raise ConnectorAuthorizationError(
                    "Connected account is not a Calendar account"
                )
            connector_call = ConnectorCall(
                call_id=task_call.call_id,
                run_id=task_call.run_id,
                authorization_id=arguments.authorization_id,
                connector=ConnectorId.GOOGLE_CALENDAR,
                capability=CapabilityId.CALENDAR_EVENT_READ,
                operation_id=request.operation_id,
                request_digest=request.request_digest,
                maximum_response_bytes=arguments.maximum_response_bytes,
            )
            lease = self._accounts.lease_access_token(
                arguments.authorization_id,
                CapabilityId.CALENDAR_EVENT_READ,
            )
            try:
                adapter = self._adapter_factory(account)
                execution = await adapter.execute(
                    connector_call,
                    request,
                    lease.token,
                )
            finally:
                lease.close()
        except TaskToolBrokerOperationError:
            raise
        except (TypeError, ValueError) as exc:
            raise TaskToolBrokerOperationError(
                "connector_request_invalid"
            ) from exc
        except ConnectorRateLimitError as exc:
            raise TaskToolBrokerOperationError(
                "connector_rate_limited"
            ) from exc
        except ConnectorTokenExpiredError as exc:
            raise TaskToolBrokerOperationError(
                "connector_token_expired"
            ) from exc
        except ConnectorTokenRevokedError as exc:
            raise TaskToolBrokerOperationError(
                "connector_token_revoked"
            ) from exc
        except ConnectorInvalidGrantError as exc:
            raise TaskToolBrokerOperationError(
                "connector_reauthentication_required"
            ) from exc
        except (
            ConnectorDisconnectedError,
            ConnectorTokenNotFoundError,
        ) as exc:
            raise TaskToolBrokerOperationError(
                "connector_disconnected"
            ) from exc
        except ConnectorAuthorizationError as exc:
            raise TaskToolBrokerOperationError(
                "connector_not_authorized"
            ) from exc
        except ConnectorRequestError as exc:
            raise TaskToolBrokerOperationError(
                "connector_request_failed"
            ) from exc
        except ConnectorResponseError as exc:
            raise TaskToolBrokerOperationError(
                "connector_response_invalid"
            ) from exc
        if (
            not isinstance(
                execution,
                ConnectorExecution,
            )
            or not isinstance(
                execution.output,
                CalendarAvailabilityResult,
            )
            or execution.result.call_id != task_call.call_id
            or execution.result.run_id != task_call.run_id
            or execution.result.operation_id != request.operation_id
        ):
            raise TaskToolBrokerOperationError(
                "connector_evidence_invalid"
            )
        return ConnectorReadOutput(
            content=execution.output.to_json_bytes(),
            provider_response_digest=execution.result.response_digest,
            provider_response_bytes=execution.result.response_bytes,
            provider_request_id=execution.result.provider_request_id,
        )


class GmailConnectorReadBroker:
    """Turn one exact task grant into one selected-thread Gmail read."""

    def __init__(
        self,
        run: TaskRun,
        account_service: ConnectedAccountService | None = None,
        *,
        adapter_factory: GmailAdapterFactory = GoogleGmailAdapter,
    ) -> None:
        _validate_service(run, account_service, adapter_factory)
        self._run = run
        self._accounts = account_service or ConnectedAccountService()
        self._adapter_factory = adapter_factory

    async def __call__(
        self,
        task_call: ToolCall,
        arguments: GmailSelectedThreadArguments,
    ) -> ConnectorReadOutput:
        if (
            not isinstance(arguments, GmailSelectedThreadArguments)
            or not _task_call_matches(
                self._run,
                task_call,
                arguments,
                tool_name="connector.read",
                capability=CapabilityId.GMAIL_MESSAGE_READ,
            )
        ):
            raise TaskToolBrokerOperationError(
                "connector_read_not_supported"
            )
        request = GmailSelectedThreadRequest(
            selected_thread_id=arguments.selected_thread_id
        )
        execution = await self._execute(
            task_call,
            arguments.authorization_id,
            arguments.maximum_response_bytes,
            request,
            CapabilityId.GMAIL_MESSAGE_READ,
        )
        if not isinstance(execution.output, GmailSelectedThreadResult):
            raise TaskToolBrokerOperationError("connector_evidence_invalid")
        return ConnectorReadOutput(
            content=execution.output.to_json_bytes(),
            provider_response_digest=execution.result.response_digest,
            provider_response_bytes=execution.result.response_bytes,
            provider_request_id=execution.result.provider_request_id,
        )

    async def _execute(
        self,
        task_call: ToolCall,
        authorization_id: str,
        maximum_response_bytes: int,
        request,
        capability: CapabilityId,
    ) -> ConnectorExecution:
        try:
            account = self._accounts.get_account(authorization_id)
            if account.connector is not ConnectorId.GMAIL:
                raise ConnectorAuthorizationError(
                    "Connected account is not a Gmail account"
                )
            connector_call = ConnectorCall(
                call_id=task_call.call_id,
                run_id=task_call.run_id,
                authorization_id=authorization_id,
                connector=ConnectorId.GMAIL,
                capability=capability,
                operation_id=request.operation_id,
                request_digest=request.request_digest,
                maximum_response_bytes=maximum_response_bytes,
            )
            lease = self._accounts.lease_access_token(
                authorization_id,
                capability,
            )
            try:
                execution = await self._adapter_factory(account).execute(
                    connector_call,
                    request,
                    lease.token,
                )
            finally:
                lease.close()
        except Exception as exc:
            _raise_broker_connector_error(exc)
            raise AssertionError("unreachable")
        if (
            not isinstance(execution, ConnectorExecution)
            or execution.result.call_id != task_call.call_id
            or execution.result.run_id != task_call.run_id
            or execution.result.operation_id != request.operation_id
        ):
            raise TaskToolBrokerOperationError(
                "connector_evidence_invalid"
            )
        return execution


class GmailConnectorWriteBroker:
    """Create one approved unsent draft and require provider read-back."""

    def __init__(
        self,
        run: TaskRun,
        account_service: ConnectedAccountService | None = None,
        *,
        adapter_factory: GmailAdapterFactory = GoogleGmailAdapter,
    ) -> None:
        _validate_service(run, account_service, adapter_factory)
        self._run = run
        self._accounts = account_service or ConnectedAccountService()
        self._adapter_factory = adapter_factory

    async def __call__(
        self,
        task_call: ToolCall,
        arguments: GmailDraftArguments,
    ) -> ConnectorWriteOutput:
        if (
            not isinstance(arguments, GmailDraftArguments)
            or not _task_call_matches(
                self._run,
                task_call,
                arguments,
                tool_name="connector.write",
                capability=CapabilityId.GMAIL_DRAFT_WRITE,
            )
        ):
            raise TaskToolBrokerOperationError(
                "connector_write_not_supported"
            )
        try:
            request = GmailDraftRequest(
                to=arguments.to,
                cc=arguments.cc,
                bcc=arguments.bcc,
                subject=arguments.subject,
                body_text=arguments.body_text,
            )
            account = self._accounts.get_account(
                arguments.authorization_id
            )
            if account.connector is not ConnectorId.GMAIL:
                raise ConnectorAuthorizationError(
                    "Connected account is not a Gmail account"
                )
            connector_call = ConnectorCall(
                call_id=task_call.call_id,
                run_id=task_call.run_id,
                authorization_id=arguments.authorization_id,
                connector=ConnectorId.GMAIL,
                capability=CapabilityId.GMAIL_DRAFT_WRITE,
                operation_id=request.operation_id,
                request_digest=request.request_digest,
                maximum_response_bytes=arguments.maximum_response_bytes,
            )
            lease = self._accounts.lease_access_token(
                arguments.authorization_id,
                CapabilityId.GMAIL_DRAFT_WRITE,
            )
            try:
                execution = await self._adapter_factory(account).execute(
                    connector_call,
                    request,
                    lease.token,
                )
            finally:
                lease.close()
        except GmailDraftOutcomeUnknownError as exc:
            raise TaskToolBrokerOperationError(
                "connector_write_outcome_unknown"
            ) from exc
        except GmailDraftVerificationError as exc:
            raise TaskToolBrokerOperationError(
                "connector_write_unverified"
            ) from exc
        except Exception as exc:
            _raise_broker_connector_error(exc)
            raise AssertionError("unreachable")
        if (
            not isinstance(execution, ConnectorExecution)
            or not isinstance(execution.output, GmailDraftResult)
            or execution.result.call_id != task_call.call_id
            or execution.result.run_id != task_call.run_id
            or execution.result.operation_id != request.operation_id
        ):
            raise TaskToolBrokerOperationError(
                "connector_evidence_invalid"
            )
        return ConnectorWriteOutput(
            content=execution.output.to_json_bytes(),
            provider_response_digest=execution.result.response_digest,
            provider_response_bytes=execution.result.response_bytes,
            provider_request_id=execution.result.provider_request_id,
        )


def _validate_service(
    run: TaskRun,
    account_service,
    adapter_factory,
) -> None:
    if not isinstance(run, TaskRun):
        raise TypeError("Connector task bridge requires a TaskRun")
    if account_service is not None and not isinstance(
        account_service,
        ConnectedAccountService,
    ):
        if not (
            callable(getattr(account_service, "get_account", None))
            and callable(getattr(account_service, "lease_access_token", None))
        ):
            raise TypeError("Connector task account service is invalid")
    if not callable(adapter_factory):
        raise TypeError("Connector adapter factory is invalid")


def _task_call_matches(
    run: TaskRun,
    task_call: ToolCall,
    arguments,
    *,
    tool_name: str,
    capability: CapabilityId,
) -> bool:
    return (
        isinstance(task_call, ToolCall)
        and run.state is TaskState.RUNNING
        and task_call.run_id == run.run_id
        and run.grant.allows(CapabilityId.TASK_AGENT_RUN)
        and run.grant.allows(capability)
        and task_call.tool_name == tool_name
        and task_call.capability is capability
        and hmac.compare_digest(
            task_call.arguments_digest,
            broker_arguments_digest(arguments),
        )
    )


def _raise_broker_connector_error(exc: Exception) -> None:
    if isinstance(exc, TaskToolBrokerOperationError):
        raise exc
    if isinstance(exc, (TypeError, ValueError)):
        raise TaskToolBrokerOperationError(
            "connector_request_invalid"
        ) from exc
    if isinstance(exc, ConnectorRateLimitError):
        raise TaskToolBrokerOperationError(
            "connector_rate_limited"
        ) from exc
    if isinstance(exc, ConnectorTokenExpiredError):
        raise TaskToolBrokerOperationError(
            "connector_token_expired"
        ) from exc
    if isinstance(exc, ConnectorTokenRevokedError):
        raise TaskToolBrokerOperationError(
            "connector_token_revoked"
        ) from exc
    if isinstance(exc, ConnectorInvalidGrantError):
        raise TaskToolBrokerOperationError(
            "connector_reauthentication_required"
        ) from exc
    if isinstance(
        exc,
        (ConnectorDisconnectedError, ConnectorTokenNotFoundError),
    ):
        raise TaskToolBrokerOperationError(
            "connector_disconnected"
        ) from exc
    if isinstance(exc, ConnectorAuthorizationError):
        raise TaskToolBrokerOperationError(
            "connector_not_authorized"
        ) from exc
    if isinstance(exc, ConnectorRequestError):
        raise TaskToolBrokerOperationError(
            "connector_request_failed"
        ) from exc
    if isinstance(exc, ConnectorResponseError):
        raise TaskToolBrokerOperationError(
            "connector_response_invalid"
        ) from exc
    raise exc


__all__ = [
    "CalendarConnectorReadBroker",
    "GmailConnectorReadBroker",
    "GmailConnectorWriteBroker",
]
