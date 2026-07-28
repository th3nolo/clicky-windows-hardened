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
from connectors.token_store import ConnectorTokenNotFoundError
from tasks.models import TaskRun, TaskState, ToolCall
from tasks.tool_broker import (
    CalendarAvailabilityArguments,
    ConnectorReadOutput,
    TaskToolBrokerOperationError,
    broker_arguments_digest,
)


CalendarAdapterFactory = Callable[
    [ConnectedAccount],
    GoogleCalendarAvailabilityAdapter,
]


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


__all__ = ["CalendarConnectorReadBroker"]
