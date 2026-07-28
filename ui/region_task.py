"""Build-gated caller from one reviewed region to one new Task Agent run."""

from __future__ import annotations

import asyncio
import hashlib
import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from PyQt6.QtCore import QObject, pyqtSignal

from capability_registry import CapabilityGrant, CapabilityId
from feature_gates import (
    DEFAULT_BUILD_FEATURE_FLAGS,
    ActionCapability,
    BuildFeatureFlag,
    action_capability_allowed,
)
from handoff.models import HandoffDestination
from handoff.routing import HandoffRouteContext
from privacy_controls import screen_capture_allowed
from tasks.coordinator import TaskWorkerCoordinator
from tasks.models import TaskLimits, TaskRun, TaskSpec
from tasks.region_context import (
    REGION_TASK_SKILL_ID,
    REGION_TASK_SKILL_VERSION,
    REGION_TASK_VERIFIER_ID,
    REGION_TASK_VERIFIER_STEP_ID,
    RegionTaskProviderSelection,
    RegionTaskRequest,
    ReviewedTaskRegionGateway,
    TaskRegionContextError,
    TaskRegionModelBroker,
    TaskRegionPermissionError,
    TaskRegionProviderError,
    verify_region_task_output,
)
from tasks.store import TaskStore
from tasks.task_center import (
    ActiveTaskHandle,
    TaskCenterActionRegistry,
    TaskDoneTitleKind,
    TaskDisplayContent,
)


REGION_TASK_RUNTIME_SECONDS = 120
REGION_TASK_MAX_OUTPUT_BYTES = 64 * 1024


class TaskRegionLaunchError(RuntimeError):
    """A reviewed route could not create a truthful new task."""


@dataclass(slots=True)
class _ActiveRegionTask:
    run: TaskRun
    context: HandoffRouteContext
    broker: TaskRegionModelBroker
    call: object
    worker: object
    future: object | None = None


class TaskRegionHandoffController(QObject):
    """Own independent region-task lifecycles and exact cancellation."""

    started = pyqtSignal(str)
    completed = pyqtSignal(str)
    failed = pyqtSignal(str, str)
    cancelled = pyqtSignal(str)

    def __init__(
        self,
        store: TaskStore,
        actions: TaskCenterActionRegistry,
        *,
        provider_selection: Callable[
            [], RegionTaskProviderSelection
        ],
        submit: Callable[[object], object],
        config_provider: Callable[[], object],
        worker_coordinator: TaskWorkerCoordinator | None = None,
        provider_factory=None,
        vision_support=None,
        clock: Callable[[], float] = time.monotonic,
        build_flags: Mapping[
            ActionCapability, BuildFeatureFlag
        ] = DEFAULT_BUILD_FEATURE_FLAGS,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(store, TaskStore):
            raise TypeError("Task region controller requires a TaskStore")
        if not isinstance(actions, TaskCenterActionRegistry):
            raise TypeError(
                "Task region controller requires Task Center actions"
            )
        for callback, label in (
            (provider_selection, "provider selection"),
            (submit, "submission"),
            (config_provider, "configuration"),
            (clock, "clock"),
        ):
            if not callable(callback):
                raise TypeError(
                    f"Task region controller {label} callback is invalid"
                )
        if not isinstance(build_flags, Mapping):
            raise TypeError("Task region controller build flags are invalid")
        if (
            worker_coordinator is not None
            and not callable(getattr(worker_coordinator, "start", None))
        ):
            raise TypeError("Task region worker coordinator is invalid")
        self._store = store
        self._actions = actions
        self._provider_selection = provider_selection
        self._submit = submit
        self._config_provider = config_provider
        self._workers = worker_coordinator or TaskWorkerCoordinator()
        self._provider_factory = provider_factory
        self._vision_support = vision_support
        self._clock = clock
        self._build_flags = build_flags
        self._lock = threading.RLock()
        self._active: dict[str, _ActiveRegionTask] = {}

    @property
    def active_run_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._active))

    def route(self, context: HandoffRouteContext) -> str:
        """Persist and start one new bounded run; never steer an old run."""

        if (
            not isinstance(context, HandoffRouteContext)
            or context.destination
            is not HandoffDestination.TASK_AGENT_NEW_RUN
        ):
            if isinstance(context, HandoffRouteContext):
                context.wipe()
            raise TypeError("Task Agent region route is invalid")
        run: TaskRun | None = None
        run_id: str | None = None
        persisted = False
        worker = None
        registered = False
        coroutine = None
        try:
            now = float(self._clock())
            if (
                not math.isfinite(now)
                or now < 0
                or now >= context.expires_at
            ):
                raise TaskRegionLaunchError(
                    "The reviewed region expired before task creation"
                )
            provider = self._provider_selection()
            if not isinstance(provider, RegionTaskProviderSelection):
                raise TypeError(
                    "Task region provider selection is invalid"
                )
            run_id = _run_id(context)
            grant = CapabilityGrant(
                run_id=run_id,
                capabilities=frozenset(
                    {
                        CapabilityId.TASK_AGENT_RUN,
                        CapabilityId.TASK_REGION_CONTEXT,
                    }
                ),
            )
            config = self._config_provider()
            if (
                not action_capability_allowed(
                    config,
                    ActionCapability.TASK_AGENT,
                    grant=grant,
                    run_id=run_id,
                    grant_capability=(
                        CapabilityId.TASK_REGION_CONTEXT
                    ),
                    build_flags=self._build_flags,
                )
                or not screen_capture_allowed(config)
            ):
                raise TaskRegionLaunchError(
                    "Task Agent region access is unavailable or not permitted"
                )
            request = RegionTaskRequest(
                run_id=run_id,
                grant=grant,
                instruction=context.purpose,
                route_id=context.route_id,
                intent_digest=context.intent_digest,
                selection_id=context.selection_id,
                selection_digest=context.selection_digest,
                image_sha256=context.image_sha256,
                image_byte_count=len(context.image_content),
                width=context.width,
                height=context.height,
                provider=provider,
            )
            run = TaskRun(
                TaskSpec(
                    run_id=run_id,
                    skill_id=REGION_TASK_SKILL_ID,
                    skill_version=REGION_TASK_SKILL_VERSION,
                    goal=context.purpose,
                    input_digest=request.input_digest,
                    requested_result=(
                        "A bounded analysis of the explicitly reviewed "
                        "screen region."
                    ),
                    verifier_step_id=REGION_TASK_VERIFIER_STEP_ID,
                    verifier_id=REGION_TASK_VERIFIER_ID,
                    limits=TaskLimits(
                        runtime_seconds=REGION_TASK_RUNTIME_SECONDS,
                        max_tool_calls=1,
                        max_network_requests=1,
                        max_output_bytes=REGION_TASK_MAX_OUTPUT_BYTES,
                    ),
                ),
                grant,
            )
            gateway = ReviewedTaskRegionGateway(
                context,
                clock=self._clock,
            )
            broker = TaskRegionModelBroker(
                run,
                request,
                gateway,
                config_provider=self._config_provider,
                current_provider=self._provider_selection,
                provider_factory=self._provider_factory,
                vision_support=self._vision_support,
                build_flags=self._build_flags,
            )
            call = broker.tool_call()
            approval = broker.approval_request(
                call,
                expires_at=context.expires_at,
            )

            self._store.create_task(run)
            persisted = True
            run.start()
            self._store.sync_run(run)
            run.request_approval(call, approval, now=now)
            self._store.sync_run(run)
            run.approve(
                approval.approval_id,
                approval.action_digest,
                now=now,
            )
            self._store.sync_run(run)
            self._store.record_tool_call(call)
            worker = self._workers.start(run)
            self._actions.register(
                ActiveTaskHandle(
                    content=TaskDisplayContent(
                        run_id=run_id,
                        goal=run.spec.goal,
                        requested_result=run.spec.requested_result,
                    ),
                    cancel_callback=(
                        lambda selected=run_id: self.cancel(selected)
                    ),
                )
            )
            self._actions.publish_commentary(
                run_id,
                "New screen-region run created after explicit review.",
            )
            registered = True
            active = _ActiveRegionTask(
                run=run,
                context=context,
                broker=broker,
                call=call,
                worker=worker,
            )
            with self._lock:
                if run_id in self._active:
                    raise TaskRegionLaunchError(
                        "Task region run identity is already active"
                    )
                self._active[run_id] = active
            coroutine = self._execute(active)
            future = self._submit(coroutine)
            if not callable(getattr(future, "cancel", None)):
                close = getattr(coroutine, "close", None)
                if callable(close):
                    close()
                coroutine = None
                raise TaskRegionLaunchError(
                    "Task Agent background execution is unavailable"
                )
            coroutine = None
            with self._lock:
                current = self._active.get(run_id)
                if current is active:
                    active.future = future
                else:
                    future.cancel()
            self.started.emit(run_id)
            return run_id
        except Exception as exc:
            context.wipe()
            if coroutine is not None:
                close = getattr(coroutine, "close", None)
                if callable(close):
                    close()
            if run_id is not None:
                with self._lock:
                    self._active.pop(run_id, None)
            if registered and run is not None:
                try:
                    self._actions.finish(run.run_id)
                except Exception:
                    pass
            if worker is not None:
                _stop_worker(worker, cancel=True)
            if persisted and run is not None and not run.terminal:
                try:
                    run.fail("region_task_launch_failed")
                    self._store.sync_run(run)
                except Exception:
                    pass
            if isinstance(exc, TaskRegionLaunchError):
                raise
            raise TaskRegionLaunchError(
                "The reviewed region could not start a new bounded task"
            ) from exc

    def cancel(self, run_id: str) -> bool:
        """Cancel one exact active task and suppress all late output."""

        if not isinstance(run_id, str):
            return False
        with self._lock:
            active = self._active.pop(run_id, None)
            if active is None or active.run.terminal:
                return False
            try:
                active.run.cancel()
                self._store.sync_run(active.run)
            except Exception:
                return False
            try:
                self._actions.finish(run_id)
            except Exception:
                pass
            active.context.wipe()
            future = active.future
        if future is not None:
            try:
                future.cancel()
            except Exception:
                pass
        _stop_worker(active.worker, cancel=True)
        self.cancelled.emit(run_id)
        return True

    def cancel_all(self) -> None:
        for run_id in self.active_run_ids:
            self.cancel(run_id)

    async def _execute(self, active: _ActiveRegionTask) -> None:
        run_id = active.run.run_id
        try:
            self._actions.publish_commentary(
                run_id,
                "Using the reviewed region snapshot in the isolated run.",
            )
            remaining = active.context.expires_at - float(self._clock())
            if not math.isfinite(remaining) or remaining <= 0:
                raise TaskRegionContextError(
                    "Reviewed task region expired"
                )
            output = await asyncio.wait_for(
                active.broker.execute(active.call),
                timeout=min(
                    float(REGION_TASK_RUNTIME_SECONDS),
                    remaining,
                ),
            )
            self._actions.publish_commentary(
                run_id,
                "Response received; verifying bounded final delivery.",
            )
            verifier = verify_region_task_output(active.run, output)
        except asyncio.CancelledError:
            self._cancel_from_executor(active)
            return
        except Exception as exc:
            self._fail(active, _failure_code(exc))
            return

        with self._lock:
            if self._active.get(run_id) is not active:
                return
            try:
                self._store.record_model_output(
                    active.call,
                    output.result,
                )
                self._store.record_tool_result(output.result)
                self._store.record_tool_result(verifier)
                active.run.complete(verifier)
                self._store.sync_run(active.run)
                record = self._store.get_task(run_id)
                if record is None:
                    raise TaskRegionLaunchError(
                        "Completed region task metadata disappeared"
                    )
                self._actions.publish_result(run_id, output.text)
                self._actions.publish_done_title(
                    record,
                    TaskDoneTitleKind.SCREEN_REGION_RESULT,
                )
                self._actions.finish(run_id)
                self._active.pop(run_id, None)
            except Exception:
                self._fail_locked(active, "region_task_result_failed")
                return
        _stop_worker(active.worker, cancel=False)
        active.context.wipe()
        self.completed.emit(run_id)

    def _cancel_from_executor(self, active: _ActiveRegionTask) -> None:
        run_id = active.run.run_id
        with self._lock:
            if self._active.get(run_id) is not active:
                return
            self._active.pop(run_id, None)
            if not active.run.terminal:
                try:
                    active.run.cancel("task_execution_cancelled")
                    self._store.sync_run(active.run)
                except Exception:
                    pass
            try:
                self._actions.finish(run_id)
            except Exception:
                pass
            active.context.wipe()
        _stop_worker(active.worker, cancel=True)
        self.cancelled.emit(run_id)

    def _fail(self, active: _ActiveRegionTask, result_code: str) -> None:
        with self._lock:
            self._fail_locked(active, result_code)

    def _fail_locked(
        self,
        active: _ActiveRegionTask,
        result_code: str,
    ) -> None:
        run_id = active.run.run_id
        if self._active.get(run_id) is not active:
            return
        self._active.pop(run_id, None)
        if not active.run.terminal:
            try:
                active.run.fail(result_code)
                self._store.sync_run(active.run)
            except Exception:
                pass
        try:
            self._actions.finish(run_id)
        except Exception:
            pass
        active.context.wipe()
        _stop_worker(active.worker, cancel=True)
        self.failed.emit(run_id, result_code)


def _run_id(context: HandoffRouteContext) -> str:
    return "task-region-" + hashlib.sha256(
        (
            context.route_id
            + ":"
            + context.intent_digest
            + ":"
            + context.selection_digest
        ).encode("utf-8")
    ).hexdigest()[:32]


def _failure_code(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "region_task_timed_out"
    if isinstance(exc, TaskRegionPermissionError):
        return "region_permission_revoked"
    if isinstance(exc, TaskRegionContextError):
        return "region_context_rejected"
    if isinstance(exc, TaskRegionProviderError):
        return "region_provider_failed"
    return "region_task_failed"


def _stop_worker(worker: object, *, cancel: bool) -> None:
    method = getattr(worker, "cancel" if cancel else "shutdown", None)
    if not callable(method):
        return
    try:
        method()
    except Exception:
        if not cancel:
            fallback = getattr(worker, "cancel", None)
            if callable(fallback):
                try:
                    fallback()
                except Exception:
                    pass


__all__ = [
    "REGION_TASK_MAX_OUTPUT_BYTES",
    "REGION_TASK_RUNTIME_SECONDS",
    "TaskRegionHandoffController",
    "TaskRegionLaunchError",
]
