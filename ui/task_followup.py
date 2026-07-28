"""Task Center launch controller and exact review for linked follow-up runs."""

from __future__ import annotations

import asyncio
import math
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from capability_registry import CapabilityGrant, CapabilityId
from feature_gates import (
    DEFAULT_BUILD_FEATURE_FLAGS,
    ActionCapability,
    BuildFeatureFlag,
    action_capability_allowed,
)
from tasks.coordinator import TaskWorkerCoordinator
from tasks.followup_context import (
    FOLLOWUP_MAX_OUTPUT_BYTES,
    FOLLOWUP_REVIEW_SECONDS,
    FOLLOWUP_RUNTIME_SECONDS,
    FOLLOWUP_SKILL_ID,
    FOLLOWUP_SKILL_VERSION,
    FOLLOWUP_VERIFIER_ID,
    FOLLOWUP_VERIFIER_STEP_ID,
    FollowupProviderSelection,
    ReviewedTaskFollowupGateway,
    TaskFollowupContextError,
    TaskFollowupModelBroker,
    TaskFollowupPermissionError,
    TaskFollowupProviderError,
    TaskFollowupRequest,
    TaskFollowupReview,
    followup_link,
    verify_followup_output,
)
from tasks.models import TERMINAL_TASK_STATES, TaskLimits, TaskRun, TaskSpec
from tasks.store import TaskStore
from tasks.task_center import (
    ActiveTaskHandle,
    TaskCenterActionRegistry,
    TaskDisplayContent,
)


class TaskFollowupLaunchError(RuntimeError):
    """A reviewed selected-task follow-up could not launch truthfully."""


MAX_CONSUMED_FOLLOWUP_REVIEWS = 4_096


@dataclass(frozen=True, slots=True)
class PreparedTaskFollowup:
    request: TaskFollowupRequest
    review: TaskFollowupReview

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request, TaskFollowupRequest)
            or not isinstance(self.review, TaskFollowupReview)
            or self.review.run_id != self.request.run_id
            or self.review.request_digest != self.request.input_digest
        ):
            raise ValueError("Prepared task follow-up review does not match")


@dataclass(slots=True)
class _ActiveFollowupTask:
    run: TaskRun
    broker: TaskFollowupModelBroker
    worker: object
    review_expires_at: float
    future: object | None = None


class TaskFollowupController(QObject):
    """Create independent child runs and suppress stale or late output."""

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
            [], FollowupProviderSelection
        ],
        submit: Callable[[object], object],
        config_provider: Callable[[], object],
        worker_coordinator: TaskWorkerCoordinator | None = None,
        provider_factory=None,
        artifact_reader=None,
        clock: Callable[[], float] = time.monotonic,
        run_id_factory: Callable[[], str] | None = None,
        review_id_factory: Callable[[], str] | None = None,
        build_flags: Mapping[
            ActionCapability, BuildFeatureFlag
        ] = DEFAULT_BUILD_FEATURE_FLAGS,
        parent=None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(store, TaskStore):
            raise TypeError("Task follow-up controller requires a TaskStore")
        if not isinstance(actions, TaskCenterActionRegistry):
            raise TypeError(
                "Task follow-up controller requires Task Center actions"
            )
        for callback, label in (
            (provider_selection, "provider selection"),
            (submit, "submission"),
            (config_provider, "configuration"),
            (clock, "clock"),
        ):
            if not callable(callback):
                raise TypeError(
                    f"Task follow-up controller {label} callback is invalid"
                )
        if (
            worker_coordinator is not None
            and not callable(getattr(worker_coordinator, "start", None))
        ):
            raise TypeError("Task follow-up worker coordinator is invalid")
        if run_id_factory is not None and not callable(run_id_factory):
            raise TypeError("Task follow-up run ID factory is invalid")
        if review_id_factory is not None and not callable(review_id_factory):
            raise TypeError("Task follow-up review ID factory is invalid")
        if not isinstance(build_flags, Mapping):
            raise TypeError("Task follow-up build flags are invalid")
        self._store = store
        self._actions = actions
        self._provider_selection = provider_selection
        self._submit = submit
        self._config_provider = config_provider
        self._workers = worker_coordinator or TaskWorkerCoordinator()
        self._provider_factory = provider_factory
        self._artifact_reader = artifact_reader
        self._clock = clock
        self._run_id_factory = run_id_factory or (
            lambda: f"task-followup-{secrets.token_hex(16)}"
        )
        self._review_id_factory = review_id_factory or (
            lambda: f"followup-review-{secrets.token_hex(16)}"
        )
        self._build_flags = build_flags
        self._lock = threading.RLock()
        self._active: dict[str, _ActiveFollowupTask] = {}
        self._consumed_reviews: set[str] = set()

    @property
    def active_run_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._active))

    def prepare(
        self,
        parent_run_id: str,
        instruction: str,
        artifact_ids: tuple[str, ...] = (),
    ) -> PreparedTaskFollowup:
        """Build an unaccepted, expiring exact review without starting work."""

        if (
            not isinstance(parent_run_id, str)
            or not isinstance(artifact_ids, tuple)
            or len(set(artifact_ids)) != len(artifact_ids)
            or any(not isinstance(item, str) for item in artifact_ids)
        ):
            raise TaskFollowupLaunchError(
                "The selected task or artifacts are invalid"
            )
        parent = self._store.get_task(parent_run_id)
        if (
            parent is None
            or parent.state not in TERMINAL_TASK_STATES
            or parent.interrupted
        ):
            raise TaskFollowupLaunchError(
                "Only a non-interrupted terminal task can have a follow-up"
            )
        available = {
            artifact.artifact_id: artifact
            for artifact in self._store.list_artifacts(parent_run_id)
        }
        if any(artifact_id not in available for artifact_id in artifact_ids):
            raise TaskFollowupLaunchError(
                "A selected verified artifact is stale or unavailable"
            )
        selected = tuple(available[item] for item in artifact_ids)
        try:
            provider = self._provider_selection()
            if not isinstance(provider, FollowupProviderSelection):
                raise TypeError("provider selection changed")
            run_id = self._run_id_factory()
            capabilities = {CapabilityId.TASK_AGENT_RUN}
            if selected:
                capabilities.add(CapabilityId.LOCAL_ARTIFACT_READ)
            grant = CapabilityGrant(
                run_id=run_id,
                capabilities=frozenset(capabilities),
            )
            request = TaskFollowupRequest(
                run_id=run_id,
                parent_run_id=parent.run_id,
                parent_updated_at=parent.updated_at,
                grant=grant,
                instruction=instruction,
                provider=provider,
                selected_artifacts=selected,
            )
            if not action_capability_allowed(
                self._config_provider(),
                ActionCapability.TASK_AGENT,
                grant=grant,
                run_id=run_id,
                grant_capability=CapabilityId.TASK_AGENT_RUN,
                build_flags=self._build_flags,
            ):
                raise TaskFollowupPermissionError(
                    "Task Agent follow-up permission is unavailable"
                )
            now = float(self._clock())
            if not math.isfinite(now) or now < 0:
                raise ValueError("clock is invalid")
            review = TaskFollowupReview(
                review_id=self._review_id_factory(),
                run_id=run_id,
                request_digest=request.input_digest,
                expires_at=now + FOLLOWUP_REVIEW_SECONDS,
            )
            return PreparedTaskFollowup(request=request, review=review)
        except TaskFollowupLaunchError:
            raise
        except Exception as exc:
            raise TaskFollowupLaunchError(
                "The selected task follow-up could not be prepared"
            ) from exc

    def launch(
        self,
        prepared: PreparedTaskFollowup,
        accepted_review_digest: str,
    ) -> str:
        """Consume one exact accepted review and start a new child run."""

        if not isinstance(prepared, PreparedTaskFollowup):
            raise TypeError("Prepared task follow-up is invalid")
        if accepted_review_digest != prepared.review.review_digest:
            raise TaskFollowupLaunchError(
                "The accepted follow-up review does not match"
            )
        with self._lock:
            if accepted_review_digest in self._consumed_reviews:
                raise TaskFollowupLaunchError(
                    "The accepted follow-up review was already consumed"
                )
            if len(self._consumed_reviews) >= MAX_CONSUMED_FOLLOWUP_REVIEWS:
                raise TaskFollowupLaunchError(
                    "The in-process follow-up review limit was reached"
                )
            self._consumed_reviews.add(accepted_review_digest)

        request = prepared.request
        run = TaskRun(
            TaskSpec(
                run_id=request.run_id,
                skill_id=FOLLOWUP_SKILL_ID,
                skill_version=FOLLOWUP_SKILL_VERSION,
                goal=request.instruction,
                input_digest=request.input_digest,
                requested_result=(
                    "A bounded response to the new follow-up instruction "
                    "using only explicitly selected adopted artifacts."
                ),
                verifier_step_id=FOLLOWUP_VERIFIER_STEP_ID,
                verifier_id=FOLLOWUP_VERIFIER_ID,
                limits=TaskLimits(
                    runtime_seconds=FOLLOWUP_RUNTIME_SECONDS,
                    max_tool_calls=len(request.selected_artifacts) + 1,
                    max_network_requests=1,
                    max_output_bytes=FOLLOWUP_MAX_OUTPUT_BYTES,
                ),
            ),
            request.grant,
        )
        persisted = False
        registered = False
        worker = None
        coroutine = None
        try:
            now = float(self._clock())
            if (
                not math.isfinite(now)
                or now < 0
                or now >= prepared.review.expires_at
            ):
                raise TaskFollowupLaunchError(
                    "The follow-up review expired before launch"
                )
            if (
                not action_capability_allowed(
                    self._config_provider(),
                    ActionCapability.TASK_AGENT,
                    grant=request.grant,
                    run_id=request.run_id,
                    grant_capability=CapabilityId.TASK_AGENT_RUN,
                    build_flags=self._build_flags,
                )
                or self._provider_selection() != request.provider
            ):
                raise TaskFollowupLaunchError(
                    "The reviewed follow-up permission or provider changed"
                )
            gateway = ReviewedTaskFollowupGateway(
                prepared.review,
                clock=self._clock,
            )
            broker = TaskFollowupModelBroker(
                run,
                request,
                gateway,
                config_provider=self._config_provider,
                current_provider=self._provider_selection,
                review_digest=accepted_review_digest,
                provider_factory=self._provider_factory,
                artifact_reader=self._artifact_reader,
                build_flags=self._build_flags,
            )
            calls = broker.tool_calls()
            self._store.create_followup(
                run,
                followup_link(request, prepared.review),
            )
            persisted = True
            run.start()
            self._store.sync_run(run)
            for call in calls:
                self._store.record_tool_call(call)
            worker = self._workers.start(run)
            self._actions.register(
                ActiveTaskHandle(
                    content=TaskDisplayContent(
                        run_id=run.run_id,
                        goal=run.spec.goal,
                        requested_result=run.spec.requested_result,
                    ),
                    cancel_callback=(
                        lambda selected=run.run_id: self.cancel(selected)
                    ),
                )
            )
            registered = True
            active = _ActiveFollowupTask(
                run=run,
                broker=broker,
                worker=worker,
                review_expires_at=prepared.review.expires_at,
            )
            with self._lock:
                if run.run_id in self._active:
                    raise TaskFollowupLaunchError(
                        "Task follow-up identity is already active"
                    )
                self._active[run.run_id] = active
            coroutine = self._execute(active)
            future = self._submit(coroutine)
            if not callable(getattr(future, "cancel", None)):
                close = getattr(coroutine, "close", None)
                if callable(close):
                    close()
                coroutine = None
                raise TaskFollowupLaunchError(
                    "Task follow-up background execution is unavailable"
                )
            coroutine = None
            with self._lock:
                current = self._active.get(run.run_id)
                if current is active:
                    active.future = future
                else:
                    future.cancel()
            self.started.emit(run.run_id)
            return run.run_id
        except Exception as exc:
            if coroutine is not None:
                close = getattr(coroutine, "close", None)
                if callable(close):
                    close()
            with self._lock:
                self._active.pop(run.run_id, None)
            if registered:
                try:
                    self._actions.finish(run.run_id)
                except Exception:
                    pass
            if worker is not None:
                _stop_worker(worker, cancel=True)
            if persisted and not run.terminal:
                try:
                    run.fail("followup_launch_failed")
                    self._store.sync_run(run)
                except Exception:
                    pass
            if isinstance(exc, TaskFollowupLaunchError):
                raise
            raise TaskFollowupLaunchError(
                "The reviewed follow-up could not start a new task"
            ) from exc

    def cancel(self, run_id: str) -> bool:
        if not isinstance(run_id, str):
            return False
        with self._lock:
            active = self._active.get(run_id)
            if active is None or active.run.terminal:
                return False
            persisted = True
            try:
                active.run.cancel()
                self._store.sync_run(active.run)
            except Exception:
                persisted = False
            self._active.pop(run_id, None)
            try:
                self._actions.finish(run_id)
            except Exception:
                pass
            future = active.future
        if future is not None:
            try:
                future.cancel()
            except Exception:
                pass
        _stop_worker(active.worker, cancel=True)
        if persisted:
            self.cancelled.emit(run_id)
        return persisted

    def cancel_all(self) -> None:
        for run_id in self.active_run_ids:
            self.cancel(run_id)

    async def _execute(self, active: _ActiveFollowupTask) -> None:
        run_id = active.run.run_id
        try:
            remaining = active.review_expires_at - float(self._clock())
            if not math.isfinite(remaining) or remaining <= 0:
                raise TaskFollowupContextError(
                    "The accepted follow-up review expired"
                )
            output = await asyncio.wait_for(
                active.broker.execute(),
                timeout=min(float(FOLLOWUP_RUNTIME_SECONDS), remaining),
            )
            verifier = verify_followup_output(active.run, output)
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
                for call, result in zip(
                    output.calls,
                    output.results,
                    strict=True,
                ):
                    if result is output.model_result:
                        self._store.record_model_output(call, result)
                    self._store.record_tool_result(result)
                self._store.record_tool_result(verifier)
                active.run.complete(verifier)
                self._store.sync_run(active.run)
                self._actions.publish_result(run_id, output.text)
                self._actions.finish(run_id)
                self._active.pop(run_id, None)
            except Exception:
                self._fail_locked(active, "followup_result_failed")
                return
        _stop_worker(active.worker, cancel=False)
        self.completed.emit(run_id)

    def _cancel_from_executor(self, active: _ActiveFollowupTask) -> None:
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
        _stop_worker(active.worker, cancel=True)
        self.cancelled.emit(run_id)

    def _fail(self, active: _ActiveFollowupTask, result_code: str) -> None:
        with self._lock:
            self._fail_locked(active, result_code)

    def _fail_locked(
        self,
        active: _ActiveFollowupTask,
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
        _stop_worker(active.worker, cancel=True)
        self.failed.emit(run_id, result_code)


class TaskFollowupReviewDialog(QDialog):
    """Show exact new authority and sources before launch acceptance."""

    def __init__(
        self,
        prepared: PreparedTaskFollowup,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(prepared, PreparedTaskFollowup):
            raise TypeError("Task follow-up review is invalid")
        self._prepared = prepared
        self._accepted_digest: str | None = None
        self.setWindowTitle("Review new follow-up run")
        self.setMinimumSize(700, 560)
        layout = QVBoxLayout(self)
        notice = QLabel(
            "This starts a new run. It does not resume the selected worker, "
            "reuse prior approvals, or inherit conversation history."
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)
        request = prepared.request
        self._details = QPlainTextEdit()
        self._details.setReadOnly(True)
        source_lines = (
            [
                "No prior artifacts selected.",
            ]
            if not request.selected_artifacts
            else [
                (
                    f"{artifact.artifact_id} · {artifact.name} · "
                    f"{artifact.media_type} · {artifact.byte_count} bytes\n"
                    f"SHA-256: {artifact.sha256}\n"
                    f"Verifier: {artifact.verification_result_id}\n"
                    "Evidence: "
                    f"{artifact.verification_evidence_digest}"
                )
                for artifact in request.selected_artifacts
            ]
        )
        self._details.setPlainText(
            f"Parent run: {request.parent_run_id}\n"
            f"New child run: {request.run_id}\n"
            f"Provider/model: {request.provider.provider_id} / "
            f"{request.provider.model_id}\n"
            "Fresh capabilities:\n"
            + "\n".join(
                f"• {capability.value}"
                for capability in sorted(
                    request.grant.capabilities,
                    key=lambda item: item.value,
                )
            )
            + "\n\nNew instruction:\n"
            + request.instruction.strip()
            + "\n\nSelected adopted artifacts:\n"
            + "\n\n".join(source_lines)
            + "\n\nNo desktop, connector, shell, browser, coding-agent, "
            "or external-write authority is granted."
        )
        layout.addWidget(self._details, stretch=1)
        self.confirm = QCheckBox(
            "I approve this exact new run, provider, capabilities, and "
            "selected artifact evidence."
        )
        layout.addWidget(self.confirm)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        self.start_button = self.buttons.button(
            QDialogButtonBox.StandardButton.Ok
        )
        self.start_button.setText("Start new follow-up run")
        self.start_button.setEnabled(False)
        self.confirm.toggled.connect(self.start_button.setEnabled)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

    @property
    def accepted_review_digest(self) -> str | None:
        if self.result() != int(QDialog.DialogCode.Accepted):
            return None
        return self._accepted_digest

    def accept(self) -> None:
        if not self.confirm.isChecked() or self._prepared is None:
            return
        self._accepted_digest = self._prepared.review.review_digest
        self._prepared = None
        self._details.clear()
        super().accept()

    def reject(self) -> None:
        self._accepted_digest = None
        self._prepared = None
        self._details.clear()
        super().reject()


def _failure_code(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "followup_timed_out"
    if isinstance(exc, TaskFollowupPermissionError):
        return "followup_permission_revoked"
    if isinstance(exc, TaskFollowupContextError):
        return "followup_context_rejected"
    if isinstance(exc, TaskFollowupProviderError):
        return "followup_provider_failed"
    return "followup_task_failed"


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
    "PreparedTaskFollowup",
    "TaskFollowupController",
    "TaskFollowupLaunchError",
    "TaskFollowupReviewDialog",
]
