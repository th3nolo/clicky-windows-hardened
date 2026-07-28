"""Visible, truthful Task Center for persisted background-task evidence."""

from __future__ import annotations

import time
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from capability_registry import require_capability
from feature_gates import ActionCapability, build_feature_available
from tasks.models import TaskState
from tasks.store import (
    INTERRUPTED_RESULT_CODE,
    TaskRecord,
    TaskStore,
    TaskStoreError,
)
from tasks.task_center import (
    DesktopActionPresentation,
    TaskActivity,
    TaskActivityKind,
    TaskCenterActionRegistry,
    TaskCenterSnapshot,
    build_task_center_snapshot,
)


_RUN_ID_ROLE = int(Qt.ItemDataRole.UserRole)
_ACTIVITY_ROLE = _RUN_ID_ROLE + 1
_ACTIVE_STATES = frozenset(
    {
        TaskState.RUNNING,
        TaskState.WAITING_FOR_APPROVAL,
    }
)


class TaskCenterPanel(QWidget):
    """Inspect metadata and route only exact, registered live actions."""

    task_cancelled = pyqtSignal(str)
    approval_decided = pyqtSignal(str, str)

    def __init__(
        self,
        store: TaskStore,
        actions: TaskCenterActionRegistry,
        *,
        task_agent_available: bool | None = None,
        clock=time.time,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(store, TaskStore):
            raise TypeError("Task Center requires a TaskStore")
        if not isinstance(actions, TaskCenterActionRegistry):
            raise TypeError(
                "Task Center requires an exact live-action registry"
            )
        if not callable(clock):
            raise TypeError("Task Center clock is invalid")
        self._store = store
        self._actions = actions
        self._clock = clock
        self._available = (
            build_feature_available(ActionCapability.TASK_AGENT)
            if task_agent_available is None
            else task_agent_available
        )
        if type(self._available) is not bool:
            raise TypeError("Task Agent availability must be explicit")
        self._current: TaskCenterSnapshot | None = None

        self.setWindowTitle("Task Center")
        self.setMinimumSize(920, 650)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)

        root = QVBoxLayout(self)
        intro = QLabel(
            "Background tasks use brokered tools and machine-checked "
            "postconditions. Model text is never completion evidence."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        toolbar = QHBoxLayout()
        self._availability = QLabel("")
        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.clicked.connect(self.refresh)
        toolbar.addWidget(self._availability, stretch=1)
        toolbar.addWidget(self._refresh_button)
        root.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter, stretch=1)
        self._tasks = QListWidget()
        self._tasks.currentItemChanged.connect(self._load_selected)
        splitter.addWidget(self._tasks)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        details = QWidget()
        detail_layout = QVBoxLayout(details)
        self._goal = QLabel("Choose a task")
        self._goal.setStyleSheet("font-size: 17px; font-weight: 600;")
        self._goal.setWordWrap(True)
        self._identity = QLabel("")
        self._identity.setWordWrap(True)
        self._state = QLabel("")
        self._state.setWordWrap(True)
        self._result = QLabel("")
        self._result.setWordWrap(True)
        self._capabilities = QLabel("")
        self._capabilities.setWordWrap(True)
        self._limits = QLabel("")
        self._limits.setWordWrap(True)
        for label in (
            self._goal,
            self._identity,
            self._state,
            self._result,
            self._capabilities,
            self._limits,
        ):
            detail_layout.addWidget(label)

        detail_layout.addWidget(QLabel("Reviewed desktop action"))
        self._desktop_action = QPlainTextEdit()
        self._desktop_action.setReadOnly(True)
        self._desktop_action.setMaximumHeight(190)
        detail_layout.addWidget(self._desktop_action)

        detail_layout.addWidget(QLabel("Activity and evidence"))
        self._activity = QListWidget()
        self._activity.currentItemChanged.connect(
            self._show_activity_metadata
        )
        detail_layout.addWidget(self._activity)
        self._activity_details = QPlainTextEdit()
        self._activity_details.setReadOnly(True)
        self._activity_details.setMaximumHeight(120)
        detail_layout.addWidget(self._activity_details)

        detail_layout.addWidget(QLabel("Pending and past approvals"))
        self._approvals = QListWidget()
        detail_layout.addWidget(self._approvals)
        self._approval_preview = QPlainTextEdit()
        self._approval_preview.setReadOnly(True)
        self._approval_preview.setMaximumHeight(150)
        detail_layout.addWidget(self._approval_preview)
        approval_actions = QHBoxLayout()
        self._approve_button = QPushButton("Approve exact action")
        self._approve_button.clicked.connect(self.approve_selected)
        self._reject_button = QPushButton("Reject")
        self._reject_button.clicked.connect(self.reject_selected)
        approval_actions.addWidget(self._approve_button)
        approval_actions.addWidget(self._reject_button)
        approval_actions.addStretch()
        detail_layout.addLayout(approval_actions)

        detail_layout.addWidget(QLabel("Verified artifacts"))
        self._artifacts = QListWidget()
        detail_layout.addWidget(self._artifacts)

        task_actions = QHBoxLayout()
        self._cancel_button = QPushButton("Cancel task")
        self._cancel_button.clicked.connect(self.cancel_selected)
        task_actions.addWidget(self._cancel_button)
        task_actions.addStretch()
        detail_layout.addLayout(task_actions)
        self._status = QLabel("")
        self._status.setWordWrap(True)
        detail_layout.addWidget(self._status)
        scroll.setWidget(details)
        splitter.addWidget(scroll)
        splitter.setStretchFactor(1, 2)

        self._timer = QTimer(self)
        self._timer.setInterval(2_000)
        self._timer.timeout.connect(self.refresh_selected)
        self._timer.start()
        self.refresh()

    def selected_run_id(self) -> str | None:
        item = self._tasks.currentItem()
        if item is None:
            return None
        run_id = item.data(_RUN_ID_ROLE)
        return run_id if isinstance(run_id, str) else None

    def refresh(self) -> None:
        wanted = self.selected_run_id()
        self._tasks.blockSignals(True)
        self._tasks.clear()
        selected_row = -1
        try:
            records = self._store.list_tasks()
        except TaskStoreError:
            records = ()
            self._availability.setText(
                "Task metadata is unavailable; actions remain disabled."
            )
        else:
            self._availability.setText(
                "Task Agent available"
                if self._available
                else "Task Agent is disabled in this build."
            )
        for row, task in enumerate(records):
            item = QListWidgetItem(self._task_list_text(task))
            item.setData(_RUN_ID_ROLE, task.run_id)
            self._tasks.addItem(item)
            if task.run_id == wanted:
                selected_row = row
        self._tasks.blockSignals(False)
        if selected_row >= 0:
            self._tasks.setCurrentRow(selected_row)
        elif records:
            self._tasks.setCurrentRow(0)
        else:
            self._clear_details("No background tasks have been recorded.")

    def refresh_selected(self) -> None:
        if self.selected_run_id() is not None:
            self._load_selected()

    def cancel_selected(self) -> None:
        snapshot = self._current
        if (
            snapshot is None
            or snapshot.task.state not in _ACTIVE_STATES
        ):
            self._status.setText("Only a running or waiting task can cancel.")
            return
        if not snapshot.controllable:
            self._status.setText(
                "This task is not active in this process. It will not be "
                "resumed or changed."
            )
            return
        if self._actions.cancel(snapshot.task.run_id):
            self.task_cancelled.emit(snapshot.task.run_id)
            self._status.setText("Cancellation was sent to the active task.")
        else:
            self._status.setText(
                "The active task did not confirm cancellation."
            )
        self.refresh()

    def approve_selected(self) -> None:
        self._decide_approval(approve=True)

    def reject_selected(self) -> None:
        self._decide_approval(approve=False)

    def _decide_approval(self, *, approve: bool) -> None:
        snapshot = self._current
        payload = snapshot.active_approval if snapshot is not None else None
        if payload is None:
            self._status.setText(
                "No exact active approval preview is available."
            )
            return
        request = payload.request
        try:
            accepted = (
                self._actions.approve(
                    request.run_id,
                    request.approval_id,
                    request.action_digest,
                )
                if approve
                else self._actions.reject(
                    request.run_id,
                    request.approval_id,
                    request.action_digest,
                )
            )
        except ValueError:
            accepted = False
        if accepted:
            decision = "approved" if approve else "rejected"
            self.approval_decided.emit(request.run_id, decision)
            self._status.setText(
                f"The exact pending action was {decision}."
            )
        else:
            self._status.setText(
                "The approval decision was stale or did not match; no "
                "authority was granted."
            )
        self.refresh()

    def _load_selected(self, *_args) -> None:
        run_id = self.selected_run_id()
        if run_id is None:
            self._clear_details("Choose a task.")
            return
        try:
            task = self._store.get_task(run_id)
            if task is None:
                raise TaskStoreError("Task metadata disappeared")
            snapshot = build_task_center_snapshot(
                task,
                self._store.list_events(run_id),
                self._store.list_approvals(run_id),
                self._store.list_artifacts(run_id),
                now=self._clock(),
                actions=self._actions,
            )
        except (TaskStoreError, TypeError, ValueError):
            self._clear_details(
                "Task metadata is unavailable or failed validation."
            )
            return
        self._current = snapshot
        self._render(snapshot)

    def _render(self, snapshot: TaskCenterSnapshot) -> None:
        task = snapshot.task
        content = snapshot.display_content
        if content is None:
            self._goal.setText(
                "Goal not retained after restart "
                f"(digest {task.goal_digest})."
            )
        else:
            self._goal.setText(content.goal)
        self._identity.setText(
            f"Skill: {task.skill_id} {task.skill_version}\n"
            f"Run: {task.run_id}"
        )
        self._state.setText(
            f"State: {task.state.value} · "
            f"Elapsed: {_duration(snapshot.elapsed_seconds)}"
        )
        if content is not None and content.result_text is not None:
            self._result.setText(
                "Bounded task result "
                "(delivery verified; factual claims not independently "
                "verified):\n"
                + content.result_text
            )
        else:
            self._result.setText(_terminal_result(task))
        self._capabilities.setText(
            "Granted capabilities:\n"
            + "\n".join(
                "• "
                + require_capability(capability).label
                + f" ({capability.value})"
                for capability in sorted(
                    task.grant.capabilities,
                    key=lambda item: item.value,
                )
            )
        )
        limits = task.limits
        self._limits.setText(
            "Limits: "
            f"{limits.runtime_seconds}s runtime · "
            f"{limits.max_tool_calls} tool calls · "
            f"{limits.max_network_requests} network requests · "
            f"{limits.max_output_bytes} output bytes"
        )
        self._desktop_action.setPlainText(
            _desktop_action_text(snapshot.desktop_action)
        )

        self._activity.clear()
        for activity in snapshot.activities:
            item = QListWidgetItem(_activity_text(activity))
            item.setData(_ACTIVITY_ROLE, activity)
            self._activity.addItem(item)
        if self._activity.count():
            self._activity.setCurrentRow(self._activity.count() - 1)
        else:
            self._activity_details.clear()

        self._approvals.clear()
        for approval in snapshot.approvals:
            self._approvals.addItem(
                f"{approval.status}: {approval.capability.value} · "
                f"{approval.approval_id} · expires "
                f"{_date_time(approval.expires_at)}"
            )
        payload = snapshot.active_approval
        if payload is None:
            self._approval_preview.setPlainText(
                "No exact active preview is available. Persisted approval "
                "records contain digests only and cannot be approved after "
                "restart."
            )
        else:
            request = payload.request
            preview = payload.preview
            self._approval_preview.setPlainText(
                f"Reason: {request.reason}\n"
                f"Target: {payload.target.label} "
                f"({payload.target.reference})\n"
                f"Media: {preview.media_type} · {preview.byte_count} bytes\n"
                f"SHA-256: {preview.content_sha256}\n\n"
                f"{preview.excerpt}"
            )

        self._artifacts.clear()
        for artifact in snapshot.artifacts:
            self._artifacts.addItem(
                f"{artifact.name} · {artifact.media_type} · "
                f"{artifact.byte_count} bytes\n"
                f"SHA-256: {artifact.sha256}\n"
                f"Source call: {artifact.source_call_id} · "
                f"Verifier result: {artifact.verification_result_id} · "
                "Evidence: "
                f"{artifact.verification_evidence_digest}"
            )
        active = task.state in _ACTIVE_STATES
        self._cancel_button.setEnabled(self._available and active)
        exact_approval = (
            self._available
            and task.state is TaskState.WAITING_FOR_APPROVAL
            and payload is not None
        )
        self._approve_button.setEnabled(exact_approval)
        self._reject_button.setEnabled(exact_approval)

    def _show_activity_metadata(
        self,
        current: QListWidgetItem | None,
        _previous: QListWidgetItem | None = None,
    ) -> None:
        activity = (
            current.data(_ACTIVITY_ROLE) if current is not None else None
        )
        if not isinstance(activity, TaskActivity):
            self._activity_details.clear()
            return
        lines = [
            f"Category: {activity.kind.value}",
            f"State: {activity.state.value}",
            f"Time: {_date_time(activity.created_at)}",
        ]
        lines.extend(
            f"{key}: {value}" for key, value in activity.metadata
        )
        self._activity_details.setPlainText("\n".join(lines))

    def _clear_details(self, message: str) -> None:
        self._current = None
        self._goal.setText(message)
        for widget in (
            self._identity,
            self._state,
            self._result,
            self._capabilities,
            self._limits,
            self._status,
        ):
            widget.clear()
        for widget in (
            self._activity,
            self._approvals,
            self._artifacts,
        ):
            widget.clear()
        self._activity_details.clear()
        self._desktop_action.clear()
        self._approval_preview.clear()
        self._cancel_button.setEnabled(False)
        self._approve_button.setEnabled(False)
        self._reject_button.setEnabled(False)

    @staticmethod
    def _task_list_text(task: TaskRecord) -> str:
        interrupted = " · interrupted" if task.interrupted else ""
        return (
            f"{task.skill_id}\n{task.state.value}{interrupted} · "
            f"{_date_time(task.created_at)}"
        )


def _activity_text(activity: TaskActivity) -> str:
    labels = {
        TaskActivityKind.LIFECYCLE: "Lifecycle",
        TaskActivityKind.MODEL_OUTPUT: "Model output (inert)",
        TaskActivityKind.TOOL_CALL: "Requested tool call",
        TaskActivityKind.TOOL_RESULT: "Actual tool result",
        TaskActivityKind.APPROVAL: "Approval",
        TaskActivityKind.VERIFIER_RESULT: "Verifier result",
        TaskActivityKind.ARTIFACT: "Verified artifact",
        TaskActivityKind.TERMINAL_OUTCOME: "Terminal outcome",
    }
    return (
        f"{labels[activity.kind]} · {_date_time(activity.created_at)}\n"
        f"{activity.title}"
    )


def _desktop_action_text(
    action: DesktopActionPresentation | None,
) -> str:
    if action is None:
        return "No reviewed desktop action is attached to this task."
    lines = [
        f"Target: {action.target_label} ({action.target_reference})",
        f"Action: {action.action_label}",
        f"Capability: {action.capability.value}",
        f"Approval: {action.approval_id}",
        f"Status: {action.status.value}",
        f"Target digest: {action.target_digest}",
        f"Action digest: {action.action_digest}",
    ]
    if action.result_code is not None:
        lines.append(f"Result: {action.result_code}")
    if action.observed_property is not None:
        lines.extend(
            (
                f"Observed property: {action.observed_property}",
                f"Before: {action.observed_before}",
                f"After: {action.observed_after}",
            )
        )
    if action.verifier_evidence_digest is not None:
        lines.append(
            "Verifier evidence: "
            + action.verifier_evidence_digest
        )
    return "\n".join(lines)


def _terminal_result(task: TaskRecord) -> str:
    if task.state is TaskState.COMPLETED:
        return (
            "Terminal result: completed from verifier evidence\n"
            f"Verifier result: {task.verifier_result_id}\n"
            f"Evidence: {task.verifier_evidence_digest}"
        )
    if task.result_code == INTERRUPTED_RESULT_CODE or task.interrupted:
        return (
            "Terminal result: interrupted on restart. This task was marked "
            "failed and was not resumed."
        )
    if task.state in {
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.EXPIRED,
    }:
        return (
            f"Terminal result: {task.state.value} · "
            f"{task.result_code or 'no_result_code'}"
        )
    return "Terminal result: pending independent verification"


def _duration(seconds: int) -> str:
    minutes, remaining = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {remaining}s"
    if minutes:
        return f"{minutes}m {remaining}s"
    return f"{remaining}s"


def _date_time(timestamp: float) -> str:
    try:
        value = datetime.fromtimestamp(timestamp).astimezone()
    except (OSError, OverflowError, ValueError):
        return "invalid timestamp"
    return value.strftime("%Y-%m-%d %H:%M:%S %Z")


__all__ = ["TaskCenterPanel"]
