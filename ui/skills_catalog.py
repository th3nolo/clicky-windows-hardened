"""Inspectable, permission-reviewed catalog for consumer Declarative Skills."""

from __future__ import annotations

from typing import Iterable, Mapping, Protocol, Any

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from capability_registry import require_capability
from feature_gates import ActionCapability, build_feature_available
from skills.registry import (
    DEVELOPER_PYTHON_WARNING,
    SkillCatalogEntry,
    SkillEnablementStore,
    SkillKind,
    SkillRegistrationStatus,
    SkillRegistryError,
    SkillRegistrySnapshot,
    combined_skill_catalog,
    permission_review_digest,
)


_CATALOG_ID_ROLE = int(Qt.ItemDataRole.UserRole)


class PermissionReviewGateway(Protocol):
    def review(
        self,
        parent: QWidget,
        entry: SkillCatalogEntry,
        review_digest: str,
    ) -> str | None: ...


def _capability_lines(entry: SkillCatalogEntry) -> tuple[str, ...]:
    return tuple(
        f"{require_capability(capability).label} ({capability.value})"
        for capability in entry.capabilities
    )


class SkillPermissionReviewDialog(QDialog):
    """Requires a positive checkbox after showing every declared authority."""

    def __init__(
        self,
        entry: SkillCatalogEntry,
        *,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if (
            not isinstance(entry, SkillCatalogEntry)
            or entry.kind is not SkillKind.DECLARATIVE
            or entry.definition is None
        ):
            raise TypeError(
                "Permission review requires a Declarative Skill"
            )
        self._entry = entry
        self.setWindowTitle(f"Review permissions — {entry.name}")
        self.setMinimumSize(620, 520)

        root = QVBoxLayout(self)
        title = QLabel(f"Enable {entry.name}?")
        title.setStyleSheet("font-size: 17px; font-weight: 600;")
        root.addWidget(title)
        identity = QLabel(
            f"Version {entry.version} · {entry.publisher_name} · "
            f"{entry.origin.value}"
        )
        identity.setWordWrap(True)
        root.addWidget(identity)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.addWidget(QLabel("Required capabilities"))
        for line in _capability_lines(entry):
            label = QLabel(f"• {line}")
            label.setWordWrap(True)
            content_layout.addWidget(label)

        definition = entry.definition
        if definition.connectors:
            content_layout.addWidget(QLabel("Connected-account scopes"))
            for requirement in definition.connectors:
                scopes = ", ".join(
                    sorted(
                        scope.value
                        for scope in requirement.oauth_scopes
                    )
                )
                label = QLabel(
                    f"• {requirement.connector.value}: {scopes}"
                )
                label.setWordWrap(True)
                content_layout.addWidget(label)

        if definition.approvals:
            content_layout.addWidget(QLabel("Actions requiring approval"))
            for approval in definition.approvals:
                label = QLabel(
                    f"• {approval.reason} "
                    f"({approval.capability.value})"
                )
                label.setWordWrap(True)
                content_layout.addWidget(label)

        limits = definition.limits
        content_layout.addWidget(QLabel("Hard limits"))
        limit_text = QLabel(
            f"Runtime: {limits.runtime_seconds}s · "
            f"tool calls: {limits.max_tool_calls} · "
            f"network requests: {limits.max_network_requests} · "
            f"output: {limits.max_output_bytes} bytes"
        )
        limit_text.setWordWrap(True)
        content_layout.addWidget(limit_text)

        invocation = definition.invocation
        if invocation.mode.value == "explicit":
            invocation_text = "Invocation: explicit catalog selection only"
        else:
            invocation_text = (
                "Invocation: exact declared phrases only — "
                + ", ".join(invocation.phrases)
            )
        invocation_label = QLabel(invocation_text)
        invocation_label.setWordWrap(True)
        content_layout.addWidget(invocation_label)
        content_layout.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll, stretch=1)

        self._confirmed = QCheckBox(
            "I reviewed every capability, connector scope, approval, "
            "and limit shown above."
        )
        self._confirmed.setChecked(False)
        root.addWidget(self._confirmed)

        buttons = QHBoxLayout()
        buttons.addStretch()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        enable = QPushButton("Enable skill")
        enable.setEnabled(False)
        enable.clicked.connect(self.accept)
        self._confirmed.toggled.connect(enable.setEnabled)
        buttons.addWidget(cancel)
        buttons.addWidget(enable)
        root.addLayout(buttons)
        self._enable_button = enable

    @property
    def permission_confirmed(self) -> bool:
        return self._confirmed.isChecked()


class QtPermissionReviewGateway:
    def review(
        self,
        parent: QWidget,
        entry: SkillCatalogEntry,
        review_digest: str,
    ) -> str | None:
        if not isinstance(review_digest, str):
            raise TypeError("Permission review digest must be text")
        dialog = SkillPermissionReviewDialog(entry, parent=parent)
        if (
            dialog.exec() == QDialog.DialogCode.Accepted
            and dialog.permission_confirmed
        ):
            return review_digest
        return None


class SkillsCatalogPanel(QWidget):
    """Show provenance and require review before changing enablement."""

    skill_enabled_changed = pyqtSignal(str, bool)

    def __init__(
        self,
        snapshot: SkillRegistrySnapshot,
        enablement: SkillEnablementStore,
        *,
        developer_skills: Iterable[Mapping[str, Any]] = (),
        review_gateway: PermissionReviewGateway | None = None,
        task_agent_available: bool | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(snapshot, SkillRegistrySnapshot):
            raise TypeError("Skills Catalog requires a registry snapshot")
        if not isinstance(enablement, SkillEnablementStore):
            raise TypeError("Skills Catalog requires an enablement store")
        self._snapshot = snapshot
        self._enablement = enablement
        self._entries = combined_skill_catalog(
            snapshot,
            developer_skills,
        )
        self._review = review_gateway or QtPermissionReviewGateway()
        self._task_agent_available = (
            build_feature_available(ActionCapability.TASK_AGENT)
            if task_agent_available is None
            else task_agent_available
        )
        if type(self._task_agent_available) is not bool:
            raise TypeError("Task Agent availability must be explicit")

        self.setWindowTitle("Skills")
        self.setMinimumSize(820, 570)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)

        root = QVBoxLayout(self)
        intro = QLabel(
            "Consumer skills are data-only workflows. Review every declared "
            "permission before enabling one. Developer Skills are separate "
            "arbitrary-code extensions."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter, stretch=1)
        self._list = QListWidget()
        self._list.currentItemChanged.connect(self._load_selected)
        splitter.addWidget(self._list)

        details = QWidget()
        detail_layout = QVBoxLayout(details)
        self._title = QLabel("Choose a skill")
        self._title.setStyleSheet("font-size: 17px; font-weight: 600;")
        self._identity = QLabel("")
        self._identity.setWordWrap(True)
        self._state = QLabel("")
        self._state.setWordWrap(True)
        self._permissions = QLabel("")
        self._permissions.setWordWrap(True)
        self._connectors = QLabel("")
        self._connectors.setWordWrap(True)
        self._invocation = QLabel("")
        self._invocation.setWordWrap(True)
        self._limits = QLabel("")
        self._limits.setWordWrap(True)
        self._warning = QLabel("")
        self._warning.setWordWrap(True)
        self._warning.setStyleSheet("color: #d39a45;")
        for widget in (
            self._title,
            self._identity,
            self._state,
            self._permissions,
            self._connectors,
            self._invocation,
            self._limits,
            self._warning,
        ):
            detail_layout.addWidget(widget)
        detail_layout.addStretch()

        actions = QHBoxLayout()
        self._enable_button = QPushButton("Review and enable…")
        self._enable_button.clicked.connect(self.enable_selected)
        self._disable_button = QPushButton("Disable")
        self._disable_button.clicked.connect(self.disable_selected)
        actions.addWidget(self._enable_button)
        actions.addWidget(self._disable_button)
        actions.addStretch()
        detail_layout.addLayout(actions)
        self._status = QLabel("")
        self._status.setWordWrap(True)
        detail_layout.addWidget(self._status)
        splitter.addWidget(details)
        splitter.setStretchFactor(1, 2)

        self.refresh()

    def refresh(self, catalog_id: str | None = None) -> None:
        selected = catalog_id
        if selected is None:
            current = self._list.currentItem()
            if current is not None:
                selected = current.data(_CATALOG_ID_ROLE)
        self._list.blockSignals(True)
        self._list.clear()
        selected_row = -1
        for row, entry in enumerate(self._entries):
            suffix = self._list_suffix(entry)
            item = QListWidgetItem(f"{entry.name}{suffix}")
            item.setData(_CATALOG_ID_ROLE, entry.catalog_id)
            self._list.addItem(item)
            if entry.catalog_id == selected:
                selected_row = row
        self._list.blockSignals(False)
        if selected_row >= 0:
            self._list.setCurrentRow(selected_row)
        elif self._entries:
            self._list.setCurrentRow(0)
        else:
            self._clear_details()

    def selected_entry(self) -> SkillCatalogEntry | None:
        item = self._list.currentItem()
        if item is None:
            return None
        catalog_id = item.data(_CATALOG_ID_ROLE)
        return next(
            (
                entry
                for entry in self._entries
                if entry.catalog_id == catalog_id
            ),
            None,
        )

    def enable_selected(self) -> None:
        entry = self.selected_entry()
        if (
            entry is None
            or entry.kind is not SkillKind.DECLARATIVE
            or entry.status is not SkillRegistrationStatus.AVAILABLE
        ):
            self._status.setText(
                "Only compatible consumer Declarative Skills can be enabled."
            )
            return
        if not self._task_agent_available:
            self._status.setText(
                "Task Agent is unavailable in this build or not permitted "
                "in Privacy settings; no skill changed."
            )
            return
        digest = permission_review_digest(entry)
        try:
            reviewed = self._review.review(self, entry, digest)
            if reviewed is None:
                self._status.setText(
                    "Enablement cancelled; no permission was granted."
                )
                return
            self._enablement.enable(
                entry,
                reviewed_permission_digest=reviewed,
            )
            self._status.setText(
                "Skill enabled for new explicit or exact-phrase requests."
            )
            self.skill_enabled_changed.emit(entry.skill_id, True)
            self.refresh(entry.catalog_id)
        except (SkillRegistryError, TypeError, ValueError) as error:
            self._status.setText(str(error))

    def disable_selected(self) -> None:
        entry = self.selected_entry()
        if entry is None or entry.kind is not SkillKind.DECLARATIVE:
            self._status.setText(
                "Developer Skills are managed through their separate "
                "hash allowlist."
            )
            return
        try:
            self._enablement.disable(entry.skill_id)
            self._status.setText(
                "Skill disabled immediately for new invocations."
            )
            self.skill_enabled_changed.emit(entry.skill_id, False)
            self.refresh(entry.catalog_id)
        except (SkillRegistryError, TypeError, ValueError) as error:
            self._status.setText(str(error))

    def _list_suffix(self, entry: SkillCatalogEntry) -> str:
        if entry.kind is SkillKind.DEVELOPER_PYTHON:
            return " · Developer Skill"
        if (
            entry.status
            is SkillRegistrationStatus.DISABLED_INCOMPATIBLE
        ):
            return " · incompatible"
        return (
            " · enabled"
            if self._enablement.is_enabled(entry)
            else " · disabled"
        )

    def _load_selected(
        self,
        _current: QListWidgetItem | None = None,
        _previous: QListWidgetItem | None = None,
    ) -> None:
        entry = self.selected_entry()
        if entry is None:
            self._clear_details()
            return
        self._title.setText(entry.name)
        self._identity.setText(
            f"Version: {entry.version}\n"
            f"Publisher: {entry.publisher_name} ({entry.publisher_id})\n"
            f"Origin: {entry.origin.value}\n"
            f"Package digest: {entry.package_digest}"
        )
        if entry.kind is SkillKind.DEVELOPER_PYTHON:
            self._state.setText("State: managed by Developer Skill allowlist")
            self._permissions.setText(
                "Declared capabilities: none. Python code is not bounded by "
                "the consumer capability schema."
            )
            self._connectors.clear()
            self._invocation.setText(
                "Invocation: legacy developer-defined trigger"
            )
            self._limits.setText("Hard consumer limits: not applicable")
            self._warning.setText(DEVELOPER_PYTHON_WARNING)
            self._enable_button.setEnabled(False)
            self._disable_button.setEnabled(False)
            return

        enabled = self._enablement.is_enabled(entry)
        self._state.setText(
            f"Compatibility: {entry.status.value}\n"
            f"Enabled for new invocations: {'yes' if enabled else 'no'}"
        )
        capability_lines = _capability_lines(entry)
        self._permissions.setText(
            "Declared capabilities:\n"
            + "\n".join(f"• {line}" for line in capability_lines)
        )
        definition = entry.definition
        assert definition is not None
        if definition.connectors:
            connector_lines = []
            for requirement in definition.connectors:
                connector_lines.append(
                    f"• {requirement.connector.value}: "
                    + ", ".join(
                        sorted(
                            scope.value
                            for scope in requirement.oauth_scopes
                        )
                    )
                )
            self._connectors.setText(
                "Connector scopes:\n" + "\n".join(connector_lines)
            )
        else:
            self._connectors.setText("Connector scopes: none")
        if definition.invocation.mode.value == "explicit":
            self._invocation.setText(
                "Invocation: explicit catalog selection only"
            )
        else:
            self._invocation.setText(
                "Invocation: exact phrases only\n"
                + "\n".join(
                    f"• {phrase}"
                    for phrase in definition.invocation.phrases
                )
            )
        limits = definition.limits
        self._limits.setText(
            "Hard limits: "
            f"{limits.runtime_seconds}s, "
            f"{limits.max_tool_calls} tool calls, "
            f"{limits.max_network_requests} network requests, "
            f"{limits.max_output_bytes} output bytes"
        )
        self._warning.clear()
        available = (
            self._task_agent_available
            and entry.status is SkillRegistrationStatus.AVAILABLE
        )
        self._enable_button.setEnabled(available and not enabled)
        self._disable_button.setEnabled(enabled)

    def _clear_details(self) -> None:
        self._title.setText("No skills are installed")
        for widget in (
            self._identity,
            self._state,
            self._permissions,
            self._connectors,
            self._invocation,
            self._limits,
            self._warning,
            self._status,
        ):
            widget.clear()
        self._enable_button.setEnabled(False)
        self._disable_button.setEnabled(False)


__all__ = [
    "PermissionReviewGateway",
    "QtPermissionReviewGateway",
    "SkillPermissionReviewDialog",
    "SkillsCatalogPanel",
]
