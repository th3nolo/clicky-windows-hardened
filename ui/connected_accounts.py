"""Connected Accounts UI over non-secret lifecycle contracts."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from PyQt6.QtCore import QObject, QThread, Qt, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from capability_registry import (
    CAPABILITY_REGISTRY,
    CapabilityId,
    ConnectorId,
)
from connectors.accounts import (
    AccountConnectRequest,
    AccountConnectionAvailability,
    AccountConnectionResult,
    AccountDisconnectResult,
)
from connectors.base import (
    ConnectedAccount,
    ConnectorError,
    ConnectorProviderId,
    provider_for_connector,
)
from connectors.oauth import GOOGLE_PROVIDER_SCOPES, OAuthConsentSummary
from connectors.token_store import ConnectorTokenStoreError


_AUTHORIZATION_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 71


class ConnectedAccountsGateway(Protocol):
    def list_accounts(self) -> tuple[ConnectedAccount, ...]: ...

    def availability(
        self,
        provider: ConnectorProviderId,
    ) -> AccountConnectionAvailability: ...

    def describe_connection(
        self,
        request: AccountConnectRequest,
    ) -> OAuthConsentSummary: ...

    def connect(
        self,
        request: AccountConnectRequest,
    ) -> AccountConnectionResult: ...

    def reconnect(
        self,
        authorization_id: str,
    ) -> AccountConnectionResult: ...

    def revoke_and_disconnect(
        self,
        authorization_id: str,
    ) -> AccountDisconnectResult: ...

    def delete_local_token(
        self,
        authorization_id: str,
    ) -> AccountDisconnectResult: ...


class AccountConfirmationGateway(Protocol):
    def confirm_oauth(
        self,
        parent: QWidget,
        consent: OAuthConsentSummary,
        *,
        reconnect: bool,
    ) -> bool: ...

    def confirm_disconnect(
        self,
        parent: QWidget,
        account: ConnectedAccount,
        *,
        local_only: bool,
    ) -> bool: ...


class AccountOperationRunner(Protocol):
    @property
    def busy(self) -> bool: ...

    def submit(
        self,
        operation: Callable[[], object],
        succeeded: Callable[[object], None],
        failed: Callable[[str], None],
    ) -> bool: ...


class OAuthConsentReviewDialog(QDialog):
    """Positive confirmation of exact scopes before the system browser."""

    def __init__(
        self,
        consent: OAuthConsentSummary,
        *,
        reconnect: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        if not isinstance(consent, OAuthConsentSummary):
            raise TypeError("OAuth consent review is invalid")
        if type(reconnect) is not bool:
            raise TypeError("OAuth reconnect review must be explicit")
        super().__init__(parent)
        self.setWindowTitle(
            "Review account reconnection"
            if reconnect
            else "Review account connection"
        )
        self.setMinimumWidth(620)
        root = QVBoxLayout(self)

        title = QLabel(
            f"{'Reconnect' if reconnect else 'Connect'} "
            f"{_connector_label(consent.connector)}"
        )
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        root.addWidget(title)
        explanation = QLabel(
            "Clicky will open the system browser only after this review. "
            "This grants the listed account scopes; it does not grant Task "
            "Agent authority, approve any external action, or create a run "
            "capability grant."
        )
        explanation.setWordWrap(True)
        root.addWidget(explanation)

        root.addWidget(QLabel("Capabilities"))
        for capability in sorted(
            consent.capabilities,
            key=lambda value: value.value,
        ):
            definition = CAPABILITY_REGISTRY[capability]
            label = QLabel(
                f"• {definition.label}  ({capability.value})"
            )
            label.setWordWrap(True)
            root.addWidget(label)

        root.addWidget(QLabel("Semantic OAuth scopes"))
        for scope in sorted(
            consent.oauth_scopes,
            key=lambda value: value.value,
        ):
            root.addWidget(QLabel(f"• {scope.value}"))

        root.addWidget(QLabel("Provider scopes sent to the browser"))
        for scope in consent.provider_scopes:
            provider_scope = QLabel(f"• {scope}")
            provider_scope.setWordWrap(True)
            root.addWidget(provider_scope)

        self._confirmed = QCheckBox(
            "I approve exactly these scopes and want to continue in my "
            "system browser."
        )
        root.addWidget(self._confirmed)
        actions = QHBoxLayout()
        actions.addStretch()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        self._continue = QPushButton("Continue in system browser")
        self._continue.setEnabled(False)
        self._continue.clicked.connect(self.accept)
        self._confirmed.toggled.connect(self._continue.setEnabled)
        actions.addWidget(cancel)
        actions.addWidget(self._continue)
        root.addLayout(actions)

    @property
    def consent_confirmed(self) -> bool:
        return self._confirmed.isChecked()


class DefaultAccountConfirmations:
    def confirm_oauth(
        self,
        parent: QWidget,
        consent: OAuthConsentSummary,
        *,
        reconnect: bool,
    ) -> bool:
        dialog = OAuthConsentReviewDialog(
            consent,
            reconnect=reconnect,
            parent=parent,
        )
        return (
            dialog.exec() == QDialog.DialogCode.Accepted
            and dialog.consent_confirmed
        )

    def confirm_disconnect(
        self,
        parent: QWidget,
        account: ConnectedAccount,
        *,
        local_only: bool,
    ) -> bool:
        if local_only:
            title = "Delete local account token?"
            text = (
                "This removes Clicky's local token but does not revoke "
                "provider access. Use only when provider revocation is "
                "unavailable; you may still need to revoke Clicky from the "
                "provider's account settings."
            )
            button = "Delete local token only"
        else:
            title = "Revoke and disconnect account?"
            text = (
                "Clicky will first ask the provider to revoke this account "
                "authorization. The local protected token is deleted only "
                "after provider revocation succeeds."
            )
            button = "Revoke and disconnect"
        box = QMessageBox(parent)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText(text)
        confirm = box.addButton(
            button,
            QMessageBox.ButtonRole.DestructiveRole,
        )
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        return box.clickedButton() is confirm


class _OperationWorker(QObject):
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, operation: Callable[[], object]) -> None:
        super().__init__()
        self._operation = operation

    @pyqtSlot()
    def run(self) -> None:
        try:
            self.succeeded.emit(self._operation())
        except (ConnectorError, ConnectorTokenStoreError) as exc:
            self.failed.emit(str(exc))
        except Exception:
            self.failed.emit(
                "Connected-account operation failed without changing "
                "account authority."
            )
        finally:
            self.finished.emit()


class ThreadedAccountOperationRunner(QObject):
    """Keep browser/network/storage work off the Qt event thread."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: _OperationWorker | None = None

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def submit(
        self,
        operation: Callable[[], object],
        succeeded: Callable[[object], None],
        failed: Callable[[str], None],
    ) -> bool:
        if self.busy:
            return False
        if not all(callable(value) for value in (operation, succeeded, failed)):
            raise TypeError("Connected-account operation callbacks are invalid")
        thread = QThread(self)
        worker = _OperationWorker(operation)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.succeeded.connect(succeeded)
        worker.failed.connect(failed)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)

        def clear() -> None:
            self._thread = None
            self._worker = None

        thread.finished.connect(clear)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        self._worker = worker
        thread.start()
        return True


class ConnectedAccountsPanel(QWidget):
    """Inspectable account scope and lifecycle controls; never run authority."""

    account_changed = pyqtSignal(str, str)

    def __init__(
        self,
        gateway: ConnectedAccountsGateway,
        *,
        available_capabilities: frozenset[CapabilityId],
        confirmations: AccountConfirmationGateway | None = None,
        operation_runner: AccountOperationRunner | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        required_methods = (
            "list_accounts",
            "availability",
            "describe_connection",
            "connect",
            "reconnect",
            "revoke_and_disconnect",
            "delete_local_token",
        )
        if not all(
            callable(getattr(gateway, name, None))
            for name in required_methods
        ):
            raise TypeError("Connected Accounts gateway is invalid")
        if (
            not isinstance(available_capabilities, frozenset)
            or any(
                not isinstance(capability, CapabilityId)
                or CAPABILITY_REGISTRY[capability].connector is None
                for capability in available_capabilities
            )
        ):
            raise TypeError(
                "Connected Accounts capabilities must be exact connectors"
            )
        confirmations = (
            confirmations
            if confirmations is not None
            else DefaultAccountConfirmations()
        )
        if not (
            callable(getattr(confirmations, "confirm_oauth", None))
            and callable(
                getattr(confirmations, "confirm_disconnect", None)
            )
        ):
            raise TypeError("Connected Accounts confirmations are invalid")
        runner = (
            operation_runner
            if operation_runner is not None
            else ThreadedAccountOperationRunner(self)
        )
        if not callable(getattr(runner, "submit", None)):
            raise TypeError("Connected Accounts operation runner is invalid")

        self._gateway = gateway
        self._available_capabilities = available_capabilities
        self._confirmations = confirmations
        self._runner = runner
        self._accounts: dict[str, ConnectedAccount] = {}
        self._scope_checks: dict[CapabilityId, QCheckBox] = {}
        self._busy = False

        self.setWindowTitle("Connected Accounts")
        self.setMinimumSize(940, 650)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)
        root = QVBoxLayout(self)
        intro = QLabel(
            "Connected Accounts grants explicit, revocable provider scopes. "
            "It does not grant Task Agent permission, per-run capability "
            "authority, or approval for an external action."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        connect_row = QHBoxLayout()
        self._connector_combo = QComboBox()
        self._connector_combo.currentIndexChanged.connect(
            self._rebuild_scope_choices
        )
        connect_row.addWidget(QLabel("Service"))
        connect_row.addWidget(self._connector_combo)
        self._connect_button = QPushButton("Review scopes and connect…")
        self._connect_button.clicked.connect(self.connect_selected_service)
        connect_row.addWidget(self._connect_button)
        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.clicked.connect(self.refresh)
        connect_row.addWidget(self._refresh_button)
        root.addLayout(connect_row)

        self._scope_area = QWidget()
        self._scope_layout = QVBoxLayout(self._scope_area)
        self._scope_layout.setContentsMargins(0, 0, 0, 0)
        root.addWidget(self._scope_area)
        self._connection_availability = QLabel("")
        self._connection_availability.setWordWrap(True)
        root.addWidget(self._connection_availability)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self._account_list = QListWidget()
        self._account_list.currentItemChanged.connect(
            self._load_selected_account
        )
        splitter.addWidget(self._account_list)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        details = QWidget()
        detail_layout = QVBoxLayout(details)
        self._identity = QLabel("Choose a connected account")
        self._identity.setWordWrap(True)
        self._identity.setStyleSheet("font-size: 17px; font-weight: 600;")
        self._provider = QLabel("")
        self._provider.setWordWrap(True)
        self._health = QLabel("")
        self._health.setWordWrap(True)
        self._capabilities = QLabel("")
        self._capabilities.setWordWrap(True)
        self._semantic_scopes = QLabel("")
        self._semantic_scopes.setWordWrap(True)
        self._provider_scopes = QLabel("")
        self._provider_scopes.setWordWrap(True)
        for label in (
            self._identity,
            self._provider,
            self._health,
            self._capabilities,
            self._semantic_scopes,
            self._provider_scopes,
        ):
            detail_layout.addWidget(label)

        actions = QHBoxLayout()
        self._reconnect_button = QPushButton("Review and reconnect…")
        self._reconnect_button.clicked.connect(self.reconnect_selected)
        self._revoke_button = QPushButton("Revoke and disconnect…")
        self._revoke_button.clicked.connect(
            self.revoke_and_disconnect_selected
        )
        self._delete_local_button = QPushButton(
            "Delete local token only…"
        )
        self._delete_local_button.clicked.connect(
            self.delete_local_selected
        )
        actions.addWidget(self._reconnect_button)
        actions.addWidget(self._revoke_button)
        actions.addWidget(self._delete_local_button)
        detail_layout.addLayout(actions)
        detail_layout.addStretch()
        self._status = QLabel("")
        self._status.setWordWrap(True)
        detail_layout.addWidget(self._status)
        scroll.setWidget(details)
        splitter.addWidget(scroll)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, stretch=1)

        connectors = sorted(
            {
                CAPABILITY_REGISTRY[capability].connector
                for capability in available_capabilities
            },
            key=lambda value: value.value,
        )
        for connector in connectors:
            self._connector_combo.addItem(
                _connector_label(connector),
                connector,
            )
        self._rebuild_scope_choices()
        self.refresh()

    def selected_account(self) -> ConnectedAccount | None:
        item = self._account_list.currentItem()
        if item is None:
            return None
        authorization_id = item.data(_AUTHORIZATION_ID_ROLE)
        return self._accounts.get(authorization_id)

    def selected_connect_request(self) -> AccountConnectRequest | None:
        connector = self._connector_combo.currentData()
        if not isinstance(connector, ConnectorId):
            return None
        capabilities = frozenset(
            capability
            for capability, checkbox in self._scope_checks.items()
            if checkbox.isChecked()
        )
        if not capabilities:
            return None
        return AccountConnectRequest(
            connector=connector,
            capabilities=capabilities,
        )

    def refresh(self) -> None:
        wanted = (
            self.selected_account().authorization_id
            if self.selected_account() is not None
            else None
        )
        try:
            accounts = self._gateway.list_accounts()
            if (
                not isinstance(accounts, tuple)
                or any(
                    not isinstance(account, ConnectedAccount)
                    for account in accounts
                )
            ):
                raise TypeError
        except (ConnectorError, ConnectorTokenStoreError) as exc:
            accounts = ()
            self._status.setText(str(exc))
        except Exception:
            accounts = ()
            self._status.setText(
                "Connected-account metadata is unavailable; account "
                "actions remain disabled."
            )
        self._accounts = {
            account.authorization_id: account
            for account in accounts
        }
        self._account_list.blockSignals(True)
        self._account_list.clear()
        selected_row = -1
        for row, account in enumerate(accounts):
            item = QListWidgetItem(
                f"{_provider_label(account.provider)} · "
                f"{_connector_label(account.connector)} · "
                f"{account.health.value}"
            )
            item.setData(
                _AUTHORIZATION_ID_ROLE,
                account.authorization_id,
            )
            self._account_list.addItem(item)
            if account.authorization_id == wanted:
                selected_row = row
        self._account_list.blockSignals(False)
        if selected_row >= 0:
            self._account_list.setCurrentRow(selected_row)
        elif accounts:
            self._account_list.setCurrentRow(0)
        else:
            self._clear_account_details()
        self._update_controls()

    def connect_selected_service(self) -> None:
        request = self.selected_connect_request()
        if request is None or self._busy:
            self._status.setText(
                "Select at least one exact capability before connecting."
            )
            return
        try:
            consent = self._gateway.describe_connection(request)
        except (ConnectorError, ConnectorTokenStoreError) as exc:
            self._status.setText(str(exc))
            return
        except Exception:
            self._status.setText(
                "Account scope review is unavailable; no browser was opened."
            )
            return
        if not self._confirmations.confirm_oauth(
            self,
            consent,
            reconnect=False,
        ):
            self._status.setText(
                "Account connection cancelled; no scope was granted."
            )
            return
        self._start_operation(
            lambda: self._gateway.connect(request),
            success_message="Account connected with the reviewed scopes.",
        )

    def reconnect_selected(self) -> None:
        account = self.selected_account()
        if account is None or self._busy:
            return
        request = AccountConnectRequest(
            connector=account.connector,
            capabilities=account.capabilities,
        )
        try:
            consent = self._gateway.describe_connection(request)
        except (ConnectorError, ConnectorTokenStoreError) as exc:
            self._status.setText(str(exc))
            return
        except Exception:
            self._status.setText(
                "Account scope review is unavailable; no browser was opened."
            )
            return
        if not self._confirmations.confirm_oauth(
            self,
            consent,
            reconnect=True,
        ):
            self._status.setText(
                "Account reconnection cancelled; existing authority was kept."
            )
            return
        self._start_operation(
            lambda: self._gateway.reconnect(account.authorization_id),
            success_message="Account reconnected with the same exact scopes.",
        )

    def revoke_and_disconnect_selected(self) -> None:
        account = self.selected_account()
        if account is None or self._busy:
            return
        if not self._confirmations.confirm_disconnect(
            self,
            account,
            local_only=False,
        ):
            self._status.setText(
                "Revocation cancelled; account authority was unchanged."
            )
            return
        self._start_operation(
            lambda: self._gateway.revoke_and_disconnect(
                account.authorization_id
            ),
            success_message=(
                "Provider access was revoked and the local token was deleted."
            ),
        )

    def delete_local_selected(self) -> None:
        account = self.selected_account()
        if account is None or self._busy:
            return
        if not self._confirmations.confirm_disconnect(
            self,
            account,
            local_only=True,
        ):
            self._status.setText(
                "Local deletion cancelled; account authority was unchanged."
            )
            return
        self._start_operation(
            lambda: self._gateway.delete_local_token(
                account.authorization_id
            ),
            success_message=(
                "The local token was deleted. Provider access was not "
                "claimed as revoked."
            ),
        )

    def _start_operation(
        self,
        operation: Callable[[], object],
        *,
        success_message: str,
    ) -> None:
        self._busy = True
        self._status.setText(
            "Account operation in progress. Tokens remain outside the UI."
        )
        self._update_controls()

        def succeeded(result: object) -> None:
            if not isinstance(
                result,
                (AccountConnectionResult, AccountDisconnectResult),
            ):
                failed("Connected-account operation returned invalid evidence.")
                return
            authorization_id = result.authorization_id if isinstance(
                result,
                AccountDisconnectResult,
            ) else result.account.authorization_id
            self._busy = False
            self.refresh()
            self._status.setText(success_message)
            self.account_changed.emit(
                authorization_id,
                result.status.value,
            )

        def failed(message: str) -> None:
            self._busy = False
            self._status.setText(message)
            self.refresh()
            self._update_controls()

        if not self._runner.submit(operation, succeeded, failed):
            self._busy = False
            self._status.setText(
                "Another connected-account operation is already running."
            )
            self._update_controls()

    def _rebuild_scope_choices(self) -> None:
        while self._scope_layout.count():
            item = self._scope_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self._scope_checks.clear()
        connector = self._connector_combo.currentData()
        if isinstance(connector, ConnectorId):
            capabilities = sorted(
                (
                    capability
                    for capability in self._available_capabilities
                    if CAPABILITY_REGISTRY[capability].connector
                    is connector
                ),
                key=lambda value: value.value,
            )
            for capability in capabilities:
                definition = CAPABILITY_REGISTRY[capability]
                checkbox = QCheckBox(
                    f"{definition.label}  ({capability.value})"
                )
                checkbox.setChecked(
                    not definition.action_approval_required
                )
                checkbox.toggled.connect(self._update_controls)
                self._scope_layout.addWidget(checkbox)
                self._scope_checks[capability] = checkbox
        self._update_connection_availability()
        self._update_controls()

    def _update_connection_availability(self) -> None:
        connector = self._connector_combo.currentData()
        if not isinstance(connector, ConnectorId):
            self._connection_availability.setText(
                "No connector capability is available in this build."
            )
            return
        provider = provider_for_connector(connector)
        availability = self._safe_availability(provider)
        if availability is AccountConnectionAvailability.READY:
            text = (
                "Ready for reviewed system-browser authorization. "
                "Read and write scopes stay independent."
            )
        elif (
            availability
            is AccountConnectionAvailability
            .MISSING_PUBLIC_CLIENT_REGISTRATION
        ):
            text = (
                "Connection is unavailable until this build has an approved "
                "public Google desktop OAuth client registration."
            )
        elif (
            availability
            is AccountConnectionAvailability.CONFIDENTIAL_BROKER_REQUIRED
        ):
            text = (
                "Connection is intentionally unavailable until a reviewed "
                "confidential OAuth broker exists."
            )
        else:
            text = "Connection availability could not be verified."
        self._connection_availability.setText(text)

    def _load_selected_account(self) -> None:
        account = self.selected_account()
        if account is None:
            self._clear_account_details()
            return
        self._identity.setText(
            f"{_connector_label(account.connector)} account "
            f"{account.account_reference}"
        )
        self._provider.setText(
            f"Provider: {_provider_label(account.provider)}\n"
            f"Authorization ID: {account.authorization_id}"
        )
        self._health.setText(f"Connection health: {account.health.value}")
        capability_lines = [
            f"{CAPABILITY_REGISTRY[value].label} ({value.value})"
            for value in sorted(
                account.capabilities,
                key=lambda item: item.value,
            )
        ]
        self._capabilities.setText(
            "Capabilities:\n" + "\n".join(capability_lines)
        )
        self._semantic_scopes.setText(
            "Semantic OAuth scopes:\n"
            + "\n".join(
                scope.value
                for scope in sorted(
                    account.oauth_scopes,
                    key=lambda item: item.value,
                )
            )
        )
        provider_scopes = _account_provider_scopes(account)
        self._provider_scopes.setText(
            "Provider scopes:\n"
            + (
                "\n".join(provider_scopes)
                if provider_scopes
                else "Unavailable until a reviewed provider broker exists."
            )
        )
        self._update_controls()

    def _clear_account_details(self) -> None:
        self._identity.setText("No connected accounts")
        self._provider.setText("")
        self._health.setText("")
        self._capabilities.setText("")
        self._semantic_scopes.setText("")
        self._provider_scopes.setText("")
        self._update_controls()

    def _update_controls(self) -> None:
        account = self.selected_account()
        request = self.selected_connect_request()
        connector = self._connector_combo.currentData()
        availability = None
        if isinstance(connector, ConnectorId):
            availability = self._safe_availability(
                provider_for_connector(connector)
            )
        can_connect = (
            not self._busy
            and request is not None
            and availability is AccountConnectionAvailability.READY
        )
        self._connect_button.setEnabled(can_connect)
        self._refresh_button.setEnabled(not self._busy)
        has_account = account is not None and not self._busy
        self._reconnect_button.setEnabled(
            has_account
            and self._safe_availability(account.provider)
            is AccountConnectionAvailability.READY
        )
        self._revoke_button.setEnabled(
            has_account
            and self._safe_availability(account.provider)
            in {
                AccountConnectionAvailability.READY,
                AccountConnectionAvailability
                .MISSING_PUBLIC_CLIENT_REGISTRATION,
            }
        )
        self._delete_local_button.setEnabled(has_account)
        self._connector_combo.setEnabled(not self._busy)
        for checkbox in self._scope_checks.values():
            checkbox.setEnabled(not self._busy)

    def _safe_availability(
        self,
        provider: ConnectorProviderId,
    ) -> AccountConnectionAvailability | None:
        try:
            value = self._gateway.availability(provider)
        except Exception:
            return None
        return (
            value
            if isinstance(value, AccountConnectionAvailability)
            else None
        )


def _provider_label(provider: ConnectorProviderId) -> str:
    return {
        ConnectorProviderId.GOOGLE: "Google",
        ConnectorProviderId.NOTION: "Notion",
    }[provider]


def _connector_label(connector: ConnectorId) -> str:
    return {
        ConnectorId.GMAIL: "Gmail",
        ConnectorId.GOOGLE_CALENDAR: "Google Calendar",
        ConnectorId.GOOGLE_DRIVE: "Google Drive",
        ConnectorId.NOTION: "Notion",
        ConnectorId.GOOGLE_SHEETS: "Google Sheets",
        ConnectorId.GOOGLE_SLIDES: "Google Slides",
    }[connector]


def _account_provider_scopes(
    account: ConnectedAccount,
) -> tuple[str, ...]:
    if account.provider is not ConnectorProviderId.GOOGLE:
        return ()
    return tuple(
        sorted(
            {
                GOOGLE_PROVIDER_SCOPES[scope]
                for scope in account.oauth_scopes
            }
        )
    )


__all__ = [
    "AccountConfirmationGateway",
    "AccountOperationRunner",
    "ConnectedAccountsGateway",
    "ConnectedAccountsPanel",
    "DefaultAccountConfirmations",
    "OAuthConsentReviewDialog",
    "ThreadedAccountOperationRunner",
]
