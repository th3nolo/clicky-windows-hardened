"""Opt-in Windows app suggestions with no retained inventory."""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
)

from config import cfg
from onboarding.app_suggestions import (
    AppNameSource,
    AppSuggestion,
    discover_local_app_suggestions,
)


_active_dialog: AppSuggestionsDialog | None = None


class AppSuggestionsDialog(QDialog):
    """Show local suggestions only after an explicit scan action."""

    def __init__(
        self,
        parent=None,
        *,
        configuration=cfg,
        source: AppNameSource | None = None,
        scanner: Callable[..., tuple[AppSuggestion, ...]] = (
            discover_local_app_suggestions
        ),
    ):
        super().__init__(parent)
        self._configuration = configuration
        self._source = source
        self._scanner = scanner
        self._suggestions: tuple[AppSuggestion, ...] = ()
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle("Local app suggestions")
        self.setMinimumSize(620, 470)
        self.setModal(False)
        self.setStyleSheet(
            "QDialog { background: #0e1014; color: #e8eaed; }"
            "QLabel { color: #e8eaed; }"
            "QLabel#title { font-size: 21px; font-weight: 700; }"
            "QLabel#privacy { color: #a8b0c0; font-size: 12px; }"
            "QListWidget { background: #171b24; color: #edf1fa;"
            " border: 1px solid #30384a; border-radius: 9px;"
            " padding: 7px; }"
            "QPushButton { background: #2f6feb; color: white; border: none;"
            " padding: 9px 15px; border-radius: 8px; font-weight: 600; }"
            "QPushButton#secondary { background: transparent; color: #c8cfdd;"
            " border: 1px solid #343c4d; }"
            "QPushButton#danger { background: transparent; color: #ffb4b4;"
            " border: 1px solid #6d3535; }"
        )
        self._build_ui()
        self._render_privacy_state()

    @property
    def suggestions(self) -> tuple[AppSuggestion, ...]:
        return self._suggestions

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 22)
        layout.setSpacing(12)

        title = QLabel("Ideas for apps already on this PC")
        title.setObjectName("title")
        layout.addWidget(title)

        explanation = QLabel(
            "Clicky can read only installed application display names from "
            "fixed Windows uninstall registry locations, then suggest how its "
            "existing features may help. It does not inspect app files, paths, "
            "icons, content, windows, or accounts."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)

        self.privacy = QLabel("")
        self.privacy.setObjectName("privacy")
        self.privacy.setWordWrap(True)
        layout.addWidget(self.privacy)

        self.results = QListWidget()
        self.results.setAccessibleName("Local app suggestions")
        layout.addWidget(self.results, 1)

        buttons = QHBoxLayout()
        self.scan_button = QPushButton("")
        self.scan_button.clicked.connect(self._scan_or_enable)
        buttons.addWidget(self.scan_button)
        self.disable_button = QPushButton("Disable suggestions")
        self.disable_button.setObjectName("danger")
        self.disable_button.clicked.connect(self._disable)
        buttons.addWidget(self.disable_button)
        buttons.addStretch(1)
        dismiss = QPushButton("Dismiss")
        dismiss.setObjectName("secondary")
        dismiss.clicked.connect(self.close)
        buttons.addWidget(dismiss)
        layout.addLayout(buttons)

    def _render_privacy_state(self) -> None:
        disabled = self._configuration.app_suggestions_disabled is True
        consent = self._configuration.app_suggestions_consent is True
        if disabled:
            self.privacy.setText(
                "Suggestions are disabled. Re-enabling does not scan; a second "
                "explicit action is still required."
            )
            self.scan_button.setText("Enable suggestions")
            self.disable_button.setEnabled(False)
        elif consent:
            self.privacy.setText(
                "Local-name access is approved. Results remain in this window "
                "only and are cleared when it closes."
            )
            self.scan_button.setText("Scan app names locally")
            self.disable_button.setEnabled(True)
        else:
            self.privacy.setText(
                "No app names have been read. Choosing Scan gives explicit "
                "consent for this local enumeration; no inventory is saved."
            )
            self.scan_button.setText("Scan locally and allow")
            self.disable_button.setEnabled(True)

    def _scan_or_enable(self) -> None:
        if self._configuration.app_suggestions_disabled is True:
            self._configuration.set_app_suggestions_preferences(
                consent=False,
                disabled=False,
            )
            self._clear_results()
            self._render_privacy_state()
            return
        if self._configuration.app_suggestions_consent is not True:
            self._configuration.set_app_suggestions_preferences(
                consent=True,
                disabled=False,
            )
        try:
            suggestions = self._scanner(
                consent=self._configuration.app_suggestions_consent,
                disabled=self._configuration.app_suggestions_disabled,
                source=self._source,
            )
        except (PermissionError, OSError, RuntimeError) as exc:
            self._clear_results()
            self.privacy.setText(
                "The local app-name scan did not complete: " + str(exc)
            )
            return
        self._suggestions = tuple(suggestions)
        self.results.clear()
        if not self._suggestions:
            self.results.addItem(
                "No suitable app display names were found. Nothing was saved."
            )
        else:
            for suggestion in self._suggestions:
                item = QListWidgetItem(
                    suggestion.app_name + "\n" + suggestion.use_case
                )
                item.setData(Qt.ItemDataRole.UserRole, None)
                self.results.addItem(item)
        self._render_privacy_state()

    def _disable(self) -> None:
        self._configuration.set_app_suggestions_preferences(
            consent=False,
            disabled=True,
        )
        self._clear_results()
        self._render_privacy_state()

    def _clear_results(self) -> None:
        self._suggestions = ()
        self.results.clear()

    def closeEvent(self, event) -> None:
        self._clear_results()
        _clear_active_dialog(self)
        super().closeEvent(event)


def _clear_active_dialog(dialog: AppSuggestionsDialog) -> None:
    global _active_dialog
    if _active_dialog is dialog:
        _active_dialog = None


def show_app_suggestions(parent=None) -> AppSuggestionsDialog:
    """Show one window without enumerating until the user presses Scan."""

    global _active_dialog
    dialog = _active_dialog
    if dialog is None:
        dialog = AppSuggestionsDialog(parent)
        dialog.destroyed.connect(
            lambda _object=None, current=dialog: _clear_active_dialog(current)
        )
        _active_dialog = dialog
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
    return dialog
