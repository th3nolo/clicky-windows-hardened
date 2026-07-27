"""Explicit writing-style management and pre-compose selection."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from PyQt6.QtCore import QIODevice, QSaveFile, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from memory.style_profiles import (
    MAX_EXAMPLES,
    MAX_EXPORT_BYTES,
    MAX_PROFILE_NAME_CHARS,
    MAX_RULES,
    StyleProfile,
    StyleProfileError,
    StyleProfileStore,
)


_PROFILE_ID_ROLE = int(Qt.ItemDataRole.UserRole)


class StyleProfileFileGateway(Protocol):
    def save(
        self,
        parent: QWidget,
        suggested_name: str,
        payload: bytes,
    ) -> bool: ...

    def open(self, parent: QWidget) -> bytes | None: ...


class QtStyleProfileFileGateway:
    """Bounded file access reached only from explicit import/export buttons."""

    def save(
        self,
        parent: QWidget,
        suggested_name: str,
        payload: bytes,
    ) -> bool:
        if (
            not isinstance(payload, bytes)
            or not payload
            or len(payload) > MAX_EXPORT_BYTES
        ):
            raise ValueError("Writing-style export is invalid")
        filename, _ = QFileDialog.getSaveFileName(
            parent,
            "Export writing style",
            suggested_name,
            "Clicky writing style (*.json)",
        )
        if not filename:
            return False
        target = QSaveFile(filename)
        if not target.open(QIODevice.OpenModeFlag.WriteOnly):
            raise OSError("Could not open the selected export file")
        if target.write(payload) != len(payload) or not target.commit():
            target.cancelWriting()
            raise OSError("Could not save the writing-style export")
        return True

    def open(self, parent: QWidget) -> bytes | None:
        filename, _ = QFileDialog.getOpenFileName(
            parent,
            "Import writing style",
            "",
            "Clicky writing style (*.json)",
        )
        if not filename:
            return None
        path = Path(filename)
        if path.is_symlink() or not path.is_file():
            raise OSError("The selected import must be a regular file")
        size = path.stat().st_size
        if not 1 <= size <= MAX_EXPORT_BYTES:
            raise ValueError("The selected writing-style import is too large")
        payload = path.read_bytes()
        if len(payload) != size:
            raise OSError("The selected writing-style import changed")
        return payload


class StyleProfilesPanel(QWidget):
    """Manage only profiles the user explicitly creates or imports."""

    profile_changed = pyqtSignal(object)

    def __init__(
        self,
        store: StyleProfileStore,
        *,
        file_gateway: StyleProfileFileGateway | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(store, StyleProfileStore):
            raise TypeError("Writing-style UI requires a profile store")
        self._store = store
        self._files = file_gateway or QtStyleProfileFileGateway()
        self._selected_id: str | None = None
        self._application_name: str | None = None
        self._application_identity: str | None = None

        self.setWindowTitle("Writing styles")
        self.setMinimumSize(760, 540)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)

        root = QVBoxLayout(self)
        intro = QLabel(
            "Create writing preferences yourself. Clicky never learns a style "
            "from email, files, screenshots, clipboard, or conversation history."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter, stretch=1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        self._profiles = QListWidget()
        self._profiles.currentItemChanged.connect(self._load_selected)
        left_layout.addWidget(self._profiles, stretch=1)
        new_button = QPushButton("New style")
        new_button.clicked.connect(self.new_profile)
        import_button = QPushButton("Import…")
        import_button.clicked.connect(self.import_profiles)
        left_buttons = QHBoxLayout()
        left_buttons.addWidget(new_button)
        left_buttons.addWidget(import_button)
        left_layout.addLayout(left_buttons)
        splitter.addWidget(left)

        editor = QWidget()
        editor_layout = QVBoxLayout(editor)
        form = QFormLayout()
        self._name = QLineEdit()
        self._name.setMaxLength(MAX_PROFILE_NAME_CHARS)
        self._rules = QPlainTextEdit()
        self._rules.setPlaceholderText(
            f"One rule per line, up to {MAX_RULES}."
        )
        self._examples = QPlainTextEdit()
        self._examples.setPlaceholderText(
            f"One approved example per line, up to {MAX_EXAMPLES}."
        )
        self._enabled = QCheckBox("Available for new requests")
        self._enabled.setChecked(True)
        self._scope_current = QCheckBox(
            "Limit to the current destination application"
        )
        self._scope_current.setEnabled(False)
        form.addRow("Name", self._name)
        form.addRow("Rules", self._rules)
        form.addRow("Approved examples", self._examples)
        form.addRow("", self._enabled)
        form.addRow("", self._scope_current)
        editor_layout.addLayout(form)

        self._application = QLabel(
            "Current destination: not supplied by a compose request"
        )
        self._default = QLabel("Application default: none")
        editor_layout.addWidget(self._application)
        editor_layout.addWidget(self._default)

        actions = QHBoxLayout()
        save_button = QPushButton("Save")
        save_button.clicked.connect(self.save_profile)
        export_button = QPushButton("Export…")
        export_button.clicked.connect(self.export_profile)
        delete_button = QPushButton("Delete…")
        delete_button.clicked.connect(self.delete_profile)
        default_button = QPushButton("Use by default for this app")
        default_button.clicked.connect(self.set_application_default)
        clear_default_button = QPushButton("Clear app default")
        clear_default_button.clicked.connect(
            self.clear_application_default
        )
        for button in (
            save_button,
            export_button,
            delete_button,
            default_button,
            clear_default_button,
        ):
            actions.addWidget(button)
        editor_layout.addLayout(actions)
        self._status = QLabel("")
        self._status.setWordWrap(True)
        editor_layout.addWidget(self._status)
        splitter.addWidget(editor)
        splitter.setStretchFactor(1, 2)

        self._save_button = save_button
        self._export_button = export_button
        self._delete_button = delete_button
        self._default_button = default_button
        self._clear_default_button = clear_default_button
        self.refresh()
        self.new_profile()

    @property
    def selected_profile_id(self) -> str | None:
        return self._selected_id

    def set_application_context(
        self,
        application_name: str,
        application_identity: str,
    ) -> None:
        if (
            not isinstance(application_name, str)
            or not application_name.strip()
            or not application_name.isprintable()
            or len(application_name) > 256
        ):
            raise ValueError("Application name is invalid")
        self._store.active_for_application(application_identity)
        self._application_name = application_name.strip()
        self._application_identity = application_identity
        self._application.setText(
            f"Current destination: {self._application_name}"
        )
        self._scope_current.setEnabled(True)
        self._load_profile_into_editor(self._current_profile())
        self._refresh_default()
        self._refresh_actions()

    def clear_application_context(self) -> None:
        self._application_name = None
        self._application_identity = None
        self._application.setText(
            "Current destination: not supplied by a compose request"
        )
        self._default.setText("Application default: none")
        self._scope_current.setChecked(False)
        self._scope_current.setEnabled(False)
        self._refresh_actions()

    def refresh(self, selected_id: str | None = None) -> None:
        wanted = selected_id if selected_id is not None else self._selected_id
        self._profiles.blockSignals(True)
        self._profiles.clear()
        selected_row = -1
        for row, profile in enumerate(self._store.list_profiles()):
            suffix = "" if profile.enabled else " (disabled)"
            item = QListWidgetItem(f"{profile.name}{suffix}")
            item.setData(_PROFILE_ID_ROLE, profile.profile_id)
            self._profiles.addItem(item)
            if profile.profile_id == wanted:
                selected_row = row
        self._profiles.blockSignals(False)
        if selected_row >= 0:
            self._profiles.setCurrentRow(selected_row)
        self._refresh_default()
        self._refresh_actions()

    def new_profile(self) -> None:
        self._profiles.clearSelection()
        self._selected_id = None
        self._name.clear()
        self._rules.clear()
        self._examples.clear()
        self._enabled.setChecked(True)
        self._scope_current.setChecked(False)
        self._status.setText(
            "New style. Nothing is stored until you choose Save."
        )
        self._refresh_actions()

    def save_profile(self) -> None:
        try:
            rules = _editor_lines(self._rules, MAX_RULES)
            examples = _editor_lines(self._examples, MAX_EXAMPLES)
            current = self._current_profile()
            scopes = current.application_scopes if current is not None else ()
            identity = self._application_identity
            if identity is not None:
                scope_set = set(scopes)
                if self._scope_current.isChecked():
                    scope_set.add(identity)
                else:
                    scope_set.discard(identity)
                scopes = tuple(sorted(scope_set))
            if current is None:
                profile = self._store.create(
                    name=self._name.text(),
                    rules=rules,
                    examples=examples,
                    application_scopes=scopes,
                )
            else:
                profile = self._store.update(
                    current.profile_id,
                    name=self._name.text(),
                    rules=rules,
                    examples=examples,
                    application_scopes=scopes,
                )
            if profile.enabled != self._enabled.isChecked():
                profile = self._store.set_enabled(
                    profile.profile_id,
                    self._enabled.isChecked(),
                )
            self._selected_id = profile.profile_id
            self.refresh(profile.profile_id)
            self._status.setText("Writing style saved.")
            self.profile_changed.emit(profile.profile_id)
        except (StyleProfileError, TypeError, ValueError) as exc:
            self._status.setText(str(exc))

    def delete_profile(self) -> None:
        profile = self._current_profile()
        if profile is None:
            self._status.setText("Choose a saved style to delete.")
            return
        answer = QMessageBox.question(
            self,
            "Delete writing style?",
            "This permanently removes the selected writing style and any "
            "application defaults that point to it.",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            deleted_id = profile.profile_id
            if not self._store.delete(deleted_id):
                raise StyleProfileError(
                    "The selected writing style no longer exists"
                )
            self.new_profile()
            self.refresh()
            self._status.setText("Writing style deleted.")
            self.profile_changed.emit(deleted_id)
        except StyleProfileError as exc:
            self._status.setText(str(exc))

    def export_profile(self) -> None:
        profile = self._current_profile()
        if profile is None:
            self._status.setText("Choose a saved style to export.")
            return
        try:
            payload = self._store.export_profile(profile.profile_id)
            if self._files.save(
                self,
                "clicky-writing-style.json",
                payload,
            ):
                self._status.setText(
                    "Writing style exported as readable JSON."
                )
        except (StyleProfileError, OSError, TypeError, ValueError) as exc:
            self._status.setText(str(exc))

    def import_profiles(self) -> None:
        try:
            payload = self._files.open(self)
            if payload is None:
                return
            imported = self._store.import_profiles(payload)
            selected = imported[0].profile_id if imported else None
            self.refresh(selected)
            self._status.setText(
                f"Imported {len(imported)} writing style"
                f"{'' if len(imported) == 1 else 's'}."
            )
            for profile in imported:
                self.profile_changed.emit(profile.profile_id)
        except (StyleProfileError, OSError, TypeError, ValueError) as exc:
            self._status.setText(str(exc))

    def set_application_default(self) -> None:
        profile = self._current_profile()
        identity = self._application_identity
        if profile is None or identity is None:
            self._status.setText(
                "Choose a saved style from an active compose destination."
            )
            return
        try:
            self._store.set_default_for_application(
                identity,
                profile.profile_id,
            )
            self._refresh_default()
            self._status.setText(
                f"{profile.name} is the default for "
                f"{self._application_name}."
            )
        except (StyleProfileError, TypeError, ValueError) as exc:
            self._status.setText(str(exc))

    def clear_application_default(self) -> None:
        identity = self._application_identity
        if identity is None:
            self._status.setText(
                "No active compose destination was supplied."
            )
            return
        try:
            self._store.set_default_for_application(identity, None)
            self._refresh_default()
            self._status.setText(
                f"No writing style is selected by default for "
                f"{self._application_name}."
            )
        except (StyleProfileError, TypeError, ValueError) as exc:
            self._status.setText(str(exc))

    def _load_selected(
        self,
        current: QListWidgetItem | None,
        _previous: QListWidgetItem | None,
    ) -> None:
        self._selected_id = (
            current.data(_PROFILE_ID_ROLE)
            if current is not None
            else None
        )
        self._load_profile_into_editor(self._current_profile())
        self._refresh_actions()

    def _load_profile_into_editor(
        self,
        profile: StyleProfile | None,
    ) -> None:
        if profile is None:
            return
        self._name.setText(profile.name)
        self._rules.setPlainText("\n".join(profile.rules))
        self._examples.setPlainText("\n".join(profile.examples))
        self._enabled.setChecked(profile.enabled)
        identity = self._application_identity
        self._scope_current.setChecked(
            identity is not None
            and identity in profile.application_scopes
        )
        self._status.setText("")

    def _current_profile(self) -> StyleProfile | None:
        if self._selected_id is None:
            return None
        return self._store.get(self._selected_id)

    def _refresh_default(self) -> None:
        identity = self._application_identity
        if identity is None:
            return
        try:
            profile = self._store.default_for_application(identity)
            self._default.setText(
                "Application default: "
                + (profile.name if profile is not None else "none")
            )
        except StyleProfileError:
            self._default.setText("Application default: unavailable")

    def _refresh_actions(self) -> None:
        saved = self._selected_id is not None
        has_application = self._application_identity is not None
        self._export_button.setEnabled(saved)
        self._delete_button.setEnabled(saved)
        self._default_button.setEnabled(saved and has_application)
        self._clear_default_button.setEnabled(has_application)


class ComposeStyleProfilePicker(QWidget):
    """Visible, explicit selection step before compose request creation."""

    selection_confirmed = pyqtSignal(object)
    cancelled = pyqtSignal()

    def __init__(
        self,
        store: StyleProfileStore,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if not isinstance(store, StyleProfileStore):
            raise TypeError("Writing-style picker requires a profile store")
        self._store = store
        self._application_identity: str | None = None
        self.setWindowTitle("Choose writing style")
        layout = QVBoxLayout(self)
        self._application = QLabel("Destination: not selected")
        self._profile = QComboBox()
        self._profile.currentIndexChanged.connect(self._update_summary)
        self._summary = QLabel("Will use: no writing style")
        self._summary.setWordWrap(True)
        layout.addWidget(self._application)
        layout.addWidget(self._profile)
        layout.addWidget(self._summary)
        buttons = QHBoxLayout()
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.cancelled.emit)
        confirm = QPushButton("Continue to compose")
        confirm.clicked.connect(self._confirm)
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(confirm)
        layout.addLayout(buttons)
        self._confirm_button = confirm
        self._confirm_button.setEnabled(False)

    @property
    def selected_profile_id(self) -> str | None:
        value = self._profile.currentData()
        return value if isinstance(value, str) else None

    def set_application_context(
        self,
        application_name: str,
        application_identity: str,
    ) -> None:
        if (
            not isinstance(application_name, str)
            or not application_name.strip()
            or not application_name.isprintable()
            or len(application_name) > 256
        ):
            raise ValueError("Application name is invalid")
        profiles = self._store.active_for_application(
            application_identity
        )
        default = self._store.default_for_application(
            application_identity
        )
        self._application_identity = application_identity
        self._application.setText(
            f"Destination: {application_name.strip()}"
        )
        self._profile.blockSignals(True)
        self._profile.clear()
        self._profile.addItem("No writing style", None)
        selected_index = 0
        for index, profile in enumerate(profiles, start=1):
            self._profile.addItem(profile.name, profile.profile_id)
            if (
                default is not None
                and profile.profile_id == default.profile_id
            ):
                selected_index = index
        self._profile.setCurrentIndex(selected_index)
        self._profile.blockSignals(False)
        self._confirm_button.setEnabled(True)
        self._update_summary()

    def clear_sensitive(self) -> None:
        self._application_identity = None
        self._profile.clear()
        self._application.setText("Destination: not selected")
        self._summary.setText("Will use: no writing style")
        self._confirm_button.setEnabled(False)

    def _update_summary(self) -> None:
        profile_name = self._profile.currentText() or "no writing style"
        destination = self._application.text().removeprefix("Destination: ")
        self._summary.setText(
            f"Will use: {profile_name} for {destination}. "
            "Only this selection is eligible for the approved request."
        )

    def _confirm(self) -> None:
        if self._application_identity is None:
            return
        self.selection_confirmed.emit(self.selected_profile_id)


def _editor_lines(
    editor: QPlainTextEdit,
    maximum: int,
) -> tuple[str, ...]:
    values = tuple(
        line.strip()
        for line in editor.toPlainText().splitlines()
        if line.strip()
    )
    if len(values) > maximum:
        raise ValueError(f"Use no more than {maximum} entries")
    return values
