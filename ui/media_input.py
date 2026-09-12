"""Explicit, one-use clipboard review and screen/voice recording controls."""

import base64
from collections.abc import Callable
from dataclasses import dataclass

from PyQt6.QtCore import QByteArray, QBuffer, QIODevice, QTimer, Qt
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QLabel, QLineEdit,
    QMessageBox, QPushButton, QTextEdit, QVBoxLayout, QWidget,
)

from screen.voice_clip import MAX_SECONDS
from turn_coordinator import TurnSession


@dataclass(frozen=True, slots=True)
class ClipboardInput:
    text: str = ""
    image_b64: str = ""


def read_clipboard() -> ClipboardInput:
    """Called only on the Qt thread after the user selects Send clipboard."""
    clipboard = QApplication.clipboard()
    if clipboard is None:
        raise ValueError("Clipboard is unavailable")
    mime = clipboard.mimeData()
    if mime is None or mime.hasUrls():
        raise ValueError("Copy text or an image; clipboard files are not opened")
    if mime.hasImage():
        image = clipboard.image()
        if image.isNull() or image.width() * image.height() > 16_000_000:
            raise ValueError("Clipboard image is empty or exceeds 16 megapixels")
        image = image.scaled(1600, 1600, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        encoded = QByteArray()
        buffer = QBuffer(encoded)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        try:
            if not image.save(buffer, "JPEG", 85):
                raise ValueError("Clipboard image could not be encoded")
        finally:
            buffer.close()
        if encoded.size() > 4 * 1024 * 1024:
            raise ValueError("Clipboard image exceeds 4 MiB")
        return ClipboardInput(image_b64=base64.b64encode(encoded.data()).decode("ascii"))
    text = clipboard.text()
    if not text.strip() or len(text) > 8000:
        raise ValueError("Copy between 1 and 8,000 characters of text, or an image")
    return ClipboardInput(text=text)


def review_clipboard(
    parent: QWidget, destination: str, send: Callable[[str, list[str]], None],
) -> None:
    try:
        snapshot = read_clipboard()
    except ValueError as exc:
        QMessageBox.information(parent, "Clipboard unavailable", str(exc))
        return
    dialog = QDialog(parent)
    dialog.setWindowTitle("Send clipboard")
    dialog.resize(520, 400)
    layout = QVBoxLayout(dialog)
    label = QLabel(f"Send this copy to {destination}")
    label.setTextFormat(Qt.TextFormat.PlainText)
    layout.addWidget(label)
    if snapshot.image_b64:
        pixmap = QPixmap()
        pixmap.loadFromData(base64.b64decode(snapshot.image_b64))
        preview = QLabel()
        preview.setPixmap(pixmap.scaled(480, 260, Qt.AspectRatioMode.KeepAspectRatio))
    else:
        text_preview = QTextEdit()
        text_preview.setReadOnly(True)
        text_preview.setPlainText(snapshot.text)
        layout.addWidget(text_preview)
    if snapshot.image_b64:
        layout.addWidget(preview)
    prompt = QLineEdit()
    prompt.setMaxLength(4000)
    prompt.setPlaceholderText("What would you like help with?")
    layout.addWidget(prompt)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    send_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
    if send_button is not None:
        send_button.setText("Send")
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        request = prompt.text().strip() or "Explain this content and help me work with it."
        if snapshot.text:
            request += f"\n\nClipboard reference:\n{snapshot.text}"
        send(request, [snapshot.image_b64] if snapshot.image_b64 else [])


def record_screen_voice(
    parent: QWidget, destination: str,
    start: Callable[[], TurnSession | None],
    send: Callable[[TurnSession], None], cancel: Callable[[TurnSession], None],
) -> None:
    dialog = QDialog(parent)
    dialog.setWindowTitle("Ask with screen + voice")
    layout = QVBoxLayout(dialog)
    status = QLabel(
        f"Record the display containing this window and your microphone.\n"
        f"When you send, the video and voice go together to {destination}.\n"
        f"Click Start, then speak and show what you mean. Sends automatically after {MAX_SECONDS} seconds."
    )
    status.setTextFormat(Qt.TextFormat.PlainText)
    status.setWordWrap(True)
    layout.addWidget(status)
    start_button = QPushButton("Start recording")
    send_button = QPushButton("Send recording")
    send_button.setEnabled(False)
    cancel_button = QPushButton("Cancel")
    for button in (start_button, send_button, cancel_button):
        layout.addWidget(button)
    session: TurnSession | None = None
    timer = QTimer(dialog)
    timer.setSingleShot(True)

    def begin() -> None:
        nonlocal session
        session = start()
        if session is not None:
            status.setText("Recording screen + voice… Send when finished, or Cancel to discard.")
            start_button.setEnabled(False)
            send_button.setEnabled(True)
            timer.start(MAX_SECONDS * 1000)

    start_button.clicked.connect(begin)
    send_button.clicked.connect(dialog.accept)
    cancel_button.clicked.connect(dialog.reject)
    timer.timeout.connect(dialog.accept)
    result = dialog.exec()
    timer.stop()
    if session is not None:
        if result == QDialog.DialogCode.Accepted:
            send(session)
        else:
            cancel(session)
