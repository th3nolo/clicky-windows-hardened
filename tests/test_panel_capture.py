import ast
import ctypes
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication
from ui.panel import CompanionPanel, AppState


class ResponseSignals(QObject):
    sig_response_chunk = pyqtSignal(str)
    sig_response_done = pyqtSignal(str)


class PanelCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        # Execute the production wiring helper without booting application services.
        tree = ast.parse(Path("main.py").read_text(encoding="utf-8"))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_wire_panel_capture")
        namespace = {}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "main.py", "exec"), namespace)
        cls.wire = staticmethod(namespace["_wire_panel_capture"])

    def setUp(self):
        with patch.object(CompanionPanel, "_populate_models"):
            self.panel = CompanionPanel()
        self.manager = Mock()
        self.manager.on_hotkey_press.return_value = True
        self.manager.on_hotkey_release.side_effect = lambda: self.panel.set_state(AppState.THINKING)
        self.manager.stop.side_effect = lambda: self.panel.set_state(AppState.IDLE)
        self.wire(self.panel, self.manager)
        self.panel.show()
        self.app.processEvents()

    def tearDown(self):
        self.panel.hide_by_user()
        self.panel.deleteLater()
        self.app.processEvents()

    def click(self, button):
        QTest.mouseClick(button, Qt.MouseButton.LeftButton)
        self.app.processEvents()

    def test_click_start_click_stop_routes_existing_capture_handlers(self):
        with patch("automation.inknotes_mcp.foreground_notebook_pid", return_value=123):
            self.click(self.panel._ptt_btn)
        self.manager.on_hotkey_press.assert_called_once_with(notebook_pid=123)
        self.assertEqual("Stop recording and send", self.panel._ptt_btn.text())
        self.click(self.panel._ptt_btn)
        self.manager.on_hotkey_release.assert_called_once_with()
        self.assertFalse(self.panel._ptt_btn.isEnabled())
        self.panel.set_state(AppState.IDLE)
        self.assertEqual("Start recording", self.panel._ptt_btn.text())
        self.assertTrue(self.panel._ptt_btn.isEnabled())

    def test_failed_start_resets_then_retry_clears_visible_error(self):
        def fail(**_kwargs):
            self.panel.show_error("Microphone denied")
            return False
        self.manager.on_hotkey_press.side_effect = fail
        self.click(self.panel._ptt_btn)
        self.assertEqual("Start recording", self.panel._ptt_btn.text())
        self.assertTrue(self.panel._error_label.isVisible())
        self.manager.on_hotkey_press.side_effect = None
        self.click(self.panel._ptt_btn)
        self.assertFalse(self.panel._error_label.isVisible())
        self.assertEqual("Stop recording and send", self.panel._ptt_btn.text())

    def test_start_exception_cancels_partial_capture_without_raw_diagnostics(self):
        self.manager.on_hotkey_press.side_effect = RuntimeError("secret diagnostic")
        self.click(self.panel._ptt_btn)
        self.manager.stop.assert_called_once_with()
        self.assertNotIn("secret", self.panel._error_label.text())
        self.assertEqual("Start recording", self.panel._ptt_btn.text())

    def test_cancel_and_user_hide_cancel_without_sending(self):
        self.click(self.panel._ptt_btn)
        self.click(self.panel._cancel_capture_btn)
        self.manager.stop.assert_called_once_with()
        self.manager.on_hotkey_release.assert_not_called()
        self.click(self.panel._ptt_btn)
        self.click(self.panel._min_btn)
        self.assertEqual(2, self.manager.stop.call_count)
        self.assertFalse(self.panel.isVisible())

    def test_internal_capture_hide_does_not_cancel_audio(self):
        self.click(self.panel._ptt_btn)
        self.panel.hide()
        self.manager.stop.assert_not_called()

    def test_hotkey_listening_can_be_stopped_from_button(self):
        self.panel.set_state(AppState.LISTENING)
        self.click(self.panel._ptt_btn)
        self.manager.on_hotkey_release.assert_called_once_with()
        self.manager.on_hotkey_press.assert_not_called()

    def test_recording_failure_state_restores_start_and_keeps_error(self):
        self.click(self.panel._ptt_btn)
        self.panel.set_state(AppState.LISTENING)
        self.panel.show_error("Microphone disconnected")
        self.panel.set_state(AppState.IDLE)
        self.assertEqual("Start recording", self.panel._ptt_btn.text())
        self.assertTrue(self.panel._ptt_btn.isEnabled())
        self.assertFalse(self.panel._cancel_capture_btn.isVisible())
        self.assertIn("Microphone disconnected", self.panel._error_label.text())

    def test_production_response_signals_replace_stream_with_final_notebook_status(self):
        manager = ResponseSignals()
        tree = ast.parse(Path("main.py").read_text(encoding="utf-8"))
        connections = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                continue
            source = ast.unparse(node)
            if source in (
                "manager.sig_response_chunk.connect(panel.append_response_chunk)",
                "manager.sig_response_done.connect(panel.update_response)",
            ):
                connections.append(node)
        self.assertEqual(2, len(connections))
        exec(compile(ast.Module(body=connections, type_ignores=[]), "main.py", "exec"),
             {"manager": manager, "panel": self.panel})
        manager.sig_response_chunk.emit("The answer is 16, ")
        manager.sig_response_chunk.emit("39.")
        manager.sig_response_done.emit("The answer is 16, 39.\nNotebook changed and saved.")
        self.assertEqual("The answer is 16, 39.\nNotebook changed and saved.",
                         self.panel._response_label.text())
        manager.sig_response_chunk.emit("A second ")
        manager.sig_response_chunk.emit("explanation.")
        self.assertEqual("A second explanation.", self.panel._response_label.text())

    def test_failed_or_cancelled_new_recording_preserves_previous_answer_until_content(self):
        self.panel.update_response("Previous completed explanation")
        self.panel.begin_transcript(1)
        self.panel.set_state(AppState.LISTENING)
        self.panel.show_error("No speech captured")
        self.panel.set_state(AppState.IDLE)
        self.panel.end_transcript(1)
        self.assertEqual("Previous completed explanation", self.panel._response_label.text())
        self.panel.begin_transcript(2)
        self.panel.set_state(AppState.LISTENING)
        self.panel._cancel_capture()
        self.assertEqual("Previous completed explanation", self.panel._response_label.text())
        self.panel.begin_transcript(3)
        self.panel.append_response_chunk("")
        self.assertEqual("Previous completed explanation", self.panel._response_label.text())
        self.panel.append_response_chunk("New answer")
        self.panel.append_response_chunk(" continues")
        self.assertEqual("New answer continues", self.panel._response_label.text())

    @unittest.skipUnless(os.name == "nt", "Windows message contract")
    def test_record_mouse_activation_preserves_foreground_without_global_flags(self):
        from ctypes import wintypes
        message = wintypes.MSG()
        message.message = 0x0021
        position = self.panel._ptt_btn.mapToGlobal(self.panel._ptt_btn.rect().center())
        with patch("ui.panel.QCursor.pos", return_value=position), patch(
            "automation.inknotes_mcp.foreground_notebook_pid", return_value=321
        ):
            self.assertEqual((True, 3), self.panel.nativeEvent(b"windows_generic_MSG", ctypes.addressof(message)))
            self.assertEqual(321, self.panel.take_capture_target_pid())
        with patch("automation.inknotes_mcp.foreground_notebook_pid", return_value=None):
            self.assertIsNone(self.panel.take_capture_target_pid())
        self.assertFalse(self.panel.windowFlags() & Qt.WindowType.WindowDoesNotAcceptFocus)

    def test_unhandled_native_messages_return_integer_lresult_without_dereference(self):
        self.assertEqual((False, 0), self.panel.nativeEvent(b"other_event", 1))
        self.assertEqual((False, 0), self.panel.nativeEvent(b"windows_generic_MSG", 0))
        self.assertEqual((False, 0), self.panel.nativeEvent(b"windows_generic_MSG", None))
        if os.name == "nt":
            from ctypes import wintypes
            message = wintypes.MSG()
            message.message = 0x000F  # WM_PAINT, unhandled
            self.assertEqual((False, 0), self.panel.nativeEvent(
                b"windows_generic_MSG", ctypes.addressof(message)))


if __name__ == "__main__":
    unittest.main()
