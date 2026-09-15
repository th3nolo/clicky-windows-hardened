import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from PyQt6.QtCore import QCoreApplication, QObject, pyqtSignal
from automation.local_control_qt import ClickyLocalControl


class Manager(QObject):
    sig_state_changed = pyqtSignal(object)
    sig_response_chunk = pyqtSignal(str)
    sig_response_done = pyqtSignal(str)
    sig_error = pyqtSignal(str)
    sig_notebook_event = pyqtSignal(int, dict)

    def __init__(self):
        super().__init__()
        self._turns = SimpleNamespace(active=None)
        self.calls = []

    def submit_notebook_task(self, text, pid):
        self.calls.append((text, pid, threading.get_ident()))
        self._turns.active = SimpleNamespace(sequence=7)
        return 7

    def stop(self):
        self._turns.active = None
        self.sig_state_changed.emit(SimpleNamespace(name='IDLE'))


class Service:
    def __init__(self, **kwargs):
        self.options = kwargs
        self.events = []
        self.statuses = []

    def record_event(self, *args): self.events.append(args)
    def set_status(self, *args): self.statuses.append(args)
    def stop(self): pass


class LocalControlQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QCoreApplication.instance() or QCoreApplication([])

    def setUp(self):
        self.manager = Manager()
        self.bridge = ClickyLocalControl(self.manager, Path('unused.json'), enabled=True, service_factory=Service)
        self.addCleanup(self.bridge.close)

    def test_callback_is_queued_on_qt_thread(self):
        futures = []
        thread = threading.Thread(target=lambda: futures.append(
            self.bridge.schedule(lambda: self.bridge._submit('draw row', 123))))
        thread.start()
        thread.join()
        self.assertEqual(self.manager.calls, [])
        self.app.processEvents()
        self.assertEqual(futures[0].result()['task_id'], '7')
        self.assertEqual(self.manager.calls[0][2], threading.get_ident())

    def test_idle_without_independent_completion_is_paused(self):
        self.bridge._submit('draw row', 123)
        self.manager.sig_response_done.emit('I am done')
        self.manager.sig_notebook_event.emit(7, {'type':'verification','complete':True})
        self.manager.sig_state_changed.emit(SimpleNamespace(name='IDLE'))
        self.app.processEvents()
        self.assertEqual(self.bridge.service.statuses[-1], ('7', 'paused'))

    def test_verified_completion_and_targeted_cancel(self):
        self.bridge._submit('draw row', 123)
        self.assertFalse(self.bridge._cancel('8'))
        self.manager.sig_notebook_event.emit(7, {'type':'verification','complete':True,'independent_output_reader':True})
        self.manager.sig_state_changed.emit(SimpleNamespace(name='IDLE'))
        self.app.processEvents()
        self.assertEqual(self.bridge.service.statuses[-1], ('7', 'completed'))
        self.bridge._submit('draw col', 123)
        self.assertTrue(self.bridge._cancel('7'))
        self.assertEqual(self.bridge._submit('another', 123)['status'], 'rejected')
        self.app.processEvents()
        self.assertEqual(self.bridge.service.statuses[-1], ('7', 'cancelled'))


if __name__ == '__main__':
    unittest.main()
