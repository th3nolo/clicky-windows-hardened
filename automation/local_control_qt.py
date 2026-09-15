"""Explicitly enabled Qt binding for the authenticated loopback control service.

LocalControlService enforces 127.0.0.1 binding, a random bearer token, exact
Host/no-Origin checks, bounded requests, and submit/status/events/cancel only.
This adapter schedules its already-authorized callbacks onto Clicky's Qt thread.
"""
from __future__ import annotations

from concurrent.futures import Future
import logging
from pathlib import Path
from PyQt6.QtCore import QObject, Qt, pyqtSignal, pyqtSlot


class _UsageObserver(logging.Handler):
    def __init__(self, signal):
        super().__init__(logging.INFO)
        self.signal = signal

    def emit(self, record):
        payload = getattr(record, 'clicky_usage', None)
        if isinstance(payload, dict):
            self.signal.emit(dict(payload))


class ClickyLocalControl(QObject):
    dispatch = pyqtSignal(object)
    usage = pyqtSignal(dict)

    def __init__(self, manager, endpoint_file: str | Path, *, enabled=False, service_factory=None):
        super().__init__()
        if enabled is not True:
            raise ValueError('Local control requires explicit opt-in')
        if service_factory is None:
            from automation.local_control import LocalControlService
            service_factory = LocalControlService
        self.manager = manager
        self.active_task_id = None
        self._verified = self._failed = self._cancelled = self._closed = False
        self.dispatch.connect(self._dispatch, Qt.ConnectionType.QueuedConnection)
        self.usage.connect(self._usage, Qt.ConnectionType.QueuedConnection)
        self.service = service_factory(submit=self._submit, cancel=self._cancel,
            schedule=self.schedule, endpoint_file=Path(endpoint_file), enabled=True)
        manager.sig_state_changed.connect(self._state, Qt.ConnectionType.QueuedConnection)
        manager.sig_response_chunk.connect(self._response_chunk, Qt.ConnectionType.QueuedConnection)
        manager.sig_response_done.connect(self._response, Qt.ConnectionType.QueuedConnection)
        manager.sig_error.connect(self._error, Qt.ConnectionType.QueuedConnection)
        manager.sig_notebook_event.connect(self._notebook, Qt.ConnectionType.QueuedConnection)
        self._usage_log = logging.getLogger('clicky.usage')
        self._old_usage_level = self._usage_log.level
        self._usage_log.setLevel(logging.INFO)
        self._usage_handler = _UsageObserver(self.usage)
        self._usage_log.addHandler(self._usage_handler)

    def start(self):
        return self.service.start()

    def schedule(self, callback):
        future = Future()
        if self._closed:
            future.set_exception(RuntimeError('Local control is closed'))
        else:
            self.dispatch.emit((callback, future))
        return future

    @pyqtSlot(object)
    def _dispatch(self, item):
        callback, future = item
        if not future.set_running_or_notify_cancel():
            return
        try:
            if self._closed:
                raise RuntimeError('Local control is closed')
            future.set_result(callback())
        except BaseException as error:
            future.set_exception(error)

    def _submit(self, text, notebook_pid):
        if self.active_task_id is not None:
            return {'status': 'rejected', 'error': 'A Clicky task is still finishing.', 'busy': True}
        result = self.manager.submit_notebook_task(text, notebook_pid)
        if type(result) is not int:
            return {'status': 'rejected', 'error': str(result)}
        self.active_task_id = str(result)
        self._verified = self._failed = self._cancelled = False
        return {'task_id': self.active_task_id, 'status': 'active'}

    def _cancel(self, task_id):
        active = self.manager._turns.active
        if (str(task_id) != self.active_task_id or active is None
                or str(active.sequence) != self.active_task_id):
            return False
        self._cancelled = True
        self.manager.stop()
        return True

    def _record(self, kind, payload):
        if self.active_task_id is not None:
            self.service.record_event(self.active_task_id, kind, payload)

    @pyqtSlot(object)
    def _state(self, state):
        name = getattr(state, 'name', str(state))
        self._record('state', {'state': name})
        if name.upper() == 'IDLE' and self.active_task_id is not None:
            status = ('cancelled' if self._cancelled else 'completed' if self._verified
                      else 'failed' if self._failed else 'paused')
            self.service.set_status(self.active_task_id, status)
            self.active_task_id = None

    @pyqtSlot(str)
    def _response_chunk(self, text):
        self._record('response_chunk', {'text': text[:4000]})

    @pyqtSlot(str)
    def _response(self, text):
        self._record('response', {'text': text[:4000]})

    @pyqtSlot(str)
    def _error(self, text):
        self._failed = True
        self._record('error', {'message': text[:2000]})

    @pyqtSlot(int, dict)
    def _notebook(self, sequence, event):
        if str(sequence) != self.active_task_id:
            return
        if event.get('type') == 'verification':
            self._verified = (event.get('complete') is True
                              and event.get('independent_output_reader') is True)
        self._record('notebook', event)

    @pyqtSlot(dict)
    def _usage(self, payload):
        self._record('usage', payload)

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._usage_log.removeHandler(self._usage_handler)
        self._usage_log.setLevel(self._old_usage_level)
        self.service.stop()
