"""Kill-on-stop single-process boundary for one interactive UIA action."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import sysconfig
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Protocol

from automation.action_protocol import MAX_WORKER_FRAME_BYTES


ACTION_TIMEOUT_SECONDS = 5.0
ACTION_MEMORY_BYTES = 256 * 1024 * 1024
MAX_WORKER_STDERR_BYTES = 4 * 1024
_SOURCE_WORKER_BOOTSTRAP = (
    "import sys;"
    "sys.path.insert(0,sys.argv[1]);"
    "sys.path.insert(1,sys.argv[2]);"
    "from automation.uia_worker import run_worker;"
    "raise SystemExit(run_worker())"
)


class UiaWorkerError(RuntimeError):
    pass


class UiaWorkerTimeout(UiaWorkerError):
    pass


class UiaWorkerHandleProtocol(Protocol):
    @property
    def request_sent(self) -> bool: ...

    def exchange(self, frame: bytes) -> bytes: ...

    def cancel(self) -> None: ...

    def close(self) -> None: ...


class UiaWorkerLauncherProtocol(Protocol):
    def start(self) -> UiaWorkerHandleProtocol: ...


class WindowsUiaWorkerLauncher:
    """Launch the exact app/runtime worker suspended, then job-assign it."""

    def __init__(
        self,
        *,
        timeout_seconds: float = ACTION_TIMEOUT_SECONDS,
    ) -> None:
        if (
            type(timeout_seconds) not in (int, float)
            or not 0.5 <= timeout_seconds <= ACTION_TIMEOUT_SECONDS
        ):
            raise ValueError("UIA worker timeout is invalid")
        self._timeout_seconds = float(timeout_seconds)

    def start(self) -> WindowsUiaWorkerHandle:
        if os.name != "nt":
            raise UiaWorkerError("UIA worker requires Windows")
        command = _worker_command()
        environment = _worker_environment()
        creation_flags = (
            subprocess.CREATE_NO_WINDOW | subprocess.CREATE_SUSPENDED
        )
        process = None
        boundary = _WindowsActionJob(
            timeout_seconds=self._timeout_seconds,
        )
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=environment["SYSTEMROOT"],
                env=environment,
                shell=False,
                close_fds=True,
                bufsize=0,
                creationflags=creation_flags,
            )
            boundary.assign_suspended(process)
            return WindowsUiaWorkerHandle(
                process,
                boundary,
                timeout_seconds=self._timeout_seconds,
            )
        except Exception as exc:
            boundary.close()
            if process is not None:
                try:
                    process.kill()
                except OSError:
                    pass
            raise UiaWorkerError("UIA worker launch failed") from exc


class WindowsUiaWorkerHandle:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        boundary: _WindowsActionJob,
        *,
        timeout_seconds: float,
    ) -> None:
        if (
            process.stdin is None
            or process.stdout is None
            or process.stderr is None
        ):
            raise UiaWorkerError("UIA worker pipes are unavailable")
        self._process = process
        self._boundary = boundary
        self._timeout_seconds = timeout_seconds
        self._lock = threading.RLock()
        self._request_sent = False
        self._closed = False

    @property
    def request_sent(self) -> bool:
        with self._lock:
            return self._request_sent

    def exchange(self, frame: bytes) -> bytes:
        if (
            not isinstance(frame, bytes)
            or not 1 < len(frame) <= MAX_WORKER_FRAME_BYTES
            or not frame.endswith(b"\n")
        ):
            raise ValueError("UIA worker request frame is invalid")
        with self._lock:
            if self._closed or self._request_sent:
                raise UiaWorkerError("UIA worker is not available")
            process = self._process
            stdin = process.stdin
            stdout = process.stdout
            stderr = process.stderr
            assert stdin is not None
            assert stdout is not None
            assert stderr is not None
            output_box: list[bytes | BaseException] = []
            error_box: list[bytes | BaseException] = []
            output_thread = threading.Thread(
                target=_read_bounded,
                args=(stdout, MAX_WORKER_FRAME_BYTES, output_box),
                daemon=True,
            )
            error_thread = threading.Thread(
                target=_read_bounded,
                args=(stderr, MAX_WORKER_STDERR_BYTES, error_box),
                daemon=True,
            )
            output_thread.start()
            error_thread.start()
            try:
                stdin.write(frame)
                stdin.flush()
                self._request_sent = True
                stdin.close()
            except (BrokenPipeError, OSError) as exc:
                self.cancel()
                raise UiaWorkerError(
                    "UIA worker rejected the request"
                ) from exc
        try:
            exit_code = process.wait(timeout=self._timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            self.cancel()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            raise UiaWorkerTimeout("UIA worker timed out") from exc
        output_thread.join(timeout=1)
        error_thread.join(timeout=1)
        if output_thread.is_alive() or error_thread.is_alive():
            self.cancel()
            raise UiaWorkerError("UIA worker pipe did not close")
        if exit_code != 0 or error_box:
            raise UiaWorkerError("UIA worker failed")
        if len(output_box) != 1 or not isinstance(output_box[0], bytes):
            raise UiaWorkerError("UIA worker response is invalid")
        return output_box[0]

    def cancel(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._boundary.terminate()
            except OSError:
                pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._boundary.close()
            for stream in (
                self._process.stdin,
                self._process.stdout,
                self._process.stderr,
            ):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


class _WindowsActionJob:
    """Kill-on-close resource boundary that intentionally permits UIA."""

    _JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

    def __init__(self, *, timeout_seconds: float) -> None:
        if os.name != "nt":
            raise OSError("Windows Job Objects are unavailable")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = self._kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        create_job = self._kernel32.CreateJobObjectW
        create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        create_job.restype = wintypes.HANDLE
        self._handle = create_job(None, None)
        self._closed = False
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self._configure(timeout_seconds)
        except Exception:
            self.close()
            raise

    def _configure(self, timeout_seconds: float) -> None:
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class BASIC_LIMITS(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class EXTENDED_LIMITS(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC_LIMITS),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        limits = EXTENDED_LIMITS()
        limits.BasicLimitInformation.PerJobUserTimeLimit = round(
            timeout_seconds * 10_000_000
        )
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        limits.BasicLimitInformation.LimitFlags = (
            self._JOB_OBJECT_LIMIT_JOB_TIME
            | self._JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | self._JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | self._JOB_OBJECT_LIMIT_JOB_MEMORY
            | self._JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        limits.ProcessMemoryLimit = ACTION_MEMORY_BYTES
        limits.JobMemoryLimit = ACTION_MEMORY_BYTES
        setter = self._kernel32.SetInformationJobObject
        setter.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        setter.restype = wintypes.BOOL
        if not setter(
            self._handle,
            9,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def assign_suspended(self, process: subprocess.Popen[bytes]) -> None:
        process_handle = getattr(process, "_handle", None)
        if (
            self._closed
            or process.poll() is not None
            or process_handle is None
        ):
            raise UiaWorkerError("Suspended UIA worker is unavailable")
        assign = self._kernel32.AssignProcessToJobObject
        assign.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        assign.restype = wintypes.BOOL
        if not assign(self._handle, process_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        _resume_process_threads(process.pid)

    def terminate(self, exit_code: int = 1) -> None:
        if self._closed:
            return
        terminate = self._kernel32.TerminateJobObject
        terminate.argtypes = (wintypes.HANDLE, wintypes.UINT)
        terminate.restype = wintypes.BOOL
        if not terminate(self._handle, exit_code):
            error = ctypes.get_last_error()
            if error not in {5, 6}:
                raise ctypes.WinError(error)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _read_bounded(stream, maximum: int, box: list) -> None:
    try:
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            box.append(UiaWorkerError("UIA worker output limit exceeded"))
        elif data:
            box.append(data)
    except BaseException as exc:
        box.append(exc)


def _worker_command() -> list[str]:
    if getattr(sys, "frozen", False):
        executable = str(Path(sys.executable).resolve(strict=True))
        return [executable, "--desktop-uia-worker"]
    # A Windows virtual-environment python.exe may be a redirector that creates
    # another process. Use the exact base runtime so the one-process Job limit
    # remains enforceable, then admit only this app and its locked site-packages
    # directory under isolated mode.
    executable = Path(
        getattr(sys, "_base_executable", sys.executable)
    ).resolve(strict=True)
    app_root = Path(__file__).resolve().parents[1]
    environment_root = Path(sys.prefix).resolve(strict=True)
    purelib_value = sysconfig.get_path("purelib")
    if not purelib_value:
        raise UiaWorkerError("Locked Python environment is unavailable")
    purelib = Path(purelib_value).resolve(strict=True)
    try:
        purelib.relative_to(environment_root)
    except ValueError as exc:
        raise UiaWorkerError(
            "Locked site-packages path is outside the environment"
        ) from exc
    if not purelib.is_dir() or not app_root.is_dir():
        raise UiaWorkerError("UIA worker source paths are unavailable")
    return [
        str(executable),
        "-I",
        "-B",
        "-c",
        _SOURCE_WORKER_BOOTSTRAP,
        str(app_root),
        str(purelib),
    ]


def _worker_environment() -> dict[str, str]:
    environment = {"CLICKY_DESKTOP_UIA_WORKER": "1"}
    for name in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    system_root = environment.get("SYSTEMROOT") or environment.get("WINDIR")
    if not system_root or not Path(system_root).is_absolute():
        raise UiaWorkerError("Windows system root is unavailable")
    environment["SYSTEMROOT"] = system_root
    environment["WINDIR"] = system_root
    return environment


def _resume_process_threads(process_id: int) -> None:
    class THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_snapshot = kernel32.CreateToolhelp32Snapshot
    create_snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    create_snapshot.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    snapshot = create_snapshot(0x00000004, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())
    thread_ids: list[int] = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        first = kernel32.Thread32First
        first.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(THREADENTRY32),
        )
        first.restype = wintypes.BOOL
        next_entry = kernel32.Thread32Next
        next_entry.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(THREADENTRY32),
        )
        next_entry.restype = wintypes.BOOL
        if first(snapshot, ctypes.byref(entry)):
            while True:
                if entry.th32OwnerProcessID == process_id:
                    thread_ids.append(entry.th32ThreadID)
                if not next_entry(snapshot, ctypes.byref(entry)):
                    break
    finally:
        close_handle(snapshot)
    if not thread_ids:
        raise UiaWorkerError("Suspended UIA worker thread was not found")

    open_thread = kernel32.OpenThread
    open_thread.argtypes = (
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    )
    open_thread.restype = wintypes.HANDLE
    resume_thread = kernel32.ResumeThread
    resume_thread.argtypes = (wintypes.HANDLE,)
    resume_thread.restype = wintypes.DWORD
    resumed = 0
    for thread_id in thread_ids:
        thread = open_thread(0x0002, False, thread_id)
        if not thread:
            continue
        try:
            previous = resume_thread(thread)
            if previous != 0xFFFFFFFF and previous > 0:
                resumed += 1
        finally:
            close_handle(thread)
    if resumed < 1:
        raise UiaWorkerError("Suspended UIA worker could not be resumed")


__all__ = [
    "UiaWorkerError",
    "UiaWorkerHandleProtocol",
    "UiaWorkerLauncherProtocol",
    "UiaWorkerTimeout",
    "WindowsUiaWorkerLauncher",
]
