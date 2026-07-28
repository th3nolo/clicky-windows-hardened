"""Host-owned worker lifecycle, Job Object, and task workspace boundary.

This process is a crash/resource fault boundary, not a complete sandbox.
All useful authority must still be supplied by the future trusted host broker.
"""

from __future__ import annotations

import hashlib
import os
import queue
import secrets
import signal
import stat
import subprocess
import sys
import threading
from pathlib import Path

from capability_registry import CapabilityId
from tasks.models import TaskRun, TaskState
from tasks.policy import WorkerPolicy, worker_environment
from tasks.protocol import (
    PROTOCOL_KEY_BYTES,
    ProtocolError,
    ProtocolMessage,
    ProtocolSession,
    WorkerBootstrap,
)


_REPARSE_POINT = 0x400
_WATCHDOG_INTERVAL_SECONDS = 0.25
_PROCESS_WAIT_SECONDS = 3.0


class TaskWorkerError(RuntimeError):
    pass


class TaskWorkerLimitError(TaskWorkerError):
    pass


class TaskWorkspaceError(TaskWorkerError):
    pass


class TaskWorkspace:
    """One private, bounded directory whose cleanup never follows links."""

    def __init__(self, path: Path, policy: WorkerPolicy) -> None:
        self.path = path
        self._policy = policy
        self._cleaned = False

    @classmethod
    def create(
        cls,
        run_id: str,
        policy: WorkerPolicy,
        *,
        root: Path | None = None,
    ) -> TaskWorkspace:
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("Task workspace run ID is invalid")
        if not isinstance(policy, WorkerPolicy):
            raise TypeError("Task workspace requires a WorkerPolicy")
        base = root or _default_workspace_root()
        if not isinstance(base, Path) or not base.is_absolute():
            raise ValueError("Task workspace root must be absolute")
        path = None
        try:
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            if _is_link_or_reparse(base) or not base.is_dir():
                raise TaskWorkspaceError(
                    "Task workspace root is linked or invalid"
                )
            _protect_directory(base)
            run_digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:16]
            path = base / f"task-{run_digest}-{secrets.token_hex(8)}"
            path.mkdir(mode=0o700)
            if _is_link_or_reparse(path) or not path.is_dir():
                raise TaskWorkspaceError(
                    "Task workspace is linked or invalid"
                )
            _protect_directory(path)
        except TaskWorkspaceError:
            if path is not None:
                _remove_tree_without_following_links(path)
            raise
        except OSError as exc:
            if path is not None:
                try:
                    _remove_tree_without_following_links(path)
                except OSError:
                    pass
            raise TaskWorkspaceError(
                "Could not establish the private task workspace"
            ) from exc
        workspace = cls(path, policy)
        workspace.verify()
        return workspace

    def verify(self) -> tuple[int, int]:
        if self._cleaned:
            raise TaskWorkspaceError("Task workspace is already cleaned")
        if _is_link_or_reparse(self.path) or not self.path.is_dir():
            raise TaskWorkspaceError(
                "Task workspace identity is invalid"
            )
        files = 0
        total_bytes = 0
        pending = [self.path]
        while pending:
            directory = pending.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError as exc:
                raise TaskWorkspaceError(
                    "Could not inspect the task workspace"
                ) from exc
            for entry in entries:
                files += 1
                if files > self._policy.workspace_files:
                    raise TaskWorkerLimitError(
                        "Task workspace file-count limit exceeded"
                    )
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise TaskWorkspaceError(
                        "Could not inspect a task workspace entry"
                    ) from exc
                if (
                    entry.is_symlink()
                    or _metadata_is_reparse(metadata)
                ):
                    raise TaskWorkspaceError(
                        "Task workspace links are not allowed"
                    )
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(Path(entry.path))
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise TaskWorkspaceError(
                        "Task workspace entries must be regular files"
                    )
                total_bytes += metadata.st_size
                if total_bytes > self._policy.workspace_bytes:
                    raise TaskWorkerLimitError(
                        "Task workspace size limit exceeded"
                    )
        return files, total_bytes

    def cleanup(self) -> None:
        if self._cleaned:
            return
        try:
            _remove_tree_without_following_links(self.path)
        except OSError as exc:
            raise TaskWorkspaceError(
                "Could not remove the task workspace"
            ) from exc
        self._cleaned = True


class _PosixProcessBoundary:
    """Test/development fallback; the shipping target uses `_WindowsJob`."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process

    def terminate(self, exit_code: int = 1) -> None:
        if self._process.poll() is not None:
            return
        try:
            os.killpg(self._process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                self._process.kill()
            except (OSError, ProcessLookupError):
                pass

    def close(self) -> None:
        return


class _WindowsJob:
    """Kill-on-close Windows Job Object configured before worker resume."""

    _JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _UI_RESTRICTIONS = 0x000000FF

    def __init__(self, policy: WorkerPolicy) -> None:
        if os.name != "nt":
            raise OSError("Windows Job Objects are unavailable")
        if not isinstance(policy, WorkerPolicy):
            raise TypeError("Windows Job Object requires a WorkerPolicy")
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._wintypes = wintypes
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close_handle = self._kernel32.CloseHandle
        close_handle.argtypes = (wintypes.HANDLE,)
        close_handle.restype = wintypes.BOOL
        create_job = self._kernel32.CreateJobObjectW
        create_job.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        create_job.restype = wintypes.HANDLE
        handle = create_job(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        self._handle = handle
        self._closed = False
        try:
            self._configure(policy)
        except Exception:
            self.close()
            raise

    def _configure(self, policy: WorkerPolicy) -> None:
        ctypes = self._ctypes
        wintypes = self._wintypes

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
        limits.BasicLimitInformation.PerJobUserTimeLimit = (
            policy.runtime_seconds * 10_000_000
        )
        limits.BasicLimitInformation.ActiveProcessLimit = (
            1 + policy.max_child_processes
        )
        limits.BasicLimitInformation.LimitFlags = (
            self._JOB_OBJECT_LIMIT_JOB_TIME
            | self._JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | self._JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | self._JOB_OBJECT_LIMIT_JOB_MEMORY
            | self._JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        limits.ProcessMemoryLimit = policy.memory_bytes
        limits.JobMemoryLimit = policy.memory_bytes
        self._set_information(9, limits)

        ui_restrictions = wintypes.DWORD(self._UI_RESTRICTIONS)
        self._set_information(4, ui_restrictions)

    def _set_information(self, info_class: int, value) -> None:
        ctypes = self._ctypes
        wintypes = self._wintypes
        set_information = self._kernel32.SetInformationJobObject
        set_information.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        set_information.restype = wintypes.BOOL
        if not set_information(
            self._handle,
            info_class,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def assign_suspended(self, process: subprocess.Popen[bytes]) -> None:
        if self._closed or process.poll() is not None:
            raise TaskWorkerError("Suspended worker process is unavailable")
        process_handle = getattr(process, "_handle", None)
        if process_handle is None:
            raise TaskWorkerError("Worker process handle is unavailable")
        assign = self._kernel32.AssignProcessToJobObject
        assign.argtypes = (
            self._wintypes.HANDLE,
            self._wintypes.HANDLE,
        )
        assign.restype = self._wintypes.BOOL
        if not assign(self._handle, process_handle):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        _resume_process_threads(process.pid)

    def assign_existing(self, process: subprocess.Popen[bytes]) -> None:
        """Assign a cooperative test process that has not spawned children."""

        if self._closed or process.poll() is not None:
            raise TaskWorkerError("Worker process is unavailable")
        process_handle = getattr(process, "_handle", None)
        if process_handle is None:
            raise TaskWorkerError("Worker process handle is unavailable")
        assign = self._kernel32.AssignProcessToJobObject
        assign.argtypes = (
            self._wintypes.HANDLE,
            self._wintypes.HANDLE,
        )
        assign.restype = self._wintypes.BOOL
        if not assign(self._handle, process_handle):
            raise self._ctypes.WinError(self._ctypes.get_last_error())

    def terminate(self, exit_code: int = 1) -> None:
        if self._closed:
            return
        terminate = self._kernel32.TerminateJobObject
        terminate.argtypes = (
            self._wintypes.HANDLE,
            self._wintypes.UINT,
        )
        terminate.restype = self._wintypes.BOOL
        if not terminate(self._handle, exit_code):
            error = self._ctypes.get_last_error()
            if error not in {5, 6}:
                raise self._ctypes.WinError(error)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


class TaskWorkerHandle:
    """One live worker; all terminal paths reject late protocol output."""

    def __init__(
        self,
        *,
        run_id: str,
        process: subprocess.Popen[bytes],
        boundary,
        workspace: TaskWorkspace,
        policy: WorkerPolicy,
        session: ProtocolSession,
    ) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise TaskWorkerError("Worker pipes are unavailable")
        self.run_id = run_id
        self.process = process
        self.workspace = workspace
        self.policy = policy
        self._boundary = boundary
        self._session = session
        self._state = "active"
        self._state_lock = threading.RLock()
        self._exchange_lock = threading.Lock()
        self._finish_lock = threading.Lock()
        self._finished = False
        self._stop = threading.Event()
        self._frames: queue.Queue[bytes | BaseException | None] = queue.Queue()
        self._output_bytes = 0
        self._timer = threading.Timer(
            policy.runtime_seconds,
            self._timeout,
        )
        self._timer.daemon = True
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name=f"clicky-task-stdout-{run_id}",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            name=f"clicky-task-stderr-{run_id}",
            daemon=True,
        )
        self._watchdog_thread = threading.Thread(
            target=self._watchdog,
            name=f"clicky-task-watchdog-{run_id}",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()
        self._watchdog_thread.start()
        self._timer.start()

    @property
    def active(self) -> bool:
        with self._state_lock:
            return self._state == "active"

    def ping(self, nonce: str) -> str:
        if not isinstance(nonce, str) or not nonce or len(nonce) > 128:
            raise ValueError("Worker ping nonce is invalid")
        response = self._exchange(
            "ping",
            {"nonce": nonce},
            expected="pong",
        )
        if response.payload != {"nonce": nonce}:
            self._fault(ProtocolError("Worker pong did not match the ping"))
            raise ProtocolError("Worker pong did not match the ping")
        return nonce

    def shutdown(self) -> None:
        with self._state_lock:
            if self._state in {"closed", "cancelled"}:
                return
            if self._state != "active":
                raise TaskWorkerError("Task worker is not active")
            self._state = "closing"
        try:
            response = self._exchange(
                "shutdown",
                {},
                expected="stopped",
                allow_closing=True,
            )
            if response.payload:
                raise ProtocolError("Worker stop response is invalid")
            try:
                self.process.wait(timeout=_PROCESS_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                self._boundary.terminate()
                self.process.wait(timeout=_PROCESS_WAIT_SECONDS)
            with self._state_lock:
                self._state = "closed"
        except Exception:
            self.cancel()
            raise
        finally:
            self._finish()

    def cancel(self) -> None:
        with self._state_lock:
            if self._state in {"cancelled", "closed"}:
                return
            self._state = "cancelled"
        self._stop.set()
        self._timer.cancel()
        try:
            self._boundary.terminate()
        finally:
            self._frames.put(
                TaskWorkerError("Task worker was cancelled")
            )
            try:
                self.process.wait(timeout=_PROCESS_WAIT_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.process.kill()
                except (OSError, ProcessLookupError):
                    pass
            self._finish()

    def _exchange(
        self,
        message_type: str,
        payload: dict[str, object],
        *,
        expected: str,
        allow_closing: bool = False,
    ) -> ProtocolMessage:
        with self._exchange_lock:
            self._require_state(allow_closing=allow_closing)
            self.workspace.verify()
            frame = self._session.encode(message_type, payload)
            try:
                assert self.process.stdin is not None
                self.process.stdin.write(frame)
                self.process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self._fault(TaskWorkerError("Worker input pipe failed"))
                raise TaskWorkerError("Worker input pipe failed") from exc
            message = self._receive(
                timeout=min(5.0, float(self.policy.runtime_seconds)),
                allow_closing=allow_closing,
            )
            if message.message_type != expected:
                self._fault(
                    ProtocolError("Worker response type is unexpected")
                )
                raise ProtocolError("Worker response type is unexpected")
            self.workspace.verify()
            return message

    def _receive(
        self,
        *,
        timeout: float,
        allow_closing: bool,
    ) -> ProtocolMessage:
        self._require_state(allow_closing=allow_closing)
        try:
            item = self._frames.get(timeout=timeout)
        except queue.Empty as exc:
            self._fault(TaskWorkerLimitError("Worker response timed out"))
            raise TaskWorkerLimitError("Worker response timed out") from exc
        self._require_state(allow_closing=allow_closing)
        if item is None:
            self._fault(TaskWorkerError("Worker output closed unexpectedly"))
            raise TaskWorkerError("Worker output closed unexpectedly")
        if isinstance(item, BaseException):
            raise item
        try:
            return self._session.decode(item)
        except ProtocolError as exc:
            self._fault(exc)
            raise

    def _require_state(self, *, allow_closing: bool) -> None:
        with self._state_lock:
            allowed = {"active", "closing"} if allow_closing else {"active"}
            if self._state not in allowed:
                raise TaskWorkerError(
                    "Task worker rejects output after its terminal boundary"
                )

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            while not self._stop.is_set():
                line = self.process.stdout.readline(
                    self.policy.max_protocol_frame_bytes + 1
                )
                if not line:
                    self._frames.put(None)
                    return
                self._output_bytes += len(line)
                if (
                    len(line) > self.policy.max_protocol_frame_bytes
                    or not line.endswith(b"\n")
                    or self._output_bytes
                    > self.policy.protocol_output_bytes
                ):
                    raise TaskWorkerLimitError(
                        "Worker protocol output limit exceeded"
                    )
                self._frames.put(line)
        except BaseException as exc:
            self._fault(exc)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        total = 0
        try:
            while not self._stop.is_set():
                chunk = self.process.stderr.read(16 * 1024)
                if not chunk:
                    return
                total += len(chunk)
                if total > self.policy.diagnostic_bytes:
                    raise TaskWorkerLimitError(
                        "Worker diagnostic output limit exceeded"
                    )
        except BaseException as exc:
            self._fault(exc)

    def _watchdog(self) -> None:
        while not self._stop.wait(_WATCHDOG_INTERVAL_SECONDS):
            with self._state_lock:
                if self._state not in {"active", "closing"}:
                    return
            try:
                self.workspace.verify()
                if self.process.poll() is not None:
                    raise TaskWorkerError("Worker exited unexpectedly")
            except BaseException as exc:
                self._fault(exc)
                return

    def _timeout(self) -> None:
        self._fault(TaskWorkerLimitError("Worker runtime limit exceeded"))

    def _fault(self, error: BaseException) -> None:
        with self._state_lock:
            if self._state not in {"active", "closing"}:
                return
            self._state = "failed"
        self._stop.set()
        try:
            self._boundary.terminate()
        except Exception:
            pass
        self._frames.put(error)
        threading.Thread(
            target=self._finalize_fault,
            name=f"clicky-task-fault-cleanup-{self.run_id}",
            daemon=True,
        ).start()

    def _finalize_fault(self) -> None:
        try:
            self.process.wait(timeout=_PROCESS_WAIT_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            try:
                self.process.kill()
            except (OSError, ProcessLookupError):
                pass
        try:
            self._finish()
        except TaskWorkspaceError:
            pass

    def _finish(self) -> None:
        with self._finish_lock:
            if self._finished:
                return
            self._stop.set()
            self._timer.cancel()
            for stream in (
                self.process.stdin,
                self.process.stdout,
                self.process.stderr,
            ):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            try:
                self._boundary.close()
            finally:
                self.workspace.cleanup()
            self._finished = True

    def __enter__(self) -> TaskWorkerHandle:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if exc_type is None:
            self.shutdown()
        else:
            self.cancel()


class TaskWorkerCoordinator:
    """Launch the fixed worker command with no ambient task authority."""

    def __init__(self, *, workspace_root: Path | None = None) -> None:
        if workspace_root is not None and (
            not isinstance(workspace_root, Path)
            or not workspace_root.is_absolute()
        ):
            raise ValueError("Task workspace root must be absolute")
        self._workspace_root = workspace_root

    def start(self, run: TaskRun) -> TaskWorkerHandle:
        if not isinstance(run, TaskRun):
            raise TypeError("Task worker requires a TaskRun")
        if run.state is not TaskState.RUNNING:
            raise ValueError("Task worker requires a running task")
        if not run.grant.allows(CapabilityId.TASK_AGENT_RUN):
            raise ValueError("Task worker grant lacks task-agent authority")
        policy = WorkerPolicy.from_task_limits(run.spec.limits)
        workspace = TaskWorkspace.create(
            run.run_id,
            policy,
            root=self._workspace_root,
        )
        process = None
        boundary = None
        handle = None
        try:
            process, boundary = _launch_worker(workspace.path, policy)
            bootstrap = WorkerBootstrap(
                key=secrets.token_bytes(PROTOCOL_KEY_BYTES),
                session_id=secrets.token_hex(16),
                run_id=run.run_id,
                max_frame_bytes=policy.max_protocol_frame_bytes,
                max_messages=policy.max_protocol_messages,
            )
            session = ProtocolSession(
                bootstrap,
                send_direction="host_to_worker",
                receive_direction="worker_to_host",
            )
            assert process.stdin is not None
            process.stdin.write(bootstrap.encode())
            process.stdin.flush()
            handle = TaskWorkerHandle(
                run_id=run.run_id,
                process=process,
                boundary=boundary,
                workspace=workspace,
                policy=policy,
                session=session,
            )
            ready = handle._exchange("start", {}, expected="ready")
            if ready.payload:
                raise ProtocolError("Worker ready response is invalid")
            return handle
        except Exception:
            if handle is not None:
                try:
                    handle.cancel()
                except Exception:
                    pass
                raise
            if boundary is not None:
                try:
                    boundary.terminate()
                except Exception:
                    pass
                try:
                    boundary.close()
                except Exception:
                    pass
            if process is not None:
                try:
                    process.kill()
                except (OSError, ProcessLookupError):
                    pass
            workspace.cleanup()
            raise


def _launch_worker(
    workspace: Path,
    policy: WorkerPolicy,
) -> tuple[subprocess.Popen[bytes], object]:
    command = _worker_command()
    kwargs: dict[str, object] = {}
    job = None
    if os.name == "nt":
        job = _WindowsJob(policy)
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(
            command,
            cwd=workspace,
            env=worker_environment(workspace),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            bufsize=0,
            **kwargs,
        )
        if os.name == "nt":
            assert job is not None
            job.assign_suspended(process)
            boundary = job
        else:
            boundary = _PosixProcessBoundary(process)
        return process, boundary
    except Exception:
        if job is not None:
            try:
                job.terminate()
            except Exception:
                pass
            job.close()
        if "process" in locals():
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
        raise


def _worker_command() -> tuple[str, ...]:
    executable = str(Path(sys.executable).resolve(strict=True))
    if getattr(sys, "frozen", False):
        return (executable, "--task-worker")
    worker = Path(__file__).with_name("worker.py").resolve(strict=True)
    return (executable, "-I", "-B", str(worker))


def _resume_process_threads(process_id: int) -> None:
    import ctypes
    from ctypes import wintypes

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
        raise TaskWorkerError("Suspended worker thread was not found")

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
        raise TaskWorkerError("Suspended worker thread could not be resumed")


def _default_workspace_root() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return (base / "Clicky" / "task-runs").absolute()


def _metadata_is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return path.is_symlink() or _metadata_is_reparse(metadata)


def _protect_directory(path: Path) -> None:
    if os.name != "nt":
        path.chmod(0o700)
        return
    import ctypes
    from ctypes import wintypes

    descriptor = ctypes.c_void_p()
    convert = (
        ctypes.windll.advapi32
        .ConvertStringSecurityDescriptorToSecurityDescriptorW
    )
    convert.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    convert.restype = wintypes.BOOL
    sddl = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError()
    try:
        set_security = ctypes.windll.advapi32.SetFileSecurityW
        set_security.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_void_p,
        )
        set_security.restype = wintypes.BOOL
        if not set_security(
            str(path),
            0x00000004 | 0x80000000,
            descriptor,
        ):
            raise ctypes.WinError()
    finally:
        ctypes.windll.kernel32.LocalFree(descriptor)


def _remove_tree_without_following_links(path: Path) -> None:
    if not os.path.lexists(path):
        return
    metadata = path.lstat()
    if path.is_symlink() or _metadata_is_reparse(metadata):
        if stat.S_ISDIR(metadata.st_mode):
            os.rmdir(path)
        else:
            os.unlink(path)
        return
    if not stat.S_ISDIR(metadata.st_mode):
        os.unlink(path)
        return
    for entry in os.scandir(path):
        _remove_tree_without_following_links(Path(entry.path))
    os.rmdir(path)
