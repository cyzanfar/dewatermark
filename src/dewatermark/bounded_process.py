"""Shared, content-redacting subprocess execution with process-tree bounds.

This module is intentionally small and dependency free so the runtime and the
independent evaluation harness can share exactly one process boundary.  It is
not a sandbox: callers remain responsible for selecting a trusted executable
and for supplying a credential-free environment. In particular, POSIX process
groups cannot contain a descendant that deliberately creates a new session;
such a process may survive, while this module bounds and closes its local pipe
ends and rejects incomplete output.
"""

from __future__ import annotations

import asyncio
import ctypes
import math
import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from threading import Event, Thread
from typing import Any, Callable, Literal, Mapping, Optional

FailureKind = Literal[
    "launch_failed",
    "timed_out",
    "output_limit",
    "nonzero_exit",
    "termination_failed",
    "pipe_drain_failed",
    "interrupted",
]
_MAX_CAPTURE_BYTES = 64 * 1024 * 1024
_PIPE_POLL_SECONDS = 0.025
_PIPE_STOP_DRAIN_SECONDS = 0.05


class BoundedProcessFailure(RuntimeError):
    """A redacted subprocess failure classified without argv or stream data."""

    def __init__(
        self,
        kind: FailureKind,
        *,
        returncode: Optional[int] = None,
    ) -> None:
        self.kind = kind
        self.returncode = returncode
        super().__init__(kind)


@dataclass(frozen=True, repr=False)
class BoundedProcessResult:
    stdout: bytes
    returncode: int

    def __repr__(self) -> str:
        return "<bounded process result; output redacted>"


@dataclass
class _StreamCapture:
    limit: int
    retain: bool
    data: bytearray = field(default_factory=bytearray)
    count: int = 0
    overflow: bool = False
    read_failed: bool = False
    forced_stop: bool = False


class _WindowsJob:
    """Best-effort Windows Job Object that owns all adapter descendants."""

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

    def __init__(self) -> None:
        self._handle: Optional[int] = None

    @staticmethod
    def _kernel32() -> Any:
        factory = vars(ctypes).get("WinDLL")
        if not callable(factory):
            raise OSError("Windows APIs are unavailable")
        return factory("kernel32", use_last_error=True)

    def attach(self, process: subprocess.Popen[bytes]) -> bool:
        if os.name != "nt":
            return False
        try:
            from ctypes import wintypes

            class _IoCounters(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class _BasicLimitInformation(ctypes.Structure):
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

            class _ExtendedLimitInformation(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", _BasicLimitInformation),
                    ("IoInfo", _IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = self._kernel32()
            kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = (
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            )
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                return False
            handle_value = ctypes.cast(handle, ctypes.c_void_p).value
            if handle_value is None:
                return False
            self._handle = int(handle_value)
            info = _ExtendedLimitInformation()
            info.BasicLimitInformation.LimitFlags = self._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            configured = kernel32.SetInformationJobObject(
                handle,
                self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            raw_process_handle = vars(process).get("_handle")
            if raw_process_handle is None:
                self.close()
                return False
            process_handle = wintypes.HANDLE(int(raw_process_handle))
            if not configured or not kernel32.AssignProcessToJobObject(handle, process_handle):
                self.close()
                return False
            return True
        except Exception:
            self.close()
            return False

    def terminate(self) -> bool:
        if self._handle is None or os.name != "nt":
            return False
        try:
            from ctypes import wintypes

            kernel32 = self._kernel32()
            kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
            kernel32.TerminateJobObject.restype = wintypes.BOOL
            return bool(kernel32.TerminateJobObject(wintypes.HANDLE(self._handle), 1))
        except Exception:
            return False

    def resume_initial_thread(self, process_id: int) -> bool:
        """Resume a newly created suspended process after Job assignment."""
        if self._handle is None or os.name != "nt":
            return False
        try:
            from ctypes import wintypes

            class _ThreadEntry32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ThreadID", wintypes.DWORD),
                    ("th32OwnerProcessID", wintypes.DWORD),
                    ("tpBasePri", wintypes.LONG),
                    ("tpDeltaPri", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                ]

            kernel32 = self._kernel32()
            kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
            kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            kernel32.Thread32First.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
            kernel32.Thread32First.restype = wintypes.BOOL
            kernel32.Thread32Next.argtypes = (wintypes.HANDLE, ctypes.c_void_p)
            kernel32.Thread32Next.restype = wintypes.BOOL
            kernel32.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            kernel32.OpenThread.restype = wintypes.HANDLE
            kernel32.ResumeThread.argtypes = (wintypes.HANDLE,)
            kernel32.ResumeThread.restype = wintypes.DWORD
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL

            snapshot = kernel32.CreateToolhelp32Snapshot(0x00000004, 0)
            invalid = ctypes.c_void_p(-1).value
            snapshot_value = ctypes.cast(snapshot, ctypes.c_void_p).value
            if snapshot_value is None or snapshot_value == invalid:
                return False
            resumed = False
            try:
                entry = _ThreadEntry32()
                entry.dwSize = ctypes.sizeof(entry)
                available = bool(kernel32.Thread32First(snapshot, ctypes.byref(entry)))
                while available:
                    if int(entry.th32OwnerProcessID) == process_id:
                        thread = kernel32.OpenThread(0x0002, False, entry.th32ThreadID)
                        if thread:
                            try:
                                previous = int(kernel32.ResumeThread(thread))
                                resumed = previous != 0xFFFFFFFF
                            finally:
                                kernel32.CloseHandle(thread)
                            if resumed:
                                break
                    available = bool(kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
            finally:
                kernel32.CloseHandle(snapshot)
            return resumed
        except Exception:
            return False

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None or os.name != "nt":
            return
        try:
            from ctypes import wintypes

            kernel32 = self._kernel32()
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            kernel32.CloseHandle(wintypes.HANDLE(handle))
        except Exception:
            pass


class _ProcessTree:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        environment: Mapping[str, str],
    ) -> None:
        self.process = process
        self.environment = dict(environment)
        self.job = _WindowsJob()
        self.job_attached = self.job.attach(process)

    def start(self) -> bool:
        if os.name != "nt":
            return True
        # Windows children are created suspended. Failing closed here removes
        # the launch-to-Job-assignment race in which a fast root could spawn an
        # unowned descendant that retained stdout or stderr.
        return self.job_attached and self.job.resume_initial_thread(self.process.pid)

    def terminate(self) -> None:
        """Terminate the root and descendants still owned by its group or Job."""
        if os.name == "nt":
            terminated = self.job.terminate() if self.job_attached else False
            if not terminated:
                self._taskkill_fallback()
        else:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        if self.process.poll() is None:
            try:
                self.process.kill()
            except OSError:
                pass

    def _taskkill_fallback(self) -> None:
        """Use the platform tree-kill tool when a Job Object cannot be assigned."""
        try:
            subprocess.run(
                ("taskkill.exe", "/PID", str(self.process.pid), "/T", "/F"),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                env=self.environment,
                timeout=2.0,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def close(self) -> None:
        self.job.close()


def _read_bounded(
    stream: Any,
    capture: _StreamCapture,
    overflow_event: Event,
    terminate: Callable[[], None],
    stop_event: Event,
) -> None:
    if os.name != "nt":
        _read_bounded_posix(stream, capture, overflow_event, terminate, stop_event)
        return
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            capture.count += len(chunk)
            remaining = max(0, capture.limit - len(capture.data))
            if capture.retain and remaining:
                capture.data.extend(chunk[:remaining])
            if capture.count > capture.limit:
                capture.overflow = True
                overflow_event.set()
                terminate()
                return
    except (OSError, ValueError):
        capture.read_failed = True


def _read_bounded_posix(
    stream: Any,
    capture: _StreamCapture,
    overflow_event: Event,
    terminate: Callable[[], None],
    stop_event: Event,
) -> None:
    """Read a POSIX pipe without allowing an escaped writer to pin a thread.

    A descendant can deliberately leave the invocation process group with
    ``setsid`` or ``setpgid``. POSIX has no portable Job Object equivalent, so
    group signalling cannot guarantee that such a process is killed. Keeping
    the local read descriptor non-blocking lets us bound our own handle and
    thread lifetime. If EOF does not arrive during the final bounded drain, the
    call fails closed rather than treating potentially incomplete output as a
    successful result.
    """
    stopped_at: Optional[float] = None
    try:
        descriptor = stream.fileno()
        os.set_blocking(descriptor, False)
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while True:
                if stop_event.is_set() and stopped_at is None:
                    stopped_at = time.monotonic()
                if stopped_at is None:
                    wait_seconds = _PIPE_POLL_SECONDS
                else:
                    remaining = _PIPE_STOP_DRAIN_SECONDS - (time.monotonic() - stopped_at)
                    if remaining <= 0:
                        capture.forced_stop = True
                        return
                    wait_seconds = remaining
                if not selector.select(wait_seconds):
                    if stopped_at is not None:
                        capture.forced_stop = True
                        return
                    continue
                try:
                    chunk = os.read(descriptor, 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    return
                capture.count += len(chunk)
                remaining_capture = max(0, capture.limit - len(capture.data))
                if capture.retain and remaining_capture:
                    capture.data.extend(chunk[:remaining_capture])
                if capture.count > capture.limit:
                    capture.overflow = True
                    overflow_event.set()
                    terminate()
                    return
    except (OSError, ValueError):
        capture.read_failed = True


def _write_request(stream: Any, payload: bytes, stop_event: Event) -> None:
    if os.name != "nt":
        _write_request_posix(stream, payload, stop_event)
        return
    try:
        stream.write(payload)
        stream.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _write_request_posix(stream: Any, payload: bytes, stop_event: Event) -> None:
    """Write without letting an escaped reader retain the local input thread."""
    try:
        descriptor = stream.fileno()
        os.set_blocking(descriptor, False)
        remaining = memoryview(payload)
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_WRITE)
            while remaining and not stop_event.is_set():
                if not selector.select(_PIPE_POLL_SECONDS):
                    continue
                try:
                    written = os.write(descriptor, remaining)
                except BlockingIOError:
                    continue
                if written <= 0:
                    break
                remaining = remaining[written:]
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


def _close_finished_stream(stream: Any, reader: Thread) -> None:
    # BufferedReader.close() can wait on a lock held by a blocked read. Never
    # call it while the reader is alive; daemon-thread ownership is safer than
    # turning a timeout into an unbounded caller hang.
    if reader.is_alive():
        return
    try:
        stream.close()
    except (OSError, ValueError):
        pass


def _validated_invocation(
    command: tuple[str, ...],
    payload: bytes,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    environment: Mapping[str, str],
    working_directory: Optional[os.PathLike[str] | str],
    checkpoint: Optional[Callable[[], None]],
    cleanup_seconds: float,
) -> tuple[dict[str, str], Optional[str]]:
    """Validate untrusted launch metadata without reflecting any of it."""
    try:
        if type(command) is not tuple or not command:
            raise TypeError
        if any(
            type(argument) is not str or not argument or "\x00" in argument for argument in command
        ):
            raise TypeError
        if type(payload) is not bytes:
            raise TypeError
        if (
            isinstance(timeout_seconds, bool)
            or type(timeout_seconds) not in (int, float)
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds) <= 3600
        ):
            raise ValueError
        if (
            isinstance(cleanup_seconds, bool)
            or type(cleanup_seconds) not in (int, float)
            or not math.isfinite(float(cleanup_seconds))
            or not 0 < float(cleanup_seconds) <= 30
        ):
            raise ValueError
        for limit in (max_stdout_bytes, max_stderr_bytes):
            if type(limit) is not int or not 1 <= limit <= _MAX_CAPTURE_BYTES:
                raise ValueError
        if checkpoint is not None and not callable(checkpoint):
            raise TypeError
        normalized_environment = dict(environment)
        if any(
            type(key) is not str
            or type(value) is not str
            or "\x00" in key
            or "\x00" in value
            or "=" in key
            for key, value in normalized_environment.items()
        ):
            raise TypeError
        normalized_directory: Optional[str] = None
        if working_directory is not None:
            normalized_directory = os.fspath(working_directory)
            if type(normalized_directory) is not str or "\x00" in normalized_directory:
                raise TypeError
        return normalized_environment, normalized_directory
    except Exception:
        raise BoundedProcessFailure("launch_failed") from None


def run_bounded_process(
    command: tuple[str, ...],
    payload: bytes,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    environment: Mapping[str, str],
    working_directory: Optional[os.PathLike[str] | str] = None,
    checkpoint: Optional[Callable[[], None]] = None,
    cleanup_seconds: float = 1.0,
) -> BoundedProcessResult:
    """Execute immutable argv with bounded time, output, and pipe cleanup.

    The exception never contains argv, input, stdout, stderr, or environment.
    Windows descendants are owned by a Job Object with a ``taskkill`` fallback.
    POSIX descendants are signalled through their process group; a process that
    deliberately creates a new session can escape that group, because this is
    not a sandbox. Non-blocking POSIX readers still bound local pipe/thread
    lifetime and fail closed if an escaped writer prevents EOF.
    """
    normalized_environment, normalized_directory = _validated_invocation(
        command,
        payload,
        timeout_seconds,
        max_stdout_bytes,
        max_stderr_bytes,
        environment,
        working_directory,
        checkpoint,
        cleanup_seconds,
    )
    popen_options: dict[str, Any] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
        "env": normalized_environment,
        "close_fds": True,
    }
    if normalized_directory is not None:
        popen_options["cwd"] = normalized_directory
    if os.name == "nt":
        popen_options["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        ) | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
    else:
        popen_options["start_new_session"] = True
    try:
        process: subprocess.Popen[bytes] = subprocess.Popen(command, **popen_options)
    except Exception:
        raise BoundedProcessFailure("launch_failed") from None

    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    tree = _ProcessTree(process, normalized_environment)
    if not tree.start():
        tree.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
        tree.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        raise BoundedProcessFailure("launch_failed") from None
    overflow_event = Event()
    io_stop_event = Event()
    stdout = _StreamCapture(max_stdout_bytes, retain=True)
    stderr = _StreamCapture(max_stderr_bytes, retain=False)
    readers = (
        Thread(
            target=_read_bounded,
            args=(process.stdout, stdout, overflow_event, tree.terminate, io_stop_event),
            name="dewatermark-stdout-reader",
            daemon=True,
        ),
        Thread(
            target=_read_bounded,
            args=(process.stderr, stderr, overflow_event, tree.terminate, io_stop_event),
            name="dewatermark-stderr-reader",
            daemon=True,
        ),
    )
    writer = Thread(
        target=_write_request,
        args=(process.stdin, payload, io_stop_event),
        name="dewatermark-stdin-writer",
        daemon=True,
    )
    started_threads: list[Thread] = []
    try:
        for thread in readers:
            thread.start()
            started_threads.append(thread)
        writer.start()
        started_threads.append(writer)
    except Exception:
        io_stop_event.set()
        tree.terminate()
        try:
            process.wait(timeout=cleanup_seconds)
        except subprocess.TimeoutExpired:
            tree.terminate()
            try:
                process.wait(timeout=cleanup_seconds)
            except subprocess.TimeoutExpired:
                pass
        tree.close()
        for thread in started_threads:
            thread.join(timeout=cleanup_seconds)
        if not writer.is_alive():
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
        for stream, reader in zip((process.stdout, process.stderr), readers):
            _close_finished_stream(stream, reader)
        raise BoundedProcessFailure("launch_failed") from None

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    interrupted: Optional[BaseException] = None
    termination_failed = False
    try:
        while process.poll() is None:
            if checkpoint is not None:
                try:
                    checkpoint()
                except BaseException as exc:
                    interrupted = exc
                    break
            if overflow_event.is_set():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            time.sleep(min(0.01, remaining))

        # Always terminate the portion of the invocation tree still owned by
        # the process group or Job. A POSIX child can deliberately detach; the
        # non-blocking drain below bounds our handles but cannot kill that child.
        tree.terminate()
        try:
            process.wait(timeout=cleanup_seconds)
        except subprocess.TimeoutExpired:
            tree.terminate()
            try:
                process.wait(timeout=cleanup_seconds)
            except subprocess.TimeoutExpired:
                termination_failed = True
    finally:
        # Closing a kill-on-close Job Object is a second fail-safe for Windows
        # descendants before the bounded pipe-drain joins.
        tree.close()
        io_stop_event.set()
        drain_deadline = time.monotonic() + cleanup_seconds
        for thread in (writer, *readers):
            thread.join(timeout=max(0.0, drain_deadline - time.monotonic()))
        for stream, reader in zip((process.stdout, process.stderr), readers):
            _close_finished_stream(stream, reader)

    if interrupted is not None:
        if isinstance(interrupted, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
            raise interrupted
        # Request-budget exceptions have a deliberately small public vocabulary.
        # Preserve their typed control flow without reflecting a forged message.
        from .request_context import ResourceBudgetExceeded, safe_error

        if isinstance(interrupted, ResourceBudgetExceeded):
            raise ResourceBudgetExceeded(safe_error("request", interrupted)) from None
        raise BoundedProcessFailure("interrupted") from None
    if timed_out:
        raise BoundedProcessFailure("timed_out") from None
    if stdout.overflow or stderr.overflow:
        raise BoundedProcessFailure("output_limit") from None
    if termination_failed:
        raise BoundedProcessFailure("termination_failed") from None
    if stdout.read_failed or stderr.read_failed:
        raise BoundedProcessFailure("pipe_drain_failed") from None
    if stdout.forced_stop or stderr.forced_stop:
        raise BoundedProcessFailure("pipe_drain_failed") from None
    if any(thread.is_alive() for thread in readers) or writer.is_alive():
        raise BoundedProcessFailure("pipe_drain_failed") from None
    returncode = process.returncode
    if returncode is None:
        raise BoundedProcessFailure("termination_failed") from None
    if returncode:
        raise BoundedProcessFailure("nonzero_exit", returncode=returncode) from None
    return BoundedProcessResult(stdout=bytes(stdout.data), returncode=returncode)


__all__ = [
    "BoundedProcessFailure",
    "BoundedProcessResult",
    "FailureKind",
    "run_bounded_process",
]
