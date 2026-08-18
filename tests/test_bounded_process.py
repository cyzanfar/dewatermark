from __future__ import annotations

import math
import os
import signal
import sys
import threading
import time

import pytest

from dewatermark.bounded_process import BoundedProcessFailure, run_bounded_process
from dewatermark.request_context import ResourceBudgetExceeded


def _environment() -> dict[str, str]:
    value = {"PATH": os.environ.get("PATH", os.defpath), "PYTHONIOENCODING": "utf-8"}
    if os.name == "nt":
        for key in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
            if key in os.environ:
                value[key] = os.environ[key]
    return value


def test_bounded_process_kills_descendant_that_inherits_output_pipe():
    script = (
        "import subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
        "sys.stdout.buffer.write(b'ok');sys.stdout.buffer.flush()"
    )
    started = time.monotonic()
    result = run_bounded_process(
        (sys.executable, "-c", script),
        b"",
        timeout_seconds=3.0,
        max_stdout_bytes=128,
        max_stderr_bytes=128,
        environment=_environment(),
    )
    assert result.stdout == b"ok"
    assert time.monotonic() - started < 3.0


@pytest.mark.skipif(os.name == "nt", reason="POSIX detached-session regression")
def test_bounded_process_closes_reader_for_detached_descendant(tmp_path):
    pid_file = tmp_path / "detached.pid"
    script = (
        "import pathlib,subprocess,sys;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],"
        "start_new_session=True);"
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii');"
        "sys.stdout.buffer.write(b'ok');sys.stdout.buffer.flush()"
    )
    io_thread_names = {
        "dewatermark-stdout-reader",
        "dewatermark-stderr-reader",
        "dewatermark-stdin-writer",
    }
    started = time.monotonic()
    try:
        with pytest.raises(BoundedProcessFailure) as caught:
            run_bounded_process(
                (sys.executable, "-c", script, str(pid_file)),
                b"x" * (1024 * 1024),
                timeout_seconds=3.0,
                max_stdout_bytes=128,
                max_stderr_bytes=128,
                environment=_environment(),
                cleanup_seconds=0.2,
            )
        assert caught.value.kind == "pipe_drain_failed"
        assert time.monotonic() - started < 2.0
        assert not any(
            thread.is_alive() and thread.name in io_thread_names for thread in threading.enumerate()
        )
    finally:
        if pid_file.exists():
            detached_pid = int(pid_file.read_text(encoding="ascii"))
            try:
                os.killpg(detached_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_bounded_process_failure_never_contains_payload_or_streams():
    private = "private-process-material"
    script = f"import sys;sys.stderr.write({private!r});sys.exit(7)"
    with pytest.raises(BoundedProcessFailure) as caught:
        run_bounded_process(
            (sys.executable, "-c", script),
            private.encode(),
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
            environment=_environment(),
        )
    assert caught.value.kind == "nonzero_exit"
    assert caught.value.returncode == 7
    assert private not in str(caught.value)
    assert private not in repr(caught.value)


def test_bounded_process_honors_working_directory(tmp_path):
    result = run_bounded_process(
        (sys.executable, "-c", "import os;print(os.getcwd(), end='')"),
        b"",
        timeout_seconds=2.0,
        max_stdout_bytes=4096,
        max_stderr_bytes=128,
        environment=_environment(),
        working_directory=tmp_path,
    )

    assert os.path.samefile(result.stdout.decode(), tmp_path)


def test_bounded_process_redacts_invalid_working_directory(tmp_path):
    private = tmp_path / "private-working-directory"
    with pytest.raises(BoundedProcessFailure) as caught:
        run_bounded_process(
            (sys.executable, "-c", "pass"),
            b"",
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
            environment=_environment(),
            working_directory=private,
        )

    assert caught.value.kind == "launch_failed"
    assert str(private) not in str(caught.value)
    assert str(private) not in repr(caught.value)


@pytest.mark.parametrize(
    "override",
    [
        {"timeout_seconds": math.nan},
        {"timeout_seconds": math.inf},
        {"timeout_seconds": -1.0},
        {"timeout_seconds": 3601.0},
        {"max_stdout_bytes": 0},
        {"max_stderr_bytes": 64 * 1024 * 1024 + 1},
        {"cleanup_seconds": math.nan},
        {"cleanup_seconds": 31.0},
    ],
)
def test_bounded_process_rejects_non_bounded_limits_before_launch(monkeypatch, override):
    launched = []
    monkeypatch.setattr(
        "dewatermark.bounded_process.subprocess.Popen",
        lambda *_args, **_kwargs: launched.append(True),
    )
    options = {
        "timeout_seconds": 2.0,
        "max_stdout_bytes": 128,
        "max_stderr_bytes": 128,
        "environment": _environment(),
        "cleanup_seconds": 1.0,
        **override,
    }

    with pytest.raises(BoundedProcessFailure) as caught:
        run_bounded_process((sys.executable, "-c", "pass"), b"", **options)

    assert caught.value.kind == "launch_failed"
    assert caught.value.__cause__ is None
    assert launched == []


def test_bounded_process_redacts_malformed_environment_before_launch():
    private = "private-environment-credential"

    class PrivateMapping(dict):
        def __iter__(self):
            raise ValueError(private)

    with pytest.raises(BoundedProcessFailure) as caught:
        run_bounded_process(
            (sys.executable, "-c", "pass"),
            b"",
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
            environment=PrivateMapping({private: object()}),  # type: ignore[dict-item]
        )

    assert caught.value.kind == "launch_failed"
    assert private not in str(caught.value)
    assert caught.value.__cause__ is None


def test_bounded_process_cleans_up_when_io_thread_start_fails(monkeypatch):
    private = "private-thread-start-credential"

    def fail_start(_thread):
        raise RuntimeError(private)

    monkeypatch.setattr("dewatermark.bounded_process.Thread.start", fail_start)
    with pytest.raises(BoundedProcessFailure) as caught:
        run_bounded_process(
            (sys.executable, "-c", "import time;time.sleep(30)"),
            b"",
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
            environment=_environment(),
            cleanup_seconds=0.1,
        )

    assert caught.value.kind == "launch_failed"
    assert private not in str(caught.value)
    assert caught.value.__cause__ is None


def test_bounded_process_redacts_arbitrary_checkpoint_failures():
    private = "private-checkpoint-credential"

    def checkpoint():
        raise RuntimeError(private)

    with pytest.raises(BoundedProcessFailure) as caught:
        run_bounded_process(
            (sys.executable, "-c", "import time;time.sleep(30)"),
            b"",
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
            environment=_environment(),
            checkpoint=checkpoint,
            cleanup_seconds=0.1,
        )

    assert caught.value.kind == "interrupted"
    assert private not in str(caught.value)
    assert caught.value.__cause__ is None


def test_bounded_process_preserves_sanitized_resource_budget_control_flow():
    private = "private-budget-credential"

    def checkpoint():
        raise ResourceBudgetExceeded(private)

    with pytest.raises(ResourceBudgetExceeded) as caught:
        run_bounded_process(
            (sys.executable, "-c", "import time;time.sleep(30)"),
            b"",
            timeout_seconds=2.0,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
            environment=_environment(),
            checkpoint=checkpoint,
            cleanup_seconds=0.1,
        )

    assert private not in str(caught.value)
    assert caught.value.__cause__ is None
