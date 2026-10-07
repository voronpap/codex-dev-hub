import subprocess
import sys
import threading

from devhub import process_capture as capture
from devhub.experiment_launch import cleanup_container


class ChunkedStream:
    def __init__(self, chunks):
        self.chunks = iter(chunks)

    def read(self, _size):
        return next(self.chunks, b"")


def test_capture_retains_bounded_prefix_and_reports_exact_observation(monkeypatch):
    monkeypatch.setattr(capture, "RETAINED_BYTE_LIMIT_PER_STREAM", 16)
    monkeypatch.setattr(capture, "HARD_OBSERVED_BYTE_LIMIT_PER_STREAM", 128)
    item = capture.capture_process(
        [sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*40)"], b"", 5
    )
    assert item.stdout.data == b"x" * 16
    assert item.stdout.evidence.retained_bytes == 16
    assert item.stdout.evidence.observed_bytes == 40
    assert item.stdout.evidence.truncated
    assert item.stdout.evidence.limit_reason == "retained_limit"


def test_hard_limit_terminates_and_never_retains_unbounded_output(monkeypatch):
    monkeypatch.setattr(capture, "RETAINED_BYTE_LIMIT_PER_STREAM", 32)
    monkeypatch.setattr(capture, "HARD_OBSERVED_BYTE_LIMIT_PER_STREAM", 64)
    code = "import sys;sys.stdout.buffer.write(b'x'*100000);sys.stdout.flush()"
    item = capture.capture_process(
        [sys.executable, "-c", code],
        b"",
        5,
    )
    assert item.output_limit_exceeded
    assert len(item.stdout.data) == 32
    assert item.stdout.evidence.limit_reason == "hard_limit"


def test_secret_detection_spans_reader_chunk_boundary():
    collector = capture._Collector(())
    stop = threading.Event()
    collector.read(ChunkedStream([b"prefix sk-abcdefghijkl", b"mnopqrstuv suffix"]), stop)
    item = collector.finish()
    assert stop.is_set()
    assert item.evidence.secret_detected
    assert item.evidence.limit_reason == "secret_detected"
    assert item.data == b""


def test_stdout_and_stderr_are_drained_concurrently(monkeypatch):
    monkeypatch.setattr(capture, "RETAINED_BYTE_LIMIT_PER_STREAM", 128 * 1024)
    monkeypatch.setattr(capture, "HARD_OBSERVED_BYTE_LIMIT_PER_STREAM", 256 * 1024)
    item = capture.capture_process(
        [
            sys.executable,
            "-c",
            "import sys;sys.stdout.buffer.write(b'o'*65536);"
            "sys.stderr.buffer.write(b'e'*65536);sys.stdout.flush();sys.stderr.flush()",
        ],
        b"",
        5,
    )
    assert item.stdout.evidence.observed_bytes == 65536
    assert item.stderr.evidence.observed_bytes == 65536
    assert not item.timed_out


def test_cleanup_uses_only_exact_cid_and_verifies_absence(monkeypatch):
    cid = "a" * 64
    commands = []

    def run(args, **kwargs):
        commands.append(args)
        return subprocess.CompletedProcess(args, 1 if "inspect" in args else 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    for _ in range(4):
        assert cleanup_container(cid)
    assert len(commands) == 8
    assert all(command[-1] == cid for command in commands)
    assert sum("rm" in command for command in commands) == 4
    assert sum("inspect" in command for command in commands) == 4


def test_cleanup_failure_is_explicit(monkeypatch):
    cid = "b" * 64

    def run(args, **kwargs):
        return subprocess.CompletedProcess(args, 1 if "rm" in args else 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    assert not cleanup_container(cid)
