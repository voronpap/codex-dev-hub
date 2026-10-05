"""Bounded subprocess capture used by the Stage 3G executor and evaluator."""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, BinaryIO, Literal

from pydantic import Field

from devhub.benchmark import Digest, digest
from devhub.models import Contract

RETAINED_BYTE_LIMIT_PER_STREAM = 1024 * 1024
HARD_OBSERVED_BYTE_LIMIT_PER_STREAM = 8 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
SCAN_OVERLAP_BYTES = 4096

SECRET_PATTERNS = (
    rb"sk-[A-Za-z0-9_-]{20,}",
    rb"gh[pousr]_[A-Za-z0-9]{20,}",
    rb"github_pat_[A-Za-z0-9_]{20,}",
    rb"gsk_[A-Za-z0-9]{30,}",
    rb"AIza[A-Za-z0-9_-]{30,}",
    rb"AQ\.[A-Za-z0-9_-]{30,}",
    rb"-----BEGIN .*PRIVATE KEY-----",
    rb"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.",
)


class CapturedStreamV1(Contract):
    retained_bytes: Annotated[int, Field(ge=0)]
    observed_bytes: Annotated[int, Field(ge=0)] | None
    truncated: bool
    retained_sha256: Digest
    limit_reason: Literal["retained_limit", "hard_limit", "secret_detected"] | None = None
    secret_detected: bool = False


@dataclass(frozen=True)
class CapturedStream:
    data: bytes
    evidence: CapturedStreamV1


@dataclass(frozen=True)
class ProcessCapture:
    stdout: CapturedStream
    stderr: CapturedStream
    returncode: int | None
    timed_out: bool
    output_limit_exceeded: bool
    secret_detected: bool
    input_error: str | None
    started_at: datetime
    ended_at: datetime
    duration_ns: int


class _Collector:
    def __init__(self, secret_values: tuple[bytes, ...]) -> None:
        self.retained = bytearray()
        self.observed = 0
        self.complete = False
        self.truncated = False
        self.hard_limit = False
        self.secret_detected = False
        self.error = False
        self.tail = b""
        self.secret_values = tuple(value for value in secret_values if value)

    def _scan(self, chunk: bytes) -> None:
        window = self.tail + chunk
        if any(re.search(pattern, window) for pattern in SECRET_PATTERNS) or any(
            value in window for value in self.secret_values
        ):
            self.secret_detected = True
        overlap = max(
            SCAN_OVERLAP_BYTES,
            max((len(value) - 1 for value in self.secret_values), default=0),
        )
        self.tail = window[-overlap:]

    def read(self, stream: BinaryIO, stop: threading.Event) -> None:
        try:
            while chunk := stream.read(READ_CHUNK_BYTES):
                self.observed += len(chunk)
                self._scan(chunk)
                remaining = RETAINED_BYTE_LIMIT_PER_STREAM - len(self.retained)
                if remaining > 0:
                    self.retained.extend(chunk[:remaining])
                if self.observed > RETAINED_BYTE_LIMIT_PER_STREAM:
                    self.truncated = True
                if self.observed > HARD_OBSERVED_BYTE_LIMIT_PER_STREAM:
                    self.hard_limit = True
                if self.secret_detected or self.hard_limit:
                    stop.set()
            self.complete = True
        except OSError:
            self.error = True
            stop.set()

    def finish(self) -> CapturedStream:
        if self.secret_detected:
            raw = b""
            reason: Literal["retained_limit", "hard_limit", "secret_detected"] | None = (
                "secret_detected"
            )
        else:
            raw = bytes(self.retained)
            reason = (
                "hard_limit" if self.hard_limit else "retained_limit" if self.truncated else None
            )
        return CapturedStream(
            data=raw,
            evidence=CapturedStreamV1(
                retained_bytes=len(raw),
                observed_bytes=self.observed if self.complete and not self.error else None,
                truncated=self.truncated or self.hard_limit or self.secret_detected,
                retained_sha256=digest(raw),
                limit_reason=reason,
                secret_detected=self.secret_detected,
            ),
        )


InputDriver = Callable[[subprocess.Popen[bytes], float, threading.Event], None]
Terminator = Callable[[], None]


def capture_process(
    argv: list[str],
    stdin: bytes | None,
    timeout: float,
    *,
    input_driver: InputDriver | None = None,
    terminate_execution: Terminator | None = None,
    secret_values: tuple[bytes, ...] = (),
) -> ProcessCapture:
    """Run fixed argv with bounded concurrent capture and no automatic retry."""

    if stdin is not None and input_driver is not None:
        raise ValueError("Choose immediate stdin or an input driver")
    started = datetime.now(UTC)
    tick = time.perf_counter_ns()
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    stop = threading.Event()
    collectors = (_Collector(secret_values), _Collector(secret_values))
    threads = [
        threading.Thread(target=item.read, args=(stream, stop), daemon=True)
        for item, stream in zip(collectors, (process.stdout, process.stderr), strict=True)
    ]
    for thread in threads:
        thread.start()
    input_error = None
    try:
        if input_driver is not None:
            try:
                input_driver(process, deadline, stop)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                input_error = f"{type(error).__name__}: {error}"
                stop.set()
        elif stdin is not None:
            try:
                process.stdin.write(stdin)
                process.stdin.flush()
            except (BrokenPipeError, OSError) as error:
                input_error = f"{type(error).__name__}: {error}"
                stop.set()
        process.stdin.close()
        timed_out = False
        terminated = False
        while process.poll() is None:
            timed_out = time.monotonic() >= deadline
            if timed_out or stop.is_set():
                if not terminated and terminate_execution is not None:
                    try:
                        terminate_execution()
                    except (OSError, subprocess.SubprocessError):
                        pass
                terminated = True
                process.kill()
                break
            time.sleep(0.02)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    captured = tuple(item.finish() for item in collectors)
    return ProcessCapture(
        stdout=captured[0],
        stderr=captured[1],
        returncode=process.returncode,
        timed_out=timed_out,
        output_limit_exceeded=any(item.hard_limit for item in collectors),
        secret_detected=any(item.secret_detected for item in collectors),
        input_error=input_error,
        started_at=started,
        ended_at=datetime.now(UTC),
        duration_ns=time.perf_counter_ns() - tick,
    )
