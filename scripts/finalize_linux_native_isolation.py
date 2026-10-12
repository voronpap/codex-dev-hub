#!/usr/bin/env python3
"""Join V5 native Linux mechanics with the exact privileged cleanup receipt."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from devhub.benchmark import canonical
from devhub.linux_isolation import (
    LinuxAppArmorCleanupReceiptV1,
    LinuxAppArmorLifecycleFailurePayloadV1,
    LinuxAppArmorLifecycleFailureV1,
    LinuxIsolationEvidenceV5,
    LinuxIsolationQualificationPayloadV5,
    LinuxIsolationQualificationV5,
)


def write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def finalize(mechanics_path: Path, cleanup_path: Path, output: Path) -> None:
    mechanics = LinuxIsolationEvidenceV5.model_validate_json(mechanics_path.read_bytes())
    cleanup = LinuxAppArmorCleanupReceiptV1.model_validate_json(cleanup_path.read_bytes())
    qualification = LinuxIsolationQualificationV5.create(
        LinuxIsolationQualificationPayloadV5(
            mechanics=mechanics,
            apparmor_cleanup=cleanup,
        )
    )
    write_new(output, canonical(qualification.model_dump(mode="json")))


def write_failure(output: Path, implementation_commit: str, environment_instance_id: str) -> None:
    failure = LinuxAppArmorLifecycleFailureV1.create(
        LinuxAppArmorLifecycleFailurePayloadV1(
            phase="finalization",
            reason_code="join_failed",
            implementation_commit=implementation_commit,
            environment_instance_id=environment_instance_id,
            cleanup_attempted=True,
            cleanup_succeeded=True,
        )
    )
    write_new(output, canonical(failure.model_dump(mode="json")))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mechanics", type=Path, required=True)
    parser.add_argument("--cleanup", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--environment-instance-id", required=True)
    parser.add_argument("--failure-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        finalize(args.mechanics, args.cleanup, args.output)
    except BaseException:
        if args.output.is_file() and not args.output.is_symlink():
            args.output.unlink()
        write_failure(
            args.failure_output,
            args.implementation_commit,
            args.environment_instance_id,
        )
        raise


if __name__ == "__main__":
    main()
