#!/usr/bin/env python3
"""Join Linux mechanics with exact AppArmor and cgroup cleanup receipts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from devhub.benchmark import canonical
from devhub.linux_isolation import (
    LinuxAppArmorCleanupReceiptV1,
    LinuxAppArmorLifecycleFailurePayloadV1,
    LinuxAppArmorLifecycleFailureV1,
    LinuxCgroupCleanupReceiptV2,
    LinuxCgroupCleanupReceiptV3,
    LinuxIsolationEvidenceV16,
    LinuxIsolationEvidenceV17,
    LinuxIsolationEvidenceV18,
    LinuxIsolationQualificationPayloadV16,
    LinuxIsolationQualificationPayloadV18,
    LinuxIsolationQualificationPayloadV19,
    LinuxIsolationQualificationV16,
    LinuxIsolationQualificationV18,
    LinuxIsolationQualificationV19,
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


def finalize(
    mechanics_path: Path,
    cleanup_path: Path,
    cgroup_cleanup_path: Path,
    output: Path | None = None,
) -> None:
    if output is None:
        output = cgroup_cleanup_path
        mechanics_v16 = LinuxIsolationEvidenceV16.model_validate_json(mechanics_path.read_bytes())
        cleanup_v16 = LinuxAppArmorCleanupReceiptV1.model_validate_json(cleanup_path.read_bytes())
        qualification_v16 = LinuxIsolationQualificationV16.create(
            LinuxIsolationQualificationPayloadV16(
                mechanics=mechanics_v16,
                apparmor_cleanup=cleanup_v16,
            )
        )
        write_new(output, canonical(qualification_v16.model_dump(mode="json")))
        return
    cleanup = LinuxAppArmorCleanupReceiptV1.model_validate_json(cleanup_path.read_bytes())
    raw_mechanics = mechanics_path.read_bytes()
    try:
        mechanics_header = json.loads(raw_mechanics)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Linux isolation mechanics evidence is not valid JSON") from error
    if not isinstance(mechanics_header, dict):
        raise ValueError("Linux isolation mechanics evidence must be a JSON object")
    if mechanics_header.get("schema_version") == 18:
        mechanics_v19 = LinuxIsolationEvidenceV18.model_validate_json(raw_mechanics)
        cgroup_cleanup_v19 = LinuxCgroupCleanupReceiptV3.model_validate_json(
            cgroup_cleanup_path.read_bytes()
        )
        qualification = LinuxIsolationQualificationV19.create(
            LinuxIsolationQualificationPayloadV19(
                mechanics=mechanics_v19,
                apparmor_cleanup=cleanup,
                cgroup_cleanup=cgroup_cleanup_v19,
            )
        )
    else:
        mechanics = LinuxIsolationEvidenceV17.model_validate_json(raw_mechanics)
        cgroup_cleanup = LinuxCgroupCleanupReceiptV2.model_validate_json(
            cgroup_cleanup_path.read_bytes()
        )
        qualification = LinuxIsolationQualificationV18.create(
            LinuxIsolationQualificationPayloadV18(
                mechanics=mechanics,
                apparmor_cleanup=cleanup,
                cgroup_cleanup=cgroup_cleanup,
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
    parser.add_argument("--cgroup-cleanup", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--environment-instance-id", required=True)
    parser.add_argument("--failure-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        finalize(args.mechanics, args.cleanup, args.cgroup_cleanup, args.output)
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
