"""Bind the retained Build-020 executable to the exact qualification context."""

import argparse
import json
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.qualification import CodexExecutableReceiptV1, load_context, receipt_header


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--runtime-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    context = load_context(args.context)
    expected = context.payload
    if args.binary.is_symlink() or not args.binary.is_file():
        raise ValueError("Qualified Codex binary must be a regular non-symlink file")
    runtime = json.loads(args.runtime_build.read_bytes())
    if not isinstance(runtime, dict):
        raise ValueError("Runtime build evidence must be an object")
    source_artifact = runtime.get("source_artifact")
    if not isinstance(source_artifact, dict):
        raise ValueError("Runtime build lacks retained Build-020 artifact provenance")
    binary_sha256 = digest(args.binary.read_bytes())
    version = runtime.get("codex_version")
    value = {
        **receipt_header(context, "codex_executable"),
        "kind": "retained_build020_executable",
        "image_id": runtime.get("image_id"),
        "source_commit": runtime.get("codex_source_commit"),
        "source_archive_sha256": runtime.get("codex_source_archive_sha256"),
        "executable_sha256": binary_sha256,
        "executable_version": version,
        "candidate_b_base_patch_sha256": runtime.get("candidate_b_base_patch_sha256"),
        "host_integration_patch_sha256": runtime.get("host_integration_patch_sha256"),
        "combined_patchset_sha256": runtime.get("combined_patchset_sha256"),
        "source_artifact": source_artifact,
        "real_codex_task_executions": 0,
        "model_requests": 0,
        "provider_sends": 0,
        "qualification_passed": True,
    }
    if (
        binary_sha256 != expected.codex.executable_sha256
        or version != expected.codex.executable_version
        or runtime.get("image_id") != expected.runtime_expected.image_id
    ):
        raise ValueError("Codex executable differs from qualification context")
    receipt = CodexExecutableReceiptV1.model_validate(value)
    raw = canonical(receipt.model_dump(mode="json"))
    write_new(args.output, raw)
    print(raw.decode())


if __name__ == "__main__":
    main()
