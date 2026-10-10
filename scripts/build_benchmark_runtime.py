"""Build the executor image from the retained, reviewed Build-020 binary."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

from devhub.benchmark import canonical, digest, write_new
from devhub.experiment_launch import DOCKER, safe_artifacts
from devhub.qualification import CodexBuildArtifactObservationV1


def load_qualified_binary(
    binary_path: Path, evidence_path: Path, lock: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    """Re-read the locator and bind it to repository-owned Build-020 identities."""

    if binary_path.is_symlink() or not binary_path.is_file():
        raise ValueError("Qualified Codex binary must be a regular non-symlink file")
    if evidence_path.is_symlink() or not evidence_path.is_file():
        raise ValueError("Build-020 evidence must be a regular non-symlink file")
    qualified = lock.get("qualified_codex_build")
    if not isinstance(qualified, dict):
        raise ValueError("Qualified Codex build identity is missing from runtime lock")
    qualified = cast(dict[str, Any], qualified)
    if qualified.get("binary_relative_path") != "binary/codex":
        raise ValueError("Qualified Codex binary locator differs from reviewed artifact layout")
    CodexBuildArtifactObservationV1.model_validate(
        {
            "workflow_run_id": qualified.get("workflow_run_id"),
            "artifact_id": qualified.get("artifact_id"),
            "artifact_name": qualified.get("artifact_name"),
            "artifact_zip_sha256": qualified.get("artifact_zip_sha256"),
        }
    )
    evidence = json.loads(evidence_path.read_bytes())
    binary = binary_path.read_bytes()
    expected = {
        "source_commit": evidence.get("source_commit"),
        "source_archive_sha256": evidence.get("source_archive_sha256"),
        "candidate_b_base_patch_sha256": evidence.get("candidate_b_base_patch_sha256"),
        "host_integration_patch_sha256": evidence.get("host_integration_patch_sha256"),
        "combined_patchset_sha256": evidence.get("combined_production_patchset_sha256"),
    }
    if any(qualified.get(key) != value for key, value in expected.items()):
        raise ValueError("Build-020 evidence differs from reviewed runtime lock")
    executable = evidence.get("executable")
    if not isinstance(executable, dict) or qualified.get("binary_sha256") != executable.get(
        "sha256"
    ):
        raise ValueError("Build-020 executable evidence differs from reviewed runtime lock")
    if hashlib.sha256(binary).hexdigest() != qualified.get("binary_sha256"):
        raise ValueError("Retained Build-020 binary integrity failure")
    if evidence.get("build_id") != "build-020" or evidence.get("compilation") != "PASS":
        raise ValueError("Build-020 evidence is not a successful retained compilation")
    if evidence.get("process_proof") != "PASS":
        raise ValueError("Build-020 process proof is not accepted")
    return binary, qualified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--codex-binary", type=Path, required=True)
    parser.add_argument("--build-evidence", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Exclusive output required")
    repo = Path(__file__).resolve().parents[1]
    lock_raw = (repo / "benchmarks/runtime-lock.json").read_bytes()
    lock = json.loads(lock_raw)
    binary, qualified = load_qualified_binary(args.codex_binary, args.build_evidence, lock)
    with tempfile.TemporaryDirectory(prefix="devhub-image-") as temporary:
        root = Path(temporary)
        (root / "codex").write_bytes(binary)
        (root / "codex").chmod(0o755)
        # The context consists of exactly these two files. No repo COPY or auth ARG.
        recipe = (
            f"FROM {lock['base_image']} AS base\n"
            "RUN rm -rf /usr/local/lib/python3.12/site-packages/* "
            "/usr/local/lib/python3.12/ensurepip /root/.cache\n"
            "FROM scratch\nCOPY --from=base / /\n"
            "COPY --chmod=755 codex /usr/local/bin/codex\n"
            'ENV PATH="/usr/local/bin:/usr/bin:/bin" LANG="C.UTF-8" HOME="/home/runner"\n'
            "USER 1000:1000\n"
        )
        (root / "Dockerfile").write_text(recipe, encoding="utf-8")
        image = (
            subprocess.check_output(
                [*DOCKER, "build", "--platform=linux/amd64", "--network=none", "-q", str(root)],
                timeout=600,
            )
            .decode()
            .strip()
        )
        version = (
            subprocess.check_output(
                [
                    *DOCKER,
                    "run",
                    "--rm",
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges",
                    "--entrypoint=codex",
                    image,
                    "--version",
                ],
                timeout=30,
            )
            .decode()
            .strip()
        )
        if version != lock["codex_version"]:
            raise ValueError("Exact CLI unavailable: STOP, protocol review required")
        evidence = canonical(
            {
                "schema_version": 1,
                "kind": "runtime_image_build",
                "image_id": image,
                "runtime_lock_sha256": digest(lock_raw),
                "dockerfile_sha256": digest(recipe.encode()),
                "codex_source_archive_sha256": qualified["source_archive_sha256"],
                "codex_binary_sha256": digest(binary),
                "codex_version": version,
                "codex_source_commit": qualified["source_commit"],
                "candidate_b_base_patch_sha256": qualified["candidate_b_base_patch_sha256"],
                "host_integration_patch_sha256": qualified["host_integration_patch_sha256"],
                "combined_patchset_sha256": qualified["combined_patchset_sha256"],
                "source_artifact": {
                    "workflow_run_id": qualified["workflow_run_id"],
                    "artifact_id": qualified["artifact_id"],
                    "artifact_name": qualified["artifact_name"],
                    "artifact_zip_sha256": qualified["artifact_zip_sha256"],
                },
                "base_image": lock["base_image"],
                "real_codex_executions": 0,
                "provider_sends": 0,
            }
        )
        safe_artifacts((evidence,))
        write_new(args.output, evidence)
        print(evidence.decode())


if __name__ == "__main__":
    main()
