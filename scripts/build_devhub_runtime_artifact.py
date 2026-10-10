"""Build and inspect an immutable DevFabric wheel/runtime; never invokes inference."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from devhub.benchmark import canonical, write_new
from devhub.runtime_artifact import (
    PythonRuntimeArtifactEvidenceV1,
    file_sha256,
    inspect_runtime_environment,
)


def _run(argv: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(argv, cwd=cwd, check=True, timeout=300)


def _output(argv: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(argv, cwd=cwd, timeout=60).decode().strip()


def _runtime_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def reviewed_commit(repo: Path, expected_commit: str) -> str:
    if re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None:
        raise ValueError("Expected implementation commit must be a lowercase 40-hex SHA")
    if _output(["git", "status", "--porcelain=v1"], cwd=repo):
        raise ValueError("Runtime artifact must be built from a clean repository")
    commit = _output(["git", "rev-parse", "HEAD"], cwd=repo)
    if commit != expected_commit:
        raise ValueError("Runtime artifact checkout differs from expected implementation commit")
    return commit


def build(
    repo: Path,
    output: Path,
    runtime_root: Path,
    expected_commit: str,
) -> PythonRuntimeArtifactEvidenceV1:
    repo = repo.resolve(strict=True)
    commit = reviewed_commit(repo, expected_commit)
    uv = shutil.which("uv")
    if uv is None:
        raise ValueError("Reviewed uv executable required")
    uv_path = Path(uv).resolve(strict=True)
    if output.exists() or runtime_root.exists():
        raise ValueError("Artifact output and runtime environment must be new")
    output.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="devfabric-wheel-") as temporary:
        scratch = Path(temporary)
        archive = scratch / "source.tar"
        source = scratch / "source"
        source.mkdir()
        _run(["git", "archive", "--format=tar", "-o", str(archive), commit], cwd=repo)
        with tarfile.open(archive) as stream:
            stream.extractall(source, filter="data")
        _run([str(uv_path), "build", "--wheel", "--out-dir", str(output)], cwd=source)
        wheels = tuple(output.glob("*.whl"))
        if len(wheels) != 1:
            raise ValueError("Build must produce exactly one wheel")
        wheel = wheels[0]
        reviewed_lock = output / "uv.lock"
        shutil.copyfile(source / "uv.lock", reviewed_lock)
        requirements = scratch / "runtime-requirements.txt"
        _run(
            [
                str(uv_path),
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--no-header",
                "--no-annotate",
                "--output-file",
                str(requirements),
            ],
            cwd=source,
        )
        _run(
            [
                str(uv_path),
                "venv",
                "--no-project",
                "--python",
                sys.executable,
                str(runtime_root),
            ]
        )
        interpreter = _runtime_python(runtime_root)
        _run(
            [
                str(uv_path),
                "pip",
                "install",
                "--python",
                str(interpreter),
                "--require-hashes",
                "-r",
                str(requirements),
            ]
        )
        _run(
            [
                str(uv_path),
                "pip",
                "install",
                "--python",
                str(interpreter),
                "--no-deps",
                str(wheel),
            ]
        )
        _run([str(uv_path), "pip", "check", "--python", str(interpreter)])
        environment = inspect_runtime_environment(interpreter, wheel, reviewed_lock, commit)
        evidence = PythonRuntimeArtifactEvidenceV1(
            implementation_commit=commit,
            source_archive_sha256=file_sha256(archive),
            wheel_filename=wheel.name,
            wheel_sha256=file_sha256(wheel),
            package_version=environment.payload.devhub_distribution_version,
            dependency_lock_sha256=file_sha256(reviewed_lock),
            build_python_implementation=platform.python_implementation(),
            build_python_version=platform.python_version(),
            build_python_executable_sha256=file_sha256(Path(sys.executable)),
            build_tool="uv " + _output([str(uv_path), "--version"]),
            build_tool_sha256=file_sha256(uv_path),
            runtime_environment=environment,
        )
        write_new(output / "runtime-artifact.json", canonical(evidence.model_dump(mode="json")))
        return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    evidence = build(
        Path(__file__).resolve().parents[1],
        args.output,
        args.runtime_root,
        args.expected_commit,
    )
    print(json.dumps(evidence.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
