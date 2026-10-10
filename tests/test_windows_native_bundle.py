from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from devhub.native_bundle import installed_wheel_plan

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "build_windows_native_bundle", SCRIPTS / "build_windows_native_bundle.py"
)
assert SPEC is not None and SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUNDLE
SPEC.loader.exec_module(BUNDLE)


def _write_pip_authority(repo: Path, *, version: str = BUNDLE.PIP_BUILD_VERSION) -> None:
    (repo / "pyproject.toml").write_text(
        '[dependency-groups]\nwindows-bundle-build = ["pip==26.2.1"]\n',
        encoding="utf-8",
    )
    (repo / "uv.lock").write_text(
        f'[[package]]\nname = "pip"\nversion = "{version}"\n', encoding="utf-8"
    )


def _pip_observation(tmp_path: Path, interpreter: Path, **overrides: str) -> str:
    prefix = tmp_path / "venv"
    origin = prefix / "Lib/site-packages/pip/__init__.py"
    origin.parent.mkdir(parents=True, exist_ok=True)
    origin.write_bytes(b"")
    base = tmp_path / "base"
    base.mkdir(exist_ok=True)
    values = {
        "version": BUNDLE.PIP_BUILD_VERSION,
        "origin": str(origin),
        "executable": str(interpreter),
        "prefix": str(prefix),
        "base_prefix": str(base),
    }
    values.update(overrides)
    return json.dumps(values)


def _write_codex_artifact(root: Path) -> tuple[Path, dict[str, object]]:
    binary = root / "binary/codex.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"codex")
    binary_sha = hashlib.sha256(b"codex").hexdigest()
    counters = {
        "model_requests": 0,
        "provider_sends": 0,
        "mcp_tool_executions": 0,
        "real_task_executions": 0,
    }
    manifest_sha = "e" * 64
    arm_a_observer = {
        "effective_tool_mode": "CodeModeOnly",
        "visible_model_tools": [],
        "nested_code_mode_map": [],
        "hosted_tools": [],
        "dynamic_tool_count": 0,
        "allowed_tools": [],
        "allowed_tools_ceiling_present": True,
        "approved_delegate_policy_present": False,
        "approved_identity": None,
        "host_manifest_sha256": manifest_sha,
        "expected_schema_sha256": None,
        "model_requests": 0,
        "provider_sends": 0,
    }
    arm_b_observer = {
        **arm_a_observer,
        "visible_model_tools": [BUNDLE.DELEGATE],
        "allowed_tools": [BUNDLE.DELEGATE],
        "approved_delegate_policy_present": True,
        "approved_identity": {
            "server_key": "devhub_delegate",
            "raw_tool": "devhub_delegate",
            "canonical_namespace": "mcp__devhub_delegate",
            "canonical_function": "devhub_delegate",
            "schema_sha256": BUNDLE.SCHEMA_SHA256,
        },
        "expected_schema_sha256": BUNDLE.SCHEMA_SHA256,
    }
    negative_names = {
        "wrong_schema_hash",
        "wrong_config_hash",
        "wrong_namespace",
        "arm_a_with_mcp",
        "arm_b_without_mcp",
        "resume_with_host_authority",
        "fork_with_host_authority",
        "task_lookalike_cannot_authorize",
    }
    proof = {
        "scope": "native Windows Codex host construction and finalized pre-sampling visibility",
        "windows_executor_isolation_qualified": False,
        "arms": {
            "A": {"passed": True, "observer": arm_a_observer},
            "B": {
                "passed": True,
                "observer": arm_b_observer,
                "mcp_child_exited": True,
            },
        },
        "default": {
            "passed": True,
            "observer": {
                "allowed_tools_ceiling_present": False,
                "allowed_tools": [],
                "approved_delegate_policy_present": False,
                "approved_identity": None,
                "host_manifest_sha256": None,
                "expected_schema_sha256": None,
                "visible_model_tools": [],
                "nested_code_mode_map": [],
                "model_requests": 0,
                "provider_sends": 0,
            },
        },
        "same_binary": {
            "binary_sha256": binary_sha,
            "b_minus_a": [BUNDLE.DELEGATE],
            "a_minus_b": [],
            "passed": True,
        },
        "final_binary_sha256": binary_sha,
        "final_binary_integrity": "PASS",
        "mcp_catalog_receipt": {
            "tool_call_count": 0,
            "records": [
                {
                    "event": "tools_list",
                    "schema_sha256": BUNDLE.SCHEMA_SHA256,
                    "provider_send": False,
                }
            ],
        },
        "negatives": {name: {"passed": True} for name in negative_names},
        **counters,
    }
    receipt: dict[str, object] = {
        "schema_version": 1,
        "build_id": "windows-build-001",
        "status": "PASS",
        "phase": "complete",
        "compilation": "PASS",
        "rust_compilation_started": True,
        "qualification": "WINDOWS_PRODUCTION_HOST_QUALIFIED_PRE_SAMPLING",
        "expected_implementation_commit": "d" * 40,
        "devfabric_implementation_commit": "d" * 40,
        "target": "x86_64-pc-windows-msvc",
        "source_commit": BUNDLE.CODEX_SOURCE_COMMIT,
        "source_archive_sha256": BUNDLE.CODEX_SOURCE_ARCHIVE_SHA256,
        "candidate_b_base_patch_sha256": BUNDLE.CANDIDATE_SHA256,
        "host_integration_patch_sha256": BUNDLE.HOST_SHA256,
        "combined_patchset_sha256": BUNDLE.COMBINED_SHA256,
        "canonical_schema_sha256": BUNDLE.SCHEMA_SHA256,
        "formatting": "PASS",
        "failure": None,
        "source_preparation": {
            "candidate_patch_applied": True,
            "candidate_patch_cwd": "pinned_source_parent",
            "host_patch_applied": True,
            "host_patch_cwd": "codex-rs",
            "lock_strategy": "complete_patched_manifest_bound_derived_lock",
            "original_cargo_lock_sha256": BUNDLE.ORIGINAL_CARGO_LOCK_SHA256,
            "proof_cargo_lock_sha256": BUNDLE.PROOF_CARGO_LOCK_SHA256,
        },
        "toolchain": {
            "rustc_command": ["rustup", "run", "1.95.0", "rustc", "-vV"],
            "rustc": "rustc 1.95.0\nrelease: 1.95.0\nhost: x86_64-pc-windows-msvc\n",
            "cargo_command": [
                "rustup",
                "run",
                "1.95.0",
                "cargo",
                "--version",
                "--verbose",
            ],
            "cargo": "cargo 1.95.0 (fixture)\nrelease: 1.95.0\n",
            "platform": "Windows-fixture",
            "target": "x86_64-pc-windows-msvc",
        },
        "locked_resolution": {
            "metadata": {
                "command": [
                    "cargo",
                    "+1.95.0",
                    "metadata",
                    "--locked",
                    "--format-version",
                    "1",
                    "--filter-platform",
                    "x86_64-pc-windows-msvc",
                ],
                "exit_code": 0,
                "lock_sha256_before": BUNDLE.PROOF_CARGO_LOCK_SHA256,
                "lock_sha256_after": BUNDLE.PROOF_CARGO_LOCK_SHA256,
                "lock_unchanged": True,
                "stdout_sha256": "1" * 64,
                "stderr_sha256": "2" * 64,
            },
            "fetch": {
                "command": [
                    "cargo",
                    "+1.95.0",
                    "fetch",
                    "--locked",
                    "--target",
                    "x86_64-pc-windows-msvc",
                ],
                "exit_code": 0,
                "lock_sha256_before": BUNDLE.PROOF_CARGO_LOCK_SHA256,
                "lock_sha256_after": BUNDLE.PROOF_CARGO_LOCK_SHA256,
                "lock_unchanged": True,
                "stdout_sha256": "3" * 64,
                "stderr_sha256": "4" * 64,
            },
        },
        "build_command": [
            "cargo",
            "+1.95.0",
            "build",
            "--release",
            "--locked",
            "-p",
            "codex-cli",
            "--bin",
            "codex",
        ],
        "windows_host_authority": {"manifest_sha256": manifest_sha},
        "executable": {
            "relative_path": "binary/codex.exe",
            "sha256": binary_sha,
            "version_stdout": "codex-cli 0.155.0-alpha.9.2",
        },
        "process_proof": proof,
        **counters,
    }
    (root / "windows-build-result.json").write_text(json.dumps(receipt), encoding="utf-8")
    return binary, receipt


def _write_demo_wheel(path: Path, *, unsafe_member: str | None = None) -> dict[str, bytes]:
    files = {
        "demo.py": b"value = 1\n",
        "ambient.pth": b"outside\n",
        "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n",
        "demo-1.0.dist-info/RECORD": b"",
    }
    if unsafe_member is not None:
        files[unsafe_member] = b"escape"
    with zipfile.ZipFile(path, "w") as stream:
        for name, raw in files.items():
            stream.writestr(name, raw)
    return files


def test_validate_windows_codex_artifact_binds_exact_proof(tmp_path: Path) -> None:
    binary, _ = _write_codex_artifact(tmp_path)

    authority = BUNDLE.validate_windows_codex_artifact(
        tmp_path, BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID
    )

    assert authority.accepted_run_id == BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID
    assert authority.executable_sha256 == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert authority.qualification == "WINDOWS_PRODUCTION_HOST_QUALIFIED_PRE_SAMPLING"


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw.update({"provider_sends": 1}), "nonzero provider_sends"),
        (
            lambda raw: raw["process_proof"]["same_binary"].update({"a_minus_b": ["x"]}),
            "same-binary surface",
        ),
        (
            lambda raw: raw["process_proof"]["negatives"]["wrong_schema_hash"].update(
                {"passed": False}
            ),
            "security-negative",
        ),
        (lambda raw: raw.update({"build_id": "windows-build-002"}), "build_id"),
        (
            lambda raw: raw["source_preparation"].update({"host_patch_applied": False}),
            "source preparation",
        ),
        (
            lambda raw: raw["toolchain"].update({"target": "x86_64-unknown-linux-gnu"}),
            "toolchain identity",
        ),
        (
            lambda raw: raw["locked_resolution"]["fetch"].update({"lock_unchanged": False}),
            "locked fetch authority",
        ),
    ],
)
def test_validate_windows_codex_artifact_rejects_weakened_receipt(
    tmp_path: Path, mutation, message: str
) -> None:
    _, raw = _write_codex_artifact(tmp_path)
    mutation(raw)
    (tmp_path / "windows-build-result.json").write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        BUNDLE.validate_windows_codex_artifact(tmp_path, BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID)


def test_validate_windows_codex_artifact_rejects_unreviewed_run_locator(tmp_path: Path) -> None:
    _write_codex_artifact(tmp_path)

    with pytest.raises(ValueError, match="workflow run"):
        BUNDLE.validate_windows_codex_artifact(tmp_path, BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID + 1)


def test_embedded_archive_member_identity_and_safe_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "python.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("python.exe", b"python")
        stream.writestr("python312._pth", b"old")

    first = BUNDLE.archive_members_sha256(archive)
    second = BUNDLE.extract_embedded_python(archive, tmp_path / "runtime")

    assert first == second
    assert (tmp_path / "runtime/python312._pth").read_text(encoding="ascii") == BUNDLE.PTH

    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as stream:
        stream.writestr("../escape", b"x")
    with pytest.raises(ValueError, match="unsafe member path"):
        BUNDLE.archive_members_sha256(unsafe)

    duplicate = tmp_path / "duplicate.zip"
    with pytest.warns(UserWarning), zipfile.ZipFile(duplicate, "w") as stream:
        stream.writestr("python.exe", b"first")
        stream.writestr("python.exe", b"second")
    with pytest.raises(ValueError, match="duplicate member path"):
        BUNDLE.archive_members_sha256(duplicate)


def test_embedded_archive_extraction_uses_one_immutable_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    archive = tmp_path / "python.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("python.exe", b"reviewed")
        stream.writestr("python312._pth", b"old")
    original = Path.read_bytes
    reads = 0

    def counted(path: Path) -> bytes:
        nonlocal reads
        if path == archive:
            reads += 1
            if reads > 1:
                return b"substituted"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", counted)
    BUNDLE.extract_embedded_python(archive, tmp_path / "runtime")

    assert reads == 1
    assert (tmp_path / "runtime/python.exe").read_bytes() == b"reviewed"


def test_dependency_wheels_must_match_uv_lock(tmp_path: Path) -> None:
    wheelhouse = tmp_path / "wheels"
    wheelhouse.mkdir()
    wheel = wheelhouse / "mcp-2.2.0-py3-none-any.whl"
    wheel.write_bytes(b"wheel")
    wheel_sha = hashlib.sha256(b"wheel").hexdigest()
    lock = tmp_path / "uv.lock"
    lock.write_text(
        f"""
version = 1
[[package]]
name = "mcp"
version = "2.2.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
  {{ url = "https://example.invalid/mcp-2.2.0-py3-none-any.whl", hash = "sha256:{wheel_sha}" }},
]
""",
        encoding="utf-8",
    )

    reviewed = BUNDLE.review_dependency_wheels(wheelhouse, lock)
    assert [(item.name, item.version, item.sha256) for item in reviewed] == [
        ("mcp", "2.2.0", wheel_sha)
    ]

    wheel.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="absent or mismatched"):
        BUNDLE.review_dependency_wheels(wheelhouse, lock)


def test_sanitize_runtime_removes_ambient_metadata_and_rewrites_record(tmp_path: Path) -> None:
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    files = _write_demo_wheel(wheel)
    site = tmp_path / "site-packages"
    site.mkdir()
    package = site / "demo.py"
    package.write_bytes(files["demo.py"])
    info = site / "demo-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_bytes(files["demo-1.0.dist-info/METADATA"])
    (info / "direct_url.json").write_text('{"url":"file:///staging"}', encoding="utf-8")
    (site / "ambient.pth").write_bytes(files["ambient.pth"])
    generated = site / "bin/generated.exe"
    generated.parent.mkdir()
    generated.write_bytes(b"entrypoint")
    record = info / "RECORD"
    with record.open("w", newline="", encoding="utf-8") as stream:
        csv.writer(stream).writerows(
            [
                ["demo.py", "sha256=bad", "1"],
                ["demo-1.0.dist-info/direct_url.json", "sha256=bad", "1"],
                ["demo-1.0.dist-info/RECORD", "", ""],
            ]
        )

    BUNDLE.sanitize_installed_wheel_tree(site, (wheel,))

    assert not (info / "direct_url.json").exists()
    assert not (tmp_path / "ambient.pth").exists()
    assert not generated.exists()
    rows = list(csv.reader(record.read_text(encoding="utf-8").splitlines()))
    assert [row[0] for row in rows] == [
        "demo-1.0.dist-info/METADATA",
        "demo.py",
        "demo-1.0.dist-info/RECORD",
    ]
    demo_row = next(row for row in rows if row[0] == "demo.py")
    assert demo_row[1].startswith("sha256=") and demo_row[2] == str(package.stat().st_size)


@pytest.mark.parametrize("mutation", ["missing", "unowned", "tampered"])
def test_wheel_install_membership_fails_closed(tmp_path: Path, mutation: str) -> None:
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    files = _write_demo_wheel(wheel)
    site = tmp_path / "site-packages"
    for name, raw in files.items():
        target = site.joinpath(*Path(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    if mutation == "missing":
        (site / "demo.py").unlink()
    elif mutation == "unowned":
        (site / "unowned.py").write_bytes(b"unowned")
    else:
        (site / "demo.py").write_bytes(b"tampered")

    with pytest.raises(ValueError, match="missing|unowned|differs"):
        BUNDLE.sanitize_installed_wheel_tree(site, (wheel,))


def test_wheel_install_plan_rejects_path_escape(tmp_path: Path) -> None:
    wheel = tmp_path / "demo-1.0-py3-none-any.whl"
    _write_demo_wheel(wheel, unsafe_member="../escape.py")

    with pytest.raises(ValueError, match="unsafe member path"):
        installed_wheel_plan((wheel,))


def test_build_locator_scan_detects_value_split_across_chunks(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    locator = tmp_path / "temporary-source"
    raw = str(locator.resolve()).encode()
    (bundle / "metadata.bin").write_bytes(b"x" * (1024 * 1024 - len(raw) // 2) + raw)

    with pytest.raises(ValueError, match="build-time locator"):
        BUNDLE.reject_build_locators(bundle, (locator,))


def test_pip_build_tool_requires_locked_isolated_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_pip_authority(tmp_path)
    interpreter = tmp_path / "venv/python.exe"
    interpreter.parent.mkdir()
    interpreter.write_bytes(b"")
    monkeypatch.setattr(BUNDLE, "_output", lambda _argv: _pip_observation(tmp_path, interpreter))

    assert BUNDLE._verified_pip_interpreter(tmp_path, interpreter) == interpreter.resolve()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "unavailable"),
        ("wrong_version", "version differs"),
        ("ambient", "dedicated virtual environment"),
        ("outside", "outside the verified environment"),
    ],
)
def test_pip_build_tool_rejects_missing_wrong_or_ambient_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    message: str,
) -> None:
    _write_pip_authority(tmp_path)
    interpreter = tmp_path / "venv/python.exe"
    interpreter.parent.mkdir()
    interpreter.write_bytes(b"")
    observation = json.loads(_pip_observation(tmp_path, interpreter))
    if mutation == "missing":
        monkeypatch.setattr(
            BUNDLE,
            "_output",
            lambda _argv: (_ for _ in ()).throw(
                subprocess.CalledProcessError(1, [str(interpreter)])
            ),
        )
    else:
        if mutation == "wrong_version":
            observation["version"] = "0.0"
        elif mutation == "ambient":
            observation["base_prefix"] = observation["prefix"]
        else:
            outside = tmp_path / "outside/pip/__init__.py"
            outside.parent.mkdir(parents=True)
            outside.write_bytes(b"")
            observation["origin"] = str(outside)
        monkeypatch.setattr(BUNDLE, "_output", lambda _argv: json.dumps(observation))

    with pytest.raises(ValueError, match=message):
        BUNDLE._verified_pip_interpreter(tmp_path, interpreter)


def test_pip_download_uses_verified_interpreter_in_isolated_mode(tmp_path: Path) -> None:
    interpreter = tmp_path / "venv/python.exe"
    command = BUNDLE._pip_download_command(
        interpreter, tmp_path / "wheelhouse", tmp_path / "requirements.txt"
    )

    assert command[:5] == [str(interpreter), "-I", "-m", "pip", "download"]
    assert "--require-hashes" in command


def test_pip_authority_failure_precedes_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "parent/release"
    called = False

    def assemble(*_args):
        nonlocal called
        called = True
        return object()

    monkeypatch.setattr(BUNDLE, "_assemble_bundle", assemble)
    monkeypatch.setattr(
        BUNDLE,
        "_verified_pip_interpreter",
        lambda *_args: (_ for _ in ()).throw(ValueError("pip authority failed")),
    )

    with pytest.raises(ValueError, match="pip authority failed"):
        BUNDLE.build(
            tmp_path,
            output,
            "d" * 40,
            tmp_path / "python.zip",
            tmp_path / "python.spdx.json",
            tmp_path / "codex",
            BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID,
        )

    assert not called
    assert not output.parent.exists()


def test_publication_is_one_atomic_release_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "release"
    marker = object()

    def assemble(_repo, bundle, manifest, *_args):
        bundle.mkdir()
        (bundle / "complete.txt").write_text("complete", encoding="utf-8")
        manifest.write_text("manifest", encoding="utf-8")
        return marker

    monkeypatch.setattr(BUNDLE, "_assemble_bundle", assemble)
    monkeypatch.setattr(BUNDLE, "_verified_pip_interpreter", lambda *_args: tmp_path)
    result = BUNDLE.build(
        tmp_path,
        output,
        "d" * 40,
        tmp_path / "python.zip",
        tmp_path / "python.spdx.json",
        tmp_path / "codex",
        BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID,
    )

    assert result is marker
    assert (output / "bundle/complete.txt").read_text(encoding="utf-8") == "complete"
    assert (output / "native-bundle.json").read_text(encoding="utf-8") == "manifest"


def test_failed_assembly_never_publishes_partial_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "release"

    def assemble(_repo, bundle, _manifest, *_args):
        bundle.mkdir()
        (bundle / "partial.txt").write_text("partial", encoding="utf-8")
        raise ValueError("qualification failed")

    monkeypatch.setattr(BUNDLE, "_assemble_bundle", assemble)
    monkeypatch.setattr(BUNDLE, "_verified_pip_interpreter", lambda *_args: tmp_path)
    with pytest.raises(ValueError, match="qualification failed"):
        BUNDLE.build(
            tmp_path,
            output,
            "d" * 40,
            tmp_path / "python.zip",
            tmp_path / "python.spdx.json",
            tmp_path / "codex",
            BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID,
        )

    assert not output.exists()


def test_failed_atomic_replace_never_exposes_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "release"

    def assemble(_repo, bundle, manifest, *_args):
        bundle.mkdir()
        manifest.write_text("manifest", encoding="utf-8")
        return object()

    monkeypatch.setattr(BUNDLE, "_assemble_bundle", assemble)
    monkeypatch.setattr(BUNDLE, "_verified_pip_interpreter", lambda *_args: tmp_path)
    monkeypatch.setattr(BUNDLE.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("x")))

    with pytest.raises(OSError, match="x"):
        BUNDLE.build(
            tmp_path,
            output,
            "d" * 40,
            tmp_path / "python.zip",
            tmp_path / "python.spdx.json",
            tmp_path / "codex",
            BUNDLE.WINDOWS_BUILD_ARTIFACT_RUN_ID,
        )
    assert not output.exists()
