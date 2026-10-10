import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "build_windows_native_codex", SCRIPTS / "build_windows_native_codex.py"
)
assert SPEC is not None and SPEC.loader is not None
WINDOWS_BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WINDOWS_BUILD)
sys.path.pop(0)


def test_windows_build_reuses_exact_reviewed_identities() -> None:
    retained = WINDOWS_BUILD.retained
    repo = Path(__file__).resolve().parents[1]
    candidate = (repo / "patches/stage3g-approved-call/candidate.patch").read_bytes()
    host = (repo / "patches/stage3g-approved-call/host-integration.patch").read_bytes()

    assert WINDOWS_BUILD.BUILD_ID == "windows-build-001"
    assert WINDOWS_BUILD.TARGET == "x86_64-pc-windows-msvc"
    assert hashlib.sha256(candidate).hexdigest() == retained.CANDIDATE_SHA256
    assert hashlib.sha256(host).hexdigest() == retained.HOST_SHA256
    assert hashlib.sha256(candidate + host).hexdigest() == retained.COMBINED_SHA256


def test_windows_build_reuses_retained_source_preparation(tmp_path, monkeypatch) -> None:
    retained = WINDOWS_BUILD.retained
    checkout = tmp_path / "pinned-source"
    root = checkout / "codex-rs"
    root.mkdir(parents=True)
    original = b"original lock\n"
    derived = b"complete production lock\n"
    (root / "Cargo.lock").write_bytes(original)
    candidate = b"""diff --git a/codex-rs/candidate.txt b/codex-rs/candidate.txt
new file mode 100644
--- /dev/null
+++ b/codex-rs/candidate.txt
@@ -0,0 +1 @@
+candidate
"""
    host = b"""diff --git a/host.txt b/host.txt
new file mode 100644
--- /dev/null
+++ b/host.txt
@@ -0,0 +1 @@
+host
"""
    monkeypatch.setattr(retained, "ORIGINAL", hashlib.sha256(original).hexdigest())
    monkeypatch.setattr(
        retained, "PRODUCTION_HOST_LOCK_SHA256", hashlib.sha256(derived).hexdigest()
    )
    monkeypatch.setattr(
        retained,
        "derive_production_host_lock",
        lambda candidate_root: (derived, [{"source": str(candidate_root)}]),
    )

    result = retained.prepare_build_source(
        root,
        candidate_patch=candidate,
        host_patch=host,
        build_id="windows-build-001",
    )

    assert (root / "candidate.txt").read_text(encoding="utf-8") == "candidate\n"
    assert (root / "host.txt").read_text(encoding="utf-8") == "host\n"
    assert result["lock_strategy"] == "complete_patched_manifest_bound_derived_lock"
    assert result["proof_cargo_lock_sha256"] == hashlib.sha256(derived).hexdigest()


def test_windows_host_manifest_binds_exact_resolved_mcp_config(tmp_path) -> None:
    source = Path(__file__).resolve().parents[1] / "benchmarks/stage3g-host-manifest-v2.json"
    output = tmp_path / "host.json"
    config = WINDOWS_BUILD.windows_mcp_config(
        Path(r"C:\Program Files\DevFabric\runtime\python.exe"),
        Path(r"C:\Program Files\DevFabric\runtime\catalog.py"),
    )
    config_hash = WINDOWS_BUILD.canonical_sha256(config)
    manifest_hash = WINDOWS_BUILD.windows_host_manifest(source, output, config_hash)
    value = json.loads(output.read_bytes())

    assert manifest_hash == hashlib.sha256(output.read_bytes()).hexdigest()
    assert (
        value["arms"]["arm_b"]["approved_delegate"]["expected_mcp_server_config_sha256"]
        == config_hash
    )
    assert config["env_vars"] == [
        "DEVHUB_BUILD009_MCP_RECEIPT",
        "DEVHUB_BUILD009_SCHEMA",
        "DEVHUB_BUILD009_MCP_PID",
    ]


def test_windows_runner_preserves_complete_authority_asset_set(tmp_path) -> None:
    repo = Path(__file__).resolve().parents[1]
    schema = repo / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
    shipping_manifest = repo / "benchmarks/stage3g-host-manifest-v2.json"
    assets, manifest, config, manifest_hash, hashes = WINDOWS_BUILD.preserve_windows_runner_assets(
        repo,
        tmp_path,
        schema=schema,
        shipping_manifest=shipping_manifest,
        python=Path(r"C:\Program Files\DevFabric\runtime\python.exe"),
    )

    assert set(hashes) == WINDOWS_BUILD.WINDOWS_RUNNER_ASSETS
    assert manifest == assets / "windows-host-manifest-v2.json"
    assert manifest_hash == WINDOWS_BUILD.sha256_file(manifest)
    assert config["args"] == [str((assets / "stage3g_build009_mcp.py").resolve()), "mcp"]
    WINDOWS_BUILD.verify_runner_assets(assets, hashes)


def test_windows_arm_commands_keep_default_a_b_authority_distinct(tmp_path) -> None:
    config = WINDOWS_BUILD.windows_mcp_config(
        Path(r"C:\runtime\python.exe"), Path(r"C:\runtime\catalog.py")
    )
    arm_a = WINDOWS_BUILD._host_exec(
        tmp_path, tmp_path / "manifest.json", tmp_path / "a.json", "a", config
    )
    arm_b = WINDOWS_BUILD._host_exec(
        tmp_path, tmp_path / "manifest.json", tmp_path / "b.json", "b", config
    )
    default = WINDOWS_BUILD.retained._default_exec(tmp_path, tmp_path / "default.json")

    assert not any("mcp_servers.devhub_delegate.command" in value for value in arm_a)
    assert sum("mcp_servers.devhub_delegate.command" in value for value in arm_b) == 1
    assert "--devhub-stage3g-host-manifest" not in default
    assert "--devhub-stage3g-arm" not in default


def test_windows_mcp_config_hash_changes_with_runtime_identity() -> None:
    first = WINDOWS_BUILD.windows_mcp_config(
        Path(r"C:\runtime-a\python.exe"), Path(r"C:\runtime-a\catalog.py")
    )
    second = WINDOWS_BUILD.windows_mcp_config(
        Path(r"C:\runtime-b\python.exe"), Path(r"C:\runtime-b\catalog.py")
    )

    assert WINDOWS_BUILD.canonical_sha256(first) != WINDOWS_BUILD.canonical_sha256(second)


def test_pre_sampling_proof_cannot_accept_plain_eof() -> None:
    result = {
        "timed_out": False,
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "stdin_closed": True,
    }

    assert not WINDOWS_BUILD.retained._proof_stopped(result)


def test_implementation_head_rejects_synthetic_merge_sha(monkeypatch, tmp_path) -> None:
    expected = "a" * 40

    def git_output(command, **_kwargs):
        if command[1:] == ["rev-parse", "HEAD"]:
            return "b" * 40 + "\n"
        raise AssertionError(command)

    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "check_output", git_output)

    with pytest.raises(ValueError, match="does not match workflow authority"):
        WINDOWS_BUILD.validate_implementation_head(tmp_path, expected)


def test_runner_asset_integrity_rejects_missing_and_changed_file(tmp_path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    for name in WINDOWS_BUILD.WINDOWS_RUNNER_ASSETS:
        (assets / name).write_text(name, encoding="utf-8")
    hashes = {path.name: WINDOWS_BUILD.sha256_file(path) for path in assets.iterdir()}
    WINDOWS_BUILD.verify_runner_assets(assets, hashes)

    changed = assets / "build_windows_native_codex.py"
    changed.write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="changed after preservation"):
        WINDOWS_BUILD.verify_runner_assets(assets, hashes)

    changed.write_text("build_windows_native_codex.py", encoding="utf-8")
    (assets / "windows-native-qualification.yml").unlink()
    with pytest.raises(ValueError, match="asset set is incomplete"):
        WINDOWS_BUILD.verify_runner_assets(assets, hashes)


def test_pre_cargo_failure_receipt_keeps_compilation_not_started(tmp_path) -> None:
    receipt = {
        "status": "PREBUILD",
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
    }
    WINDOWS_BUILD.record_build_failure(
        tmp_path, receipt, "locked_resolution", ValueError("locked graph mismatch")
    )
    observed = json.loads((tmp_path / "windows-build-result.json").read_bytes())

    assert observed["status"] == "FAIL"
    assert observed["rust_compilation_started"] is False
    assert observed["compilation"] == "NOT_RUN"
    assert observed["process_proof"] is None
    assert observed["failure"] == {
        "phase": "locked_resolution",
        "type": "ValueError",
        "message": "locked graph mismatch",
    }


def test_final_binary_identity_rejects_post_proof_mutation(tmp_path) -> None:
    binary = tmp_path / "codex.exe"
    binary.write_bytes(b"retained binary")
    expected = WINDOWS_BUILD.sha256_file(binary)
    assert WINDOWS_BUILD.verify_binary_identity(binary, expected) == expected

    binary.write_bytes(b"mutated binary")
    with pytest.raises(ValueError, match="changed after the final process proof"):
        WINDOWS_BUILD.verify_binary_identity(binary, expected)


def test_workflow_binds_pull_request_head_and_never_cancels_build() -> None:
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/windows-native-qualification.yml"
    ).read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert "--expected-implementation-commit" in workflow
    assert "cancel-in-progress: false" in workflow
