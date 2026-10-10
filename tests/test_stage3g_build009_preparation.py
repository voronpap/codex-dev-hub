import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "build_stage3g_build009", SCRIPTS / "build_stage3g_build009.py"
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
sys.path.pop(0)

CANDIDATE_PATCH = b"""\
diff --git a/codex-rs/candidate.txt b/codex-rs/candidate.txt
new file mode 100644
--- /dev/null
+++ b/codex-rs/candidate.txt
@@ -0,0 +1 @@
+candidate
"""

HOST_PATCH = b"""\
diff --git a/host.txt b/host.txt
new file mode 100644
--- /dev/null
+++ b/host.txt
@@ -0,0 +1 @@
+host
"""


def test_runner_preparation_uses_distinct_reviewed_patch_roots(tmp_path, monkeypatch) -> None:
    checkout = tmp_path / "codex-pinned"
    root = checkout / "codex-rs"
    root.mkdir(parents=True)
    original = b"pinned lock\n"
    derived = b"derived proof lock\n"
    (root / "Cargo.lock").write_bytes(original)
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    monkeypatch.setattr(RUNNER, "ORIGINAL", hashlib.sha256(original).hexdigest())
    monkeypatch.setattr(RUNNER, "BUILD009_DERIVED", hashlib.sha256(derived).hexdigest())
    monkeypatch.setattr(RUNNER, "derive_build009", lambda candidate_root: (derived, []))

    result = RUNNER.prepare_build_source(
        root,
        candidate_patch=CANDIDATE_PATCH,
        host_patch=HOST_PATCH,
        evidence_directory=evidence,
    )

    assert (root / "candidate.txt").read_text(encoding="utf-8") == "candidate\n"
    assert (root / "host.txt").read_text(encoding="utf-8") == "host\n"
    assert (root / "Cargo.lock").read_bytes() == derived
    assert (evidence / "Cargo.lock.original").read_bytes() == original
    assert (evidence / "Cargo.lock.proof").read_bytes() == derived
    assert result == {
        "original_cargo_lock_sha256": hashlib.sha256(original).hexdigest(),
        "proof_cargo_lock_sha256": hashlib.sha256(derived).hexdigest(),
        "lock_strategy": "LOCK_B_minimal_manifest_bound_derived_lock",
        "candidate_patch_cwd": "pinned_source_parent",
        "host_patch_cwd": "codex-rs",
        "candidate_patch_applied": True,
        "host_patch_applied": True,
    }


def test_default_observer_proves_absent_authority(tmp_path) -> None:
    observer = tmp_path / "observer.json"
    observer.write_text(
        json.dumps(
            {
                "allowed_tools_ceiling_present": False,
                "allowed_tools": [],
                "approved_delegate_policy_present": False,
                "approved_identity": None,
                "host_manifest_sha256": None,
                "expected_schema_sha256": None,
                "visible_model_tools": ["functions.apply_patch"],
                "nested_code_mode_map": [],
                "model_requests": 0,
                "provider_sends": 0,
            }
        ),
        encoding="utf-8",
    )

    assert RUNNER._verify_default_observer(observer)["host_manifest_sha256"] is None


def test_default_observer_rejects_hidden_ceiling(tmp_path) -> None:
    observer = tmp_path / "observer.json"
    observer.write_text(
        json.dumps(
            {
                "allowed_tools_ceiling_present": True,
                "allowed_tools": [],
                "approved_delegate_policy_present": False,
                "approved_identity": None,
                "host_manifest_sha256": None,
                "expected_schema_sha256": None,
                "visible_model_tools": [],
                "nested_code_mode_map": [],
                "model_requests": 0,
                "provider_sends": 0,
            }
        ),
        encoding="utf-8",
    )

    try:
        RUNNER._verify_default_observer(observer)
    except ValueError as error:
        assert "AllowedTools ceiling" in str(error)
    else:
        raise AssertionError("default observer accepted a hidden ceiling")


def test_proof_stop_requires_exact_pre_sampling_termination() -> None:
    valid = {
        "timed_out": False,
        "exit_code": 1,
        "stdout": "",
        "stderr": "DevFabric proof observer stopped before model sampling",
    }
    assert RUNNER._proof_stopped(valid)
    assert not RUNNER._proof_stopped({**valid, "timed_out": True})
    assert not RUNNER._proof_stopped({**valid, "exit_code": 0})
    assert not RUNNER._proof_stopped({**valid, "stderr": "other failure"})


def test_host_patch_maps_observer_error_into_session_error_boundary() -> None:
    patch = (
        Path(__file__).resolve().parents[1] / "patches/stage3g-approved-call/host-integration.patch"
    ).read_text(encoding="utf-8")

    assert ".map_err(|error| CodexErrorDetails::InvalidRequest(error.to_string()))?;" in patch
    assert (
        """observer
+                .observe(
+                    tool_router.as_ref(),"""
        in patch
    )


def test_host_patch_passes_owned_extension_template_into_static_start_task() -> None:
    patch = (
        Path(__file__).resolve().parents[1] / "patches/stage3g-approved-call/host-integration.patch"
    ).read_text(encoding="utf-8")

    clone = "+        let host_thread_extension_init = self.thread_extension_init.clone();"
    task = "         let thread_start_task = async move {"
    assert clone in patch
    assert task in patch
    assert patch.index(clone) < patch.index(task)
    assert "+                host_thread_extension_init," in patch
    assert "+        mut thread_extension_init: ExtensionDataInit," in patch
    assert (
        "+        let mut thread_extension_init = self.thread_extension_init.clone();" not in patch
    )


def test_host_patch_matches_pinned_remote_and_resolved_config_api_shapes() -> None:
    patch = (
        Path(__file__).resolve().parents[1] / "patches/stage3g-approved-call/host-integration.patch"
    ).read_text(encoding="utf-8")

    tui_diff = patch.split("diff --git a/tui/src/lib.rs b/tui/src/lib.rs", 1)[1].split(
        "diff --git a/tui/src/onboarding/auth.rs", 1
    )[0]
    assert "connect_remote_app_server" not in tui_diff
    assert (
        "+        thread_extension_init: codex_extension_api::ExtensionDataInit::new()," in tui_diff
    )
    assert (
        "config.mcp_servers.get().get(SERVER_KEY).context(\n"
        '+                        "reviewed devhub_delegate MCP server missing from '
        'resolved config",\n'
        "+                    )?;"
    ) in patch
    host_file_diff = patch.split(
        "diff --git a/exec/src/approved_delegate_host.rs b/exec/src/approved_delegate_host.rs",
        1,
    )[1].split("diff --git ", 1)[0]
    host_file_body = host_file_diff.split("@@ -0,0 +1,253 @@\n", 1)[1]
    added_lines = [line for line in host_file_body.splitlines() if line.startswith("+")]
    assert len(added_lines) == 253
    assert added_lines[-1] == "+}"


def test_locked_resolution_requires_byte_identical_lock(tmp_path, monkeypatch) -> None:
    root = tmp_path / "source"
    output = tmp_path / "evidence"
    root.mkdir()
    output.mkdir()
    lock = b"complete reviewed lock\n"
    (root / "Cargo.lock").write_bytes(lock)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, b"ok", b"")

    monkeypatch.setattr(RUNNER.subprocess, "run", run)
    expected = hashlib.sha256(lock).hexdigest()

    result = RUNNER._verify_locked_resolution(root, output, expected)

    assert list(result) == ["metadata", "fetch"]
    assert all(item["lock_unchanged"] for item in result.values())
    assert calls[0][0][0:3] == ["cargo", "+1.95.0", "metadata"]
    assert calls[1][0][0:3] == ["cargo", "+1.95.0", "fetch"]


def test_locked_resolution_rejects_lock_mutation(tmp_path, monkeypatch) -> None:
    root = tmp_path / "source"
    output = tmp_path / "evidence"
    root.mkdir()
    output.mkdir()
    lock = b"complete reviewed lock\n"
    lock_path = root / "Cargo.lock"
    lock_path.write_bytes(lock)

    def run(command, **kwargs):
        lock_path.write_bytes(b"mutated\n")
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(RUNNER.subprocess, "run", run)

    try:
        RUNNER._verify_locked_resolution(root, output, hashlib.sha256(lock).hexdigest())
    except ValueError as error:
        assert "metadata" in str(error)
    else:
        raise AssertionError("locked verification accepted Cargo.lock mutation")


def test_toolchain_provenance_uses_exact_pinned_toolchain(tmp_path, monkeypatch) -> None:
    calls = []

    def check_output(command, **kwargs):
        calls.append((command, kwargs))
        if command[-2:] == ["rustc", "-vV"]:
            return "rustc 1.95.0\nhost: x86_64-unknown-linux-gnu\n"
        return "cargo 1.95.0\nrelease: 1.95.0\n"

    monkeypatch.setattr(RUNNER.subprocess, "check_output", check_output)
    monkeypatch.setattr(RUNNER.platform, "platform", lambda: "reviewed-platform")

    identity = RUNNER._pinned_toolchain_identity(tmp_path)

    assert calls == [
        (
            ["rustup", "run", "1.95.0", "rustc", "-vV"],
            {"cwd": tmp_path, "text": True},
        ),
        (
            ["rustup", "run", "1.95.0", "cargo", "--version", "--verbose"],
            {"cwd": tmp_path, "text": True},
        ),
    ]
    assert identity["target"] == "x86_64-unknown-linux-gnu"
    assert identity["rustc_command"] == calls[0][0]
    assert identity["cargo_command"] == calls[1][0]


def test_precompilation_failure_retains_complete_hashed_runner_assets(
    tmp_path, monkeypatch
) -> None:
    repo = tmp_path / "repo"
    output = tmp_path / "evidence"
    root = tmp_path / "source"
    output.mkdir()
    root.mkdir()
    expected_assets = {
        "stage3g-host-manifest-v2.json": "benchmarks/stage3g-host-manifest-v2.json",
        "delegation-request-schema.json": (
            "docs/evidence/stage3g-production-router/delegate-input-schema.json"
        ),
        "candidate.patch": "patches/stage3g-approved-call/candidate.patch",
        "host-integration.patch": "patches/stage3g-approved-call/host-integration.patch",
        "stage3g_build009_mcp.py": "scripts/stage3g_build009_mcp.py",
        "build_stage3g_build009.py": "scripts/build_stage3g_build009.py",
        "preflight_stage3g_build009.py": "scripts/preflight_stage3g_build009.py",
        "derive_router_build_lock.py": "scripts/derive_router_build_lock.py",
        "derive_stage3g_production_lock.py": "scripts/derive_stage3g_production_lock.py",
        "stage3g_schema_hash.py": "scripts/stage3g_schema_hash.py",
        "production-router-proof.yml": ".github/workflows/production-router-proof.yml",
    }
    for index, relative in enumerate(expected_assets.values()):
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"asset-{index}\n".encode())

    assets, hashes = RUNNER._preserve_runner_assets(
        repo,
        output,
        manifest=repo / expected_assets["stage3g-host-manifest-v2.json"],
        schema=repo / expected_assets["delegation-request-schema.json"],
    )
    lock = b"reviewed lock\n"
    (root / "Cargo.lock").write_bytes(lock)

    def fail_resolution(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, b"", b"resolution failed")

    monkeypatch.setattr(RUNNER.subprocess, "run", fail_resolution)
    try:
        RUNNER._verify_locked_resolution(root, output, hashlib.sha256(lock).hexdigest())
    except ValueError:
        pass
    else:
        raise AssertionError("locked resolution unexpectedly passed")

    assert {path.name for path in assets.iterdir()} == set(expected_assets)
    assert set(hashes) == set(expected_assets)
    for name, expected_hash in hashes.items():
        assert hashlib.sha256((assets / name).read_bytes()).hexdigest() == expected_hash
