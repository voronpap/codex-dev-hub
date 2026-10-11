import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.native_proof import ORDINARY_DEFAULT_VISIBLE_TOOLS_V1
from devhub.windows_native import (
    WindowsBuildProvenanceV2,
    WindowsBuildProvenanceV3,
    WindowsBuildProvenanceV5,
    WindowsHostProofSummaryV2,
    WindowsHostProofSummaryV3,
    WindowsNativeCodexBuildPayloadV2,
    WindowsNativeCodexBuildPayloadV3,
    WindowsNativeCodexBuildPayloadV5,
    WindowsNativeCodexBuildV2,
    WindowsNativeCodexBuildV3,
    WindowsNativeCodexBuildV5,
)

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

    assert WINDOWS_BUILD.BUILD_ID == "windows-build-006"
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
        build_id=WINDOWS_BUILD.BUILD_ID,
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
    assert observed["phase"] == observed["failure"]["phase"] == "locked_resolution"
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
    assert "$workspace = 'C:\\dfw003\\s'" in workflow
    assert "$output = 'C:\\dfw003\\e'" in workflow
    assert "--build-id windows-build-006" in workflow
    assert "--workflow-run-id '${{ github.run_id }}'" in workflow
    assert "--workflow-run-attempt '${{ github.run_attempt }}'" in workflow
    assert "name: devfabric-windows-build-006-evidence" in workflow
    assert "name: devfabric-windows-build-006-binaries" in workflow
    assert "scripts/inventory_native_build_artifact.py" in workflow
    assert "--evidence-projection C:\\dfw003\\u\\evidence" in workflow
    assert "path: C:/dfw003/u/evidence/**" in workflow
    assert "include-hidden-files: true" in workflow
    assert "C:/dfw003/e/windows-process-proof.json" in workflow
    assert "C:/dfw003/e/code-mode-host-eof.json" in workflow
    assert "if: success()" in workflow


def _pe64_console() -> bytes:
    raw = bytearray(0x200)
    raw[:2] = b"MZ"
    raw[0x3C:0x40] = (0x80).to_bytes(4, "little")
    raw[0x80:0x84] = b"PE\0\0"
    raw[0x84:0x86] = (0x8664).to_bytes(2, "little")
    raw[0x94:0x96] = (0xF0).to_bytes(2, "little")
    raw[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    raw[0x98 + 68 : 0x98 + 70] = (3).to_bytes(2, "little")
    raw[0x98 + 70 : 0x98 + 72] = (0x8160).to_bytes(2, "little")
    return bytes(raw)


@pytest.mark.parametrize("role", ["codex", "codex-code-mode-host"])
def test_pe_identity_binds_exact_role_path_and_amd64_console(tmp_path, role) -> None:
    binary = tmp_path / f"{role}.exe"
    binary.write_bytes(_pe64_console())

    identity = WINDOWS_BUILD.inspect_pe(role, binary)

    assert identity.relative_path == f"binary/{role}.exe"
    assert identity.sha256 == hashlib.sha256(_pe64_console()).hexdigest()
    assert identity.pe.machine_code == 0x8664
    assert identity.pe.subsystem_code == 3
    assert identity.pe.dll_characteristics == 0x8160


@pytest.mark.parametrize(
    ("offset", "value", "message"),
    [
        (0, b"NO", "not a PE"),
        (0x84, (0x14C).to_bytes(2, "little"), "not an x86_64"),
        (0x98, (0x10B).to_bytes(2, "little"), "not an x86_64"),
        (0x98 + 68, (2).to_bytes(2, "little"), "not an x86_64"),
    ],
)
def test_pe_identity_rejects_wrong_format(tmp_path, offset, value, message) -> None:
    raw = bytearray(_pe64_console())
    raw[offset : offset + len(value)] = value
    binary = tmp_path / "codex.exe"
    binary.write_bytes(raw)

    with pytest.raises(ValueError, match=message):
        WINDOWS_BUILD.inspect_pe("codex", binary)


def test_workflow_builds_exact_sibling_pair_with_one_locked_command() -> None:
    source = (SCRIPTS / "build_windows_native_codex.py").read_text(encoding="utf-8")

    assert '"--target",\n            TARGET,' in source
    assert source.count('"codex-code-mode-host"') >= 3
    assert 'root / "target" / TARGET / "release"' in source
    assert "windows-native-codex-build.json" in source
    assert "build_id=BUILD_ID" in source


def test_shared_process_proof_places_every_runtime_home_outside_sealed_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "sealed"
    output.mkdir()
    runtime_root = tmp_path / "runtime-scratch"
    runtime_root.mkdir()
    binary = tmp_path / "codex"
    binary.write_bytes(b"exact binary")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    schema = tmp_path / "schema.json"
    schema.write_text("{}", encoding="utf-8")
    observed_homes: list[Path] = []

    def proof_env(home: Path, _receipt: Path, _schema: Path, pid_path: Path) -> dict[str, str]:
        observed_homes.append(home)
        pid_path.write_text("4242", encoding="ascii")
        return {"CODEX_HOME": str(home)}

    def capture(
        command: list[str], *, cwd: Path, env: dict[str, str], timeout: int
    ) -> dict[str, object]:
        del cwd, env, timeout
        if "--devhub-proof-observe-router" in command:
            observer = Path(command[command.index("--devhub-proof-observe-router") + 1])
            observer.write_text("{}", encoding="utf-8")
        return {
            "exit_code": 7,
            "timed_out": False,
            "stdout": "",
            "stderr": (
                "unreviewed schema hash resolved devhub_delegate MCP config hash mismatch "
                "approved canonical namespace mismatch Stage 3G Arm A must not configure "
                "MCP servers reviewed devhub_delegate MCP server missing "
                "Stage 3G host admission is fresh-thread only"
            ),
        }

    monkeypatch.setattr(
        WINDOWS_BUILD.retained,
        "_verify_observer",
        lambda _path, arm, **_kwargs: {
            "visible_model_tools": [] if arm == "a" else [WINDOWS_BUILD.DELEGATE]
        },
    )
    monkeypatch.setattr(
        WINDOWS_BUILD.retained,
        "_verify_default_observer",
        lambda _path: {"visible_model_tools": list(ORDINARY_DEFAULT_VISIBLE_TOOLS_V1)},
    )
    monkeypatch.setattr(WINDOWS_BUILD.retained, "_proof_stopped", lambda _run: True)
    monkeypatch.setattr(
        WINDOWS_BUILD.retained,
        "_verify_mcp_catalog_records",
        lambda _records: None,
    )
    monkeypatch.setattr(
        WINDOWS_BUILD.retained,
        "_mutated_manifest",
        lambda _source, destination, _path, _value: destination.write_text("{}", encoding="utf-8"),
    )

    result = WINDOWS_BUILD.process_proof(
        binary,
        output=output,
        manifest=manifest,
        manifest_sha256="0" * 64,
        schema=schema,
        python=tmp_path / "python",
        server=tmp_path / "server.py",
        capture=capture,
        wait_pid_exit=lambda _pid, _timeout: True,
        proof_env=proof_env,
        runtime_home_root=runtime_root,
    )

    expected = {
        "arm-a",
        "arm-b",
        "default",
        "negative-wrong_schema_hash",
        "negative-wrong_config_hash",
        "negative-wrong_namespace",
        "negative-arm_a_with_mcp",
        "negative-arm_b_without_mcp",
        "negative-resume_with_host_authority",
        "negative-fork_with_host_authority",
        "lookalike",
    }
    assert {home.relative_to(runtime_root).as_posix() for home in observed_homes} == expected
    assert all(home.is_dir() and not home.is_relative_to(output) for home in observed_homes)
    assert not list((output / "process-proof").rglob("codex home"))
    assert result["same_binary"]["passed"] is True


def _proof_fixture() -> dict[str, object]:
    def observer(tools, *, ceiling, policy):
        return {
            "visible_model_tools": tools,
            "allowed_tools_ceiling_present": ceiling,
            "approved_delegate_policy_present": policy,
        }

    return {
        "arms": {
            "A": {"observer": observer([], ceiling=True, policy=False)},
            "B": {
                "observer": observer(
                    ["mcp__devhub_delegate.devhub_delegate"], ceiling=True, policy=True
                ),
                "mcp_child_exited": True,
            },
        },
        "default": {
            "observer": observer(
                list(ORDINARY_DEFAULT_VISIBLE_TOOLS_V1),
                ceiling=False,
                policy=False,
            )
        },
        "same_binary": {
            "b_minus_a": ["mcp__devhub_delegate.devhub_delegate"],
            "a_minus_b": [],
        },
        "negatives": {"wrong_schema": {"passed": True}},
        "model_requests": 0,
        "provider_sends": 0,
        "mcp_tool_executions": 0,
        "real_task_executions": 0,
    }


def _host_identity(tmp_path):
    binary = tmp_path / "codex-code-mode-host.exe"
    binary.write_bytes(_pe64_console())
    return WINDOWS_BUILD.inspect_pe("codex-code-mode-host", binary)


def test_proof_summary_rejects_historical_missing_host_diagnostic(tmp_path) -> None:
    proof = _proof_fixture()
    proof["default"]["stderr"] = "Code mode host executable was not found"
    host = _host_identity(tmp_path)
    eof = {
        "binary_sha256": host.sha256,
        "binary_relative_path": host.relative_path,
        "exit_code": 0,
        "timed_out": False,
        "process_exited": True,
    }

    with pytest.raises(ValueError, match="code-mode host failure"):
        WINDOWS_BUILD._proof_summary(proof, "1" * 64, eof, "2" * 64, host)


@pytest.mark.parametrize(("returncode", "active"), [(9, False), (0, True)])
def test_code_mode_host_eof_rejects_nonzero_or_surviving_process(
    tmp_path, monkeypatch, returncode, active
) -> None:
    binary = tmp_path / "codex-code-mode-host.exe"
    binary.write_bytes(b"host")

    class Process:
        pid = 42

        def __init__(self):
            self.returncode = returncode

        def communicate(self, _input=None, timeout=None):
            return b"", b""

    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "CREATE_NEW_PROCESS_GROUP", 0, raising=False)
    monkeypatch.setattr(WINDOWS_BUILD, "_pid_is_active", lambda _pid: active)

    with pytest.raises(ValueError, match="did not terminate cleanly"):
        WINDOWS_BUILD._host_eof_proof(binary, tmp_path / "eof.json")


def test_code_mode_host_eof_rejects_timeout(tmp_path, monkeypatch) -> None:
    binary = tmp_path / "codex-code-mode-host.exe"
    binary.write_bytes(b"host")

    class Process:
        pid = 42
        returncode = 1

        def __init__(self):
            self.calls = 0

        def communicate(self, _input=None, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise WINDOWS_BUILD.subprocess.TimeoutExpired(["host"], timeout)
            return b"", b""

    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "CREATE_NEW_PROCESS_GROUP", 0, raising=False)
    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(WINDOWS_BUILD, "_pid_is_active", lambda _pid: False)

    with pytest.raises(ValueError, match="did not terminate cleanly"):
        WINDOWS_BUILD._host_eof_proof(binary, tmp_path / "eof.json")


def test_pair_contract_rejects_reordering_and_forged_self_hash(tmp_path) -> None:
    codex_path = tmp_path / "codex.exe"
    host_path = tmp_path / "codex-code-mode-host.exe"
    codex_path.write_bytes(_pe64_console())
    host_path.write_bytes(_pe64_console() + b"host")
    codex = WINDOWS_BUILD.inspect_pe("codex", codex_path)
    host = WINDOWS_BUILD.inspect_pe("codex-code-mode-host", host_path)
    payload = WindowsNativeCodexBuildPayloadV2(
        provenance=WindowsBuildProvenanceV2(
            build_id="windows-build-003",
            implementation_commit="a" * 40,
            workflow_run_id=1,
            workflow_run_attempt=1,
            codex_source_commit="b" * 40,
            source_archive_sha256="1" * 64,
            candidate_b_base_patch_sha256="2" * 64,
            host_integration_patch_sha256="3" * 64,
            combined_patchset_sha256="4" * 64,
            canonical_schema_sha256="5" * 64,
            raw_schema_file_sha256="6" * 64,
            host_manifest_sha256="7" * 64,
            resolved_mcp_config_sha256="8" * 64,
            original_cargo_lock_sha256="9" * 64,
            derived_cargo_lock_sha256="a" * 64,
            rustc_version="rustc",
            cargo_version="cargo",
            rustc_sha256="b" * 64,
            cargo_sha256="c" * 64,
            build_script_sha256="d" * 64,
            shared_proof_script_sha256="e" * 64,
            workflow_sha256="f" * 64,
        ),
        binaries=(codex, host),
        process_proof=WindowsHostProofSummaryV2(
            process_proof_sha256="1" * 64,
            code_mode_host_sha256=host.sha256,
            code_mode_host_eof_receipt_sha256="2" * 64,
        ),
    )
    receipt = WindowsNativeCodexBuildV2.create(payload)
    assert receipt.payload.provenance.build_id == "windows-build-003"

    historical_payload = payload.model_copy(
        update={
            "provenance": payload.provenance.model_copy(update={"build_id": "windows-build-002"})
        }
    )
    historical = WindowsNativeCodexBuildV2.create(historical_payload)
    assert WindowsNativeCodexBuildV2.model_validate_json(historical.model_dump_json()) == historical

    unsupported_payload = payload.model_dump(mode="python")
    unsupported_payload["provenance"]["build_id"] = "windows-build-004"
    with pytest.raises(ValidationError, match="windows-build-002.*windows-build-003"):
        WindowsNativeCodexBuildPayloadV2.model_validate(unsupported_payload)

    raw = receipt.model_dump(mode="python")
    raw["windows_native_codex_build_id"] = "0" * 64
    with pytest.raises(ValidationError, match="build ID mismatch"):
        WindowsNativeCodexBuildV2.model_validate(raw)

    reordered = payload.model_dump(mode="python")
    reordered["binaries"] = tuple(reversed(reordered["binaries"]))
    with pytest.raises(ValidationError, match="ordered Codex"):
        WindowsNativeCodexBuildPayloadV2.model_validate(reordered)


def test_windows_build_004_binds_official_sandbox_release() -> None:
    codex = WINDOWS_BUILD.WindowsNativeBinaryV2(
        role="codex",
        relative_path="binary/codex.exe",
        sha256="1" * 64,
        size=1,
        pe=WINDOWS_BUILD.WindowsPeIdentityV1(dll_characteristics=0x8160),
    )
    host = WINDOWS_BUILD.WindowsNativeBinaryV2(
        role="codex-code-mode-host",
        relative_path="binary/codex-code-mode-host.exe",
        sha256="2" * 64,
        size=1,
        pe=WINDOWS_BUILD.WindowsPeIdentityV1(dll_characteristics=0x8160),
    )
    payload = WindowsNativeCodexBuildPayloadV3(
        provenance=WindowsBuildProvenanceV3(
            workflow_run_id=1,
            workflow_run_attempt=1,
            implementation_commit="a" * 40,
            codex_source_commit="b" * 40,
            source_archive_sha256="3" * 64,
            candidate_b_base_patch_sha256="4" * 64,
            host_integration_patch_sha256="5" * 64,
            combined_patchset_sha256="6" * 64,
            canonical_schema_sha256="7" * 64,
            raw_schema_file_sha256="8" * 64,
            host_manifest_sha256="9" * 64,
            resolved_mcp_config_sha256="a" * 64,
            original_cargo_lock_sha256="b" * 64,
            derived_cargo_lock_sha256="c" * 64,
            rustc_version="rustc 1.95.0",
            cargo_version="cargo 1.95.0",
            rustc_sha256="d" * 64,
            cargo_sha256="e" * 64,
            build_script_sha256="f" * 64,
            shared_proof_script_sha256="1" * 64,
            workflow_sha256="2" * 64,
            codex_module_bazel_sha256=WINDOWS_BUILD.CODEX_MODULE_BAZEL_SHA256,
            v8_archive_url=f"{WINDOWS_BUILD.V8_RELEASE_BASE}/{WINDOWS_BUILD.V8_ARCHIVE_NAME}",
            v8_archive_sha256=WINDOWS_BUILD.V8_ARCHIVE_SHA256,
            v8_binding_url=f"{WINDOWS_BUILD.V8_RELEASE_BASE}/{WINDOWS_BUILD.V8_BINDING_NAME}",
            v8_binding_sha256=WINDOWS_BUILD.V8_BINDING_SHA256,
            v8_checksum_url=f"{WINDOWS_BUILD.V8_RELEASE_BASE}/{WINDOWS_BUILD.V8_CHECKSUM_NAME}",
            v8_checksum_sha256=WINDOWS_BUILD.V8_CHECKSUM_SHA256,
            v8_archive_post_build_sha256=WINDOWS_BUILD.V8_ARCHIVE_SHA256,
            v8_binding_post_build_sha256=WINDOWS_BUILD.V8_BINDING_SHA256,
            v8_checksum_post_build_sha256=WINDOWS_BUILD.V8_CHECKSUM_SHA256,
        ),
        binaries=(codex, host),
        process_proof=WindowsHostProofSummaryV2(
            process_proof_sha256="3" * 64,
            code_mode_host_sha256=host.sha256,
            code_mode_host_eof_receipt_sha256="4" * 64,
        ),
    )
    receipt = WindowsNativeCodexBuildV3.create(payload)

    assert receipt.payload.provenance.build_id == "windows-build-004"
    assert receipt.payload.provenance.v8_sandbox_feature_enabled is True
    assert WindowsNativeCodexBuildV3.model_validate_json(receipt.model_dump_json()) == receipt


def test_windows_build_006_binds_exact_ordinary_default_surface() -> None:
    codex = WINDOWS_BUILD.WindowsNativeBinaryV2(
        role="codex",
        relative_path="binary/codex.exe",
        sha256="1" * 64,
        size=1,
        pe=WINDOWS_BUILD.WindowsPeIdentityV1(dll_characteristics=0x8160),
    )
    host = WINDOWS_BUILD.WindowsNativeBinaryV2(
        role="codex-code-mode-host",
        relative_path="binary/codex-code-mode-host.exe",
        sha256="2" * 64,
        size=1,
        pe=WINDOWS_BUILD.WindowsPeIdentityV1(dll_characteristics=0x8160),
    )
    provenance = WindowsBuildProvenanceV5(
        workflow_run_id=1,
        workflow_run_attempt=1,
        implementation_commit="a" * 40,
        codex_source_commit="b" * 40,
        source_archive_sha256="3" * 64,
        candidate_b_base_patch_sha256="4" * 64,
        host_integration_patch_sha256="5" * 64,
        combined_patchset_sha256="6" * 64,
        canonical_schema_sha256="7" * 64,
        raw_schema_file_sha256="8" * 64,
        host_manifest_sha256="9" * 64,
        resolved_mcp_config_sha256="a" * 64,
        original_cargo_lock_sha256="b" * 64,
        derived_cargo_lock_sha256="c" * 64,
        rustc_version="rustc 1.95.0",
        cargo_version="cargo 1.95.0",
        rustc_sha256="d" * 64,
        cargo_sha256="e" * 64,
        build_script_sha256="f" * 64,
        shared_proof_script_sha256="1" * 64,
        workflow_sha256="2" * 64,
        codex_module_bazel_sha256=WINDOWS_BUILD.CODEX_MODULE_BAZEL_SHA256,
        v8_archive_url=f"{WINDOWS_BUILD.V8_RELEASE_BASE}/{WINDOWS_BUILD.V8_ARCHIVE_NAME}",
        v8_archive_sha256=WINDOWS_BUILD.V8_ARCHIVE_SHA256,
        v8_binding_url=f"{WINDOWS_BUILD.V8_RELEASE_BASE}/{WINDOWS_BUILD.V8_BINDING_NAME}",
        v8_binding_sha256=WINDOWS_BUILD.V8_BINDING_SHA256,
        v8_checksum_url=f"{WINDOWS_BUILD.V8_RELEASE_BASE}/{WINDOWS_BUILD.V8_CHECKSUM_NAME}",
        v8_checksum_sha256=WINDOWS_BUILD.V8_CHECKSUM_SHA256,
        v8_archive_post_build_sha256=WINDOWS_BUILD.V8_ARCHIVE_SHA256,
        v8_binding_post_build_sha256=WINDOWS_BUILD.V8_BINDING_SHA256,
        v8_checksum_post_build_sha256=WINDOWS_BUILD.V8_CHECKSUM_SHA256,
    )
    proof = WindowsHostProofSummaryV3(
        process_proof_sha256="3" * 64,
        code_mode_host_sha256=host.sha256,
        code_mode_host_eof_receipt_sha256="4" * 64,
    )
    receipt = WindowsNativeCodexBuildV5.create(
        WindowsNativeCodexBuildPayloadV5(
            provenance=provenance,
            binaries=(codex, host),
            process_proof=proof,
        )
    )
    assert receipt.payload.process_proof.default_visible_tools == (
        ORDINARY_DEFAULT_VISIBLE_TOOLS_V1
    )

    changed = receipt.payload.model_dump(mode="python")
    changed["process_proof"]["default_visible_tools"] = tuple(
        ORDINARY_DEFAULT_VISIBLE_TOOLS_V1[:-1]
    )
    with pytest.raises(ValidationError, match="literal_error|tuple_type|Field required"):
        WindowsNativeCodexBuildPayloadV5.model_validate(changed)


def test_download_exact_rejects_overflow_and_removes_partial_file(tmp_path, monkeypatch) -> None:
    class Response:
        headers: dict[str, str] = {}

        def __init__(self) -> None:
            self._raw = b"x" * 65

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, size: int) -> bytes:
            value, self._raw = self._raw[:size], self._raw[size:]
            return value

    monkeypatch.setattr(WINDOWS_BUILD.urllib.request, "urlopen", lambda *_a, **_k: Response())
    target = tmp_path / "overflow"
    with pytest.raises(ValueError, match="byte limit"):
        WINDOWS_BUILD._download_exact("https://example.invalid/asset", target, "0" * 64, 64)
    assert not target.exists()


def test_v8_release_environment_binds_exact_assets_and_cargo_environment(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "source" / "codex-rs"
    root.mkdir(parents=True)
    output = tmp_path / "evidence"
    output.mkdir()
    monkeypatch.setattr(
        WINDOWS_BUILD,
        "_verify_pinned_v8_authority",
        lambda _root: WINDOWS_BUILD.CODEX_MODULE_BAZEL_SHA256,
    )

    def fake_download(_url: str, destination: Path, _sha256: str, _limit: int) -> int:
        if destination.name == WINDOWS_BUILD.V8_CHECKSUM_NAME:
            raw = (
                f"{WINDOWS_BUILD.V8_ARCHIVE_SHA256}  {WINDOWS_BUILD.V8_ARCHIVE_NAME}\n"
                f"{WINDOWS_BUILD.V8_BINDING_SHA256}  {WINDOWS_BUILD.V8_BINDING_NAME}\n"
            ).encode()
        else:
            raw = destination.name.encode()
        destination.write_bytes(raw)
        return len(raw)

    monkeypatch.setattr(WINDOWS_BUILD, "_download_exact", fake_download)
    environment, observed = WINDOWS_BUILD._v8_release_environment(root, output)

    assert "V8_FROM_SOURCE" not in environment
    assert environment["RUSTY_V8_ARCHIVE_SHA256"] == WINDOWS_BUILD.V8_ARCHIVE_SHA256
    assert environment["RUSTY_V8_ARCHIVE"].endswith(WINDOWS_BUILD.V8_ARCHIVE_NAME)
    assert environment["RUSTY_V8_SRC_BINDING_PATH"].endswith(WINDOWS_BUILD.V8_BINDING_NAME)
    assert observed["sandbox_feature_enabled"] is True


def test_v8_release_environment_removes_assets_on_checksum_mismatch(tmp_path, monkeypatch) -> None:
    root = tmp_path / "source" / "codex-rs"
    root.mkdir(parents=True)
    output = tmp_path / "evidence"
    output.mkdir()
    monkeypatch.setattr(WINDOWS_BUILD, "_verify_pinned_v8_authority", lambda _root: "0" * 64)

    def fake_download(_url: str, destination: Path, _sha256: str, _limit: int) -> int:
        destination.write_bytes(b"wrong")
        return 5

    monkeypatch.setattr(WINDOWS_BUILD, "_download_exact", fake_download)
    with pytest.raises(ValueError, match="checksum manifest content mismatch"):
        WINDOWS_BUILD._v8_release_environment(root, output)
    assert not (output / "v8-release").exists()


@pytest.mark.parametrize(
    "mutated_name",
    (
        WINDOWS_BUILD.V8_ARCHIVE_NAME,
        WINDOWS_BUILD.V8_BINDING_NAME,
        WINDOWS_BUILD.V8_CHECKSUM_NAME,
    ),
)
def test_post_build_v8_rehash_rejects_each_mutated_asset(
    tmp_path, monkeypatch, mutated_name
) -> None:
    asset_dir = tmp_path / "v8-release"
    asset_dir.mkdir()
    contents = {
        WINDOWS_BUILD.V8_ARCHIVE_NAME: b"archive",
        WINDOWS_BUILD.V8_BINDING_NAME: b"binding",
        WINDOWS_BUILD.V8_CHECKSUM_NAME: b"checksum",
    }
    monkeypatch.setattr(
        WINDOWS_BUILD,
        "V8_ARCHIVE_SHA256",
        hashlib.sha256(contents[WINDOWS_BUILD.V8_ARCHIVE_NAME]).hexdigest(),
    )
    monkeypatch.setattr(
        WINDOWS_BUILD,
        "V8_BINDING_SHA256",
        hashlib.sha256(contents[WINDOWS_BUILD.V8_BINDING_NAME]).hexdigest(),
    )
    monkeypatch.setattr(
        WINDOWS_BUILD,
        "V8_CHECKSUM_SHA256",
        hashlib.sha256(contents[WINDOWS_BUILD.V8_CHECKSUM_NAME]).hexdigest(),
    )
    for name, value in contents.items():
        (asset_dir / name).write_bytes(value + (b"tampered" if name == mutated_name else b""))
    with pytest.raises(ValueError, match="changed during build"):
        WINDOWS_BUILD._rehash_v8_assets(tmp_path)


def test_cargo_receives_reviewed_v8_release_environment(tmp_path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Process:
        def wait(self) -> int:
            return 0

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return Process()

    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "Popen", fake_popen)
    monkeypatch.setenv("V8_FROM_SOURCE", "1")
    monkeypatch.setenv("RUSTY_V8_MIRROR", "https://untrusted.invalid")
    receipt: dict[str, object] = {
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
    }
    assert (
        WINDOWS_BUILD._run_cargo_build(
            ["cargo", "build"],
            root=tmp_path,
            output=tmp_path,
            receipt=receipt,
            build_environment={
                "RUSTY_V8_ARCHIVE": r"C:\v8\archive.lib.gz",
                "RUSTY_V8_ARCHIVE_SHA256": WINDOWS_BUILD.V8_ARCHIVE_SHA256,
                "RUSTY_V8_SRC_BINDING_PATH": r"C:\v8\binding.rs",
            },
        )
        == 0
    )
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert "V8_FROM_SOURCE" not in environment
    assert "RUSTY_V8_MIRROR" not in environment
    assert environment["RUSTY_V8_ARCHIVE"] == r"C:\v8\archive.lib.gz"
    assert environment["RUSTY_V8_ARCHIVE_SHA256"] == WINDOWS_BUILD.V8_ARCHIVE_SHA256
    assert environment["RUSTY_V8_SRC_BINDING_PATH"] == r"C:\v8\binding.rs"


def test_post_build_v8_failure_records_exact_phase(tmp_path, monkeypatch) -> None:
    receipt: dict[str, object] = {
        "status": "COMPILING",
        "phase": "cargo_compile",
        "rust_compilation_started": True,
        "compilation": "PASS",
        "process_proof": None,
    }
    monkeypatch.setattr(
        WINDOWS_BUILD,
        "_rehash_v8_assets",
        lambda _output: (_ for _ in ()).throw(ValueError("V8 release asset changed during build")),
    )
    try:
        WINDOWS_BUILD._verify_post_build_v8_assets(receipt, tmp_path)
    except ValueError as error:
        WINDOWS_BUILD.record_build_failure(tmp_path, receipt, "cargo_compile", error)
    observed = json.loads((tmp_path / "windows-build-result.json").read_bytes())
    assert observed["phase"] == observed["failure"]["phase"] == "v8_release_post_build"
    assert observed["rust_compilation_started"] is True
    assert observed["compilation"] == "PASS"
    assert observed["process_proof"] is None


def test_cargo_wait_failure_records_sealed_compile_phase(tmp_path, monkeypatch) -> None:
    class Process:
        def wait(self) -> int:
            raise OSError("wait failed")

    monkeypatch.setattr(WINDOWS_BUILD.subprocess, "Popen", lambda *_args, **_kwargs: Process())
    receipt: dict[str, object] = {
        "status": "READY_FOR_COMPILE",
        "phase": "ready_for_cargo",
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
    }
    try:
        WINDOWS_BUILD._run_cargo_build(
            ["cargo", "build"],
            root=tmp_path,
            output=tmp_path,
            receipt=receipt,
            build_environment={},
        )
    except OSError as error:
        WINDOWS_BUILD.record_build_failure(tmp_path, receipt, "cargo_start", error)
    observed = json.loads((tmp_path / "windows-build-result.json").read_bytes())
    assert observed["phase"] == observed["failure"]["phase"] == "cargo_compile"
    assert observed["rust_compilation_started"] is True
    assert observed["compilation"] == "NOT_RUN"
    assert observed["process_proof"] is None
