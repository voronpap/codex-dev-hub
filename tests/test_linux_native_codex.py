from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.linux_native import (
    LinuxBuildProvenanceV1,
    LinuxBuildProvenanceV2,
    LinuxElfIdentityV1,
    LinuxHostProofSummaryV1,
    LinuxNativeBinaryV1,
    LinuxNativeCodexBuildPayloadV1,
    LinuxNativeCodexBuildPayloadV2,
    LinuxNativeCodexBuildV1,
    LinuxNativeCodexBuildV2,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "build_linux_native_codex", SCRIPTS / "build_linux_native_codex.py"
)
assert SPEC is not None and SPEC.loader is not None
LINUX_BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINUX_BUILD)
sys.path.pop(0)

HASH = "a" * 64
OTHER_HASH = "b" * 64
COMMIT = "c" * 40


def elf() -> LinuxElfIdentityV1:
    return LinuxElfIdentityV1(
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed=("libc.so.6", "libgcc_s.so.1"),
        required_symbol_versions=("GCC_3.0", "GLIBC_2.34"),
    )


def binary(role: str, sha256: str) -> LinuxNativeBinaryV1:
    return LinuxNativeBinaryV1(
        role=role,
        relative_path=f"binary/{role}",
        sha256=sha256,
        size=123,
        elf=elf(),
        identity_output_sha256=HASH,
    )


def proof(host_sha256: str = OTHER_HASH) -> LinuxHostProofSummaryV1:
    return LinuxHostProofSummaryV1(
        process_proof_sha256=HASH,
        code_mode_host_sha256=host_sha256,
        code_mode_host_eof_receipt_sha256=HASH,
    )


def provenance() -> LinuxBuildProvenanceV1:
    return LinuxBuildProvenanceV1(
        implementation_commit=COMMIT,
        codex_source_commit=COMMIT,
        source_archive_sha256=HASH,
        candidate_b_base_patch_sha256=HASH,
        host_integration_patch_sha256=HASH,
        combined_patchset_sha256=HASH,
        canonical_schema_sha256=HASH,
        raw_schema_file_sha256=HASH,
        host_manifest_sha256=HASH,
        resolved_mcp_config_sha256=HASH,
        original_cargo_lock_sha256=HASH,
        derived_cargo_lock_sha256=HASH,
        rustc_version="rustc 1.95.0",
        cargo_version="cargo 1.95.0",
        rustc_sha256=HASH,
        cargo_sha256=HASH,
        build_script_sha256=HASH,
        shared_proof_script_sha256=HASH,
        workflow_sha256=HASH,
    )


def receipt() -> LinuxNativeCodexBuildV1:
    payload = LinuxNativeCodexBuildPayloadV1(
        provenance=provenance(),
        binaries=(binary("codex", HASH), binary("codex-code-mode-host", OTHER_HASH)),
        process_proof=proof(),
    )
    return LinuxNativeCodexBuildV1.create(payload)


def process_proof_raw(message: str = "") -> dict[str, object]:
    observer = {
        "visible_model_tools": [],
        "allowed_tools_ceiling_present": False,
        "approved_delegate_policy_present": False,
    }
    return {
        "arms": {
            "A": {"observer": {**observer, "allowed_tools_ceiling_present": True}},
            "B": {
                "observer": {
                    **observer,
                    "visible_model_tools": ["mcp__devhub_delegate.devhub_delegate"],
                    "allowed_tools_ceiling_present": True,
                    "approved_delegate_policy_present": True,
                },
                "mcp_child_exited": True,
            },
        },
        "default": {"observer": observer, "stderr": message},
        "same_binary": {
            "b_minus_a": ["mcp__devhub_delegate.devhub_delegate"],
            "a_minus_b": [],
        },
        "negatives": {"guard": {"passed": True}},
        "model_requests": 0,
        "provider_sends": 0,
        "mcp_tool_executions": 0,
        "real_task_executions": 0,
    }


def test_linux_build_receipt_is_canonical_strict_and_self_hashed() -> None:
    value = receipt()
    reparsed = LinuxNativeCodexBuildV1.model_validate_json(value.model_dump_json())
    assert reparsed == value
    raw = value.model_dump(mode="json")
    raw["linux_native_codex_build_id"] = "f" * 64
    with pytest.raises(ValidationError, match="build ID mismatch"):
        LinuxNativeCodexBuildV1.model_validate_json(json.dumps(raw))
    raw = value.model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        LinuxNativeCodexBuildV1.model_validate_json(json.dumps(raw))


def test_linux_build_002_records_sandboxed_v8_source_build() -> None:
    current = LinuxNativeCodexBuildV2.create(
        LinuxNativeCodexBuildPayloadV2(
            provenance=LinuxBuildProvenanceV2(
                **{
                    **provenance().model_dump(mode="python"),
                    "build_id": "linux-build-002",
                    "v8_crate_version": "150.4.0",
                    "v8_build_mode": "from_source",
                }
            ),
            binaries=(binary("codex", HASH), binary("codex-code-mode-host", OTHER_HASH)),
            process_proof=proof(),
        )
    )

    assert current.payload.provenance.build_id == "linux-build-002"
    assert current.payload.provenance.v8_build_mode == "from_source"
    assert receipt().payload.provenance.build_id == "linux-build-001"


@pytest.mark.parametrize(
    ("roles", "message"),
    [
        (("codex-code-mode-host", "codex"), "ordered Codex/code-mode-host pair"),
        (("codex", "codex"), "ordered Codex/code-mode-host pair"),
    ],
)
def test_linux_build_requires_exact_distinct_ordered_binary_pair(
    roles: tuple[str, str], message: str
) -> None:
    binaries = tuple(
        binary(role, HASH if index == 0 else OTHER_HASH) for index, role in enumerate(roles)
    )
    with pytest.raises(ValidationError, match=message):
        LinuxNativeCodexBuildPayloadV1(
            provenance=provenance(), binaries=binaries, process_proof=proof()
        )


def test_linux_binary_role_must_match_path() -> None:
    with pytest.raises(ValidationError, match="role and path differ"):
        LinuxNativeBinaryV1(
            role="codex",
            relative_path="binary/codex-code-mode-host",
            sha256=HASH,
            size=123,
            elf=elf(),
            identity_output_sha256=HASH,
        )


def test_linux_receipt_rejects_sibling_host_substitution_and_eof_tamper() -> None:
    with pytest.raises(ValidationError, match="exact sibling code-mode host"):
        LinuxNativeCodexBuildPayloadV1(
            provenance=provenance(),
            binaries=(binary("codex", HASH), binary("codex-code-mode-host", OTHER_HASH)),
            process_proof=proof("d" * 64),
        )

    raw = receipt().model_dump(mode="json")
    raw["payload"]["process_proof"]["code_mode_host_eof_receipt_sha256"] = "e" * 64
    with pytest.raises(ValidationError, match="build ID mismatch"):
        LinuxNativeCodexBuildV1.model_validate_json(json.dumps(raw))


def test_linux_elf_contract_rejects_rpath_and_noncanonical_dynamic_identity() -> None:
    with pytest.raises(ValidationError, match="must be sorted and unique"):
        LinuxElfIdentityV1(
            interpreter="/lib64/ld-linux-x86-64.so.2",
            needed=("libgcc_s.so.1", "libc.so.6"),
            required_symbol_versions=(),
        )
    with pytest.raises(ValidationError, match="must not embed RPATH"):
        LinuxElfIdentityV1(
            interpreter="/lib64/ld-linux-x86-64.so.2",
            needed=("libc.so.6",),
            rpath=("/tmp/ambient",),
            required_symbol_versions=(),
        )


def test_readelf_parser_binds_machine_loader_dependencies_and_versions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary_path = tmp_path / "codex"
    binary_path.write_bytes(b"elf")
    outputs = iter(
        (
            b"Class:                             ELF64\n"
            b"Data:                              2's complement, little endian\n"
            b"Machine:                           Advanced Micro Devices X86-64\n",
            b"[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]\n",
            b"(NEEDED) Shared library: [libgcc_s.so.1]\n(NEEDED) Shared library: [libc.so.6]\n",
            b"Name: GLIBC_2.34\nName: GCC_3.0\nName: GLIBC_2.34\n",
        )
    )

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 0, next(outputs), b"")

    monkeypatch.setattr(LINUX_BUILD.subprocess, "run", fake_run)
    identity_file = tmp_path / "identity.txt"
    identity = LINUX_BUILD._readelf(binary_path, identity_file)
    assert identity.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert identity.needed == ("libc.so.6", "libgcc_s.so.1")
    assert identity.required_symbol_versions == ("GCC_3.0", "GLIBC_2.34")
    assert identity_file.is_file()


def test_cargo_spawn_failure_remains_precompilation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = {
        "status": "READY_FOR_COMPILE",
        "phase": "ready_for_cargo",
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
    }
    state_path = tmp_path / "linux-build-result.json"

    def fail_spawn(*_args, **_kwargs):
        raise FileNotFoundError("cargo unavailable")

    monkeypatch.setattr(LINUX_BUILD.subprocess, "Popen", fail_spawn)
    with pytest.raises(FileNotFoundError, match="cargo unavailable"):
        LINUX_BUILD._run_cargo_build(
            ["cargo", "build"],
            root=tmp_path,
            output=tmp_path,
            state=state,
            state_path=state_path,
            build_environment={"V8_FROM_SOURCE": "1"},
        )
    observed = json.loads(state_path.read_bytes())
    assert observed["phase"] == "cargo_start"
    assert observed["rust_compilation_started"] is False
    assert observed["compilation"] == "NOT_RUN"
    assert observed["process_proof"] is None


def test_v8_source_build_environment_requires_and_records_exact_prerequisites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tools = {}
    for name in ("python3", "curl", "pkg-config", "llvm-config-19"):
        path = tmp_path / name
        path.write_bytes(b"tool")
        tools[name] = str(path)
    llvm_lib = tmp_path / "llvm-19" / "lib"
    llvm_lib.mkdir(parents=True)
    (llvm_lib / "libclang.so.19").write_bytes(b"clang")
    monkeypatch.setattr(LINUX_BUILD.shutil, "which", tools.get)

    def fake_run(command, **_kwargs):
        if command[1:] == ["--modversion", "glib-2.0"]:
            return subprocess.CompletedProcess(command, 0, "2.80.0\n", "")
        if command[1:] == ["--libdir"]:
            return subprocess.CompletedProcess(command, 0, f"{llvm_lib}\n", "")
        raise AssertionError(command)

    monkeypatch.setattr(LINUX_BUILD.subprocess, "run", fake_run)

    environment, observed = LINUX_BUILD._v8_source_build_environment()

    assert environment == {
        "V8_FROM_SOURCE": "1",
        "PYTHON": str((tmp_path / "python3").resolve()),
        "LIBCLANG_PATH": str(llvm_lib.resolve()),
    }
    assert observed == {
        "v8_crate_version": "150.4.0",
        "v8_build_mode": "from_source",
        "python": environment["PYTHON"],
        "libclang_path": environment["LIBCLANG_PATH"],
        "glib_version": "2.80.0",
    }


def test_missing_llvm_config_fails_before_cargo_and_preserves_prebuild_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
    }
    tools = {
        "python3": "/usr/bin/python3",
        "curl": "/usr/bin/curl",
        "pkg-config": "/usr/bin/pkg-config",
        "llvm-config-19": None,
    }
    monkeypatch.setattr(LINUX_BUILD.shutil, "which", tools.get)
    monkeypatch.setattr(
        LINUX_BUILD.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("Cargo must not start without llvm-config-19"),
    )

    with pytest.raises(ValueError, match="prerequisites are incomplete"):
        LINUX_BUILD._v8_source_build_environment()

    assert state == {
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
    }


def test_linux_workflow_installs_complete_v8_source_build_prerequisites() -> None:
    workflow = (ROOT / ".github/workflows/linux-native-codex.yml").read_text(encoding="utf-8")

    assert "libclang-19-dev" in workflow
    assert "llvm-19-dev" in workflow
    assert "libglib2.0-dev" in workflow
    assert "devfabric-linux-build-002" in workflow


def test_cargo_receives_reviewed_v8_source_build_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    class Process:
        def wait(self) -> int:
            return 0

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return Process()

    monkeypatch.setattr(LINUX_BUILD.subprocess, "Popen", fake_popen)
    state: dict[str, object] = {
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
    }
    state_path = tmp_path / "linux-build-result.json"

    assert (
        LINUX_BUILD._run_cargo_build(
            ["cargo", "build"],
            root=tmp_path,
            output=tmp_path,
            state=state,
            state_path=state_path,
            build_environment={
                "V8_FROM_SOURCE": "1",
                "PYTHON": "/usr/bin/python3",
                "LIBCLANG_PATH": "/usr/lib/llvm-19/lib",
            },
        )
        == 0
    )
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert environment["V8_FROM_SOURCE"] == "1"
    assert environment["PYTHON"] == "/usr/bin/python3"
    assert environment["LIBCLANG_PATH"] == "/usr/lib/llvm-19/lib"


@pytest.mark.parametrize(
    ("phase", "message"),
    (
        ("binary_identity", "ELF machine mismatch"),
        ("code_mode_host_eof", "host EOF timeout"),
    ),
)
def test_post_compilation_failure_preserves_exact_phase(
    tmp_path: Path, phase: str, message: str
) -> None:
    state = {
        "status": "COMPILING",
        "phase": "cargo_compile",
        "rust_compilation_started": True,
        "compilation": "PASS",
        "process_proof": None,
    }
    state_path = tmp_path / "linux-build-result.json"
    LINUX_BUILD._seal_phase(state, state_path, phase)
    LINUX_BUILD._record_failure(state, state_path, ValueError(message))
    observed = json.loads(state_path.read_bytes())
    assert observed["status"] == "FAIL"
    assert observed["phase"] == observed["failure"]["phase"] == phase
    assert observed["failure"]["message"] == message
    assert observed["rust_compilation_started"] is True
    assert observed["compilation"] == "PASS"
    assert observed["process_proof"] is None


def test_process_summary_binds_exact_eof_receipt_and_sibling_host() -> None:
    host = binary("codex-code-mode-host", OTHER_HASH)
    eof = {
        "binary_sha256": host.sha256,
        "binary_relative_path": host.relative_path,
        "exit_code": 0,
        "timed_out": False,
        "process_exited": True,
    }
    summary = LINUX_BUILD._proof_summary(process_proof_raw(), HASH, eof, "d" * 64, host)
    assert summary.code_mode_host_sha256 == host.sha256
    assert summary.code_mode_host_eof_receipt_sha256 == "d" * 64
    with pytest.raises(ValueError, match="exact sibling code-mode host"):
        LINUX_BUILD._proof_summary(
            process_proof_raw(),
            HASH,
            {**eof, "binary_sha256": "e" * 64},
            "d" * 64,
            host,
        )


def test_committed_provenance_is_worktree_crlf_independent(tmp_path: Path) -> None:
    paths = (
        "scripts/build_linux_native_codex.py",
        "scripts/build_windows_native_codex.py",
        ".github/workflows/linux-native-codex.yml",
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.invalid"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "config", "user.name", "DevFabric test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=tmp_path, check=True)
    for path in paths:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"first\nsecond\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=tmp_path, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_path, text=True).strip()
    expected = LINUX_BUILD.committed_provenance_hashes(tmp_path, commit)
    for path in paths:
        (tmp_path / path).write_bytes(b"first\r\nsecond\r\n")
    assert LINUX_BUILD.committed_provenance_hashes(tmp_path, commit) == expected


def test_process_summary_rejects_missing_sibling_host_error() -> None:
    with pytest.raises(ValueError, match="code-mode host failure"):
        LINUX_BUILD._proof_summary(
            process_proof_raw("host executable was not found"),
            HASH,
            {},
            HASH,
            binary("codex-code-mode-host", OTHER_HASH),
        )


@pytest.mark.parametrize(
    "message",
    (
        "Code Mode is unavailable because the helper failed",
        "failed to spawn code-mode host: permission denied",
        "error while loading shared libraries: libc.so.6",
        "failed to read code-mode host hello: unexpected EOF",
        "code-mode host protocol mismatch",
    ),
)
def test_process_summary_rejects_alternate_code_mode_failures(message: str) -> None:
    with pytest.raises(ValueError, match="code-mode host failure"):
        LINUX_BUILD._proof_summary(
            process_proof_raw(message),
            HASH,
            {},
            HASH,
            binary("codex-code-mode-host", OTHER_HASH),
        )


def test_linux_builder_reuses_shared_source_and_process_authority() -> None:
    assert LINUX_BUILD.retained.prepare_build_source is not None
    signature = inspect.signature(LINUX_BUILD.shared.process_proof)
    assert {"capture", "wait_pid_exit", "proof_env", "platform_label"} <= set(signature.parameters)
    candidate = (ROOT / "patches/stage3g-approved-call/candidate.patch").read_bytes()
    host = (ROOT / "patches/stage3g-approved-call/host-integration.patch").read_bytes()
    assert hashlib.sha256(candidate).hexdigest() == LINUX_BUILD.retained.CANDIDATE_SHA256
    assert hashlib.sha256(host).hexdigest() == LINUX_BUILD.retained.HOST_SHA256
    assert hashlib.sha256(candidate + host).hexdigest() == LINUX_BUILD.retained.COMBINED_SHA256


def test_linux_workflow_binds_exact_pr_head_pair_and_never_cancels() -> None:
    workflow = (ROOT / ".github/workflows/linux-native-codex.yml").read_text(encoding="utf-8")
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert "--expected-implementation-commit" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "x86_64-unknown-linux-gnu" in workflow
    assert "scripts/build_linux_native_codex.py" in workflow
