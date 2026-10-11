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
    LinuxBuildProvenanceV3,
    LinuxBuildProvenanceV4,
    LinuxBuildProvenanceV5,
    LinuxBuildProvenanceV6,
    LinuxBuildProvenanceV7,
    LinuxElfIdentityV1,
    LinuxHostProofSummaryV1,
    LinuxHostProofSummaryV2,
    LinuxHostProofSummaryV3,
    LinuxNativeBinaryV1,
    LinuxNativeCodexBuildPayloadV1,
    LinuxNativeCodexBuildPayloadV2,
    LinuxNativeCodexBuildPayloadV3,
    LinuxNativeCodexBuildPayloadV4,
    LinuxNativeCodexBuildPayloadV5,
    LinuxNativeCodexBuildPayloadV6,
    LinuxNativeCodexBuildPayloadV7,
    LinuxNativeCodexBuildV1,
    LinuxNativeCodexBuildV2,
    LinuxNativeCodexBuildV3,
    LinuxNativeCodexBuildV4,
    LinuxNativeCodexBuildV5,
    LinuxNativeCodexBuildV6,
    LinuxNativeCodexBuildV7,
)
from devhub.native_proof import ORDINARY_DEFAULT_VISIBLE_TOOLS_V1

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


def proof_v2(host_sha256: str = OTHER_HASH) -> LinuxHostProofSummaryV2:
    return LinuxHostProofSummaryV2(
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
        "default": {
            "observer": {
                **observer,
                "visible_model_tools": list(ORDINARY_DEFAULT_VISIBLE_TOOLS_V1),
            },
            "stderr": message,
        },
        "same_binary": {
            "b_minus_a": ["mcp__devhub_delegate.devhub_delegate"],
            "a_minus_b": [],
        },
        "negatives": {"guard": {"passed": True}},
        "model_requests": 0,
        "provider_sends": 0,
        "mcp_tool_executions": 0,
        "real_task_executions": 0,
        "runtime_scratch_cleanup_passed": True,
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


def test_linux_build_003_binds_official_sandbox_release_and_preserves_history() -> None:
    current = LinuxNativeCodexBuildV3.create(
        LinuxNativeCodexBuildPayloadV3(
            provenance=LinuxBuildProvenanceV3(
                **{
                    **provenance().model_dump(mode="python"),
                    "build_id": "linux-build-003",
                    "v8_crate_version": "150.4.0",
                    "v8_build_mode": "official_openai_sandbox_release",
                    "v8_release_tag": LINUX_BUILD.V8_RELEASE_TAG,
                    "codex_module_bazel_sha256": LINUX_BUILD.CODEX_MODULE_BAZEL_SHA256,
                    "v8_sandbox_feature_enabled": True,
                    "v8_archive_url": (
                        f"{LINUX_BUILD.V8_RELEASE_BASE}/{LINUX_BUILD.V8_ARCHIVE_NAME}"
                    ),
                    "v8_archive_sha256": LINUX_BUILD.V8_ARCHIVE_SHA256,
                    "v8_binding_url": (
                        f"{LINUX_BUILD.V8_RELEASE_BASE}/{LINUX_BUILD.V8_BINDING_NAME}"
                    ),
                    "v8_binding_sha256": LINUX_BUILD.V8_BINDING_SHA256,
                    "v8_checksum_url": (
                        f"{LINUX_BUILD.V8_RELEASE_BASE}/{LINUX_BUILD.V8_CHECKSUM_NAME}"
                    ),
                    "v8_checksum_sha256": LINUX_BUILD.V8_CHECKSUM_SHA256,
                    "v8_archive_post_build_sha256": LINUX_BUILD.V8_ARCHIVE_SHA256,
                    "v8_binding_post_build_sha256": LINUX_BUILD.V8_BINDING_SHA256,
                    "v8_checksum_post_build_sha256": LINUX_BUILD.V8_CHECKSUM_SHA256,
                }
            ),
            binaries=(binary("codex", HASH), binary("codex-code-mode-host", OTHER_HASH)),
            process_proof=proof(),
        )
    )

    assert current.payload.provenance.build_id == "linux-build-003"
    assert current.payload.provenance.v8_sandbox_feature_enabled is True
    assert LinuxNativeCodexBuildV3.model_validate_json(current.model_dump_json()) == current
    assert receipt().payload.provenance.build_id == "linux-build-001"


def test_linux_build_004_binds_ordinary_default_and_preserves_history() -> None:
    current = LinuxNativeCodexBuildV4.create(
        LinuxNativeCodexBuildPayloadV4(
            provenance=LinuxBuildProvenanceV4(
                **{
                    **provenance().model_dump(mode="python"),
                    "build_id": "linux-build-004",
                    "v8_crate_version": "150.4.0",
                    "v8_build_mode": "official_openai_sandbox_release",
                    "v8_release_tag": LINUX_BUILD.V8_RELEASE_TAG,
                    "codex_module_bazel_sha256": LINUX_BUILD.CODEX_MODULE_BAZEL_SHA256,
                    "v8_sandbox_feature_enabled": True,
                    "v8_archive_url": (
                        f"{LINUX_BUILD.V8_RELEASE_BASE}/{LINUX_BUILD.V8_ARCHIVE_NAME}"
                    ),
                    "v8_archive_sha256": LINUX_BUILD.V8_ARCHIVE_SHA256,
                    "v8_binding_url": (
                        f"{LINUX_BUILD.V8_RELEASE_BASE}/{LINUX_BUILD.V8_BINDING_NAME}"
                    ),
                    "v8_binding_sha256": LINUX_BUILD.V8_BINDING_SHA256,
                    "v8_checksum_url": (
                        f"{LINUX_BUILD.V8_RELEASE_BASE}/{LINUX_BUILD.V8_CHECKSUM_NAME}"
                    ),
                    "v8_checksum_sha256": LINUX_BUILD.V8_CHECKSUM_SHA256,
                    "v8_archive_post_build_sha256": LINUX_BUILD.V8_ARCHIVE_SHA256,
                    "v8_binding_post_build_sha256": LINUX_BUILD.V8_BINDING_SHA256,
                    "v8_checksum_post_build_sha256": LINUX_BUILD.V8_CHECKSUM_SHA256,
                }
            ),
            binaries=(binary("codex", HASH), binary("codex-code-mode-host", OTHER_HASH)),
            process_proof=proof_v2(),
        )
    )

    assert current.payload.provenance.build_id == "linux-build-004"
    assert current.payload.process_proof.default_visible_tools == (
        ORDINARY_DEFAULT_VISIBLE_TOOLS_V1
    )
    assert LinuxNativeCodexBuildV4.model_validate_json(current.model_dump_json()) == current
    assert receipt().payload.provenance.build_id == "linux-build-001"

    forward = LinuxNativeCodexBuildV5.create(
        LinuxNativeCodexBuildPayloadV5(
            provenance=LinuxBuildProvenanceV5(
                **{
                    **current.payload.provenance.model_dump(mode="python"),
                    "build_id": "linux-build-005",
                }
            ),
            binaries=current.payload.binaries,
            process_proof=LinuxHostProofSummaryV3(
                **current.payload.process_proof.model_dump(mode="python"),
                runtime_scratch_cleanup_passed=True,
            ),
        )
    )
    assert forward.payload.provenance.build_id == "linux-build-005"
    assert forward.payload.process_proof.runtime_scratch_cleanup_passed is True
    assert LinuxNativeCodexBuildV5.model_validate_json(forward.model_dump_json()) == forward

    merged_main = LinuxNativeCodexBuildV6.create(
        LinuxNativeCodexBuildPayloadV6(
            provenance=LinuxBuildProvenanceV6(
                **{
                    **forward.payload.provenance.model_dump(mode="python"),
                    "build_id": "linux-build-006",
                }
            ),
            binaries=forward.payload.binaries,
            process_proof=forward.payload.process_proof,
        )
    )
    assert merged_main.payload.provenance.build_id == "linux-build-006"
    assert LinuxNativeCodexBuildV6.model_validate_json(merged_main.model_dump_json()) == merged_main

    bundled_main = LinuxNativeCodexBuildV7.create(
        LinuxNativeCodexBuildPayloadV7(
            provenance=LinuxBuildProvenanceV7(
                **{
                    **merged_main.payload.provenance.model_dump(mode="python"),
                    "build_id": "linux-build-007",
                    "workflow_run_id": 123,
                    "workflow_run_attempt": 1,
                }
            ),
            binaries=merged_main.payload.binaries,
            process_proof=merged_main.payload.process_proof,
        )
    )
    assert bundled_main.payload.provenance.build_id == "linux-build-007"
    assert bundled_main.payload.provenance.workflow_run_id == 123
    assert (
        LinuxNativeCodexBuildV7.model_validate_json(bundled_main.model_dump_json()) == bundled_main
    )


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
            build_environment={"RUSTY_V8_ARCHIVE": "/tmp/v8.a.gz"},
        )
    observed = json.loads(state_path.read_bytes())
    assert observed["phase"] == "cargo_start"
    assert observed["rust_compilation_started"] is False
    assert observed["compilation"] == "NOT_RUN"
    assert observed["process_proof"] is None


def test_pinned_v8_authority_requires_exact_module_and_sandbox_feature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "codex-rs"
    root.mkdir()
    module = tmp_path / "MODULE.bazel"
    content = (
        b'crate = "v8"\n'
        b'"x86_64-unknown-linux-gnu": ["v8_enable_sandbox"]\n'
        b'name = "v8_crate_150_4_0"\n'
        b'urls = ["https://static.crates.io/crates/v8/v8-150.4.0.crate"]\n'
    )
    module.write_bytes(content)
    monkeypatch.setattr(
        LINUX_BUILD, "CODEX_MODULE_BAZEL_SHA256", hashlib.sha256(content).hexdigest()
    )
    assert LINUX_BUILD._verify_pinned_v8_authority(root) == hashlib.sha256(content).hexdigest()
    module.write_bytes(content.replace(b"v8_enable_sandbox", b"v8_disable_sandbox"))
    monkeypatch.setattr(
        LINUX_BUILD, "CODEX_MODULE_BAZEL_SHA256", hashlib.sha256(module.read_bytes()).hexdigest()
    )
    with pytest.raises(ValueError, match="sandbox authority"):
        LINUX_BUILD._verify_pinned_v8_authority(root)


def test_exact_v8_download_is_bounded_and_hash_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = b"reviewed sandbox asset"

    class Response:
        def __init__(self, value: bytes, *, content_length: bool = True) -> None:
            self.remaining = value
            self.headers = {"Content-Length": str(len(value))} if content_length else {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, size: int) -> bytes:
            value, self.remaining = self.remaining[:size], self.remaining[size:]
            return value

    monkeypatch.setattr(
        LINUX_BUILD.urllib.request, "urlopen", lambda *_args, **_kwargs: Response(raw)
    )
    target = tmp_path / "asset"
    assert LINUX_BUILD._download_exact(
        "https://example.invalid/asset", target, hashlib.sha256(raw).hexdigest(), 64
    ) == len(raw)
    assert target.read_bytes() == raw
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        LINUX_BUILD._download_exact("https://example.invalid/asset", tmp_path / "bad", HASH, 64)
    assert not (tmp_path / "bad").exists()
    monkeypatch.setattr(
        LINUX_BUILD.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: Response(b"x" * 65, content_length=False),
    )
    with pytest.raises(ValueError, match="byte limit"):
        LINUX_BUILD._download_exact(
            "https://example.invalid/asset", tmp_path / "overflow", HASH, 64
        )
    assert not (tmp_path / "overflow").exists()


def test_v8_release_environment_requires_exact_three_assets_and_checksum_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source" / "codex-rs"
    root.mkdir(parents=True)
    output = tmp_path / "evidence"
    output.mkdir()
    monkeypatch.setattr(
        LINUX_BUILD,
        "_verify_pinned_v8_authority",
        lambda _root: LINUX_BUILD.CODEX_MODULE_BAZEL_SHA256,
    )
    calls: list[tuple[str, str, str, int]] = []

    def fake_download(url: str, destination: Path, sha256: str, limit: int) -> int:
        calls.append((url, destination.name, sha256, limit))
        if destination.name == LINUX_BUILD.V8_CHECKSUM_NAME:
            raw = (
                f"{LINUX_BUILD.V8_ARCHIVE_SHA256}  {LINUX_BUILD.V8_ARCHIVE_NAME}\n"
                f"{LINUX_BUILD.V8_BINDING_SHA256}  {LINUX_BUILD.V8_BINDING_NAME}\n"
            ).encode()
        else:
            raw = destination.name.encode()
        destination.write_bytes(raw)
        return len(raw)

    monkeypatch.setattr(LINUX_BUILD, "_download_exact", fake_download)
    environment, observed = LINUX_BUILD._v8_release_environment(root, output)

    assert [item[1] for item in calls] == [
        LINUX_BUILD.V8_CHECKSUM_NAME,
        LINUX_BUILD.V8_ARCHIVE_NAME,
        LINUX_BUILD.V8_BINDING_NAME,
    ]
    assert [item[2] for item in calls] == [
        LINUX_BUILD.V8_CHECKSUM_SHA256,
        LINUX_BUILD.V8_ARCHIVE_SHA256,
        LINUX_BUILD.V8_BINDING_SHA256,
    ]
    assert "V8_FROM_SOURCE" not in environment
    assert environment["RUSTY_V8_ARCHIVE_SHA256"] == LINUX_BUILD.V8_ARCHIVE_SHA256
    assert observed["sandbox_feature_enabled"] is True


def test_v8_release_environment_removes_assets_on_checksum_content_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source" / "codex-rs"
    root.mkdir(parents=True)
    output = tmp_path / "evidence"
    output.mkdir()
    monkeypatch.setattr(LINUX_BUILD, "_verify_pinned_v8_authority", lambda _root: HASH)

    def fake_download(_url: str, destination: Path, _sha256: str, _limit: int) -> int:
        destination.write_bytes(b"not the reviewed checksum manifest")
        return destination.stat().st_size

    monkeypatch.setattr(LINUX_BUILD, "_download_exact", fake_download)
    monkeypatch.setattr(
        LINUX_BUILD.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("Cargo must not start after checksum mismatch"),
    )
    with pytest.raises(ValueError, match="checksum manifest content mismatch"):
        LINUX_BUILD._v8_release_environment(root, output)
    assert not (output / "v8-release").exists()


@pytest.mark.parametrize(
    "mutated_name",
    (LINUX_BUILD.V8_ARCHIVE_NAME, LINUX_BUILD.V8_BINDING_NAME, LINUX_BUILD.V8_CHECKSUM_NAME),
)
def test_post_build_v8_rehash_rejects_each_mutated_asset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutated_name: str
) -> None:
    asset_dir = tmp_path / "v8-release"
    asset_dir.mkdir()
    contents = {
        LINUX_BUILD.V8_ARCHIVE_NAME: b"archive",
        LINUX_BUILD.V8_BINDING_NAME: b"binding",
        LINUX_BUILD.V8_CHECKSUM_NAME: b"checksum",
    }
    monkeypatch.setattr(
        LINUX_BUILD,
        "V8_ARCHIVE_SHA256",
        hashlib.sha256(contents[LINUX_BUILD.V8_ARCHIVE_NAME]).hexdigest(),
    )
    monkeypatch.setattr(
        LINUX_BUILD,
        "V8_BINDING_SHA256",
        hashlib.sha256(contents[LINUX_BUILD.V8_BINDING_NAME]).hexdigest(),
    )
    monkeypatch.setattr(
        LINUX_BUILD,
        "V8_CHECKSUM_SHA256",
        hashlib.sha256(contents[LINUX_BUILD.V8_CHECKSUM_NAME]).hexdigest(),
    )
    for name, value in contents.items():
        (asset_dir / name).write_bytes(value + (b"tampered" if name == mutated_name else b""))
    with pytest.raises(ValueError, match="changed during build"):
        LINUX_BUILD._rehash_v8_assets(tmp_path)


def test_post_build_v8_failure_records_exact_phase_and_preserves_compile_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state: dict[str, object] = {
        "status": "COMPILING",
        "phase": "cargo_compile",
        "rust_compilation_started": True,
        "compilation": "PASS",
        "process_proof": None,
    }
    state_path = tmp_path / "linux-build-result.json"

    def fail_rehash(_output: Path) -> dict[str, str]:
        raise ValueError("V8 release asset changed during build")

    monkeypatch.setattr(LINUX_BUILD, "_rehash_v8_assets", fail_rehash)
    try:
        LINUX_BUILD._verify_post_build_v8_assets(state, state_path, tmp_path)
    except ValueError as error:
        LINUX_BUILD._record_failure(state, state_path, error)
    observed = json.loads(state_path.read_bytes())
    assert observed["phase"] == observed["failure"]["phase"] == "v8_release_post_build"
    assert observed["rust_compilation_started"] is True
    assert observed["compilation"] == "PASS"
    assert observed["process_proof"] is None


def test_linux_workflow_reserves_build_007_for_merged_main_dispatch() -> None:
    workflow = (ROOT / ".github/workflows/linux-native-codex.yml").read_text(encoding="utf-8")
    assert "devfabric-linux-build-007-evidence" in workflow
    assert "devfabric-linux-build-007-binaries" in workflow
    assert "--platform linux" in workflow
    assert "--build-id linux-build-007" in workflow
    assert "pull_request:" not in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "--expected-implementation-commit '${{ github.sha }}'" in workflow
    assert "--workflow-run-id '${{ github.run_id }}'" in workflow
    assert "--workflow-run-attempt '${{ github.run_attempt }}'" in workflow
    assert "include-hidden-files: true" in workflow
    assert "if: always() && steps.seal.outcome == 'success'" in workflow
    assert "if: success()" in workflow
    assert "devfabric-linux-build-005" not in workflow


def test_linux_build_007_uses_complete_source_preparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "pinned-source"
    root = checkout / "codex-rs"
    root.mkdir(parents=True)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(checkout.parent))
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
    monkeypatch.setattr(LINUX_BUILD.retained, "ORIGINAL", hashlib.sha256(original).hexdigest())
    monkeypatch.setattr(
        LINUX_BUILD.retained,
        "PRODUCTION_HOST_LOCK_SHA256",
        hashlib.sha256(derived).hexdigest(),
    )
    monkeypatch.setattr(
        LINUX_BUILD.retained,
        "derive_production_host_lock",
        lambda candidate_root: (derived, [{"source": str(candidate_root)}]),
    )

    result = LINUX_BUILD.retained.prepare_build_source(
        root,
        candidate_patch=candidate,
        host_patch=host,
        build_id="linux-build-007",
    )

    assert (root / "candidate.txt").read_text(encoding="utf-8") == "candidate\n"
    assert (root / "host.txt").read_text(encoding="utf-8") == "host\n"
    assert result["candidate_patch_applied"] is True
    assert result["host_patch_applied"] is True
    assert result["lock_strategy"] == "complete_patched_manifest_bound_derived_lock"
    assert result["proof_cargo_lock_sha256"] == hashlib.sha256(derived).hexdigest()


def test_cargo_receives_reviewed_v8_release_environment(
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
                "RUSTY_V8_ARCHIVE": "/tmp/v8.a.gz",
                "RUSTY_V8_ARCHIVE_SHA256": LINUX_BUILD.V8_ARCHIVE_SHA256,
                "RUSTY_V8_SRC_BINDING_PATH": "/tmp/binding.rs",
            },
        )
        == 0
    )
    environment = captured["environment"]
    assert isinstance(environment, dict)
    assert "V8_FROM_SOURCE" not in environment
    assert environment["RUSTY_V8_ARCHIVE"] == "/tmp/v8.a.gz"
    assert environment["RUSTY_V8_ARCHIVE_SHA256"] == LINUX_BUILD.V8_ARCHIVE_SHA256
    assert environment["RUSTY_V8_SRC_BINDING_PATH"] == "/tmp/binding.rs"


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
    assert summary.default_visible_tools == ORDINARY_DEFAULT_VISIBLE_TOOLS_V1
    with pytest.raises(ValueError, match="exact sibling code-mode host"):
        LINUX_BUILD._proof_summary(
            process_proof_raw(),
            HASH,
            {**eof, "binary_sha256": "e" * 64},
            "d" * 64,
            host,
        )


def test_process_proof_runtime_scratch_is_external_cleaned_and_bound(tmp_path: Path) -> None:
    output = tmp_path / "sealed"
    output.mkdir()
    scratch = tmp_path / "runtime-scratch"

    def proof(**kwargs: object) -> dict[str, object]:
        observed = kwargs["runtime_home_root"]
        assert observed == scratch.absolute()
        assert not Path(observed).is_relative_to(output)
        home = Path(observed) / "arm-a"
        home.mkdir()
        (home / "runtime-created").write_bytes(b"transient")
        return {"model_requests": 0}

    result = LINUX_BUILD._process_proof_with_runtime_scratch(
        runtime_scratch=scratch,
        output=output,
        process_proof=proof,
    )

    assert result == {"model_requests": 0, "runtime_scratch_cleanup_passed": True}
    assert not scratch.exists()


def test_process_proof_runtime_scratch_rejects_overlap(tmp_path: Path) -> None:
    output = tmp_path / "sealed"
    output.mkdir()
    with pytest.raises(ValueError, match="overlaps sealed output"):
        LINUX_BUILD._process_proof_with_runtime_scratch(
            runtime_scratch=output / "runtime-scratch",
            output=output,
            process_proof=lambda **_kwargs: {},
        )


def test_process_proof_runtime_scratch_cleanup_failure_is_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "sealed"
    output.mkdir()
    scratch = tmp_path / "runtime-scratch"

    def cleanup_failure(_path: Path) -> None:
        raise OSError("injected cleanup failure")

    monkeypatch.setattr(LINUX_BUILD.shutil, "rmtree", cleanup_failure)
    with pytest.raises(OSError, match="injected cleanup failure"):
        LINUX_BUILD._process_proof_with_runtime_scratch(
            runtime_scratch=scratch,
            output=output,
            process_proof=lambda **_kwargs: {},
        )
    assert scratch.is_dir()


def test_process_proof_failure_preserves_error_after_successful_cleanup(tmp_path: Path) -> None:
    output = tmp_path / "sealed"
    output.mkdir()
    scratch = tmp_path / "runtime-scratch"
    failure = RuntimeError("injected proof failure")

    def proof(**_kwargs: object) -> dict[str, object]:
        (scratch / "arm-a").mkdir()
        raise failure

    with pytest.raises(RuntimeError, match="injected proof failure") as caught:
        LINUX_BUILD._process_proof_with_runtime_scratch(
            runtime_scratch=scratch,
            output=output,
            process_proof=proof,
        )
    assert caught.value is failure
    assert not scratch.exists()


def test_process_proof_and_cleanup_failure_preserve_both_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "sealed"
    output.mkdir()
    scratch = tmp_path / "runtime-scratch"

    def proof(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("injected proof failure")

    def cleanup_failure(_path: Path) -> None:
        raise OSError("injected cleanup failure")

    monkeypatch.setattr(LINUX_BUILD.shutil, "rmtree", cleanup_failure)
    with pytest.raises(ExceptionGroup, match="process proof and runtime cleanup failed") as caught:
        LINUX_BUILD._process_proof_with_runtime_scratch(
            runtime_scratch=scratch,
            output=output,
            process_proof=proof,
        )
    assert [str(error) for error in caught.value.exceptions] == [
        "injected proof failure",
        "injected cleanup failure",
    ]
    assert scratch.is_dir()


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
    assert LINUX_BUILD.BUILD_ID == "linux-build-007"
    assert LINUX_BUILD.retained.prepare_build_source is not None
    signature = inspect.signature(LINUX_BUILD.shared.process_proof)
    assert {"capture", "wait_pid_exit", "proof_env", "platform_label"} <= set(signature.parameters)
    candidate = (ROOT / "patches/stage3g-approved-call/candidate.patch").read_bytes()
    host = (ROOT / "patches/stage3g-approved-call/host-integration.patch").read_bytes()
    assert hashlib.sha256(candidate).hexdigest() == LINUX_BUILD.retained.CANDIDATE_SHA256
    assert hashlib.sha256(host).hexdigest() == LINUX_BUILD.retained.HOST_SHA256
    assert hashlib.sha256(candidate + host).hexdigest() == LINUX_BUILD.retained.COMBINED_SHA256


def test_linux_workflow_binds_exact_merged_main_pair_and_never_cancels() -> None:
    workflow = (ROOT / ".github/workflows/linux-native-codex.yml").read_text(encoding="utf-8")
    assert "ref: ${{ github.sha }}" in workflow
    assert "--expected-implementation-commit '${{ github.sha }}'" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "x86_64-unknown-linux-gnu" in workflow
    assert "scripts/build_linux_native_codex.py" in workflow
