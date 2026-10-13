from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from devhub.linux_native import (
    LinuxBuildProvenanceV5,
    LinuxBuildProvenanceV6,
    LinuxBuildProvenanceV7,
    LinuxBuildProvenanceV8,
    LinuxBuildProvenanceV9,
    LinuxBuildProvenanceV10,
    LinuxElfIdentityV1,
    LinuxHostProofSummaryV3,
    LinuxNativeBinaryV1,
    LinuxNativeCodexBuildPayloadV5,
    LinuxNativeCodexBuildPayloadV6,
    LinuxNativeCodexBuildPayloadV7,
    LinuxNativeCodexBuildPayloadV8,
    LinuxNativeCodexBuildPayloadV9,
    LinuxNativeCodexBuildPayloadV10,
    LinuxNativeCodexBuildV5,
    LinuxNativeCodexBuildV6,
    LinuxNativeCodexBuildV7,
    LinuxNativeCodexBuildV8,
    LinuxNativeCodexBuildV9,
    LinuxNativeCodexBuildV10,
)

LinuxBuildId = Literal[
    "linux-build-005",
    "linux-build-006",
    "linux-build-007",
    "linux-build-008",
    "linux-build-009",
    "linux-build-010",
]
LinuxBuildReceipt = (
    LinuxNativeCodexBuildV5
    | LinuxNativeCodexBuildV6
    | LinuxNativeCodexBuildV7
    | LinuxNativeCodexBuildV8
    | LinuxNativeCodexBuildV9
    | LinuxNativeCodexBuildV10
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def linux_pass_artifact(
    root: Path,
    build_id: LinuxBuildId = "linux-build-010",
    *,
    implementation_commit: str = "a" * 40,
    workflow_run_id: int = 123,
    workflow_run_attempt: int = 1,
) -> LinuxBuildReceipt:
    """Materialize a complete retained Linux PASS artifact for strict join tests."""

    root.mkdir(parents=True, exist_ok=True)
    binary = root / "binary"
    binary.mkdir()
    codex_path = binary / "codex"
    host_path = binary / "codex-code-mode-host"
    codex_path.write_bytes(b"exact linux codex")
    host_path.write_bytes(b"exact linux code mode host")
    proof_path = root / "linux-process-proof.json"
    eof_path = root / "code-mode-host-eof.json"
    proof_path.write_bytes(b'{"proof":"pass"}\n')
    eof_path.write_bytes(b'{"eof":"pass"}\n')
    elf = LinuxElfIdentityV1(
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed=("libc.so.6",),
        required_symbol_versions=("GLIBC_2.34",),
    )
    codex = LinuxNativeBinaryV1(
        role="codex",
        relative_path="binary/codex",
        sha256=_sha256(codex_path),
        size=codex_path.stat().st_size,
        elf=elf,
        identity_output_sha256="1" * 64,
    )
    host = LinuxNativeBinaryV1(
        role="codex-code-mode-host",
        relative_path="binary/codex-code-mode-host",
        sha256=_sha256(host_path),
        size=host_path.stat().st_size,
        elf=elf,
        identity_output_sha256="2" * 64,
    )
    provenance_fields: dict[str, str] = dict(
        implementation_commit=implementation_commit,
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
        rustc_version="rustc 1.95.0",
        cargo_version="cargo 1.95.0",
        rustc_sha256="b" * 64,
        cargo_sha256="c" * 64,
        build_script_sha256="d" * 64,
        shared_proof_script_sha256="e" * 64,
        workflow_sha256="f" * 64,
        codex_module_bazel_sha256=(
            "1a6c8685d241a5390ff94432581e842c2950cbe5262b47b27d8db467cebec4c2"
        ),
        v8_archive_url=(
            "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
            "librusty_v8_ptrcomp_sandbox_release_x86_64-unknown-linux-gnu.a.gz"
        ),
        v8_archive_sha256="a35c75d1f26e6a983885a45b33490a4ebe54f05050568b32b89cfb421b30b583",
        v8_binding_url=(
            "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
            "src_binding_ptrcomp_sandbox_release_x86_64-unknown-linux-gnu.rs"
        ),
        v8_binding_sha256="7727826ae479bdb645e807239fb12d1f8e2e23de7a6cf16f5ee592690d1d8506",
        v8_checksum_url=(
            "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
            "rusty_v8_ptrcomp_sandbox_release_x86_64-unknown-linux-gnu.sha256"
        ),
        v8_checksum_sha256="6774b42c9424c098c72a805c08d4e94be17c591cf02b1dc2633060255a8a61be",
        v8_archive_post_build_sha256=(
            "a35c75d1f26e6a983885a45b33490a4ebe54f05050568b32b89cfb421b30b583"
        ),
        v8_binding_post_build_sha256=(
            "7727826ae479bdb645e807239fb12d1f8e2e23de7a6cf16f5ee592690d1d8506"
        ),
        v8_checksum_post_build_sha256=(
            "6774b42c9424c098c72a805c08d4e94be17c591cf02b1dc2633060255a8a61be"
        ),
    )
    proof = LinuxHostProofSummaryV3(
        process_proof_sha256=_sha256(proof_path),
        code_mode_host_sha256=host.sha256,
        code_mode_host_eof_receipt_sha256=_sha256(eof_path),
    )
    if build_id == "linux-build-005":
        receipt: LinuxBuildReceipt = LinuxNativeCodexBuildV5.create(
            LinuxNativeCodexBuildPayloadV5(
                provenance=LinuxBuildProvenanceV5(**provenance_fields),
                binaries=(codex, host),
                process_proof=proof,
            )
        )
    elif build_id == "linux-build-006":
        receipt = LinuxNativeCodexBuildV6.create(
            LinuxNativeCodexBuildPayloadV6(
                provenance=LinuxBuildProvenanceV6(**provenance_fields),
                binaries=(codex, host),
                process_proof=proof,
            )
        )
    elif build_id == "linux-build-007":
        receipt = LinuxNativeCodexBuildV7.create(
            LinuxNativeCodexBuildPayloadV7(
                provenance=LinuxBuildProvenanceV7(
                    **provenance_fields,
                    workflow_run_id=workflow_run_id,
                    workflow_run_attempt=workflow_run_attempt,
                ),
                binaries=(codex, host),
                process_proof=proof,
            )
        )
    elif build_id == "linux-build-008":
        receipt = LinuxNativeCodexBuildV8.create(
            LinuxNativeCodexBuildPayloadV8(
                provenance=LinuxBuildProvenanceV8(
                    **provenance_fields,
                    workflow_run_id=workflow_run_id,
                    workflow_run_attempt=workflow_run_attempt,
                ),
                binaries=(codex, host),
                process_proof=proof,
            )
        )
    elif build_id == "linux-build-009":
        receipt = LinuxNativeCodexBuildV9.create(
            LinuxNativeCodexBuildPayloadV9(
                provenance=LinuxBuildProvenanceV9(
                    **provenance_fields,
                    workflow_run_id=workflow_run_id,
                    workflow_run_attempt=workflow_run_attempt,
                ),
                binaries=(codex, host),
                process_proof=proof,
            )
        )
    else:
        receipt = LinuxNativeCodexBuildV10.create(
            LinuxNativeCodexBuildPayloadV10(
                provenance=LinuxBuildProvenanceV10(
                    **provenance_fields,
                    workflow_run_id=workflow_run_id,
                    workflow_run_attempt=workflow_run_attempt,
                ),
                binaries=(codex, host),
                process_proof=proof,
            )
        )
    (root / "linux-native-codex-build.json").write_text(
        receipt.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (root / "linux-build-result.json").write_text(
        json.dumps(
            {
                "build_id": build_id,
                "status": "PASS",
                "linux_native_codex_build_id": receipt.linux_native_codex_build_id,
                "executable_sha256": codex.sha256,
                "code_mode_host_sha256": host.sha256,
            }
        ),
        encoding="utf-8",
    )
    return receipt
