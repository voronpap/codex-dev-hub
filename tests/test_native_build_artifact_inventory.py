from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.native_proof import (
    NativeBuildArtifactEntryV1,
    NativeBuildArtifactInventoryPayloadV1,
    NativeBuildArtifactInventoryV1,
    WindowsNativeBuildArtifactJoinV1,
)
from devhub.windows_native import (
    WindowsBuildProvenanceV4,
    WindowsHostProofSummaryV3,
    WindowsNativeBinaryV2,
    WindowsNativeCodexBuildPayloadV4,
    WindowsNativeCodexBuildV4,
    WindowsPeIdentityV1,
)

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "inventory_native_build_artifact", SCRIPTS / "inventory_native_build_artifact.py"
)
assert SPEC is not None and SPEC.loader is not None
INVENTORY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INVENTORY
SPEC.loader.exec_module(INVENTORY)


def _result(root: Path, *, status: str = "FAIL") -> None:
    (root / "windows-build-result.json").write_text(
        json.dumps({"build_id": "windows-build-005", "status": status}), encoding="utf-8"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pass_artifact(root: Path) -> WindowsNativeCodexBuildV4:
    binary = root / "binary"
    binary.mkdir()
    codex_path = binary / "codex.exe"
    host_path = binary / "codex-code-mode-host.exe"
    codex_path.write_bytes(b"exact codex")
    host_path.write_bytes(b"exact code mode host")
    proof_path = root / "windows-process-proof.json"
    eof_path = root / "code-mode-host-eof.json"
    proof_path.write_bytes(b'{"proof":"pass"}\n')
    eof_path.write_bytes(b'{"eof":"pass"}\n')
    pe = WindowsPeIdentityV1(dll_characteristics=0x8160)
    codex = WindowsNativeBinaryV2(
        role="codex",
        relative_path="binary/codex.exe",
        sha256=_sha256(codex_path),
        size=codex_path.stat().st_size,
        pe=pe,
    )
    host = WindowsNativeBinaryV2(
        role="codex-code-mode-host",
        relative_path="binary/codex-code-mode-host.exe",
        sha256=_sha256(host_path),
        size=host_path.stat().st_size,
        pe=pe,
    )
    provenance = WindowsBuildProvenanceV4(
        workflow_run_id=1,
        workflow_run_attempt=1,
        implementation_commit="a" * 40,
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
            "rusty_v8_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.lib.gz"
        ),
        v8_archive_sha256="732ec5da4243aa166799780c8519a5eea6f32f6e47657a323342794dc3c239d6",
        v8_binding_url=(
            "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
            "src_binding_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.rs"
        ),
        v8_binding_sha256="dabf78ba1faac127660db9862b1d0354175c71b8db2d4fcb5bacbd9c93576b16",
        v8_checksum_url=(
            "https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/"
            "rusty_v8_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.sha256"
        ),
        v8_checksum_sha256="a4d6221dddb4b5724b23411eaac47caf6095489fbf9d126f65b33cef96a0a8ef",
        v8_archive_post_build_sha256=(
            "732ec5da4243aa166799780c8519a5eea6f32f6e47657a323342794dc3c239d6"
        ),
        v8_binding_post_build_sha256=(
            "dabf78ba1faac127660db9862b1d0354175c71b8db2d4fcb5bacbd9c93576b16"
        ),
        v8_checksum_post_build_sha256=(
            "a4d6221dddb4b5724b23411eaac47caf6095489fbf9d126f65b33cef96a0a8ef"
        ),
    )
    proof = WindowsHostProofSummaryV3(
        process_proof_sha256=_sha256(proof_path),
        code_mode_host_sha256=host.sha256,
        code_mode_host_eof_receipt_sha256=_sha256(eof_path),
    )
    receipt = WindowsNativeCodexBuildV4.create(
        WindowsNativeCodexBuildPayloadV4(
            provenance=provenance,
            binaries=(codex, host),
            process_proof=proof,
        )
    )
    (root / "windows-native-codex-build.json").write_text(
        receipt.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (root / "windows-build-result.json").write_text(
        json.dumps(
            {
                "build_id": "windows-build-005",
                "status": "PASS",
                "windows_native_codex_build_id": receipt.windows_native_codex_build_id,
                "executable_sha256": codex.sha256,
                "code_mode_host_sha256": host.sha256,
            }
        ),
        encoding="utf-8",
    )
    return receipt


def test_windows_build_inventory_is_sorted_content_bound_and_self_hashed(tmp_path: Path) -> None:
    _result(tmp_path)
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets/z.json").write_bytes(b"z")
    (tmp_path / "binary").mkdir()
    (tmp_path / "binary/codex.exe").write_bytes(b"codex")

    receipt = INVENTORY.seal_windows(tmp_path, "windows-build-005")

    assert [item.relative_path for item in receipt.payload.files] == [
        "assets/z.json",
        "binary/codex.exe",
        "windows-build-result.json",
    ]
    assert [item.kind for item in receipt.payload.files] == ["evidence", "binary", "evidence"]
    assert (
        NativeBuildArtifactInventoryV1.model_validate_json(
            (tmp_path / INVENTORY.INVENTORY_NAME).read_bytes()
        )
        == receipt
    )

    changed = receipt.model_dump(mode="python")
    changed["payload"]["files"][0]["sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="inventory ID mismatch"):
        NativeBuildArtifactInventoryV1.model_validate(changed)


def test_windows_pass_inventory_exactly_joins_pair_proof_and_result(tmp_path: Path) -> None:
    pair = _pass_artifact(tmp_path)

    receipt = INVENTORY.seal_windows(tmp_path, "windows-build-005")

    assert receipt.payload.status == "PASS"
    assert receipt.payload.windows_pair is not None
    assert (
        receipt.payload.windows_pair.windows_native_codex_build_id
        == pair.windows_native_codex_build_id
    )
    assert receipt.payload.windows_pair.codex_sha256 == pair.payload.binaries[0].sha256
    assert receipt.payload.windows_pair.code_mode_host_sha256 == pair.payload.binaries[1].sha256
    assert tuple(item.relative_path for item in receipt.payload.files if item.kind == "binary") == (
        "binary/codex-code-mode-host.exe",
        "binary/codex.exe",
    )


def test_windows_pass_inventory_rejects_binary_substitution(tmp_path: Path) -> None:
    _pass_artifact(tmp_path)
    (tmp_path / "binary/codex.exe").write_bytes(b"substituted")

    with pytest.raises(ValueError, match="exact binary pair"):
        INVENTORY.seal_windows(tmp_path, "windows-build-005")


def test_linux_inventory_rejects_windows_pair_authority() -> None:
    with pytest.raises(ValidationError, match="cannot be used by another platform"):
        NativeBuildArtifactInventoryPayloadV1(
            platform="linux",
            build_id="linux-build-004",
            status="PASS",
            build_result_sha256="1" * 64,
            windows_pair=WindowsNativeBuildArtifactJoinV1(
                build_receipt_sha256="2" * 64,
                windows_native_codex_build_id="3" * 64,
                codex_sha256="4" * 64,
                code_mode_host_sha256="5" * 64,
                process_proof_sha256="6" * 64,
                code_mode_host_eof_receipt_sha256="7" * 64,
            ),
            files=(
                NativeBuildArtifactEntryV1(
                    relative_path="linux-build-result.json",
                    kind="evidence",
                    size=1,
                    sha256="8" * 64,
                ),
            ),
        )


def test_windows_build_inventory_rejects_unknown_root_entry(tmp_path: Path) -> None:
    _result(tmp_path)
    (tmp_path / "unexpected.txt").write_bytes(b"not allowlisted")

    with pytest.raises(ValueError, match="unknown root file"):
        INVENTORY.seal_windows(tmp_path, "windows-build-005")


def test_windows_build_inventory_rejects_linked_entry(tmp_path: Path) -> None:
    _result(tmp_path)
    (tmp_path / "assets").mkdir()
    target = tmp_path / "outside"
    target.write_bytes(b"outside")
    link = tmp_path / "assets/link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("current host cannot create test symlinks")

    with pytest.raises(ValueError, match="plain regular files"):
        INVENTORY.seal_windows(tmp_path, "windows-build-005")


def test_windows_build_inventory_rejects_linked_root(tmp_path: Path) -> None:
    root = tmp_path / "real"
    root.mkdir()
    _result(root)
    link = tmp_path / "linked"
    try:
        link.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("current host cannot create test symlinks")

    with pytest.raises(ValueError, match="plain directory"):
        INVENTORY.seal_windows(link, "windows-build-005")


def test_windows_build_inventory_refuses_overwrite(tmp_path: Path) -> None:
    _result(tmp_path)
    INVENTORY.seal_windows(tmp_path, "windows-build-005")

    with pytest.raises(FileExistsError):
        INVENTORY.seal_windows(tmp_path, "windows-build-005")


def test_windows_build_inventory_refuses_preexisting_link_destination(tmp_path: Path) -> None:
    _result(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"do not replace")
    destination = tmp_path / INVENTORY.INVENTORY_NAME
    try:
        destination.symlink_to(outside)
    except OSError:
        pytest.skip("current host cannot create test symlinks")

    with pytest.raises(FileExistsError):
        INVENTORY.seal_windows(tmp_path, "windows-build-005")
    assert outside.read_bytes() == b"do not replace"


def test_windows_build_inventory_atomic_failure_never_publishes_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _result(tmp_path)

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("simulated interrupted publish")

    monkeypatch.setattr("devhub.experiment_launch.os.replace", fail_replace)
    with pytest.raises(OSError, match="interrupted publish"):
        INVENTORY.seal_windows(tmp_path, "windows-build-005")
    assert not (tmp_path / INVENTORY.INVENTORY_NAME).exists()
    assert (tmp_path / f"{INVENTORY.INVENTORY_NAME}.tmp").is_file()


def test_windows_failure_inventory_keeps_binary_classification_separate(tmp_path: Path) -> None:
    _result(tmp_path)
    (tmp_path / "binary").mkdir()
    (tmp_path / "binary/codex.exe").write_bytes(b"failed proof binary")

    receipt = INVENTORY.seal_windows(tmp_path, "windows-build-005")

    assert receipt.payload.status == "FAIL"
    assert tuple(item.kind for item in receipt.payload.files) == ("binary", "evidence")
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/windows-native-qualification.yml"
    ).read_text(encoding="utf-8")
    assert "!C:/dfw003/e/binary/**" in workflow
    assert "if: always() && steps.seal.outcome == 'success'" in workflow
    assert "Upload exact successful Windows executable pair" in workflow
    assert "if: success()" in workflow
    assert "C:/dfw003/e/windows-process-proof.json" in workflow
    assert "C:/dfw003/e/code-mode-host-eof.json" in workflow
