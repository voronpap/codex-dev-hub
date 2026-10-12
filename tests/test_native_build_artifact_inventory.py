from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Literal

import pytest
from linux_native_artifact_support import linux_pass_artifact
from pydantic import ValidationError

from devhub.native_proof import (
    LinuxNativeBuildArtifactJoinV1,
    NativeBuildArtifactEntryV1,
    NativeBuildArtifactInventoryPayloadV1,
    NativeBuildArtifactInventoryPayloadV2,
    NativeBuildArtifactInventoryV1,
    NativeBuildArtifactInventoryV2,
    WindowsNativeBuildArtifactJoinV1,
)
from devhub.windows_native import (
    WindowsBuildProvenanceV7,
    WindowsHostProofSummaryV3,
    WindowsNativeBinaryV2,
    WindowsNativeCodexBuildPayloadV7,
    WindowsNativeCodexBuildV7,
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
        json.dumps({"build_id": "windows-build-008", "status": status}), encoding="utf-8"
    )


def _linux_result(
    root: Path,
    *,
    status: str = "FAIL",
    build_id: Literal[
        "linux-build-005", "linux-build-006", "linux-build-007", "linux-build-008"
    ] = ("linux-build-008"),
) -> None:
    (root / "linux-build-result.json").write_text(
        json.dumps({"build_id": build_id, "status": status}), encoding="utf-8"
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pass_artifact(root: Path) -> WindowsNativeCodexBuildV7:
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
    provenance = WindowsBuildProvenanceV7(
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
    receipt = WindowsNativeCodexBuildV7.create(
        WindowsNativeCodexBuildPayloadV7(
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
                "build_id": "windows-build-008",
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

    receipt = INVENTORY.seal_windows(tmp_path, "windows-build-008")

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

    receipt = INVENTORY.seal_windows(tmp_path, "windows-build-008")

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
        INVENTORY.seal_windows(tmp_path, "windows-build-008")


def test_linux_pass_inventory_exactly_joins_pair_proof_and_result(tmp_path: Path) -> None:
    pair = linux_pass_artifact(tmp_path)

    receipt = INVENTORY.seal_linux(tmp_path, "linux-build-008")

    assert receipt.payload.status == "PASS"
    assert receipt.payload.linux_pair is not None
    assert (
        receipt.payload.linux_pair.linux_native_codex_build_id == pair.linux_native_codex_build_id
    )
    assert receipt.payload.linux_pair.codex_sha256 == pair.payload.binaries[0].sha256
    assert receipt.payload.linux_pair.code_mode_host_sha256 == pair.payload.binaries[1].sha256
    assert tuple(item.relative_path for item in receipt.payload.files if item.kind == "binary") == (
        "binary/codex",
        "binary/codex-code-mode-host",
    )
    assert (
        NativeBuildArtifactInventoryV2.model_validate_json(
            (tmp_path / INVENTORY.INVENTORY_NAME).read_bytes()
        )
        == receipt
    )


def test_linux_build_005_inventory_remains_strictly_parseable(tmp_path: Path) -> None:
    pair = linux_pass_artifact(tmp_path, "linux-build-005")

    receipt = INVENTORY.seal_linux(tmp_path, "linux-build-005")

    assert receipt.payload.status == "PASS"
    assert receipt.payload.linux_pair is not None
    assert (
        receipt.payload.linux_pair.linux_native_codex_build_id == pair.linux_native_codex_build_id
    )


def test_linux_build_006_inventory_remains_strictly_parseable(tmp_path: Path) -> None:
    pair = linux_pass_artifact(tmp_path, "linux-build-006")

    receipt = INVENTORY.seal_linux(tmp_path, "linux-build-006")

    assert receipt.payload.status == "PASS"
    assert receipt.payload.linux_pair is not None
    assert (
        receipt.payload.linux_pair.linux_native_codex_build_id == pair.linux_native_codex_build_id
    )


def test_linux_build_007_inventory_remains_strictly_parseable(tmp_path: Path) -> None:
    pair = linux_pass_artifact(tmp_path, "linux-build-007")

    receipt = INVENTORY.seal_linux(tmp_path, "linux-build-007")

    assert receipt.payload.status == "PASS"
    assert receipt.payload.linux_pair is not None
    assert (
        receipt.payload.linux_pair.linux_native_codex_build_id == pair.linux_native_codex_build_id
    )


def test_linux_pass_inventory_rejects_binary_substitution(tmp_path: Path) -> None:
    linux_pass_artifact(tmp_path)
    (tmp_path / "binary/codex").write_bytes(b"substituted")

    with pytest.raises(ValueError, match="exact binary pair"):
        INVENTORY.seal_linux(tmp_path, "linux-build-008")


def test_linux_failure_projection_retains_hidden_evidence_and_excludes_binary(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    _linux_result(root)
    (root / "binary").mkdir()
    (root / "binary/codex").write_bytes(b"failed proof binary")
    hidden = root / "process-proof/arm-a/observer/.hidden-state.json"
    hidden.parent.mkdir(parents=True)
    hidden.write_bytes(b"hidden evidence")
    lock = root / "process-proof/arm-a/observer/.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_bytes(b"locked")

    inventory = INVENTORY.seal_linux(root, "linux-build-008")
    projection = tmp_path / "projection"
    members = INVENTORY.project_linux_evidence(root, projection, inventory)

    assert inventory.payload.status == "FAIL"
    assert inventory.payload.linux_pair is None
    assert members == (
        "linux-build-result.json",
        INVENTORY.INVENTORY_NAME,
        "process-proof/arm-a/observer/.hidden-state.json",
        "process-proof/arm-a/observer/.lock",
    )
    assert not (projection / "binary/codex").exists()
    assert INVENTORY.verify_linux_evidence_projection(projection, inventory) == members


def test_inventory_v2_rejects_cross_platform_pair_authority() -> None:
    entry = NativeBuildArtifactEntryV1(
        relative_path="linux-build-result.json",
        kind="evidence",
        size=1,
        sha256="8" * 64,
    )
    windows_pair = WindowsNativeBuildArtifactJoinV1(
        build_receipt_sha256="2" * 64,
        windows_native_codex_build_id="3" * 64,
        codex_sha256="4" * 64,
        code_mode_host_sha256="5" * 64,
        process_proof_sha256="6" * 64,
        code_mode_host_eof_receipt_sha256="7" * 64,
    )
    linux_pair = LinuxNativeBuildArtifactJoinV1(
        build_receipt_sha256="2" * 64,
        linux_native_codex_build_id="3" * 64,
        codex_sha256="4" * 64,
        code_mode_host_sha256="5" * 64,
        process_proof_sha256="6" * 64,
        code_mode_host_eof_receipt_sha256="7" * 64,
    )

    with pytest.raises(ValidationError, match="Windows pair authority cannot be used by Linux"):
        NativeBuildArtifactInventoryPayloadV2(
            platform="linux",
            build_id="linux-build-004",
            status="PASS",
            build_result_sha256="1" * 64,
            windows_pair=windows_pair,
            linux_pair=linux_pair,
            files=(entry,),
        )
    with pytest.raises(ValidationError, match="Linux pair authority cannot be used by Windows"):
        NativeBuildArtifactInventoryPayloadV2(
            platform="windows",
            build_id="windows-build-006",
            status="PASS",
            build_result_sha256="1" * 64,
            windows_pair=windows_pair,
            linux_pair=linux_pair,
            files=(entry.model_copy(update={"relative_path": "windows-build-result.json"}),),
        )


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
        INVENTORY.seal_windows(tmp_path, "windows-build-008")


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
        INVENTORY.seal_windows(tmp_path, "windows-build-008")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation requires Unix")
def test_linux_build_inventory_rejects_special_file_with_bounded_path(tmp_path: Path) -> None:
    _linux_result(tmp_path)
    (tmp_path / "process-proof").mkdir()
    fifo = tmp_path / "process-proof/runtime.pipe"
    os.mkfifo(fifo)

    with pytest.raises(
        ValueError,
        match=r"plain regular files: process-proof/runtime\.pipe$",
    ):
        INVENTORY.seal_linux(tmp_path, "linux-build-008")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation requires Unix")
def test_nonplain_path_diagnostic_is_ascii_escaped_and_bounded(tmp_path: Path) -> None:
    special = tmp_path / ("line\nbreak-" + "x" * 180)
    os.mkfifo(special)

    with pytest.raises(ValueError) as caught:
        INVENTORY._plain_file(special, relative_path=special.name)

    message = str(caught.value)
    assert "line\\nbreak" in message
    assert "\n" not in message
    assert "path_sha256=" in message
    assert message.isascii()
    assert len(message) <= 220


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
        INVENTORY.seal_windows(link, "windows-build-008")


def test_windows_build_inventory_refuses_overwrite(tmp_path: Path) -> None:
    _result(tmp_path)
    INVENTORY.seal_windows(tmp_path, "windows-build-008")

    with pytest.raises(FileExistsError):
        INVENTORY.seal_windows(tmp_path, "windows-build-008")


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
        INVENTORY.seal_windows(tmp_path, "windows-build-008")
    assert outside.read_bytes() == b"do not replace"


def test_windows_build_inventory_atomic_failure_never_publishes_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _result(tmp_path)

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("simulated interrupted publish")

    monkeypatch.setattr("devhub.experiment_launch.os.replace", fail_replace)
    with pytest.raises(OSError, match="interrupted publish"):
        INVENTORY.seal_windows(tmp_path, "windows-build-008")
    assert not (tmp_path / INVENTORY.INVENTORY_NAME).exists()
    assert (tmp_path / f"{INVENTORY.INVENTORY_NAME}.tmp").is_file()


def test_windows_failure_inventory_keeps_binary_classification_separate(tmp_path: Path) -> None:
    _result(tmp_path)
    (tmp_path / "binary").mkdir()
    (tmp_path / "binary/codex.exe").write_bytes(b"failed proof binary")

    receipt = INVENTORY.seal_windows(tmp_path, "windows-build-008")

    assert receipt.payload.status == "FAIL"
    assert tuple(item.kind for item in receipt.payload.files) == ("binary", "evidence")
    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/windows-native-qualification.yml"
    ).read_text(encoding="utf-8")
    assert "--evidence-projection C:\\dfw003\\u\\evidence" in workflow
    assert "path: C:/dfw003/u/evidence/**" in workflow
    assert "include-hidden-files: true" in workflow
    assert "if: always() && steps.seal.outcome == 'success'" in workflow
    assert "Upload exact successful Windows executable pair" in workflow
    assert "if: success()" in workflow
    assert "C:/dfw003/e/windows-process-proof.json" in workflow
    assert "C:/dfw003/e/code-mode-host-eof.json" in workflow


def test_windows_evidence_projection_contains_every_hidden_inventory_member(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    _result(root)
    (root / "binary").mkdir()
    (root / "binary/codex.exe").write_bytes(b"not evidence")
    hidden = root / "process-proof/arm-a/codex home/skills/.system/SKILL.md"
    hidden.parent.mkdir(parents=True)
    hidden.write_bytes(b"hidden evidence")
    lock = root / "process-proof/arm-a/codex home/tmp/arg0/session/.lock"
    lock.parent.mkdir(parents=True)
    lock.write_bytes(b"locked")
    inventory = INVENTORY.seal_windows(root, "windows-build-008")

    projection = tmp_path / "projection"
    members = INVENTORY.project_windows_evidence(root, projection, inventory)

    assert members == (
        INVENTORY.INVENTORY_NAME,
        "process-proof/arm-a/codex home/skills/.system/SKILL.md",
        "process-proof/arm-a/codex home/tmp/arg0/session/.lock",
        "windows-build-result.json",
    )
    assert not (projection / "binary/codex.exe").exists()
    assert INVENTORY.verify_windows_evidence_projection(projection, inventory) == members


def test_windows_evidence_projection_rejects_missing_hidden_member(tmp_path: Path) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    _result(root)
    hidden = root / "process-proof/default/codex home/.tmp/plugins.sync.lock"
    hidden.parent.mkdir(parents=True)
    hidden.write_bytes(b"hidden evidence")
    inventory = INVENTORY.seal_windows(root, "windows-build-008")
    projection = tmp_path / "projection"
    INVENTORY.project_windows_evidence(root, projection, inventory)
    (projection / hidden.relative_to(root)).unlink()

    with pytest.raises(ValueError, match="member set differs"):
        INVENTORY.verify_windows_evidence_projection(projection, inventory)


def test_windows_evidence_projection_rejects_overlap_without_source_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    _result(root)
    evidence = root / "process-proof/default/receipt.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"sealed")
    inventory = INVENTORY.seal_windows(root, "windows-build-008")
    before = INVENTORY.inventory_windows(root)
    destination = root / "projection"

    with pytest.raises(ValueError, match="outside the sealed build root"):
        INVENTORY.project_windows_evidence(root, destination, inventory)

    assert not destination.exists()
    assert INVENTORY.inventory_windows(root) == before


def test_windows_evidence_projection_rejects_linked_parent(tmp_path: Path) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    _result(root)
    inventory = INVENTORY.seal_windows(root, "windows-build-008")
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("current host cannot create test directory symlinks")

    with pytest.raises(ValueError, match="plain directory"):
        INVENTORY.project_windows_evidence(root, linked_parent / "projection", inventory)

    assert not (real_parent / "projection").exists()


@pytest.mark.parametrize("failure_stage", ("copy", "verify", "publish", "post_publish"))
def test_windows_evidence_projection_failure_leaves_no_published_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    _result(root)
    inventory = INVENTORY.seal_windows(root, "windows-build-008")
    destination = tmp_path / "projection"
    original_verify = INVENTORY.verify_windows_evidence_projection

    if failure_stage == "copy":
        monkeypatch.setattr(
            INVENTORY.shutil,
            "copyfile",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("copy failed")),
        )
    elif failure_stage == "verify":
        monkeypatch.setattr(
            INVENTORY,
            "verify_windows_evidence_projection",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("verify failed")),
        )
    elif failure_stage == "publish":
        monkeypatch.setattr(
            INVENTORY.os,
            "replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("publish failed")),
        )
    else:
        calls = 0

        def fail_after_publish(*args: object, **kwargs: object) -> tuple[str, ...]:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise ValueError("post-publish verification failed")
            return original_verify(*args, **kwargs)

        monkeypatch.setattr(INVENTORY, "verify_windows_evidence_projection", fail_after_publish)

    with pytest.raises((OSError, ValueError), match="failed"):
        INVENTORY.project_windows_evidence(root, destination, inventory)

    assert not destination.exists()
    assert not destination.with_name(destination.name + ".tmp").exists()


def test_windows_evidence_projection_reports_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    _result(root)
    inventory = INVENTORY.seal_windows(root, "windows-build-008")
    destination = tmp_path / "projection"
    monkeypatch.setattr(
        INVENTORY.shutil,
        "copyfile",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("copy failed")),
    )
    monkeypatch.setattr(
        INVENTORY,
        "_remove_projection_tree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cleanup failed")),
    )

    with pytest.raises(RuntimeError, match="cleanup failed"):
        INVENTORY.project_windows_evidence(root, destination, inventory)

    assert not destination.exists()
