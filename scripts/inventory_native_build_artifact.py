"""Seal a bounded native-build output inventory before CI artifact upload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

from devhub.experiment_launch import durable_publish
from devhub.native_proof import (
    NativeBuildArtifactEntryV1,
    NativeBuildArtifactInventoryPayloadV1,
    NativeBuildArtifactInventoryV1,
    WindowsNativeBuildArtifactJoinV1,
)
from devhub.windows_native import WindowsNativeCodexBuildV4

INVENTORY_NAME = "native-build-artifact-inventory.json"
WINDOWS_ROOT_FILES = frozenset(
    {
        "build.stderr",
        "build.stdout",
        "cargo-fetch.stderr",
        "cargo-fetch.stdout",
        "cargo-fmt.stderr",
        "cargo-fmt.stdout",
        "cargo-metadata.stderr",
        "cargo-metadata.stdout",
        "Cargo.lock.original",
        "Cargo.lock.proof",
        "code-mode-host-eof.json",
        "derived-lock-manifest-bindings.json",
        "runner-manifest.json",
        "windows-build-result.json",
        "windows-native-codex-build.json",
        "windows-process-proof.json",
    }
)
WINDOWS_ROOT_DIRECTORIES = frozenset({"assets", "binary", "process-proof", "v8-release"})


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _plain_file(path: Path) -> os.stat_result:
    result = path.lstat()
    reparse = getattr(result, "st_file_attributes", 0) & 0x400
    if path.is_symlink() or reparse or not stat.S_ISREG(result.st_mode):
        raise ValueError("Native build artifact entries must be plain regular files")
    return result


def _validate_root(root: Path) -> Path:
    lexical_root = root.absolute()
    result = lexical_root.lstat()
    reparse = getattr(result, "st_file_attributes", 0) & 0x400
    if lexical_root.is_symlink() or reparse or not stat.S_ISDIR(result.st_mode):
        raise ValueError("Native build artifact root must be a plain directory")
    return lexical_root.resolve(strict=True)


def inventory_windows(root: Path) -> tuple[NativeBuildArtifactEntryV1, ...]:
    root = _validate_root(root)
    entries: list[NativeBuildArtifactEntryV1] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        top = relative.split("/", 1)[0]
        if path.is_dir():
            result = path.lstat()
            if path.is_symlink() or getattr(result, "st_file_attributes", 0) & 0x400:
                raise ValueError("Native build artifact contains a linked directory")
            if top not in WINDOWS_ROOT_DIRECTORIES:
                raise ValueError("Windows native build artifact contains an unknown directory")
            continue
        if relative == INVENTORY_NAME:
            continue
        if "/" not in relative and relative not in WINDOWS_ROOT_FILES:
            raise ValueError("Windows native build artifact contains an unknown root file")
        if "/" in relative and top not in WINDOWS_ROOT_DIRECTORIES:
            raise ValueError("Windows native build artifact contains an unknown file tree")
        result = _plain_file(path)
        entries.append(
            NativeBuildArtifactEntryV1(
                relative_path=relative,
                kind="binary" if top == "binary" else "evidence",
                size=result.st_size,
                sha256=_sha256(path),
            )
        )
    return tuple(entries)


def seal_windows(root: Path, build_id: str) -> NativeBuildArtifactInventoryV1:
    root = _validate_root(root)
    destination = root / INVENTORY_NAME
    temporary = destination.with_name(destination.name + ".tmp")
    for unpublished in (destination, temporary):
        try:
            unpublished.lstat()
        except FileNotFoundError:
            continue
        raise FileExistsError(unpublished)
    result_path = root / "windows-build-result.json"
    result_stat = _plain_file(result_path)
    if result_stat.st_size > 1024 * 1024:
        raise ValueError("Windows native build result exceeds its size bound")
    result = json.loads(result_path.read_bytes())
    if not isinstance(result, dict) or result.get("build_id") != build_id:
        raise ValueError("Windows native build result identity differs")
    status = result.get("status")
    if status not in {"PASS", "FAIL"}:
        raise ValueError("Windows native build result is not terminal")
    files = inventory_windows(root)
    windows_pair = None
    if status == "PASS":
        receipt_path = root / "windows-native-codex-build.json"
        receipt_stat = _plain_file(receipt_path)
        if receipt_stat.st_size > 256 * 1024:
            raise ValueError("Windows native build receipt exceeds its size bound")
        receipt = WindowsNativeCodexBuildV4.model_validate_json(receipt_path.read_bytes())
        if receipt.payload.provenance.build_id != build_id:
            raise ValueError("Windows native build receipt identity differs")
        binary_by_role = {item.role: item for item in receipt.payload.binaries}
        codex = binary_by_role["codex"]
        host = binary_by_role["codex-code-mode-host"]
        expected_binaries = {
            codex.relative_path: (codex.size, codex.sha256),
            host.relative_path: (host.size, host.sha256),
        }
        observed_binaries = {
            item.relative_path: (item.size, item.sha256) for item in files if item.kind == "binary"
        }
        if observed_binaries != expected_binaries:
            raise ValueError("Windows native build inventory differs from the exact binary pair")
        proof = receipt.payload.process_proof
        proof_path = root / "windows-process-proof.json"
        eof_path = root / "code-mode-host-eof.json"
        if (
            _sha256(proof_path) != proof.process_proof_sha256
            or _sha256(eof_path) != proof.code_mode_host_eof_receipt_sha256
            or result.get("windows_native_codex_build_id") != receipt.windows_native_codex_build_id
            or result.get("executable_sha256") != codex.sha256
            or result.get("code_mode_host_sha256") != host.sha256
        ):
            raise ValueError("Windows native build result/proof join differs")
        windows_pair = WindowsNativeBuildArtifactJoinV1(
            build_receipt_sha256=_sha256(receipt_path),
            windows_native_codex_build_id=receipt.windows_native_codex_build_id,
            codex_sha256=codex.sha256,
            code_mode_host_sha256=host.sha256,
            process_proof_sha256=proof.process_proof_sha256,
            code_mode_host_eof_receipt_sha256=proof.code_mode_host_eof_receipt_sha256,
        )
    payload = NativeBuildArtifactInventoryPayloadV1(
        platform="windows",
        build_id=build_id,
        status=status,
        build_result_sha256=_sha256(result_path),
        windows_pair=windows_pair,
        files=files,
    )
    inventory = NativeBuildArtifactInventoryV1.create(payload)
    durable_publish(destination, (inventory.model_dump_json(indent=2) + "\n").encode())
    return inventory


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("windows",), required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build-id", required=True)
    args = parser.parse_args()
    seal_windows(args.root, args.build_id)


if __name__ == "__main__":
    main()
