"""Seal a bounded native-build output inventory before CI artifact upload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from devhub.experiment_launch import durable_publish
from devhub.linux_native import (
    LinuxNativeCodexBuildV4,
    LinuxNativeCodexBuildV5,
    LinuxNativeCodexBuildV6,
    LinuxNativeCodexBuildV7,
)
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
    WindowsNativeCodexBuildV4,
    WindowsNativeCodexBuildV5,
    WindowsNativeCodexBuildV6,
)

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
LINUX_ROOT_FILES = frozenset(
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
        "linux-build-result.json",
        "linux-native-codex-build.json",
        "linux-process-proof.json",
        "runner-manifest.json",
    }
)
LINUX_ROOT_DIRECTORIES = frozenset({"assets", "binary", "elf", "process-proof", "v8-release"})


def _sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _safe_path_diagnostic(relative_path: str) -> str:
    """Return a bounded ASCII-only label for an untrusted filesystem name."""

    escaped = relative_path.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    if len(escaped) <= 160:
        return escaped
    identity = hashlib.sha256(relative_path.encode("utf-8", errors="surrogatepass")).hexdigest()
    return f"{escaped[:80]}...[path_sha256={identity}]"


def _plain_file(path: Path, *, relative_path: str | None = None) -> os.stat_result:
    result = path.lstat()
    reparse = getattr(result, "st_file_attributes", 0) & 0x400
    if path.is_symlink() or reparse or not stat.S_ISREG(result.st_mode):
        suffix = f": {_safe_path_diagnostic(relative_path)}" if relative_path is not None else ""
        raise ValueError(f"Native build artifact entries must be plain regular files{suffix}")
    return result


def _validate_root(root: Path) -> Path:
    lexical_root = root.absolute()
    result = lexical_root.lstat()
    reparse = getattr(result, "st_file_attributes", 0) & 0x400
    if lexical_root.is_symlink() or reparse or not stat.S_ISDIR(result.st_mode):
        raise ValueError("Native build artifact root must be a plain directory")
    return lexical_root.resolve(strict=True)


def _paths_overlap(first: Path, second: Path) -> bool:
    left = os.path.normcase(os.fspath(first.absolute()))
    right = os.path.normcase(os.fspath(second.absolute()))
    try:
        common = os.path.normcase(os.path.commonpath((left, right)))
    except ValueError:
        return False
    return common in {left, right}


def _plain_directory(path: Path) -> None:
    result = path.lstat()
    reparse = getattr(result, "st_file_attributes", 0) & 0x400
    if path.is_symlink() or reparse or not stat.S_ISDIR(result.st_mode):
        raise ValueError("Windows evidence projection parent must be a plain directory")


def _validate_existing_directory_chain(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    _plain_directory(current)
    for part in absolute.parts[1:]:
        current /= part
        try:
            _plain_directory(current)
        except FileNotFoundError:
            return


def _create_plain_directory_chain(path: Path) -> Path:
    absolute = path.absolute()
    _validate_existing_directory_chain(absolute)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            _plain_directory(current)
        except FileNotFoundError:
            current.mkdir()
            _plain_directory(current)
    _validate_existing_directory_chain(absolute)
    return absolute.resolve(strict=True)


def _remove_projection_tree(path: Path) -> None:
    try:
        _plain_directory(path)
    except FileNotFoundError:
        return
    shutil.rmtree(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("Windows evidence projection cleanup did not remove the tree")


def _inventory_native(
    root: Path,
    *,
    root_files: frozenset[str],
    root_directories: frozenset[str],
    platform_label: str,
) -> tuple[NativeBuildArtifactEntryV1, ...]:
    root = _validate_root(root)
    entries: list[NativeBuildArtifactEntryV1] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        top = relative.split("/", 1)[0]
        if path.is_dir():
            result = path.lstat()
            if path.is_symlink() or getattr(result, "st_file_attributes", 0) & 0x400:
                raise ValueError("Native build artifact contains a linked directory")
            if top not in root_directories:
                raise ValueError(
                    f"{platform_label} native build artifact contains an unknown directory"
                )
            continue
        if relative == INVENTORY_NAME:
            continue
        if "/" not in relative and relative not in root_files:
            raise ValueError(
                f"{platform_label} native build artifact contains an unknown root file"
            )
        if "/" in relative and top not in root_directories:
            raise ValueError(
                f"{platform_label} native build artifact contains an unknown file tree"
            )
        result = _plain_file(path, relative_path=relative)
        entries.append(
            NativeBuildArtifactEntryV1(
                relative_path=relative,
                kind="binary" if top == "binary" else "evidence",
                size=result.st_size,
                sha256=_sha256(path),
            )
        )
    return tuple(entries)


def inventory_windows(root: Path) -> tuple[NativeBuildArtifactEntryV1, ...]:
    return _inventory_native(
        root,
        root_files=WINDOWS_ROOT_FILES,
        root_directories=WINDOWS_ROOT_DIRECTORIES,
        platform_label="Windows",
    )


def inventory_linux(root: Path) -> tuple[NativeBuildArtifactEntryV1, ...]:
    return _inventory_native(
        root,
        root_files=LINUX_ROOT_FILES,
        root_directories=LINUX_ROOT_DIRECTORIES,
        platform_label="Linux",
    )


NativeInventory = NativeBuildArtifactInventoryV1 | NativeBuildArtifactInventoryV2


def _verify_evidence_projection(
    projection: Path,
    inventory: NativeInventory,
    *,
    inventory_model: type[NativeBuildArtifactInventoryV1] | type[NativeBuildArtifactInventoryV2],
    platform_label: str,
) -> tuple[str, ...]:
    projection = _validate_root(projection)
    inventory_path = projection / INVENTORY_NAME
    _plain_file(inventory_path)
    observed_inventory = inventory_model.model_validate_json(inventory_path.read_bytes())
    if observed_inventory != inventory:
        raise ValueError(f"{platform_label} evidence projection inventory differs")
    expected_entries = {
        item.relative_path: item for item in inventory.payload.files if item.kind == "evidence"
    }
    expected_paths = set(expected_entries) | {INVENTORY_NAME}
    observed_paths: set[str] = set()
    for path in projection.rglob("*"):
        if path.is_dir():
            result = path.lstat()
            if path.is_symlink() or getattr(result, "st_file_attributes", 0) & 0x400:
                raise ValueError(
                    f"{platform_label} evidence projection contains a linked directory"
                )
            continue
        result = _plain_file(path)
        relative = path.relative_to(projection).as_posix()
        observed_paths.add(relative)
        entry = expected_entries.get(relative)
        if entry is not None and (result.st_size != entry.size or _sha256(path) != entry.sha256):
            raise ValueError(f"{platform_label} evidence projection entry differs from inventory")
    if observed_paths != expected_paths:
        raise ValueError(f"{platform_label} evidence projection member set differs from inventory")
    return tuple(sorted(observed_paths))


def verify_windows_evidence_projection(
    projection: Path, inventory: NativeBuildArtifactInventoryV1
) -> tuple[str, ...]:
    return _verify_evidence_projection(
        projection,
        inventory,
        inventory_model=NativeBuildArtifactInventoryV1,
        platform_label="Windows",
    )


def verify_linux_evidence_projection(
    projection: Path, inventory: NativeBuildArtifactInventoryV2
) -> tuple[str, ...]:
    return _verify_evidence_projection(
        projection,
        inventory,
        inventory_model=NativeBuildArtifactInventoryV2,
        platform_label="Linux",
    )


def _project_evidence(
    root: Path,
    destination: Path,
    inventory: NativeInventory,
    *,
    inventory_files: Callable[[Path], tuple[NativeBuildArtifactEntryV1, ...]],
    verify_projection: Callable[..., tuple[str, ...]],
    platform_label: str,
) -> tuple[str, ...]:
    root = _validate_root(root)
    destination = destination.absolute()
    if _paths_overlap(root, destination):
        raise ValueError(
            f"{platform_label} evidence projection must be outside the sealed build root"
        )
    _validate_existing_directory_chain(destination.parent)
    parent = _create_plain_directory_chain(destination.parent)
    destination = parent / destination.name
    if _paths_overlap(root, destination):
        raise ValueError(
            f"{platform_label} evidence projection must be outside the sealed build root"
        )
    temporary = destination.with_name(destination.name + ".tmp")
    for unpublished in (destination, temporary):
        try:
            unpublished.lstat()
        except FileNotFoundError:
            continue
        raise FileExistsError(unpublished)
    if inventory_files(root) != inventory.payload.files:
        raise ValueError(f"{platform_label} evidence source tree differs from sealed inventory")
    temporary.mkdir()
    published = False
    try:
        for entry in inventory.payload.files:
            if entry.kind != "evidence":
                continue
            source = root.joinpath(*PurePosixPath(entry.relative_path).parts)
            result = _plain_file(source)
            if result.st_size != entry.size or _sha256(source) != entry.sha256:
                raise ValueError(f"{platform_label} evidence source differs from sealed inventory")
            target = temporary.joinpath(*PurePosixPath(entry.relative_path).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        shutil.copyfile(root / INVENTORY_NAME, temporary / INVENTORY_NAME)
        verify_projection(temporary, inventory)
        os.replace(temporary, destination)
        published = True
        return verify_projection(destination, inventory)
    except Exception as primary:
        cleanup_target = destination if published else temporary
        try:
            _remove_projection_tree(cleanup_target)
        except Exception as cleanup:
            raise RuntimeError(
                f"{platform_label} evidence projection cleanup failed"
            ) from ExceptionGroup("projection and cleanup failures", (primary, cleanup))
        raise


def project_windows_evidence(
    root: Path, destination: Path, inventory: NativeBuildArtifactInventoryV1
) -> tuple[str, ...]:
    return _project_evidence(
        root,
        destination,
        inventory,
        inventory_files=inventory_windows,
        verify_projection=verify_windows_evidence_projection,
        platform_label="Windows",
    )


def project_linux_evidence(
    root: Path, destination: Path, inventory: NativeBuildArtifactInventoryV2
) -> tuple[str, ...]:
    return _project_evidence(
        root,
        destination,
        inventory,
        inventory_files=inventory_linux,
        verify_projection=verify_linux_evidence_projection,
        platform_label="Linux",
    )


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
        receipt: WindowsNativeCodexBuildV4 | WindowsNativeCodexBuildV5 | WindowsNativeCodexBuildV6
        if build_id == "windows-build-007":
            receipt = WindowsNativeCodexBuildV6.model_validate_json(receipt_path.read_bytes())
        elif build_id == "windows-build-006":
            receipt = WindowsNativeCodexBuildV5.model_validate_json(receipt_path.read_bytes())
        elif build_id == "windows-build-005":
            receipt = WindowsNativeCodexBuildV4.model_validate_json(receipt_path.read_bytes())
        else:
            raise ValueError("Windows native build inventory does not support this build ID")
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


def seal_linux(root: Path, build_id: str) -> NativeBuildArtifactInventoryV2:
    root = _validate_root(root)
    destination = root / INVENTORY_NAME
    temporary = destination.with_name(destination.name + ".tmp")
    for unpublished in (destination, temporary):
        try:
            unpublished.lstat()
        except FileNotFoundError:
            continue
        raise FileExistsError(unpublished)
    result_path = root / "linux-build-result.json"
    result_stat = _plain_file(result_path)
    if result_stat.st_size > 1024 * 1024:
        raise ValueError("Linux native build result exceeds its size bound")
    result = json.loads(result_path.read_bytes())
    if not isinstance(result, dict) or result.get("build_id") != build_id:
        raise ValueError("Linux native build result identity differs")
    status = result.get("status")
    if status not in {"PASS", "FAIL"}:
        raise ValueError("Linux native build result is not terminal")
    files = inventory_linux(root)
    linux_pair = None
    if status == "PASS":
        if build_id not in {
            "linux-build-004",
            "linux-build-005",
            "linux-build-006",
            "linux-build-007",
        }:
            raise ValueError("Linux native build inventory does not support this build ID")
        receipt_path = root / "linux-native-codex-build.json"
        receipt_stat = _plain_file(receipt_path)
        if receipt_stat.st_size > 256 * 1024:
            raise ValueError("Linux native build receipt exceeds its size bound")
        receipt_model = {
            "linux-build-004": LinuxNativeCodexBuildV4,
            "linux-build-005": LinuxNativeCodexBuildV5,
            "linux-build-006": LinuxNativeCodexBuildV6,
            "linux-build-007": LinuxNativeCodexBuildV7,
        }[build_id]
        receipt = receipt_model.model_validate_json(receipt_path.read_bytes())
        if receipt.payload.provenance.build_id != build_id:
            raise ValueError("Linux native build receipt identity differs")
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
            raise ValueError("Linux native build inventory differs from the exact binary pair")
        proof = receipt.payload.process_proof
        proof_path = root / "linux-process-proof.json"
        eof_path = root / "code-mode-host-eof.json"
        if (
            _sha256(proof_path) != proof.process_proof_sha256
            or _sha256(eof_path) != proof.code_mode_host_eof_receipt_sha256
            or result.get("linux_native_codex_build_id") != receipt.linux_native_codex_build_id
            or result.get("executable_sha256") != codex.sha256
            or result.get("code_mode_host_sha256") != host.sha256
        ):
            raise ValueError("Linux native build result/proof join differs")
        linux_pair = LinuxNativeBuildArtifactJoinV1(
            build_receipt_sha256=_sha256(receipt_path),
            linux_native_codex_build_id=receipt.linux_native_codex_build_id,
            codex_sha256=codex.sha256,
            code_mode_host_sha256=host.sha256,
            process_proof_sha256=proof.process_proof_sha256,
            code_mode_host_eof_receipt_sha256=proof.code_mode_host_eof_receipt_sha256,
        )
    payload = NativeBuildArtifactInventoryPayloadV2(
        platform="linux",
        build_id=build_id,
        status=status,
        build_result_sha256=_sha256(result_path),
        linux_pair=linux_pair,
        files=files,
    )
    inventory = NativeBuildArtifactInventoryV2.create(payload)
    durable_publish(destination, (inventory.model_dump_json(indent=2) + "\n").encode())
    return inventory


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("windows", "linux"), required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--evidence-projection", type=Path)
    args = parser.parse_args()
    if args.platform == "windows":
        windows_inventory = seal_windows(args.root, args.build_id)
        if args.evidence_projection is not None:
            project_windows_evidence(args.root, args.evidence_projection, windows_inventory)
    else:
        linux_inventory = seal_linux(args.root, args.build_id)
        if args.evidence_projection is not None:
            project_linux_evidence(args.root, args.evidence_projection, linux_inventory)


if __name__ == "__main__":
    main()
