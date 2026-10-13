from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType

import pytest
from linux_native_artifact_support import linux_pass_artifact
from pydantic import ValidationError

from devhub.benchmark import canonical, digest
from devhub.linux_bundle import (
    LinuxBundleEntryV1,
    LinuxCodexAuthorityV1,
    LinuxCodexAuthorityV2,
    LinuxCodexAuthorityV3,
    LinuxCodexAuthorityV4,
    LinuxCodexAuthorityV5,
    LinuxCodexAuthorityV6,
    LinuxElfRequirementV1,
    LinuxLauncherV1,
    LinuxLauncherV2,
    LinuxModuleOriginV1,
    LinuxNativeArchivePayloadV1,
    LinuxNativeArchivePayloadV2,
    LinuxNativeArchivePayloadV3,
    LinuxNativeArchivePayloadV4,
    LinuxNativeArchivePayloadV5,
    LinuxNativeArchivePayloadV6,
    LinuxNativeArchivePayloadV7,
    LinuxNativeArchivePayloadV8,
    LinuxNativeArchivePayloadV9,
    LinuxNativeArchivePayloadV10,
    LinuxNativeArchivePayloadV11,
    LinuxNativeArchiveV1,
    LinuxNativeArchiveV2,
    LinuxNativeArchiveV3,
    LinuxNativeArchiveV4,
    LinuxNativeArchiveV5,
    LinuxNativeArchiveV6,
    LinuxNativeArchiveV7,
    LinuxNativeArchiveV8,
    LinuxNativeArchiveV9,
    LinuxNativeArchiveV10,
    LinuxNativeArchiveV11,
    LinuxNativeBundlePayloadV1,
    LinuxNativeBundlePayloadV2,
    LinuxNativeBundlePayloadV3,
    LinuxNativeBundlePayloadV4,
    LinuxNativeBundlePayloadV5,
    LinuxNativeBundlePayloadV6,
    LinuxNativeBundlePayloadV7,
    LinuxNativeBundlePayloadV8,
    LinuxNativeBundlePayloadV9,
    LinuxNativeBundlePayloadV10,
    LinuxNativeBundlePayloadV11,
    LinuxNativeBundleV1,
    LinuxNativeBundleV2,
    LinuxNativeBundleV3,
    LinuxNativeBundleV4,
    LinuxNativeBundleV5,
    LinuxNativeBundleV6,
    LinuxNativeBundleV7,
    LinuxNativeBundleV8,
    LinuxNativeBundleV9,
    LinuxNativeBundleV10,
    LinuxNativeBundleV11,
    LinuxPythonAuthorityV1,
    LinuxPythonRuntimePayloadV1,
    LinuxPythonRuntimeV1,
    LinuxRuntimeClosureV1,
    LinuxRuntimeLibraryV1,
    bundled_loader_command,
    extract_and_verify_linux_archive,
    inspect_linux_dynamic_elf,
    inventory_linux_bundle,
    observe_linux_runtime,
    runtime_library_authority_json,
    runtime_library_authority_sha256,
    smoke_linux_bundle_cli,
    strip_linux_elf_search_paths,
    verify_linux_native_bundle,
    verify_linux_native_release,
)
from devhub.native_bundle import NativeDependencyWheelV1, file_sha256
from devhub.native_proof import (
    LinuxNativeBuildArtifactJoinV1,
    NativeBuildArtifactEntryV1,
    NativeBuildArtifactInventoryPayloadV2,
    NativeBuildArtifactInventoryV2,
)
from devhub.runtime_artifact import DistributionIdentityV1

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_linux_native_bundle", ROOT / "scripts/build_linux_native_bundle.py"
)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILDER
SPEC.loader.exec_module(BUILDER)
CHILD: ModuleType | None = None
if os.name == "posix":
    CHILD_SPEC = importlib.util.spec_from_file_location(
        "linux_native_isolation_child_bundle_test",
        ROOT / "src/devhub/linux_native_isolation_child.py",
    )
    assert CHILD_SPEC is not None and CHILD_SPEC.loader is not None
    CHILD = importlib.util.module_from_spec(CHILD_SPEC)
    sys.modules[CHILD_SPEC.name] = CHILD
    CHILD_SPEC.loader.exec_module(CHILD)
INVENTORY_SPEC = importlib.util.spec_from_file_location(
    "inventory_native_build_artifact", ROOT / "scripts/inventory_native_build_artifact.py"
)
assert INVENTORY_SPEC is not None and INVENTORY_SPEC.loader is not None
INVENTORY = importlib.util.module_from_spec(INVENTORY_SPEC)
sys.modules[INVENTORY_SPEC.name] = INVENTORY
INVENTORY_SPEC.loader.exec_module(INVENTORY)

HASH = "a" * 64
OTHER_HASH = "b" * 64
COMMIT = "c" * 40
RETAINED_CODEX_COMMIT = "d" * 40


def _write(root: Path, relative: str, value: bytes) -> Path:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return path


def _minimal_dynamic_elf(
    *,
    interpreter: str = "/lib64/ld-linux-x86-64.so.2",
    needed: tuple[str, ...] = ("libc.so.6",),
    rpath: str | None = None,
    runpath: str | None = None,
) -> bytes:
    string_values = [*needed]
    if rpath is not None:
        string_values.append(rpath)
    if runpath is not None:
        string_values.append(runpath)
    strings = bytearray(b"\x00")
    offsets: list[int] = []
    for value in string_values:
        offsets.append(len(strings))
        strings.extend(value.encode("utf-8") + b"\x00")
    dynamic: list[tuple[int, int]] = [(5, 0x400300), (10, len(strings))]
    dynamic.extend((1, offsets[index]) for index in range(len(needed)))
    cursor = len(needed)
    if rpath is not None:
        dynamic.append((15, offsets[cursor]))
        cursor += 1
    if runpath is not None:
        dynamic.append((29, offsets[cursor]))
    dynamic.append((0, 0))
    dynamic_bytes = b"".join(struct.pack("<qQ", *item) for item in dynamic)
    interpreter_bytes = interpreter.encode("utf-8") + b"\x00"
    total = max(0x300 + len(strings), 0x200 + len(dynamic_bytes), 0x180 + len(interpreter_bytes))
    value = bytearray(total)
    ident = bytearray(16)
    ident[:7] = b"\x7fELF\x02\x01\x01"
    value[:64] = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident),
        3,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        3,
        0,
        0,
        0,
    )
    program_headers = (
        (1, 5, 0, 0x400000, 0, total, total, 0x1000),
        (3, 4, 0x180, 0x400180, 0, len(interpreter_bytes), len(interpreter_bytes), 1),
        (2, 4, 0x200, 0x400200, 0, len(dynamic_bytes), len(dynamic_bytes), 8),
    )
    for index, item in enumerate(program_headers):
        start = 64 + index * 56
        value[start : start + 56] = struct.pack("<IIQQQQQQ", *item)
    value[0x180 : 0x180 + len(interpreter_bytes)] = interpreter_bytes
    value[0x200 : 0x200 + len(dynamic_bytes)] = dynamic_bytes
    value[0x300 : 0x300 + len(strings)] = strings
    return bytes(value)


def _entries(root: Path) -> tuple[LinuxBundleEntryV1, ...]:
    executable = {
        "python/bin/python3.12",
        "codex/codex",
        "codex/codex-code-mode-host",
        "bin/devfabric",
        "bin/devhub-delegate-server",
        "runtime/loader/ld-linux-x86-64.so.2",
    }
    values: list[LinuxBundleEntryV1] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            values.append(LinuxBundleEntryV1(path=relative, kind="directory", mode=0o755))
        else:
            values.append(
                LinuxBundleEntryV1(
                    path=relative,
                    kind="file",
                    mode=0o755 if relative in executable else 0o644,
                    size=path.stat().st_size,
                    sha256=file_sha256(path),
                )
            )
    return tuple(sorted(values, key=lambda item: item.path))


def _runtime(root: Path, wheel: Path, lock: Path) -> LinuxPythonRuntimeV1:
    interpreter = root / "python/bin/python3.12"
    return LinuxPythonRuntimeV1.create(
        LinuxPythonRuntimePayloadV1(
            python_executable_sha256=file_sha256(interpreter),
            platform_tag="linux-x86_64",
            platform_machine="x86_64",
            libc_name="glibc",
            libc_version="2.39",
            devhub_source_commit=COMMIT,
            devhub_wheel_sha256=file_sha256(wheel),
            dependency_lock_sha256=file_sha256(lock),
            devhub_distribution_version="0.1.0",
            sys_path=(
                "python/lib/python312.zip",
                "python/lib/python3.12",
                "python/lib/python3.12/lib-dynload",
                "python/lib/python3.12/site-packages",
            ),
            module_origins=tuple(
                LinuxModuleOriginV1(
                    module=module,
                    path=f"python/lib/python3.12/site-packages/{module}/__init__.py",
                )
                for module in ("devhub", "mcp", "pydantic", "tokenizers")
            ),
            distributions=(
                DistributionIdentityV1(
                    name="codex-dev-hub", version="0.1.0", record_sha256=HASH, file_count=2
                ),
                DistributionIdentityV1(
                    name="pydantic", version="2.12.5", record_sha256=OTHER_HASH, file_count=2
                ),
            ),
        )
    )


def materialize(root: Path) -> LinuxNativeBundleV1:
    interpreter = _write(root, "python/bin/python3.12", b"python")
    wheel = _write(root, "authority/codex_dev_hub-0.1.0-py3-none-any.whl", b"project")
    lock = _write(root, "authority/uv.lock", b"lock")
    dependency = _write(root, "authority/wheels/pydantic-2.12.5-py3-none-any.whl", b"dep")
    receipt = _write(root, "authority/linux-native-codex-build.json", b"receipt")
    inventory = _write(root, "authority/native-build-artifact-inventory.json", b"inventory")
    codex = _write(root, "codex/codex", b"codex")
    host = _write(root, "codex/codex-code-mode-host", b"host")
    cli = _write(root, "bin/devfabric", b"#!/bin/sh\n")
    delegate = _write(root, "bin/devhub-delegate-server", b"#!/bin/sh\n")
    runtime = _runtime(root, wheel, lock)
    payload = LinuxNativeBundlePayloadV1(
        implementation_commit=COMMIT,
        python=LinuxPythonAuthorityV1(
            executable_sha256=file_sha256(interpreter),
            devhub_wheel_path="authority/codex_dev_hub-0.1.0-py3-none-any.whl",
            devhub_wheel_sha256=file_sha256(wheel),
            devhub_source_archive_sha256=HASH,
            dependency_lock_sha256=file_sha256(lock),
            dependency_wheels=(
                NativeDependencyWheelV1(
                    name="pydantic",
                    version="2.12.5",
                    filename=dependency.name,
                    sha256=file_sha256(dependency),
                ),
            ),
            runtime=runtime,
        ),
        codex=LinuxCodexAuthorityV1(
            accepted_run_id=123,
            accepted_run_attempt=1,
            devfabric_implementation_commit=COMMIT,
            build_receipt_sha256=file_sha256(receipt),
            inventory_sha256=file_sha256(inventory),
            linux_native_codex_build_id=HASH,
            executable_sha256=file_sha256(codex),
            code_mode_host_sha256=file_sha256(host),
            process_proof_sha256=HASH,
            code_mode_host_eof_receipt_sha256=OTHER_HASH,
        ),
        launcher=LinuxLauncherV1(
            cli_sha256=file_sha256(cli),
            delegate_sha256=file_sha256(delegate),
        ),
        files=_entries(root),
    )
    return LinuxNativeBundleV1.create(payload)


def materialize_v2(root: Path) -> LinuxNativeBundleV2:
    historical = materialize(root)
    raw = historical.payload.model_dump(mode="python")
    raw["schema_version"] = 2
    raw["codex"] = {
        **raw["codex"],
        "schema_version": 2,
        "build_id": "linux-build-008",
    }
    return LinuxNativeBundleV2.create(LinuxNativeBundlePayloadV2.model_validate(raw))


def materialize_v3(root: Path) -> LinuxNativeBundleV3:
    historical = materialize(root)
    raw = historical.payload.model_dump(mode="python")
    raw["schema_version"] = 3
    raw["codex"] = {
        **raw["codex"],
        "schema_version": 3,
        "build_id": "linux-build-009",
    }
    return LinuxNativeBundleV3.create(LinuxNativeBundlePayloadV3.model_validate(raw))


def materialize_v4(root: Path) -> LinuxNativeBundleV4:
    historical = materialize(root)
    raw = historical.payload.model_dump(mode="python")
    raw["schema_version"] = 4
    raw["codex"] = {
        **raw["codex"],
        "schema_version": 4,
        "build_id": "linux-build-010",
    }
    return LinuxNativeBundleV4.create(LinuxNativeBundlePayloadV4.model_validate(raw))


def materialize_v5(root: Path) -> LinuxNativeBundleV5:
    historical = materialize(root)
    raw = historical.payload.model_dump(mode="python")
    raw["schema_version"] = 5
    raw["codex"] = {
        **raw["codex"],
        "schema_version": 5,
        "build_id": "linux-build-011",
    }
    return LinuxNativeBundleV5.create(LinuxNativeBundlePayloadV5.model_validate(raw))


def materialize_v6(root: Path) -> LinuxNativeBundleV6:
    historical = materialize(root)
    raw = historical.payload.model_dump(mode="python")
    raw["schema_version"] = 6
    raw["codex"] = {
        **raw["codex"],
        "schema_version": 6,
        "build_id": "linux-build-012",
    }
    return LinuxNativeBundleV6.create(LinuxNativeBundlePayloadV6.model_validate(raw))


def materialize_v7(root: Path) -> LinuxNativeBundleV7:
    current = materialize_v6(root)
    raw = current.payload.model_dump(mode="python")
    raw["schema_version"] = 7
    raw["retained_codex_implementation_commit"] = RETAINED_CODEX_COMMIT
    raw["codex"]["devfabric_implementation_commit"] = RETAINED_CODEX_COMMIT
    return LinuxNativeBundleV7.create(LinuxNativeBundlePayloadV7.model_validate(raw))


def materialize_v8(root: Path) -> LinuxNativeBundleV8:
    current = materialize_v7(root)
    raw = current.payload.model_dump(mode="python")
    raw["schema_version"] = 8
    return LinuxNativeBundleV8.create(LinuxNativeBundlePayloadV8.model_validate(raw))


def materialize_v9(root: Path) -> LinuxNativeBundleV9:
    current = materialize_v8(root)
    loader = _write(root, "runtime/loader/ld-linux-x86-64.so.2", b"loader")
    libc = _write(root, "runtime/lib/libc.so.6", b"libc")
    libm = _write(root, "runtime/lib/libm.so.6", b"libm")
    closure = LinuxRuntimeClosureV1(
        loader_sha256=file_sha256(loader),
        loader_size=loader.stat().st_size,
        libraries=(
            LinuxRuntimeLibraryV1(
                soname="libc.so.6",
                path="runtime/lib/libc.so.6",
                size=libc.stat().st_size,
                sha256=file_sha256(libc),
            ),
            LinuxRuntimeLibraryV1(
                soname="libm.so.6",
                path="runtime/lib/libm.so.6",
                size=libm.stat().st_size,
                sha256=file_sha256(libm),
            ),
        ),
        elf_requirements=(
            LinuxElfRequirementV1(
                path="codex/codex",
                interpreter="/lib64/ld-linux-x86-64.so.2",
                needed=("libc.so.6",),
            ),
            LinuxElfRequirementV1(
                path="codex/codex-code-mode-host",
                interpreter="/lib64/ld-linux-x86-64.so.2",
                needed=("libc.so.6",),
            ),
            LinuxElfRequirementV1(
                path="python/bin/python3.12",
                interpreter="/lib64/ld-linux-x86-64.so.2",
                needed=("libc.so.6",),
            ),
            LinuxElfRequirementV1(
                path="runtime/lib/libc.so.6",
                needed=("ld-linux-x86-64.so.2", "libm.so.6"),
            ),
            LinuxElfRequirementV1(path="runtime/lib/libm.so.6"),
            LinuxElfRequirementV1(path="runtime/loader/ld-linux-x86-64.so.2"),
        ),
    )
    raw = current.payload.model_dump(mode="python")
    raw["schema_version"] = 9
    raw["launcher"] = {
        **raw["launcher"],
        "schema_version": 2,
        "loader_path": "runtime/loader/ld-linux-x86-64.so.2",
        "library_directory": "runtime/lib",
        "loader_arguments": ("--inhibit-cache", "--library-path"),
    }
    raw["runtime_closure"] = closure.model_dump(mode="python")
    raw["files"] = tuple(item.model_dump(mode="python") for item in _entries(root))
    return LinuxNativeBundleV9.create(LinuxNativeBundlePayloadV9.model_validate(raw))


def materialize_v10(root: Path) -> LinuxNativeBundleV10:
    current = materialize_v9(root)
    raw = current.payload.model_dump(mode="python")
    raw["schema_version"] = 10
    return LinuxNativeBundleV10.create(LinuxNativeBundlePayloadV10.model_validate(raw))


def materialize_v11(root: Path) -> LinuxNativeBundleV11:
    current = materialize_v10(root)
    raw = current.payload.model_dump(mode="python")
    raw["schema_version"] = 11
    return LinuxNativeBundleV11.create(LinuxNativeBundlePayloadV11.model_validate(raw))


def reviewable_v12_artifact(root: Path) -> None:
    linux_pass_artifact(
        root,
        implementation_commit=COMMIT,
        workflow_run_id=123,
        workflow_run_attempt=1,
    )
    INVENTORY.seal_linux(root, "linux-build-012")


def write_test_archive(
    release: Path, bundle_id: str, schema_version: int
) -> (
    LinuxNativeArchiveV1
    | LinuxNativeArchiveV2
    | LinuxNativeArchiveV3
    | LinuxNativeArchiveV4
    | LinuxNativeArchiveV5
    | LinuxNativeArchiveV6
    | LinuxNativeArchiveV7
    | LinuxNativeArchiveV8
    | LinuxNativeArchiveV9
    | LinuxNativeArchiveV10
    | LinuxNativeArchiveV11
):
    archive_path = release / BUILDER.ARCHIVE_NAME
    with tarfile.open(archive_path, mode="w:gz", format=tarfile.PAX_FORMAT) as stream:
        stream.add(release / "bundle", arcname="bundle", recursive=True)
    fields = {
        "bundle_id": bundle_id,
        "size": archive_path.stat().st_size,
        "sha256": file_sha256(archive_path),
    }
    if schema_version == 1:
        receipt: (
            LinuxNativeArchiveV1
            | LinuxNativeArchiveV2
            | LinuxNativeArchiveV3
            | LinuxNativeArchiveV4
            | LinuxNativeArchiveV5
            | LinuxNativeArchiveV6
            | LinuxNativeArchiveV7
            | LinuxNativeArchiveV8
            | LinuxNativeArchiveV9
            | LinuxNativeArchiveV10
            | LinuxNativeArchiveV11
        ) = LinuxNativeArchiveV1.create(LinuxNativeArchivePayloadV1(**fields))
    elif schema_version == 2:
        receipt = LinuxNativeArchiveV2.create(LinuxNativeArchivePayloadV2(**fields))
    elif schema_version == 3:
        receipt = LinuxNativeArchiveV3.create(LinuxNativeArchivePayloadV3(**fields))
    elif schema_version == 4:
        receipt = LinuxNativeArchiveV4.create(LinuxNativeArchivePayloadV4(**fields))
    elif schema_version == 5:
        receipt = LinuxNativeArchiveV5.create(LinuxNativeArchivePayloadV5(**fields))
    elif schema_version == 6:
        receipt = LinuxNativeArchiveV6.create(LinuxNativeArchivePayloadV6(**fields))
    elif schema_version == 7:
        receipt = LinuxNativeArchiveV7.create(LinuxNativeArchivePayloadV7(**fields))
    elif schema_version == 8:
        receipt = LinuxNativeArchiveV8.create(LinuxNativeArchivePayloadV8(**fields))
    elif schema_version == 9:
        receipt = LinuxNativeArchiveV9.create(LinuxNativeArchivePayloadV9(**fields))
    elif schema_version == 10:
        receipt = LinuxNativeArchiveV10.create(LinuxNativeArchivePayloadV10(**fields))
    else:
        receipt = LinuxNativeArchiveV11.create(LinuxNativeArchivePayloadV11(**fields))
    (release / BUILDER.ARCHIVE_RECEIPT_NAME).write_text(receipt.model_dump_json(), encoding="utf-8")
    return receipt


def test_linux_native_bundle_is_self_hashed_and_closed(tmp_path: Path) -> None:
    bundle = materialize(tmp_path)
    assert LinuxNativeBundleV1.model_validate_json(bundle.model_dump_json()) == bundle
    assert bundle.payload.native_executor_isolation_qualified is False
    assert bundle.payload.package_readiness is False

    raw = bundle.model_dump(mode="python")
    raw["linux_native_bundle_id"] = OTHER_HASH
    with pytest.raises(ValidationError, match="bundle ID mismatch"):
        LinuxNativeBundleV1.model_validate(raw)


def test_linux_native_bundle_v2_requires_build_008_and_preserves_v1(tmp_path: Path) -> None:
    current = materialize_v2(tmp_path / "current")
    assert LinuxNativeBundleV2.model_validate_json(current.model_dump_json()) == current
    assert isinstance(current.payload.codex, LinuxCodexAuthorityV2)
    assert current.payload.codex.build_id == "linux-build-008"
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize(tmp_path / "historical")
    assert LinuxNativeBundleV1.model_validate_json(historical.model_dump_json()) == historical
    raw = current.payload.model_dump(mode="python")
    raw["codex"]["build_id"] = "linux-build-007"
    with pytest.raises(ValidationError):
        LinuxNativeBundlePayloadV2.model_validate(raw)


def test_linux_native_bundle_v3_requires_build_009_and_preserves_v2(tmp_path: Path) -> None:
    current = materialize_v3(tmp_path / "current")
    assert LinuxNativeBundleV3.model_validate_json(current.model_dump_json()) == current
    assert isinstance(current.payload.codex, LinuxCodexAuthorityV3)
    assert current.payload.codex.build_id == "linux-build-009"
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize_v2(tmp_path / "historical")
    assert LinuxNativeBundleV2.model_validate_json(historical.model_dump_json()) == historical
    raw = current.payload.model_dump(mode="python")
    raw["codex"]["build_id"] = "linux-build-008"
    with pytest.raises(ValidationError):
        LinuxNativeBundlePayloadV3.model_validate(raw)


def test_linux_native_bundle_v4_requires_build_010_and_preserves_v3(tmp_path: Path) -> None:
    current = materialize_v4(tmp_path / "current")
    assert LinuxNativeBundleV4.model_validate_json(current.model_dump_json()) == current
    assert isinstance(current.payload.codex, LinuxCodexAuthorityV4)
    assert current.payload.codex.build_id == "linux-build-010"
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize_v3(tmp_path / "historical")
    assert LinuxNativeBundleV3.model_validate_json(historical.model_dump_json()) == historical
    raw = current.payload.model_dump(mode="python")
    raw["codex"]["build_id"] = "linux-build-009"
    with pytest.raises(ValidationError):
        LinuxNativeBundlePayloadV4.model_validate(raw)


def test_linux_native_bundle_v5_requires_build_011_and_preserves_v4(tmp_path: Path) -> None:
    current = materialize_v5(tmp_path / "current")
    assert LinuxNativeBundleV5.model_validate_json(current.model_dump_json()) == current
    assert isinstance(current.payload.codex, LinuxCodexAuthorityV5)
    assert current.payload.codex.build_id == "linux-build-011"
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize_v4(tmp_path / "historical")
    assert LinuxNativeBundleV4.model_validate_json(historical.model_dump_json()) == historical
    raw = current.payload.model_dump(mode="python")
    raw["codex"]["build_id"] = "linux-build-010"
    with pytest.raises(ValidationError):
        LinuxNativeBundlePayloadV5.model_validate(raw)


def test_linux_native_bundle_v6_requires_build_012_and_preserves_v5(tmp_path: Path) -> None:
    current = materialize_v6(tmp_path / "current")
    assert LinuxNativeBundleV6.model_validate_json(current.model_dump_json()) == current
    assert isinstance(current.payload.codex, LinuxCodexAuthorityV6)
    assert current.payload.codex.build_id == "linux-build-012"
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize_v5(tmp_path / "historical")
    assert LinuxNativeBundleV5.model_validate_json(historical.model_dump_json()) == historical
    raw = current.payload.model_dump(mode="python")
    raw["codex"]["build_id"] = "linux-build-011"
    with pytest.raises(ValidationError):
        LinuxNativeBundlePayloadV6.model_validate(raw)


def test_linux_native_bundle_v7_splits_current_python_from_retained_build_012(
    tmp_path: Path,
) -> None:
    current = materialize_v7(tmp_path / "current")
    assert LinuxNativeBundleV7.model_validate_json(current.model_dump_json()) == current
    assert current.payload.implementation_commit == COMMIT
    assert current.payload.python.runtime.payload.devhub_source_commit == COMMIT
    assert current.payload.retained_codex_implementation_commit == RETAINED_CODEX_COMMIT
    assert current.payload.codex.devfabric_implementation_commit == RETAINED_CODEX_COMMIT
    assert current.payload.codex.build_id == "linux-build-012"
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    raw = current.payload.model_dump(mode="python")
    raw["retained_codex_implementation_commit"] = "e" * 40
    with pytest.raises(ValidationError, match="components differ"):
        LinuxNativeBundlePayloadV7.model_validate(raw)

    raw = current.payload.model_dump(mode="python")
    raw["python"]["runtime"]["payload"]["devhub_source_commit"] = "e" * 40
    raw["python"]["runtime"]["linux_python_runtime_id"] = digest(
        canonical(raw["python"]["runtime"]["payload"])
    )
    with pytest.raises(ValidationError, match="components differ"):
        LinuxNativeBundlePayloadV7.model_validate(raw)

    historical = materialize_v6(tmp_path / "historical")
    assert LinuxNativeBundleV6.model_validate_json(historical.model_dump_json()) == historical


def test_linux_native_bundle_v8_preserves_split_authority_and_versions_capture_fix(
    tmp_path: Path,
) -> None:
    current = materialize_v8(tmp_path / "current")
    assert LinuxNativeBundleV8.model_validate_json(current.model_dump_json()) == current
    assert current.payload.schema_version == 8
    assert current.payload.implementation_commit == COMMIT
    assert current.payload.python.runtime.payload.devhub_source_commit == COMMIT
    assert current.payload.retained_codex_implementation_commit == RETAINED_CODEX_COMMIT
    assert current.payload.codex.devfabric_implementation_commit == RETAINED_CODEX_COMMIT
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize_v7(tmp_path / "historical")
    assert LinuxNativeBundleV7.model_validate_json(historical.model_dump_json()) == historical


def test_linux_native_bundle_v9_binds_exact_recursive_loader_closure(tmp_path: Path) -> None:
    current = materialize_v9(tmp_path / "current")
    assert LinuxNativeBundleV9.model_validate_json(current.model_dump_json()) == current
    assert current.payload.schema_version == 9
    assert isinstance(current.payload.launcher, LinuxLauncherV2)
    assert current.payload.runtime_closure.embedded_interpreter == ("/lib64/ld-linux-x86-64.so.2")
    assert [item.soname for item in current.payload.runtime_closure.libraries] == [
        "libc.so.6",
        "libm.so.6",
    ]
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    raw = current.payload.model_dump(mode="python")
    raw["runtime_closure"]["libraries"][0]["soname"] = "liba.so.1"
    raw["runtime_closure"]["libraries"][0]["path"] = "runtime/lib/liba.so.1"
    with pytest.raises(ValidationError, match="required ELF object"):
        LinuxNativeBundlePayloadV9.model_validate(raw)

    substituted = current.payload.model_dump(mode="python")
    substituted["runtime_closure"]["libraries"][1]["sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="library differs from closure authority"):
        LinuxNativeBundlePayloadV9.model_validate(substituted)

    historical = materialize_v8(tmp_path / "historical")
    assert LinuxNativeBundleV8.model_validate_json(historical.model_dump_json()) == historical


def test_linux_native_bundle_v10_preserves_v9_and_versions_search_path_removal(
    tmp_path: Path,
) -> None:
    current = materialize_v10(tmp_path / "current")
    assert LinuxNativeBundleV10.model_validate_json(current.model_dump_json()) == current
    assert current.payload.schema_version == 10
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize_v9(tmp_path / "historical")
    assert LinuxNativeBundleV9.model_validate_json(historical.model_dump_json()) == historical


def test_linux_native_bundle_v11_binds_v10_predecessor_and_remains_non_ready(
    tmp_path: Path,
) -> None:
    current = materialize_v11(tmp_path / "current")
    assert LinuxNativeBundleV11.model_validate_json(current.model_dump_json()) == current
    assert current.payload.schema_version == 11
    assert current.payload.predecessor_bundle_run_id == 38418589025
    assert current.payload.predecessor_bundle_run_attempt == 1
    assert (
        current.payload.predecessor_bundle_id
        == "10a30fb6a28a9d77bd0b8bf31c329a6638d96121050aff1be4cfe07792d023e2"
    )
    assert (
        current.payload.predecessor_bundle_manifest_sha256
        == "a3bc252955bb45fd9e10a34d92a27d3b55fdcf5efa4265e4546ad6082ff964fd"
    )
    assert (
        current.payload.predecessor_archive_id
        == "e3560a690a47b86683c3ba41c6b2699279e96e19932a7bfd0fb7d9b26d7e0c00"
    )
    assert (
        current.payload.predecessor_archive_sha256
        == "7e4032107cf364b4caf3659bdd334ed18c31e95afe7de8145f9c529a2788cda3"
    )
    assert current.payload.native_executor_isolation_qualified is False
    assert current.payload.package_readiness is False

    historical = materialize_v10(tmp_path / "historical")
    assert LinuxNativeBundleV10.model_validate_json(historical.model_dump_json()) == historical


@pytest.mark.skipif(os.name != "posix", reason="Immutable isolation child is Linux-only")
def test_runtime_library_authority_projection_round_trips_immutable_child(tmp_path: Path) -> None:
    assert CHILD is not None
    closure = materialize_v11(tmp_path / "bundle").payload.runtime_closure
    raw = runtime_library_authority_json(closure)
    parsed = CHILD.parse_runtime_library_authority(raw)

    assert parsed == tuple(
        (Path(item.path).name, item.sha256, item.size) for item in closure.libraries
    )
    assert CHILD.digest(CHILD.canonical(json.loads(raw))) == runtime_library_authority_sha256(
        closure
    )


def test_linux_bundle_loader_command_is_exact_and_rejects_tamper(tmp_path: Path) -> None:
    bundle = materialize_v9(tmp_path / "bundle")
    closure = bundle.payload.runtime_closure
    command = bundled_loader_command(
        tmp_path / "bundle",
        closure,
        "python/bin/python3.12",
        ("-I", "-B", "-m", "devhub.cli", "schema"),
    )
    assert command == [
        str(tmp_path / "bundle/runtime/loader/ld-linux-x86-64.so.2"),
        "--inhibit-cache",
        "--library-path",
        str(tmp_path / "bundle/runtime/lib"),
        str(tmp_path / "bundle/python/bin/python3.12"),
        "-I",
        "-B",
        "-m",
        "devhub.cli",
        "schema",
    ]
    (tmp_path / "bundle/runtime/loader/ld-linux-x86-64.so.2").write_bytes(b"changed")
    with pytest.raises(ValueError, match="loader bytes differ"):
        bundled_loader_command(tmp_path / "bundle", closure, "python/bin/python3.12", ("-I",))


@pytest.mark.parametrize("manifest_version", (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11))
def test_linux_release_rejects_mixed_manifest_and_archive_versions(
    tmp_path: Path, manifest_version: int
) -> None:
    release = tmp_path / "release"
    root = release / "bundle"
    bundle = (
        materialize(root)
        if manifest_version == 1
        else materialize_v2(root)
        if manifest_version == 2
        else materialize_v3(root)
        if manifest_version == 3
        else materialize_v4(root)
        if manifest_version == 4
        else materialize_v5(root)
        if manifest_version == 5
        else materialize_v6(root)
        if manifest_version == 6
        else materialize_v7(root)
        if manifest_version == 7
        else materialize_v8(root)
        if manifest_version == 8
        else materialize_v9(root)
        if manifest_version == 9
        else materialize_v10(root)
        if manifest_version == 10
        else materialize_v11(root)
    )
    (release / "linux-native-bundle.json").write_text(bundle.model_dump_json(), encoding="utf-8")
    write_test_archive(release, bundle.linux_native_bundle_id, 2 if manifest_version != 2 else 1)
    shutil.rmtree(root)

    with pytest.raises(ValueError, match="schema versions differ"):
        verify_linux_native_release(release, tmp_path / "extracted")


def test_linux_release_rejects_v6_manifest_with_v5_archive(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    root = release / "bundle"
    bundle = materialize_v6(root)
    (release / "linux-native-bundle.json").write_text(bundle.model_dump_json(), encoding="utf-8")
    write_test_archive(release, bundle.linux_native_bundle_id, 5)
    shutil.rmtree(root)

    with pytest.raises(ValueError, match="schema versions differ"):
        verify_linux_native_release(release, tmp_path / "extracted")


def test_linux_release_rejects_v5_manifest_with_v6_archive(
    tmp_path: Path,
) -> None:
    release = tmp_path / "release"
    root = release / "bundle"
    bundle = materialize_v5(root)
    (release / "linux-native-bundle.json").write_text(bundle.model_dump_json(), encoding="utf-8")
    write_test_archive(release, bundle.linux_native_bundle_id, 6)
    shutil.rmtree(root)

    with pytest.raises(ValueError, match="schema versions differ"):
        verify_linux_native_release(release, tmp_path / "extracted")


def test_linux_native_bundle_rejects_mutable_state_and_inventory_tamper(tmp_path: Path) -> None:
    bundle = materialize(tmp_path)
    _write(tmp_path, "ledger/ledger.db", b"mutable")
    raw = bundle.payload.model_dump(mode="python")
    raw["files"] = _entries(tmp_path)
    with pytest.raises(ValidationError, match="Mutable state"):
        LinuxNativeBundlePayloadV1.model_validate(raw)

    raw = bundle.payload.model_dump(mode="python")
    raw["python"]["executable_sha256"] = OTHER_HASH
    with pytest.raises(ValidationError):
        LinuxNativeBundlePayloadV1.model_validate(raw)


@pytest.mark.parametrize(
    "relative",
    ("authority/extra.json", "bin/extra", "codex/extra"),
)
def test_linux_native_bundle_rejects_extra_closed_layout_file(
    tmp_path: Path, relative: str
) -> None:
    bundle = materialize(tmp_path)
    _write(tmp_path, relative, b"extra")
    raw = bundle.payload.model_dump(mode="python")
    raw["files"] = _entries(tmp_path)
    with pytest.raises(ValidationError, match="not closed"):
        LinuxNativeBundlePayloadV1.model_validate(raw)


def test_linux_native_bundle_rejects_mode_tamper(tmp_path: Path) -> None:
    bundle = materialize(tmp_path)
    raw = bundle.payload.model_dump(mode="python")
    for item in raw["files"]:
        if item["path"] == "bin/devfabric":
            item["mode"] = 0o644
            break
    with pytest.raises(ValidationError, match="executable mode differs"):
        LinuxNativeBundlePayloadV1.model_validate(raw)

    raw = bundle.payload.model_dump(mode="python")
    raw["files"][0]["mode"] = 0o777
    with pytest.raises(ValidationError, match="group/world writable"):
        LinuxNativeBundlePayloadV1.model_validate(raw)


def test_runtime_observation_binds_relocation_and_allows_nullable_machine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "release/bundle"
    interpreter = _write(root, "python/bin/python3.12", b"python")
    wheel = _write(root, "authority/devhub.whl", b"wheel")
    lock = _write(root, "authority/uv.lock", b"lock")
    for relative in (
        "python/lib/python312.zip",
        "python/lib/python3.12/os.py",
        "python/lib/python3.12/lib-dynload/_ssl.so",
        "python/lib/python3.12/site-packages/devhub/__init__.py",
        "python/lib/python3.12/site-packages/mcp/__init__.py",
        "python/lib/python3.12/site-packages/pydantic/__init__.py",
        "python/lib/python3.12/site-packages/tokenizers/__init__.py",
    ):
        _write(root, relative, b"x")
    site = root / "python/lib/python3.12/site-packages"
    observed = {
        "implementation": "CPython",
        "version": "3.12.10",
        "cache_tag": "cpython-312",
        "platform_tag": "linux-x86_64",
        "machine": None,
        "libc": ["glibc", "2.39"],
        "system": "Linux",
        "isolated": True,
        "ignore_environment": True,
        "no_user_site": True,
        "dont_write_bytecode": True,
        "editable": False,
        "executable": str(interpreter.resolve()),
        "prefix": str((root / "python").resolve()),
        "base_prefix": str((root / "python").resolve()),
        "sys_path": [
            str((root / "python/lib/python312.zip").resolve()),
            str((root / "python/lib/python3.12").resolve()),
            str((root / "python/lib/python3.12/lib-dynload").resolve()),
            str(site.resolve()),
        ],
        "modules": [
            {
                "module": module,
                "path": f"python/lib/python3.12/site-packages/{module}/__init__.py",
            }
            for module in ("devhub", "mcp", "pydantic", "tokenizers")
        ],
        "distributions": [
            {
                "name": "codex-dev-hub",
                "version": "0.1.0",
                "record_sha256": HASH,
                "file_count": 1,
            }
        ],
    }
    monkeypatch.setattr(
        "devhub.linux_bundle.subprocess.check_output",
        lambda *_, **__: json.dumps(observed).encode(),
    )
    runtime = observe_linux_runtime(interpreter, wheel, lock, COMMIT)
    assert runtime.payload.platform_machine is None
    assert runtime.payload.platform_tag == "linux-x86_64"


def test_runtime_observation_accepts_only_missing_sys_path_inside_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "release/bundle"
    interpreter = _write(root, "python/bin/python3.12", b"python")
    wheel = _write(root, "authority/devhub.whl", b"wheel")
    lock = _write(root, "authority/uv.lock", b"lock")
    for relative in (
        "python/lib/python3.12/os.py",
        "python/lib/python3.12/lib-dynload/_ssl.so",
        "python/lib/python3.12/site-packages/devhub/__init__.py",
        "python/lib/python3.12/site-packages/mcp/__init__.py",
        "python/lib/python3.12/site-packages/pydantic/__init__.py",
        "python/lib/python3.12/site-packages/tokenizers/__init__.py",
    ):
        _write(root, relative, b"x")
    site = root / "python/lib/python3.12/site-packages"
    observed = {
        "implementation": "CPython",
        "version": "3.12.10",
        "cache_tag": "cpython-312",
        "platform_tag": "linux-x86_64",
        "machine": "x86_64",
        "libc": ["glibc", "2.39"],
        "system": "Linux",
        "isolated": True,
        "ignore_environment": True,
        "no_user_site": True,
        "dont_write_bytecode": True,
        "editable": False,
        "executable": str(interpreter.resolve()),
        "prefix": str((root / "python").resolve()),
        "base_prefix": str((root / "python").resolve()),
        "sys_path": [
            str((root / "python/lib/python312.zip").resolve()),
            str((root / "python/lib/python3.12").resolve()),
            str((root / "python/lib/python3.12/lib-dynload").resolve()),
            str(site.resolve()),
        ],
        "modules": [
            {
                "module": module,
                "path": f"python/lib/python3.12/site-packages/{module}/__init__.py",
            }
            for module in ("devhub", "mcp", "pydantic", "tokenizers")
        ],
        "distributions": [
            {
                "name": "codex-dev-hub",
                "version": "0.1.0",
                "record_sha256": HASH,
                "file_count": 1,
            }
        ],
    }
    monkeypatch.setattr(
        "devhub.linux_bundle.subprocess.check_output",
        lambda *_, **__: json.dumps(observed).encode(),
    )

    runtime = observe_linux_runtime(interpreter, wheel, lock, COMMIT)
    assert runtime.payload.sys_path[0] == "python/lib/python312.zip"

    observed["sys_path"][0] = str(tmp_path / "outside.zip")
    with pytest.raises(ValueError, match="escapes"):
        observe_linux_runtime(interpreter, wheel, lock, COMMIT)


def test_linux_bundle_workflow_is_exact_main_only_and_non_ready() -> None:
    workflow = (ROOT / ".github/workflows/linux-native-bundle.yml").read_text(encoding="utf-8")
    assert workflow.startswith("name: Native Linux directory bundle V11\n")
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "devfabric-linux-build-012-binaries" in workflow
    assert "EXPECTED_CODEX_COMMIT: c272ed6169a718204f2830a4aa34a5548a650652" in workflow
    assert 'test "$BUILD_RUN_ID" = "38354927618"' in workflow
    assert 'test "$BUILD_RUN_ATTEMPT" = "1"' in workflow
    assert 'gh run view "$BUILD_RUN_ID"' in workflow
    assert ".headSha == $head and .attempt == $attempt" in workflow
    assert '.conclusion == "success" and .event == "workflow_dispatch"' in workflow
    assert '.path == ".github/workflows/linux-native-codex.yml"' in workflow
    codex_workflow = (ROOT / ".github/workflows/linux-native-codex.yml").read_text(encoding="utf-8")
    assert "linux-native-codex-evidence/linux-native-codex-build.json" in codex_workflow
    assert "--expected-commit '${{ github.sha }}'" in workflow
    assert "--expected-codex-commit 'c272ed6169a718204f2830a4aa34a5548a650652'" in workflow
    assert "--accepted-run-id '${{ inputs.native_build_run_id }}'" in workflow
    assert "--accepted-run-attempt '${{ inputs.native_build_run_attempt }}'" in workflow
    assert "scripts/verify_linux_native_bundle.py" in workflow
    builder = (ROOT / "scripts/build_linux_native_bundle.py").read_text(encoding="utf-8")
    assert 'ARCHIVE_NAME = "devfabric-linux-native.tar.gz"' in builder
    assert "LinuxNativeBundleV11.create" in builder
    assert "LinuxNativeBundleV10.create" not in builder
    source = (ROOT / "src/devhub/linux_bundle.py").read_text(encoding="utf-8")
    assert "native_executor_isolation_qualified: Literal[False]" in source
    assert "package_readiness: Literal[False]" in source


def test_linux_bundle_builder_rejects_external_runtime_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    external = tmp_path / "external"
    external.write_text("outside", encoding="utf-8")
    link = source / "escape"
    try:
        link.symlink_to(external)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="symlink escapes"):
        BUILDER._validate_source_prefix(source)


def test_linux_bundle_elf_observation_is_strict_static_and_rejects_search_paths(
    tmp_path: Path,
) -> None:
    elf = _write(
        tmp_path,
        "python",
        _minimal_dynamic_elf(needed=("libpython3.12.so.1.0", "libc.so.6")),
    )
    observed = inspect_linux_dynamic_elf(elf, "python/bin/python3.12")
    assert observed.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert observed.needed == ("libc.so.6", "libpython3.12.so.1.0")

    elf.write_bytes(_minimal_dynamic_elf(needed=("libc.so.6", "libz.so.1")))
    substituted = inspect_linux_dynamic_elf(elf, "python/bin/python3.12")
    assert substituted != observed
    assert substituted.needed == ("libc.so.6", "libz.so.1")

    elf.write_bytes(_minimal_dynamic_elf(interpreter="/unreviewed/loader"))
    with pytest.raises(ValueError, match="another interpreter"):
        inspect_linux_dynamic_elf(elf, "python/bin/python3.12")


@pytest.mark.parametrize("value", ("", ":", "::", "$ORIGIN/../lib", "/usr/lib"))
@pytest.mark.parametrize("tag", ("rpath", "runpath"))
def test_linux_bundle_elf_observation_rejects_any_search_path_tag(
    tmp_path: Path, tag: str, value: str
) -> None:
    arguments = {tag: value}
    elf = _write(tmp_path, f"{tag}-{len(value)}", _minimal_dynamic_elf(**arguments))
    with pytest.raises(ValueError, match="contains RPATH/RUNPATH"):
        inspect_linux_dynamic_elf(elf, "python/bin/python3.12")


@pytest.mark.parametrize(
    "relative,mode",
    (
        ("python/bin/python3.12", 0o755),
        ("runtime/lib/libpython3.12.so.1.0", 0o644),
        ("python/lib/python3.12/lib-dynload/_ssl.so", 0o755),
    ),
)
def test_linux_bundle_strips_setup_python_search_paths_without_other_authority_changes(
    tmp_path: Path, relative: str, mode: int
) -> None:
    hosted = "/opt/hostedtoolcache/Python/3.12.10/x64/lib"
    elf = _write(
        tmp_path,
        relative,
        _minimal_dynamic_elf(
            needed=("libpython3.12.so.1.0", "libc.so.6"),
            rpath=hosted,
            runpath=hosted,
        ),
    )
    elf.chmod(mode)
    before = elf.read_bytes()
    before_mode = elf.stat().st_mode & 0o777

    assert strip_linux_elf_search_paths(elf, relative) == 2
    observed = inspect_linux_dynamic_elf(elf, relative)
    after = elf.read_bytes()

    assert observed.needed == ("libc.so.6", "libpython3.12.so.1.0")
    assert observed.rpath == ()
    assert observed.runpath == ()
    assert len(after) == len(before)
    assert elf.stat().st_mode & 0o777 == before_mode
    assert after[:0x200] == before[:0x200]
    assert after[0x270:] == before[0x270:]
    assert strip_linux_elf_search_paths(elf, relative) == 0


def test_linux_bundle_authoritative_interpreter_still_requires_sanitization_if_alias_removed(
    tmp_path: Path,
) -> None:
    raw = _minimal_dynamic_elf(
        needed=("libpython3.12.so.1.0",),
        runpath="/opt/hostedtoolcache/Python/3.12.10/x64/lib",
    )
    alias = _write(tmp_path, "python/bin/python", raw)
    interpreter = _write(tmp_path, "python/bin/python3.12", raw)
    alias.unlink()

    with pytest.raises(ValueError, match="contains RPATH/RUNPATH"):
        inspect_linux_dynamic_elf(interpreter, "python/bin/python3.12")


def test_linux_bundle_builder_sanitizes_every_dynamic_object(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    hosted = "/opt/hostedtoolcache/Python/3.12.10/x64/lib"
    paths = (
        "python/bin/python3.12",
        "runtime/lib/libpython3.12.so.1.0",
        "python/lib/python3.12/lib-dynload/_ssl.so",
    )
    for relative in paths:
        _write(root, relative, _minimal_dynamic_elf(runpath=hosted))

    assert BUILDER._strip_runtime_search_paths(root) == len(paths)
    for relative in paths:
        observed = inspect_linux_dynamic_elf(root / relative, relative)
        assert observed.rpath == ()
        assert observed.runpath == ()


def test_linux_bundle_search_path_sanitizer_rejects_malformed_dynamic_tables(
    tmp_path: Path,
) -> None:
    truncated = _write(tmp_path, "truncated", b"\x7fELF\x02\x01")
    with pytest.raises(ValueError, match="header is truncated"):
        strip_linux_elf_search_paths(truncated, "python/bin/python3.12")

    duplicate = bytearray(_minimal_dynamic_elf(runpath="/runner/lib"))
    duplicate[56:58] = struct.pack("<H", 4)
    dynamic_header = duplicate[64 + 2 * 56 : 64 + 3 * 56]
    duplicate[64 + 3 * 56 : 64 + 4 * 56] = dynamic_header
    duplicate_path = _write(tmp_path, "duplicate", bytes(duplicate))
    with pytest.raises(ValueError, match="multiple PT_DYNAMIC"):
        strip_linux_elf_search_paths(duplicate_path, "python/bin/python3.12")

    unterminated = bytearray(_minimal_dynamic_elf(runpath="/runner/lib"))
    dynamic_size = 5 * 16
    unterminated[0x200 + dynamic_size - 16 : 0x200 + dynamic_size] = struct.pack("<qQ", 2, 0)
    unterminated_path = _write(tmp_path, "unterminated", bytes(unterminated))
    with pytest.raises(ValueError, match="has no terminator"):
        strip_linux_elf_search_paths(unterminated_path, "python/bin/python3.12")

    unaligned = bytearray(_minimal_dynamic_elf(runpath="/runner/lib"))
    dynamic_header_offset = 64 + 2 * 56
    unaligned[dynamic_header_offset + 32 : dynamic_header_offset + 40] = struct.pack("<Q", 17)
    unaligned_path = _write(tmp_path, "unaligned", bytes(unaligned))
    with pytest.raises(ValueError, match="dynamic table is invalid"):
        strip_linux_elf_search_paths(unaligned_path, "python/bin/python3.12")


def test_linux_bundle_search_path_sanitizer_rejects_symlink(tmp_path: Path) -> None:
    target = _write(tmp_path, "target", _minimal_dynamic_elf(runpath="/runner/lib"))
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="not a plain file"):
        strip_linux_elf_search_paths(link, "python/bin/python3.12")


def test_linux_bundle_loader_diagnostic_is_bounded_and_authority_specific() -> None:
    requirement = LinuxElfRequirementV1(path="python/lib/extension.so")
    line = "statically linked"
    diagnostic = json.loads(BUILDER._loader_output_diagnostic(line, 3, requirement))

    assert diagnostic == {
        "classification": "UNRECOGNIZED_LOADER_OUTPUT_LINE_V1",
        "interpreter_present": False,
        "line_byte_count": len(line.encode()),
        "line_index": 3,
        "line_sha256": hashlib.sha256(line.encode()).hexdigest(),
        "needed_count": 0,
    }
    assert line not in json.dumps(diagnostic)
    assert "/" not in json.dumps(diagnostic)

    changed_line = json.loads(
        BUILDER._loader_output_diagnostic("statically linked ", 3, requirement)
    )
    assert changed_line["line_sha256"] != diagnostic["line_sha256"]

    changed_authority = json.loads(
        BUILDER._loader_output_diagnostic(
            line,
            3,
            LinuxElfRequirementV1(
                path="python/bin/python3.12",
                interpreter="/lib64/ld-linux-x86-64.so.2",
                needed=("libc.so.6",),
            ),
        )
    )
    assert changed_authority["interpreter_present"] is True
    assert changed_authority["needed_count"] == 1


def test_linux_bundle_dependency_free_loader_output_is_exact() -> None:
    dependency_free = LinuxElfRequirementV1(path="python/lib/extension.so")
    exact = ("\tstatically linked",)

    assert BUILDER._is_expected_dependency_free_loader_output(exact, dependency_free)
    assert not BUILDER._is_expected_dependency_free_loader_output(
        ("statically linked",), dependency_free
    )
    assert not BUILDER._is_expected_dependency_free_loader_output(
        ("\tstatically linked", ""), dependency_free
    )
    assert not BUILDER._is_expected_dependency_free_loader_output(
        ("\tstatically linked", "extra"), dependency_free
    )
    assert not BUILDER._is_expected_dependency_free_loader_output(
        exact,
        LinuxElfRequirementV1(
            path="python/bin/python3.12",
            interpreter="/lib64/ld-linux-x86-64.so.2",
        ),
    )
    assert not BUILDER._is_expected_dependency_free_loader_output(
        exact,
        LinuxElfRequirementV1(path="runtime/lib/libc.so.6", needed=("libm.so.6",)),
    )


@pytest.mark.skipif(sys.platform == "win32", reason="Bundled glibc resolution is Linux-only")
def test_linux_bundle_loader_resolution_rejects_ambient_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle"
    bundle = materialize_v9(root)
    raw_closure = bundle.payload.runtime_closure.model_dump(mode="python")
    for requirement in raw_closure["elf_requirements"]:
        if requirement["path"] == "codex/codex":
            requirement["needed"] = ("ld-linux-x86-64.so.2", "libc.so.6")
    closure = LinuxRuntimeClosureV1.model_validate(raw_closure)
    ambient = _write(tmp_path, "ambient/libc.so.6", b"ambient")

    def completed(
        *,
        ambient_libc: bool,
        include_loader: bool = True,
        omit_library: str | None = None,
        loader_alias: str | None = None,
        loader_locator: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        lines = ["linux-vdso.so.1 (0x0000000000000002)"]
        if include_loader:
            loader = root / closure.loader_path
            lines.insert(
                0,
                f"{loader_alias or closure.embedded_interpreter} => "
                f"{loader_locator or loader} (0x0000000000000001)",
            )
        for library in closure.libraries:
            if library.soname == omit_library:
                continue
            locator = root / library.path
            if ambient_libc and library.soname == "libc.so.6":
                locator = ambient
            lines.append(f"{library.soname} => {locator} (0x0000000000000003)")
        return subprocess.CompletedProcess([], 0, ("\n".join(lines) + "\n").encode(), b"")

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: completed(ambient_libc=False))
    BUILDER._verify_loader_resolution(root, closure)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: completed(ambient_libc=False, include_loader=False),
    )
    BUILDER._verify_loader_resolution(root, closure)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: completed(ambient_libc=False, omit_library="libc.so.6"),
    )
    with pytest.raises(ValueError, match="omitted a direct dependency"):
        BUILDER._verify_loader_resolution(root, closure)

    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: completed(ambient_libc=True))
    with pytest.raises(ValueError, match="ambient dependency: libc.so.6"):
        BUILDER._verify_loader_resolution(root, closure)

    ambient_loader = _write(tmp_path, "ambient/ld-linux-x86-64.so.2", b"ambient")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: completed(ambient_libc=False, loader_locator=str(ambient_loader)),
    )
    with pytest.raises(ValueError, match="alias did not resolve to bundled loader"):
        BUILDER._verify_loader_resolution(root, closure)

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: completed(
            ambient_libc=False,
            loader_alias="/unexpected/ld-linux-x86-64.so.2",
        ),
    )
    with pytest.raises(ValueError, match="unexpected absolute alias"):
        BUILDER._verify_loader_resolution(root, closure)

    loader = root / closure.loader_path
    loader.write_bytes(b"substituted")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("subprocess ran before loader identity validation"),
    )
    with pytest.raises(ValueError, match="loader bytes differ"):
        BUILDER._verify_loader_resolution(root, closure)


@pytest.mark.skipif(sys.platform == "win32", reason="Bundled glibc resolution is Linux-only")
def test_linux_bundle_loader_resolution_accepts_only_exact_dependency_free_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle"
    bundle = materialize_v9(root)
    dependency_free = LinuxElfRequirementV1(path="python/lib/extension.so")
    closure = bundle.payload.runtime_closure.model_copy(
        update={"elf_requirements": (dependency_free,)}
    )

    def completed(stdout: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, stdout, b"")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: completed(b"\tstatically linked\n"),
    )
    BUILDER._verify_loader_resolution(root, closure)

    for rejected in (
        b"statically linked\n",
        b"\tstatically linked\n\n",
        b"\tstatically linked\nextra\n",
    ):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *_args, _stdout=rejected, **_kwargs: completed(_stdout),
        )
        with pytest.raises(ValueError, match="UNRECOGNIZED_LOADER_OUTPUT_LINE_V1"):
            BUILDER._verify_loader_resolution(root, closure)

    dependent = closure.model_copy(
        update={
            "elf_requirements": (dependency_free.model_copy(update={"needed": ("libc.so.6",)}),)
        }
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: completed(b"\tstatically linked\n"),
    )
    with pytest.raises(ValueError, match="UNRECOGNIZED_LOADER_OUTPUT_LINE_V1"):
        BUILDER._verify_loader_resolution(root, dependent)


def test_linux_bundle_copies_transitive_runtime_closure_as_plain_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "bundle"
    objects = tuple(
        _write(root, relative, b"\x7fELF-object")
        for relative in (
            "python/bin/python3.12",
            "codex/codex",
            "codex/codex-code-mode-host",
        )
    )
    sources = tmp_path / "sources"
    loader = _write(sources, "ld-linux-x86-64.so.2", b"loader")
    libc = _write(sources, "libc.so.6", b"libc")
    libm = _write(sources, "libm.so.6", b"libm")
    monkeypatch.setattr(BUILDER, "_EXPECTED_INTERPRETER", str(loader))
    monkeypatch.setattr(BUILDER, "_elf_files", lambda _: objects)
    monkeypatch.setattr(BUILDER, "linux_elf_needed_names", lambda *_: ("libc.so.6",))
    monkeypatch.setattr(
        BUILDER,
        "_ldd_resolutions",
        lambda _: {"libc.so.6": libc, "libm.so.6": libm},
    )

    BUILDER._copy_runtime_closure(root)

    copied_loader = root / "runtime/loader/ld-linux-x86-64.so.2"
    assert copied_loader.read_bytes() == b"loader"
    if sys.platform != "win32":
        assert copied_loader.stat().st_mode & 0o777 == 0o755
    assert (root / "runtime/lib/libc.so.6").read_bytes() == b"libc"
    assert (root / "runtime/lib/libm.so.6").read_bytes() == b"libm"
    assert not (root / "runtime/lib/libc.so.6").is_symlink()


def test_linux_strict_verifiers_reject_symlinked_root_and_archive(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    bundle = materialize(root)
    root_link = tmp_path / "bundle-link"
    archive = tmp_path / "archive.tar.gz"
    archive.write_bytes(b"archive")
    archive_link = tmp_path / "archive-link.tar.gz"
    try:
        root_link.symlink_to(root, target_is_directory=True)
        archive_link.symlink_to(archive)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="plain directory"):
        verify_linux_native_bundle(bundle, root_link)
    with pytest.raises(ValueError, match="plain regular file"):
        extract_and_verify_linux_archive(archive_link, tmp_path / "extracted", bundle)


def test_linux_bundle_builder_rejects_downloaded_artifact_layout_and_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifact"
    _write(root, "binary/codex", b"codex")
    _write(root, "binary/codex-code-mode-host", b"host")
    _write(root, "linux-native-codex-build.json", b"{}")
    _write(root, "native-build-artifact-inventory.json", b"{}")
    _write(root, "linux-build-result.json", b"result")
    _write(root, "linux-process-proof.json", b"proof")
    _write(root, "code-mode-host-eof.json", b"eof")
    BUILDER._plain_artifact_layout(root)

    _write(root, "unexpected.json", b"substitution")
    with pytest.raises(ValueError, match="layout differs"):
        BUILDER._plain_artifact_layout(root)
    (root / "unexpected.json").unlink()

    target = tmp_path / "outside"
    target.write_bytes(b"outside")
    link = root / "binary/codex"
    link.unlink()
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="symlink"):
        BUILDER._plain_artifact_layout(root)


def test_linux_bundle_accepts_observed_codex_size_within_codex_only_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifact"
    _write(root, "binary/codex", b"")
    _write(root, "binary/codex-code-mode-host", b"host")
    for name in (
        "linux-native-codex-build.json",
        "native-build-artifact-inventory.json",
        "linux-build-result.json",
        "linux-process-proof.json",
        "code-mode-host-eof.json",
    ):
        _write(root, name, b"{}")
    codex = root / "binary/codex"
    original_stat = Path.stat

    def reported_size(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        result = original_stat(path, follow_symlinks=follow_symlinks)
        if path == codex:
            values = list(result)
            values[6] = 1_344_548_808
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "stat", reported_size)

    BUILDER._plain_artifact_layout(root)


@pytest.mark.parametrize(
    ("relative", "size"),
    (
        ("binary/codex", 1536 * 1024 * 1024 + 1),
        ("binary/codex-code-mode-host", 512 * 1024 * 1024 + 1),
    ),
)
def test_linux_bundle_rejects_binary_over_its_role_specific_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative: str, size: int
) -> None:
    root = tmp_path / "artifact"
    _write(root, "binary/codex", b"codex")
    _write(root, "binary/codex-code-mode-host", b"host")
    for name in (
        "linux-native-codex-build.json",
        "native-build-artifact-inventory.json",
        "linux-build-result.json",
        "linux-process-proof.json",
        "code-mode-host-eof.json",
    ):
        _write(root, name, b"{}")
    target = root / relative
    original_stat = Path.stat

    def reported_size(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        result = original_stat(path, follow_symlinks=follow_symlinks)
        if path == target:
            values = list(result)
            values[6] = size
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, "stat", reported_size)

    with pytest.raises(ValueError, match=f"exceeds its bound: {relative}"):
        BUILDER._plain_artifact_layout(root)


def test_linux_bundle_reviews_exact_v12_artifact_authority(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    reviewable_v12_artifact(root)

    receipt = BUILDER._review_codex_artifact(root, COMMIT, 123, 1)

    assert receipt.payload.provenance.implementation_commit == COMMIT
    assert receipt.payload.provenance.workflow_run_id == 123
    assert receipt.payload.provenance.workflow_run_attempt == 1
    assert receipt.payload.provenance.build_id == "linux-build-012"
    assert len(tuple(root.rglob("*"))) == 8  # binary directory plus seven retained files


@pytest.mark.parametrize(
    ("expected_commit", "run_id", "run_attempt"),
    (
        ("d" * 40, 123, 1),
        (COMMIT, 124, 1),
        (COMMIT, 123, 2),
    ),
)
def test_linux_bundle_rejects_v12_artifact_authority_mismatch(
    tmp_path: Path, expected_commit: str, run_id: int, run_attempt: int
) -> None:
    root = tmp_path / "artifact"
    reviewable_v12_artifact(root)

    with pytest.raises(ValueError, match="provenance differs"):
        BUILDER._review_codex_artifact(root, expected_commit, run_id, run_attempt)


def test_linux_bundle_rejects_v11_artifact_and_receipt_inventory_substitution(
    tmp_path: Path,
) -> None:
    historical = tmp_path / "historical"
    linux_pass_artifact(
        historical,
        "linux-build-011",
        implementation_commit=COMMIT,
        workflow_run_id=123,
        workflow_run_attempt=1,
    )
    INVENTORY.seal_linux(historical, "linux-build-011")
    with pytest.raises(ValidationError):
        BUILDER._review_codex_artifact(historical, COMMIT, 123, 1)

    current = tmp_path / "current"
    reviewable_v12_artifact(current)
    inventory_path = current / "native-build-artifact-inventory.json"
    inventory = NativeBuildArtifactInventoryV2.model_validate_json(inventory_path.read_bytes())
    raw = inventory.payload.model_dump(mode="python")
    assert raw["linux_pair"] is not None
    raw["linux_pair"]["linux_native_codex_build_id"] = OTHER_HASH
    substituted = NativeBuildArtifactInventoryV2.create(
        NativeBuildArtifactInventoryPayloadV2.model_validate(raw)
    )
    inventory_path.write_text(substituted.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="provenance differs"):
        BUILDER._review_codex_artifact(current, COMMIT, 123, 1)


def test_linux_bundle_builder_joins_retained_result_proof_and_eof(tmp_path: Path) -> None:
    root = tmp_path / "artifact"
    content = {
        "binary/codex": b"codex",
        "binary/codex-code-mode-host": b"host",
        "code-mode-host-eof.json": b"eof",
        "linux-build-result.json": b"result",
        "linux-native-codex-build.json": b"receipt",
        "linux-process-proof.json": b"proof",
    }
    entries = []
    for relative, value in content.items():
        path = _write(root, relative, value)
        entries.append(
            NativeBuildArtifactEntryV1(
                relative_path=relative,
                kind="binary" if relative.startswith("binary/") else "evidence",
                size=path.stat().st_size,
                sha256=file_sha256(path),
            )
        )
    entries.sort(key=lambda item: item.relative_path)
    pair = LinuxNativeBuildArtifactJoinV1(
        build_receipt_sha256=file_sha256(root / "linux-native-codex-build.json"),
        linux_native_codex_build_id=HASH,
        codex_sha256=file_sha256(root / "binary/codex"),
        code_mode_host_sha256=file_sha256(root / "binary/codex-code-mode-host"),
        process_proof_sha256=file_sha256(root / "linux-process-proof.json"),
        code_mode_host_eof_receipt_sha256=file_sha256(root / "code-mode-host-eof.json"),
    )
    inventory = NativeBuildArtifactInventoryV2.create(
        NativeBuildArtifactInventoryPayloadV2(
            platform="linux",
            build_id="linux-build-012",
            status="PASS",
            build_result_sha256=file_sha256(root / "linux-build-result.json"),
            linux_pair=pair,
            files=tuple(entries),
        )
    )
    BUILDER._verify_retained_authority(root, inventory, pair)

    (root / "linux-process-proof.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="linux-process-proof"):
        BUILDER._verify_retained_authority(root, inventory, pair)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix mode preservation requires Linux")
@pytest.mark.parametrize("schema_version", (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11))
def test_linux_bundle_archive_preserves_modes_and_fresh_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schema_version: int
) -> None:
    release = tmp_path / "release"
    root = release / "bundle"
    bundle = (
        materialize(root)
        if schema_version == 1
        else materialize_v2(root)
        if schema_version == 2
        else materialize_v3(root)
        if schema_version == 3
        else materialize_v4(root)
        if schema_version == 4
        else materialize_v5(root)
        if schema_version == 5
        else materialize_v6(root)
        if schema_version == 6
        else materialize_v7(root)
        if schema_version == 7
        else materialize_v8(root)
        if schema_version == 8
        else materialize_v9(root)
        if schema_version == 9
        else materialize_v10(root)
        if schema_version == 10
        else materialize_v11(root)
    )
    for item in bundle.payload.files:
        root.joinpath(*item.path.split("/")).chmod(item.mode)
    (release / "linux-native-bundle.json").write_text(bundle.model_dump_json(), encoding="utf-8")
    archive = write_test_archive(release, bundle.linux_native_bundle_id, schema_version)
    assert archive.payload.sha256 == file_sha256(release / archive.payload.filename)

    inspected: list[tuple[LinuxBundleEntryV1, ...]] = []
    smoked: list[Path] = []
    monkeypatch.setattr(
        "devhub.linux_bundle.verify_linux_native_bundle",
        lambda expected, extracted: inspected.append(_entries(extracted)),
    )
    monkeypatch.setattr(
        "devhub.linux_bundle.smoke_linux_bundle_cli",
        lambda extracted, *_: smoked.append(extracted),
    )
    shutil.rmtree(root)
    verified = verify_linux_native_release(release, tmp_path / "extracted")
    assert verified == archive
    assert inspected == [bundle.payload.files]
    assert smoked == [tmp_path / "extracted/bundle"]

    extracted = tmp_path / "extracted/bundle"
    (extracted / "bin/devfabric").chmod(0o644)
    assert inventory_linux_bundle(extracted) != bundle.payload.files


@pytest.mark.skipif(sys.platform == "win32", reason="Archive substitution checks require Linux")
@pytest.mark.parametrize("substitution", ("archive", "manifest", "receipt"))
def test_linux_release_rejects_substitution(tmp_path: Path, substitution: str) -> None:
    release = tmp_path / "release"
    root = release / "bundle"
    bundle = materialize_v7(root)
    for item in bundle.payload.files:
        root.joinpath(*item.path.split("/")).chmod(item.mode)
    manifest = release / "linux-native-bundle.json"
    manifest.write_text(bundle.model_dump_json(), encoding="utf-8")
    archive = BUILDER._write_archive(release, bundle)
    shutil.rmtree(root)
    if substitution == "archive":
        with (release / archive.payload.filename).open("ab") as stream:
            stream.write(b"changed")
    elif substitution == "manifest":
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        raw["linux_native_bundle_id"] = OTHER_HASH
        manifest.write_text(json.dumps(raw), encoding="utf-8")
    else:
        receipt = release / "linux-native-archive.json"
        raw = json.loads(receipt.read_text(encoding="utf-8"))
        raw["linux_native_archive_id"] = OTHER_HASH
        receipt.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises((ValueError, ValidationError)):
        verify_linux_native_release(release, tmp_path / "extracted")


@pytest.mark.skipif(sys.platform == "win32", reason="Tar security checks require POSIX modes")
@pytest.mark.parametrize("unsafe", ("symlink", "traversal", "duplicate"))
def test_linux_bundle_archive_rejects_unsafe_members(tmp_path: Path, unsafe: str) -> None:
    root = tmp_path / "bundle"
    bundle = materialize(root)
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        if unsafe == "symlink":
            member = tarfile.TarInfo("bundle/escape")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../outside"
            stream.addfile(member)
        elif unsafe == "traversal":
            member = tarfile.TarInfo("bundle/../outside")
            member.size = 1
            stream.addfile(member, io.BytesIO(b"x"))
        else:
            for value in (b"a", b"b"):
                member = tarfile.TarInfo("bundle/value")
                member.size = 1
                stream.addfile(member, io.BytesIO(value))
    with pytest.raises(ValueError, match="unsafe member"):
        extract_and_verify_linux_archive(archive, tmp_path / "extracted", bundle)


@pytest.mark.skipif(sys.platform == "win32", reason="Native launcher smoke requires POSIX shell")
def test_linux_bundle_smoke_uses_valid_metadata_only_command(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    schema = json.dumps(
        {
            "HubConfig": {},
            "ModelResult": {},
            "StatusRequest": {},
            "StatusResponse": {},
            "TaskRequest": {},
        },
        separators=(",", ":"),
    )
    launcher = _write(
        root,
        "bin/devfabric",
        f"#!/bin/sh\nprintf '%s\\n' '{schema}'\n".encode(),
    )
    launcher.chmod(0o755)
    smoke_linux_bundle_cli(root)
