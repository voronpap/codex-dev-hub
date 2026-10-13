from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

import pytest
from linux_native_artifact_support import linux_pass_artifact
from pydantic import ValidationError

from devhub.linux_bundle import (
    LinuxBundleEntryV1,
    LinuxCodexAuthorityV1,
    LinuxCodexAuthorityV2,
    LinuxCodexAuthorityV3,
    LinuxCodexAuthorityV4,
    LinuxCodexAuthorityV5,
    LinuxCodexAuthorityV6,
    LinuxLauncherV1,
    LinuxModuleOriginV1,
    LinuxNativeArchivePayloadV1,
    LinuxNativeArchivePayloadV2,
    LinuxNativeArchivePayloadV3,
    LinuxNativeArchivePayloadV4,
    LinuxNativeArchivePayloadV5,
    LinuxNativeArchivePayloadV6,
    LinuxNativeArchiveV1,
    LinuxNativeArchiveV2,
    LinuxNativeArchiveV3,
    LinuxNativeArchiveV4,
    LinuxNativeArchiveV5,
    LinuxNativeArchiveV6,
    LinuxNativeBundlePayloadV1,
    LinuxNativeBundlePayloadV2,
    LinuxNativeBundlePayloadV3,
    LinuxNativeBundlePayloadV4,
    LinuxNativeBundlePayloadV5,
    LinuxNativeBundlePayloadV6,
    LinuxNativeBundleV1,
    LinuxNativeBundleV2,
    LinuxNativeBundleV3,
    LinuxNativeBundleV4,
    LinuxNativeBundleV5,
    LinuxNativeBundleV6,
    LinuxPythonAuthorityV1,
    LinuxPythonRuntimePayloadV1,
    LinuxPythonRuntimeV1,
    extract_and_verify_linux_archive,
    inventory_linux_bundle,
    observe_linux_runtime,
    smoke_linux_bundle_cli,
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


def _write(root: Path, relative: str, value: bytes) -> Path:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return path


def _entries(root: Path) -> tuple[LinuxBundleEntryV1, ...]:
    executable = {
        "python/bin/python3.12",
        "codex/codex",
        "codex/codex-code-mode-host",
        "bin/devfabric",
        "bin/devhub-delegate-server",
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
        ) = LinuxNativeArchiveV1.create(LinuxNativeArchivePayloadV1(**fields))
    elif schema_version == 2:
        receipt = LinuxNativeArchiveV2.create(LinuxNativeArchivePayloadV2(**fields))
    elif schema_version == 3:
        receipt = LinuxNativeArchiveV3.create(LinuxNativeArchivePayloadV3(**fields))
    elif schema_version == 4:
        receipt = LinuxNativeArchiveV4.create(LinuxNativeArchivePayloadV4(**fields))
    elif schema_version == 5:
        receipt = LinuxNativeArchiveV5.create(LinuxNativeArchivePayloadV5(**fields))
    else:
        receipt = LinuxNativeArchiveV6.create(LinuxNativeArchivePayloadV6(**fields))
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


@pytest.mark.parametrize("manifest_version", (1, 2, 3, 4, 5, 6))
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
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "devfabric-linux-build-012-binaries" in workflow
    assert 'gh run view "$BUILD_RUN_ID"' in workflow
    assert ".headSha == $head and .attempt == $attempt" in workflow
    assert '.conclusion == "success" and .event == "workflow_dispatch"' in workflow
    assert '.path == ".github/workflows/linux-native-codex.yml"' in workflow
    codex_workflow = (ROOT / ".github/workflows/linux-native-codex.yml").read_text(encoding="utf-8")
    assert "linux-native-codex-evidence/linux-native-codex-build.json" in codex_workflow
    assert "--expected-commit '${{ github.sha }}'" in workflow
    assert "--accepted-run-id '${{ inputs.native_build_run_id }}'" in workflow
    assert "--accepted-run-attempt '${{ inputs.native_build_run_attempt }}'" in workflow
    assert "scripts/verify_linux_native_bundle.py" in workflow
    builder = (ROOT / "scripts/build_linux_native_bundle.py").read_text(encoding="utf-8")
    assert 'ARCHIVE_NAME = "devfabric-linux-native.tar.gz"' in builder
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
@pytest.mark.parametrize("schema_version", (1, 2, 3, 4, 5, 6))
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
        "devhub.linux_bundle.smoke_linux_bundle_cli", lambda extracted: smoked.append(extracted)
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
    bundle = materialize_v6(root)
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
