from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.native_bundle import (
    EmbeddedPythonAuthorityV1,
    NativeBundleFileV1,
    NativeBundlePayloadV1,
    NativeBundleV1,
    NativeCodexAuthorityV1,
    NativeCodexAuthorityV2,
    NativeDependencyWheelV1,
    NativeLauncherV1,
    NativeLauncherV2,
    NativeModuleOriginV1,
    NativePythonRuntimePayloadV1,
    NativePythonRuntimeV1,
    _native_bundle_payload_json,
    embedded_archive_members_sha256,
    file_sha256,
    inspect_embedded_windows_runtime,
    inventory_native_bundle,
    sanitize_installed_wheel_tree,
    verify_native_bundle,
)
from devhub.runtime_artifact import DistributionIdentityV1
from devhub.windows_native import (
    WindowsBuildProvenanceV2,
    WindowsHostProofSummaryV2,
    WindowsNativeBinaryV2,
    WindowsNativeCodexBuildPayloadV2,
    WindowsNativeCodexBuildV2,
    WindowsPeIdentityV1,
)

HASH = "a" * 64
COMMIT = "b" * 40


def write(root: Path, relative: str, raw: bytes) -> Path:
    target = root / Path(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return target


def write_wheel(path: Path, name: str, version: str, module: str) -> dict[str, bytes]:
    info = f"{name.replace('-', '_')}-{version}.dist-info"
    files = {
        f"{module}/__init__.py": b"__version__ = 'fixture'\n",
        f"{info}/METADATA": f"Name: {name}\nVersion: {version}\n".encode(),
        f"{info}/RECORD": b"",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as stream:
        for relative, raw in files.items():
            stream.writestr(relative, raw)
    return files


def install_fixture_wheels(site_packages: Path, wheels: tuple[Path, ...]) -> None:
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as stream:
            stream.extractall(site_packages)
    sanitize_installed_wheel_tree(site_packages, wheels)


def build_fixture(root: Path) -> NativeBundleV1:
    pth = write(
        root,
        "python/python312._pth",
        (
            "python312.zip\n"
            ".\n"
            "site-packages\n"
            "site-packages\\win32\n"
            "site-packages\\win32\\lib\n"
            "site-packages\\pythonwin\n"
            "site-packages\\pywin32_system32\n"
        ).encode("ascii"),
    )
    python = write(root, "python/python.exe", b"python")
    archive = root / "authority/python-3.12.10-embed-amd64.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("python.exe", b"python")
        stream.writestr("python312._pth", b"upstream path file")
    sbom = write(root, "authority/python-3.12.10-embed-amd64.zip.spdx.json", b"sbom")
    wheel = root / "authority/codex_dev_hub-0.1.0-py3-none-any.whl"
    write_wheel(wheel, "codex-dev-hub", "0.1.0", "devhub")
    dependency_wheel = root / "authority/wheels/mcp-2.2.0-py3-none-any.whl"
    write_wheel(dependency_wheel, "mcp", "2.2.0", "mcp")
    install_fixture_wheels(root / "python/site-packages", (wheel, dependency_wheel))
    lock = write(root, "authority/uv.lock", b"lock")
    receipt = write(root, "authority/windows-build-result.json", b"receipt")
    codex = write(root, "codex/codex.exe", b"codex")
    runtime = NativePythonRuntimeV1.create(
        NativePythonRuntimePayloadV1(
            python_executable_sha256=file_sha256(python),
            platform_machine="AMD64",
            devhub_source_commit=COMMIT,
            devhub_wheel_sha256=file_sha256(wheel),
            dependency_lock_sha256=file_sha256(lock),
            devhub_distribution_version="0.1.0",
            sys_path=(
                "python/python312.zip",
                "python",
                "python/site-packages",
                "python/site-packages/win32",
                "python/site-packages/win32/lib",
                "python/site-packages/pythonwin",
                "python/site-packages/pywin32_system32",
            ),
            module_origins=tuple(
                NativeModuleOriginV1(module=name, path=f"python/site-packages/{name}")
                for name in ("devhub", "mcp", "pydantic", "pywintypes", "tokenizers")
            ),
            distributions=(
                DistributionIdentityV1(
                    name="codex-dev-hub", version="0.1.0", record_sha256=HASH, file_count=1
                ),
                DistributionIdentityV1(
                    name="mcp", version="2.2.0", record_sha256="c" * 64, file_count=2
                ),
            ),
        )
    )
    payload = NativeBundlePayloadV1(
        platform="windows",
        architecture="x86_64",
        implementation_commit=COMMIT,
        python=EmbeddedPythonAuthorityV1(
            archive_sha256=file_sha256(archive),
            archive_members_sha256=embedded_archive_members_sha256(archive.read_bytes()),
            sbom_sha256=file_sha256(sbom),
            executable_sha256=file_sha256(python),
            pth_sha256=file_sha256(pth),
            devhub_wheel_path="authority/codex_dev_hub-0.1.0-py3-none-any.whl",
            devhub_source_archive_sha256=HASH,
            devhub_wheel_sha256=file_sha256(wheel),
            dependency_lock_sha256=file_sha256(lock),
            dependency_wheels=(
                NativeDependencyWheelV1(
                    name="mcp",
                    version="2.2.0",
                    filename="mcp-2.2.0-py3-none-any.whl",
                    sha256=file_sha256(dependency_wheel),
                ),
            ),
            runtime=runtime,
        ),
        codex=NativeCodexAuthorityV1(
            accepted_run_id=1,
            devfabric_implementation_commit=COMMIT,
            build_receipt_sha256=file_sha256(receipt),
            executable_sha256=file_sha256(codex),
            codex_source_commit=COMMIT,
            source_archive_sha256=HASH,
            candidate_b_base_patch_sha256=HASH,
            host_integration_patch_sha256=HASH,
            combined_patchset_sha256=HASH,
        ),
        launcher=NativeLauncherV1(),
        files=inventory_native_bundle(root),
    )
    return NativeBundleV1.create(payload)


def build_pair_fixture(root: Path) -> NativeBundleV1:
    historical = build_fixture(root)
    (root / "authority/windows-build-result.json").unlink()
    host = write(root, "codex/codex-code-mode-host.exe", b"code mode host")
    codex_binary = WindowsNativeBinaryV2(
        role="codex",
        relative_path="binary/codex.exe",
        sha256=file_sha256(root / "codex/codex.exe"),
        size=(root / "codex/codex.exe").stat().st_size,
        pe=WindowsPeIdentityV1(dll_characteristics=0x8160),
    )
    host_binary = WindowsNativeBinaryV2(
        role="codex-code-mode-host",
        relative_path="binary/codex-code-mode-host.exe",
        sha256=file_sha256(host),
        size=host.stat().st_size,
        pe=WindowsPeIdentityV1(dll_characteristics=0x8160),
    )
    pair = WindowsNativeCodexBuildV2.create(
        WindowsNativeCodexBuildPayloadV2(
            provenance=WindowsBuildProvenanceV2(
                implementation_commit=COMMIT,
                workflow_run_id=2,
                workflow_run_attempt=1,
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
            ),
            binaries=(codex_binary, host_binary),
            process_proof=WindowsHostProofSummaryV2(
                process_proof_sha256=HASH,
                code_mode_host_sha256=host_binary.sha256,
                code_mode_host_eof_receipt_sha256=HASH,
            ),
        )
    )
    pair_receipt = write(
        root,
        "authority/windows-native-codex-build.json",
        pair.model_dump_json(indent=2).encode() + b"\n",
    )
    payload = NativeBundlePayloadV1(
        platform="windows",
        architecture="x86_64",
        implementation_commit=historical.payload.implementation_commit,
        python=historical.payload.python,
        codex=NativeCodexAuthorityV2(
            accepted_run_id=2,
            accepted_run_attempt=1,
            devfabric_implementation_commit=COMMIT,
            build_receipt_sha256=file_sha256(pair_receipt),
            windows_native_codex_build_id=pair.windows_native_codex_build_id,
            executable_sha256=file_sha256(root / "codex/codex.exe"),
            code_mode_host_sha256=file_sha256(host),
            process_proof_sha256=pair.payload.process_proof.process_proof_sha256,
            code_mode_host_eof_receipt_sha256=(
                pair.payload.process_proof.code_mode_host_eof_receipt_sha256
            ),
            codex_source_commit=COMMIT,
            source_archive_sha256=HASH,
            candidate_b_base_patch_sha256=HASH,
            host_integration_patch_sha256=HASH,
            combined_patchset_sha256=HASH,
        ),
        launcher=NativeLauncherV2(),
        files=inventory_native_bundle(root),
    )
    return NativeBundleV1.create(payload)


def test_native_bundle_canonical_id_and_exact_inventory(tmp_path: Path) -> None:
    bundle = build_fixture(tmp_path)

    canonical_payload = _native_bundle_payload_json(bundle.payload)
    assert isinstance(canonical_payload, dict)
    assert canonical_payload["codex"] == bundle.payload.codex.model_dump(mode="json")
    assert canonical_payload["launcher"] == bundle.payload.launcher.model_dump(mode="json")
    assert "code_mode_host_path" not in canonical_payload["launcher"]
    assert "accepted_run_attempt" not in canonical_payload["codex"]
    reparsed = NativeBundleV1.model_validate_json(bundle.model_dump_json())
    verify_native_bundle(
        reparsed, tmp_path, expected_platform="windows", expected_architecture="x86_64"
    )
    assert reparsed == bundle


def test_native_bundle_v2_requires_exact_codex_sibling_pair(tmp_path: Path) -> None:
    bundle = build_pair_fixture(tmp_path)
    reparsed = NativeBundleV1.model_validate_json(bundle.model_dump_json())
    verify_native_bundle(
        reparsed, tmp_path, expected_platform="windows", expected_architecture="x86_64"
    )
    assert isinstance(reparsed.payload.codex, NativeCodexAuthorityV2)
    assert isinstance(reparsed.payload.launcher, NativeLauncherV2)

    (tmp_path / "codex/codex-code-mode-host.exe").write_bytes(b"changed")
    with pytest.raises(ValueError, match="files differ"):
        verify_native_bundle(
            reparsed, tmp_path, expected_platform="windows", expected_architecture="x86_64"
        )


def test_native_bundle_v2_rejects_self_consistent_embedded_receipt_substitution(
    tmp_path: Path,
) -> None:
    bundle = build_pair_fixture(tmp_path)
    receipt_path = tmp_path / "authority/windows-native-codex-build.json"
    receipt = WindowsNativeCodexBuildV2.model_validate_json(receipt_path.read_bytes())
    provenance = receipt.payload.provenance.model_dump(mode="python")
    provenance["workflow_run_id"] = 3
    changed_payload = receipt.payload.model_dump(mode="python")
    changed_payload["provenance"] = provenance
    changed = WindowsNativeCodexBuildV2.create(
        WindowsNativeCodexBuildPayloadV2.model_validate(changed_payload)
    )
    receipt_path.write_text(changed.model_dump_json(indent=2) + "\n", encoding="utf-8")
    authority = bundle.payload.codex.model_dump(mode="python")
    authority["build_receipt_sha256"] = file_sha256(receipt_path)
    changed_bundle = NativeBundleV1.create(
        NativeBundlePayloadV1(
            **{
                **bundle.payload.model_dump(mode="python"),
                "codex": NativeCodexAuthorityV2.model_validate(authority),
                "files": inventory_native_bundle(tmp_path),
            }
        )
    )

    with pytest.raises(ValueError, match="build authority differs"):
        verify_native_bundle(
            changed_bundle,
            tmp_path,
            expected_platform="windows",
            expected_architecture="x86_64",
        )


def test_native_bundle_rejects_forged_id(tmp_path: Path) -> None:
    raw = build_fixture(tmp_path).model_dump(mode="json")
    raw["bundle_id"] = "f" * 64

    with pytest.raises(ValidationError, match="Native bundle ID mismatch"):
        NativeBundleV1.model_validate_json(json.dumps(raw))


@pytest.mark.parametrize("mutation", ["extra", "missing", "tampered"])
def test_native_bundle_rejects_file_inventory_changes(tmp_path: Path, mutation: str) -> None:
    bundle = build_fixture(tmp_path)
    if mutation == "extra":
        write(tmp_path, "unexpected.txt", b"extra")
    elif mutation == "missing":
        (tmp_path / "codex/codex.exe").unlink()
    else:
        (tmp_path / "codex/codex.exe").write_bytes(b"changed")

    with pytest.raises(ValueError, match="files differ"):
        verify_native_bundle(
            bundle, tmp_path, expected_platform="windows", expected_architecture="x86_64"
        )


def test_native_bundle_rejects_wrong_target(tmp_path: Path) -> None:
    bundle = build_fixture(tmp_path)

    with pytest.raises(ValueError, match="target differs"):
        verify_native_bundle(
            bundle, tmp_path, expected_platform="linux", expected_architecture="x86_64"
        )


def test_native_bundle_rejects_pth_import_or_extra_pth(tmp_path: Path) -> None:
    bundle = build_fixture(tmp_path)
    pth = tmp_path / "python/python312._pth"
    pth.write_text(pth.read_text(encoding="ascii") + "import site\n", encoding="ascii")
    payload = bundle.payload.model_copy(
        update={
            "python": bundle.payload.python.model_copy(update={"pth_sha256": file_sha256(pth)}),
            "files": inventory_native_bundle(tmp_path),
        }
    )
    forged = NativeBundleV1.create(payload)

    with pytest.raises(ValueError, match="path authority"):
        verify_native_bundle(
            forged, tmp_path, expected_platform="windows", expected_architecture="x86_64"
        )

    pth.write_text(
        "python312.zip\n.\nsite-packages\nsite-packages\\win32\n"
        "site-packages\\win32\\lib\nsite-packages\\pythonwin\n"
        "site-packages\\pywin32_system32\n",
        encoding="ascii",
    )
    write(tmp_path, "python/site-packages/unreviewed.pth", b"outside\n")
    payload = bundle.payload.model_copy(
        update={
            "python": bundle.payload.python.model_copy(update={"pth_sha256": file_sha256(pth)}),
            "files": inventory_native_bundle(tmp_path),
        }
    )
    forged = NativeBundleV1.create(payload)
    with pytest.raises(ValueError, match="unreviewed Python startup"):
        verify_native_bundle(
            forged, tmp_path, expected_platform="windows", expected_architecture="x86_64"
        )


def test_native_bundle_rejects_path_escape_and_mutable_state(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="must not escape"):
        NativeBundleFileV1(path="../escape", size=0, sha256=HASH)

    bundle = build_fixture(tmp_path)
    mutable = write(tmp_path, "config/settings.json", b"{}")
    files = tuple(
        sorted(
            (
                *bundle.payload.files,
                NativeBundleFileV1(
                    path="config/settings.json", size=2, sha256=file_sha256(mutable)
                ),
            ),
            key=lambda item: item.path,
        )
    )
    with pytest.raises(ValidationError, match="Mutable application state"):
        NativeBundlePayloadV1.model_validate_json(
            json.dumps(
                {
                    **bundle.payload.model_dump(mode="json"),
                    "files": [item.model_dump(mode="json") for item in files],
                }
            )
        )


def test_native_bundle_rejects_unreviewed_authority_and_case_collision(tmp_path: Path) -> None:
    bundle = build_fixture(tmp_path)
    raw = bundle.payload.model_dump(mode="json")
    raw["files"].append({"path": "authority/unreviewed.json", "size": 2, "sha256": HASH})
    raw["files"] = sorted(raw["files"], key=lambda item: item["path"])
    with pytest.raises(ValidationError, match="closed layout"):
        NativeBundlePayloadV1.model_validate_json(json.dumps(raw))

    raw = bundle.payload.model_dump(mode="json")
    raw["files"].append({"path": "CODEX/codex.exe", "size": 5, "sha256": HASH})
    raw["files"] = sorted(raw["files"], key=lambda item: item["path"])
    with pytest.raises(ValidationError, match="case-insensitively unique"):
        NativeBundlePayloadV1.model_validate_json(json.dumps(raw))


def test_native_bundle_rejects_symlink(tmp_path: Path) -> None:
    build_fixture(tmp_path)
    target = tmp_path / "python/python.exe"
    link = tmp_path / "python/linked.exe"
    try:
        os.symlink(target, link)
    except OSError:
        pytest.skip("symlink creation unavailable on this host")

    with pytest.raises(ValueError, match="symlink/reparse"):
        inventory_native_bundle(tmp_path)


def test_embedded_runtime_inspection_uses_isolated_hostile_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python_root = tmp_path / "python"
    site_packages = python_root / "site-packages"
    interpreter = write(tmp_path, "python/python.exe", b"python")
    write(tmp_path, "python/python312.zip", b"stdlib")
    wheel = write(tmp_path, "authority/devhub.whl", b"wheel")
    lock = write(tmp_path, "authority/uv.lock", b"lock")
    sys_path = (
        python_root / "python312.zip",
        python_root,
        site_packages,
        site_packages / "win32",
        site_packages / "win32/lib",
        site_packages / "pythonwin",
        site_packages / "pywin32_system32",
    )
    for item in sys_path[1:]:
        item.mkdir(parents=True, exist_ok=True)
    modules = []
    for name in ("devhub", "mcp", "pydantic", "pywintypes", "tokenizers"):
        origin = write(tmp_path, f"python/site-packages/{name}/__init__.py", b"")
        modules.append({"module": name, "path": origin.relative_to(tmp_path).as_posix()})
    observed = {
        "implementation": "CPython",
        "version": "3.12.10",
        "cache_tag": "cpython-312",
        "platform_tag": "win-amd64",
        "system": "Windows",
        "machine": None,
        "executable": str(interpreter.resolve()),
        "prefix": str(python_root.resolve()),
        "base_prefix": str(python_root.resolve()),
        "isolated": True,
        "ignore_environment": True,
        "no_user_site": True,
        "dont_write_bytecode": True,
        "editable": False,
        "sys_path": [str(item.resolve()) for item in sys_path],
        "modules": modules,
        "distributions": [
            {
                "name": "codex_dev_hub",
                "version": "0.1.0",
                "record_sha256": HASH,
                "file_count": 12,
            },
            {
                "name": "MCP",
                "version": "2.2.0",
                "record_sha256": "c" * 64,
                "file_count": 4,
            },
        ],
    }
    invocation: dict[str, object] = {}

    def fake_check_output(argv: list[str], **kwargs: object) -> bytes:
        invocation.update({"argv": argv, **kwargs})
        return json.dumps(observed).encode()

    monkeypatch.setattr("devhub.native_bundle.subprocess.check_output", fake_check_output)
    runtime = inspect_embedded_windows_runtime(interpreter, wheel, lock, COMMIT)

    assert invocation["argv"][:4] == [str(interpreter), "-I", "-B", "-c"]
    environment = invocation["env"]
    assert isinstance(environment, dict)
    assert environment["PATH"] == ""
    assert set(environment) <= {"PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE", "SYSTEMROOT"}
    assert runtime.payload.platform_machine is None
    assert [item.name for item in runtime.payload.distributions] == ["codex-dev-hub", "mcp"]
    assert runtime.payload.sys_path[0] == "python/python312.zip"
    assert runtime.payload.editable_install is False


def test_embedded_runtime_inspection_rejects_nonisolated_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter = write(tmp_path, "python/python.exe", b"python")
    wheel = write(tmp_path, "authority/devhub.whl", b"wheel")
    lock = write(tmp_path, "authority/uv.lock", b"lock")
    observed = {
        "implementation": "CPython",
        "version": "3.12.10",
        "cache_tag": "cpython-312",
        "platform_tag": "win-amd64",
        "system": "Windows",
        "isolated": False,
        "ignore_environment": True,
        "no_user_site": True,
        "dont_write_bytecode": True,
        "editable": False,
    }
    monkeypatch.setattr(
        "devhub.native_bundle.subprocess.check_output",
        lambda *args, **kwargs: json.dumps(observed).encode(),
    )

    with pytest.raises(ValueError, match="not isolated"):
        inspect_embedded_windows_runtime(interpreter, wheel, lock, COMMIT)
