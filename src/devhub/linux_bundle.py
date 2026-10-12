"""Strict contracts for a relocatable native Linux DevFabric directory.

This slice seals a runnable directory and its exact runtime identities.  Native
executor isolation and platform readiness remain separate qualification gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tarfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.linux_native import (
    LinuxNativeCodexBuildV7,
    LinuxNativeCodexBuildV8,
    LinuxNativeCodexBuildV9,
)
from devhub.models import Contract
from devhub.native_bundle import (
    NativeDependencyWheelV1,
    file_sha256,
)
from devhub.native_proof import NativeBuildArtifactInventoryV2
from devhub.qualification import GitCommit
from devhub.runtime_artifact import DistributionIdentityV1, normalize_distribution_name

_INSPECT = r"""
import base64, hashlib, importlib, importlib.metadata as md, json, pathlib, platform, sys, sysconfig

def h(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()

root = pathlib.Path(sys.executable).resolve().parent.parent
site_packages = root / 'lib' / 'python3.12' / 'site-packages'
items = []
editable = False
for dist in md.distributions(path=[str(site_packages)]):
    name = (dist.metadata.get('Name') or '').strip()
    version = (dist.version or '').strip()
    if not name or not version:
        raise SystemExit('distribution metadata incomplete')
    direct = dist.read_text('direct_url.json')
    if direct:
        editable = True
        raise SystemExit('native bundle contains direct_url metadata')
    entries = []
    for item in dist.files or []:
        located = pathlib.Path(dist.locate_file(item)).resolve()
        if not located.is_relative_to(root) or not located.is_file():
            raise SystemExit('installed distribution file escapes or is missing')
        declared = item.hash
        text = str(item).replace('\\', '/')
        if declared is None:
            if not text.endswith('/RECORD'):
                raise SystemExit('unhashed installed file outside RECORD')
            declared_value = None
        else:
            if declared.mode != 'sha256':
                raise SystemExit('non-sha256 RECORD entry')
            observed = base64.urlsafe_b64encode(bytes.fromhex(h(located))).decode().rstrip('=')
            if observed != declared.value:
                raise SystemExit('installed file differs from RECORD')
            declared_value = declared.value
        entries.append([text, declared_value, located.stat().st_size])
    entries.sort()
    items.append({
        'name': name,
        'version': version,
        'record_sha256': hashlib.sha256(
            json.dumps(entries, separators=(',', ':'), sort_keys=True).encode()
        ).hexdigest(),
        'file_count': len(entries),
    })
items.sort(key=lambda value: value['name'].lower().replace('_', '-'))
modules = []
for name in ('devhub', 'mcp', 'pydantic', 'tokenizers'):
    module = importlib.import_module(name)
    origin = pathlib.Path(module.__file__).resolve()
    if not origin.is_relative_to(site_packages):
        raise SystemExit('module origin escapes native site-packages')
    modules.append({'module': name, 'path': origin.relative_to(root.parent).as_posix()})
print(json.dumps({
    'implementation': platform.python_implementation(),
    'version': platform.python_version(),
    'cache_tag': sys.implementation.cache_tag,
    'platform_tag': sysconfig.get_platform(),
    'machine': platform.machine() or None,
    'libc': list(platform.libc_ver()),
    'system': platform.system(),
    'isolated': bool(sys.flags.isolated),
    'ignore_environment': bool(sys.flags.ignore_environment),
    'no_user_site': bool(sys.flags.no_user_site),
    'dont_write_bytecode': bool(sys.dont_write_bytecode),
    'editable': editable,
    'executable': str(pathlib.Path(sys.executable).resolve()),
    'prefix': str(pathlib.Path(sys.prefix).resolve()),
    'base_prefix': str(pathlib.Path(sys.base_prefix).resolve()),
    'sys_path': [str(pathlib.Path(value).resolve()) for value in sys.path if value],
    'modules': modules,
    'distributions': items,
}, sort_keys=True))
"""


def _relative_inside(value: str, root: Path, label: str) -> str:
    path = Path(value).resolve(strict=False)
    if not path.is_relative_to(root):
        raise ValueError(f"{label} escapes the native Linux bundle")
    return path.relative_to(root).as_posix()


def _canonical_relative(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("Linux bundle paths must be non-empty POSIX paths")
    if value != unicodedata.normalize("NFC", value):
        raise ValueError("Linux bundle paths must use NFC normalization")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Linux bundle paths must be canonical and relative")
    if path.as_posix() != value:
        raise ValueError("Linux bundle paths must use one representation")
    return value


class LinuxBundleEntryV1(Contract):
    path: str = Field(min_length=1, max_length=1024)
    kind: Literal["directory", "file"]
    mode: Annotated[int, Field(ge=0, le=0o777)]
    size: Annotated[int, Field(ge=0)] | None = None
    sha256: Digest | None = None

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        return _canonical_relative(value)

    @model_validator(mode="after")
    def kind_fields(self) -> LinuxBundleEntryV1:
        if self.kind == "file":
            if self.size is None or self.sha256 is None:
                raise ValueError("Linux bundle file requires size and SHA-256")
        elif self.size is not None or self.sha256 is not None:
            raise ValueError("Linux bundle directory cannot carry file identity")
        if self.mode & 0o022:
            raise ValueError("Linux bundle entries cannot be group/world writable")
        return self


def inventory_linux_bundle(root: Path) -> tuple[LinuxBundleEntryV1, ...]:
    """Inventory every directory, regular file and exact reviewed Unix mode."""

    root = Path(os.path.abspath(root))
    root_stat = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("Linux bundle root must be a plain directory")
    records: list[LinuxBundleEntryV1] = []

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            result = path.lstat()
            if path.is_symlink():
                raise ValueError("Linux bundle contains a symlink")
            relative = path.relative_to(root).as_posix()
            mode = stat.S_IMODE(result.st_mode)
            if stat.S_ISDIR(result.st_mode):
                records.append(LinuxBundleEntryV1(path=relative, kind="directory", mode=mode))
                visit(path)
            elif stat.S_ISREG(result.st_mode):
                records.append(
                    LinuxBundleEntryV1(
                        path=relative,
                        kind="file",
                        mode=mode,
                        size=result.st_size,
                        sha256=file_sha256(path),
                    )
                )
            else:
                raise ValueError("Linux bundle contains a non-file entry")

    visit(root)
    records.sort(key=lambda item: item.path)
    return tuple(records)


class LinuxModuleOriginV1(Contract):
    module: Literal["devhub", "mcp", "pydantic", "tokenizers"]
    path: str = Field(min_length=1, max_length=1024)

    @field_validator("path")
    @classmethod
    def inside_site_packages(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or path.as_posix() != value
            or ".." in path.parts
            or not value.startswith("python/lib/python3.12/site-packages/")
        ):
            raise ValueError("Linux module origin must be a canonical bundled path")
        return value


class LinuxPythonRuntimePayloadV1(Contract):
    python_executable_sha256: Digest
    implementation: Literal["CPython"] = "CPython"
    version: Literal["3.12.10"] = "3.12.10"
    cache_tag: Literal["cpython-312"] = "cpython-312"
    platform_tag: str = Field(min_length=1, max_length=128)
    platform_machine: str | None = Field(default=None, max_length=128)
    libc_name: str = Field(min_length=1, max_length=64)
    libc_version: str = Field(min_length=1, max_length=64)
    devhub_source_commit: GitCommit
    devhub_wheel_sha256: Digest
    dependency_lock_sha256: Digest
    devhub_distribution_version: str = Field(min_length=1, max_length=128)
    sys_path: tuple[str, ...] = Field(min_length=1)
    module_origins: tuple[LinuxModuleOriginV1, ...] = Field(min_length=4, max_length=4)
    distributions: tuple[DistributionIdentityV1, ...] = Field(min_length=1)
    isolated: Literal[True] = True
    ignore_environment: Literal[True] = True
    no_user_site: Literal[True] = True
    dont_write_bytecode: Literal[True] = True
    editable_install: Literal[False] = False
    entrypoint: Literal["devhub.delegate_server"] = "devhub.delegate_server"
    isolated_argv: tuple[
        Literal["-I"], Literal["-B"], Literal["-m"], Literal["devhub.delegate_server"]
    ] = ("-I", "-B", "-m", "devhub.delegate_server")

    @model_validator(mode="after")
    def canonical_inventory(self) -> LinuxPythonRuntimePayloadV1:
        modules = [item.module for item in self.module_origins]
        if modules != sorted(modules) or len(modules) != len(set(modules)):
            raise ValueError("Linux module origins must be unique and sorted")
        names = [item.name for item in self.distributions]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("Linux runtime distributions must be unique and sorted")
        if "codex-dev-hub" not in names:
            raise ValueError("Linux runtime is missing DevFabric")
        if len(self.sys_path) != len(set(self.sys_path)):
            raise ValueError("Linux runtime sys.path must be unique")
        if any(not value.startswith("python/") for value in self.sys_path):
            raise ValueError("Linux runtime sys.path escapes the bundle")
        return self


class LinuxPythonRuntimeV1(Contract):
    linux_python_runtime_id: Digest
    payload: LinuxPythonRuntimePayloadV1

    @classmethod
    def create(cls, payload: LinuxPythonRuntimePayloadV1) -> LinuxPythonRuntimeV1:
        return cls(
            linux_python_runtime_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxPythonRuntimeV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_python_runtime_id != expected:
            raise ValueError("Linux Python runtime ID mismatch")
        return self


class LinuxPythonAuthorityV1(Contract):
    executable_path: Literal["python/bin/python3.12"] = "python/bin/python3.12"
    executable_sha256: Digest
    devhub_wheel_path: str = Field(min_length=1, max_length=1024)
    devhub_wheel_sha256: Digest
    devhub_source_archive_sha256: Digest
    dependency_lock_path: Literal["authority/uv.lock"] = "authority/uv.lock"
    dependency_lock_sha256: Digest
    dependency_wheels: tuple[NativeDependencyWheelV1, ...] = Field(min_length=1)
    runtime: LinuxPythonRuntimeV1

    @model_validator(mode="after")
    def matching_runtime(self) -> LinuxPythonAuthorityV1:
        payload = self.runtime.payload
        if (
            payload.python_executable_sha256 != self.executable_sha256
            or payload.devhub_wheel_sha256 != self.devhub_wheel_sha256
            or payload.dependency_lock_sha256 != self.dependency_lock_sha256
        ):
            raise ValueError("Linux Python authority differs from runtime observation")
        names = [item.name for item in self.dependency_wheels]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("Linux dependency wheel identities must be unique and sorted")
        observed = {
            (item.name, item.version)
            for item in payload.distributions
            if item.name != "codex-dev-hub"
        }
        reviewed = {(item.name, item.version) for item in self.dependency_wheels}
        if observed != reviewed:
            raise ValueError("Linux dependency wheels differ from installed distributions")
        return self


class LinuxCodexAuthorityV1(Contract):
    accepted_run_id: Annotated[int, Field(ge=1)]
    accepted_run_attempt: Annotated[int, Field(ge=1)]
    devfabric_implementation_commit: GitCommit
    build_id: Literal["linux-build-007"] = "linux-build-007"
    build_receipt_path: Literal["authority/linux-native-codex-build.json"] = (
        "authority/linux-native-codex-build.json"
    )
    build_receipt_sha256: Digest
    inventory_path: Literal["authority/native-build-artifact-inventory.json"] = (
        "authority/native-build-artifact-inventory.json"
    )
    inventory_sha256: Digest
    linux_native_codex_build_id: Digest
    target: Literal["x86_64-unknown-linux-gnu"] = "x86_64-unknown-linux-gnu"
    executable_path: Literal["codex/codex"] = "codex/codex"
    executable_sha256: Digest
    code_mode_host_path: Literal["codex/codex-code-mode-host"] = "codex/codex-code-mode-host"
    code_mode_host_sha256: Digest
    process_proof_sha256: Digest
    code_mode_host_eof_receipt_sha256: Digest


class LinuxCodexAuthorityV2(LinuxCodexAuthorityV1):
    """Forward authority for the exact-current-commit Linux build pair."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    build_id: Literal["linux-build-008"] = "linux-build-008"  # type: ignore[assignment]


class LinuxCodexAuthorityV3(LinuxCodexAuthorityV1):
    """Forward authority for the size-corrected exact-current-commit build pair."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    build_id: Literal["linux-build-009"] = "linux-build-009"  # type: ignore[assignment]


class LinuxLauncherV1(Contract):
    cli_path: Literal["bin/devfabric"] = "bin/devfabric"
    cli_sha256: Digest
    delegate_path: Literal["bin/devhub-delegate-server"] = "bin/devhub-delegate-server"
    delegate_sha256: Digest
    python_path: Literal["python/bin/python3.12"] = "python/bin/python3.12"
    delegate_argv_prefix: tuple[
        Literal["-I"], Literal["-B"], Literal["-m"], Literal["devhub.delegate_server"]
    ] = ("-I", "-B", "-m", "devhub.delegate_server")
    config_flag: Literal["--config"] = "--config"
    codex_path: Literal["codex/codex"] = "codex/codex"
    code_mode_host_path: Literal["codex/codex-code-mode-host"] = "codex/codex-code-mode-host"
    config_locator_external: Literal[True] = True
    mutable_state_external: Literal[True] = True


class LinuxNativeBundlePayloadV1(Contract):
    kind: Literal["devfabric_linux_native_directory"] = "devfabric_linux_native_directory"
    platform: Literal["linux"] = "linux"
    architecture: Literal["x86_64"] = "x86_64"
    root_mode: Literal[0o755] = 0o755
    implementation_commit: GitCommit
    python: LinuxPythonAuthorityV1
    codex: LinuxCodexAuthorityV1
    launcher: LinuxLauncherV1
    files: tuple[LinuxBundleEntryV1, ...] = Field(min_length=1)
    trusted_prelaunch_verifier_required: Literal[True] = True
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False

    @model_validator(mode="after")
    def exact_closed_layout(self) -> LinuxNativeBundlePayloadV1:
        if (
            self.python.runtime.payload.devhub_source_commit != self.implementation_commit
            or self.codex.devfabric_implementation_commit != self.implementation_commit
        ):
            raise ValueError("Linux bundle components differ from implementation commit")
        paths = [item.path for item in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("Linux bundle inventory must be unique and sorted")
        by_path = {item.path: item for item in self.files}
        required = {
            self.python.executable_path: self.python.executable_sha256,
            self.python.devhub_wheel_path: self.python.devhub_wheel_sha256,
            self.python.dependency_lock_path: self.python.dependency_lock_sha256,
            self.codex.build_receipt_path: self.codex.build_receipt_sha256,
            self.codex.inventory_path: self.codex.inventory_sha256,
            self.codex.executable_path: self.codex.executable_sha256,
            self.codex.code_mode_host_path: self.codex.code_mode_host_sha256,
            self.launcher.cli_path: self.launcher.cli_sha256,
            self.launcher.delegate_path: self.launcher.delegate_sha256,
            **{
                f"authority/wheels/{wheel.filename}": wheel.sha256
                for wheel in self.python.dependency_wheels
            },
        }
        for path, expected in required.items():
            item = by_path.get(path)
            if item is None or item.kind != "file" or item.sha256 != expected:
                raise ValueError(f"Linux bundle authority file is absent or mismatched: {path}")
        top_level = {PurePosixPath(path).parts[0] for path in paths}
        forbidden = {"config", "data", "ledger", "logs", "projects", "secrets", "evidence"}
        if top_level & forbidden:
            raise ValueError("Mutable state must remain outside the Linux bundle")
        if top_level != {"authority", "bin", "codex", "python"}:
            raise ValueError("Linux bundle contains an unreviewed top-level path")
        authority_files = {
            path
            for path, item in by_path.items()
            if item.kind == "file" and PurePosixPath(path).parts[0] == "authority"
        }
        expected_authority = {
            self.python.devhub_wheel_path,
            self.python.dependency_lock_path,
            self.codex.build_receipt_path,
            self.codex.inventory_path,
            *(f"authority/wheels/{wheel.filename}" for wheel in self.python.dependency_wheels),
        }
        if authority_files != expected_authority:
            raise ValueError("Linux bundle authority directory is not closed")
        authority_directories = {
            path
            for path, item in by_path.items()
            if item.kind == "directory" and PurePosixPath(path).parts[0] == "authority"
        }
        if authority_directories != {"authority", "authority/wheels"}:
            raise ValueError("Linux bundle authority directory tree is not closed")
        bin_files = {
            path
            for path, item in by_path.items()
            if item.kind == "file" and PurePosixPath(path).parts[0] == "bin"
        }
        if bin_files != {self.launcher.cli_path, self.launcher.delegate_path}:
            raise ValueError("Linux bundle launcher directory is not closed")
        if by_path.get("bin") is None or by_path["bin"].kind != "directory":
            raise ValueError("Linux bundle launcher directory is absent")
        if any(
            item.kind == "directory" and path.startswith("bin/") for path, item in by_path.items()
        ):
            raise ValueError("Linux bundle launcher directory tree is not closed")
        codex_files = {
            path
            for path, item in by_path.items()
            if item.kind == "file" and PurePosixPath(path).parts[0] == "codex"
        }
        if codex_files != {self.codex.executable_path, self.codex.code_mode_host_path}:
            raise ValueError("Linux bundle Codex directory is not closed")
        if by_path.get("codex") is None or by_path["codex"].kind != "directory":
            raise ValueError("Linux bundle Codex directory is absent")
        if any(
            item.kind == "directory" and path.startswith("codex/") for path, item in by_path.items()
        ):
            raise ValueError("Linux bundle Codex directory tree is not closed")
        for path in (
            self.python.executable_path,
            self.codex.executable_path,
            self.codex.code_mode_host_path,
            self.launcher.cli_path,
            self.launcher.delegate_path,
        ):
            if by_path[path].mode != 0o755:
                raise ValueError(f"Linux executable mode differs: {path}")
        return self


class LinuxNativeBundlePayloadV2(LinuxNativeBundlePayloadV1):
    """Forward bundle payload consuming only linux-build-008 authority."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    codex: LinuxCodexAuthorityV2


class LinuxNativeBundlePayloadV3(LinuxNativeBundlePayloadV1):
    """Forward bundle payload consuming only linux-build-009 authority."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    codex: LinuxCodexAuthorityV3


class LinuxNativeBundleV1(Contract):
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV1

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV1) -> LinuxNativeBundleV1:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native bundle ID mismatch")
        return self


class LinuxNativeBundleV2(Contract):
    schema_version: Literal[2] = 2  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV2

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV2) -> LinuxNativeBundleV2:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV2:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native bundle ID mismatch")
        return self


class LinuxNativeBundleV3(Contract):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV3

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV3) -> LinuxNativeBundleV3:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV3:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native bundle ID mismatch")
        return self


class LinuxNativeArchivePayloadV1(Contract):
    kind: Literal["devfabric_linux_native_archive"] = "devfabric_linux_native_archive"
    format: Literal["tar_gzip"] = "tar_gzip"
    filename: Literal["devfabric-linux-native.tar.gz"] = "devfabric-linux-native.tar.gz"
    bundle_id: Digest
    size: Annotated[int, Field(ge=1)]
    sha256: Digest


class LinuxNativeArchiveV1(Contract):
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV1

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV1) -> LinuxNativeArchiveV1:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native archive ID mismatch")
        return self


class LinuxNativeArchivePayloadV2(LinuxNativeArchivePayloadV1):
    schema_version: Literal[2] = 2  # type: ignore[assignment]


class LinuxNativeArchiveV2(Contract):
    schema_version: Literal[2] = 2  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV2

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV2) -> LinuxNativeArchiveV2:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV2:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native archive ID mismatch")
        return self


class LinuxNativeArchivePayloadV3(LinuxNativeArchivePayloadV1):
    schema_version: Literal[3] = 3  # type: ignore[assignment]


class LinuxNativeArchiveV3(Contract):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV3

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV3) -> LinuxNativeArchiveV3:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV3:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native archive ID mismatch")
        return self


def observe_linux_runtime(
    interpreter: Path, devhub_wheel: Path, lock_path: Path, source_commit: str
) -> LinuxPythonRuntimeV1:
    """Observe the relocated runtime under hostile ambient Python configuration."""

    interpreter = interpreter.resolve(strict=True)
    bundle_root = interpreter.parent.parent.parent.resolve(strict=True)
    environment = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(bundle_root.parent / "untrusted-pythonpath"),
        "PYTHONHOME": str(bundle_root.parent / "untrusted-pythonhome"),
        "PYTHONUSERBASE": str(bundle_root.parent / "untrusted-user-site"),
    }
    raw = subprocess.check_output(
        [str(interpreter), "-I", "-B", "-c", _INSPECT],
        cwd=bundle_root.parent,
        env=environment,
        timeout=120,
    )
    observed = json.loads(raw)
    if (
        observed.get("implementation") != "CPython"
        or observed.get("version") != "3.12.10"
        or observed.get("cache_tag") != "cpython-312"
        or observed.get("system") != "Linux"
        or observed.get("isolated") is not True
        or observed.get("ignore_environment") is not True
        or observed.get("no_user_site") is not True
        or observed.get("dont_write_bytecode") is not True
        or observed.get("editable") is not False
    ):
        raise ValueError("Bundled Linux Python identity or isolation differs")
    python_root = bundle_root / "python"
    if (
        Path(observed.get("executable", "")).resolve(strict=True) != interpreter
        or Path(observed.get("prefix", "")).resolve(strict=True) != python_root
        or Path(observed.get("base_prefix", "")).resolve(strict=True) != python_root
    ):
        raise ValueError("Bundled Linux Python prefix did not relocate")
    libc = observed.get("libc")
    if (
        not isinstance(libc, list)
        or len(libc) != 2
        or not all(isinstance(item, str) and item for item in libc)
    ):
        raise ValueError("Bundled Linux libc identity is incomplete")
    sys_path = tuple(
        _relative_inside(value, bundle_root, "Python sys.path") for value in observed["sys_path"]
    )
    modules = tuple(
        sorted(
            (LinuxModuleOriginV1.model_validate(item) for item in observed["modules"]),
            key=lambda item: item.module,
        )
    )
    distributions = tuple(
        sorted(
            (
                DistributionIdentityV1(
                    name=normalize_distribution_name(item["name"]),
                    version=item["version"],
                    record_sha256=item["record_sha256"],
                    file_count=item["file_count"],
                )
                for item in observed["distributions"]
            ),
            key=lambda item: item.name,
        )
    )
    payload = LinuxPythonRuntimePayloadV1(
        python_executable_sha256=file_sha256(interpreter),
        platform_tag=observed["platform_tag"],
        platform_machine=observed.get("machine"),
        libc_name=libc[0],
        libc_version=libc[1],
        devhub_source_commit=source_commit,
        devhub_wheel_sha256=file_sha256(devhub_wheel),
        dependency_lock_sha256=file_sha256(lock_path),
        devhub_distribution_version=next(
            item.version for item in distributions if item.name == "codex-dev-hub"
        ),
        sys_path=sys_path,
        module_origins=modules,
        distributions=distributions,
    )
    return LinuxPythonRuntimeV1.create(payload)


LinuxNativeBundle = LinuxNativeBundleV1 | LinuxNativeBundleV2 | LinuxNativeBundleV3
LinuxNativeArchive = LinuxNativeArchiveV1 | LinuxNativeArchiveV2 | LinuxNativeArchiveV3


def verify_linux_native_bundle(bundle: LinuxNativeBundle, root: Path) -> None:
    """Verify exact bytes, build authority and relocated Python observation."""

    root = Path(os.path.abspath(root))
    root_result = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_result.st_mode):
        raise ValueError("Linux native bundle root must be a plain directory")
    if stat.S_IMODE(root_result.st_mode) != bundle.payload.root_mode:
        raise ValueError("Linux native bundle root mode differs from manifest")
    if inventory_linux_bundle(root) != bundle.payload.files:
        raise ValueError("Linux native bundle files differ from manifest")
    receipt_path = root / "authority/linux-native-codex-build.json"
    inventory_path = root / "authority/native-build-artifact-inventory.json"
    receipt: LinuxNativeCodexBuildV7 | LinuxNativeCodexBuildV8 | LinuxNativeCodexBuildV9
    if isinstance(bundle, LinuxNativeBundleV3):
        receipt = LinuxNativeCodexBuildV9.model_validate_json(receipt_path.read_bytes())
    elif isinstance(bundle, LinuxNativeBundleV2):
        receipt = LinuxNativeCodexBuildV8.model_validate_json(receipt_path.read_bytes())
    else:
        receipt = LinuxNativeCodexBuildV7.model_validate_json(receipt_path.read_bytes())
    inventory = NativeBuildArtifactInventoryV2.model_validate_json(inventory_path.read_bytes())
    payload = receipt.payload
    binaries = {item.role: item for item in payload.binaries}
    codex = bundle.payload.codex
    if (
        file_sha256(receipt_path) != codex.build_receipt_sha256
        or file_sha256(inventory_path) != codex.inventory_sha256
        or inventory.payload.platform != "linux"
        or inventory.payload.build_id != codex.build_id
        or inventory.payload.status != "PASS"
        or inventory.payload.linux_pair is None
        or inventory.payload.linux_pair.build_receipt_sha256 != codex.build_receipt_sha256
        or inventory.payload.linux_pair.linux_native_codex_build_id
        != codex.linux_native_codex_build_id
        or receipt.linux_native_codex_build_id != codex.linux_native_codex_build_id
        or payload.provenance.workflow_run_id != codex.accepted_run_id
        or payload.provenance.workflow_run_attempt != codex.accepted_run_attempt
        or payload.provenance.implementation_commit != codex.devfabric_implementation_commit
        or payload.provenance.build_id != codex.build_id
        or payload.process_proof.process_proof_sha256 != codex.process_proof_sha256
        or payload.process_proof.code_mode_host_eof_receipt_sha256
        != codex.code_mode_host_eof_receipt_sha256
        or binaries["codex"].sha256 != codex.executable_sha256
        or binaries["codex-code-mode-host"].sha256 != codex.code_mode_host_sha256
        or file_sha256(root / codex.executable_path) != codex.executable_sha256
        or file_sha256(root / codex.code_mode_host_path) != codex.code_mode_host_sha256
    ):
        raise ValueError("Linux Codex artifact differs from bundle authority")
    runtime = observe_linux_runtime(
        root / bundle.payload.python.executable_path,
        root / bundle.payload.python.devhub_wheel_path,
        root / bundle.payload.python.dependency_lock_path,
        bundle.payload.implementation_commit,
    )
    if runtime != bundle.payload.python.runtime:
        raise ValueError("Linux Python runtime differs from sealed observation")


def extract_and_verify_linux_archive(
    archive: Path,
    destination: Path,
    bundle: LinuxNativeBundle,
) -> Path:
    """Extract a closed regular-file archive and re-run strict bundle verification."""

    archive = Path(os.path.abspath(archive))
    archive_result = archive.lstat()
    if archive.is_symlink() or not stat.S_ISREG(archive_result.st_mode):
        raise ValueError("Linux native archive must be a plain regular file")
    if destination.exists():
        raise ValueError("Linux archive extraction root must be new")
    destination.mkdir(parents=True)
    with tarfile.open(archive, mode="r:gz") as stream:
        members = stream.getmembers()
        if not members:
            raise ValueError("Linux native archive is empty")
        names: set[str] = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or not path.parts
                or path.parts[0] != "bundle"
                or ".." in path.parts
                or path.as_posix() != member.name.rstrip("/")
                or path.as_posix() in names
                or not (member.isfile() or member.isdir())
            ):
                raise ValueError("Linux native archive contains an unsafe member")
            names.add(path.as_posix())
        stream.extractall(destination, filter="data")
    root = destination / "bundle"
    verify_linux_native_bundle(bundle, root)
    return root


def smoke_linux_bundle_cli(root: Path) -> None:
    """Run one metadata-only command through the packaged relative launcher."""

    environment = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(root.parent / "untrusted-pythonpath"),
        "PYTHONHOME": str(root.parent / "untrusted-pythonhome"),
        "PYTHONUSERBASE": str(root.parent / "untrusted-user-site"),
    }
    completed = subprocess.run(
        [str(root / "bin/devfabric"), "schema"],
        cwd=root.parent,
        env=environment,
        check=True,
        capture_output=True,
        timeout=60,
    )
    observed = json.loads(completed.stdout)
    if set(observed) != {
        "HubConfig",
        "ModelResult",
        "StatusRequest",
        "StatusResponse",
        "TaskRequest",
    }:
        raise ValueError("Linux native CLI schema smoke differs from reviewed command")
    if completed.stderr:
        raise ValueError("Linux native CLI schema smoke produced stderr")


def verify_linux_native_release(release: Path, destination: Path) -> LinuxNativeArchive:
    """Join the three published files, extract afresh, verify and smoke the runtime."""

    release = Path(os.path.abspath(release))
    result = release.lstat()
    if release.is_symlink() or not stat.S_ISDIR(result.st_mode):
        raise ValueError("Linux native release root must be a plain directory")
    expected = {
        "devfabric-linux-native.tar.gz",
        "linux-native-archive.json",
        "linux-native-bundle.json",
    }
    observed: set[str] = set()
    for path in release.rglob("*"):
        entry = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(entry.st_mode):
            raise ValueError("Linux native release contains a non-plain file")
        observed.add(path.relative_to(release).as_posix())
    if observed != expected:
        raise ValueError("Linux native release layout differs from reviewed authority")
    manifest_path = release / "linux-native-bundle.json"
    archive_receipt_path = release / "linux-native-archive.json"
    archive_path = release / "devfabric-linux-native.tar.gz"
    if manifest_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Linux native bundle manifest exceeds its size bound")
    if archive_receipt_path.stat().st_size > 256 * 1024:
        raise ValueError("Linux native archive receipt exceeds its size bound")
    if archive_path.stat().st_size > 2 * 1024 * 1024 * 1024:
        raise ValueError("Linux native archive exceeds its size bound")
    manifest_raw = manifest_path.read_bytes()
    archive_raw = archive_receipt_path.read_bytes()
    manifest_version = json.loads(manifest_raw).get("schema_version")
    archive_version = json.loads(archive_raw).get("schema_version")
    bundle: LinuxNativeBundle
    archive: LinuxNativeArchive
    if manifest_version == 1 and archive_version == 1:
        bundle = LinuxNativeBundleV1.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV1.model_validate_json(archive_raw)
    elif manifest_version == 2 and archive_version == 2:
        bundle = LinuxNativeBundleV2.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV2.model_validate_json(archive_raw)
    elif manifest_version == 3 and archive_version == 3:
        bundle = LinuxNativeBundleV3.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV3.model_validate_json(archive_raw)
    else:
        raise ValueError("Linux native release schema versions differ or are unsupported")
    if (
        archive.payload.bundle_id != bundle.linux_native_bundle_id
        or archive.payload.filename != archive_path.name
        or archive.payload.size != archive_path.stat().st_size
        or archive.payload.sha256 != file_sha256(archive_path)
    ):
        raise ValueError("Linux native release files do not share one authority")
    extracted = extract_and_verify_linux_archive(archive_path, destination, bundle)
    smoke_linux_bundle_cli(extracted)
    return archive


def runtime_tree_sha256(root: Path) -> str:
    """Return a compact identity for tests and external evidence projection."""

    records = inventory_linux_bundle(root)
    payload = [item.model_dump(mode="json") for item in records]
    return hashlib.sha256(canonical(cast(JsonValue, payload))).hexdigest()
