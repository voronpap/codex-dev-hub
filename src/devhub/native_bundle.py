"""Strict authority contract for relocatable native DevFabric directories.

The manifest is deliberately external to the immutable bundle directory.  A
future trusted launcher must verify it before starting any bundled executable;
the bundled Python interpreter is not allowed to attest to itself.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import platform
import stat
import subprocess
import sys
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.models import Contract
from devhub.qualification import GitCommit
from devhub.runtime_artifact import DistributionIdentityV1, normalize_distribution_name

NativePlatform = Literal["windows", "linux"]
NativeArchitecture = Literal["x86_64"]

_NATIVE_INSPECT_SCRIPT = r"""
import base64, hashlib, importlib, importlib.metadata as md, json, pathlib, platform, sys, sysconfig

def h(path):
    value = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()

root = pathlib.Path(sys.executable).resolve().parent.parent
site_packages = root / 'python' / 'site-packages'
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
            actual = base64.urlsafe_b64encode(bytes.fromhex(h(located))).decode().rstrip('=')
            if actual != declared.value:
                raise SystemExit('installed RECORD integrity failure')
            declared_value = declared.value
        entries.append([text, declared_value, item.size])
    entries.sort()
    encoded = (json.dumps(entries, sort_keys=True, separators=(',', ':')) + '\n').encode()
    record = hashlib.sha256(encoded).hexdigest()
    items.append({
        'name': name,
        'version': version,
        'record_sha256': record,
        'file_count': len(entries),
    })

modules = []
for name in ('devhub', 'mcp', 'pydantic', 'pywintypes', 'tokenizers'):
    module = importlib.import_module(name)
    origin = pathlib.Path(module.__file__).resolve()
    if not origin.is_relative_to(root):
        raise SystemExit('module origin escapes native bundle')
    modules.append({'module': name, 'path': origin.relative_to(root).as_posix()})

print(json.dumps({
    'implementation': platform.python_implementation(),
    'version': platform.python_version(),
    'cache_tag': sys.implementation.cache_tag,
    'platform_tag': sysconfig.get_platform(),
    'system': platform.system(),
    'machine': platform.machine() or None,
    'executable': str(pathlib.Path(sys.executable).resolve()),
    'prefix': str(pathlib.Path(sys.prefix).resolve()),
    'base_prefix': str(pathlib.Path(sys.base_prefix).resolve()),
    'isolated': sys.flags.isolated == 1,
    'ignore_environment': sys.flags.ignore_environment == 1,
    'no_user_site': sys.flags.no_user_site == 1,
    'dont_write_bytecode': sys.dont_write_bytecode,
    'editable': editable,
    'sys_path': [str(pathlib.Path(item).resolve()) for item in sys.path],
    'modules': modules,
    'distributions': items,
}, sort_keys=True))
"""


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def embedded_archive_members_sha256(raw: bytes) -> str:
    records: list[dict[str, JsonValue]] = []
    names: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(raw)) as stream:
        for item in sorted(stream.infolist(), key=lambda value: value.filename):
            member = PurePosixPath(item.filename)
            if item.filename in names:
                raise ValueError("Embedded Python archive contains a duplicate member path")
            names.add(item.filename)
            if member.is_absolute() or ".." in member.parts or "\\" in item.filename:
                raise ValueError("Embedded Python archive contains an unsafe member path")
            mode = item.external_attr >> 16
            if mode and (mode & 0o170000) == 0o120000:
                raise ValueError("Embedded Python archive contains a symlink")
            if item.is_dir():
                continue
            member_raw = stream.read(item)
            records.append(
                {
                    "path": item.filename,
                    "size": len(member_raw),
                    "sha256": hashlib.sha256(member_raw).hexdigest(),
                }
            )
    return digest(canonical(cast(JsonValue, records)))


@dataclass(frozen=True)
class InstalledWheelPlan:
    owned: dict[str, tuple[str, int, str]]
    record_owners: dict[str, str]
    removable: frozenset[str]
    generated: frozenset[str]


def _wheel_install_path(member: str) -> tuple[str, bool]:
    path = PurePosixPath(member)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in member
        or path.as_posix() != member
    ):
        raise ValueError("Dependency wheel contains an unsafe member path")
    data_index = next(
        (index for index, part in enumerate(path.parts) if part.endswith(".data")), None
    )
    if data_index is None:
        return path.as_posix(), False
    parts = path.parts
    if data_index != 0 or len(parts) < 3:
        raise ValueError("Dependency wheel contains an unsupported data-scheme path")
    scheme = parts[1]
    tail = PurePosixPath(*parts[2:]).as_posix()
    if scheme in {"purelib", "platlib"}:
        return tail, False
    if scheme == "scripts":
        return f"bin/{tail}", True
    raise ValueError(f"Dependency wheel uses unsupported install scheme: {scheme}")


def installed_wheel_plan(wheels: tuple[Path, ...]) -> InstalledWheelPlan:
    """Derive the exact installed-file ownership from immutable wheel bytes."""

    owned: dict[str, tuple[str, int, str]] = {}
    record_owners: dict[str, str] = {}
    removable: set[str] = set()
    generated: set[str] = set()
    casefolded: set[str] = set()
    for wheel in wheels:
        owner = wheel.name
        records: list[str] = []
        with zipfile.ZipFile(wheel) as stream:
            names: set[str] = set()
            for item in stream.infolist():
                if item.is_dir():
                    continue
                if item.filename in names:
                    raise ValueError("Dependency wheel contains a duplicate member path")
                names.add(item.filename)
                mode = item.external_attr >> 16
                if mode and (mode & 0o170000) == 0o120000:
                    raise ValueError("Dependency wheel contains a symlink")
                installed, script = _wheel_install_path(item.filename)
                folded = installed.casefold()
                if folded in casefolded:
                    raise ValueError("Dependency wheels contain case-colliding installed paths")
                casefolded.add(folded)
                if installed.endswith(".dist-info/RECORD"):
                    records.append(installed)
                    continue
                raw = stream.read(item)
                if installed in owned:
                    raise ValueError(
                        f"Dependency wheels claim the same installed file: {installed}"
                    )
                owned[installed] = (hashlib.sha256(raw).hexdigest(), len(raw), owner)
                if script or installed.endswith(".pth"):
                    removable.add(installed)
        if len(records) != 1:
            raise ValueError("Dependency wheel must contain exactly one RECORD")
        record = records[0]
        if record in record_owners:
            raise ValueError("Dependency wheels claim the same RECORD")
        record_owners[record] = owner
        parent = PurePosixPath(record).parent
        generated.update(
            f"{parent.as_posix()}/{name}" for name in ("INSTALLER", "REQUESTED", "direct_url.json")
        )
    return InstalledWheelPlan(
        owned=owned,
        record_owners=record_owners,
        removable=frozenset(removable),
        generated=frozenset(generated),
    )


def _record_bytes(plan: InstalledWheelPlan, record: str, owner: str) -> bytes:
    rows: list[list[str]] = []
    for relative, (sha256, size, file_owner) in sorted(plan.owned.items()):
        if file_owner != owner or relative in plan.removable:
            continue
        encoded = base64.urlsafe_b64encode(bytes.fromhex(sha256)).decode().rstrip("=")
        rows.append([relative, f"sha256={encoded}", str(size)])
    rows.append([record, "", ""])
    buffer = io.StringIO(newline="")
    csv.writer(buffer, lineterminator="\n").writerows(rows)
    return buffer.getvalue().encode()


def verify_installed_wheel_tree(site_packages: Path, wheels: tuple[Path, ...]) -> None:
    """Verify final installed files directly against retained reviewed wheels."""

    plan = installed_wheel_plan(wheels)
    observed: dict[str, Path] = {}
    casefolded: set[str] = set()
    for path in site_packages.rglob("*"):
        result = _assert_plain(path)
        if stat.S_ISDIR(result.st_mode):
            continue
        if not stat.S_ISREG(result.st_mode):
            raise ValueError("Installed runtime contains a non-file entry")
        relative = path.relative_to(site_packages).as_posix()
        folded = relative.casefold()
        if folded in casefolded:
            raise ValueError("Installed runtime contains case-colliding paths")
        casefolded.add(folded)
        observed[relative] = path
    expected = (set(plan.owned) - set(plan.removable)) | set(plan.record_owners)
    if set(observed) != expected:
        difference = sorted(set(observed) ^ expected)
        raise ValueError(f"Installed runtime differs from exact wheel ownership: {difference[0]}")
    for relative, (expected_hash, expected_size, _) in plan.owned.items():
        if relative in plan.removable:
            continue
        path = observed[relative]
        if path.stat().st_size != expected_size or file_sha256(path) != expected_hash:
            raise ValueError(f"Installed runtime differs from its exact wheel: {relative}")
    for record, owner in plan.record_owners.items():
        if observed[record].read_bytes() != _record_bytes(plan, record, owner):
            raise ValueError(f"Installed RECORD differs from exact wheel ownership: {record}")


def sanitize_installed_wheel_tree(site_packages: Path, wheels: tuple[Path, ...]) -> None:
    """Remove only reviewed install-time additions and seal exact RECORD files."""

    plan = installed_wheel_plan(wheels)
    observed: dict[str, Path] = {}
    casefolded: set[str] = set()
    for path in site_packages.rglob("*"):
        if path.is_symlink() or _is_reparse(path.lstat()):
            raise ValueError("Installed runtime contains a symlink/reparse entry")
        if path.is_file():
            relative = path.relative_to(site_packages).as_posix()
            folded = relative.casefold()
            if folded in casefolded:
                raise ValueError("Installed runtime contains case-colliding paths")
            casefolded.add(folded)
            observed[relative] = path
    allowed = set(plan.owned) | set(plan.record_owners) | set(plan.generated)
    extras = set(observed) - allowed
    if extras and not all(path.startswith("bin/") for path in extras):
        raise ValueError(f"Installed runtime contains an unowned file: {sorted(extras)[0]}")
    missing = set(plan.owned) - set(observed)
    if missing:
        raise ValueError(f"Installed runtime is missing a wheel-owned file: {sorted(missing)[0]}")
    for relative, (expected_hash, expected_size, _) in plan.owned.items():
        path = observed[relative]
        if path.stat().st_size != expected_size or file_sha256(path) != expected_hash:
            raise ValueError(f"Installed runtime differs from its exact wheel: {relative}")
    for relative in sorted(set(plan.generated) | set(plan.removable) | extras):
        path = site_packages.joinpath(*PurePosixPath(relative).parts)
        if path.is_file():
            path.unlink()
    bin_dir = site_packages / "bin"
    if bin_dir.exists():
        for path in sorted(bin_dir.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
        bin_dir.rmdir()
    for record, owner in sorted(plan.record_owners.items()):
        target = site_packages.joinpath(*PurePosixPath(record).parts)
        target.write_bytes(_record_bytes(plan, record, owner))
    verify_installed_wheel_tree(site_packages, wheels)


def _normalized_relative_path(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("Bundle paths must be non-empty POSIX relative paths")
    if value != unicodedata.normalize("NFC", value):
        raise ValueError("Bundle paths must use NFC Unicode normalization")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("Bundle paths must not escape or contain ambiguous components")
    normalized = path.as_posix()
    if normalized != value:
        raise ValueError("Bundle paths must use one canonical representation")
    return value


class NativeBundleFileV1(Contract):
    path: str = Field(min_length=1, max_length=1024)
    size: Annotated[int, Field(ge=0)]
    sha256: Digest

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        return _normalized_relative_path(value)


class NativeDependencyWheelV1(Contract):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    version: str = Field(min_length=1, max_length=128)
    filename: str = Field(min_length=1, max_length=255, pattern=r"^[^/\\]+\.whl$")
    sha256: Digest


class NativeModuleOriginV1(Contract):
    module: Literal["devhub", "mcp", "pydantic", "pywintypes", "tokenizers"]
    path: str = Field(min_length=1, max_length=1024)

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        value = _normalized_relative_path(value)
        if not value.startswith("python/site-packages/"):
            raise ValueError("Native module origin must be inside bundled site-packages")
        return value


class NativePythonRuntimePayloadV1(Contract):
    python_implementation: Literal["CPython"] = "CPython"
    python_version: Literal["3.12.10"] = "3.12.10"
    python_executable_sha256: Digest
    python_cache_tag: Literal["cpython-312"] = "cpython-312"
    python_platform_tag: Literal["win-amd64"] = "win-amd64"
    platform_system: Literal["Windows"] = "Windows"
    platform_machine: str | None
    devhub_source_commit: GitCommit
    devhub_wheel_sha256: Digest
    dependency_lock_sha256: Digest
    devhub_distribution_version: str = Field(min_length=1, max_length=64)
    sys_path: tuple[str, ...] = Field(min_length=7, max_length=7)
    module_origins: tuple[NativeModuleOriginV1, ...] = Field(min_length=5, max_length=5)
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
    def sorted_authority(self) -> NativePythonRuntimePayloadV1:
        expected_paths = (
            "python/python312.zip",
            "python",
            "python/site-packages",
            "python/site-packages/win32",
            "python/site-packages/win32/lib",
            "python/site-packages/pythonwin",
            "python/site-packages/pywin32_system32",
        )
        if self.sys_path != expected_paths:
            raise ValueError("Embedded Windows Python sys.path differs from the reviewed layout")
        modules = [item.module for item in self.module_origins]
        if modules != sorted(modules) or len(modules) != len(set(modules)):
            raise ValueError("Native module origins must be unique and sorted")
        names = [item.name for item in self.distributions]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("Native distribution inventory must be unique and sorted")
        if "codex-dev-hub" not in names:
            raise ValueError("Native runtime is missing the DevFabric distribution")
        return self


class NativePythonRuntimeV1(Contract):
    native_python_runtime_id: Digest
    payload: NativePythonRuntimePayloadV1

    @classmethod
    def create(cls, payload: NativePythonRuntimePayloadV1) -> NativePythonRuntimeV1:
        identifier = digest(canonical(cast(JsonValue, payload.model_dump(mode="json"))))
        return cls(native_python_runtime_id=identifier, payload=payload)

    @model_validator(mode="after")
    def canonical_id(self) -> NativePythonRuntimeV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.native_python_runtime_id != expected:
            raise ValueError("Native Python runtime ID mismatch")
        return self


class EmbeddedPythonAuthorityV1(Contract):
    archive_filename: Literal["python-3.12.10-embed-amd64.zip"] = "python-3.12.10-embed-amd64.zip"
    archive_sha256: Digest
    archive_members_sha256: Digest
    archive_path: Literal["authority/python-3.12.10-embed-amd64.zip"] = (
        "authority/python-3.12.10-embed-amd64.zip"
    )
    sbom_filename: Literal["python-3.12.10-embed-amd64.zip.spdx.json"] = (
        "python-3.12.10-embed-amd64.zip.spdx.json"
    )
    sbom_sha256: Digest
    sbom_path: Literal["authority/python-3.12.10-embed-amd64.zip.spdx.json"] = (
        "authority/python-3.12.10-embed-amd64.zip.spdx.json"
    )
    license_expression: Literal["PSF-2.0"] = "PSF-2.0"
    executable_path: Literal["python/python.exe"] = "python/python.exe"
    executable_sha256: Digest
    pth_path: Literal["python/python312._pth"] = "python/python312._pth"
    pth_sha256: Digest
    devhub_wheel_path: str = Field(min_length=1, max_length=1024)
    devhub_source_archive_sha256: Digest
    devhub_wheel_sha256: Digest
    dependency_lock_path: Literal["authority/uv.lock"] = "authority/uv.lock"
    dependency_lock_sha256: Digest
    dependency_wheels: tuple[NativeDependencyWheelV1, ...] = Field(min_length=1)
    runtime: NativePythonRuntimeV1

    @field_validator("devhub_wheel_path")
    @classmethod
    def canonical_wheel_path(cls, value: str) -> str:
        return _normalized_relative_path(value)

    @model_validator(mode="after")
    def sorted_wheels(self) -> EmbeddedPythonAuthorityV1:
        names = [item.name for item in self.dependency_wheels]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("Dependency wheel identities must be unique and sorted")
        payload = self.runtime.payload
        if (
            payload.python_executable_sha256 != self.executable_sha256
            or payload.devhub_wheel_sha256 != self.devhub_wheel_sha256
            or payload.dependency_lock_sha256 != self.dependency_lock_sha256
        ):
            raise ValueError("Embedded Python authority differs from runtime observation")
        observed = {
            (item.name, item.version)
            for item in payload.distributions
            if item.name != "codex-dev-hub"
        }
        reviewed = {(item.name, item.version) for item in self.dependency_wheels}
        if observed != reviewed:
            raise ValueError("Dependency wheel set differs from installed runtime distributions")
        return self


class NativeCodexAuthorityV1(Contract):
    accepted_run_id: Annotated[int, Field(ge=1)]
    devfabric_implementation_commit: GitCommit
    build_id: Literal["windows-build-001"] = "windows-build-001"
    build_receipt_path: Literal["authority/windows-build-result.json"] = (
        "authority/windows-build-result.json"
    )
    build_receipt_sha256: Digest
    qualification: Literal["WINDOWS_PRODUCTION_HOST_QUALIFIED_PRE_SAMPLING"] = (
        "WINDOWS_PRODUCTION_HOST_QUALIFIED_PRE_SAMPLING"
    )
    target: Literal["x86_64-pc-windows-msvc"] = "x86_64-pc-windows-msvc"
    executable_path: Literal["codex/codex.exe"] = "codex/codex.exe"
    executable_sha256: Digest
    executable_version: Literal["codex-cli 0.155.0-alpha.9.2"] = "codex-cli 0.155.0-alpha.9.2"
    codex_source_commit: GitCommit
    source_archive_sha256: Digest
    candidate_b_base_patch_sha256: Digest
    host_integration_patch_sha256: Digest
    combined_patchset_sha256: Digest


class NativeLauncherV1(Contract):
    python_path: Literal["python/python.exe"] = "python/python.exe"
    delegate_argv_prefix: tuple[
        Literal["-I"], Literal["-B"], Literal["-m"], Literal["devhub.delegate_server"]
    ] = ("-I", "-B", "-m", "devhub.delegate_server")
    config_flag: Literal["--config"] = "--config"
    codex_path: Literal["codex/codex.exe"] = "codex/codex.exe"
    config_locator_external: Literal[True] = True
    mutable_state_external: Literal[True] = True


class NativeBundlePayloadV1(Contract):
    kind: Literal["devfabric_native_directory"] = "devfabric_native_directory"
    platform: NativePlatform
    architecture: NativeArchitecture
    implementation_commit: GitCommit
    python: EmbeddedPythonAuthorityV1
    codex: NativeCodexAuthorityV1
    launcher: NativeLauncherV1
    files: tuple[NativeBundleFileV1, ...] = Field(min_length=1)
    trusted_prelaunch_verifier_required: Literal[True] = True
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False

    @model_validator(mode="after")
    def exact_inventory(self) -> NativeBundlePayloadV1:
        if self.python.runtime.payload.devhub_source_commit != self.implementation_commit:
            raise ValueError("Native runtime source commit differs from bundle implementation")
        paths = [item.path for item in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("Native bundle inventory must be unique and sorted")
        if len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("Windows native bundle paths must be case-insensitively unique")
        by_path = {item.path: item for item in self.files}
        required = {
            self.python.archive_path: self.python.archive_sha256,
            self.python.sbom_path: self.python.sbom_sha256,
            self.python.executable_path: self.python.executable_sha256,
            self.python.pth_path: self.python.pth_sha256,
            self.python.devhub_wheel_path: self.python.devhub_wheel_sha256,
            self.python.dependency_lock_path: self.python.dependency_lock_sha256,
            self.codex.build_receipt_path: self.codex.build_receipt_sha256,
            self.codex.executable_path: self.codex.executable_sha256,
        }
        required.update(
            {
                f"authority/wheels/{wheel.filename}": wheel.sha256
                for wheel in self.python.dependency_wheels
            }
        )
        for path, expected_hash in required.items():
            item = by_path.get(path)
            if item is None or item.sha256 != expected_hash:
                raise ValueError(f"Bundle authority file is absent or mismatched: {path}")
        forbidden_top_level = {"config", "data", "ledger", "logs", "projects", "secrets"}
        if any(PurePosixPath(path).parts[0].lower() in forbidden_top_level for path in paths):
            raise ValueError("Mutable application state must remain outside the native bundle")
        allowed_top_level = {"authority", "codex", "python"}
        if any(PurePosixPath(path).parts[0].lower() not in allowed_top_level for path in paths):
            raise ValueError("Native bundle contains an unreviewed top-level path")
        expected_authority = {
            self.python.archive_path,
            self.python.sbom_path,
            self.python.devhub_wheel_path,
            self.python.dependency_lock_path,
            self.codex.build_receipt_path,
            *(f"authority/wheels/{wheel.filename}" for wheel in self.python.dependency_wheels),
        }
        observed_authority = {path for path in paths if path.startswith("authority/")}
        if observed_authority != expected_authority:
            raise ValueError("Native bundle authority directory differs from the closed layout")
        if {path for path in paths if path.startswith("codex/")} != {self.codex.executable_path}:
            raise ValueError("Native bundle Codex directory differs from the closed layout")
        if self.platform != "windows" or self.architecture != "x86_64":
            raise ValueError("Native bundle V1 currently defines only Windows x86_64")
        return self


class NativeBundleV1(Contract):
    bundle_id: Digest
    payload: NativeBundlePayloadV1

    @classmethod
    def create(cls, payload: NativeBundlePayloadV1) -> NativeBundleV1:
        identifier = digest(canonical(cast(JsonValue, payload.model_dump(mode="json"))))
        return cls(bundle_id=identifier, payload=payload)

    @model_validator(mode="after")
    def canonical_id(self) -> NativeBundleV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.bundle_id != expected:
            raise ValueError("Native bundle ID mismatch")
        return self


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _assert_plain(path: Path) -> os.stat_result:
    result = path.lstat()
    if path.is_symlink() or _is_reparse(result):
        raise ValueError(f"Native bundle contains a symlink/reparse entry: {path.name}")
    return result


def inventory_native_bundle(root: Path) -> tuple[NativeBundleFileV1, ...]:
    """Hash every regular file without following symlink or reparse entries."""

    root = Path(os.path.abspath(root))
    root_stat = _assert_plain(root)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("Native bundle root must be a real directory")
    records: list[NativeBundleFileV1] = []

    def visit(directory: Path) -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            result = _assert_plain(path)
            if stat.S_ISDIR(result.st_mode):
                visit(path)
            elif stat.S_ISREG(result.st_mode):
                relative = path.relative_to(root).as_posix()
                records.append(
                    NativeBundleFileV1(
                        path=relative,
                        size=result.st_size,
                        sha256=file_sha256(path),
                    )
                )
            else:
                raise ValueError(f"Native bundle contains a non-file entry: {path.name}")

    visit(root)
    records.sort(key=lambda item: item.path)
    return tuple(records)


def observed_native_platform() -> tuple[NativePlatform, NativeArchitecture]:
    if sys.platform == "win32":
        system: NativePlatform = "windows"
    elif sys.platform.startswith("linux"):
        system = "linux"
    else:
        raise ValueError("Unsupported native platform")
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        raise ValueError("Unsupported native architecture")
    return system, "x86_64"


def _inside_relative(path: str, root: Path, label: str) -> str:
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError(f"{label} escapes the native bundle")
    return resolved.relative_to(root).as_posix()


def inspect_embedded_windows_runtime(
    interpreter: Path,
    devhub_wheel: Path,
    lock_path: Path,
    source_commit: str,
) -> NativePythonRuntimeV1:
    """Inspect the reviewed embedded runtime with hostile ambient Python settings."""

    interpreter = Path(os.path.abspath(interpreter))
    root = interpreter.parent.parent.resolve(strict=True)
    for path, label in (
        (interpreter, "interpreter"),
        (devhub_wheel, "DevFabric wheel"),
        (lock_path, "dependency lock"),
    ):
        result = _assert_plain(path)
        if not stat.S_ISREG(result.st_mode):
            raise ValueError(f"Native {label} must be a regular non-reparse file")
    environment = {
        "PATH": "",
        "PYTHONPATH": str(root.parent / "untrusted-pythonpath"),
        "PYTHONHOME": str(root.parent / "untrusted-pythonhome"),
        "PYTHONUSERBASE": str(root.parent / "untrusted-user-site"),
    }
    if system_root := os.environ.get("SYSTEMROOT"):
        environment["SYSTEMROOT"] = system_root
    raw = subprocess.check_output(
        [str(interpreter), "-I", "-B", "-c", _NATIVE_INSPECT_SCRIPT],
        cwd=root.parent,
        env=environment,
        timeout=60,
    )
    observed = json.loads(raw)
    if (
        observed.get("implementation") != "CPython"
        or observed.get("version") != "3.12.10"
        or observed.get("cache_tag") != "cpython-312"
        or observed.get("platform_tag") != "win-amd64"
        or observed.get("system") != "Windows"
    ):
        raise ValueError("Embedded Python platform identity differs from the reviewed runtime")
    if (
        not all(
            observed.get(key) is True
            for key in ("isolated", "ignore_environment", "no_user_site", "dont_write_bytecode")
        )
        or observed.get("editable") is not False
    ):
        raise ValueError("Embedded Python is not isolated from ambient installation state")
    python_root = root / "python"
    expected_root = str(python_root.resolve(strict=True))
    if observed.get("prefix") != expected_root or observed.get("base_prefix") != expected_root:
        raise ValueError("Embedded Python prefix escapes the immutable bundle")
    if Path(observed.get("executable", "")) != interpreter.resolve(strict=True):
        raise ValueError("Embedded Python executable identity differs from the invoked file")
    sys_path = tuple(
        _inside_relative(item, root, "Python sys.path") for item in observed["sys_path"]
    )
    modules = tuple(
        sorted(
            (
                NativeModuleOriginV1(
                    module=item["module"],
                    path=_inside_relative(str(root / item["path"]), root, "module origin"),
                )
                for item in observed["modules"]
            ),
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
    payload = NativePythonRuntimePayloadV1(
        python_executable_sha256=file_sha256(interpreter),
        platform_machine=observed.get("machine"),
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
    return NativePythonRuntimeV1.create(payload)


def verify_native_bundle(
    bundle: NativeBundleV1,
    root: Path,
    *,
    expected_platform: NativePlatform | None = None,
    expected_architecture: NativeArchitecture | None = None,
) -> None:
    """Verify exact content and target before a trusted launcher may execute it."""

    if expected_platform is None or expected_architecture is None:
        observed_platform, observed_architecture = observed_native_platform()
        expected_platform = expected_platform or observed_platform
        expected_architecture = expected_architecture or observed_architecture
    if (
        bundle.payload.platform != expected_platform
        or bundle.payload.architecture != expected_architecture
    ):
        raise ValueError("Native bundle target differs from the current trusted launcher target")
    observed = inventory_native_bundle(root)
    if observed != bundle.payload.files:
        raise ValueError("Native bundle files differ from the immutable manifest")
    pth = root / PurePosixPath(bundle.payload.python.pth_path)
    pth_lines = pth.read_text(encoding="ascii").splitlines()
    expected_pth = [
        "python312.zip",
        ".",
        "site-packages",
        r"site-packages\win32",
        r"site-packages\win32\lib",
        r"site-packages\pythonwin",
        r"site-packages\pywin32_system32",
    ]
    if pth_lines != expected_pth or any(line.lstrip().startswith("import ") for line in pth_lines):
        raise ValueError("Embedded Python path authority differs from the reviewed inert layout")
    unexpected_pth = [
        item.path
        for item in observed
        if item.path.endswith(".pth") and item.path != bundle.payload.python.pth_path
    ]
    if unexpected_pth:
        raise ValueError("Native bundle contains an unreviewed Python startup path file")
    archive = root / PurePosixPath(bundle.payload.python.archive_path)
    archive_raw = archive.read_bytes()
    if embedded_archive_members_sha256(archive_raw) != bundle.payload.python.archive_members_sha256:
        raise ValueError("Retained CPython archive member identity differs from the manifest")
    expected_archive_files: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(archive_raw)) as stream:
        names: set[str] = set()
        for item in stream.infolist():
            if item.is_dir():
                continue
            member = PurePosixPath(item.filename)
            if (
                item.filename in names
                or member.is_absolute()
                or ".." in member.parts
                or "\\" in item.filename
            ):
                raise ValueError("Retained CPython archive member layout is unsafe")
            names.add(item.filename)
            relative = f"python/{member.as_posix()}"
            expected_archive_files.add(relative)
            if relative == bundle.payload.python.pth_path:
                continue
            target = root.joinpath(*PurePosixPath(relative).parts)
            raw = stream.read(item)
            if not target.is_file() or target.stat().st_size != len(raw):
                raise ValueError("Extracted CPython layout differs from its retained archive")
            if file_sha256(target) != hashlib.sha256(raw).hexdigest():
                raise ValueError("Extracted CPython file differs from its retained archive")
    observed_python_base = {
        item.path
        for item in observed
        if item.path.startswith("python/") and not item.path.startswith("python/site-packages/")
    }
    if observed_python_base != expected_archive_files:
        raise ValueError("Embedded Python base layout differs from the retained archive")
    retained_wheels = (
        root / PurePosixPath(bundle.payload.python.devhub_wheel_path),
        *(
            root / "authority" / "wheels" / wheel.filename
            for wheel in bundle.payload.python.dependency_wheels
        ),
    )
    verify_installed_wheel_tree(root / "python" / "site-packages", retained_wheels)
