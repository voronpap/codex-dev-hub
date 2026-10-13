"""Strict contracts for a relocatable native Linux DevFabric directory.

This slice seals a runnable directory and its exact runtime identities.  Native
executor isolation and platform readiness remain separate qualification gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import subprocess
import tarfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Annotated, BinaryIO, Literal, cast

from pydantic import Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.linux_native import (
    LinuxNativeCodexBuildV7,
    LinuxNativeCodexBuildV8,
    LinuxNativeCodexBuildV9,
    LinuxNativeCodexBuildV10,
    LinuxNativeCodexBuildV11,
    LinuxNativeCodexBuildV12,
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


def is_linux_dynamic_elf(path: Path) -> bool:
    """Identify one loadable/executable little-endian ELF64 object without execution."""

    with path.open("rb") as stream:
        header = stream.read(18)
    return (
        len(header) == 18
        and header[:4] == b"\x7fELF"
        and header[4:6] == b"\x02\x01"
        and int.from_bytes(header[16:18], "little") in {2, 3}
    )


def inspect_linux_dynamic_elf(path: Path, relative: str) -> LinuxElfRequirementV1:
    """Recompute PT_INTERP and dynamic-string authority with the Python stdlib."""

    relative = _canonical_relative(relative)
    size = path.stat().st_size
    if size < 64:
        raise ValueError(f"Linux runtime ELF header is truncated: {relative}")

    def read_at(stream: BinaryIO, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > size:
            raise ValueError(f"Linux runtime ELF range is invalid: {relative}")
        stream.seek(offset)
        value = stream.read(length)
        if len(value) != length:
            raise ValueError(f"Linux runtime ELF range is truncated: {relative}")
        return value

    with path.open("rb") as stream:
        header = read_at(stream, 0, 64)
        (
            ident,
            elf_type,
            machine,
            _version,
            _entry,
            program_offset,
            _section_offset,
            _flags,
            header_size,
            program_entry_size,
            program_count,
            _section_entry_size,
            _section_count,
            _section_names,
        ) = struct.unpack("<16sHHIQQQIHHHHHH", header)
        if (
            ident[:6] != b"\x7fELF\x02\x01"
            or elf_type not in {2, 3}
            or machine != 62
            or header_size != 64
            or program_entry_size < 56
            or not 1 <= program_count <= 1024
        ):
            raise ValueError(f"Linux runtime object is not reviewed ELF64 x86-64: {relative}")
        segments: list[tuple[int, int, int, int, int]] = []
        interpreter: str | None = None
        dynamic: tuple[int, int] | None = None
        for index in range(program_count):
            raw = read_at(stream, program_offset + index * program_entry_size, 56)
            (
                segment_type,
                _segment_flags,
                file_offset,
                virtual_address,
                _physical_address,
                file_size,
                _memory_size,
                _alignment,
            ) = struct.unpack("<IIQQQQQQ", raw)
            segments.append((segment_type, file_offset, virtual_address, file_size, size))
            if segment_type == 3:
                raw_interpreter = read_at(stream, file_offset, file_size)
                if not raw_interpreter.endswith(b"\x00"):
                    raise ValueError(f"Linux runtime PT_INTERP is invalid: {relative}")
                interpreter = raw_interpreter[:-1].decode("utf-8", errors="strict")
            elif segment_type == 2:
                dynamic = (file_offset, file_size)
        if interpreter is not None and interpreter != "/lib64/ld-linux-x86-64.so.2":
            raise ValueError(f"Linux runtime object uses another interpreter: {relative}")
        needed_offsets: list[int] = []
        rpath_offset: int | None = None
        runpath_offset: int | None = None
        string_address: int | None = None
        string_size: int | None = None
        if dynamic is not None:
            dynamic_offset, dynamic_size = dynamic
            if dynamic_size > 4 * 1024 * 1024 or dynamic_size % 16:
                raise ValueError(f"Linux runtime dynamic table is invalid: {relative}")
            for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
                tag, value = struct.unpack("<qQ", read_at(stream, offset, 16))
                if tag == 0:
                    break
                if tag == 1:
                    needed_offsets.append(value)
                elif tag == 5:
                    string_address = value
                elif tag == 10:
                    string_size = value
                elif tag == 15:
                    rpath_offset = value
                elif tag == 29:
                    runpath_offset = value
        if rpath_offset is not None or runpath_offset is not None:
            raise ValueError(f"Linux runtime ELF contains RPATH/RUNPATH: {relative}")
        if needed_offsets or rpath_offset is not None or runpath_offset is not None:
            if (
                string_address is None
                or string_size is None
                or not 1 <= string_size <= 16 * 1024**2
            ):
                raise ValueError(f"Linux runtime dynamic strings are invalid: {relative}")
            string_offset: int | None = None
            for segment_type, file_offset, virtual_address, file_size, _ in segments:
                if (
                    segment_type == 1
                    and virtual_address <= string_address < virtual_address + file_size
                ):
                    string_offset = file_offset + string_address - virtual_address
                    break
            if string_offset is None:
                raise ValueError(f"Linux runtime dynamic strings are unmapped: {relative}")
            strings = read_at(stream, string_offset, string_size)

            def dynamic_string(offset: int) -> str:
                if offset >= len(strings):
                    raise ValueError(f"Linux runtime dynamic string is invalid: {relative}")
                end = strings.find(b"\x00", offset)
                if end < 0:
                    raise ValueError(f"Linux runtime dynamic string is unterminated: {relative}")
                return strings[offset:end].decode("utf-8", errors="strict")

            needed = tuple(sorted(set(dynamic_string(value) for value in needed_offsets)))
            rpath = ()
            runpath = ()
        else:
            needed = ()
            rpath = ()
            runpath = ()
    return LinuxElfRequirementV1(
        path=relative,
        interpreter=cast(
            Literal["/lib64/ld-linux-x86-64.so.2"] | None,
            interpreter,
        ),
        needed=needed,
        rpath=rpath,
        runpath=runpath,
    )


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


class LinuxCodexAuthorityV4(LinuxCodexAuthorityV1):
    """Forward authority for the corrected module-entrypoint build pair."""

    schema_version: Literal[4] = 4  # type: ignore[assignment]
    build_id: Literal["linux-build-010"] = "linux-build-010"  # type: ignore[assignment]


class LinuxCodexAuthorityV5(LinuxCodexAuthorityV1):
    """Forward authority for the package-bound-isolation build pair."""

    schema_version: Literal[5] = 5  # type: ignore[assignment]
    build_id: Literal["linux-build-011"] = "linux-build-011"  # type: ignore[assignment]


class LinuxCodexAuthorityV6(LinuxCodexAuthorityV1):
    """Forward authority for the corrected package-bound runtime."""

    schema_version: Literal[6] = 6  # type: ignore[assignment]
    build_id: Literal["linux-build-012"] = "linux-build-012"  # type: ignore[assignment]


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


class LinuxRuntimeLibraryV1(Contract):
    """One exact DT_NEEDED name supplied by the immutable runtime closure."""

    soname: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.+\-]+$")
    path: str = Field(min_length=1, max_length=1024)
    size: Annotated[int, Field(ge=1)]
    sha256: Digest

    @model_validator(mode="after")
    def exact_path(self) -> LinuxRuntimeLibraryV1:
        if self.path != f"runtime/lib/{self.soname}":
            raise ValueError("Linux runtime library path differs from its SONAME")
        return self


class LinuxElfRequirementV1(Contract):
    """Static ELF dependency observation for one manifest-bound bundle file."""

    path: str = Field(min_length=1, max_length=1024)
    interpreter: Literal["/lib64/ld-linux-x86-64.so.2"] | None = None
    needed: tuple[str, ...] = ()
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        return _canonical_relative(value)

    @field_validator("needed")
    @classmethod
    def canonical_needed(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("Linux ELF DT_NEEDED names must be unique and sorted")
        if any(
            not item or len(item) > 255 or "/" in item or "\\" in item or "\x00" in item
            for item in value
        ):
            raise ValueError("Linux ELF DT_NEEDED name is unsafe")
        return value

    @field_validator("rpath", "runpath")
    @classmethod
    def no_ambient_search_path(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value:
            raise ValueError("Linux runtime ELF RPATH/RUNPATH is not allowed")
        return value


class LinuxRuntimeClosureV1(Contract):
    """Closed, exact glibc loader/library authority for post-chroot execution."""

    loader_path: Literal["runtime/loader/ld-linux-x86-64.so.2"] = (
        "runtime/loader/ld-linux-x86-64.so.2"
    )
    loader_sha256: Digest
    loader_size: Annotated[int, Field(ge=1)]
    embedded_interpreter: Literal["/lib64/ld-linux-x86-64.so.2"] = "/lib64/ld-linux-x86-64.so.2"
    library_directory: Literal["runtime/lib"] = "runtime/lib"
    loader_arguments: tuple[Literal["--inhibit-cache"], Literal["--library-path"]] = (
        "--inhibit-cache",
        "--library-path",
    )
    libraries: tuple[LinuxRuntimeLibraryV1, ...] = Field(min_length=1, max_length=256)
    elf_requirements: tuple[LinuxElfRequirementV1, ...] = Field(min_length=4)

    @model_validator(mode="after")
    def exact_recursive_closure(self) -> LinuxRuntimeClosureV1:
        library_names = [item.soname for item in self.libraries]
        if library_names != sorted(library_names) or len(library_names) != len(set(library_names)):
            raise ValueError("Linux runtime libraries must be unique and sorted")
        object_paths = [item.path for item in self.elf_requirements]
        if object_paths != sorted(object_paths) or len(object_paths) != len(set(object_paths)):
            raise ValueError("Linux ELF requirements must be unique and sorted")
        required_objects = {
            "python/bin/python3.12",
            "codex/codex",
            "codex/codex-code-mode-host",
            self.loader_path,
            *(item.path for item in self.libraries),
        }
        if not required_objects.issubset(object_paths):
            raise ValueError("Linux runtime closure omits a required ELF object")
        needed = {name for item in self.elf_requirements for name in item.needed}
        loader_name = PurePosixPath(self.loader_path).name
        if needed - {loader_name} != set(library_names):
            raise ValueError("Linux runtime libraries differ from recursive DT_NEEDED closure")
        interpreted = {item.path for item in self.elf_requirements if item.interpreter is not None}
        if not {
            "python/bin/python3.12",
            "codex/codex",
            "codex/codex-code-mode-host",
        }.issubset(interpreted):
            raise ValueError("Linux executable interpreter authority is incomplete")
        return self


class LinuxLauncherV2(LinuxLauncherV1):
    """Launcher that enters the exact bundle-owned dynamic runtime."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    loader_path: Literal["runtime/loader/ld-linux-x86-64.so.2"] = (
        "runtime/loader/ld-linux-x86-64.so.2"
    )
    library_directory: Literal["runtime/lib"] = "runtime/lib"
    loader_arguments: tuple[Literal["--inhibit-cache"], Literal["--library-path"]] = (
        "--inhibit-cache",
        "--library-path",
    )


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
        expected_codex_commit = getattr(
            self, "retained_codex_implementation_commit", self.implementation_commit
        )
        if (
            self.python.runtime.payload.devhub_source_commit != self.implementation_commit
            or self.codex.devfabric_implementation_commit != expected_codex_commit
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
        expected_top_level = {"authority", "bin", "codex", "python"}
        if getattr(self, "runtime_closure", None) is not None:
            expected_top_level.add("runtime")
        if top_level != expected_top_level:
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


class LinuxNativeBundlePayloadV4(LinuxNativeBundlePayloadV1):
    """Forward bundle payload consuming only linux-build-010 authority."""

    schema_version: Literal[4] = 4  # type: ignore[assignment]
    codex: LinuxCodexAuthorityV4


class LinuxNativeBundlePayloadV5(LinuxNativeBundlePayloadV1):
    """Forward bundle payload consuming only linux-build-011 authority."""

    schema_version: Literal[5] = 5  # type: ignore[assignment]
    codex: LinuxCodexAuthorityV5


class LinuxNativeBundlePayloadV6(LinuxNativeBundlePayloadV1):
    """Forward bundle payload consuming only linux-build-012 authority."""

    schema_version: Literal[6] = 6  # type: ignore[assignment]
    codex: LinuxCodexAuthorityV6


class LinuxNativeBundlePayloadV7(LinuxNativeBundlePayloadV1):
    """Forward bundle with current Python code and retained Build-012 binaries."""

    schema_version: Literal[7] = 7  # type: ignore[assignment]
    codex: LinuxCodexAuthorityV6
    retained_codex_implementation_commit: GitCommit

    @model_validator(mode="after")
    def exact_split_authority(self) -> LinuxNativeBundlePayloadV7:
        if (
            self.python.runtime.payload.devhub_source_commit != self.implementation_commit
            or self.codex.devfabric_implementation_commit
            != self.retained_codex_implementation_commit
        ):
            raise ValueError("Linux V7 bundle split authority differs")
        return self


class LinuxNativeBundlePayloadV8(LinuxNativeBundlePayloadV7):
    """Forward bundle with the versioned packaged-subprocess capture frame."""

    schema_version: Literal[8] = 8  # type: ignore[assignment]


class LinuxNativeBundlePayloadV9(LinuxNativeBundlePayloadV8):
    """Forward bundle with an exact post-chroot dynamic-runtime closure."""

    schema_version: Literal[9] = 9  # type: ignore[assignment]
    launcher: LinuxLauncherV2
    runtime_closure: LinuxRuntimeClosureV1

    @model_validator(mode="after")
    def exact_runtime_files(self) -> LinuxNativeBundlePayloadV9:
        by_path = {item.path: item for item in self.files}
        runtime_files = {
            path
            for path, item in by_path.items()
            if item.kind == "file" and PurePosixPath(path).parts[0] == "runtime"
        }
        expected = {
            self.runtime_closure.loader_path,
            *(item.path for item in self.runtime_closure.libraries),
        }
        if runtime_files != expected:
            raise ValueError("Linux runtime directory differs from closure authority")
        loader = by_path.get(self.runtime_closure.loader_path)
        if (
            loader is None
            or loader.kind != "file"
            or loader.sha256 != self.runtime_closure.loader_sha256
            or loader.size != self.runtime_closure.loader_size
            or loader.mode != 0o755
        ):
            raise ValueError("Linux dynamic loader differs from closure authority")
        for library in self.runtime_closure.libraries:
            entry = by_path.get(library.path)
            if (
                entry is None
                or entry.kind != "file"
                or entry.sha256 != library.sha256
                or entry.size != library.size
            ):
                raise ValueError("Linux shared library differs from closure authority")
        runtime_directories = {
            path
            for path, item in by_path.items()
            if item.kind == "directory" and PurePosixPath(path).parts[0] == "runtime"
        }
        if runtime_directories != {"runtime", "runtime/lib", "runtime/loader"}:
            raise ValueError("Linux runtime directory tree is not closed")
        return self


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


class LinuxNativeBundleV4(Contract):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV4

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV4) -> LinuxNativeBundleV4:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV4:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native bundle ID mismatch")
        return self


class LinuxNativeBundleV5(Contract):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV5

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV5) -> LinuxNativeBundleV5:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV5:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native bundle ID mismatch")
        return self


class LinuxNativeBundleV6(Contract):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV6

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV6) -> LinuxNativeBundleV6:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV6:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native bundle ID mismatch")
        return self


class LinuxNativeBundleV7(Contract):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV7

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV7) -> LinuxNativeBundleV7:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV7:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native V7 bundle ID mismatch")
        return self


class LinuxNativeBundleV8(Contract):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV8

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV8) -> LinuxNativeBundleV8:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV8:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native V8 bundle ID mismatch")
        return self


class LinuxNativeBundleV9(Contract):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    linux_native_bundle_id: Digest
    payload: LinuxNativeBundlePayloadV9

    @classmethod
    def create(cls, payload: LinuxNativeBundlePayloadV9) -> LinuxNativeBundleV9:
        return cls(
            linux_native_bundle_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeBundleV9:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_bundle_id != expected:
            raise ValueError("Linux native V9 bundle ID mismatch")
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


class LinuxNativeArchivePayloadV4(LinuxNativeArchivePayloadV1):
    schema_version: Literal[4] = 4  # type: ignore[assignment]


class LinuxNativeArchiveV4(Contract):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV4

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV4) -> LinuxNativeArchiveV4:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV4:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native archive ID mismatch")
        return self


class LinuxNativeArchivePayloadV5(LinuxNativeArchivePayloadV1):
    schema_version: Literal[5] = 5  # type: ignore[assignment]


class LinuxNativeArchiveV5(Contract):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV5

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV5) -> LinuxNativeArchiveV5:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV5:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native archive ID mismatch")
        return self


class LinuxNativeArchivePayloadV6(LinuxNativeArchivePayloadV1):
    schema_version: Literal[6] = 6  # type: ignore[assignment]


class LinuxNativeArchiveV6(Contract):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV6

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV6) -> LinuxNativeArchiveV6:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV6:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native archive ID mismatch")
        return self


class LinuxNativeArchivePayloadV7(LinuxNativeArchivePayloadV1):
    schema_version: Literal[7] = 7  # type: ignore[assignment]


class LinuxNativeArchiveV7(Contract):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV7

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV7) -> LinuxNativeArchiveV7:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV7:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native V7 archive ID mismatch")
        return self


class LinuxNativeArchivePayloadV8(LinuxNativeArchivePayloadV1):
    schema_version: Literal[8] = 8  # type: ignore[assignment]


class LinuxNativeArchiveV8(Contract):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV8

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV8) -> LinuxNativeArchiveV8:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV8:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native V8 archive ID mismatch")
        return self


class LinuxNativeArchivePayloadV9(LinuxNativeArchivePayloadV1):
    schema_version: Literal[9] = 9  # type: ignore[assignment]


class LinuxNativeArchiveV9(Contract):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    linux_native_archive_id: Digest
    payload: LinuxNativeArchivePayloadV9

    @classmethod
    def create(cls, payload: LinuxNativeArchivePayloadV9) -> LinuxNativeArchiveV9:
        return cls(
            linux_native_archive_id=digest(
                canonical(cast(JsonValue, payload.model_dump(mode="json")))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def canonical_id(self) -> LinuxNativeArchiveV9:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.linux_native_archive_id != expected:
            raise ValueError("Linux native V9 archive ID mismatch")
        return self


def bundled_loader_command(
    root: Path,
    closure: LinuxRuntimeClosureV1,
    program_relative: str,
    arguments: tuple[str, ...],
) -> list[str]:
    """Build an exact bundle-only dynamic-loader invocation."""

    relative = _canonical_relative(program_relative)
    root = Path(os.path.abspath(root))
    loader = root.joinpath(*closure.loader_path.split("/"))
    library_directory = root.joinpath(*closure.library_directory.split("/"))
    program = root.joinpath(*relative.split("/"))
    for path, label in (
        (loader, "dynamic loader"),
        (library_directory, "runtime library directory"),
        (program, "runtime program"),
    ):
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root.resolve(strict=True)):
            raise ValueError(f"Linux {label} escapes the bundle")
    if file_sha256(loader) != closure.loader_sha256:
        raise ValueError("Linux dynamic loader bytes differ from closure authority")
    return [
        str(loader),
        *closure.loader_arguments,
        str(library_directory),
        str(program),
        *arguments,
    ]


def observe_linux_runtime(
    interpreter: Path,
    devhub_wheel: Path,
    lock_path: Path,
    source_commit: str,
    closure: LinuxRuntimeClosureV1 | None = None,
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
    command = [str(interpreter), "-I", "-B", "-c", _INSPECT]
    if closure is not None:
        command = bundled_loader_command(
            bundle_root,
            closure,
            interpreter.relative_to(bundle_root).as_posix(),
            ("-I", "-B", "-c", _INSPECT),
        )
    raw = subprocess.check_output(
        command,
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


LinuxNativeBundle = (
    LinuxNativeBundleV1
    | LinuxNativeBundleV2
    | LinuxNativeBundleV3
    | LinuxNativeBundleV4
    | LinuxNativeBundleV5
    | LinuxNativeBundleV6
    | LinuxNativeBundleV7
    | LinuxNativeBundleV8
    | LinuxNativeBundleV9
)
LinuxNativeArchive = (
    LinuxNativeArchiveV1
    | LinuxNativeArchiveV2
    | LinuxNativeArchiveV3
    | LinuxNativeArchiveV4
    | LinuxNativeArchiveV5
    | LinuxNativeArchiveV6
    | LinuxNativeArchiveV7
    | LinuxNativeArchiveV8
    | LinuxNativeArchiveV9
)


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
    receipt: (
        LinuxNativeCodexBuildV7
        | LinuxNativeCodexBuildV8
        | LinuxNativeCodexBuildV9
        | LinuxNativeCodexBuildV10
        | LinuxNativeCodexBuildV11
        | LinuxNativeCodexBuildV12
    )
    if isinstance(
        bundle, (LinuxNativeBundleV6, LinuxNativeBundleV7, LinuxNativeBundleV8, LinuxNativeBundleV9)
    ):
        receipt = LinuxNativeCodexBuildV12.model_validate_json(receipt_path.read_bytes())
    elif isinstance(bundle, LinuxNativeBundleV5):
        receipt = LinuxNativeCodexBuildV11.model_validate_json(receipt_path.read_bytes())
    elif isinstance(bundle, LinuxNativeBundleV4):
        receipt = LinuxNativeCodexBuildV10.model_validate_json(receipt_path.read_bytes())
    elif isinstance(bundle, LinuxNativeBundleV3):
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
    if isinstance(bundle, LinuxNativeBundleV9):
        observed_elf: list[LinuxElfRequirementV1] = []
        for item in bundle.payload.files:
            if item.kind != "file":
                continue
            path = root.joinpath(*item.path.split("/"))
            if is_linux_dynamic_elf(path):
                observed_elf.append(inspect_linux_dynamic_elf(path, item.path))
        observed_elf.sort(key=lambda item: item.path)
        if tuple(observed_elf) != bundle.payload.runtime_closure.elf_requirements:
            raise ValueError("Linux ELF inventory differs from runtime closure authority")
    runtime = observe_linux_runtime(
        root / bundle.payload.python.executable_path,
        root / bundle.payload.python.devhub_wheel_path,
        root / bundle.payload.python.dependency_lock_path,
        bundle.payload.implementation_commit,
        bundle.payload.runtime_closure if isinstance(bundle, LinuxNativeBundleV9) else None,
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


def smoke_linux_bundle_cli(root: Path, bundle: LinuxNativeBundleV9 | None = None) -> None:
    """Run one metadata-only command through the packaged relative launcher."""

    environment = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(root.parent / "untrusted-pythonpath"),
        "PYTHONHOME": str(root.parent / "untrusted-pythonhome"),
        "PYTHONUSERBASE": str(root.parent / "untrusted-user-site"),
    }
    command = [str(root / "bin/devfabric"), "schema"]
    if bundle is not None:
        command = bundled_loader_command(
            root,
            bundle.payload.runtime_closure,
            bundle.payload.python.executable_path,
            ("-I", "-B", "-m", "devhub.cli", "schema"),
        )
    completed = subprocess.run(
        command,
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
    elif manifest_version == 4 and archive_version == 4:
        bundle = LinuxNativeBundleV4.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV4.model_validate_json(archive_raw)
    elif manifest_version == 5 and archive_version == 5:
        bundle = LinuxNativeBundleV5.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV5.model_validate_json(archive_raw)
    elif manifest_version == 6 and archive_version == 6:
        bundle = LinuxNativeBundleV6.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV6.model_validate_json(archive_raw)
    elif manifest_version == 7 and archive_version == 7:
        bundle = LinuxNativeBundleV7.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV7.model_validate_json(archive_raw)
    elif manifest_version == 8 and archive_version == 8:
        bundle = LinuxNativeBundleV8.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV8.model_validate_json(archive_raw)
    elif manifest_version == 9 and archive_version == 9:
        bundle = LinuxNativeBundleV9.model_validate_json(manifest_raw)
        archive = LinuxNativeArchiveV9.model_validate_json(archive_raw)
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
    if isinstance(bundle, LinuxNativeBundleV9):
        smoke_linux_bundle_cli(extracted, bundle)
    else:
        smoke_linux_bundle_cli(extracted)
    return archive


def runtime_tree_sha256(root: Path) -> str:
    """Return a compact identity for tests and external evidence projection."""

    records = inventory_linux_bundle(root)
    payload = [item.model_dump(mode="json") for item in records]
    return hashlib.sha256(canonical(cast(JsonValue, payload))).hexdigest()
