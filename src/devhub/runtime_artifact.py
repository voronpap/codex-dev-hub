"""Build-time and runtime verification for the immutable DevFabric Python artifact."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.models import Contract
from devhub.qualification import (
    GitCommit,
    PythonRuntimeExpectedV1,
    QualificationReceiptHeaderV1,
    VerifiedQualificationV2,
)


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def normalize_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


class DistributionIdentityV1(Contract):
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=128)
    record_sha256: Digest
    file_count: Annotated[int, Field(ge=1)]


class PythonRuntimeEnvironmentPayloadV1(Contract):
    python_implementation: Literal["CPython"]
    python_version: Annotated[str, Field(pattern=r"^3\.12(?:\.[0-9]+)?$")]
    python_executable_sha256: Digest
    python_cache_tag: str = Field(min_length=1, max_length=64)
    python_soabi: str = Field(min_length=1, max_length=128)
    platform_system: str = Field(min_length=1, max_length=64)
    platform_machine: str = Field(min_length=1, max_length=64)
    devhub_source_commit: GitCommit
    devhub_wheel_sha256: Digest
    dependency_lock_sha256: Digest
    devhub_distribution_version: str = Field(min_length=1, max_length=64)
    devhub_module_origin: str = Field(min_length=1, max_length=512)
    distributions: tuple[DistributionIdentityV1, ...] = Field(min_length=1)
    entrypoint: Literal["devhub.delegate_server"] = "devhub.delegate_server"
    isolated_argv: tuple[Literal["-I"], Literal["-m"], Literal["devhub.delegate_server"]] = (
        "-I",
        "-m",
        "devhub.delegate_server",
    )

    @model_validator(mode="after")
    def normalized_inventory(self) -> PythonRuntimeEnvironmentPayloadV1:
        names = [item.name for item in self.distributions]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("Runtime distribution inventory must be unique and sorted")
        if "codex-dev-hub" not in names:
            raise ValueError("DevFabric distribution is missing from runtime environment")
        return self


class PythonRuntimeEnvironmentV1(Contract):
    python_runtime_environment_id: Digest
    payload: PythonRuntimeEnvironmentPayloadV1

    @classmethod
    def create(cls, payload: PythonRuntimeEnvironmentPayloadV1) -> PythonRuntimeEnvironmentV1:
        identifier = digest(canonical(cast(JsonValue, payload.model_dump(mode="json"))))
        return cls(python_runtime_environment_id=identifier, payload=payload)

    @model_validator(mode="after")
    def canonical_id(self) -> PythonRuntimeEnvironmentV1:
        expected = digest(canonical(cast(JsonValue, self.payload.model_dump(mode="json"))))
        if self.python_runtime_environment_id != expected:
            raise ValueError("Python runtime environment ID mismatch")
        return self


class PythonRuntimeArtifactEvidenceV1(Contract):
    kind: Literal["devfabric_python_runtime_artifact"] = "devfabric_python_runtime_artifact"
    implementation_commit: GitCommit
    source_archive_sha256: Digest
    wheel_filename: str = Field(min_length=1, max_length=255)
    wheel_sha256: Digest
    package_name: Literal["codex-dev-hub"] = "codex-dev-hub"
    package_version: str = Field(min_length=1, max_length=64)
    dependency_lock_sha256: Digest
    build_python_implementation: Literal["CPython"] = "CPython"
    build_python_version: str = Field(min_length=1, max_length=64)
    build_python_executable_sha256: Digest
    build_tool: str = Field(min_length=1, max_length=128)
    build_tool_sha256: Digest
    build_backend: Literal["hatchling==1.27.0"] = "hatchling==1.27.0"
    runtime_environment: PythonRuntimeEnvironmentV1
    wheel_reproducibility_claimed: Literal[False] = False
    provider_sends: Literal[0] = 0
    model_requests: Literal[0] = 0

    @model_validator(mode="after")
    def evidence_matches_environment(self) -> PythonRuntimeArtifactEvidenceV1:
        payload = self.runtime_environment.payload
        if (
            payload.devhub_source_commit != self.implementation_commit
            or payload.devhub_wheel_sha256 != self.wheel_sha256
            or payload.dependency_lock_sha256 != self.dependency_lock_sha256
            or payload.devhub_distribution_version != self.package_version
        ):
            raise ValueError("Runtime environment differs from built artifact evidence")
        return self


class PythonRuntimeReceiptV1(QualificationReceiptHeaderV1):
    qualification_passed: Literal[True] = True
    interpreter_path: str = Field(min_length=1, max_length=1024)
    wheel_path: str = Field(min_length=1, max_length=1024)
    lock_path: str = Field(min_length=1, max_length=1024)
    interpreter_sha256: Digest
    python_implementation: Literal["CPython"]
    python_version: str = Field(min_length=1, max_length=64)
    wheel_sha256: Digest
    dependency_lock_sha256: Digest
    module_origin: str = Field(min_length=1, max_length=512)
    runtime_environment_id: Digest
    entrypoint: Literal["devhub.delegate_server"] = "devhub.delegate_server"
    isolated_argv: tuple[Literal["-I"], Literal["-m"], Literal["devhub.delegate_server"]] = (
        "-I",
        "-m",
        "devhub.delegate_server",
    )
    isolated_flag: Literal[True] = True
    ignore_environment_flag: Literal[True] = True
    no_user_site_flag: Literal[True] = True
    editable_install: Literal[False] = False

    @model_validator(mode="after")
    def python_receipt_kind(self) -> PythonRuntimeReceiptV1:
        if self.receipt_kind != "python_runtime":
            raise ValueError("Python runtime receipt has the wrong kind")
        return self


_INSPECT_SCRIPT = r"""
import base64, hashlib, importlib.metadata as md, json, os, pathlib, platform, site, sys, sysconfig

def h(path):
    x=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1048576),b''): x.update(b)
    return x.hexdigest()

items=[]
editable=False
for dist in md.distributions():
    name=(dist.metadata.get('Name') or '').strip()
    version=(dist.version or '').strip()
    if not name or not version: raise SystemExit('distribution metadata incomplete')
    direct=dist.read_text('direct_url.json')
    if direct:
        try:
            if json.loads(direct).get('dir_info',{}).get('editable') is True: editable=True
        except Exception: raise SystemExit('invalid direct_url.json')
    entries=[]
    files=dist.files or []
    for item in files:
        located=pathlib.Path(dist.locate_file(item))
        if not located.is_file(): raise SystemExit('installed distribution file missing')
        declared=item.hash
        if declared is not None:
            if declared.mode != 'sha256': raise SystemExit('non-sha256 RECORD entry')
            actual=base64.urlsafe_b64encode(bytes.fromhex(h(located))).decode().rstrip('=')
            if actual != declared.value: raise SystemExit('installed RECORD integrity failure')
            declared_value=declared.value
        else:
            text=str(item).replace('\\','/')
            if not (text.endswith('/RECORD') or text.endswith('.pyc')):
                raise SystemExit('unhashed installed file outside RECORD/pyc')
            declared_value=None
        entries.append([str(item).replace('\\','/'), declared_value, item.size])
    entries.sort()
    record=hashlib.sha256((json.dumps(entries,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()
    items.append({'name':name,'version':version,'record_sha256':record,'file_count':len(entries)})
import devhub
origin=pathlib.Path(devhub.__file__).resolve()
print(json.dumps({
  'implementation':platform.python_implementation(),
  'version':platform.python_version(),
  'cache_tag':sys.implementation.cache_tag,
  'soabi':sysconfig.get_config_var('SOABI'),
  'system':platform.system(),
  'machine':platform.machine(),
  'executable':str(pathlib.Path(sys.executable).resolve()),
  'module_origin':str(origin),
  'isolated':sys.flags.isolated==1,
  'ignore_environment':sys.flags.ignore_environment==1,
  'no_user_site':sys.flags.no_user_site==1 and site.ENABLE_USER_SITE is False,
  'editable':editable,
  'distributions':items,
},sort_keys=True))
"""


def _wheel_metadata(wheel: Path) -> tuple[str, str]:
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("Wheel must contain exactly one METADATA file")
        metadata = archive.read(names[0]).decode("utf-8")
    fields: dict[str, str] = {}
    for line in metadata.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields.setdefault(key, value)
    name = normalize_distribution_name(fields.get("Name", ""))
    version = fields.get("Version", "")
    if name != "codex-dev-hub" or not version:
        raise ValueError("Unexpected DevFabric wheel metadata")
    return name, version


def _lock_versions(lock_path: Path) -> dict[str, set[str]]:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    result: dict[str, set[str]] = {}
    for package in lock.get("package", []):
        name = normalize_distribution_name(package.get("name", ""))
        version = package.get("version")
        if name and isinstance(version, str):
            result.setdefault(name, set()).add(version)
    return result


def _inside(path: Path, root: Path) -> str:
    resolved = path.resolve(strict=True)
    base = root.resolve(strict=True)
    if not resolved.is_relative_to(base):
        raise ValueError("Runtime module origin escapes dedicated environment")
    return resolved.relative_to(base).as_posix()


def inspect_runtime_environment(
    interpreter: Path,
    wheel: Path,
    lock_path: Path,
    source_commit: str,
) -> PythonRuntimeEnvironmentV1:
    """Inspect a dedicated environment under isolated Python semantics."""

    if not interpreter.is_file():
        raise ValueError("Runtime interpreter must resolve to a regular file")
    for path, label in ((wheel, "wheel"), (lock_path, "lock")):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Runtime {label} must be a regular non-symlink file")
    environment_root = interpreter.parent.parent
    raw = subprocess.check_output(
        [str(interpreter), "-I", "-c", _INSPECT_SCRIPT],
        env={"PATH": os.defpath, "PYTHONPATH": "untrusted-must-be-ignored"},
        timeout=60,
    )
    observed = json.loads(raw)
    if (
        not all(
            observed.get(key) is True for key in ("isolated", "ignore_environment", "no_user_site")
        )
        or observed.get("editable") is not False
    ):
        raise ValueError("Python runtime is not isolated from ambient installation state")
    if observed.get("implementation") != "CPython" or not str(
        observed.get("version", "")
    ).startswith("3.12."):
        raise ValueError("Reviewed CPython 3.12 runtime required")
    module_origin = _inside(Path(observed["module_origin"]), environment_root)
    executable = Path(observed["executable"])
    # Venv launchers may resolve to a base executable; authority binds the invoked file bytes.
    invoked_sha = file_sha256(interpreter)
    if not executable.is_file():
        raise ValueError("Runtime interpreter resolution is invalid")
    package_name, package_version = _wheel_metadata(wheel)
    lock_versions = _lock_versions(lock_path)
    inventory: list[DistributionIdentityV1] = []
    for item in observed["distributions"]:
        name = normalize_distribution_name(item["name"])
        version = item["version"]
        if name == package_name:
            if version != package_version:
                raise ValueError("Installed DevFabric version differs from reviewed wheel")
        elif version not in lock_versions.get(name, set()):
            raise ValueError("Installed runtime dependency is absent from exact lock")
        inventory.append(
            DistributionIdentityV1(
                name=name,
                version=version,
                record_sha256=item["record_sha256"],
                file_count=item["file_count"],
            )
        )
    inventory.sort(key=lambda item: item.name)
    payload = PythonRuntimeEnvironmentPayloadV1(
        python_implementation="CPython",
        python_version=observed["version"],
        python_executable_sha256=invoked_sha,
        python_cache_tag=observed["cache_tag"],
        python_soabi=observed["soabi"],
        platform_system=observed["system"],
        platform_machine=observed["machine"],
        devhub_source_commit=source_commit,
        devhub_wheel_sha256=file_sha256(wheel),
        dependency_lock_sha256=file_sha256(lock_path),
        devhub_distribution_version=package_version,
        devhub_module_origin=module_origin,
        distributions=tuple(inventory),
    )
    return PythonRuntimeEnvironmentV1.create(payload)


def python_runtime_expected(
    evidence: PythonRuntimeArtifactEvidenceV1,
) -> PythonRuntimeExpectedV1:
    payload = evidence.runtime_environment.payload
    return PythonRuntimeExpectedV1(
        source_commit=evidence.implementation_commit,
        wheel_sha256=evidence.wheel_sha256,
        dependency_lock_sha256=evidence.dependency_lock_sha256,
        python_implementation=payload.python_implementation,
        python_version=payload.python_version,
        python_executable_sha256=payload.python_executable_sha256,
        runtime_environment_id=evidence.runtime_environment.python_runtime_environment_id,
        distribution_version=evidence.package_version,
    )


def verify_runtime_against_expected(
    interpreter: Path,
    wheel: Path,
    lock_path: Path,
    expected: PythonRuntimeExpectedV1,
    header: QualificationReceiptHeaderV1,
) -> PythonRuntimeReceiptV1:
    environment = inspect_runtime_environment(interpreter, wheel, lock_path, expected.source_commit)
    payload = environment.payload
    actual = {
        "wheel_sha256": payload.devhub_wheel_sha256,
        "dependency_lock_sha256": payload.dependency_lock_sha256,
        "python_executable_sha256": payload.python_executable_sha256,
        "runtime_environment_id": environment.python_runtime_environment_id,
        "python_implementation": payload.python_implementation,
        "python_version": payload.python_version,
        "distribution_version": payload.devhub_distribution_version,
        "entrypoint": payload.entrypoint,
        "isolated_argv": payload.isolated_argv,
    }
    wanted = {
        "wheel_sha256": expected.wheel_sha256,
        "dependency_lock_sha256": expected.dependency_lock_sha256,
        "python_executable_sha256": expected.python_executable_sha256,
        "runtime_environment_id": expected.runtime_environment_id,
        "python_implementation": expected.python_implementation,
        "python_version": expected.python_version,
        "distribution_version": expected.distribution_version,
        "entrypoint": expected.entrypoint,
        "isolated_argv": expected.isolated_argv,
    }
    if actual != wanted:
        raise ValueError("Observed Python runtime differs from qualification context")
    return PythonRuntimeReceiptV1(
        receipt_kind=header.receipt_kind,
        qualification_context_id=header.qualification_context_id,
        environment_instance_id=header.environment_instance_id,
        interpreter_path=str(interpreter.resolve(strict=True)),
        wheel_path=str(wheel.resolve(strict=True)),
        lock_path=str(lock_path.resolve(strict=True)),
        interpreter_sha256=payload.python_executable_sha256,
        python_implementation=payload.python_implementation,
        python_version=payload.python_version,
        wheel_sha256=payload.devhub_wheel_sha256,
        dependency_lock_sha256=payload.dependency_lock_sha256,
        module_origin=payload.devhub_module_origin,
        runtime_environment_id=environment.python_runtime_environment_id,
    )


def invoked_python_sha() -> str:
    return file_sha256(Path(sys.executable))


def verified_delegate_command(qualification: VerifiedQualificationV2) -> list[str]:
    """Re-verify the located runtime and return its exact isolated entrypoint argv."""

    raw = qualification.receipts.get("python_runtime")
    if raw is None:
        raise ValueError("Python runtime receipt is missing")
    receipt = PythonRuntimeReceiptV1.model_validate(raw)
    header = QualificationReceiptHeaderV1(
        receipt_kind=receipt.receipt_kind,
        qualification_context_id=receipt.qualification_context_id,
        environment_instance_id=receipt.environment_instance_id,
    )
    current = verify_runtime_against_expected(
        Path(receipt.interpreter_path),
        Path(receipt.wheel_path),
        Path(receipt.lock_path),
        qualification.context.payload.implementation.python_runtime,
        header,
    )
    if current != receipt:
        raise ValueError("Python runtime receipt no longer matches its artifact locators")
    return [receipt.interpreter_path, *receipt.isolated_argv]
