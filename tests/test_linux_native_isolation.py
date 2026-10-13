from __future__ import annotations

import ast
import copy
import errno
import importlib.util
import inspect
import io
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Literal, cast

import pytest
from pydantic import JsonValue, ValidationError

import devhub.linux_ollama_broker as LINUX_BROKER
from devhub.benchmark import canonical, digest
from devhub.ledger import LedgerIdentityCoreV1, ledger_identity_sha256
from devhub.linux_isolation import (
    LINUX_APPARMOR_CURRENT,
    LinuxAppArmorAuthorityV2,
    LinuxAppArmorCleanupPayloadV1,
    LinuxAppArmorCleanupReceiptV1,
    LinuxAppArmorLifecycleFailurePayloadV1,
    LinuxAppArmorLifecycleFailureV1,
    LinuxAppArmorParserAuthorityV2,
    LinuxAppArmorSetupStatePayloadV1,
    LinuxAppArmorSetupStateV1,
    LinuxBrokerExpectationV1,
    LinuxBrokerObservationV1,
    LinuxBundleDirectoryAuthorityV1,
    LinuxChildBootstrapFailurePayloadV1,
    LinuxChildBootstrapFailurePayloadV2,
    LinuxChildBootstrapFailurePayloadV3,
    LinuxChildBootstrapFailureV1,
    LinuxChildBootstrapFailureV2,
    LinuxChildBootstrapFailureV3,
    LinuxChildRegistrationPayloadV2,
    LinuxChildRegistrationPayloadV3,
    LinuxChildRegistrationV2,
    LinuxChildRegistrationV3,
    LinuxChildRuntimeFailurePayloadV1,
    LinuxChildRuntimeFailurePayloadV2,
    LinuxChildRuntimeFailurePayloadV3,
    LinuxChildRuntimeFailureV1,
    LinuxChildRuntimeFailureV2,
    LinuxChildRuntimeFailureV3,
    LinuxDirectoryAuthorityV1,
    LinuxFileAuthorityV1,
    LinuxHostAuthorityV3,
    LinuxHostBrokerFailurePayloadV1,
    LinuxHostBrokerFailureV1,
    LinuxHostCleanupObservationV1,
    LinuxIsolationEvidencePayloadV1,
    LinuxIsolationEvidencePayloadV2,
    LinuxIsolationEvidencePayloadV3,
    LinuxIsolationEvidencePayloadV4,
    LinuxIsolationEvidencePayloadV5,
    LinuxIsolationEvidencePayloadV6,
    LinuxIsolationEvidencePayloadV7,
    LinuxIsolationEvidencePayloadV8,
    LinuxIsolationEvidencePayloadV9,
    LinuxIsolationEvidencePayloadV10,
    LinuxIsolationEvidencePayloadV11,
    LinuxIsolationEvidencePayloadV13,
    LinuxIsolationEvidencePayloadV14,
    LinuxIsolationEvidenceV1,
    LinuxIsolationEvidenceV2,
    LinuxIsolationEvidenceV3,
    LinuxIsolationEvidenceV4,
    LinuxIsolationEvidenceV5,
    LinuxIsolationEvidenceV6,
    LinuxIsolationEvidenceV7,
    LinuxIsolationEvidenceV8,
    LinuxIsolationEvidenceV9,
    LinuxIsolationEvidenceV10,
    LinuxIsolationEvidenceV13,
    LinuxIsolationEvidenceV14,
    LinuxIsolationFailurePayloadV1,
    LinuxIsolationFailurePayloadV2,
    LinuxIsolationFailurePayloadV3,
    LinuxIsolationFailurePayloadV4,
    LinuxIsolationFailurePayloadV5,
    LinuxIsolationFailurePayloadV6,
    LinuxIsolationFailurePayloadV7,
    LinuxIsolationFailurePayloadV8,
    LinuxIsolationFailureV1,
    LinuxIsolationFailureV2,
    LinuxIsolationFailureV3,
    LinuxIsolationFailureV4,
    LinuxIsolationFailureV5,
    LinuxIsolationFailureV6,
    LinuxIsolationFailureV7,
    LinuxIsolationFailureV8,
    LinuxIsolationObservationV1,
    LinuxIsolationObservationV2,
    LinuxIsolationObservationV3,
    LinuxIsolationObservationV4,
    LinuxIsolationObservationV5,
    LinuxIsolationObservationV6,
    LinuxIsolationObservationV7,
    LinuxIsolationObservationV8,
    LinuxIsolationObservationV9,
    LinuxIsolationObservationV10,
    LinuxIsolationObservationV11,
    LinuxIsolationObservationV13,
    LinuxIsolationObservationV14,
    LinuxIsolationProfilePayloadV1,
    LinuxIsolationProfilePayloadV2,
    LinuxIsolationProfilePayloadV3,
    LinuxIsolationProfilePayloadV4,
    LinuxIsolationProfilePayloadV5,
    LinuxIsolationProfilePayloadV6,
    LinuxIsolationProfilePayloadV7,
    LinuxIsolationProfilePayloadV8,
    LinuxIsolationProfilePayloadV9,
    LinuxIsolationProfilePayloadV10,
    LinuxIsolationProfilePayloadV11,
    LinuxIsolationProfilePayloadV12,
    LinuxIsolationProfilePayloadV13,
    LinuxIsolationProfilePayloadV14,
    LinuxIsolationProfileV1,
    LinuxIsolationProfileV2,
    LinuxIsolationProfileV3,
    LinuxIsolationProfileV4,
    LinuxIsolationProfileV5,
    LinuxIsolationProfileV6,
    LinuxIsolationProfileV7,
    LinuxIsolationProfileV8,
    LinuxIsolationProfileV9,
    LinuxIsolationProfileV10,
    LinuxIsolationProfileV11,
    LinuxIsolationProfileV12,
    LinuxIsolationProfileV13,
    LinuxIsolationProfileV14,
    LinuxIsolationQualificationPayloadV3,
    LinuxIsolationQualificationPayloadV4,
    LinuxIsolationQualificationPayloadV5,
    LinuxIsolationQualificationPayloadV6,
    LinuxIsolationQualificationPayloadV7,
    LinuxIsolationQualificationPayloadV8,
    LinuxIsolationQualificationPayloadV9,
    LinuxIsolationQualificationPayloadV10,
    LinuxIsolationQualificationV4,
    LinuxIsolationQualificationV5,
    LinuxIsolationQualificationV6,
    LinuxIsolationQualificationV7,
    LinuxIsolationQualificationV8,
    LinuxIsolationQualificationV9,
    LinuxIsolationQualificationV10,
    LinuxIsolationQualificationV14,
    LinuxIsolationReceiptPayloadV1,
    LinuxIsolationReceiptPayloadV2,
    LinuxIsolationReceiptPayloadV3,
    LinuxIsolationReceiptPayloadV4,
    LinuxIsolationReceiptPayloadV5,
    LinuxIsolationReceiptPayloadV6,
    LinuxIsolationReceiptPayloadV7,
    LinuxIsolationReceiptPayloadV8,
    LinuxIsolationReceiptPayloadV9,
    LinuxIsolationReceiptPayloadV10,
    LinuxIsolationReceiptPayloadV13,
    LinuxIsolationReceiptPayloadV14,
    LinuxIsolationReceiptV1,
    LinuxIsolationReceiptV2,
    LinuxIsolationReceiptV3,
    LinuxIsolationReceiptV4,
    LinuxIsolationReceiptV5,
    LinuxIsolationReceiptV6,
    LinuxIsolationReceiptV7,
    LinuxIsolationReceiptV8,
    LinuxIsolationReceiptV9,
    LinuxIsolationReceiptV10,
    LinuxIsolationReceiptV11,
    LinuxIsolationReceiptV13,
    LinuxIsolationReceiptV14,
    LinuxMountAuthorityObservationV1,
    LinuxMountAuthorityV1,
    LinuxNamespaceObservationV1,
    LinuxNamespaceOwnerProjectionExpectationV1,
    LinuxNamespaceOwnerProjectionObservationV1,
    LinuxNativePathIdentityV1,
    LinuxPackageAuthorityV1,
    LinuxPackageAuthorityV2,
    LinuxPackageAuthorityV3,
    LinuxPackagedMcpMetadataObservationV1,
    LinuxPackagedSubprocessCaptureV1,
    LinuxRlimitsV1,
    LinuxSyntheticUpstreamAuthorityV1,
    LinuxSyntheticUpstreamObservationV1,
    LinuxToolAuthorityV1,
    LinuxToolAuthorityV4,
    LinuxToolVersionEnvironmentV1,
    enforced_landlock_abi,
    landlock_handled_access,
    observed_private_mount_targets,
)
from devhub.linux_ollama_broker import (
    BoundedHTTPRequest,
    LinuxBrokerPeerAuthorityV1,
    LinuxMetadataBrokerFailure,
    LinuxMetadataBrokerV1,
    drain_rejected_request,
    process_start_time_ticks,
    read_metadata_request,
)

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROBE = load_script(
    "linux_native_isolation_probe", ROOT / "scripts/probe_linux_native_isolation.py"
)
APPARMOR_MANAGER = load_script(
    "linux_native_isolation_apparmor_manager",
    ROOT / "scripts/manage_linux_native_isolation_apparmor.py",
)
FINALIZER = load_script(
    "linux_native_isolation_finalizer",
    ROOT / "scripts/finalize_linux_native_isolation.py",
)
CHILD = (
    load_script(
        "linux_native_isolation_child",
        ROOT / "src/devhub/linux_native_isolation_child.py",
    )
    if os.name == "posix"
    else None
)
H = "1" * 64
ENVIRONMENT = "2" * 32
COMMIT = "3" * 40
DirectoryRole = Literal["fixture", "state", "output", "broker", "scratch_root"]
MOUNT_TARGETS = (
    "/bundle",
    "/dev",
    "/home/devfabric",
    "/output",
    "/proc",
    "/run/devfabric",
    "/state",
    "/tmp",
)
RULE_TARGETS = ("/bundle", "/home", "/output", "/proc", "/run/devfabric", "/state", "/tmp")


def native(index: int = 1) -> LinuxNativePathIdentityV1:
    return LinuxNativePathIdentityV1(device=1, inode=index)


def plain_file(
    locator: str = "/usr/bin/python3",
    *,
    index: int = 1,
    mode: str = "0755",
    sha: str = H,
    size: int = 1,
) -> LinuxFileAuthorityV1:
    return LinuxFileAuthorityV1(
        locator=locator,
        sha256=sha,
        size=size,
        owner_uid=0,
        owner_gid=0,
        mode=mode,
        native_identity=native(index),
    )


def tool(
    name: Literal["unshare", "mount"],
    *,
    locator: str | None = None,
    index: int = 1,
) -> LinuxToolAuthorityV1:
    return LinuxToolAuthorityV1(
        **plain_file(locator or f"/usr/bin/{name}", index=index).model_dump(mode="python"),
        name=name,
        version_output_sha256=H,
    )


def full_mode_tool(
    *,
    name: Literal["unshare", "mount"] = "mount",
    locator: str = "/usr/bin/mount",
    index: int = 22,
    permission_bits: str = "0755",
    special_bits: str = "04000",
    full_mode: str = "04755",
) -> LinuxToolAuthorityV4:
    return LinuxToolAuthorityV4(
        name=name,
        locator=locator,
        sha256=H,
        size=1,
        owner_uid=0,
        owner_gid=0,
        permission_bits=permission_bits,
        special_bits=special_bits,
        full_mode=full_mode,
        native_identity=native(index),
        version_output_sha256=H,
    )


def apparmor() -> LinuxAppArmorAuthorityV2:
    parser = plain_file("/usr/sbin/apparmor_parser", index=23)
    snapshot = (LINUX_APPARMOR_CURRENT + "\n").encode()
    return LinuxAppArmorAuthorityV2(
        source_git_blob_sha256=H,
        source_sha256=H,
        installed_profile=plain_file(
            "/etc/apparmor.d/devfabric-linux-isolation-unshare", index=24, mode="0644"
        ),
        parser=LinuxAppArmorParserAuthorityV2(
            **parser.model_dump(mode="python"), version_output_sha256=H
        ),
        loaded_profiles_snapshot=plain_file(
            "/run/devfabric/devfabric-linux-isolation-profiles",
            index=25,
            mode="0444",
            sha=digest(snapshot),
            size=len(snapshot),
        ),
    )


def directory(role: str, index: int) -> LinuxDirectoryAuthorityV1:
    return LinuxDirectoryAuthorityV1(
        locator=f"/tmp/{role}",
        role=cast(DirectoryRole, role),
        owner_uid=1000,
        owner_gid=1000,
        native_identity=native(index),
    )


def mount(
    target: str,
    kind: Literal[
        "bundle_read_only",
        "state_read_write",
        "output_read_write",
        "broker_read_only",
        "tmpfs_home",
        "tmpfs_tmp",
        "proc",
        "dev_tmpfs",
    ],
    *,
    source: bool = False,
    read_only: bool = False,
    nodev: bool = True,
    noexec: bool = True,
    source_hash: str = H,
) -> LinuxMountAuthorityV1:
    return LinuxMountAuthorityV1(
        target=target,
        kind=kind,
        source_identity_sha256=source_hash if source else None,
        read_only=read_only,
        nodev=nodev,
        noexec=noexec,
    )


def broker() -> LinuxBrokerExpectationV1:
    return LinuxBrokerExpectationV1(
        broker_host_pid=123,
        broker_host_start_time_ticks=456,
        broker_host_uid=1000,
        broker_module_sha256=H,
    )


def synthetic_upstream() -> LinuxSyntheticUpstreamAuthorityV1:
    return LinuxSyntheticUpstreamAuthorityV1(
        port=43123,
        socket_inode=789,
        owner_pid=123,
        owner_start_time_ticks=456,
        owner_uid=1000,
    )


def profile_payload() -> LinuxIsolationProfilePayloadV3:
    roles: tuple[
        Literal["broker"],
        Literal["fixture"],
        Literal["output"],
        Literal["scratch_root"],
        Literal["state"],
    ] = ("broker", "fixture", "output", "scratch_root", "state")
    sources = tuple(directory(role, index) for index, role in enumerate(roles, 2))
    source_hashes = {item.role: digest(canonical(item.model_dump(mode="json"))) for item in sources}
    return LinuxIsolationProfilePayloadV3(
        environment_instance_id=ENVIRONMENT,
        implementation_commit=COMMIT,
        native_bundle_id=H,
        bundle_manifest_sha256=H,
        bootstrap_python=plain_file(),
        probe_sha256=H,
        child_probe_sha256=H,
        host=LinuxHostAuthorityV3(
            os_release_sha256=H,
            kernel_release="6.8.0-1018-azure",
            kernel_version_sha256=H,
            apparmor=apparmor(),
            kernel_landlock_abi=7,
            enforced_landlock_abi=6,
            delegated_cgroup_available=False,
        ),
        system_unshare=tool("unshare", index=20),
        unshare=tool("unshare", locator="/opt/devfabric/libexec/unshare", index=21),
        mount=tool("mount", index=22),
        source_directories=sources,
        mounts=(
            mount(
                "/bundle",
                "bundle_read_only",
                source=True,
                read_only=True,
                noexec=False,
                source_hash=source_hashes["fixture"],
            ),
            mount("/dev", "dev_tmpfs", nodev=False),
            mount("/home/devfabric", "tmpfs_home"),
            mount("/output", "output_read_write", source=True, source_hash=source_hashes["output"]),
            mount("/proc", "proc"),
            mount(
                "/run/devfabric",
                "broker_read_only",
                source=True,
                read_only=True,
                source_hash=source_hashes["broker"],
            ),
            mount("/state", "state_read_write", source=True, source_hash=source_hashes["state"]),
            mount("/tmp", "tmpfs_tmp"),
        ),
        broker=broker(),
        landlock_handled_access=landlock_handled_access(6),
    )


def profile_payload_v4() -> LinuxIsolationProfilePayloadV4:
    raw = profile_payload().model_dump(mode="python")
    raw["schema_version"] = 4
    raw["profile_kind"] = "linux_native_isolation_v4"
    raw["mount"] = full_mode_tool().model_dump(mode="python")
    return LinuxIsolationProfilePayloadV4.model_validate(raw)


def profile_payload_v5() -> LinuxIsolationProfilePayloadV5:
    raw = profile_payload_v4().model_dump(mode="python")
    raw["schema_version"] = 5
    raw["profile_kind"] = "linux_native_isolation_v5"
    authority = synthetic_upstream()
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    return LinuxIsolationProfilePayloadV5.model_validate(raw)


def profile_payload_v6() -> LinuxIsolationProfilePayloadV6:
    raw = profile_payload_v5().model_dump(mode="python")
    raw["schema_version"] = 6
    raw["profile_kind"] = "linux_native_isolation_v6"
    raw["child_python_flags"] = ("-I", "-B")
    raw["child_stdlib_only"] = True
    return LinuxIsolationProfilePayloadV6.model_validate(raw)


def profile_payload_v7() -> LinuxIsolationProfilePayloadV7:
    raw = profile_payload_v6().model_dump(mode="python")
    raw["schema_version"] = 7
    raw["profile_kind"] = "linux_native_isolation_v7"
    raw["child_registration_protocol"] = "linux_child_registration_v2"
    raw["mount_owner_projection"] = LinuxNamespaceOwnerProjectionExpectationV1(
        overflow_uid=65534,
        overflow_gid=65534,
    ).model_dump(mode="python")
    return LinuxIsolationProfilePayloadV7.model_validate(raw)


def profile_payload_v8() -> LinuxIsolationProfilePayloadV8:
    raw = profile_payload_v7().model_dump(mode="python")
    raw["schema_version"] = 8
    raw["profile_kind"] = "linux_native_isolation_v8"
    raw["child_registration_protocol"] = "linux_child_registration_v3"
    raw["child_bootstrap_failure_protocol"] = "linux_child_bootstrap_failure_v2"
    raw["mount_authority_protocol"] = "linux_mount_authority_observation_v1"
    raw["mount_version_environment"] = LinuxToolVersionEnvironmentV1().model_dump(mode="python")
    return LinuxIsolationProfilePayloadV8.model_validate(raw)


def profile_payload_v9() -> LinuxIsolationProfilePayloadV9:
    raw = profile_payload_v8().model_dump(mode="python")
    raw["schema_version"] = 9
    raw["profile_kind"] = "linux_native_isolation_v9"
    raw["child_bootstrap_failure_protocol"] = "linux_child_bootstrap_failure_v3"
    return LinuxIsolationProfilePayloadV9.model_validate(raw)


def profile_payload_v10() -> LinuxIsolationProfilePayloadV10:
    raw = profile_payload_v9().model_dump(mode="python")
    raw["schema_version"] = 10
    raw["profile_kind"] = "linux_native_isolation_v10"
    raw["child_runtime_failure_protocol"] = "linux_child_runtime_failure_v1"
    return LinuxIsolationProfilePayloadV10.model_validate(raw)


def profile_payload_v11() -> LinuxIsolationProfilePayloadV11:
    raw = profile_payload_v10().model_dump(mode="python")
    raw["schema_version"] = 11
    raw["profile_kind"] = "linux_native_isolation_v11"
    raw["child_runtime_failure_protocol"] = "linux_child_runtime_failure_v2"
    return LinuxIsolationProfilePayloadV11.model_validate(raw)


def package_authority() -> LinuxPackageAuthorityV2:
    return LinuxPackageAuthorityV2()


def package_authority_v3() -> LinuxPackageAuthorityV3:
    return LinuxPackageAuthorityV3()


def package_probe_hash(path: Path) -> str:
    if path.name == "linux_native_isolation_child.py":
        return package_authority().child_module_sha256
    return H


def package_probe_hash_v3(path: Path) -> str:
    if path.name == "linux_native_isolation_child.py":
        return package_authority_v3().child_module_sha256
    return H


def historical_package_authority_v1() -> LinuxPackageAuthorityV1:
    return LinuxPackageAuthorityV1(
        implementation_commit=COMMIT,
        build_run_id=10,
        build_run_attempt=1,
        bundle_run_id=11,
        bundle_run_attempt=1,
        archive_id=H,
        archive_sha256=H,
        archive_size=1,
        bundle_id=H,
        bundle_manifest_sha256=H,
        build_receipt_sha256=H,
        build_inventory_sha256=H,
        linux_native_codex_build_id=H,
        codex_sha256=H,
        code_mode_host_sha256=H,
        python_runtime_id=H,
        python_executable_sha256=H,
        child_module_sha256=H,
    )


def profile_payload_v13() -> LinuxIsolationProfilePayloadV13:
    raw = profile_payload_v11().model_dump(mode="python")
    package = package_authority()
    raw["schema_version"] = 13
    raw["profile_kind"] = "linux_native_isolation_v13"
    raw["package"] = package.model_dump(mode="python")
    raw["native_bundle_id"] = package.bundle_id
    raw["bundle_manifest_sha256"] = package.bundle_manifest_sha256
    raw["bootstrap_python"]["sha256"] = package.python_executable_sha256
    raw["child_probe_sha256"] = package.child_module_sha256
    fixture = LinuxBundleDirectoryAuthorityV1(
        locator="/tmp/fixture",
        owner_uid=1000,
        owner_gid=1000,
        native_identity=native(3),
    )
    raw["source_directories"] = tuple(
        fixture.model_dump(mode="python") if item["role"] == "fixture" else item
        for item in raw["source_directories"]
    )
    fixture_hash = digest(canonical(fixture.model_dump(mode="json")))
    for item in raw["mounts"]:
        if item["target"] == "/bundle":
            item["source_identity_sha256"] = fixture_hash
    return LinuxIsolationProfilePayloadV13.model_validate(raw)


def profile_payload_v14() -> LinuxIsolationProfilePayloadV14:
    raw = profile_payload_v11().model_dump(mode="python")
    package = package_authority_v3()
    raw["schema_version"] = 14
    raw["profile_kind"] = "linux_native_isolation_v14"
    raw["child_runtime_failure_protocol"] = "linux_child_runtime_failure_v3"
    raw["package"] = package.model_dump(mode="python")
    raw["native_bundle_id"] = package.bundle_id
    raw["bundle_manifest_sha256"] = package.bundle_manifest_sha256
    raw["bootstrap_python"]["sha256"] = package.python_executable_sha256
    raw["child_probe_sha256"] = package.child_module_sha256
    fixture = LinuxBundleDirectoryAuthorityV1(
        locator="/tmp/fixture",
        owner_uid=1000,
        owner_gid=1000,
        native_identity=native(3),
    )
    raw["source_directories"] = tuple(
        fixture.model_dump(mode="python") if item["role"] == "fixture" else item
        for item in raw["source_directories"]
    )
    fixture_hash = digest(canonical(fixture.model_dump(mode="json")))
    for item in raw["mounts"]:
        if item["target"] == "/bundle":
            item["source_identity_sha256"] = fixture_hash
    return LinuxIsolationProfilePayloadV14.model_validate(raw)


def historical_profile_payload_v12() -> LinuxIsolationProfilePayloadV12:
    raw = profile_payload_v11().model_dump(mode="python")
    raw["schema_version"] = 12
    raw["profile_kind"] = "linux_native_isolation_v12"
    raw["package"] = historical_package_authority_v1().model_dump(mode="python")
    fixture = LinuxBundleDirectoryAuthorityV1(
        locator="/tmp/fixture",
        owner_uid=1000,
        owner_gid=1000,
        native_identity=native(3),
    )
    raw["source_directories"] = tuple(
        fixture.model_dump(mode="python") if item["role"] == "fixture" else item
        for item in raw["source_directories"]
    )
    fixture_hash = digest(canonical(fixture.model_dump(mode="json")))
    for item in raw["mounts"]:
        if item["target"] == "/bundle":
            item["source_identity_sha256"] = fixture_hash
    return LinuxIsolationProfilePayloadV12.model_validate(raw)


def profile_v6_for_server(server: socket.socket) -> LinuxIsolationProfileV6:
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v6().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV6.create(LinuxIsolationProfilePayloadV6.model_validate(raw))


def profile_v7_for_server(server: socket.socket) -> LinuxIsolationProfileV7:
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v7().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV7.create(LinuxIsolationProfilePayloadV7.model_validate(raw))


def profile_v8_for_server(server: socket.socket) -> LinuxIsolationProfileV8:
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v8().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV8.create(LinuxIsolationProfilePayloadV8.model_validate(raw))


def profile_v9_for_server(server: socket.socket) -> LinuxIsolationProfileV9:
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v9().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV9.create(LinuxIsolationProfilePayloadV9.model_validate(raw))


def profile_v10_for_server(server: socket.socket) -> LinuxIsolationProfileV10:
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v10().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV10.create(LinuxIsolationProfilePayloadV10.model_validate(raw))


def profile_v11_for_server(server: socket.socket) -> LinuxIsolationProfileV11:
    raw = profile_payload_v11().model_dump(mode="python")
    authority = PROBE.synthetic_upstream_authority(server)
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV11.create(LinuxIsolationProfilePayloadV11.model_validate(raw))


def profile_v13_for_server(server: socket.socket) -> LinuxIsolationProfileV13:
    raw = profile_payload_v13().model_dump(mode="python")
    authority = PROBE.synthetic_upstream_authority(server)
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV13.create(LinuxIsolationProfilePayloadV13.model_validate(raw))


def profile_v14_for_server(server: socket.socket) -> LinuxIsolationProfileV14:
    raw = profile_payload_v14().model_dump(mode="python")
    authority = PROBE.synthetic_upstream_authority(server)
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    return LinuxIsolationProfileV14.create(LinuxIsolationProfilePayloadV14.model_validate(raw))


def registered_child_command(
    registration_write: int,
    result_write: int,
    result: bytes | None,
    returncode: int,
) -> list[str]:
    payload = LinuxChildRegistrationPayloadV3(
        apparmor_current_profile=LINUX_APPARMOR_CURRENT,
        outer_pid=1,
        outer_uid=0,
        start_time_ticks=456,
        mount_owner_projection=owner_projection(),
        mount_authority=LinuxMountAuthorityObservationV1(),
    ).model_dump(mode="json")
    code = (
        "import hashlib,json,os;"
        f"p=json.loads({json.dumps(json.dumps(payload))});"
        "p['outer_pid']=os.getpid();p['outer_uid']=os.getuid();"
        "raw=(json.dumps(p,ensure_ascii=False,sort_keys=True,indent=2)+'\\n').encode();"
        "f={'schema_version':3,'child_registration_id':hashlib.sha256(raw).hexdigest(),"
        "'payload':p};"
        f"os.write({registration_write},json.dumps(f,sort_keys=True,separators=(',',':')).encode()+b'\\n');"
    )
    if result is not None:
        code += f"os.write({result_write},{result!r});"
    code += f"raise SystemExit({returncode})"
    return [str(Path(sys.executable).resolve(strict=True)), "-I", "-B", "-c", code]


def namespace_observation() -> LinuxNamespaceObservationV1:
    return LinuxNamespaceObservationV1(
        host_user_namespace_id="user:[1]",
        child_user_namespace_id="user:[2]",
        host_mount_namespace_id="mnt:[3]",
        child_mount_namespace_id="mnt:[4]",
        host_pid_namespace_id="pid:[5]",
        child_pid_namespace_id="pid:[6]",
        host_network_namespace_id="net:[7]",
        child_network_namespace_id="net:[8]",
        uid_map_sha256=H,
        gid_map_sha256=H,
    )


def observation() -> LinuxIsolationObservationV3:
    return LinuxIsolationObservationV3(
        namespaces=namespace_observation(),
        mount_table_sha256=H,
        observed_mount_targets=MOUNT_TARGETS,
        kernel_landlock_abi=7,
        enforced_landlock_abi=6,
        landlock_handled_access=landlock_handled_access(6),
        landlock_rule_targets=RULE_TARGETS,
        landlock_ruleset_sha256=H,
        rlimits_sha256=digest(canonical(LinuxRlimitsV1().model_dump(mode="json"))),
        broker=LinuxBrokerObservationV1(socket_inode=42),
    )


def observation_v4() -> LinuxIsolationObservationV4:
    raw = observation().model_dump(mode="python")
    raw["schema_version"] = 4
    raw["mount_authority_revalidated"] = True
    return LinuxIsolationObservationV4.model_validate(raw)


def observation_v5() -> LinuxIsolationObservationV5:
    raw = observation_v4().model_dump(mode="python")
    raw["schema_version"] = 5
    raw["synthetic_upstream"] = LinuxSyntheticUpstreamObservationV1(
        authority=synthetic_upstream()
    ).model_dump(mode="python")
    return LinuxIsolationObservationV5.model_validate(raw)


def observation_v6() -> LinuxIsolationObservationV6:
    raw = observation_v5().model_dump(mode="python")
    raw["schema_version"] = 6
    raw["child_bootstrap"] = {
        "isolated_python": True,
        "bytecode_disabled": True,
        "stdlib_only": True,
    }
    return LinuxIsolationObservationV6.model_validate(raw)


def owner_projection() -> LinuxNamespaceOwnerProjectionObservationV1:
    return LinuxNamespaceOwnerProjectionObservationV1(
        overflow_uid=65534,
        overflow_gid=65534,
        observed_owner_uid=65534,
        observed_owner_gid=65534,
    )


def observation_v7() -> LinuxIsolationObservationV7:
    raw = observation_v6().model_dump(mode="python")
    raw["schema_version"] = 7
    raw["mount_owner_projection"] = owner_projection().model_dump(mode="python")
    return LinuxIsolationObservationV7.model_validate(raw)


def observation_v8() -> LinuxIsolationObservationV8:
    raw = observation_v7().model_dump(mode="python")
    raw["schema_version"] = 8
    raw["mount_authority"] = LinuxMountAuthorityObservationV1().model_dump(mode="python")
    return LinuxIsolationObservationV8.model_validate(raw)


def observation_v9() -> LinuxIsolationObservationV9:
    raw = observation_v8().model_dump(mode="python")
    raw["schema_version"] = 9
    return LinuxIsolationObservationV9.model_validate(raw)


def observation_v10() -> LinuxIsolationObservationV10:
    raw = observation_v9().model_dump(mode="python")
    raw["schema_version"] = 10
    return LinuxIsolationObservationV10.model_validate(raw)


def observation_v11() -> LinuxIsolationObservationV11:
    raw = observation_v10().model_dump(mode="python")
    raw["schema_version"] = 11
    return LinuxIsolationObservationV11.model_validate(raw)


def observation_v13() -> LinuxIsolationObservationV13:
    package = package_authority()
    raw = observation_v11().model_dump(mode="python")
    raw["schema_version"] = 13
    raw["child_module_sha256"] = package.child_module_sha256
    raw["packaged_mcp"] = LinuxPackagedMcpMetadataObservationV1(
        python_executable_sha256=package.python_executable_sha256,
        stdout_retained_sha256=H,
        stderr_retained_sha256=H,
        stdout_retained_bytes=1,
        stderr_retained_bytes=0,
    ).model_dump(mode="python")
    return LinuxIsolationObservationV13.model_validate(raw)


def observation_v14() -> LinuxIsolationObservationV14:
    package = package_authority_v3()
    raw = observation_v11().model_dump(mode="python")
    raw["schema_version"] = 14
    raw["child_module_sha256"] = package.child_module_sha256
    raw["packaged_mcp"] = LinuxPackagedMcpMetadataObservationV1(
        python_executable_sha256=package.python_executable_sha256,
        stdout_retained_sha256=H,
        stderr_retained_sha256=H,
        stdout_retained_bytes=1,
        stderr_retained_bytes=0,
    ).model_dump(mode="python")
    return LinuxIsolationObservationV14.model_validate(raw)


def evidence_payload(
    profile: LinuxIsolationProfileV3, receipt: LinuxIsolationReceiptV3
) -> LinuxIsolationEvidencePayloadV3:
    return LinuxIsolationEvidencePayloadV3(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v4(
    profile: LinuxIsolationProfileV4, receipt: LinuxIsolationReceiptV4
) -> LinuxIsolationEvidencePayloadV4:
    return LinuxIsolationEvidencePayloadV4(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v5(
    profile: LinuxIsolationProfileV5, receipt: LinuxIsolationReceiptV5
) -> LinuxIsolationEvidencePayloadV5:
    return LinuxIsolationEvidencePayloadV5(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v6(
    profile: LinuxIsolationProfileV6, receipt: LinuxIsolationReceiptV6
) -> LinuxIsolationEvidencePayloadV6:
    return LinuxIsolationEvidencePayloadV6(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v7(
    profile: LinuxIsolationProfileV7, receipt: LinuxIsolationReceiptV7
) -> LinuxIsolationEvidencePayloadV7:
    return LinuxIsolationEvidencePayloadV7(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v8(
    profile: LinuxIsolationProfileV8, receipt: LinuxIsolationReceiptV8
) -> LinuxIsolationEvidencePayloadV8:
    return LinuxIsolationEvidencePayloadV8(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v9(
    profile: LinuxIsolationProfileV9, receipt: LinuxIsolationReceiptV9
) -> LinuxIsolationEvidencePayloadV9:
    return LinuxIsolationEvidencePayloadV9(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v10(
    profile: LinuxIsolationProfileV10, receipt: LinuxIsolationReceiptV10
) -> LinuxIsolationEvidencePayloadV10:
    return LinuxIsolationEvidencePayloadV10(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v11(
    profile: LinuxIsolationProfileV11, receipt: LinuxIsolationReceiptV11
) -> LinuxIsolationEvidencePayloadV11:
    return LinuxIsolationEvidencePayloadV11(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v13(
    profile: LinuxIsolationProfileV13, receipt: LinuxIsolationReceiptV13
) -> LinuxIsolationEvidencePayloadV13:
    return LinuxIsolationEvidencePayloadV13(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def evidence_payload_v14(
    profile: LinuxIsolationProfileV14, receipt: LinuxIsolationReceiptV14
) -> LinuxIsolationEvidencePayloadV14:
    return LinuxIsolationEvidencePayloadV14(
        profile=profile,
        receipt=receipt,
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup=LinuxHostCleanupObservationV1(),
    )


def historical_v2_profile_payload() -> LinuxIsolationProfilePayloadV2:
    raw = profile_payload().model_dump(mode="python")
    raw["schema_version"] = 2
    raw["profile_kind"] = "linux_native_isolation_v2"
    host = raw["host"]
    host["schema_version"] = 1
    host["landlock_abi"] = host.pop("enforced_landlock_abi")
    host.pop("kernel_landlock_abi")
    return LinuxIsolationProfilePayloadV2.model_validate(raw)


def historical_v2_observation() -> LinuxIsolationObservationV2:
    raw = observation().model_dump(mode="python")
    raw["schema_version"] = 2
    raw["landlock_abi"] = raw.pop("enforced_landlock_abi")
    raw.pop("kernel_landlock_abi")
    return LinuxIsolationObservationV2.model_validate(raw)


def test_linux_profile_receipt_and_composite_are_self_hashed_and_non_ready() -> None:
    profile = LinuxIsolationProfileV3.create(profile_payload())
    receipt = LinuxIsolationReceiptV3.create(
        LinuxIsolationReceiptPayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation(),
        )
    )
    evidence = LinuxIsolationEvidenceV3.create(evidence_payload(profile, receipt))
    assert profile.model_validate_json(profile.model_dump_json()) == profile
    assert receipt.model_validate_json(receipt.model_dump_json()) == receipt
    assert evidence.model_validate_json(evidence.model_dump_json()) == evidence
    assert receipt.payload.metadata_isolation_baseline_qualified is True
    assert receipt.payload.native_executor_isolation_qualified is False
    assert receipt.payload.package_readiness is False
    assert (
        receipt.payload.model_requests,
        receipt.payload.provider_sends,
        receipt.payload.mcp_tool_executions,
        receipt.payload.real_task_executions,
    ) == (0, 0, 0, 0)


def test_v4_mount_mode_profile_receipt_evidence_and_qualification_are_closed() -> None:
    profile = LinuxIsolationProfileV4.create(profile_payload_v4())
    receipt = LinuxIsolationReceiptV4.create(
        LinuxIsolationReceiptPayloadV4(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v4(),
        )
    )
    evidence = LinuxIsolationEvidenceV4.create(evidence_payload_v4(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    qualification = LinuxIsolationQualificationV4.create(
        LinuxIsolationQualificationPayloadV4(
            mechanics=evidence,
            apparmor_cleanup=cleanup,
        )
    )
    assert profile.model_validate_json(profile.model_dump_json()) == profile
    assert receipt.model_validate_json(receipt.model_dump_json()) == receipt
    assert evidence.model_validate_json(evidence.model_dump_json()) == evidence
    assert qualification.model_validate_json(qualification.model_dump_json()) == qualification
    assert profile.payload.mount.full_mode == "04755"
    assert profile.payload.mount.special_bits == "04000"
    assert receipt.payload.observation.mount_authority_revalidated is True
    assert qualification.payload.package_readiness is False


def test_v5_synthetic_upstream_profile_receipt_evidence_and_qualification_are_closed() -> None:
    profile = LinuxIsolationProfileV5.create(profile_payload_v5())
    receipt = LinuxIsolationReceiptV5.create(
        LinuxIsolationReceiptPayloadV5(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v5(),
        )
    )
    evidence = LinuxIsolationEvidenceV5.create(evidence_payload_v5(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    qualification = LinuxIsolationQualificationV5.create(
        LinuxIsolationQualificationPayloadV5(
            mechanics=evidence,
            apparmor_cleanup=cleanup,
        )
    )
    assert profile.model_validate_json(profile.model_dump_json()) == profile
    assert receipt.model_validate_json(receipt.model_dump_json()) == receipt
    assert evidence.model_validate_json(evidence.model_dump_json()) == evidence
    assert qualification.model_validate_json(qualification.model_dump_json()) == qualification
    assert (
        receipt.payload.model_requests,
        receipt.payload.provider_sends,
        receipt.payload.mcp_tool_executions,
        receipt.payload.real_task_executions,
    ) == (0, 0, 0, 0)
    assert receipt.payload.package_readiness is False


def test_v6_stdlib_child_profile_receipt_evidence_and_qualification_are_closed() -> None:
    profile = LinuxIsolationProfileV6.create(profile_payload_v6())
    receipt = LinuxIsolationReceiptV6.create(
        LinuxIsolationReceiptPayloadV6(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v6(),
        )
    )
    evidence = LinuxIsolationEvidenceV6.create(evidence_payload_v6(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    qualification = LinuxIsolationQualificationV6.create(
        LinuxIsolationQualificationPayloadV6(
            mechanics=evidence,
            apparmor_cleanup=cleanup,
        )
    )
    assert profile.model_validate_json(profile.model_dump_json()) == profile
    assert receipt.model_validate_json(receipt.model_dump_json()) == receipt
    assert evidence.model_validate_json(evidence.model_dump_json()) == evidence
    assert qualification.model_validate_json(qualification.model_dump_json()) == qualification
    assert profile.payload.child_python_flags == ("-I", "-B")
    assert receipt.payload.observation.child_bootstrap.stdlib_only is True
    assert (
        receipt.payload.model_requests,
        receipt.payload.provider_sends,
        receipt.payload.mcp_tool_executions,
        receipt.payload.real_task_executions,
    ) == (0, 0, 0, 0)
    assert receipt.payload.package_readiness is False


def test_v7_owner_projection_profile_receipt_evidence_and_qualification_are_closed() -> None:
    profile = LinuxIsolationProfileV7.create(profile_payload_v7())
    receipt = LinuxIsolationReceiptV7.create(
        LinuxIsolationReceiptPayloadV7(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v7(),
        )
    )
    evidence = LinuxIsolationEvidenceV7.create(evidence_payload_v7(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    qualification = LinuxIsolationQualificationV7.create(
        LinuxIsolationQualificationPayloadV7(
            mechanics=evidence,
            apparmor_cleanup=cleanup,
        )
    )
    assert LinuxIsolationProfileV7.model_validate_json(profile.model_dump_json()) == profile
    assert LinuxIsolationReceiptV7.model_validate_json(receipt.model_dump_json()) == receipt
    assert LinuxIsolationEvidenceV7.model_validate_json(evidence.model_dump_json()) == evidence
    assert (
        LinuxIsolationQualificationV7.model_validate_json(qualification.model_dump_json())
        == qualification
    )
    assert profile.payload.mount_owner_projection.host_owner_uid == 0
    assert receipt.payload.observation.mount_owner_projection.host_root_uid_mapped is False
    assert qualification.payload.package_readiness is False


def test_v7_rejects_owner_projection_substitution() -> None:
    profile = LinuxIsolationProfileV7.create(profile_payload_v7())
    raw = observation_v7().model_dump(mode="python")
    raw["mount_owner_projection"]["overflow_uid"] = 65533
    raw["mount_owner_projection"]["observed_owner_uid"] = 65533
    receipt = LinuxIsolationReceiptV7.create(
        LinuxIsolationReceiptPayloadV7(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=LinuxIsolationObservationV7.model_validate(raw),
        )
    )
    with pytest.raises(ValidationError, match="owner projection authority differs"):
        evidence_payload_v7(profile, receipt)


def test_v8_mount_authority_profile_receipt_evidence_and_qualification_are_closed() -> None:
    profile = LinuxIsolationProfileV8.create(profile_payload_v8())
    receipt = LinuxIsolationReceiptV8.create(
        LinuxIsolationReceiptPayloadV8(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v8(),
        )
    )
    evidence = LinuxIsolationEvidenceV8.create(evidence_payload_v8(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    qualification = LinuxIsolationQualificationV8.create(
        LinuxIsolationQualificationPayloadV8(
            mechanics=evidence,
            apparmor_cleanup=cleanup,
        )
    )
    assert LinuxIsolationProfileV8.model_validate_json(profile.model_dump_json()) == profile
    assert LinuxIsolationReceiptV8.model_validate_json(receipt.model_dump_json()) == receipt
    assert LinuxIsolationEvidenceV8.model_validate_json(evidence.model_dump_json()) == evidence
    assert (
        LinuxIsolationQualificationV8.model_validate_json(qualification.model_dump_json())
        == qualification
    )
    assert receipt.payload.observation.mount_authority.post_exec_authority_matched is True
    assert qualification.payload.package_readiness is False


def test_v9_diagnostic_profile_receipt_evidence_and_qualification_are_closed() -> None:
    profile = LinuxIsolationProfileV9.create(profile_payload_v9())
    receipt = LinuxIsolationReceiptV9.create(
        LinuxIsolationReceiptPayloadV9(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v9(),
        )
    )
    evidence = LinuxIsolationEvidenceV9.create(evidence_payload_v9(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    qualification = LinuxIsolationQualificationV9.create(
        LinuxIsolationQualificationPayloadV9(
            mechanics=evidence,
            apparmor_cleanup=cleanup,
        )
    )
    assert LinuxIsolationProfileV9.model_validate_json(profile.model_dump_json()) == profile
    assert LinuxIsolationReceiptV9.model_validate_json(receipt.model_dump_json()) == receipt
    assert LinuxIsolationEvidenceV9.model_validate_json(evidence.model_dump_json()) == evidence
    assert (
        LinuxIsolationQualificationV9.model_validate_json(qualification.model_dump_json())
        == qualification
    )
    assert qualification.payload.package_readiness is False


def test_v10_runtime_failure_profile_receipt_evidence_and_qualification_are_closed() -> None:
    profile = LinuxIsolationProfileV10.create(profile_payload_v10())
    receipt = LinuxIsolationReceiptV10.create(
        LinuxIsolationReceiptPayloadV10(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v10(),
        )
    )
    evidence = LinuxIsolationEvidenceV10.create(evidence_payload_v10(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    qualification = LinuxIsolationQualificationV10.create(
        LinuxIsolationQualificationPayloadV10(
            mechanics=evidence,
            apparmor_cleanup=cleanup,
        )
    )
    assert LinuxIsolationProfileV10.model_validate_json(profile.model_dump_json()) == profile
    assert LinuxIsolationReceiptV10.model_validate_json(receipt.model_dump_json()) == receipt
    assert LinuxIsolationEvidenceV10.model_validate_json(evidence.model_dump_json()) == evidence
    assert (
        LinuxIsolationQualificationV10.model_validate_json(qualification.model_dump_json())
        == qualification
    )
    assert qualification.payload.package_readiness is False


@pytest.mark.parametrize(
    ("stage", "reason", "outer_phase", "outer_reason"),
    [
        ("private_root", "private_root_failed", "private_root", "private_root_failed"),
        ("rlimits", "rlimits_failed", "child_result", "child_output_invalid"),
        (
            "capability_drop",
            "capability_drop_failed",
            "capability_drop",
            "capability_drop_failed",
        ),
        ("landlock", "landlock_failed", "landlock", "landlock_failed"),
        (
            "negative_probes",
            "negative_probes_failed",
            "negative_probes",
            "negative_probe_failed",
        ),
        ("broker", "broker_failed", "broker", "broker_failed"),
        ("result_assembly", "result_assembly_failed", "child_result", "child_output_invalid"),
    ],
)
def test_v10_runtime_failure_stages_are_self_hashed_and_retained(
    stage: str, reason: str, outer_phase: str, outer_reason: str
) -> None:
    frame = LinuxChildRuntimeFailureV1.create(
        LinuxChildRuntimeFailurePayloadV1(stage=stage, reason_code=reason)
    )
    failure = LinuxIsolationFailureV6.create(
        LinuxIsolationFailurePayloadV6(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            phase=outer_phase,
            reason_code=outer_reason,
            child_stdout_retained_sha256=digest(b""),
            child_stderr_retained_sha256=digest(b""),
            child_stdout_truncated=False,
            child_stderr_truncated=False,
            child_process_started=True,
            child_returncode=71,
            child_stdout_retained_bytes=0,
            child_stderr_retained_bytes=0,
            child_stdout_observed_bytes=0,
            child_stderr_observed_bytes=0,
            child_runtime_failure=frame,
            cleanup_attempted=True,
            cleanup_succeeded=True,
        )
    )
    assert failure.payload.child_runtime_failure == frame
    assert LinuxIsolationFailureV6.model_validate_json(failure.model_dump_json()) == failure


def test_v10_cleanup_failure_retains_prior_typed_child_failure() -> None:
    runtime = LinuxChildRuntimeFailureV1.create(
        LinuxChildRuntimeFailurePayloadV1(stage="landlock", reason_code="landlock_failed")
    )
    failure = LinuxIsolationFailurePayloadV6(
        linux_isolation_profile_id=H,
        environment_instance_id=ENVIRONMENT,
        phase="cleanup",
        reason_code="cleanup_failed",
        child_stdout_retained_sha256=digest(b""),
        child_stderr_retained_sha256=digest(b""),
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        child_process_started=True,
        child_returncode=71,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_observed_bytes=0,
        child_stderr_observed_bytes=0,
        child_runtime_failure=runtime,
        cleanup_attempted=True,
        cleanup_succeeded=False,
    )
    assert failure.child_runtime_failure == runtime

    bootstrap = LinuxChildBootstrapFailureV3.create(
        LinuxChildBootstrapFailurePayloadV3(
            stage="mount_authority",
            reason_code="namespace_owner_projection_mismatch",
        )
    )
    bootstrap_failure = failure.model_dump(mode="python")
    bootstrap_failure["child_runtime_failure"] = None
    bootstrap_failure["child_bootstrap_failure"] = bootstrap.model_dump(mode="python")
    bootstrap_failure["child_returncode"] = 70
    assert (
        LinuxIsolationFailurePayloadV6.model_validate(bootstrap_failure).child_bootstrap_failure
        == bootstrap
    )


def test_v10_child_failure_requires_exact_exit_code() -> None:
    runtime = LinuxChildRuntimeFailureV1.create(
        LinuxChildRuntimeFailurePayloadV1(stage="landlock", reason_code="landlock_failed")
    )
    raw = LinuxIsolationFailurePayloadV6(
        linux_isolation_profile_id=H,
        environment_instance_id=ENVIRONMENT,
        phase="landlock",
        reason_code="landlock_failed",
        child_stdout_retained_sha256=digest(b""),
        child_stderr_retained_sha256=digest(b""),
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        child_process_started=True,
        child_returncode=71,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=0,
        child_stdout_observed_bytes=0,
        child_stderr_observed_bytes=0,
        child_runtime_failure=runtime,
        cleanup_attempted=True,
        cleanup_succeeded=True,
    ).model_dump(mode="python")
    raw["child_returncode"] = 1
    with pytest.raises(ValidationError, match="unexpected return code"):
        LinuxIsolationFailurePayloadV6.model_validate(raw)


def test_v10_runtime_failure_rejects_tampering_rehashing_and_extra_fields() -> None:
    frame = LinuxChildRuntimeFailureV1.create(
        LinuxChildRuntimeFailurePayloadV1(stage="private_root", reason_code="private_root_failed")
    )
    tampered = frame.model_dump(mode="python")
    tampered["payload"]["stage"] = "landlock"
    tampered["payload"]["reason_code"] = "landlock_failed"
    with pytest.raises(ValidationError, match="hash mismatch"):
        LinuxChildRuntimeFailureV1.model_validate(tampered)

    rehashed = frame.model_dump(mode="python")
    rehashed["payload"]["stage"] = "landlock"
    rehashed["child_runtime_failure_id"] = digest(canonical(rehashed["payload"]))
    with pytest.raises(ValidationError, match="stage and reason differ"):
        LinuxChildRuntimeFailureV1.model_validate(rehashed)

    extra = frame.model_dump(mode="python")
    extra["payload"]["message"] = "raw detail"
    extra["child_runtime_failure_id"] = digest(canonical(extra["payload"]))
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxChildRuntimeFailureV1.model_validate(extra)


def test_v11_binds_self_hashed_bounded_broker_failure_contracts() -> None:
    profile = LinuxIsolationProfileV11.create(profile_payload_v11())
    assert profile.payload.child_runtime_failure_protocol == "linux_child_runtime_failure_v2"
    child = LinuxChildRuntimeFailureV2.create(
        LinuxChildRuntimeFailurePayloadV2(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            stage="broker",
            reason_code="broker_connect_failed",
            broker_checkpoint="version",
            broker_operation="connect",
            errno_category="connection_refused",
        )
    )
    host = LinuxHostBrokerFailureV1.create(
        LinuxHostBrokerFailurePayloadV1(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            checkpoint="upstream_connect",
            reason_code="upstream_connect_failed",
            failure_kind="os_error",
            errno_category="connection_refused",
            completed_outcomes=("/api/version", "/api/tags", "/api/show", "denied"),
        )
    )
    assert LinuxChildRuntimeFailureV2.model_validate_json(child.model_dump_json()) == child
    assert LinuxHostBrokerFailureV1.model_validate_json(host.model_dump_json()) == host

    tampered_child = child.model_dump(mode="python")
    tampered_child["payload"]["broker_checkpoint"] = "tags"
    with pytest.raises(ValidationError, match="hash mismatch"):
        LinuxChildRuntimeFailureV2.model_validate(tampered_child)
    tampered_host = host.model_dump(mode="python")
    tampered_host["payload"]["checkpoint"] = "upstream_read"
    tampered_host["payload"]["reason_code"] = "upstream_read_failed"
    with pytest.raises(ValidationError, match="hash mismatch"):
        LinuxHostBrokerFailureV1.model_validate(tampered_host)


def test_child_runtime_failure_v3_binds_bounded_packaged_mcp_checkpoint() -> None:
    capture = {
        "schema_version": 1,
        "process_started": True,
        "returncode": 71,
        "stdout_retained_bytes": 3,
        "stdout_observed_bytes": 5,
        "stdout_retained_sha256": digest(b"abc"),
        "stdout_truncated": True,
        "stderr_retained_bytes": 0,
        "stderr_observed_bytes": 0,
        "stderr_retained_sha256": digest(b""),
        "stderr_truncated": False,
        "timed_out": False,
        "output_limit_exceeded": True,
    }
    failure = LinuxChildRuntimeFailureV3.create(
        LinuxChildRuntimeFailurePayloadV3(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            stage="result_assembly",
            reason_code="result_assembly_failed",
            packaged_mcp_checkpoint="mcp_exchange",
            packaged_subprocess=capture,
        )
    )
    assert LinuxChildRuntimeFailureV3.model_validate_json(failure.model_dump_json()) == failure
    raw = failure.model_dump(mode="python")
    raw["payload"]["environment_instance_id"] = "5" * 32
    with pytest.raises(ValidationError, match="hash mismatch"):
        LinuxChildRuntimeFailureV3.model_validate(raw)

    raw = failure.model_dump(mode="python")
    raw["payload"]["packaged_subprocess"]["stdout_observed_bytes"] = 2
    raw["child_runtime_failure_id"] = digest(canonical(raw["payload"]))
    with pytest.raises(ValidationError, match="stream bounds differ"):
        LinuxChildRuntimeFailureV3.model_validate(raw)

    raw = failure.model_dump(mode="python")
    raw["payload"]["packaged_subprocess"]["output_limit_exceeded"] = False
    raw["child_runtime_failure_id"] = digest(canonical(raw["payload"]))
    with pytest.raises(ValidationError, match="output-limit state differs"):
        LinuxChildRuntimeFailureV3.model_validate(raw)

    raw = failure.model_dump(mode="python")
    raw["payload"]["packaged_subprocess"]["stdout_observed_bytes"] = (1024 + 64) * 1024 + 1
    raw["child_runtime_failure_id"] = digest(canonical(raw["payload"]))
    with pytest.raises(ValidationError):
        LinuxChildRuntimeFailureV3.model_validate(raw)

    raw = failure.model_dump(mode="python")
    raw["payload"]["raw_stdout"] = "secret"
    raw["child_runtime_failure_id"] = digest(canonical(raw["payload"]))
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxChildRuntimeFailureV3.model_validate(raw)


@pytest.mark.parametrize(
    ("checkpoint", "capture_required"),
    [
        ("python_authority", False),
        ("state_config_preparation", False),
        ("module_origin", True),
        ("ledger_initialization", True),
        ("mcp_exchange", True),
        ("capture_publication", True),
        ("response_parsing", True),
        ("initialize_shape", True),
        ("tools_shape", True),
        ("observation_assembly", False),
        ("result_frame_publication", False),
    ],
)
def test_child_runtime_failure_v3_fixed_checkpoint_shape(
    checkpoint: str, capture_required: bool
) -> None:
    capture = {
        "schema_version": 1,
        "process_started": True,
        "returncode": 0,
        "stdout_retained_bytes": 0,
        "stdout_observed_bytes": 0,
        "stdout_retained_sha256": digest(b""),
        "stdout_truncated": False,
        "stderr_retained_bytes": 0,
        "stderr_observed_bytes": 0,
        "stderr_retained_sha256": digest(b""),
        "stderr_truncated": False,
        "timed_out": False,
        "output_limit_exceeded": False,
    }
    payload = {
        "linux_isolation_profile_id": H,
        "environment_instance_id": ENVIRONMENT,
        "stage": "result_assembly",
        "reason_code": "result_assembly_failed",
        "packaged_mcp_checkpoint": checkpoint,
        "packaged_subprocess": capture if capture_required else None,
    }
    parsed = LinuxChildRuntimeFailurePayloadV3.model_validate(payload)
    assert parsed.packaged_mcp_checkpoint == checkpoint
    if capture_required:
        payload["packaged_subprocess"] = None
        with pytest.raises(ValidationError, match="subprocess evidence differs"):
            LinuxChildRuntimeFailurePayloadV3.model_validate(payload)
    else:
        payload["packaged_subprocess"] = capture
        with pytest.raises(ValidationError, match="subprocess evidence differs"):
            LinuxChildRuntimeFailurePayloadV3.model_validate(payload)


def test_child_runtime_failure_v3_rejects_false_unstarted_process_evidence() -> None:
    capture = {
        "schema_version": 1,
        "process_started": False,
        "returncode": 1,
        "stdout_retained_bytes": 0,
        "stdout_observed_bytes": 0,
        "stdout_retained_sha256": digest(b""),
        "stdout_truncated": False,
        "stderr_retained_bytes": 0,
        "stderr_observed_bytes": 0,
        "stderr_retained_sha256": digest(b""),
        "stderr_truncated": False,
        "timed_out": False,
        "output_limit_exceeded": False,
    }
    with pytest.raises(ValidationError, match="Unstarted packaged subprocess"):
        LinuxChildRuntimeFailurePayloadV3(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            stage="result_assembly",
            reason_code="result_assembly_failed",
            packaged_mcp_checkpoint="mcp_exchange",
            packaged_subprocess=capture,
        )


@pytest.mark.parametrize(
    "checkpoint",
    [
        "construction",
        "thread_creation",
        "thread_start",
        "worker",
        "parent_validation",
        "bind",
        "chmod",
        "listen",
        "accept",
        "peer_credentials",
        "peer_start_time",
        "request_parse",
        "denial_response",
        "upstream_connect",
        "upstream_send",
        "upstream_read",
        "client_forwarding",
        "cleanup",
    ],
)
def test_v11_host_broker_failure_has_fixed_checkpoint_vocabulary(checkpoint: str) -> None:
    frame = LinuxHostBrokerFailureV1.create(
        LinuxHostBrokerFailurePayloadV1(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            checkpoint=checkpoint,
            reason_code=f"{checkpoint}_failed",
            failure_kind="internal_error",
        )
    )
    assert frame.payload.checkpoint == checkpoint


def test_v11_host_broker_failure_rejects_noncanonical_outcome_history() -> None:
    with pytest.raises(ValidationError, match="canonical prefix"):
        LinuxHostBrokerFailurePayloadV1(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            checkpoint="upstream_read",
            reason_code="upstream_read_failed",
            failure_kind="internal_error",
            completed_outcomes=("/api/version", "/api/show"),
        )


@pytest.mark.parametrize(
    ("reason", "operation", "errno_category"),
    [
        ("broker_connect_failed", "receive", "connection_refused"),
        ("broker_connect_failed", "connect", None),
        ("broker_socket_mode_invalid", "socket_mode", "permission_denied"),
        ("broker_peer_credentials_failed", "peer_pid", "permission_denied"),
        ("broker_socket_stat_failed", "socket_type", "permission_denied"),
    ],
)
def test_v11_child_broker_failure_rejects_impossible_diagnostic_tuple(
    reason: str, operation: str, errno_category: str | None
) -> None:
    with pytest.raises(ValidationError):
        LinuxChildRuntimeFailurePayloadV2(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            stage="broker",
            reason_code=reason,
            broker_checkpoint="version",
            broker_operation=operation,
            errno_category=errno_category,
        )


def test_v11_host_writer_and_reader_bind_exact_profile_environment() -> None:
    profile = LinuxIsolationProfileV11.create(profile_payload_v11())
    failure = LinuxMetadataBrokerFailure(
        "bind", (), OSError(errno.EADDRINUSE, "address already in use")
    )
    frame = PROBE.host_broker_failure_frame(profile, failure)
    parsed = LinuxHostBrokerFailureV1.model_validate_json(frame.model_dump_json())
    assert parsed.payload.linux_isolation_profile_id == profile.linux_isolation_profile_id
    assert parsed.payload.environment_instance_id == profile.payload.environment_instance_id
    assert (
        parsed.payload.checkpoint,
        parsed.payload.reason_code,
        parsed.payload.failure_kind,
        parsed.payload.errno_category,
    ) == ("bind", "bind_failed", "os_error", "address_in_use")


def test_v11_failure_retains_consistent_child_and_host_broker_diagnostics() -> None:
    child = LinuxChildRuntimeFailureV2.create(
        LinuxChildRuntimeFailurePayloadV2(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            stage="broker",
            reason_code="broker_receive_failed",
            broker_checkpoint="tags",
            broker_operation="receive",
            errno_category="connection_reset",
        )
    )
    host = LinuxHostBrokerFailureV1.create(
        LinuxHostBrokerFailurePayloadV1(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            checkpoint="upstream_read",
            reason_code="upstream_read_failed",
            failure_kind="os_error",
            errno_category="connection_reset",
            completed_outcomes=("/api/version",),
        )
    )
    failure = LinuxIsolationFailureV7.create(
        LinuxIsolationFailurePayloadV7(
            linux_isolation_profile_id=H,
            environment_instance_id=ENVIRONMENT,
            phase="broker",
            reason_code="broker_failed",
            child_stdout_retained_sha256=digest(b""),
            child_stderr_retained_sha256=digest(b""),
            child_stdout_truncated=False,
            child_stderr_truncated=False,
            cleanup_attempted=True,
            cleanup_succeeded=True,
            child_process_started=True,
            child_returncode=71,
            child_stdout_retained_bytes=0,
            child_stderr_retained_bytes=0,
            child_stdout_observed_bytes=0,
            child_stderr_observed_bytes=0,
            child_runtime_failure=child,
            host_broker_failure=host,
        )
    )
    assert failure.payload.child_runtime_failure == child
    assert failure.payload.host_broker_failure == host
    raw = failure.payload.model_dump(mode="python")
    raw["child_runtime_failure"]["payload"]["stage"] = "landlock"
    raw["child_runtime_failure"]["payload"]["reason_code"] = "landlock_failed"
    raw["child_runtime_failure"]["payload"]["broker_checkpoint"] = None
    raw["child_runtime_failure"]["payload"]["broker_operation"] = None
    raw["child_runtime_failure"]["payload"]["errno_category"] = None
    raw["child_runtime_failure"]["child_runtime_failure_id"] = digest(
        canonical(raw["child_runtime_failure"]["payload"])
    )
    raw["phase"] = "cleanup"
    raw["reason_code"] = "cleanup_failed"
    raw["cleanup_succeeded"] = False
    with pytest.raises(ValidationError, match="inconsistent"):
        LinuxIsolationFailurePayloadV7.model_validate(raw)

    transplanted = failure.payload.model_dump(mode="python")
    transplanted["linux_isolation_profile_id"] = "4" * 64
    with pytest.raises(ValidationError, match="authority differs"):
        LinuxIsolationFailurePayloadV7.model_validate(transplanted)

    transplanted_environment = failure.payload.model_dump(mode="python")
    transplanted_environment["environment_instance_id"] = "5" * 32
    with pytest.raises(ValidationError, match="authority differs"):
        LinuxIsolationFailurePayloadV7.model_validate(transplanted_environment)

    missing = failure.payload.model_dump(mode="python")
    missing["child_runtime_failure"] = None
    missing["host_broker_failure"] = None
    with pytest.raises(ValidationError, match="lacks typed diagnostics"):
        LinuxIsolationFailurePayloadV7.model_validate(missing)


def test_v10_broker_cancellation_is_secondary_only_after_child_exit() -> None:
    cancelled = TimeoutError("Linux metadata broker was cancelled")
    assert PROBE.expected_broker_cancellation([cancelled], child_exited=True) is True
    assert PROBE.expected_broker_cancellation([cancelled], child_exited=False) is False
    assert (
        PROBE.expected_broker_cancellation(
            [TimeoutError("Linux metadata broker deadline expired")], child_exited=True
        )
        is False
    )
    assert (
        PROBE.expected_broker_cancellation([ValueError("broker failed")], child_exited=True)
        is False
    )


@pytest.mark.skipif(os.name != "posix", reason="Child runtime framing is Linux-only")
def test_child_runtime_failure_writer_uses_the_reviewed_v11_contract() -> None:
    assert CHILD is not None
    for stage in (
        "private_root",
        "rlimits",
        "capability_drop",
        "landlock",
        "negative_probes",
        "broker",
        "result_assembly",
    ):
        frame = CHILD.runtime_failure_frame(stage, H, ENVIRONMENT)
        if stage == "result_assembly":
            failure = CHILD.PackagedMcpObservationFailure("observation_assembly")
            frame = CHILD.runtime_failure_frame(stage, H, ENVIRONMENT, None, failure)
        assert LinuxChildRuntimeFailureV3.model_validate(frame).payload.stage == stage


@pytest.mark.skipif(os.name != "posix", reason="Child runtime framing is Linux-only")
@pytest.mark.parametrize(
    "capture",
    [
        pytest.param(
            lambda child: child.completed_subprocess_capture(0, b"ok", b""),
            id="completed",
        ),
        pytest.param(
            lambda child: child.unstarted_subprocess_capture(),
            id="unstarted",
        ),
        pytest.param(
            lambda child: child.packaged_subprocess_capture(
                True,
                None,
                {"stdout": b"partial", "stderr": b""},
                {"stdout": 7, "stderr": 0},
                timed_out=True,
                output_limit_exceeded=False,
            ),
            id="timeout",
        ),
        pytest.param(
            lambda child: child.packaged_subprocess_capture(
                True,
                -9,
                {"stdout": b"kept", "stderr": b""},
                {"stdout": 5, "stderr": 0},
                timed_out=False,
                output_limit_exceeded=True,
            ),
            id="overflow",
        ),
        pytest.param(
            lambda child: child.completed_subprocess_capture(71, b"", b"bounded error"),
            id="error",
        ),
    ],
)
def test_child_runtime_failure_v3_wire_round_trip_binds_actual_capture_producer(
    capture: Callable[[ModuleType], dict[str, object]],
) -> None:
    assert CHILD is not None
    produced = capture(CHILD)
    failure = CHILD.PackagedMcpObservationFailure("mcp_exchange", produced)
    frame = CHILD.runtime_failure_frame("result_assembly", H, ENVIRONMENT, None, failure)
    wire = json.dumps(frame, sort_keys=True, separators=(",", ":"))
    raw = json.loads(wire)

    assert raw["payload"]["packaged_subprocess"]["schema_version"] == 1
    assert raw["child_runtime_failure_id"] == digest(canonical(raw["payload"]))
    parsed = LinuxChildRuntimeFailureV3.model_validate(raw)
    assert parsed.payload.packaged_subprocess is not None
    assert parsed.payload.packaged_subprocess.schema_version == 1


@pytest.mark.skipif(os.name != "posix", reason="Child runtime framing is Linux-only")
@pytest.mark.parametrize("mutation", ["missing", "changed"])
def test_child_runtime_failure_v3_rejects_nested_capture_version_drift(mutation: str) -> None:
    assert CHILD is not None
    capture = CHILD.completed_subprocess_capture(71, b"", b"bounded error")
    failure = CHILD.PackagedMcpObservationFailure("mcp_exchange", capture)
    frame = CHILD.runtime_failure_frame("result_assembly", H, ENVIRONMENT, None, failure)
    raw = json.loads(json.dumps(frame, sort_keys=True, separators=(",", ":")))
    nested = raw["payload"]["packaged_subprocess"]
    if mutation == "missing":
        del nested["schema_version"]
    else:
        nested["schema_version"] = 2

    with pytest.raises(ValidationError):
        LinuxPackagedSubprocessCaptureV1.model_validate(nested)

    raw["child_runtime_failure_id"] = digest(canonical(raw["payload"]))
    with pytest.raises(ValidationError):
        LinuxChildRuntimeFailureV3.model_validate(raw)


@pytest.mark.skipif(os.name != "posix", reason="Linux finalizer requires O_NOFOLLOW")
def test_finalizer_joins_only_v14_mechanics(tmp_path: Path) -> None:
    profile = LinuxIsolationProfileV14.create(profile_payload_v14())
    receipt = LinuxIsolationReceiptV14.create(
        LinuxIsolationReceiptPayloadV14(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v14(),
        )
    )
    evidence = LinuxIsolationEvidenceV14.create(evidence_payload_v14(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=evidence.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    mechanics_path = tmp_path / "mechanics.json"
    cleanup_path = tmp_path / "cleanup.json"
    output = tmp_path / "qualification.json"
    mechanics_path.write_text(evidence.model_dump_json(), encoding="utf-8")
    cleanup_path.write_text(cleanup.model_dump_json(), encoding="utf-8")
    assert APPARMOR_MANAGER.read_mechanics(mechanics_path) == evidence
    FINALIZER.finalize(mechanics_path, cleanup_path, output)
    qualification = LinuxIsolationQualificationV14.model_validate_json(output.read_bytes())
    assert qualification.payload.mechanics == evidence
    assert qualification.payload.apparmor_cleanup == cleanup


def test_v5_rejects_synthetic_upstream_substitution_and_arbitrary_host() -> None:
    profile = LinuxIsolationProfileV5.create(profile_payload_v5())
    observed = observation_v5().model_dump(mode="python")
    observed["synthetic_upstream"]["authority"]["port"] += 1
    receipt = LinuxIsolationReceiptV5.create(
        LinuxIsolationReceiptPayloadV5(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=LinuxIsolationObservationV5.model_validate(observed),
        )
    )
    with pytest.raises(ValidationError, match="synthetic upstream authority differs"):
        LinuxIsolationEvidencePayloadV5(
            profile=profile,
            receipt=receipt,
            child_stdout_retained_sha256=H,
            child_stderr_retained_sha256=H,
            child_stdout_retained_bytes=0,
            child_stderr_retained_bytes=0,
            child_stdout_truncated=False,
            child_stderr_truncated=False,
            cleanup=LinuxHostCleanupObservationV1(),
        )
    raw = synthetic_upstream().model_dump(mode="python")
    raw["host"] = "0.0.0.0"
    with pytest.raises(ValidationError):
        LinuxSyntheticUpstreamAuthorityV1.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner_pid", 124),
        ("owner_start_time_ticks", 457),
        ("owner_uid", 1001),
    ],
)
def test_v5_rejects_rehashed_synthetic_owner_substitution(field: str, value: int) -> None:
    raw = profile_payload_v5().model_dump(mode="python")
    raw["synthetic_upstream"][field] = value
    with pytest.raises(ValidationError, match="owner differs from broker host"):
        LinuxIsolationProfilePayloadV5.model_validate(raw)


def test_v5_rejects_production_ollama_port_as_synthetic_fixture() -> None:
    raw = profile_payload_v5().model_dump(mode="python")
    raw["synthetic_upstream"]["port"] = 11434
    with pytest.raises(ValidationError, match="must not use the production Ollama port"):
        LinuxIsolationProfilePayloadV5.model_validate(raw)


def test_historical_v1_contracts_remain_strictly_parseable_and_canonical() -> None:
    raw_profile = historical_v2_profile_payload().model_dump(mode="python")
    raw_profile["schema_version"] = 1
    raw_profile["profile_kind"] = "linux_native_isolation_v1"
    raw_profile["unshare"] = raw_profile.pop("system_unshare")
    raw_profile["host"].pop("apparmor")
    v1_payload = LinuxIsolationProfilePayloadV1.model_validate(raw_profile)
    v1_profile = LinuxIsolationProfileV1.create(v1_payload)

    raw_observation = historical_v2_observation().model_dump(mode="python")
    raw_observation["schema_version"] = 1
    raw_observation.pop("apparmor_current_profile")
    v1_observation = LinuxIsolationObservationV1.model_validate(raw_observation)
    v1_receipt = LinuxIsolationReceiptV1.create(
        LinuxIsolationReceiptPayloadV1(
            linux_isolation_profile_id=v1_profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=v1_observation,
        )
    )
    v1_evidence = LinuxIsolationEvidenceV1.create(
        LinuxIsolationEvidencePayloadV1(
            profile=v1_profile,
            receipt=v1_receipt,
            child_stdout_retained_sha256=H,
            child_stderr_retained_sha256=H,
            child_stdout_retained_bytes=0,
            child_stderr_retained_bytes=0,
            child_stdout_truncated=False,
            child_stderr_truncated=False,
            cleanup=LinuxHostCleanupObservationV1(),
        )
    )
    encoded = canonical(v1_evidence.model_dump(mode="json"))
    assert LinuxIsolationEvidenceV1.model_validate_json(encoded) == v1_evidence
    assert b"apparmor_current_profile" not in encoded
    assert b"system_unshare" not in encoded


def test_historical_v2_contracts_remain_strictly_parseable_and_canonical() -> None:
    profile = LinuxIsolationProfileV2.create(historical_v2_profile_payload())
    receipt = LinuxIsolationReceiptV2.create(
        LinuxIsolationReceiptPayloadV2(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=historical_v2_observation(),
        )
    )
    evidence = LinuxIsolationEvidenceV2.create(
        LinuxIsolationEvidencePayloadV2(
            profile=profile,
            receipt=receipt,
            child_stdout_retained_sha256=H,
            child_stderr_retained_sha256=H,
            child_stdout_retained_bytes=0,
            child_stderr_retained_bytes=0,
            child_stdout_truncated=False,
            child_stderr_truncated=False,
            cleanup=LinuxHostCleanupObservationV1(),
        )
    )
    encoded = canonical(evidence.model_dump(mode="json"))
    assert LinuxIsolationEvidenceV2.model_validate_json(encoded) == evidence
    assert b"kernel_landlock_abi" not in encoded
    assert b"enforced_landlock_abi" not in encoded


def test_linux_composite_rejects_cross_environment_and_profile_observation_mismatch() -> None:
    profile = LinuxIsolationProfileV3.create(profile_payload())
    wrong_environment = LinuxIsolationReceiptV3.create(
        LinuxIsolationReceiptPayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id="a" * 32,
            observation=observation(),
        )
    )
    with pytest.raises(ValidationError, match="authority differ"):
        evidence_payload(profile, wrong_environment)
    changed = observation().model_copy(update={"landlock_handled_access": 1})
    with pytest.raises(ValidationError, match="Landlock mask"):
        LinuxIsolationReceiptPayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=changed,
        )


def test_profile_rejects_tampering_open_bags_and_weakened_authority() -> None:
    profile = LinuxIsolationProfileV3.create(profile_payload()).model_dump(mode="json")
    profile["linux_isolation_profile_id"] = "f" * 64
    with pytest.raises(ValidationError, match="profile hash mismatch"):
        LinuxIsolationProfileV3.model_validate_json(json.dumps(profile))
    raw = profile_payload().model_dump(mode="python") | {"unexpected_authority": True}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxIsolationProfilePayloadV3.model_validate(raw)
    raw = profile_payload().model_dump(mode="python")
    raw["mounts"] = tuple(reversed(raw["mounts"]))
    with pytest.raises(ValidationError, match="sorted and unique"):
        LinuxIsolationProfilePayloadV3.model_validate(raw)
    raw = profile_payload().model_dump(mode="python")
    raw["landlock_handled_access"] = 1
    with pytest.raises(ValidationError, match="exact reviewed host ABI"):
        LinuxIsolationProfilePayloadV3.model_validate(raw)
    raw = profile_payload().model_dump(mode="python")
    raw["host"]["apparmor_userns_restriction"] = 0
    with pytest.raises(ValidationError, match="literal_error|Input should be 1"):
        LinuxIsolationProfilePayloadV3.model_validate(raw)
    raw = profile_payload().model_dump(mode="python")
    raw["host"]["apparmor"]["installed_profile"]["owner_uid"] = 1000
    with pytest.raises(ValidationError, match="Installed AppArmor profile"):
        LinuxIsolationProfilePayloadV3.model_validate(raw)
    raw = profile_payload().model_dump(mode="python")
    raw["unshare"]["native_identity"] = raw["system_unshare"]["native_identity"]
    with pytest.raises(ValidationError, match="Private unshare"):
        LinuxIsolationProfilePayloadV3.model_validate(raw)


def test_observation_requires_exact_child_apparmor_attachment() -> None:
    raw = observation().model_dump(mode="python")
    raw["apparmor_current_profile"] = "unconfined"
    with pytest.raises(ValidationError, match="literal_error"):
        LinuxIsolationObservationV3.model_validate(raw)


def test_apparmor_authority_rejects_source_snapshot_and_parser_substitution() -> None:
    raw = apparmor().model_dump(mode="python")
    changed = copy.deepcopy(raw)
    changed["source_git_blob_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="Git blob"):
        LinuxAppArmorAuthorityV2.model_validate(changed)

    changed = copy.deepcopy(raw)
    changed["loaded_profiles_snapshot"]["sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="snapshot authority"):
        LinuxAppArmorAuthorityV2.model_validate(changed)

    changed = copy.deepcopy(raw)
    changed["parser"]["owner_uid"] = 1000
    with pytest.raises(ValidationError, match="root-owned"):
        LinuxAppArmorAuthorityV2.model_validate(changed)


def test_apparmor_parser_version_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        PROBE,
        "plain_file_authority",
        lambda _path: plain_file("/usr/sbin/apparmor_parser", index=99),
    )
    monkeypatch.setattr(
        PROBE.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, b"", b"failed"),
    )
    with pytest.raises(ValueError, match="version observation failed"):
        PROBE.apparmor_parser_authority(Path("/usr/sbin/apparmor_parser"))


def test_apparmor_authority_rejects_unloaded_or_wrong_mode_profile(tmp_path: Path) -> None:
    loaded = tmp_path / "loaded-profiles"
    loaded.write_text("devfabric-linux-isolation-unshare (enforce)\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not loaded"):
        PROBE.apparmor_authority(
            ROOT,
            COMMIT,
            installed=tmp_path / "installed",
            parser=tmp_path / "parser",
            loaded=loaded,
        )


def test_cleanup_receipt_is_required_for_final_v4_qualification() -> None:
    profile = LinuxIsolationProfileV4.create(profile_payload_v4())
    receipt = LinuxIsolationReceiptV4.create(
        LinuxIsolationReceiptPayloadV4(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v4(),
        )
    )
    mechanics = LinuxIsolationEvidenceV4.create(evidence_payload_v4(profile, receipt))
    authority_sha = digest(canonical(profile.payload.host.apparmor.model_dump(mode="json")))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=mechanics.linux_isolation_evidence_id,
            apparmor_authority_sha256=authority_sha,
        )
    )
    qualification = LinuxIsolationQualificationV4.create(
        LinuxIsolationQualificationPayloadV4(mechanics=mechanics, apparmor_cleanup=cleanup)
    )
    assert qualification.payload.package_readiness is False
    forged = cleanup.model_dump(mode="python")
    forged["payload"]["environment_instance_id"] = "a" * 32
    forged_cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1.model_validate(forged["payload"])
    )
    with pytest.raises(ValidationError, match="authority differ"):
        LinuxIsolationQualificationPayloadV4(
            mechanics=mechanics,
            apparmor_cleanup=forged_cleanup,
        )


def test_apparmor_setup_rejects_preexisting_owned_target_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private-unshare"
    installed = tmp_path / "installed-profile"
    snapshot = tmp_path / "snapshot"
    state = tmp_path / "state.json"
    private.write_bytes(b"foreign")
    monkeypatch.setattr(APPARMOR_MANAGER, "PRIVATE_LAUNCHER", private)
    monkeypatch.setattr(APPARMOR_MANAGER, "INSTALLED_PROFILE", installed)
    monkeypatch.setattr(APPARMOR_MANAGER, "LOADED_SNAPSHOT", snapshot)
    monkeypatch.setattr(APPARMOR_MANAGER, "profile_is_loaded", lambda: False)
    with pytest.raises(ValueError, match="already exists"):
        APPARMOR_MANAGER.ensure_absent_before_setup(state)
    assert private.read_bytes() == b"foreign"
    assert not installed.exists()
    assert not snapshot.exists()


def apparmor_setup_state(**changes: bool) -> LinuxAppArmorSetupStateV1:
    payload = LinuxAppArmorSetupStatePayloadV1(
        implementation_commit=COMMIT,
        environment_instance_id=ENVIRONMENT,
        source_git_blob_sha256=H,
        source_sha256=H,
        system_unshare_sha256=H,
        parser_sha256=H,
    ).model_copy(update=changes)
    return LinuxAppArmorSetupStateV1.create(payload)


def in_memory_state_update(
    _path: Path, payload: LinuxAppArmorSetupStatePayloadV1, **changes: object
) -> LinuxAppArmorSetupStatePayloadV1:
    return LinuxAppArmorSetupStatePayloadV1.model_validate(
        payload.model_dump(mode="python") | changes
    )


def test_partial_setup_rollback_removes_only_recorded_owned_objects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_bytes(b"state")
    private = tmp_path / "private"
    private.write_bytes(b"owned")
    foreign = tmp_path / "foreign-profile"
    foreign.write_bytes(b"foreign")
    recorded = apparmor_setup_state(private_launcher_created=True)
    removed: list[Path] = []

    def remove(path: Path, _sha: str, _mode: int) -> None:
        removed.append(path)
        path.unlink()

    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", lambda _path: recorded)
    monkeypatch.setattr(APPARMOR_MANAGER, "PRIVATE_LAUNCHER", private)
    monkeypatch.setattr(APPARMOR_MANAGER, "INSTALLED_PROFILE", foreign)
    monkeypatch.setattr(APPARMOR_MANAGER, "remove_owned_file", remove)
    monkeypatch.setattr(APPARMOR_MANAGER, "validate_owned_file", lambda *_args: None)
    monkeypatch.setattr(APPARMOR_MANAGER, "loaded_profile_lines", lambda: ())
    monkeypatch.setattr(APPARMOR_MANAGER, "update_state", in_memory_state_update)
    APPARMOR_MANAGER.cleanup_owned(state_path, require_complete=False)
    assert removed == [private]
    assert foreign.read_bytes() == b"foreign"
    assert not state_path.exists()


def test_cleanup_failure_keeps_state_and_refuses_success_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_bytes(b"state")
    parser = tmp_path / "parser"
    parser.write_bytes(b"parser")
    installed = tmp_path / "profile"
    installed.write_bytes(b"profile")
    recorded = apparmor_setup_state(profile_loaded=True)
    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", lambda _path: recorded)
    monkeypatch.setattr(APPARMOR_MANAGER, "PARSER", parser)
    monkeypatch.setattr(APPARMOR_MANAGER, "INSTALLED_PROFILE", installed)
    monkeypatch.setattr(APPARMOR_MANAGER, "profile_is_loaded", lambda: True)
    monkeypatch.setattr(APPARMOR_MANAGER, "loaded_profile_lines", lambda: (LINUX_APPARMOR_CURRENT,))
    monkeypatch.setattr(
        APPARMOR_MANAGER,
        "file_sha256",
        lambda path: H if path in {parser, installed} else "f" * 64,
    )

    def fail(_command: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(_command, 1, b"", b"failed")

    with pytest.raises(ValueError, match="did not remove every independently safe"):
        APPARMOR_MANAGER.cleanup_owned(state_path, runner=fail, require_complete=False)
    assert state_path.exists()


def completed_cleanup_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, LinuxAppArmorSetupStateV1, list[str]]:
    parser = tmp_path / "parser"
    installed = tmp_path / "installed"
    private = tmp_path / "private"
    snapshot = tmp_path / "snapshot"
    state_path = tmp_path / "state.json"
    parser.write_bytes(b"parser")
    installed.write_bytes(b"policy")
    private.write_bytes(b"unshare")
    snapshot.write_bytes((LINUX_APPARMOR_CURRENT + "\n").encode())
    state_path.write_bytes(b"state")
    parser.chmod(0o755)
    installed.chmod(0o644)
    private.chmod(0o755)
    snapshot.chmod(0o644)
    payload = LinuxAppArmorSetupStatePayloadV1(
        implementation_commit=COMMIT,
        environment_instance_id=ENVIRONMENT,
        source_git_blob_sha256=APPARMOR_MANAGER.file_sha256(installed),
        source_sha256=APPARMOR_MANAGER.file_sha256(installed),
        system_unshare_sha256=APPARMOR_MANAGER.file_sha256(private),
        parser_sha256=APPARMOR_MANAGER.file_sha256(parser),
        private_launcher_created=True,
        installed_profile_created=True,
        profile_loaded=True,
        loaded_snapshot_created=True,
        setup_complete=True,
    )
    state = LinuxAppArmorSetupStateV1.create(payload)
    loaded = [LINUX_APPARMOR_CURRENT]
    monkeypatch.setattr(APPARMOR_MANAGER, "PARSER", parser)
    monkeypatch.setattr(APPARMOR_MANAGER, "INSTALLED_PROFILE", installed)
    monkeypatch.setattr(APPARMOR_MANAGER, "PRIVATE_LAUNCHER", private)
    monkeypatch.setattr(APPARMOR_MANAGER, "LOADED_SNAPSHOT", snapshot)
    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", lambda _path: state)
    monkeypatch.setattr(APPARMOR_MANAGER, "loaded_profile_lines", lambda: tuple(loaded))
    monkeypatch.setattr(APPARMOR_MANAGER, "safe_root_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(APPARMOR_MANAGER, "update_state", in_memory_state_update)

    def validate(path: Path, expected_sha: str, _expected_mode: int) -> None:
        if not path.exists() or APPARMOR_MANAGER.file_sha256(path) != expected_sha:
            raise ValueError("Owned AppArmor lifecycle file is unavailable before cleanup")

    def remove(path: Path, expected_sha: str, expected_mode: int) -> None:
        validate(path, expected_sha, expected_mode)
        path.unlink()

    monkeypatch.setattr(APPARMOR_MANAGER, "validate_owned_file", validate)
    monkeypatch.setattr(APPARMOR_MANAGER, "remove_owned_file", remove)
    return state_path, state, loaded


def test_completed_cleanup_prevalidates_then_removes_exact_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path, state, loaded = completed_cleanup_authority(tmp_path, monkeypatch)

    def unload(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        assert command[1] == "-R"
        loaded.clear()
        return subprocess.CompletedProcess(command, 0, b"", b"")

    result = APPARMOR_MANAGER.cleanup_owned(
        state_path,
        runner=unload,
        expected_state_id=state.linux_apparmor_setup_state_id,
    )
    assert result == state
    assert not state_path.exists()
    assert not APPARMOR_MANAGER.INSTALLED_PROFILE.exists()
    assert not APPARMOR_MANAGER.PRIVATE_LAUNCHER.exists()
    assert not APPARMOR_MANAGER.LOADED_SNAPSHOT.exists()


def test_completed_cleanup_rejects_missing_object_before_any_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path, state, _loaded = completed_cleanup_authority(tmp_path, monkeypatch)
    APPARMOR_MANAGER.LOADED_SNAPSHOT.unlink()
    called = False

    def forbidden(_command: list[str]) -> subprocess.CompletedProcess[bytes]:
        nonlocal called
        called = True
        raise AssertionError("cleanup must not mutate before complete prevalidation")

    with pytest.raises(ValueError, match="unavailable before cleanup"):
        APPARMOR_MANAGER.cleanup_owned(
            state_path,
            runner=forbidden,
            expected_state_id=state.linux_apparmor_setup_state_id,
        )
    assert called is False
    assert APPARMOR_MANAGER.INSTALLED_PROFILE.exists()
    assert APPARMOR_MANAGER.PRIVATE_LAUNCHER.exists()
    assert state_path.exists()


@pytest.mark.parametrize("loaded", [[], ["devfabric-linux-isolation-unshare (enforce)"]])
def test_completed_cleanup_rejects_absent_or_wrong_loaded_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    loaded: list[str],
) -> None:
    state_path, state, observed = completed_cleanup_authority(tmp_path, monkeypatch)
    observed[:] = loaded
    with pytest.raises(ValueError, match="loaded AppArmor profile authority"):
        APPARMOR_MANAGER.cleanup_owned(
            state_path,
            expected_state_id=state.linux_apparmor_setup_state_id,
        )
    assert APPARMOR_MANAGER.INSTALLED_PROFILE.exists()
    assert state_path.exists()


def test_created_directory_identity_and_contents_reject_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    child = owned / "expected"
    child.write_bytes(b"owned")
    identity = APPARMOR_MANAGER.native_identity(owned)
    monkeypatch.setattr(APPARMOR_MANAGER, "safe_root_directory", lambda _path: None)
    APPARMOR_MANAGER.validate_journal_directory(
        owned,
        created=True,
        started=False,
        removed=False,
        identity=identity,
        expected_children=(child.name,),
        require_complete=True,
    )
    child.unlink()
    (owned / "foreign").write_bytes(b"foreign")
    with pytest.raises(ValueError, match="contents changed"):
        APPARMOR_MANAGER.validate_journal_directory(
            owned,
            created=True,
            started=False,
            removed=False,
            identity=identity,
            expected_children=(child.name,),
            require_complete=True,
        )
    (owned / "foreign").unlink()
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    assert APPARMOR_MANAGER.native_identity(replacement) != identity
    owned.rmdir()
    replacement.rename(owned)
    with pytest.raises(ValueError, match="identity changed"):
        APPARMOR_MANAGER.validate_journal_directory(
            owned,
            created=True,
            started=False,
            removed=False,
            identity=identity,
            expected_children=(),
            require_complete=True,
        )


def test_post_unload_failure_is_exhaustive_and_retry_uses_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path, state, loaded = completed_cleanup_authority(tmp_path, monkeypatch)
    state_box = [state]

    def read(_path: Path) -> LinuxAppArmorSetupStateV1:
        return state_box[0]

    def update(
        _path: Path, payload: LinuxAppArmorSetupStatePayloadV1, **changes: object
    ) -> LinuxAppArmorSetupStatePayloadV1:
        updated = in_memory_state_update(_path, payload, **changes)
        state_box[0] = LinuxAppArmorSetupStateV1.create(updated)
        return updated

    attempts: list[Path] = []
    fail_snapshot = [True]

    def remove(path: Path, expected_sha: str, expected_mode: int) -> None:
        attempts.append(path)
        if path == APPARMOR_MANAGER.LOADED_SNAPSHOT and fail_snapshot[0]:
            fail_snapshot[0] = False
            raise OSError("synthetic removal failure")
        if APPARMOR_MANAGER.file_sha256(path) != expected_sha:
            raise AssertionError("test authority mismatch")
        path.unlink()

    def unload(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        loaded.clear()
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", read)
    monkeypatch.setattr(APPARMOR_MANAGER, "update_state", update)
    monkeypatch.setattr(APPARMOR_MANAGER, "remove_owned_file", remove)
    with pytest.raises(ValueError, match="did not remove every independently safe"):
        APPARMOR_MANAGER.cleanup_owned(state_path, runner=unload)
    assert attempts == [
        APPARMOR_MANAGER.LOADED_SNAPSHOT,
        APPARMOR_MANAGER.INSTALLED_PROFILE,
        APPARMOR_MANAGER.PRIVATE_LAUNCHER,
    ]
    assert state_box[0].payload.profile_unloaded is True
    assert state_box[0].payload.loaded_snapshot_removed is False
    assert state_box[0].payload.installed_profile_removed is True
    assert state_box[0].payload.private_launcher_removed is True
    assert APPARMOR_MANAGER.LOADED_SNAPSHOT.exists()
    assert not APPARMOR_MANAGER.INSTALLED_PROFILE.exists()
    assert not APPARMOR_MANAGER.PRIVATE_LAUNCHER.exists()
    assert state_path.exists()

    attempts.clear()
    APPARMOR_MANAGER.cleanup_owned(state_path, runner=unload)
    assert attempts == [APPARMOR_MANAGER.LOADED_SNAPSHOT]
    assert not state_path.exists()


def test_profile_unload_crash_window_reconciles_pending_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_bytes(b"state")
    parser = tmp_path / "parser"
    parser.write_bytes(b"parser")
    state_box = [apparmor_setup_state(profile_loaded=True)]
    loaded = [LINUX_APPARMOR_CURRENT]
    reject_completion = [True]

    def read(_path: Path) -> LinuxAppArmorSetupStateV1:
        return state_box[0]

    def update(
        path: Path, payload: LinuxAppArmorSetupStatePayloadV1, **changes: object
    ) -> LinuxAppArmorSetupStatePayloadV1:
        if changes == {"profile_unloaded": True} and reject_completion[0]:
            reject_completion[0] = False
            raise OSError("synthetic journal failure after unload")
        updated = in_memory_state_update(path, payload, **changes)
        state_box[0] = LinuxAppArmorSetupStateV1.create(updated)
        return updated

    def unload(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        loaded.clear()
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(APPARMOR_MANAGER, "PARSER", parser)
    monkeypatch.setattr(APPARMOR_MANAGER, "file_sha256", lambda _path: H)
    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", read)
    monkeypatch.setattr(APPARMOR_MANAGER, "update_state", update)
    monkeypatch.setattr(APPARMOR_MANAGER, "loaded_profile_lines", lambda: tuple(loaded))
    with pytest.raises(ValueError, match="did not remove every independently safe"):
        APPARMOR_MANAGER.cleanup_owned(state_path, runner=unload, require_complete=False)
    assert state_box[0].payload.profile_unload_started is True
    assert state_box[0].payload.profile_unloaded is False
    assert loaded == []
    assert state_path.exists()

    APPARMOR_MANAGER.cleanup_owned(state_path, runner=unload, require_complete=False)
    assert not state_path.exists()


def test_file_removal_crash_window_rejects_substitution_then_reconciles_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path = tmp_path / "state.json"
    state_path.write_bytes(b"state")
    private = tmp_path / "private"
    private.write_bytes(b"owned")
    owned_sha = APPARMOR_MANAGER.file_sha256(private)
    state = LinuxAppArmorSetupStateV1.create(
        LinuxAppArmorSetupStatePayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            source_git_blob_sha256=H,
            source_sha256=H,
            system_unshare_sha256=owned_sha,
            parser_sha256=H,
            private_launcher_created=True,
        )
    )
    state_box = [state]
    reject_completion = [True]

    def read(_path: Path) -> LinuxAppArmorSetupStateV1:
        return state_box[0]

    def update(
        path: Path, payload: LinuxAppArmorSetupStatePayloadV1, **changes: object
    ) -> LinuxAppArmorSetupStatePayloadV1:
        if changes == {"private_launcher_removed": True} and reject_completion[0]:
            reject_completion[0] = False
            raise OSError("synthetic journal failure after removal")
        updated = in_memory_state_update(path, payload, **changes)
        state_box[0] = LinuxAppArmorSetupStateV1.create(updated)
        return updated

    def validate(path: Path, expected_sha: str, _expected_mode: int) -> None:
        if APPARMOR_MANAGER.file_sha256(path) != expected_sha:
            raise ValueError("Owned AppArmor lifecycle file changed before cleanup")

    monkeypatch.setattr(APPARMOR_MANAGER, "PRIVATE_LAUNCHER", private)
    monkeypatch.setattr(APPARMOR_MANAGER, "loaded_profile_lines", lambda: ())
    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", read)
    monkeypatch.setattr(APPARMOR_MANAGER, "update_state", update)
    monkeypatch.setattr(APPARMOR_MANAGER, "validate_owned_file", validate)
    monkeypatch.setattr(
        APPARMOR_MANAGER,
        "remove_owned_file",
        lambda path, _sha, _mode: path.unlink(),
    )
    with pytest.raises(ValueError, match="did not remove every independently safe"):
        APPARMOR_MANAGER.cleanup_owned(state_path, require_complete=False)
    assert state_box[0].payload.private_launcher_removal_started is True
    assert state_box[0].payload.private_launcher_removed is False
    assert not private.exists()

    private.write_bytes(b"substitute")
    with pytest.raises(ValueError, match="changed before cleanup"):
        APPARMOR_MANAGER.cleanup_owned(state_path, require_complete=False)
    assert private.read_bytes() == b"substitute"
    private.unlink()
    APPARMOR_MANAGER.cleanup_owned(state_path, require_complete=False)
    assert not state_path.exists()


def production_cleanup_retry_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[
    Path,
    Path,
    Path,
    list[LinuxAppArmorSetupStateV1],
    list[str],
]:
    system = tmp_path / "system-unshare"
    private = tmp_path / "private-unshare"
    parser = tmp_path / "apparmor-parser"
    installed = tmp_path / "installed-profile"
    snapshot = tmp_path / "loaded-snapshot"
    state_path = tmp_path / "state.json"
    mechanics_path = tmp_path / "mechanics.json"
    output = tmp_path / "cleanup.json"
    for path, raw, mode in (
        (system, b"system", 0o755),
        (private, b"private", 0o755),
        (parser, b"parser", 0o755),
        (installed, b"profile", 0o644),
        (snapshot, (LINUX_APPARMOR_CURRENT + "\n").encode(), 0o444),
    ):
        path.write_bytes(raw)
        path.chmod(mode)
    state_path.write_bytes(b"state")
    state_box = [
        apparmor_setup_state(
            private_launcher_created=True,
            installed_profile_created=True,
            profile_loaded=True,
            loaded_snapshot_created=True,
            setup_complete=True,
        )
    ]
    loaded = [LINUX_APPARMOR_CURRENT]
    profile = LinuxIsolationProfileV4.create(profile_payload_v4())
    receipt = LinuxIsolationReceiptV4.create(
        LinuxIsolationReceiptPayloadV4(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v4(),
        )
    )
    mechanics = LinuxIsolationEvidenceV4.create(evidence_payload_v4(profile, receipt))
    mechanics_path.write_text(mechanics.model_dump_json(), encoding="utf-8")
    snapshot_sha = digest((LINUX_APPARMOR_CURRENT + "\n").encode())

    def observed_sha(path: Path) -> str:
        if path == snapshot:
            return snapshot_sha
        if path in {system, private, parser, installed} and path.read_bytes() != b"substitute":
            return H
        return "f" * 64

    def validate_owned(path: Path, expected_sha: str, _expected_mode: int) -> None:
        if not path.exists() or observed_sha(path) != expected_sha:
            raise ValueError("Owned AppArmor lifecycle file changed before cleanup")

    def validate_authority(path: Path, authority: LinuxFileAuthorityV1) -> None:
        validate_owned(path, authority.sha256, int(authority.mode, 8))

    def remove_owned(path: Path, expected_sha: str, expected_mode: int) -> None:
        validate_owned(path, expected_sha, expected_mode)
        path.chmod(0o600)
        path.unlink()

    monkeypatch.setattr(APPARMOR_MANAGER, "SYSTEM_LAUNCHER", system)
    monkeypatch.setattr(APPARMOR_MANAGER, "PRIVATE_LAUNCHER", private)
    monkeypatch.setattr(APPARMOR_MANAGER, "PARSER", parser)
    monkeypatch.setattr(APPARMOR_MANAGER, "INSTALLED_PROFILE", installed)
    monkeypatch.setattr(APPARMOR_MANAGER, "LOADED_SNAPSHOT", snapshot)
    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", lambda _path: state_box[0])
    monkeypatch.setattr(APPARMOR_MANAGER, "file_sha256", observed_sha)
    monkeypatch.setattr(APPARMOR_MANAGER, "validate_owned_file", validate_owned)
    monkeypatch.setattr(APPARMOR_MANAGER, "validate_file_authority", validate_authority)
    monkeypatch.setattr(APPARMOR_MANAGER, "remove_owned_file", remove_owned)
    monkeypatch.setattr(APPARMOR_MANAGER, "loaded_profile_lines", lambda: tuple(loaded))
    monkeypatch.setattr(
        APPARMOR_MANAGER,
        "write_exclusive",
        lambda path, raw, _mode: path.write_bytes(raw),
    )
    return state_path, mechanics_path, output, state_box, loaded


def test_production_cleanup_retry_after_unload_journal_crash_writes_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path, mechanics_path, output, state_box, loaded = production_cleanup_retry_authority(
        tmp_path, monkeypatch
    )
    reject_completion = [True]

    def update(
        path: Path, payload: LinuxAppArmorSetupStatePayloadV1, **changes: object
    ) -> LinuxAppArmorSetupStatePayloadV1:
        if changes == {"profile_unloaded": True} and reject_completion[0]:
            reject_completion[0] = False
            raise OSError("synthetic journal failure after unload")
        updated = in_memory_state_update(path, payload, **changes)
        state_box[0] = LinuxAppArmorSetupStateV1.create(updated)
        return updated

    def unload(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        loaded.clear()
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(APPARMOR_MANAGER, "update_state", update)
    with pytest.raises(ValueError, match="did not remove every independently safe"):
        APPARMOR_MANAGER.cleanup(state_path, mechanics_path, output, runner=unload)
    assert not output.exists()
    assert state_box[0].payload.profile_unload_started is True
    assert state_box[0].payload.profile_unloaded is False

    APPARMOR_MANAGER.cleanup(state_path, mechanics_path, output, runner=unload)
    cleanup = LinuxAppArmorCleanupReceiptV1.model_validate_json(output.read_bytes())
    mechanics = LinuxIsolationEvidenceV4.model_validate_json(mechanics_path.read_bytes())
    assert cleanup.payload.linux_isolation_profile_id == (
        mechanics.payload.profile.linux_isolation_profile_id
    )
    assert cleanup.payload.linux_isolation_evidence_id == mechanics.linux_isolation_evidence_id


def test_production_cleanup_retry_rejects_substituted_pending_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_path, mechanics_path, output, state_box, loaded = production_cleanup_retry_authority(
        tmp_path, monkeypatch
    )
    reject_completion = [True]

    def update(
        path: Path, payload: LinuxAppArmorSetupStatePayloadV1, **changes: object
    ) -> LinuxAppArmorSetupStatePayloadV1:
        if changes == {"private_launcher_removed": True} and reject_completion[0]:
            reject_completion[0] = False
            raise OSError("synthetic journal failure after file removal")
        updated = in_memory_state_update(path, payload, **changes)
        state_box[0] = LinuxAppArmorSetupStateV1.create(updated)
        return updated

    def unload(command: list[str]) -> subprocess.CompletedProcess[bytes]:
        loaded.clear()
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(APPARMOR_MANAGER, "update_state", update)
    with pytest.raises(ValueError, match="did not remove every independently safe"):
        APPARMOR_MANAGER.cleanup(state_path, mechanics_path, output, runner=unload)
    assert state_box[0].payload.private_launcher_removal_started is True
    assert state_box[0].payload.private_launcher_removed is False
    assert not APPARMOR_MANAGER.PRIVATE_LAUNCHER.exists()

    APPARMOR_MANAGER.PRIVATE_LAUNCHER.write_bytes(b"substitute")
    with pytest.raises(ValueError, match="changed before cleanup"):
        APPARMOR_MANAGER.cleanup(state_path, mechanics_path, output, runner=unload)
    assert APPARMOR_MANAGER.PRIVATE_LAUNCHER.read_bytes() == b"substitute"
    assert not output.exists()

    APPARMOR_MANAGER.PRIVATE_LAUNCHER.unlink()
    APPARMOR_MANAGER.cleanup(state_path, mechanics_path, output, runner=unload)
    LinuxAppArmorCleanupReceiptV1.model_validate_json(output.read_bytes())


@pytest.mark.parametrize(
    "updates",
    [
        {"source_git_blob_sha256": "f" * 64, "source_sha256": "f" * 64},
        {"system_unshare_sha256": "f" * 64},
        {"parser_sha256": "f" * 64},
    ],
)
def test_cleanup_rejects_complete_state_substitution_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    updates: dict[str, str],
) -> None:
    profile = LinuxIsolationProfileV4.create(profile_payload_v4())
    receipt = LinuxIsolationReceiptV4.create(
        LinuxIsolationReceiptPayloadV4(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation_v4(),
        )
    )
    mechanics = LinuxIsolationEvidenceV4.create(evidence_payload_v4(profile, receipt))
    mechanics_path = tmp_path / "mechanics.json"
    mechanics_path.write_text(mechanics.model_dump_json(), encoding="utf-8")
    state = apparmor_setup_state(
        private_launcher_created=True,
        installed_profile_created=True,
        profile_loaded=True,
        loaded_snapshot_created=True,
        setup_complete=True,
    )
    changed = state.payload.model_copy(update=updates)
    substituted = LinuxAppArmorSetupStateV1.create(changed)
    monkeypatch.setattr(APPARMOR_MANAGER, "read_state", lambda _path: substituted)
    monkeypatch.setattr(
        APPARMOR_MANAGER,
        "cleanup_owned",
        lambda *_args, **_kwargs: pytest.fail("substituted state must fail before cleanup"),
    )
    with pytest.raises(ValueError, match="differs from mechanics authority"):
        APPARMOR_MANAGER.cleanup(
            tmp_path / "state.json",
            mechanics_path,
            tmp_path / "cleanup.json",
        )


def test_cleanup_receipt_cannot_replay_against_different_profile_or_evidence() -> None:
    profile = LinuxIsolationProfileV3.create(profile_payload())
    receipt = LinuxIsolationReceiptV3.create(
        LinuxIsolationReceiptPayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation(),
        )
    )
    mechanics = LinuxIsolationEvidenceV3.create(evidence_payload(profile, receipt))
    cleanup = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=COMMIT,
            environment_instance_id=ENVIRONMENT,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=mechanics.linux_isolation_evidence_id,
            apparmor_authority_sha256=digest(
                canonical(profile.payload.host.apparmor.model_dump(mode="json"))
            ),
        )
    )
    changed_profile = LinuxIsolationProfileV3.create(
        profile_payload().model_copy(update={"native_bundle_id": "f" * 64})
    )
    changed_receipt = LinuxIsolationReceiptV3.create(
        LinuxIsolationReceiptPayloadV3(
            linux_isolation_profile_id=changed_profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation(),
        )
    )
    changed_mechanics = LinuxIsolationEvidenceV3.create(
        evidence_payload(changed_profile, changed_receipt)
    )
    with pytest.raises(ValidationError, match="authority differ"):
        LinuxIsolationQualificationPayloadV3(
            mechanics=changed_mechanics,
            apparmor_cleanup=cleanup,
        )
    changed_evidence = LinuxIsolationEvidenceV3.create(
        evidence_payload(
            profile,
            LinuxIsolationReceiptV3.create(
                LinuxIsolationReceiptPayloadV3(
                    linux_isolation_profile_id=profile.linux_isolation_profile_id,
                    environment_instance_id=ENVIRONMENT,
                    observation=observation(),
                )
            ),
        ).model_copy(update={"child_stdout_retained_sha256": "f" * 64})
    )
    with pytest.raises(ValidationError, match="authority differ"):
        LinuxIsolationQualificationPayloadV3(
            mechanics=changed_evidence,
            apparmor_cleanup=cleanup,
        )


def test_lifecycle_failure_is_self_hashed_sanitized_and_zero_countered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "failure.json"
    monkeypatch.setattr(
        APPARMOR_MANAGER, "write_exclusive", lambda path, raw, _mode: path.write_bytes(raw)
    )
    APPARMOR_MANAGER.write_lifecycle_failure(
        output,
        phase="cleanup",
        implementation_commit=COMMIT,
        environment_instance_id=ENVIRONMENT,
        state_id=H,
        cleanup_attempted=True,
        cleanup_succeeded=False,
    )
    failure = LinuxAppArmorLifecycleFailureV1.model_validate_json(output.read_bytes())
    assert failure.payload.reason_code == "cleanup_failed"
    assert failure.payload.model_requests == failure.payload.provider_sends == 0
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxAppArmorLifecycleFailurePayloadV1.model_validate(
            failure.payload.model_dump(mode="python") | {"detail": "/secret/path"}
        )


def test_namespace_observation_rejects_any_host_namespace_reuse() -> None:
    raw = namespace_observation().model_dump(mode="python")
    raw["child_network_namespace_id"] = raw["host_network_namespace_id"]
    with pytest.raises(ValidationError, match="namespace was not replaced"):
        LinuxNamespaceObservationV1.model_validate(raw)


def send_request(raw: bytes, limit: int = 64 * 1024) -> BoundedHTTPRequest:
    server, client = socket.socketpair()
    try:
        client.sendall(raw)
        client.shutdown(socket.SHUT_WR)
        return read_metadata_request(server, limit)
    finally:
        server.close()
        client.close()


@pytest.mark.parametrize(
    ("raw_request", "method", "path"),
    [
        (b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n\r\n", "GET", "/api/version"),
        (b"GET /api/tags HTTP/1.1\r\nHost: localhost:11434\r\n\r\n", "GET", "/api/tags"),
        (
            b"POST /api/show HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: 32\r\n\r\n"
            b'{"model":"qwen2.5:14b-instruct"}',
            "POST",
            "/api/show",
        ),
    ],
)
def test_broker_accepts_only_exact_bounded_metadata(
    raw_request: bytes, method: str, path: str
) -> None:
    observed = send_request(raw_request)
    assert (observed.method, observed.path, observed.raw) == (method, path, raw_request)


@pytest.mark.parametrize(
    "raw_request",
    [
        b"POST /api/generate HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: 2\r\n\r\n{}",
        b"GET /api/version HTTP/1.1\r\nHost: foreign:11434\r\n\r\n",
        b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nX-Foreign: x\r\n\r\n",
        b"POST /api/show HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: 17\r\n\r\n"
        b'{"model":"other"}',
    ],
)
def test_broker_rejects_generation_ambiguity_and_model_substitution(raw_request: bytes) -> None:
    with pytest.raises(ValueError):
        send_request(raw_request)


class RejectedRequestStream:
    def __init__(self, chunks: list[bytes | BaseException]) -> None:
        self.chunks = iter(chunks)
        self.max_requested = 0

    def recv(self, count: int) -> bytes:
        self.max_requested = max(self.max_requested, count)
        item = next(self.chunks)
        if isinstance(item, BaseException):
            raise item
        return item


def test_rejected_request_drain_is_fixed_memory_and_bounded() -> None:
    stream = RejectedRequestStream([b"a" * 4096, b"b" * 4096, b""])
    assert drain_rejected_request(cast(socket.socket, stream), 8192) == 8192
    assert stream.max_requested == 4096


def test_rejected_request_drain_fails_closed_above_discard_bound() -> None:
    stream = RejectedRequestStream([b"a" * 4096, b"b" * 4096, b"c"])
    with pytest.raises(ValueError, match="exceeds the discard limit"):
        drain_rejected_request(cast(socket.socket, stream), 8192)


@pytest.mark.parametrize(
    "error",
    [TimeoutError(errno.ETIMEDOUT, "timed out"), ConnectionResetError(errno.ECONNRESET, "reset")],
)
def test_rejected_request_drain_propagates_no_eof_and_os_errors(error: OSError) -> None:
    stream = RejectedRequestStream([b"partial", error])
    with pytest.raises(type(error)):
        drain_rejected_request(cast(socket.socket, stream), 8192)


def _current_linux_broker_peer() -> LinuxBrokerPeerAuthorityV1:
    geteuid = getattr(os, "geteuid", None)
    assert callable(geteuid)
    return LinuxBrokerPeerAuthorityV1(
        outer_pid=os.getpid(),
        outer_uid=int(geteuid()),
        start_time_ticks=process_start_time_ticks(os.getpid()),
    )


def _wait_for_broker_socket(path: Path, failures: list[BaseException]) -> None:
    deadline = time.monotonic() + 3
    while not path.exists() and not failures and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not failures
    assert path.exists()


def _connect_to_ready_broker(path: Path, failures: list[BaseException]) -> socket.socket:
    _wait_for_broker_socket(path, failures)
    deadline = time.monotonic() + 3
    while True:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(3)
        try:
            client.connect(str(path))
            return client
        except ConnectionRefusedError:
            client.close()
            if failures or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
        except BaseException:
            client.close()
            raise


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SO_PEERCRED") or os.geteuid() < 1,
    reason="Non-root Linux SO_PEERCRED required",
)
def test_broker_real_oversized_denial_drains_before_complete_403(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "ollama.sock"
    runtime = LinuxMetadataBrokerV1(path, _current_linux_broker_peer())
    failures: list[BaseException] = []
    outcomes: list[tuple[str, ...]] = []

    def serve() -> None:
        try:
            outcomes.append(runtime.serve_requests(1))
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    client = _connect_to_ready_broker(path, failures)
    try:
        client.sendall(
            b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nX: " + b"a" * (70 * 1024)
        )
        client.shutdown(socket.SHUT_WR)
        response = bytearray()
        while chunk := client.recv(4096):
            response.extend(chunk)
    finally:
        client.close()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert not failures
    assert outcomes == [("denied",)]
    assert bytes(response) == (
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    assert not path.exists()


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SO_PEERCRED") or os.geteuid() < 1,
    reason="Non-root Linux SO_PEERCRED required",
)
def test_broker_discard_bound_failure_is_typed_and_cleans_socket(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "ollama.sock"
    runtime = LinuxMetadataBrokerV1(path, _current_linux_broker_peer())
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            runtime.serve_requests(1)
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    client = _connect_to_ready_broker(path, failures)
    try:
        client.sendall(
            b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nX: " + b"a" * (129 * 1024)
        )
        client.shutdown(socket.SHUT_WR)
        try:
            while client.recv(4096):
                pass
        except ConnectionResetError:
            pass
    finally:
        client.close()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert len(failures) == 1
    failure = failures[0]
    assert isinstance(failure, LinuxMetadataBrokerFailure)
    assert (failure.checkpoint, failure.completed_outcomes) == ("denial_response", ())
    assert (failure.failure_kind, failure.errno_category) == ("internal_error", None)
    assert not path.exists()


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(socket, "SO_PEERCRED") or os.geteuid() < 1,
    reason="Non-root Linux SO_PEERCRED required",
)
@pytest.mark.parametrize(
    ("error", "errno_category"),
    [
        (TimeoutError(errno.ETIMEDOUT, "timed out"), "timed_out"),
        (ConnectionResetError(errno.ECONNRESET, "reset"), "connection_reset"),
    ],
)
def test_broker_drain_os_failure_is_typed_without_outcome_or_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: OSError,
    errno_category: str,
) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "ollama.sock"
    runtime = LinuxMetadataBrokerV1(path, _current_linux_broker_peer())
    failures: list[BaseException] = []

    def fail_drain(_connection: socket.socket, _limit: int) -> int:
        raise error

    monkeypatch.setattr(LINUX_BROKER, "drain_rejected_request", fail_drain)

    def serve() -> None:
        try:
            runtime.serve_requests(1)
        except BaseException as observed:
            failures.append(observed)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    client = _connect_to_ready_broker(path, failures)
    response = bytearray()
    try:
        client.sendall(
            b"POST /api/generate HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: 2\r\n\r\n{}"
        )
        client.shutdown(socket.SHUT_WR)
        try:
            while chunk := client.recv(4096):
                response.extend(chunk)
        except ConnectionResetError:
            pass
    finally:
        client.close()
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert len(failures) == 1
    failure = failures[0]
    assert isinstance(failure, LinuxMetadataBrokerFailure)
    assert (
        failure.checkpoint,
        failure.completed_outcomes,
        failure.failure_kind,
        failure.errno_category,
    ) == ("denial_response", (), "os_error", errno_category)
    assert response == b""
    assert not path.exists()


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux SO_PEERCRED required")
def test_broker_cancellation_removes_socket(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    peer = LinuxBrokerPeerAuthorityV1(outer_pid=1, outer_uid=1, start_time_ticks=1)
    runtime = LinuxMetadataBrokerV1(tmp_path / "ollama.sock", peer)
    assert (runtime.destination_host, runtime.destination_port) == ("127.0.0.1", 11434)
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(TimeoutError, match="cancelled"):
        runtime.serve_requests(1, stop_event=cancelled)
    assert not (tmp_path / "ollama.sock").exists()


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux SO_PEERCRED required")
def test_broker_preserves_foreign_preexisting_socket(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "ollama.sock"
    foreign = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    foreign.bind(str(path))
    foreign.listen(1)
    try:
        peer = LinuxBrokerPeerAuthorityV1(outer_pid=1, outer_uid=1, start_time_ticks=1)
        runtime = LinuxMetadataBrokerV1(path, peer)
        with pytest.raises(LinuxMetadataBrokerFailure) as error:
            runtime.serve_requests(1)
        assert error.value.checkpoint == "parent_validation"
        assert error.value.failure_kind == "authority_validation"
        assert path.exists()
    finally:
        foreign.close()
        path.unlink(missing_ok=True)


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux SO_PEERCRED required")
def test_broker_preserves_substituted_socket_during_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "ollama.sock"
    peer = LinuxBrokerPeerAuthorityV1(outer_pid=1, outer_uid=1, start_time_ticks=1)
    runtime = LinuxMetadataBrokerV1(path, peer)
    stopped = threading.Event()
    owned_socket_recorded = threading.Event()
    failures: list[BaseException] = []
    real_chmod = Path.chmod

    def observed_chmod(target: Path, mode: int) -> None:
        real_chmod(target, mode)
        if target == path and mode == 0o600:
            owned_socket_recorded.set()

    monkeypatch.setattr(Path, "chmod", observed_chmod)

    def serve() -> None:
        try:
            runtime.serve_requests(1, stop_event=stopped)
        except BaseException as error:
            failures.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    assert owned_socket_recorded.wait(timeout=3)
    assert path.exists()
    path.unlink()
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement.bind(str(path))
    replacement.listen(1)
    replacement_info = os.lstat(path)
    replacement_identity = (replacement_info.st_dev, replacement_info.st_ino)
    stopped.set()
    worker.join(timeout=3)
    try:
        assert not worker.is_alive()
        assert len(failures) == 1
        failure = failures[0]
        assert isinstance(failure, LinuxMetadataBrokerFailure)
        assert failure.checkpoint == "cleanup"
        assert failure.failure_kind == "cleanup_error"
        assert path.exists()
        current = os.lstat(path)
        assert (current.st_dev, current.st_ino) == replacement_identity
    finally:
        replacement.close()
        path.unlink(missing_ok=True)


def send_stub_request(port: int, path: str) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n\r\n".encode("ascii"))
        return connection.recv(4096)


def test_synthetic_ollama_stub_is_bound_before_worker_and_observes_exact_requests() -> None:
    server = PROBE.bind_stub_ollama(port=0)
    port = int(server.getsockname()[1])
    outcomes: list[str] = []
    errors: list[BaseException] = []
    stop = threading.Event()
    worker = threading.Thread(
        target=PROBE.stub_ollama,
        args=(server, stop, outcomes, errors),
        daemon=True,
    )
    # The parent-owned listener is ready even before the worker starts.
    queued = socket.create_connection(("127.0.0.1", port), timeout=2)
    worker.start()
    queued.sendall(b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n\r\n")
    assert b"200 OK" in queued.recv(4096)
    queued.close()
    assert b"200 OK" in send_stub_request(port, "/api/tags")
    assert b"200 OK" in send_stub_request(port, "/api/show")
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert outcomes == ["/api/version", "/api/tags", "/api/show"]
    assert errors == []
    assert server.fileno() == -1


def test_synthetic_ollama_stub_captures_failure_and_cleans_listener() -> None:
    server = PROBE.bind_stub_ollama(port=0)
    port = int(server.getsockname()[1])
    outcomes: list[str] = []
    errors: list[BaseException] = []
    stop = threading.Event()
    worker = threading.Thread(
        target=PROBE.stub_ollama,
        args=(server, stop, outcomes, errors),
        daemon=True,
    )
    worker.start()
    send_stub_request(port, "/api/generate")
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert outcomes == []
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)
    assert stop.is_set()
    assert server.fileno() == -1


def test_synthetic_ollama_stub_cancellation_cleans_listener() -> None:
    server = PROBE.bind_stub_ollama(port=0)
    outcomes: list[str] = []
    errors: list[BaseException] = []
    stop = threading.Event()
    worker = threading.Thread(
        target=PROBE.stub_ollama,
        args=(server, stop, outcomes, errors),
        daemon=True,
    )
    worker.start()
    stop.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert outcomes == []
    assert errors == []
    assert server.fileno() == -1


@pytest.mark.skipif(os.name != "posix", reason="Synthetic listener authority is Linux-only")
def test_synthetic_upstream_ignores_occupied_production_port_and_retains_authority() -> None:
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    production_port_owned = False
    try:
        try:
            occupied.bind(("127.0.0.1", 11434))
            occupied.listen(1)
            production_port_owned = True
        except OSError:
            occupied.close()
        server = PROBE.bind_stub_ollama(port=0)
        try:
            authority = PROBE.synthetic_upstream_authority(server)
            assert authority.port != 11434
            PROBE.revalidate_synthetic_upstream(server, authority)
            stolen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(OSError):
                    stolen.bind((authority.host, authority.port))
            finally:
                stolen.close()
        finally:
            server.close()
    finally:
        if production_port_owned:
            occupied.close()


@pytest.mark.skipif(os.name != "posix", reason="Synthetic listener authority is Linux-only")
def test_synthetic_upstream_rejects_listener_substitution() -> None:
    first = PROBE.bind_stub_ollama(port=0)
    second = PROBE.bind_stub_ollama(port=0)
    try:
        expected = PROBE.synthetic_upstream_authority(first)
        with pytest.raises(ValueError, match="changed before launch"):
            PROBE.revalidate_synthetic_upstream(second, expected)
    finally:
        first.close()
        second.close()


@pytest.mark.skipif(os.name != "posix", reason="Synthetic listener authority is Linux-only")
def test_synthetic_upstream_rejects_close_and_rebind() -> None:
    first = PROBE.bind_stub_ollama(port=0)
    expected = PROBE.synthetic_upstream_authority(first)
    first.close()
    replacement = PROBE.bind_stub_ollama(host=expected.host, port=expected.port)
    try:
        with pytest.raises(ValueError, match="changed before launch"):
            PROBE.revalidate_synthetic_upstream(replacement, expected)
    finally:
        replacement.close()


@pytest.mark.skipif(os.name != "posix", reason="Synthetic listener authority is Linux-only")
def test_pre_worker_launch_failure_closes_retained_synthetic_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v7().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    profile = LinuxIsolationProfileV7.create(LinuxIsolationProfilePayloadV7.model_validate(raw))
    capture = PROBE.ProbeProcessCapture()
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE, "namespace_command", lambda *_args: ["unreachable"])

    def fail_launch(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic launch failure")

    monkeypatch.setattr(PROBE.subprocess, "Popen", fail_launch)
    with pytest.raises(PROBE.ProbePhaseFailure) as error:
        PROBE.run_probe(
            profile,
            Path("/repo/src/devhub/linux_native_isolation_child.py"),
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.phase == "namespace_creation"
    assert isinstance(error.value.__cause__, OSError)
    assert str(error.value.__cause__) == "synthetic launch failure"
    assert server.fileno() == -1
    assert capture.process_started is False
    assert capture.returncode is None


@pytest.mark.skipif(os.name != "posix", reason="Synthetic broker authority is Linux-only")
def test_broker_accepts_only_current_retained_synthetic_upstream(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    server = PROBE.bind_stub_ollama(port=0)
    try:
        authority = PROBE.synthetic_upstream_authority(server)
        peer = LinuxBrokerPeerAuthorityV1(outer_pid=1, outer_uid=1, start_time_ticks=1)
        runtime = LinuxMetadataBrokerV1(
            tmp_path / "ollama.sock", peer, synthetic_upstream=authority
        )
        assert (runtime.destination_host, runtime.destination_port) == (
            authority.host,
            authority.port,
        )
        wrong_owner = authority.model_copy(update={"owner_pid": authority.owner_pid + 1})
        with pytest.raises(ValueError, match="owner authority differs"):
            LinuxMetadataBrokerV1(tmp_path / "other.sock", peer, synthetic_upstream=wrong_owner)
    finally:
        server.close()


@pytest.mark.parametrize("abi", [3, 4])
def test_landlock_abi3_and_abi4_have_reviewed_mask(abi: int) -> None:
    assert landlock_handled_access(abi) == (1 << 15) - 1


@pytest.mark.parametrize("abi", [5, 6])
def test_landlock_abi5_and_abi6_include_ioctl_dev(abi: int) -> None:
    assert landlock_handled_access(abi) == (1 << 16) - 1


@pytest.mark.parametrize("abi", [0, 2, 7])
def test_landlock_rejects_unreviewed_abi(abi: int) -> None:
    with pytest.raises(ValueError, match="exactly Landlock ABI 3 through 6"):
        landlock_handled_access(abi)


@pytest.mark.parametrize(
    ("kernel_abi", "expected"),
    [(3, 3), (4, 4), (5, 5), (6, 6), (7, 6), (99, 6)],
)
def test_kernel_landlock_abi_uses_reviewed_policy_ceiling(kernel_abi: int, expected: int) -> None:
    assert enforced_landlock_abi(kernel_abi) == expected


@pytest.mark.parametrize("kernel_abi", [0, 1, 2])
def test_kernel_landlock_abi_below_minimum_fails_closed(kernel_abi: int) -> None:
    with pytest.raises(ValueError, match="kernel ABI 3 or newer"):
        enforced_landlock_abi(kernel_abi)


def test_child_independently_derives_reviewed_policy_from_kernel_abi() -> None:
    source = (ROOT / "src/devhub/linux_native_isolation_child.py").read_text(encoding="utf-8")
    assert "kernel_abi = landlock_abi()" in source
    assert "policy_abi = enforced_landlock_abi(kernel_abi)" in source
    assert "landlock_handled_access(policy_abi)" in source


@pytest.mark.skipif(os.name != "posix", reason="Isolated child policy is Linux-only")
def test_child_seals_empty_private_dev_before_landlock(tmp_path: Path) -> None:
    assert CHILD is not None
    assert CHILD.validate_private_dev(tmp_path) is True
    (tmp_path / "unexpected").write_bytes(b"")
    with pytest.raises(ValueError, match="unexpected entry"):
        CHILD.validate_private_dev(tmp_path)

    source = inspect.getsource(CHILD.run_post_registration)
    assert source.count("minimal_dev = validate_private_dev()") == 1
    assert source.index("minimal_dev = validate_private_dev()") < source.index('stage = "landlock"')
    assert 'Path("/dev").iterdir()' not in source
    assert 'Path("/dev/forbidden").write_text' in source


@pytest.mark.skipif(os.name != "posix", reason="Isolated child policy is Linux-only")
def test_child_landlock_keeps_dev_outside_reviewed_read_targets() -> None:
    assert CHILD is not None
    assert tuple(path for path, _access in CHILD.landlock_rules()) == RULE_TARGETS
    assert "/dev" not in RULE_TARGETS


@pytest.mark.skipif(os.name != "posix", reason="Isolated child policy is Linux-only")
def test_nonempty_private_dev_fails_before_landlock_or_result_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert CHILD is not None
    recorded: dict[str, object] = {}
    monkeypatch.setattr(CHILD, "private_root", lambda *_args: None)
    monkeypatch.setattr(CHILD.os, "chroot", lambda _path: None)
    monkeypatch.setattr(CHILD.os, "chdir", lambda _path: None)
    monkeypatch.setattr(
        CHILD,
        "validate_private_dev",
        lambda: (_ for _ in ()).throw(ValueError("Private /dev contains an unexpected entry")),
    )
    monkeypatch.setattr(
        CHILD,
        "apply_landlock",
        lambda: (_ for _ in ()).throw(AssertionError("Landlock must not run")),
    )
    monkeypatch.setattr(
        CHILD,
        "write_frame",
        lambda *_args: (_ for _ in ()).throw(AssertionError("Result must not be published")),
    )

    def record_failure(
        descriptor: int,
        stage: str,
        profile_id: str,
        environment_id: str,
        broker_failure: object,
        packaged_mcp_failure: object,
    ) -> None:
        recorded.update(
            descriptor=descriptor,
            stage=stage,
            profile_id=profile_id,
            environment_id=environment_id,
            broker_failure=broker_failure,
            packaged_mcp_failure=packaged_mcp_failure,
        )

    monkeypatch.setattr(CHILD, "write_runtime_failure", record_failure)
    args = SimpleNamespace(
        root=tmp_path / "root",
        bundle=tmp_path / "bundle",
        state=tmp_path / "state",
        output=tmp_path / "output",
        broker=tmp_path / "broker",
        mount_binary="/bin/mount",
        result_fd=9,
        linux_isolation_profile_id=H,
        environment_instance_id=ENVIRONMENT,
    )
    with pytest.raises(SystemExit) as error:
        CHILD.run_post_registration(args, LINUX_APPARMOR_CURRENT, {}, {})
    assert error.value.code == 71
    assert recorded == {
        "descriptor": 9,
        "stage": "private_root",
        "profile_id": H,
        "environment_id": ENVIRONMENT,
        "broker_failure": None,
        "packaged_mcp_failure": None,
    }


def test_v3_rejects_kernel_policy_and_observation_tampering() -> None:
    raw_host = profile_payload().host.model_dump(mode="python")
    raw_host["enforced_landlock_abi"] = 5
    with pytest.raises(ValidationError, match="policy ceiling"):
        LinuxHostAuthorityV3.model_validate(raw_host)

    raw_observation = observation().model_dump(mode="python")
    raw_observation["enforced_landlock_abi"] = 5
    with pytest.raises(ValidationError, match="policy ceiling"):
        LinuxIsolationObservationV3.model_validate(raw_observation)

    profile = LinuxIsolationProfileV3.create(profile_payload())
    changed = observation().model_copy(update={"kernel_landlock_abi": 8})
    receipt = LinuxIsolationReceiptV3.create(
        LinuxIsolationReceiptPayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=changed,
        )
    )
    with pytest.raises(ValidationError, match="kernel ABI differs"):
        evidence_payload(profile, receipt)


def test_mount_parser_requires_exact_private_root_options() -> None:
    lines = [
        "1 0 0:1 / / rw,nosuid,nodev - tmpfs tmpfs rw",
        "2 1 0:2 / /bundle ro,nosuid,nodev - ext4 /dev/x ro",
        "3 1 0:3 / /dev rw,nosuid,noexec - tmpfs tmpfs rw",
        "4 1 0:4 / /home/devfabric rw,nosuid,nodev,noexec - tmpfs tmpfs rw",
        "5 1 0:5 / /output rw,nosuid,nodev,noexec - ext4 /dev/x rw",
        "6 1 0:6 / /proc rw,nosuid,nodev,noexec - proc proc rw",
        "7 1 0:7 / /run/devfabric ro,nosuid,nodev,noexec - ext4 /dev/x ro",
        "8 1 0:8 / /state rw,nosuid,nodev,noexec - ext4 /dev/x rw",
        "9 1 0:9 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw",
    ]
    raw = ("\n".join(lines) + "\n").encode()
    assert observed_private_mount_targets(raw, MOUNT_TARGETS) == MOUNT_TARGETS
    if CHILD is not None:
        assert CHILD.observed_private_mount_targets(raw, MOUNT_TARGETS) == MOUNT_TARGETS
    with pytest.raises(ValueError, match="weaker options"):
        observed_private_mount_targets(
            raw.replace(b"ro,nosuid,nodev - ext4", b"rw - ext4", 1), MOUNT_TARGETS
        )


def test_namespace_command_uses_keep_caps_and_bound_bootstrap() -> None:
    profile = LinuxIsolationProfileV9.create(profile_payload_v9())
    command = PROBE.namespace_command(
        profile,
        Path("/repo/src/devhub/linux_native_isolation_child.py"),
        Path("/tmp/root"),
        Path("/tmp/fixture"),
        Path("/tmp/state"),
        Path("/tmp/output"),
        Path("/tmp/broker"),
        10,
        11,
        {"user": "user:[1]", "mnt": "mnt:[2]", "pid": "pid:[3]", "net": "net:[4]"},
    )
    assert "--keep-caps" in command
    python_index = command.index("--net") + 1
    assert command[python_index : python_index + 2] == [
        profile.payload.bootstrap_python.locator,
        str(Path("/repo/src/devhub/linux_native_isolation_child.py")),
    ]
    assert command[0] == "/opt/devfabric/libexec/unshare"
    assert command[command.index("--expected-apparmor-current") + 1] == LINUX_APPARMOR_CURRENT
    assert command[command.index("--expected-kernel-landlock-abi") + 1] == "7"
    assert command[command.index("--expected-enforced-landlock-abi") + 1] == "6"
    assert json.loads(command[command.index("--expected-mount-authority") + 1]) == (
        profile.payload.mount.model_dump(mode="json")
    )
    assert json.loads(command[command.index("--expected-mount-version-environment") + 1]) == (
        profile.payload.mount_version_environment.model_dump(mode="json")
    )
    assert command[command.index("--expected-overflow-uid") + 1] == "65534"
    assert command[command.index("--expected-overflow-gid") + 1] == "65534"
    assert "--dependency" not in command


def test_v13_namespace_command_uses_exact_installed_child_module() -> None:
    profile = LinuxIsolationProfileV13.create(profile_payload_v13())
    command = PROBE.namespace_command(
        profile,
        Path("/bundle/python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"),
        Path("/tmp/root"),
        Path("/tmp/fixture"),
        Path("/tmp/state"),
        Path("/tmp/output"),
        Path("/tmp/broker"),
        10,
        11,
        {"user": "user:[1]", "mnt": "mnt:[2]", "pid": "pid:[3]", "net": "net:[4]"},
    )
    python_index = command.index("--net") + 1
    assert command[python_index : python_index + 5] == [
        profile.payload.bootstrap_python.locator,
        "-I",
        "-B",
        "-m",
        "devhub.linux_native_isolation_child",
    ]
    assert command[command.index("--expected-python-sha256") + 1] == (
        profile.payload.package.python_executable_sha256
    )
    assert command[command.index("--expected-child-module-sha256") + 1] == (
        profile.payload.package.child_module_sha256
    )
    assert str(ROOT / "scripts/linux_native_isolation_child.py") not in command


def test_v13_profile_and_observation_bind_exact_package_authority() -> None:
    profile = LinuxIsolationProfileV13.create(profile_payload_v13())
    observed = observation_v13()
    receipt = LinuxIsolationReceiptV13.create(
        LinuxIsolationReceiptPayloadV13(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observed,
        )
    )

    assert profile.payload.package.bundle_schema_version == 6
    assert profile.payload.package.archive_schema_version == 6
    assert profile.payload.package.build_id == "linux-build-012"
    assert profile.payload.package.package_implementation_commit == (
        "c272ed6169a718204f2830a4aa34a5548a650652"
    )
    assert profile.payload.package.build_run_id == 38354927618
    assert profile.payload.package.bundle_run_id == 38359494446
    assert (
        profile.payload.package.bundle_workflow_path == ".github/workflows/linux-native-bundle.yml"
    )
    assert profile.payload.package.bundle_id == profile.payload.native_bundle_id
    assert observed.child_module_sha256 == profile.payload.package.child_module_sha256
    assert observed.packaged_mcp.tools_call_sent is False
    assert observed.packaged_mcp.module_origin.endswith("/devhub/delegate_server.py")
    evidence = LinuxIsolationEvidenceV13.create(evidence_payload_v13(profile, receipt))
    assert evidence.payload.receipt.payload.model_requests == 0

    tampered = profile.payload.model_dump(mode="python")
    tampered["package"]["child_module_sha256"] = "f" * 64
    with pytest.raises(ValidationError):
        LinuxIsolationProfilePayloadV13.model_validate(tampered)

    wrong_workflow = profile.payload.model_dump(mode="python")
    wrong_workflow["package"]["bundle_workflow_path"] = ".github/workflows/linux-native-codex.yml"
    with pytest.raises(ValidationError):
        LinuxIsolationProfilePayloadV13.model_validate(wrong_workflow)

    for field, value in (
        ("package_implementation_commit", "f" * 40),
        ("build_run_id", 1),
        ("bundle_run_id", 1),
        ("archive_id", "f" * 64),
        ("bundle_id", "f" * 64),
    ):
        substituted = profile.payload.model_dump(mode="python")
        substituted["package"][field] = value
        with pytest.raises(ValidationError):
            LinuxIsolationProfilePayloadV13.model_validate(substituted)

    mismatched_observation = observed.model_copy(update={"child_module_sha256": "f" * 64})
    mismatched_receipt = LinuxIsolationReceiptV13.create(
        LinuxIsolationReceiptPayloadV13(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=mismatched_observation,
        )
    )
    with pytest.raises(ValidationError, match="package observation authority differs"):
        evidence_payload_v13(profile, mismatched_receipt)

    mismatched_python = observed.model_copy(
        update={
            "packaged_mcp": observed.packaged_mcp.model_copy(
                update={"python_executable_sha256": "f" * 64}
            )
        }
    )
    mismatched_python_receipt = LinuxIsolationReceiptV13.create(
        LinuxIsolationReceiptPayloadV13(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=mismatched_python,
        )
    )
    with pytest.raises(ValidationError, match="package observation authority differs"):
        evidence_payload_v13(profile, mismatched_python_receipt)


def test_v14_profile_and_observation_bind_exact_bundle_v7_split_authority() -> None:
    profile = LinuxIsolationProfileV14.create(profile_payload_v14())
    observed = observation_v14()
    receipt = LinuxIsolationReceiptV14.create(
        LinuxIsolationReceiptPayloadV14(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observed,
        )
    )
    evidence = LinuxIsolationEvidenceV14.create(evidence_payload_v14(profile, receipt))
    package = profile.payload.package

    assert package.bundle_schema_version == 7
    assert package.archive_schema_version == 7
    assert package.package_implementation_commit == ("0c39acf9afca1106985a1c35fca846c86d5789c7")
    assert package.retained_codex_implementation_commit == (
        "c272ed6169a718204f2830a4aa34a5548a650652"
    )
    assert package.bundle_run_id == 38374815599
    assert package.bundle_run_attempt == 1
    assert package.bundle_id == profile.payload.native_bundle_id
    assert package.child_module_sha256 == observed.child_module_sha256
    assert profile.payload.child_runtime_failure_protocol == "linux_child_runtime_failure_v3"
    assert evidence.payload.receipt.payload.model_requests == 0
    assert evidence.payload.receipt.payload.provider_sends == 0
    assert evidence.payload.receipt.payload.mcp_tool_executions == 0
    assert evidence.payload.receipt.payload.real_task_executions == 0
    assert evidence.payload.receipt.payload.native_executor_isolation_qualified is False
    assert evidence.payload.receipt.payload.package_readiness is False

    for field, value in (
        ("package_implementation_commit", "f" * 40),
        ("retained_codex_implementation_commit", "f" * 40),
        ("bundle_run_id", 1),
        ("archive_id", "f" * 64),
        ("bundle_id", "f" * 64),
        ("python_runtime_id", "f" * 64),
        ("child_module_sha256", "f" * 64),
    ):
        substituted = profile.payload.model_dump(mode="python")
        substituted["package"][field] = value
        with pytest.raises(ValidationError):
            LinuxIsolationProfilePayloadV14.model_validate(substituted)


def test_v14_failure_accepts_only_bound_child_runtime_failure_v3() -> None:
    profile = LinuxIsolationProfileV14.create(profile_payload_v14())
    child = LinuxChildRuntimeFailureV3.create(
        LinuxChildRuntimeFailurePayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            stage="result_assembly",
            reason_code="result_assembly_failed",
            packaged_mcp_checkpoint="observation_assembly",
        )
    )
    failure = LinuxIsolationFailureV8.create(
        LinuxIsolationFailurePayloadV8(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            phase="child_result",
            reason_code="child_output_invalid",
            child_stdout_retained_sha256=digest(b""),
            child_stderr_retained_sha256=digest(b""),
            child_stdout_truncated=False,
            child_stderr_truncated=False,
            cleanup_attempted=True,
            cleanup_succeeded=True,
            child_process_started=True,
            child_returncode=71,
            child_stdout_retained_bytes=0,
            child_stderr_retained_bytes=0,
            child_stdout_observed_bytes=0,
            child_stderr_observed_bytes=0,
            child_runtime_failure=child,
        )
    )
    assert failure.payload.child_runtime_failure == child

    wrong_environment = failure.payload.model_dump(mode="python")
    wrong_environment["child_runtime_failure"]["payload"]["environment_instance_id"] = "f" * 32
    wrong_environment["child_runtime_failure"]["child_runtime_failure_id"] = digest(
        canonical(wrong_environment["child_runtime_failure"]["payload"])
    )
    with pytest.raises(ValidationError, match="authority differs"):
        LinuxIsolationFailurePayloadV8.model_validate(wrong_environment)

    legacy = failure.payload.model_dump(mode="python")
    legacy["child_runtime_failure"] = LinuxChildRuntimeFailureV2.create(
        LinuxChildRuntimeFailurePayloadV2(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            stage="result_assembly",
            reason_code="result_assembly_failed",
        )
    ).model_dump(mode="python")
    with pytest.raises(ValidationError):
        LinuxIsolationFailurePayloadV8.model_validate(legacy)


def test_v12_profile_remains_historical_and_parseable() -> None:
    historical = LinuxIsolationProfileV12.create(historical_profile_payload_v12())
    reparsed = LinuxIsolationProfileV12.model_validate_json(historical.model_dump_json())

    assert reparsed == historical
    assert reparsed.schema_version == 12
    assert reparsed.payload.package.build_id == "linux-build-011"
    assert reparsed.payload.profile_kind == "linux_native_isolation_v12"


def test_v12_and_v13_package_authorities_cannot_be_mixed() -> None:
    current = profile_payload_v13().model_dump(mode="python")
    current["package"] = historical_package_authority_v1().model_dump(mode="python")
    with pytest.raises(ValidationError):
        LinuxIsolationProfilePayloadV13.model_validate(current)

    historical = historical_profile_payload_v12().model_dump(mode="python")
    historical["package"] = package_authority().model_dump(mode="python")
    with pytest.raises(ValidationError):
        LinuxIsolationProfilePayloadV12.model_validate(historical)


def test_v13_bundle_v6_profile_remains_historical_and_parseable() -> None:
    historical = LinuxIsolationProfileV13.create(profile_payload_v13())
    reparsed = LinuxIsolationProfileV13.model_validate_json(historical.model_dump_json())

    assert reparsed == historical
    assert reparsed.payload.package.bundle_schema_version == 6
    assert reparsed.payload.package.bundle_run_id == 38359494446


@pytest.mark.skipif(os.name != "posix", reason="Isolated child bootstrap is Linux-only")
def test_child_bootstrap_is_stdlib_only_and_matches_host_helpers() -> None:
    assert CHILD is not None
    source = (ROOT / "src/devhub/linux_native_isolation_child.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    roots: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.split(".", 1)[0])
    assert "devhub" not in roots
    assert "pydantic" not in roots
    assert '"tools/call"' not in source
    assert roots - {"__future__"} <= sys.stdlib_module_names
    for abi in (3, 4, 5, 6):
        assert CHILD.landlock_handled_access(abi) == landlock_handled_access(abi)
    for kernel_abi in (3, 6, 7):
        assert CHILD.enforced_landlock_abi(kernel_abi) == enforced_landlock_abi(kernel_abi)
    value = cast(
        JsonValue,
        {"rlimits": LinuxRlimitsV1().model_dump(mode="json"), "rules": [["/tmp", 1]]},
    )
    assert CHILD.canonical(value) == canonical(value)
    assert CHILD.digest(CHILD.canonical(value)) == digest(canonical(value))


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_subprocess_is_bounded_and_observes_eof() -> None:
    assert CHILD is not None
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    returncode, stdout, stderr = CHILD.run_bounded_subprocess(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)",
        ],
        environment=environment,
        input_data=b"exact-input",
        timeout=5,
    )
    assert (returncode, stdout, stderr) == (0, b"exact-input", b"")

    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure, match="retained bound") as error:
        CHILD.run_bounded_subprocess(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * (1024 * 1024 + 1))",
            ],
            environment=environment,
            input_data=None,
            timeout=5,
        )
    capture = error.value.capture
    assert capture["stdout_retained_bytes"] == 1024 * 1024
    assert cast(int, capture["stdout_observed_bytes"]) > 1024 * 1024
    assert capture["stdout_truncated"] is True
    assert capture["output_limit_exceeded"] is True


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_timeout_capture_is_final_and_started() -> None:
    assert CHILD is not None
    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure, match="timed out") as error:
        CHILD.run_bounded_subprocess(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(10)"],
            environment={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            input_data=None,
            timeout=0.05,
        )
    assert error.value.capture["process_started"] is True
    assert error.value.capture["returncode"] is None
    assert error.value.capture["timed_out"] is True
    assert error.value.capture["stdout_observed_bytes"] == 0
    assert error.value.capture["stderr_observed_bytes"] == 0


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_post_kill_wait_failure_keeps_timeout_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class Process:
        def __init__(self) -> None:
            self.pid = 6420
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(b"final")
            self.stderr = io.BytesIO()
            self.returncode: int | None = None
            self.wait_count = 0

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            self.wait_count += 1
            if self.wait_count == 1:
                raise CHILD.subprocess.TimeoutExpired(["python"], timeout)
            if self.wait_count == 2:
                raise OSError("injected post-kill wait failure")
            self.returncode = -9
            return self.returncode

    process = Process()

    def killpg(_pid: int, _signal_number: int) -> None:
        process.returncode = -9

    monkeypatch.setattr(CHILD.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(CHILD.os, "killpg", killpg)

    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure) as captured:
        CHILD.run_bounded_subprocess(
            ["/bundle/python/bin/python3.12", "-I", "-B"],
            environment={"PATH": "/usr/bin:/bin"},
            input_data=None,
            timeout=0.05,
        )
    assert captured.value.capture["process_started"] is True
    assert captured.value.capture["timed_out"] is True
    assert captured.value.capture["returncode"] is None
    assert captured.value.capture["stdout_retained_bytes"] == len(b"final")
    assert isinstance(captured.value.__cause__, OSError)
    assert "post-kill wait failure" in str(captured.value.__cause__)


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_closes_pipe_and_kills_group_after_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class FailingInput(io.BytesIO):
        def write(self, data: bytes, /) -> int:
            del data
            raise OSError("injected write failure")

    class Process:
        def __init__(self) -> None:
            self.pid = 1234
            self.stdin = FailingInput()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode: int | None = None
            self.waits: list[float | None] = []

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            self.waits.append(timeout)
            if self.returncode is None:
                self.returncode = 0
            return self.returncode

    process = Process()
    popen_arguments: dict[str, object] = {}

    def popen(command: list[str], **kwargs: object) -> Process:
        popen_arguments["command"] = command
        popen_arguments.update(kwargs)
        return process

    killed: list[tuple[int, int]] = []

    def killpg(pid: int, signal_number: int) -> None:
        killed.append((pid, signal_number))
        process.returncode = -signal_number

    monkeypatch.setattr(CHILD.subprocess, "Popen", popen)
    monkeypatch.setattr(CHILD.os, "killpg", killpg)

    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure) as captured:
        CHILD.run_bounded_subprocess(
            ["/bundle/python/bin/python3.12", "-I", "-B"],
            environment={"PATH": "/usr/bin:/bin"},
            input_data=b"request",
            timeout=5,
        )

    assert isinstance(captured.value.__cause__, OSError)
    assert "injected write failure" in str(captured.value.__cause__)
    assert captured.value.capture["process_started"] is True
    assert popen_arguments["stdin"] is subprocess.PIPE
    assert popen_arguments["stdout"] is subprocess.PIPE
    assert popen_arguments["stderr"] is subprocess.PIPE
    assert killed == [(process.pid, CHILD.signal.SIGKILL)]
    assert process.waits == [5]
    assert process.stdin.closed is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_preserves_primary_and_cleanup_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class FailingInput(io.BytesIO):
        def write(self, data: bytes, /) -> int:
            del data
            raise OSError("primary write failure")

    class TrackedOutput(io.BytesIO):
        def __init__(self, *, fail_close: bool = False) -> None:
            super().__init__()
            self.close_attempted = False
            self.fail_close = fail_close

        def close(self) -> None:
            self.close_attempted = True
            if self.fail_close:
                raise OSError("cleanup close failure")
            super().close()

    class Process:
        def __init__(self) -> None:
            self.pid = 4321
            self.stdin = FailingInput()
            self.stdout = TrackedOutput()
            self.stderr = TrackedOutput(fail_close=True)
            self.returncode: int | None = None
            self.wait_attempted = False

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            self.wait_attempted = True
            raise OSError("cleanup wait failure")

    process = Process()
    kill_attempted = False

    def killpg(pid: int, signal_number: int) -> None:
        del pid, signal_number
        nonlocal kill_attempted
        kill_attempted = True
        raise OSError("cleanup kill failure")

    monkeypatch.setattr(CHILD.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(CHILD.os, "killpg", killpg)

    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure) as captured:
        CHILD.run_bounded_subprocess(
            ["/bundle/python/bin/python3.12", "-I", "-B"],
            environment={"PATH": "/usr/bin:/bin"},
            input_data=b"request",
            timeout=5,
        )

    assert isinstance(captured.value.__cause__, BaseExceptionGroup)
    messages = {str(error) for error in captured.value.__cause__.exceptions}
    assert "primary write failure" in messages
    assert "cleanup kill failure" in messages
    assert "cleanup wait failure" in messages
    assert "cleanup close failure" in messages
    assert kill_attempted is True
    assert process.wait_attempted is True
    assert process.stdin.closed is True
    assert process.stdout.close_attempted is True
    assert process.stderr.close_attempted is True
    assert captured.value.capture["process_started"] is True


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_missing_stream_is_typed_as_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class Process:
        def __init__(self) -> None:
            self.pid = 2468
            self.stdin = None
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            self.returncode = -9
            return self.returncode

    process = Process()
    monkeypatch.setattr(CHILD.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(CHILD.os, "killpg", lambda *_args: None)

    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure) as captured:
        CHILD.run_bounded_subprocess(
            ["/bundle/python/bin/python3.12", "-I", "-B"],
            environment={"PATH": "/usr/bin:/bin"},
            input_data=None,
            timeout=5,
        )
    assert captured.value.capture == {
        "schema_version": 1,
        "process_started": True,
        "returncode": -9,
        "stdout_retained_bytes": 0,
        "stdout_observed_bytes": 0,
        "stdout_retained_sha256": CHILD.sha256(b""),
        "stdout_truncated": False,
        "stderr_retained_bytes": 0,
        "stderr_observed_bytes": 0,
        "stderr_retained_sha256": CHILD.sha256(b""),
        "stderr_truncated": False,
        "timed_out": False,
        "output_limit_exceeded": False,
    }


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_unexpected_wait_failure_is_typed_as_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class Process:
        def __init__(self) -> None:
            self.pid = 9753
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode: int | None = None
            self.wait_count = 0

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            self.wait_count += 1
            if self.wait_count == 1:
                raise OSError("injected wait failure")
            self.returncode = -9
            return self.returncode

    process = Process()

    def killpg(_pid: int, _signal_number: int) -> None:
        process.returncode = -9

    monkeypatch.setattr(CHILD.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(CHILD.os, "killpg", killpg)

    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure) as captured:
        CHILD.run_bounded_subprocess(
            ["/bundle/python/bin/python3.12", "-I", "-B"],
            environment={"PATH": "/usr/bin:/bin"},
            input_data=None,
            timeout=5,
        )
    assert captured.value.capture["process_started"] is True
    assert isinstance(captured.value.__cause__, OSError)
    assert "injected wait failure" in str(captured.value.__cause__)


@pytest.mark.skipif(os.name != "posix", reason="Bounded child subprocess is Linux-only")
def test_packaged_observer_thread_start_failure_is_typed_as_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class Process:
        def __init__(self) -> None:
            self.pid = 8642
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            self.returncode = -9
            return self.returncode

    class Thread:
        def __init__(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

        def start(self) -> None:
            raise RuntimeError("injected thread start failure")

    process = Process()
    monkeypatch.setattr(CHILD.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(CHILD.threading, "Thread", Thread)
    monkeypatch.setattr(CHILD.os, "killpg", lambda *_args: None)

    with pytest.raises(CHILD.PackagedSubprocessExecutionFailure) as captured:
        CHILD.run_bounded_subprocess(
            ["/bundle/python/bin/python3.12", "-I", "-B"],
            environment={"PATH": "/usr/bin:/bin"},
            input_data=None,
            timeout=5,
        )
    assert captured.value.capture["process_started"] is True
    assert isinstance(captured.value.__cause__, RuntimeError)
    assert "injected thread start failure" in str(captured.value.__cause__)


@pytest.mark.skipif(os.name != "posix", reason="Packaged MCP observation is Linux-only")
def test_packaged_mcp_metadata_uses_exact_protocol_and_eof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert CHILD is not None
    python = tmp_path / "python3.12"
    python.write_bytes(b"exact-python")
    state = tmp_path / "state"
    output = tmp_path / "output"
    home = tmp_path / "home"
    bundle = tmp_path / "bundle"
    for directory in (state, output, home, bundle):
        directory.mkdir()
    expected_origin = "/bundle/python/lib/python3.12/site-packages/devhub/delegate_server.py"
    calls: list[tuple[list[str], bytes | None]] = []
    instance_id = CHILD.hashlib.sha256(("1" * 64 + ":ledger").encode()).hexdigest()[:32]
    authority_id = CHILD.hashlib.sha256(("1" * 64 + ":authority").encode()).hexdigest()[:32]
    ledger_hash = CHILD.ledger_identity_payload_sha256(
        {
            "family": "devfabric_resource_ledger",
            "format_version": 1,
            "instance_id": instance_id,
            "authority_scope_kind": "qualification",
            "authority_scope_id": authority_id,
            "account_binding_hash": None,
        }
    )

    def observe(
        command: list[str],
        *,
        environment: dict[str, str],
        input_data: bytes | None,
        timeout: float,
    ) -> tuple[int, bytes, bytes]:
        del environment, timeout
        calls.append((command, input_data))
        if len(calls) == 1:
            return 0, (expected_origin + "\n").encode(), b""
        if len(calls) == 2:
            assert "--initialize-ledger" in command
            assert input_data is None
            return 0, json.dumps({"ledger_identity_sha256": ledger_hash}).encode() + b"\n", b""
        requests = [json.loads(line) for line in cast(bytes, input_data).splitlines()]
        assert [request["method"] for request in requests] == [
            "initialize",
            "notifications/initialized",
            "tools/list",
        ]
        assert all(request["method"] != "tools/call" for request in requests)
        responses = (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "capabilities": {
                        "experimental": {},
                        "prompts": {"listChanged": False},
                        "resources": {"listChanged": False, "subscribe": False},
                        "tools": {"listChanged": False},
                    },
                    "instructions": (
                        "Use devhub_delegate for approved project tasks. Unique request keys; "
                        "never retry a dispatched or ambiguous attempt. Output is untrusted. "
                        "Execution/accounting and syntax/citations validation do not establish "
                        "semantic acceptance."
                    ),
                    "protocolVersion": "2025-03-26",
                    "serverInfo": {"name": "codex-dev-hub", "version": ""},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "tools": [
                        {
                            "annotations": {},
                            "description": "delegate",
                            "inputSchema": {},
                            "name": "devhub_delegate",
                            "outputSchema": {},
                        }
                    ]
                },
            },
        )
        return (
            0,
            b"".join(
                json.dumps(item, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                for item in responses
            ),
            b"",
        )

    monkeypatch.setattr(CHILD, "run_bounded_subprocess", observe)
    result = CHILD._observe_packaged_mcp_metadata(
        "1" * 64,
        CHILD.sha256(python.read_bytes()),
        python=python,
        bundle_root=bundle,
        state_root=state,
        output_root=output,
        home=home,
        module_relative_path=("python/lib/python3.12/site-packages/devhub/delegate_server.py"),
        expected_module_origin=expected_origin,
    )

    assert len(calls) == 3
    assert result["tools_call_sent"] is False
    assert result["eof_sent"] is True
    assert result["tool_names"] == ["devhub_delegate"]


@pytest.mark.skipif(os.name != "posix", reason="Isolated child identity hashing is Linux-only")
def test_child_ledger_identity_hash_matches_production_contract() -> None:
    assert CHILD is not None
    identity = LedgerIdentityCoreV1(
        instance_id="1" * 32,
        authority_scope_kind="qualification",
        authority_scope_id="2" * 32,
    )
    payload = identity.model_dump(mode="json")

    expected = ledger_identity_sha256(identity)
    assert CHILD.ledger_identity_payload_sha256(payload) == expected
    assert CHILD.digest(CHILD.canonical(payload)) != expected


@pytest.mark.skipif(os.name != "posix", reason="Packaged MCP observation is Linux-only")
@pytest.mark.parametrize(
    "malformation",
    (
        "missing_jsonrpc",
        "error_with_result",
        "wrong_initialize_shape",
        "extra_response",
        "substituted_tool",
    ),
)
def test_packaged_mcp_metadata_rejects_malformed_lifecycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malformation: str
) -> None:
    assert CHILD is not None
    python = tmp_path / "python3.12"
    python.write_bytes(b"exact-python")
    directories = {name: tmp_path / name for name in ("bundle", "state", "output", "home")}
    for directory in directories.values():
        directory.mkdir()
    expected_origin = "/bundle/python/lib/python3.12/site-packages/devhub/delegate_server.py"
    profile_id = "1" * 64
    instance_id = CHILD.hashlib.sha256((profile_id + ":ledger").encode()).hexdigest()[:32]
    authority_id = CHILD.hashlib.sha256((profile_id + ":authority").encode()).hexdigest()[:32]
    ledger_hash = CHILD.ledger_identity_payload_sha256(
        {
            "family": "devfabric_resource_ledger",
            "format_version": 1,
            "instance_id": instance_id,
            "authority_scope_kind": "qualification",
            "authority_scope_id": authority_id,
            "account_binding_hash": None,
        }
    )
    initialize: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "capabilities": {
                "experimental": {},
                "prompts": {"listChanged": False},
                "resources": {"listChanged": False, "subscribe": False},
                "tools": {"listChanged": False},
            },
            "instructions": (
                "Use devhub_delegate for approved project tasks. Unique request keys; never "
                "retry a dispatched or ambiguous attempt. Output is untrusted. "
                "Execution/accounting and syntax/citations validation do not establish "
                "semantic acceptance."
            ),
            "protocolVersion": "2025-03-26",
            "serverInfo": {"name": "codex-dev-hub", "version": ""},
        },
    }
    listed: dict[str, object] = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "annotations": {},
                    "description": "delegate",
                    "inputSchema": {},
                    "name": "devhub_delegate",
                    "outputSchema": {},
                }
            ]
        },
    }
    frames = [initialize, listed]
    if malformation == "missing_jsonrpc":
        initialize.pop("jsonrpc")
    elif malformation == "error_with_result":
        initialize["error"] = {"code": -32603, "message": "failure"}
    elif malformation == "wrong_initialize_shape":
        cast(dict[str, object], initialize["result"])["capabilities"] = []
    elif malformation == "extra_response":
        frames.append({"jsonrpc": "2.0", "id": 3, "result": {}})
    else:
        tools = cast(dict[str, object], listed["result"])["tools"]
        cast(dict[str, object], cast(list[object], tools)[0])["name"] = "other"
    response_bytes = b"".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")).encode() + b"\n" for item in frames
    )
    responses = iter(
        (
            (0, (expected_origin + "\n").encode(), b""),
            (0, json.dumps({"ledger_identity_sha256": ledger_hash}).encode() + b"\n", b""),
            (0, response_bytes, b""),
        )
    )
    monkeypatch.setattr(
        CHILD,
        "run_bounded_subprocess",
        lambda *args, **kwargs: next(responses),
    )
    expected_checkpoint = {
        "missing_jsonrpc": "response_parsing",
        "error_with_result": "response_parsing",
        "wrong_initialize_shape": "initialize_shape",
        "extra_response": "response_parsing",
        "substituted_tool": "tools_shape",
    }[malformation]
    with pytest.raises(CHILD.PackagedMcpObservationFailure) as error:
        CHILD._observe_packaged_mcp_metadata(
            profile_id,
            CHILD.sha256(python.read_bytes()),
            python=python,
            bundle_root=directories["bundle"],
            state_root=directories["state"],
            output_root=directories["output"],
            home=directories["home"],
            module_relative_path=("python/lib/python3.12/site-packages/devhub/delegate_server.py"),
            expected_module_origin=expected_origin,
        )
    assert error.value.checkpoint == expected_checkpoint
    assert error.value.capture is not None


@pytest.mark.skipif(os.name != "posix", reason="Packaged MCP observation is Linux-only")
@pytest.mark.parametrize(
    "malformation", ("wrong_hash", "former_pretty_hash", "extra_line", "stderr")
)
def test_packaged_mcp_metadata_rejects_malformed_ledger_initialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malformation: str
) -> None:
    assert CHILD is not None
    python = tmp_path / "python3.12"
    python.write_bytes(b"exact-python")
    directories = {name: tmp_path / name for name in ("bundle", "state", "output", "home")}
    for directory in directories.values():
        directory.mkdir()
    expected_origin = "/bundle/python/lib/python3.12/site-packages/devhub/delegate_server.py"
    profile_id = "1" * 64
    instance_id = CHILD.hashlib.sha256((profile_id + ":ledger").encode()).hexdigest()[:32]
    authority_id = CHILD.hashlib.sha256((profile_id + ":authority").encode()).hexdigest()[:32]
    identity_payload = {
        "family": "devfabric_resource_ledger",
        "format_version": 1,
        "instance_id": instance_id,
        "authority_scope_kind": "qualification",
        "authority_scope_id": authority_id,
        "account_binding_hash": None,
    }
    expected_hash = CHILD.ledger_identity_payload_sha256(identity_payload)
    retained_hash = expected_hash
    if malformation == "wrong_hash":
        retained_hash = "f" * 64
    elif malformation == "former_pretty_hash":
        retained_hash = CHILD.digest(CHILD.canonical(identity_payload))
        assert retained_hash != expected_hash
    stdout = json.dumps({"ledger_identity_sha256": retained_hash}).encode() + b"\n"
    stderr = b""
    if malformation == "extra_line":
        stdout += b"{}\n"
    elif malformation == "stderr":
        stderr = b"unexpected"
    responses = iter(
        (
            (0, (expected_origin + "\n").encode(), b""),
            (0, stdout, stderr),
        )
    )
    monkeypatch.setattr(
        CHILD,
        "run_bounded_subprocess",
        lambda *args, **kwargs: next(responses),
    )
    with pytest.raises(CHILD.PackagedMcpObservationFailure) as error:
        CHILD._observe_packaged_mcp_metadata(
            profile_id,
            CHILD.sha256(python.read_bytes()),
            python=python,
            bundle_root=directories["bundle"],
            state_root=directories["state"],
            output_root=directories["output"],
            home=directories["home"],
            module_relative_path=("python/lib/python3.12/site-packages/devhub/delegate_server.py"),
            expected_module_origin=expected_origin,
        )
    assert error.value.checkpoint == "ledger_initialization"
    assert error.value.capture is not None


@pytest.mark.skipif(os.name != "posix", reason="Packaged MCP observation is Linux-only")
def test_packaged_mcp_metadata_wrapper_binds_exact_release_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None
    observed: dict[str, object] = {}

    def capture(*args: object, **kwargs: object) -> dict[str, object]:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return {"tools_call_sent": False}

    monkeypatch.setattr(CHILD, "_observe_packaged_mcp_metadata", capture)
    assert CHILD.packaged_mcp_metadata_observation("1" * 64, "2" * 64) == {"tools_call_sent": False}
    kwargs = cast(dict[str, object], observed["kwargs"])
    assert kwargs["python"] == Path("/bundle/python/bin/python3.12")
    assert kwargs["bundle_root"] == Path("/bundle")
    assert kwargs["state_root"] == Path("/state")
    assert kwargs["output_root"] == Path("/output")
    assert kwargs["home"] == Path("/home/devfabric")


@pytest.mark.skipif(os.name != "posix", reason="Isolated child rlimits are Linux-only")
def test_child_rlimits_match_exact_profile_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None
    applied: dict[int, tuple[int, int]] = {}

    def setrlimit(kind: int, value: tuple[int, int]) -> None:
        applied[kind] = value

    def getrlimit(kind: int) -> tuple[int, int]:
        return applied[kind]

    monkeypatch.setattr(CHILD.resource, "setrlimit", setrlimit)
    monkeypatch.setattr(CHILD.resource, "getrlimit", getrlimit)

    observed = CHILD.set_limits()
    expected = LinuxRlimitsV1().model_dump(mode="json")
    assert applied == {
        CHILD.resource.RLIMIT_CPU: (60, 60),
        CHILD.resource.RLIMIT_AS: (2 * 1024**3, 2 * 1024**3),
        CHILD.resource.RLIMIT_FSIZE: (64 * 1024**2, 64 * 1024**2),
        CHILD.resource.RLIMIT_NOFILE: (128, 128),
        CHILD.resource.RLIMIT_NPROC: (32, 32),
        CHILD.resource.RLIMIT_CORE: (0, 0),
    }
    assert observed == expected

    expected_hash = digest(canonical(cast(JsonValue, expected)))
    assert CHILD.digest(CHILD.canonical(observed)) == expected_hash
    mutated = dict(observed)
    mutated["open_files"] += 1
    assert CHILD.digest(CHILD.canonical(mutated)) != expected_hash


def broker_observation_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    peer_pid: int = 0,
    peer_uid: int = 1000,
    inodes: tuple[int, ...] = (7, 7, 7, 7, 7),
    devices: tuple[int, ...] = (1, 1, 1, 1, 1),
    parent_mode: int = 0o700,
    socket_mode: int = 0o600,
    parent_modes: tuple[int, ...] | None = None,
    socket_modes: tuple[int, ...] | None = None,
    responses: tuple[bytes, ...] = (
        b"HTTP/1.1 200 OK",
        b"HTTP/1.1 200 OK",
        b"HTTP/1.1 200 OK",
        b"HTTP/1.1 403 Forbidden",
        b"HTTP/1.1 403 Forbidden",
    ),
) -> dict[str, bool | str | int]:
    assert CHILD is not None
    response_iterator = iter(
        zip(
            responses,
            devices,
            inodes,
            parent_modes or (parent_mode,) * 5,
            socket_modes or (socket_mode,) * 5,
            strict=True,
        )
    )

    def fail_outer_pid() -> int:
        raise AssertionError("post-chroot code must not inspect the outer PID")

    def unix_http(
        _checkpoint: str, _socket_path: str, _raw: bytes
    ) -> tuple[bytes, tuple[int, int, int], tuple[int, int], int, int]:
        response, device, inode, observed_parent_mode, observed_socket_mode = next(
            response_iterator
        )
        return (
            response,
            (peer_pid, peer_uid, 1000),
            (device, inode),
            observed_socket_mode,
            observed_parent_mode,
        )

    def fail_post_session_lstat(_path: object) -> os.stat_result:
        raise FileNotFoundError("broker socket was removed after the final response")

    monkeypatch.setattr(CHILD, "outer_pid", fail_outer_pid)
    monkeypatch.setattr(CHILD, "unix_http", unix_http)
    monkeypatch.setattr(CHILD.Path, "exists", lambda _path: True)
    monkeypatch.setattr(CHILD.os, "lstat", fail_post_session_lstat)
    return cast(dict[str, bool | str | int], CHILD.broker_observations())


@pytest.mark.skipif(os.name != "posix", reason="Isolated child broker is Linux-only")
def test_child_broker_connect_race_is_a_bounded_typed_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class RefusedSocket:
        def settimeout(self, _timeout: float) -> None:
            pass

        def connect(self, _path: str) -> None:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")

        def close(self) -> None:
            pass

    monkeypatch.setattr(CHILD.socket, "socket", lambda *_args: RefusedSocket())
    with pytest.raises(CHILD.BrokerObservationFailure) as error:
        CHILD.unix_http("version", "/run/devfabric/ollama.sock", b"request")
    assert (
        error.value.checkpoint,
        error.value.operation,
        error.value.reason_code,
        error.value.errno_category,
    ) == ("version", "connect", "broker_connect_failed", "connection_refused")


@pytest.mark.skipif(os.name != "posix", reason="Isolated child broker is Linux-only")
@pytest.mark.parametrize(
    ("failure_point", "checkpoint", "operation", "reason"),
    [
        (
            "peer_credentials",
            "version",
            "peer_credentials",
            "broker_peer_credentials_failed",
        ),
        ("path_stat", "tags", "path_stat", "broker_socket_stat_failed"),
    ],
)
def test_child_broker_os_failure_writer_reader_uses_exact_tuple(
    failure_point: str,
    checkpoint: str,
    operation: str,
    reason: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert CHILD is not None

    class FailingSocket:
        def settimeout(self, _timeout: float) -> None:
            pass

        def connect(self, _path: str) -> None:
            pass

        def getsockopt(self, *_args: object) -> bytes:
            if failure_point == "peer_credentials":
                raise PermissionError(errno.EACCES, "denied")
            return CHILD.struct.pack("3i", 0, 1000, 1000)

        def close(self) -> None:
            pass

    monkeypatch.setattr(CHILD.socket, "socket", lambda *_args: FailingSocket())
    if failure_point == "path_stat":
        monkeypatch.setattr(
            CHILD.os,
            "lstat",
            lambda _path: (_ for _ in ()).throw(PermissionError(errno.EACCES, "denied")),
        )
    with pytest.raises(CHILD.BrokerObservationFailure) as error:
        CHILD.unix_http(checkpoint, "/run/devfabric/ollama.sock", b"request")
    assert (
        error.value.checkpoint,
        error.value.operation,
        error.value.reason_code,
        error.value.errno_category,
    ) == (checkpoint, operation, reason, "permission_denied")
    frame = CHILD.runtime_failure_frame("broker", H, ENVIRONMENT, error.value)
    parsed = LinuxChildRuntimeFailureV3.model_validate(frame)
    assert parsed.payload.broker_operation == operation
    assert parsed.payload.reason_code == reason


@pytest.mark.skipif(os.name != "posix", reason="AF_UNIX bind/listen boundary is Linux-only")
def test_child_broker_real_bound_before_listen_race_is_typed(tmp_path: Path) -> None:
    assert CHILD is not None
    tmp_path.chmod(0o700)
    path = tmp_path / "ollama.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    path.chmod(0o600)
    try:
        assert path.exists()
        with pytest.raises(CHILD.BrokerObservationFailure) as error:
            CHILD.unix_http("version", str(path), b"request")
        assert (
            error.value.checkpoint,
            error.value.operation,
            error.value.reason_code,
            error.value.errno_category,
        ) == ("version", "connect", "broker_connect_failed", "connection_refused")
    finally:
        listener.close()
        path.unlink(missing_ok=True)


@pytest.mark.skipif(os.name != "posix", reason="Isolated child broker is Linux-only")
@pytest.mark.parametrize(
    ("index", "checkpoint"),
    [
        (0, "version"),
        (1, "tags"),
        (2, "show"),
        (3, "generate_denial"),
        (4, "oversized_denial"),
    ],
)
def test_child_broker_status_failure_identifies_exact_checkpoint(
    index: int, checkpoint: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert CHILD is not None
    responses = [
        b"HTTP/1.1 200 OK",
        b"HTTP/1.1 200 OK",
        b"HTTP/1.1 200 OK",
        b"HTTP/1.1 403 Forbidden",
        b"HTTP/1.1 403 Forbidden",
    ]
    responses[index] = b"HTTP/1.1 500 Error"
    with pytest.raises(CHILD.BrokerObservationFailure) as error:
        broker_observation_fixture(monkeypatch, responses=tuple(responses))
    assert (
        error.value.checkpoint,
        error.value.operation,
        error.value.reason_code,
    ) == (checkpoint, "response_status", "broker_response_status_invalid")


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux SO_PEERCRED required")
def test_host_broker_parent_validation_failure_is_bounded_and_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    path = tmp_path / "ollama.sock"
    peer = LinuxBrokerPeerAuthorityV1(outer_pid=1, outer_uid=1, start_time_ticks=1)
    runtime = LinuxMetadataBrokerV1(path, peer)
    monkeypatch.setattr(
        runtime,
        "_validate_socket_parent",
        lambda: (_ for _ in ()).throw(PermissionError(errno.EACCES, "denied")),
    )
    with pytest.raises(LinuxMetadataBrokerFailure) as error:
        runtime.serve_requests(1)
    assert (
        error.value.checkpoint,
        error.value.completed_outcomes,
        error.value.errno_category,
    ) == ("parent_validation", (), "permission_denied")
    assert not path.exists()


@pytest.mark.skipif(os.name != "posix", reason="Isolated child broker is Linux-only")
def test_child_broker_translation_uses_exact_peer_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = broker_observation_fixture(monkeypatch)
    assert observed["pid_namespace_translation_validated"] is True
    assert observed["child_verified_broker_pid_translation"] is True
    assert observed["child_verified_broker_uid"] is True
    assert observed["socket_inode"] == 7


@pytest.mark.skipif(os.name != "posix", reason="Isolated child broker is Linux-only")
def test_child_broker_assembles_from_per_request_snapshots_after_socket_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = broker_observation_fixture(monkeypatch)
    assert observed["socket_parent_mode"] == "0700"
    assert observed["socket_mode"] == "0600"
    assert observed["socket_inode"] == 7


@pytest.mark.skipif(os.name != "posix", reason="Isolated child broker is Linux-only")
@pytest.mark.parametrize(
    ("overrides", "direct_reason"),
    [
        ({"peer_pid": 1}, None),
        ({"peer_uid": 1001}, None),
        ({"inodes": (7, 7, 8, 7, 7)}, "broker_inode_substitution"),
        ({"devices": (1, 1, 2, 1, 1)}, "broker_inode_substitution"),
        ({"parent_modes": (0o700, 0o700, 0o755, 0o700, 0o700)}, "broker_parent_mode_invalid"),
        ({"socket_modes": (0o600, 0o600, 0o644, 0o600, 0o600)}, "broker_socket_mode_invalid"),
        (
            {
                "responses": (
                    b"HTTP/1.1 500 Error",
                    b"HTTP/1.1 200 OK",
                    b"HTTP/1.1 200 OK",
                    b"HTTP/1.1 403 Forbidden",
                    b"HTTP/1.1 403 Forbidden",
                )
            },
            "broker_response_status_invalid",
        ),
    ],
)
def test_child_broker_observation_rejects_authority_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    direct_reason: str | None,
) -> None:
    if direct_reason is not None:
        with pytest.raises(CHILD.BrokerObservationFailure) as error:
            broker_observation_fixture(monkeypatch, **overrides)
        assert error.value.reason_code == direct_reason
        return
    observed = broker_observation_fixture(monkeypatch, **overrides)
    observed.update(
        {
            "peer_pid_matched": True,
            "peer_start_time_matched": True,
            "peer_uid_matched": True,
        }
    )
    with pytest.raises(ValidationError):
        LinuxBrokerObservationV1.model_validate(observed)


@pytest.mark.skipif(os.name != "posix", reason="Isolated child broker is Linux-only")
def test_child_broker_snapshot_failure_writer_reader_preserves_exact_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(CHILD.BrokerObservationFailure) as error:
        broker_observation_fixture(
            monkeypatch,
            socket_modes=(0o600, 0o600, 0o600, 0o600, 0o644),
        )
    frame = CHILD.runtime_failure_frame("broker", H, ENVIRONMENT, error.value)
    parsed = LinuxChildRuntimeFailureV3.model_validate(frame)
    assert (
        parsed.payload.broker_checkpoint,
        parsed.payload.broker_operation,
        parsed.payload.reason_code,
        parsed.payload.errno_category,
    ) == ("oversized_denial", "socket_mode", "broker_socket_mode_invalid", None)


@pytest.mark.skipif(os.name != "posix", reason="Namespace projection is Linux-only")
@pytest.mark.parametrize(
    ("owner_uid", "uid_map", "overflow_uid", "observed_uid", "reason"),
    [
        (1, "1000 1000 1\n", 65534, 65534, "mount_host_authority_not_root"),
        (0, "0 0 1\n", 65534, 65534, "namespace_host_root_mapped"),
        (0, "1000 1000 1\n", 65533, 65533, "namespace_overflow_invalid"),
        (0, "1000 1000 1\n", 65534, 65533, "namespace_owner_projection_mismatch"),
    ],
)
def test_child_owner_projection_rejects_authority_substitution(
    owner_uid: int,
    uid_map: str,
    overflow_uid: int,
    observed_uid: int,
    reason: str,
) -> None:
    assert CHILD is not None
    expected = {"owner_uid": owner_uid, "owner_gid": 0}
    with pytest.raises(CHILD.BootstrapValidationFailure) as error:
        CHILD.validate_owner_projection(
            expected,
            65534,
            65534,
            overflow_uid,
            65534,
            uid_map,
            "1000 1000 1\n",
            observed_uid,
            65534,
        )
    assert error.value.stage == "mount_authority"
    assert error.value.reason_code == reason


@pytest.mark.skipif(os.name != "posix", reason="Namespace projection is Linux-only")
def test_child_owner_projection_accepts_exact_unmapped_root_overflow() -> None:
    assert CHILD is not None
    observed = CHILD.validate_owner_projection(
        {"owner_uid": 0, "owner_gid": 0},
        65534,
        65534,
        65534,
        65534,
        "1000 1000 1\n",
        "1000 1000 1\n",
        65534,
        65534,
    )
    assert LinuxNamespaceOwnerProjectionObservationV1.model_validate(observed) == owner_projection()


def test_child_registration_and_failure_frames_are_self_hashed_and_strict() -> None:
    registration = LinuxChildRegistrationV2.create(
        LinuxChildRegistrationPayloadV2(
            apparmor_current_profile=LINUX_APPARMOR_CURRENT,
            outer_pid=123,
            outer_uid=1000,
            start_time_ticks=456,
            mount_owner_projection=owner_projection(),
        )
    )
    failure = LinuxChildBootstrapFailureV1.create(
        LinuxChildBootstrapFailurePayloadV1(
            stage="mount_authority",
            reason_code="namespace_owner_projection_mismatch",
        )
    )
    assert (
        LinuxChildRegistrationV2.model_validate_json(registration.model_dump_json()) == registration
    )
    assert LinuxChildBootstrapFailureV1.model_validate_json(failure.model_dump_json()) == failure
    with pytest.raises(ValidationError, match="registration hash mismatch"):
        LinuxChildRegistrationV2.model_validate(
            registration.model_dump(mode="python") | {"child_registration_id": H}
        )
    with pytest.raises(ValidationError, match="bootstrap failure hash mismatch"):
        LinuxChildBootstrapFailureV1.model_validate(
            failure.model_dump(mode="python") | {"child_bootstrap_failure_id": H}
        )
    with pytest.raises(ValidationError, match="stage and reason differ"):
        LinuxChildBootstrapFailurePayloadV1(
            stage="process_identity",
            reason_code="namespace_owner_projection_mismatch",
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxChildBootstrapFailureV1.model_validate(
            failure.model_dump(mode="python") | {"details": "/host/path"}
        )


def test_v3_child_registration_and_v2_failure_frames_are_self_hashed_and_bounded() -> None:
    registration = LinuxChildRegistrationV3.create(
        LinuxChildRegistrationPayloadV3(
            apparmor_current_profile=LINUX_APPARMOR_CURRENT,
            outer_pid=123,
            outer_uid=1000,
            start_time_ticks=456,
            mount_owner_projection=owner_projection(),
            mount_authority=LinuxMountAuthorityObservationV1(),
        )
    )
    failure = LinuxChildBootstrapFailureV2.create(
        LinuxChildBootstrapFailurePayloadV2(
            stage="mount_authority",
            reason_code="mount_version_output_mismatch",
        )
    )
    assert (
        LinuxChildRegistrationV3.model_validate_json(registration.model_dump_json()) == registration
    )
    assert LinuxChildBootstrapFailureV2.model_validate_json(failure.model_dump_json()) == failure
    with pytest.raises(ValidationError, match="V3 registration hash mismatch"):
        LinuxChildRegistrationV3.model_validate(
            registration.model_dump(mode="python") | {"child_registration_id": H}
        )
    with pytest.raises(ValidationError, match="V2 bootstrap failure hash mismatch"):
        LinuxChildBootstrapFailureV2.model_validate(
            failure.model_dump(mode="python") | {"child_bootstrap_failure_id": H}
        )
    with pytest.raises(ValidationError, match="stage and reason differ"):
        LinuxChildBootstrapFailurePayloadV2(
            stage="process_identity",
            reason_code="mount_post_exec_substitution",
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxChildBootstrapFailureV2.model_validate(
            failure.model_dump(mode="python") | {"details": "/host/path"}
        )


@pytest.mark.skipif(os.name != "posix", reason="Child registration writer is Linux-only")
def test_child_registration_writer_emits_exact_canonical_v3_frame() -> None:
    assert CHILD is not None
    projection = owner_projection().model_dump(mode="json")
    authority = LinuxMountAuthorityObservationV1().model_dump(mode="json")
    raw = CHILD.child_registration_frame(
        apparmor_current_profile=LINUX_APPARMOR_CURRENT,
        outer_process_id=123,
        inner_process_id=1,
        outer_user_id=1000,
        inner_user_id=1000,
        process_start_time_ticks=456,
        mount_owner_projection=projection,
        mount_authority=authority,
    )
    parsed = LinuxChildRegistrationV3.model_validate(raw)
    assert parsed.payload.mount_owner_projection.model_dump(mode="json") == projection
    assert parsed.payload.mount_authority.model_dump(mode="json") == authority

    mutations: tuple[tuple[str, str, object], ...] = (
        ("mount_owner_projection", "schema_version", None),
        ("mount_owner_projection", "schema_version", 2),
        ("mount_owner_projection", "extra", True),
        ("mount_authority", "schema_version", None),
        ("mount_authority", "schema_version", 2),
        ("mount_authority", "extra", True),
    )
    for section, field, value in mutations:
        changed = copy.deepcopy(raw)
        payload = cast(dict[str, object], changed["payload"])
        nested = cast(dict[str, object], payload[section])
        if value is None:
            del nested[field]
        else:
            nested[field] = value
        changed["child_registration_id"] = CHILD.digest(CHILD.canonical(payload))
        with pytest.raises(ValidationError):
            LinuxChildRegistrationV3.model_validate(changed)

    substituted = copy.deepcopy(raw)
    substituted_payload = cast(dict[str, object], substituted["payload"])
    substituted_authority = cast(dict[str, object], substituted_payload["mount_authority"])
    substituted_authority["pre_exec_authority_matched"] = False
    substituted["child_registration_id"] = CHILD.digest(CHILD.canonical(substituted_payload))
    with pytest.raises(ValidationError):
        LinuxChildRegistrationV3.model_validate(substituted)


@pytest.mark.parametrize(
    "observed",
    [
        LinuxNativePathIdentityV1(device=2, inode=10),
        LinuxNativePathIdentityV1(device=1, inode=11),
        LinuxNativePathIdentityV1(device=2, inode=11),
    ],
)
def test_v3_failure_records_only_differing_bounded_native_identities(
    observed: LinuxNativePathIdentityV1,
) -> None:
    expected = LinuxNativePathIdentityV1(device=1, inode=10)
    failure = LinuxChildBootstrapFailureV3.create(
        LinuxChildBootstrapFailurePayloadV3(
            stage="mount_authority",
            reason_code="mount_pre_exec_identity_mismatch",
            expected_native_identity=expected,
            observed_native_identity=observed,
        )
    )
    assert LinuxChildBootstrapFailureV3.model_validate_json(failure.model_dump_json()) == failure
    with pytest.raises(ValidationError, match="V3 bootstrap failure hash mismatch"):
        LinuxChildBootstrapFailureV3.model_validate(
            failure.model_dump(mode="python") | {"child_bootstrap_failure_id": H}
        )


@pytest.mark.parametrize(
    "change",
    [
        {"observed_native_identity": None},
        {"expected_native_identity": None},
        {"observed_native_identity": {"device": 1, "inode": 10}},
        {"reason_code": "mount_version_output_mismatch"},
    ],
)
def test_v3_failure_rejects_missing_equal_or_unrelated_native_identity_evidence(
    change: dict[str, object],
) -> None:
    raw: dict[str, object] = {
        "stage": "mount_authority",
        "reason_code": "mount_pre_exec_identity_mismatch",
        "expected_native_identity": {"device": 1, "inode": 10},
        "observed_native_identity": {"device": 2, "inode": 11},
    }
    raw.update(change)
    with pytest.raises(ValidationError, match="native identity"):
        LinuxChildBootstrapFailurePayloadV3.model_validate(raw)


def test_v3_failure_rejects_malformed_and_rehashed_profile_identity_forgery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = LinuxNativePathIdentityV1(device=123, inode=456)
    observed = LinuxNativePathIdentityV1(device=124, inode=457)
    payload = LinuxChildBootstrapFailurePayloadV3(
        stage="mount_authority",
        reason_code="mount_pre_exec_identity_mismatch",
        expected_native_identity=expected,
        observed_native_identity=observed,
    )
    failure = LinuxChildBootstrapFailureV3.create(payload)
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxChildBootstrapFailurePayloadV3.model_validate(
            payload.model_dump(mode="python") | {"path": "/host/secret"}
        )
    profile = LinuxIsolationProfileV9.create(profile_payload_v9())
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    with pytest.raises(PROBE.ChildRegistrationFailure, match="differs from profile authority"):
        PROBE.validate_child_bootstrap_failure(
            profile,
            failure,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            ROOT,
        )


def test_v3_failure_host_accepts_only_exact_profile_expected_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = LinuxIsolationProfileV9.create(profile_payload_v9())
    expected = profile.payload.mount.native_identity
    observed = LinuxNativePathIdentityV1(device=expected.device + 1, inode=expected.inode + 1)
    failure = LinuxChildBootstrapFailureV3.create(
        LinuxChildBootstrapFailurePayloadV3(
            stage="mount_authority",
            reason_code="mount_pre_exec_identity_mismatch",
            expected_native_identity=expected,
            observed_native_identity=observed,
        )
    )
    revalidated: list[bool] = []
    monkeypatch.setattr(
        PROBE,
        "revalidate_profile_sources",
        lambda *_args: revalidated.append(True),
    )
    PROBE.validate_child_bootstrap_failure(
        profile,
        failure,
        ROOT / "src/devhub/linux_native_isolation_child.py",
        ROOT,
    )
    assert revalidated == [True]


def test_v3_registration_cannot_supply_missing_result_mount_authority() -> None:
    registration = LinuxChildRegistrationV3.create(
        LinuxChildRegistrationPayloadV3(
            apparmor_current_profile=LINUX_APPARMOR_CURRENT,
            outer_pid=123,
            outer_uid=1000,
            start_time_ticks=456,
            mount_owner_projection=owner_projection(),
            mount_authority=LinuxMountAuthorityObservationV1(),
        )
    )
    raw_observation = observation_v11().model_dump(mode="python")
    del raw_observation["mount_authority"]
    with pytest.raises(ValidationError, match="mount_authority"):
        PROBE.validate_registered_observation(raw_observation, registration.payload)

    assert (
        PROBE.validate_registered_observation(
            observation_v11().model_dump(mode="python"), registration.payload
        )
        == observation_v11()
    )


def test_registered_observation_uses_strict_json_representation_boundary() -> None:
    registration = LinuxChildRegistrationPayloadV3(
        apparmor_current_profile=LINUX_APPARMOR_CURRENT,
        outer_pid=123,
        outer_uid=1000,
        start_time_ticks=456,
        mount_owner_projection=owner_projection(),
        mount_authority=LinuxMountAuthorityObservationV1(),
    )
    raw = cast(dict[str, object], json.loads(observation_v11().model_dump_json()))
    for field in ("observed_mount_targets", "landlock_rule_targets", "cleanup_failures"):
        assert isinstance(raw[field], list)
    with pytest.raises(ValidationError, match="valid tuple"):
        LinuxIsolationObservationV11.model_validate(raw)

    observed = PROBE.validate_registered_observation(raw, registration)
    assert observed == observation_v11()
    assert isinstance(observed.observed_mount_targets, tuple)
    assert isinstance(observed.landlock_rule_targets, tuple)
    assert isinstance(observed.cleanup_failures, tuple)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("observed_mount_targets", "/bundle"),
        ("landlock_rule_targets", [1]),
        ("cleanup_failures", ["forged"]),
        ("unexpected", True),
    ],
)
def test_registered_observation_json_boundary_rejects_tampering(field: str, value: object) -> None:
    registration = LinuxChildRegistrationPayloadV3(
        apparmor_current_profile=LINUX_APPARMOR_CURRENT,
        outer_pid=123,
        outer_uid=1000,
        start_time_ticks=456,
        mount_owner_projection=owner_projection(),
        mount_authority=LinuxMountAuthorityObservationV1(),
    )
    raw = cast(dict[str, object], json.loads(observation_v11().model_dump_json()))
    raw[field] = value
    with pytest.raises(ValidationError):
        PROBE.validate_registered_observation(raw, registration)


def test_registered_observation_keeps_registration_authority_join() -> None:
    raw = cast(dict[str, object], json.loads(observation_v11().model_dump_json()))
    mismatched = LinuxMountAuthorityObservationV1().model_copy(
        update={"post_exec_authority_matched": False}
    )
    registration = LinuxChildRegistrationPayloadV3(
        apparmor_current_profile=LINUX_APPARMOR_CURRENT,
        outer_pid=123,
        outer_uid=1000,
        start_time_ticks=456,
        mount_owner_projection=owner_projection(),
        mount_authority=mismatched,
    )
    with pytest.raises(ValueError, match="result/registration mount authority mismatch"):
        PROBE.validate_registered_observation(raw, registration)


@pytest.mark.skipif(os.name != "posix", reason="Linux probe success path is Linux-only")
def test_run_probe_accepts_zero_exit_child_json_arrays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v14_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    broker_dir = tmp_path / "broker"
    broker_dir.mkdir(mode=0o700)
    child_result = observation_v14().model_dump_json().encode("utf-8") + b"\n"
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "revalidate_synthetic_upstream", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE, "process_start_time", lambda _pid: 456)
    monkeypatch.setattr(PROBE, "is_descendant", lambda *_args: True)
    monkeypatch.setattr(
        PROBE,
        "namespace_command",
        lambda *args: registered_child_command(
            cast(int, args[7]), cast(int, args[8]), child_result, 0
        ),
    )
    monkeypatch.setattr(
        PROBE.LinuxMetadataBrokerV1,
        "serve_requests",
        lambda *_args, **_kwargs: (
            "/api/version",
            "/api/tags",
            "/api/show",
            "denied",
            "denied",
        ),
    )

    def complete_stub(
        _server: socket.socket,
        _stop: threading.Event,
        outcomes: list[str],
        _errors: list[BaseException],
    ) -> None:
        outcomes.extend(("/api/version", "/api/tags", "/api/show"))

    monkeypatch.setattr(PROBE, "stub_ollama", complete_stub)
    try:
        observed = PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            broker_dir,
            server,
            capture,
        )
    finally:
        server.close()
    assert observed == observation_v14().model_copy(
        update={
            "synthetic_upstream": LinuxSyntheticUpstreamObservationV1(
                authority=profile.payload.synthetic_upstream
            )
        }
    )
    assert capture.returncode == 0


@pytest.mark.skipif(os.name != "posix", reason="Isolated child bootstrap is Linux-only")
def test_child_bootstrap_starts_with_base_interpreter_under_hostile_python_env(
    tmp_path: Path,
) -> None:
    child = ROOT / "src/devhub/linux_native_isolation_child.py"
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONHOME": str(tmp_path / "hostile-home"),
            "PYTHONNOUSERSITE": "0",
        }
    )
    result = subprocess.run(
        [str(Path(sys.executable).resolve(strict=True)), "-I", "-B", str(child), "--help"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert b"ModuleNotFoundError" not in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="Child process capture is Linux-only")
def test_pre_registration_failure_retains_actual_bounded_process_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v7().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    profile = LinuxIsolationProfileV7.create(LinuxIsolationProfilePayloadV7.model_validate(raw))
    capture = PROBE.ProbeProcessCapture()
    diagnostic = b"bounded-child-bootstrap-failure"
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(
        PROBE,
        "namespace_command",
        lambda *_args: [
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            "-B",
            "-c",
            f"import sys; sys.stderr.buffer.write({diagnostic!r})",
        ],
    )
    with pytest.raises(PROBE.ChildRegistrationFailure):
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert capture.process_started is True
    assert capture.returncode == 0
    assert bytes(capture.stdout.data) == b""
    assert bytes(capture.stderr.data) == diagnostic
    assert capture.stdout.observed == 0
    assert capture.stderr.observed == len(diagnostic)
    assert capture.stdout.truncated is False
    assert capture.stderr.truncated is False
    assert digest(bytes(capture.stderr.data)) == digest(diagnostic)
    assert server.fileno() == -1


@pytest.mark.skipif(os.name != "posix", reason="Child registration pipe is Linux-only")
def test_run_probe_accepts_only_self_hashed_bounded_bootstrap_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v9_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    failure = LinuxChildBootstrapFailureV3.create(
        LinuxChildBootstrapFailurePayloadV3(
            stage="mount_authority",
            reason_code="namespace_owner_projection_mismatch",
        )
    )
    encoded = (
        json.dumps(
            failure.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    assert encoded.count(b"\n") == 1
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")

    def emit_failure(*args: object) -> list[str]:
        registration_write = cast(int, args[7])
        return [
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            "-B",
            "-c",
            f"import os; os.write({registration_write}, {encoded!r}); raise SystemExit(70)",
        ]

    monkeypatch.setattr(PROBE, "namespace_command", emit_failure)
    with pytest.raises(PROBE.ChildBootstrapFailure) as error:
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.frame == failure
    assert capture.child_bootstrap_failure == failure
    assert capture.process_started is True
    assert capture.returncode == 70
    assert capture.cleanup_failed is False
    assert server.fileno() == -1


@pytest.mark.skipif(os.name != "posix", reason="Runtime failure pipe is Linux-only")
def test_run_probe_prefers_typed_runtime_failure_over_expected_broker_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v14_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    failure = LinuxChildRuntimeFailureV3.create(
        LinuxChildRuntimeFailurePayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=profile.payload.environment_instance_id,
            stage="landlock",
            reason_code="landlock_failed",
        )
    )
    encoded = (
        json.dumps(failure.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )
    (tmp_path / "broker").mkdir(mode=0o700)
    host_pid = os.getpid()
    host_start_time = PROBE.process_start_time(host_pid)
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(
        PROBE,
        "process_start_time",
        lambda pid: host_start_time if pid == host_pid else 456,
    )
    monkeypatch.setattr(PROBE, "is_descendant", lambda *_args: True)
    monkeypatch.setattr(
        PROBE,
        "namespace_command",
        lambda *args: registered_child_command(cast(int, args[7]), cast(int, args[8]), encoded, 71),
    )
    with pytest.raises(PROBE.ChildRuntimeFailure) as error:
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.frame == failure
    assert capture.child_runtime_failure == failure
    assert capture.host_broker_failure is None
    assert capture.returncode == 71
    assert capture.cleanup_failed is False


@pytest.mark.skipif(os.name != "posix", reason="Runtime failure pipe is Linux-only")
def test_run_probe_keeps_independent_broker_failure_primary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v14_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    failure = LinuxChildRuntimeFailureV3.create(
        LinuxChildRuntimeFailurePayloadV3(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=profile.payload.environment_instance_id,
            stage="landlock",
            reason_code="landlock_failed",
        )
    )
    encoded = (
        json.dumps(failure.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        + b"\n"
    )
    (tmp_path / "broker").mkdir(mode=0o700)
    host_pid = os.getpid()
    host_start_time = PROBE.process_start_time(host_pid)
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(
        PROBE,
        "process_start_time",
        lambda pid: host_start_time if pid == host_pid else 456,
    )
    monkeypatch.setattr(PROBE, "is_descendant", lambda *_args: True)
    monkeypatch.setattr(
        PROBE,
        "namespace_command",
        lambda *args: registered_child_command(cast(int, args[7]), cast(int, args[8]), encoded, 71),
    )

    def fail_broker(*_args: object, **_kwargs: object) -> list[str]:
        raise ValueError("independent broker failure")

    monkeypatch.setattr(PROBE.LinuxMetadataBrokerV1, "serve_requests", fail_broker)
    with pytest.raises(PROBE.ProbePhaseFailure) as error:
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.phase == "broker"
    assert capture.child_runtime_failure == failure
    assert capture.host_broker_failure is not None
    assert capture.host_broker_failure.payload.checkpoint == "worker"
    projected_child, projected_host = PROBE.projected_failure_diagnostics(capture)
    assert projected_child is None
    assert projected_host == capture.host_broker_failure


@pytest.mark.skipif(os.name != "posix", reason="Runtime failure pipe is Linux-only")
@pytest.mark.parametrize("failure_point", ["construction", "thread_start"])
def test_run_probe_binds_preworker_broker_failure(
    failure_point: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v14_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    (tmp_path / "broker").mkdir(mode=0o700)
    host_pid = os.getpid()
    host_start_time = PROBE.process_start_time(host_pid)
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(
        PROBE,
        "process_start_time",
        lambda pid: host_start_time if pid == host_pid else 456,
    )
    monkeypatch.setattr(PROBE, "is_descendant", lambda *_args: True)
    monkeypatch.setattr(
        PROBE,
        "namespace_command",
        lambda *args: registered_child_command(cast(int, args[7]), cast(int, args[8]), None, 0),
    )
    if failure_point == "construction":

        def fail_construction(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("synthetic construction failure")

        monkeypatch.setattr(PROBE, "LinuxMetadataBrokerV1", fail_construction)
    else:
        real_thread = threading.Thread

        class FailingStartThread:
            ident = None

            def start(self) -> None:
                raise RuntimeError("synthetic thread start failure")

        def make_thread(*args: object, **kwargs: object) -> threading.Thread | FailingStartThread:
            target = kwargs.get("target")
            if getattr(target, "__name__", None) == "serve":
                return FailingStartThread()
            return real_thread(*args, **kwargs)

        monkeypatch.setattr(PROBE.threading, "Thread", make_thread)
    with pytest.raises(PROBE.ProbePhaseFailure) as error:
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.phase == "broker"
    assert capture.host_broker_failure is not None
    assert capture.host_broker_failure.payload.checkpoint == failure_point
    assert capture.cleanup_failed is False


@pytest.mark.skipif(os.name != "posix", reason="Linux probe main path is Linux-only")
@pytest.mark.parametrize("failure_point", ["construction", "concurrent_worker_child"])
def test_main_seals_every_primary_broker_failure(
    failure_point: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = profile_payload_v14()
    output = tmp_path / "mechanics.json"
    failure_output = tmp_path / "failure.json"
    release = tmp_path / "release"
    release.mkdir()
    host_pid = os.getpid()
    host_start_time = PROBE.process_start_time(host_pid)
    projection_inputs: list[
        tuple[LinuxChildRuntimeFailureV3 | None, LinuxHostBrokerFailureV1 | None]
    ] = []
    real_projection = PROBE.projected_failure_diagnostics

    def fixed_file_authority(path: Path, name: str) -> LinuxToolAuthorityV1:
        if name != "unshare":
            raise AssertionError("unexpected tool authority request")
        return (
            expected.system_unshare if str(path) == PROBE.LINUX_SYSTEM_UNSHARE else expected.unshare
        )

    def child_command(*args: object) -> list[str]:
        result: bytes | None = None
        returncode = 0
        if failure_point == "concurrent_worker_child":
            profile = cast(LinuxIsolationProfileV14, args[0])
            child = LinuxChildRuntimeFailureV3.create(
                LinuxChildRuntimeFailurePayloadV3(
                    linux_isolation_profile_id=profile.linux_isolation_profile_id,
                    environment_instance_id=profile.payload.environment_instance_id,
                    stage="landlock",
                    reason_code="landlock_failed",
                )
            )
            result = (
                json.dumps(
                    child.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            assert result.count(b"\n") == 1
            returncode = 71
        return registered_child_command(cast(int, args[7]), cast(int, args[8]), result, returncode)

    def observe_projection(
        capture: PROBE.ProbeProcessCapture,
    ) -> tuple[LinuxChildRuntimeFailureV3 | None, LinuxHostBrokerFailureV1 | None]:
        projection_inputs.append((capture.child_runtime_failure, capture.host_broker_failure))
        return real_projection(capture)

    monkeypatch.setattr(PROBE, "verified_git_head", lambda *_args: None)
    monkeypatch.setattr(
        PROBE,
        "verified_package_authority",
        lambda *_args: (tmp_path, package_authority_v3()),
    )
    fixture = next(item for item in expected.source_directories if item.role == "fixture")
    monkeypatch.setattr(PROBE, "bundle_directory_authority", lambda *_args: fixture)
    monkeypatch.setattr(PROBE, "file_sha256", package_probe_hash_v3)
    monkeypatch.setattr(PROBE, "apparmor_authority", lambda *_args: expected.host.apparmor)
    monkeypatch.setattr(PROBE, "host_authority", lambda *_args: expected.host)
    monkeypatch.setattr(PROBE, "file_authority", fixed_file_authority)
    monkeypatch.setattr(PROBE, "full_mode_authority", lambda *_args: expected.mount)
    monkeypatch.setattr(PROBE, "plain_file_authority", lambda *_args: expected.bootstrap_python)
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(
        PROBE,
        "process_start_time",
        lambda pid: host_start_time if pid == host_pid else 456,
    )
    monkeypatch.setattr(PROBE, "is_descendant", lambda *_args: True)
    monkeypatch.setattr(PROBE, "namespace_command", child_command)
    monkeypatch.setattr(PROBE, "projected_failure_diagnostics", observe_projection)
    if failure_point == "construction":

        def fail_construction(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("synthetic construction failure")

        monkeypatch.setattr(PROBE, "LinuxMetadataBrokerV1", fail_construction)
    else:

        def fail_worker(*_args: object, **_kwargs: object) -> tuple[str, ...]:
            raise RuntimeError("synthetic worker failure")

        monkeypatch.setattr(PROBE.LinuxMetadataBrokerV1, "serve_requests", fail_worker)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "probe_linux_native_isolation.py",
            "--implementation-commit",
            COMMIT,
            "--environment-instance-id",
            ENVIRONMENT,
            "--output",
            str(output),
            "--failure-output",
            str(failure_output),
            "--release",
            str(release),
            "--bundle-root",
            str(tmp_path),
            "--bundle-run-id",
            "11",
            "--bundle-run-attempt",
            "1",
        ],
    )
    with pytest.raises(PROBE.ProbePhaseFailure):
        PROBE.main()
    failure = LinuxIsolationFailureV8.model_validate_json(failure_output.read_bytes())
    assert failure.payload.phase == "broker"
    assert failure.payload.host_broker_failure is not None
    assert failure.payload.host_broker_failure.payload.checkpoint == (
        "construction" if failure_point == "construction" else "worker"
    )
    assert failure.payload.child_runtime_failure is None
    assert len(projection_inputs) == 1
    observed_child, observed_host = projection_inputs[0]
    assert observed_host is not None
    if failure_point == "concurrent_worker_child":
        assert observed_child is not None
        assert observed_child.payload.stage == "landlock"
        assert observed_host.payload.checkpoint == "worker"
    else:
        assert observed_child is None
    assert failure.payload.cleanup_attempted is True
    assert failure.payload.cleanup_succeeded is True
    assert (
        failure.payload.model_requests,
        failure.payload.provider_sends,
        failure.payload.mcp_tool_executions,
        failure.payload.real_task_executions,
    ) == (0, 0, 0, 0)
    assert output.exists() is False


@pytest.mark.skipif(os.name != "posix", reason="Runtime failure pipe is Linux-only")
@pytest.mark.parametrize("result", [None, b'{"schema_version":1}\n'])
def test_run_probe_rejects_missing_or_malformed_runtime_failure(
    result: bytes | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v14_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    (tmp_path / "broker").mkdir(mode=0o700)
    host_pid = os.getpid()
    host_start_time = PROBE.process_start_time(host_pid)
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(
        PROBE,
        "process_start_time",
        lambda pid: host_start_time if pid == host_pid else 456,
    )
    monkeypatch.setattr(PROBE, "is_descendant", lambda *_args: True)
    monkeypatch.setattr(
        PROBE,
        "namespace_command",
        lambda *args: registered_child_command(cast(int, args[7]), cast(int, args[8]), result, 1),
    )
    with pytest.raises(PROBE.ProbePhaseFailure) as error:
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.phase == "child_result"
    assert capture.child_runtime_failure is None


@pytest.mark.skipif(os.name != "posix", reason="Failure artifact publication is Linux-only")
@pytest.mark.parametrize(
    ("failure_phase", "expected_reason", "cleanup_succeeded"),
    [
        ("child_registration", "child_registration_invalid", True),
        ("private_root", "private_root_failed", True),
        ("broker", "broker_failed", True),
        ("negative_probes", "negative_probe_failed", True),
        ("child_result", "child_output_invalid", True),
        ("cleanup", "cleanup_failed", False),
    ],
)
def test_main_publishes_exact_v8_child_failure_phase_without_success(
    failure_phase: PROBE.FailurePhase,
    expected_reason: PROBE.FailureReason,
    cleanup_succeeded: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = profile_payload_v14()
    diagnostic = b"bounded-main-child-bootstrap-failure"
    output = tmp_path / "mechanics.json"
    failure_output = tmp_path / "failure.json"
    release = tmp_path / "release"
    release.mkdir()
    scratch_paths: list[Path] = []
    real_temporary_directory = PROBE.tempfile.TemporaryDirectory

    class TrackingTemporaryDirectory:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.inner = real_temporary_directory(*args, **kwargs)

        def __enter__(self) -> str:
            path = self.inner.__enter__()
            scratch_paths.append(Path(path))
            return path

        def __exit__(self, *args: object) -> object:
            return self.inner.__exit__(*args)

    def fixed_file_authority(path: Path, name: str) -> LinuxToolAuthorityV1:
        if name != "unshare":
            raise AssertionError("unexpected tool authority request")
        return (
            expected.system_unshare if str(path) == PROBE.LINUX_SYSTEM_UNSHARE else expected.unshare
        )

    def fail_after_launch(*args: object) -> None:
        active_profile = cast(LinuxIsolationProfileV14, args[0])
        server = cast(socket.socket, args[7])
        capture = cast(PROBE.ProbeProcessCapture, args[8])
        capture.process_started = True
        capture.returncode = 7
        capture.stderr.data.extend(diagnostic)
        capture.stderr.observed = len(diagnostic)
        server.close()
        if failure_phase == "child_registration":
            frame = LinuxChildBootstrapFailureV3.create(
                LinuxChildBootstrapFailurePayloadV3(
                    stage="mount_authority",
                    reason_code="namespace_owner_projection_mismatch",
                )
            )
            capture.child_bootstrap_failure = frame
            capture.returncode = 70
            raise PROBE.ChildBootstrapFailure(frame)
        if failure_phase == "private_root":
            frame = LinuxChildRuntimeFailureV3.create(
                LinuxChildRuntimeFailurePayloadV3(
                    linux_isolation_profile_id=active_profile.linux_isolation_profile_id,
                    environment_instance_id=ENVIRONMENT,
                    stage="private_root",
                    reason_code="private_root_failed",
                )
            )
            capture.child_runtime_failure = frame
            capture.returncode = 71
            raise PROBE.ChildRuntimeFailure(frame)
        if failure_phase == "broker":
            capture.child_runtime_failure = LinuxChildRuntimeFailureV3.create(
                LinuxChildRuntimeFailurePayloadV3(
                    linux_isolation_profile_id=active_profile.linux_isolation_profile_id,
                    environment_instance_id=ENVIRONMENT,
                    stage="landlock",
                    reason_code="landlock_failed",
                )
            )
            capture.returncode = 71
            capture.host_broker_failure = LinuxHostBrokerFailureV1.create(
                LinuxHostBrokerFailurePayloadV1(
                    linux_isolation_profile_id=active_profile.linux_isolation_profile_id,
                    environment_instance_id=ENVIRONMENT,
                    checkpoint="construction",
                    reason_code="construction_failed",
                    failure_kind="internal_error",
                )
            )
        if failure_phase == "cleanup":
            capture.cleanup_failed = True
            raise PROBE.ProbeCleanupFailure("synthetic cleanup failure")
        raise PROBE.ProbePhaseFailure(failure_phase, f"synthetic {failure_phase} failure")

    monkeypatch.setattr(PROBE.tempfile, "TemporaryDirectory", TrackingTemporaryDirectory)
    monkeypatch.setattr(PROBE, "verified_git_head", lambda *_args: None)
    monkeypatch.setattr(
        PROBE,
        "verified_package_authority",
        lambda *_args: (tmp_path, package_authority_v3()),
    )
    fixture = next(item for item in expected.source_directories if item.role == "fixture")
    monkeypatch.setattr(PROBE, "bundle_directory_authority", lambda *_args: fixture)
    monkeypatch.setattr(PROBE, "file_sha256", package_probe_hash_v3)
    monkeypatch.setattr(PROBE, "apparmor_authority", lambda *_args: expected.host.apparmor)
    monkeypatch.setattr(PROBE, "host_authority", lambda *_args: expected.host)
    monkeypatch.setattr(PROBE, "file_authority", fixed_file_authority)
    monkeypatch.setattr(PROBE, "full_mode_authority", lambda *_args: expected.mount)
    monkeypatch.setattr(PROBE, "plain_file_authority", lambda *_args: expected.bootstrap_python)
    monkeypatch.setattr(PROBE, "run_probe", fail_after_launch)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "probe_linux_native_isolation.py",
            "--implementation-commit",
            COMMIT,
            "--environment-instance-id",
            ENVIRONMENT,
            "--output",
            str(output),
            "--failure-output",
            str(failure_output),
            "--release",
            str(release),
            "--bundle-root",
            str(tmp_path),
            "--bundle-run-id",
            "11",
            "--bundle-run-attempt",
            "1",
        ],
    )
    expected_exception = (
        PROBE.ChildRegistrationFailure
        if failure_phase == "child_registration"
        else PROBE.ChildRuntimeFailure
        if failure_phase == "private_root"
        else PROBE.ProbeCleanupFailure
        if failure_phase == "cleanup"
        else PROBE.ProbePhaseFailure
    )
    with pytest.raises(expected_exception):
        PROBE.main()
    failure = LinuxIsolationFailureV8.model_validate_json(failure_output.read_bytes())
    assert failure.payload.phase == failure_phase
    assert failure.payload.reason_code == expected_reason
    assert failure.payload.child_process_started is True
    expected_returncode = (
        70
        if failure_phase == "child_registration"
        else 71
        if failure_phase in {"private_root", "broker"}
        else 7
    )
    assert failure.payload.child_returncode == expected_returncode
    assert failure.payload.child_stdout_retained_bytes == 0
    assert failure.payload.child_stdout_observed_bytes == 0
    assert failure.payload.child_stdout_retained_sha256 == digest(b"")
    assert failure.payload.child_stdout_truncated is False
    assert failure.payload.child_stderr_retained_bytes == len(diagnostic)
    assert failure.payload.child_stderr_observed_bytes == len(diagnostic)
    assert failure.payload.child_stderr_retained_sha256 == digest(diagnostic)
    assert failure.payload.child_stderr_truncated is False
    assert failure.payload.cleanup_attempted is True
    assert failure.payload.cleanup_succeeded is cleanup_succeeded
    assert (
        failure.payload.model_requests,
        failure.payload.provider_sends,
        failure.payload.mcp_tool_executions,
        failure.payload.real_task_executions,
    ) == (0, 0, 0, 0)
    if failure_phase == "child_registration":
        assert failure.payload.child_bootstrap_failure is not None
        assert (
            failure.payload.child_bootstrap_failure.payload.reason_code
            == "namespace_owner_projection_mismatch"
        )
    else:
        assert failure.payload.child_bootstrap_failure is None
    if failure_phase == "private_root":
        assert failure.payload.child_runtime_failure is not None
        assert failure.payload.child_runtime_failure.payload.stage == "private_root"
    else:
        assert failure.payload.child_runtime_failure is None
    if failure_phase == "broker":
        assert failure.payload.host_broker_failure is not None
        assert failure.payload.host_broker_failure.payload.checkpoint == "construction"
    else:
        assert failure.payload.host_broker_failure is None
    assert output.exists() is False
    assert scratch_paths and all(not path.exists() for path in scratch_paths)


def test_failure_contract_has_typed_reason_and_rejects_raw_details() -> None:
    value = LinuxIsolationFailurePayloadV1(
        linux_isolation_profile_id=None,
        environment_instance_id=ENVIRONMENT,
        phase="host_inspection",
        reason_code="host_authority_invalid",
        child_stdout_retained_sha256=H,
        child_stderr_retained_sha256=H,
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup_attempted=False,
        cleanup_succeeded=False,
    )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxIsolationFailurePayloadV1.model_validate(
            value.model_dump(mode="python") | {"reason": "C:/secret/path"}
        )


def test_historical_failure_v1_through_v5_remain_parseable() -> None:
    v1_payload = LinuxIsolationFailurePayloadV1(
        linux_isolation_profile_id=None,
        environment_instance_id=ENVIRONMENT,
        phase="host_inspection",
        reason_code="host_authority_invalid",
        child_stdout_retained_sha256=digest(b""),
        child_stderr_retained_sha256=digest(b""),
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        cleanup_attempted=False,
        cleanup_succeeded=False,
    )
    v1 = LinuxIsolationFailureV1.create(v1_payload)
    assert LinuxIsolationFailureV1.model_validate_json(v1.model_dump_json()) == v1

    v2_raw = v1_payload.model_dump(mode="python")
    v2_raw.update(
        {
            "schema_version": 2,
            "receipt_kind": "linux_native_isolation_failure_v2",
            "child_process_started": False,
            "child_returncode": None,
            "child_stdout_retained_bytes": 0,
            "child_stderr_retained_bytes": 0,
            "child_stdout_observed_bytes": 0,
            "child_stderr_observed_bytes": 0,
        }
    )
    v2_payload = LinuxIsolationFailurePayloadV2.model_validate(v2_raw)
    versions = (
        (LinuxIsolationFailurePayloadV2, LinuxIsolationFailureV2, 2),
        (LinuxIsolationFailurePayloadV3, LinuxIsolationFailureV3, 3),
        (LinuxIsolationFailurePayloadV4, LinuxIsolationFailureV4, 4),
        (LinuxIsolationFailurePayloadV5, LinuxIsolationFailureV5, 5),
    )
    for payload_type, envelope_type, version in versions:
        raw = v2_payload.model_dump(mode="python")
        raw["schema_version"] = version
        raw["receipt_kind"] = f"linux_native_isolation_failure_v{version}"
        if version >= 3:
            raw["child_bootstrap_failure"] = None
        payload = payload_type.model_validate(raw)
        envelope = envelope_type.create(payload)
        assert envelope_type.model_validate_json(envelope.model_dump_json()) == envelope


def test_failure_v2_process_capture_is_closed_and_truthful() -> None:
    base = LinuxIsolationFailurePayloadV2(
        linux_isolation_profile_id=None,
        environment_instance_id=ENVIRONMENT,
        phase="child_registration",
        reason_code="child_registration_invalid",
        child_stdout_retained_sha256=digest(b""),
        child_stderr_retained_sha256=digest(b"abc"),
        child_stdout_truncated=False,
        child_stderr_truncated=False,
        child_process_started=True,
        child_returncode=1,
        child_stdout_retained_bytes=0,
        child_stderr_retained_bytes=3,
        child_stdout_observed_bytes=0,
        child_stderr_observed_bytes=3,
        cleanup_attempted=True,
        cleanup_succeeded=True,
    )
    assert base.child_returncode == 1
    with pytest.raises(ValidationError, match="phase and reason code differ"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python") | {"reason_code": "namespace_launch_failed"}
        )
    with pytest.raises(ValidationError, match="return code for an unstarted child"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python")
            | {
                "phase": "namespace_creation",
                "reason_code": "namespace_launch_failed",
                "child_process_started": False,
                "child_returncode": 1,
                "child_stderr_retained_bytes": 0,
                "child_stderr_observed_bytes": 0,
                "child_stderr_retained_sha256": digest(b""),
            }
        )
    with pytest.raises(ValidationError, match="stderr truncation differs"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python")
            | {"child_stderr_observed_bytes": 4, "child_stderr_truncated": False}
        )
    with pytest.raises(ValidationError, match="lacks a return code"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python") | {"child_returncode": None}
        )
    with pytest.raises(ValidationError, match="child-phase failure records an unstarted child"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python")
            | {
                "child_process_started": False,
                "child_returncode": None,
                "child_stderr_retained_bytes": 0,
                "child_stderr_observed_bytes": 0,
                "child_stderr_retained_sha256": digest(b""),
            }
        )
    with pytest.raises(ValidationError, match="child output for an unstarted child"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python")
            | {
                "phase": "namespace_creation",
                "reason_code": "namespace_launch_failed",
                "child_process_started": False,
                "child_returncode": None,
            }
        )
    with pytest.raises(ValidationError, match="cleanup success without an attempt"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python") | {"cleanup_attempted": False}
        )
    with pytest.raises(ValidationError, match="pre-launch failure records a started child"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python")
            | {"phase": "host_inspection", "reason_code": "host_authority_invalid"}
        )
    with pytest.raises(ValidationError, match="empty stdout hash differs"):
        LinuxIsolationFailurePayloadV2.model_validate(
            base.model_dump(mode="python") | {"child_stdout_retained_sha256": H}
        )


def test_exhaustive_cleanup_attempts_every_independent_resource_category() -> None:
    attempted: list[str] = []

    def failing_action(label: str) -> object:
        attempted.append(label)
        raise OSError(label)

    labels = ("descriptor", "socket", "kill", "wait", "stream", "thread")
    failures = PROBE.exhaustive_cleanup(
        tuple(lambda label=label: failing_action(label) for label in labels)
    )
    assert attempted == list(labels)
    assert len(failures) == len(labels)
    assert all(isinstance(error, OSError) for error in failures)


@pytest.mark.skipif(os.name != "posix", reason="Pre-launch descriptor cleanup is Linux-only")
def test_pre_launch_cleanup_attempts_all_descriptors_after_one_close_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    authority = PROBE.synthetic_upstream_authority(server)
    raw = profile_payload_v7().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    profile = LinuxIsolationProfileV7.create(LinuxIsolationProfilePayloadV7.model_validate(raw))
    capture = PROBE.ProbeProcessCapture()
    closed: list[int] = []
    real_close = PROBE.os.close

    def close_with_first_reported_failure(descriptor: int) -> None:
        real_close(descriptor)
        closed.append(descriptor)
        if len(closed) == 1:
            raise OSError("synthetic descriptor cleanup failure")

    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE, "namespace_command", lambda *_args: ["unreachable"])
    monkeypatch.setattr(
        PROBE,
        "revalidate_synthetic_upstream",
        lambda *_args: (_ for _ in ()).throw(ValueError("synthetic revalidation failure")),
    )
    monkeypatch.setattr(PROBE.os, "close", close_with_first_reported_failure)
    with pytest.raises(PROBE.ProbeCleanupFailure):
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert len(closed) == 4
    assert len(set(closed)) == 4
    assert server.fileno() == -1
    assert capture.process_started is False
    assert capture.cleanup_failed is True


@pytest.mark.skipif(os.name != "posix", reason="Lifecycle acquisition cleanup is Linux-only")
@pytest.mark.parametrize("failure_stage", ["second_pipe", "namespace_command"])
def test_acquisition_failures_close_every_owned_descriptor_and_listener(
    failure_stage: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v7_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    created: list[int] = []
    real_pipe = PROBE.os.pipe

    def recording_pipe() -> tuple[int, int]:
        if failure_stage == "second_pipe" and created:
            raise OSError("synthetic second pipe failure")
        descriptors = real_pipe()
        created.extend(descriptors)
        return descriptors

    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE.os, "pipe", recording_pipe)
    if failure_stage == "namespace_command":
        monkeypatch.setattr(
            PROBE,
            "namespace_command",
            lambda *_args: (_ for _ in ()).throw(ValueError("synthetic command failure")),
        )
    with pytest.raises((OSError, ValueError)):
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert len(created) == (2 if failure_stage == "second_pipe" else 4)
    for descriptor in created:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert server.fileno() == -1
    assert capture.process_started is False
    assert capture.cleanup_failed is False


@pytest.mark.skipif(os.name != "posix", reason="Parent descriptor ownership is Linux-only")
@pytest.mark.parametrize("failed_parent_close", [1, 2])
def test_each_parent_write_close_failure_still_cleans_all_resources(
    failed_parent_close: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v7_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    created: list[int] = []
    parent_close_count = 0
    real_pipe = PROBE.os.pipe
    real_close = PROBE.os.close

    class FinishedProcess:
        def __init__(self) -> None:
            self.pid = 987654321
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode = 0

        def poll(self) -> int:
            return self.returncode

        def wait(self, timeout: float) -> int:
            return self.returncode

    def recording_pipe() -> tuple[int, int]:
        descriptors = real_pipe()
        created.extend(descriptors)
        return descriptors

    def fail_selected_parent_close(descriptor: int) -> None:
        nonlocal parent_close_count
        parent_close_count += 1
        if parent_close_count == failed_parent_close:
            raise OSError("synthetic parent write close failure")
        real_close(descriptor)

    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE, "namespace_command", lambda *_args: ["synthetic"])
    monkeypatch.setattr(PROBE, "revalidate_synthetic_upstream", lambda *_args: None)
    monkeypatch.setattr(PROBE.os, "pipe", recording_pipe)
    monkeypatch.setattr(PROBE.os, "close", fail_selected_parent_close)
    monkeypatch.setattr(PROBE.subprocess, "Popen", lambda *_args, **_kwargs: FinishedProcess())
    with pytest.raises(PROBE.ProbePhaseFailure) as error:
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.phase == "namespace_creation"
    assert isinstance(error.value.__cause__, OSError)
    assert str(error.value.__cause__) == "synthetic parent write close failure"
    assert len(created) == 4
    for descriptor in created:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert server.fileno() == -1
    assert capture.process_started is True
    assert capture.returncode == 0
    assert capture.cleanup_failed is False


@pytest.mark.skipif(os.name != "posix", reason="Partial collector startup is Linux-only")
def test_partial_collector_start_failure_cleans_started_thread_process_and_fds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v7_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    created: list[int] = []
    real_pipe = PROBE.os.pipe
    real_thread = PROBE.threading.Thread
    starts = 0

    class FinishedProcess:
        def __init__(self) -> None:
            self.pid = 987654321
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode = 0

        def poll(self) -> int:
            return self.returncode

        def wait(self, timeout: float) -> int:
            return self.returncode

    class ControlledThread:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.inner = real_thread(*args, **kwargs)

        @property
        def ident(self) -> int | None:
            return self.inner.ident

        def start(self) -> None:
            nonlocal starts
            starts += 1
            if starts == 2:
                raise RuntimeError("synthetic second collector start failure")
            self.inner.start()

        def join(self, timeout: float | None = None) -> None:
            self.inner.join(timeout)

        def is_alive(self) -> bool:
            return self.inner.is_alive()

    def recording_pipe() -> tuple[int, int]:
        descriptors = real_pipe()
        created.extend(descriptors)
        return descriptors

    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE, "namespace_command", lambda *_args: ["synthetic"])
    monkeypatch.setattr(PROBE, "revalidate_synthetic_upstream", lambda *_args: None)
    monkeypatch.setattr(PROBE.os, "pipe", recording_pipe)
    monkeypatch.setattr(PROBE.subprocess, "Popen", lambda *_args, **_kwargs: FinishedProcess())
    monkeypatch.setattr(PROBE.threading, "Thread", ControlledThread)
    with pytest.raises(PROBE.ProbePhaseFailure) as error:
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert error.value.phase == "namespace_creation"
    assert isinstance(error.value.__cause__, RuntimeError)
    assert str(error.value.__cause__) == "synthetic second collector start failure"
    assert starts == 2
    assert len(created) == 4
    for descriptor in created:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert server.fileno() == -1
    assert capture.process_started is True
    assert capture.returncode == 0
    assert capture.cleanup_failed is False


@pytest.mark.skipif(os.name != "posix", reason="Process cleanup is Linux-only")
def test_process_poll_failure_still_kills_waits_closes_and_reports_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = PROBE.bind_stub_ollama(port=0)
    profile = profile_v7_for_server(server)
    capture = PROBE.ProbeProcessCapture()
    created: list[int] = []
    killed: list[int] = []
    waits: list[float] = []
    real_pipe = PROBE.os.pipe

    class PollFailureProcess:
        def __init__(self) -> None:
            self.pid = 987654321
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()
            self.returncode: int | None = None
            self.poll_calls = 0

        def poll(self) -> int | None:
            self.poll_calls += 1
            if self.poll_calls == 1:
                raise OSError("synthetic poll failure")
            return self.returncode

        def wait(self, timeout: float) -> int:
            waits.append(timeout)
            self.returncode = 9
            return self.returncode

    process = PollFailureProcess()

    def recording_pipe() -> tuple[int, int]:
        descriptors = real_pipe()
        created.extend(descriptors)
        return descriptors

    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE, "namespace_command", lambda *_args: ["synthetic"])
    monkeypatch.setattr(PROBE, "revalidate_synthetic_upstream", lambda *_args: None)
    monkeypatch.setattr(PROBE.os, "pipe", recording_pipe)
    monkeypatch.setattr(PROBE.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(PROBE, "kill_process_group", lambda pid: killed.append(pid))
    with pytest.raises(PROBE.ProbeCleanupFailure, match="OSError"):
        PROBE.run_probe(
            profile,
            ROOT / "src/devhub/linux_native_isolation_child.py",
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
            capture,
        )
    assert killed == [process.pid]
    assert waits == [10]
    assert process.poll_calls == 2
    assert capture.process_started is True
    assert capture.returncode == 9
    assert capture.cleanup_failed is True
    assert process.stdout.closed is True
    assert process.stderr.closed is True
    assert server.fileno() == -1
    for descriptor in created:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_workflow_checks_out_exact_head_and_manual_runs_are_main_only() -> None:
    workflow = (ROOT / ".github/workflows/linux-native-isolation.yml").read_text(encoding="utf-8")
    assert "pull_request:" not in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'" in workflow
    assert "Exact successful Linux Bundle V7 workflow run ID" in workflow
    assert "EXPECTED_BUNDLE_COMMIT: 0c39acf9afca1106985a1c35fca846c86d5789c7" in workflow
    assert 'test "$BUNDLE_RUN_ID" = "38374815599"' in workflow
    assert 'test "$BUNDLE_RUN_ATTEMPT" = "1"' in workflow
    assert 'gh run view "$BUNDLE_RUN_ID"' in workflow
    assert 'gh api "repos/${{ github.repository }}/actions/runs/$BUNDLE_RUN_ID"' in workflow
    assert "jq -e '.path == \".github/workflows/linux-native-bundle.yml\"'" in workflow
    assert ".headSha == $head" in workflow
    assert "--name devfabric-linux-native-bundle" in workflow
    assert "scripts/verify_linux_native_bundle.py" in workflow
    assert "--bundle-run-id '${{ inputs.native_bundle_run_id }}'" in workflow
    source = (ROOT / "scripts/probe_linux_native_isolation.py").read_text(encoding="utf-8")
    assert '["git", "rev-parse", "HEAD"]' in source
    assert '["git", "status", "--porcelain"]' in source
    manager = (ROOT / "scripts/manage_linux_native_isolation_apparmor.py").read_text(
        encoding="utf-8"
    )
    assert "LINUX_PRIVATE_UNSHARE" in manager
    assert "apparmor_restrict_unprivileged_userns=0" not in workflow
    assert "profile devfabric-linux-isolation-unshare /opt/devfabric/libexec/unshare" in (
        ROOT / "packaging/linux/apparmor/devfabric-linux-isolation-unshare"
    ).read_text(encoding="utf-8")
    assert workflow.index("Remove owned AppArmor authority and seal cleanup") < workflow.index(
        "Upload bounded qualification evidence"
    )
    assert "scripts/manage_linux_native_isolation_apparmor.py setup" in workflow
    assert "scripts/finalize_linux_native_isolation.py" in workflow


def test_receipt_rejects_nonzero_counters_and_forged_readiness() -> None:
    profile = LinuxIsolationProfileV3.create(profile_payload())
    raw = LinuxIsolationReceiptPayloadV3(
        linux_isolation_profile_id=profile.linux_isolation_profile_id,
        environment_instance_id=ENVIRONMENT,
        observation=observation(),
    ).model_dump(mode="python")
    for field in (
        "model_requests",
        "provider_sends",
        "mcp_tool_executions",
        "real_task_executions",
    ):
        changed = copy.deepcopy(raw)
        changed[field] = 1
        with pytest.raises(ValidationError):
            LinuxIsolationReceiptPayloadV3.model_validate(changed)
    for field in (
        "cgroup_resource_boundary_qualified",
        "syscall_filter_qualified",
        "native_executor_isolation_qualified",
        "package_readiness",
    ):
        changed = copy.deepcopy(raw)
        changed[field] = True
        with pytest.raises(ValidationError):
            LinuxIsolationReceiptPayloadV3.model_validate(changed)


def test_file_authority_rejects_relative_locator_and_missing_native_identity() -> None:
    raw = plain_file().model_dump(mode="python")
    raw["locator"] = "usr/bin/python3"
    with pytest.raises(ValidationError):
        LinuxFileAuthorityV1.model_validate(raw)
    raw = plain_file().model_dump(mode="python")
    del raw["native_identity"]
    with pytest.raises(ValidationError):
        LinuxFileAuthorityV1.model_validate(raw)


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"full_mode": "00755"}, "full mode differs"),
        ({"special_bits": "02000", "full_mode": "02755"}, "setgid or sticky"),
        ({"special_bits": "01000", "full_mode": "01755"}, "setgid or sticky"),
        ({"permission_bits": "0777", "full_mode": "04777"}, "permissions are unsafe"),
        ({"owner_uid": 1000}, "root-owned"),
        ({"owner_gid": 1000}, "root-owned"),
        (
            {
                "name": "unshare",
                "locator": "/usr/bin/unshare",
                "special_bits": "04000",
                "full_mode": "04755",
            },
            "Only exact /usr/bin/mount",
        ),
        ({"locator": "/opt/devfabric/libexec/mount"}, "Only exact /usr/bin/mount"),
    ),
)
def test_v4_tool_authority_rejects_unsafe_or_inconsistent_modes(
    changes: dict[str, object], message: str
) -> None:
    raw = full_mode_tool().model_dump(mode="python") | changes
    with pytest.raises(ValidationError, match=message):
        LinuxToolAuthorityV4.model_validate(raw)


@pytest.mark.skipif(os.name != "posix", reason="Child authority probe is Linux-only")
def test_host_mount_version_observation_uses_exact_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[object] = []

    def version(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed.append(kwargs.get("env"))
        return subprocess.CompletedProcess(command, 0, b"mount version\n", b"")

    monkeypatch.setattr(PROBE.subprocess, "run", version)
    authority = PROBE.full_mode_authority(Path("/usr/bin/mount"), "mount")
    assert authority.version_output_sha256 == PROBE.sha256(b"mount version\n\n---stderr---\n")
    assert observed == [{"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}]


@pytest.mark.skipif(os.name != "posix", reason="Host authority probe is Linux-only")
def test_host_mount_authority_rejects_substitution_during_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = (tmp_path / "mount").resolve()
    candidate.write_bytes(b"same")
    candidate.chmod(0o755)

    def replace(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        candidate.rename(tmp_path / "mount-before-version")
        candidate.write_bytes(b"same")
        candidate.chmod(0o755)
        return subprocess.CompletedProcess(command, 0, b"mount version\n", b"")

    monkeypatch.setattr(PROBE.subprocess, "run", replace)
    with pytest.raises(ValueError, match="changed during version observation"):
        PROBE.full_mode_authority(candidate, "mount")


@pytest.mark.skipif(os.name != "posix", reason="Child authority probe is Linux-only")
def test_child_revalidates_complete_mount_authority_before_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert CHILD is not None
    candidate = (tmp_path / "mount").resolve()
    candidate.write_bytes(b"mount-v1")
    candidate.chmod(0o755)

    observed_environments: list[object] = []

    def version(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed_environments.append(kwargs.get("env"))
        return subprocess.CompletedProcess(command, 0, b"mount version\n", b"")

    monkeypatch.setattr(PROBE.subprocess, "run", version)
    monkeypatch.setattr(CHILD.subprocess, "run", version)
    monkeypatch.setattr(CHILD, "configured_overflow_id", lambda _path: 65534)
    monkeypatch.setattr(
        CHILD,
        "validate_owner_projection",
        lambda *_args: owner_projection().model_dump(mode="json"),
    )
    info = candidate.stat()
    complete_mode = stat.S_IMODE(info.st_mode)
    expected = LinuxToolAuthorityV4(
        name="mount",
        locator=str(candidate),
        sha256=PROBE.file_sha256(candidate),
        size=info.st_size,
        owner_uid=0,
        owner_gid=0,
        permission_bits=f"0{complete_mode & 0o777:03o}",
        special_bits=f"0{complete_mode & 0o7000:04o}",
        full_mode=f"0{complete_mode:04o}",
        native_identity=LinuxNativePathIdentityV1(device=info.st_dev, inode=info.st_ino),
        version_output_sha256=PROBE.sha256(b"mount version\n\n---stderr---\n"),
    ).model_dump(mode="json")
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"))
    environment = LinuxToolVersionEnvironmentV1().model_dump_json()
    projection, authority = CHILD.validate_mount_authority(
        candidate, encoded, environment, 65534, 65534
    )
    assert LinuxNamespaceOwnerProjectionObservationV1.model_validate(projection) == (
        owner_projection()
    )
    assert LinuxMountAuthorityObservationV1.model_validate(authority) == (
        LinuxMountAuthorityObservationV1()
    )
    assert observed_environments == [
        {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}
    ]

    for field in ("device", "inode"):
        mismatched_identity = copy.deepcopy(expected)
        mismatched_identity["native_identity"][field] += 1
        with pytest.raises(CHILD.BootstrapValidationFailure) as identity_mismatch:
            CHILD.validate_mount_authority(
                candidate,
                json.dumps(mismatched_identity, sort_keys=True, separators=(",", ":")),
                environment,
                65534,
                65534,
            )
        assert identity_mismatch.value.reason_code == "mount_pre_exec_identity_mismatch"
        expected_projection = {
            "device": mismatched_identity["native_identity"]["device"],
            "inode": mismatched_identity["native_identity"]["inode"],
        }
        observed_projection = {
            "device": expected["native_identity"]["device"],
            "inode": expected["native_identity"]["inode"],
        }
        assert identity_mismatch.value.expected_native_identity == expected_projection
        assert identity_mismatch.value.observed_native_identity == observed_projection
        frame = LinuxChildBootstrapFailureV3.create(
            LinuxChildBootstrapFailurePayloadV3(
                stage=identity_mismatch.value.stage,
                reason_code=identity_mismatch.value.reason_code,
                expected_native_identity=identity_mismatch.value.expected_native_identity,
                observed_native_identity=identity_mismatch.value.observed_native_identity,
            )
        )
        assert LinuxChildBootstrapFailureV3.model_validate_json(frame.model_dump_json()) == frame

    malformed_identities: tuple[object, ...] = (
        {"device": info.st_dev, "inode": info.st_ino},
        {"schema_version": 2, "device": info.st_dev, "inode": info.st_ino},
        {
            "schema_version": 1,
            "device": info.st_dev,
            "inode": info.st_ino,
            "extra": 1,
        },
        {"schema_version": True, "device": info.st_dev, "inode": info.st_ino},
        {"schema_version": 1, "device": True, "inode": info.st_ino},
        {"schema_version": 1, "device": info.st_dev, "inode": True},
    )
    for malformed_identity in malformed_identities:
        malformed = copy.deepcopy(expected)
        malformed["native_identity"] = malformed_identity
        with pytest.raises(CHILD.BootstrapValidationFailure) as invalid_identity:
            CHILD.validate_mount_authority(
                candidate,
                json.dumps(malformed, sort_keys=True, separators=(",", ":")),
                environment,
                65534,
                65534,
            )
        assert invalid_identity.value.reason_code == "mount_pre_exec_content_mismatch"
        assert invalid_identity.value.expected_native_identity is None
        assert invalid_identity.value.observed_native_identity is None

    candidate.write_bytes(b"mount-v2")
    with pytest.raises(CHILD.BootstrapValidationFailure) as changed_bytes:
        CHILD.validate_mount_authority(candidate, encoded, environment, 65534, 65534)
    assert changed_bytes.value.reason_code == "mount_pre_exec_content_mismatch"
    candidate.write_bytes(b"mount-v1")
    candidate.chmod(0o700)
    with pytest.raises(CHILD.BootstrapValidationFailure) as changed_mode:
        CHILD.validate_mount_authority(candidate, encoded, environment, 65534, 65534)
    assert changed_mode.value.reason_code == "mount_pre_exec_mode_mismatch"

    invalid_environments = (
        {"lang": "C.UTF-8", "lc_all": "C.UTF-8", "path": "/usr/bin:/bin"},
        {
            "schema_version": 2,
            "lang": "C.UTF-8",
            "lc_all": "C.UTF-8",
            "path": "/usr/bin:/bin",
        },
        {
            "schema_version": 1,
            "lang": "C.UTF-8",
            "lc_all": "C.UTF-8",
            "path": "/usr/bin:/bin",
            "extra": "forbidden",
        },
    )
    for invalid_environment in invalid_environments:
        with pytest.raises(CHILD.BootstrapValidationFailure) as changed_environment:
            CHILD.validate_mount_authority(
                candidate,
                encoded,
                json.dumps(invalid_environment),
                65534,
                65534,
            )
        assert changed_environment.value.reason_code == "mount_version_environment_invalid"

    candidate.chmod(0o755)
    monkeypatch.setattr(
        CHILD.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, b"", b"denied"),
    )
    with pytest.raises(CHILD.BootstrapValidationFailure) as nonzero_version:
        CHILD.validate_mount_authority(candidate, encoded, environment, 65534, 65534)
    assert nonzero_version.value.reason_code == "mount_version_exit_nonzero"

    monkeypatch.setattr(
        CHILD.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, b"other\n", b""),
    )
    with pytest.raises(CHILD.BootstrapValidationFailure) as changed_version:
        CHILD.validate_mount_authority(candidate, encoded, environment, 65534, 65534)
    assert changed_version.value.reason_code == "mount_version_output_mismatch"

    def replace_during_version(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        candidate.rename(tmp_path / "mount-before-version")
        candidate.write_bytes(b"mount-v1")
        candidate.chmod(0o755)
        return subprocess.CompletedProcess(command, 0, b"mount version\n", b"")

    monkeypatch.setattr(CHILD.subprocess, "run", replace_during_version)
    with pytest.raises(CHILD.BootstrapValidationFailure) as replaced:
        CHILD.validate_mount_authority(candidate, encoded, environment, 65534, 65534)
    assert replaced.value.reason_code == "mount_post_exec_substitution"

    replacement_info = candidate.stat()
    expected["native_identity"] = {
        "schema_version": 1,
        "device": replacement_info.st_dev,
        "inode": replacement_info.st_ino,
    }
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"))
    monkeypatch.setattr(CHILD.subprocess, "run", version)
    projection_calls = 0

    def change_owner_projection(*_args: object) -> dict[str, bool | int]:
        nonlocal projection_calls
        projection_calls += 1
        projected = owner_projection().model_dump(mode="json")
        if projection_calls == 2:
            projected["observed_owner_uid"] = 65533
        return projected

    monkeypatch.setattr(CHILD, "validate_owner_projection", change_owner_projection)
    with pytest.raises(CHILD.BootstrapValidationFailure) as changed_owner:
        CHILD.validate_mount_authority(candidate, encoded, environment, 65534, 65534)
    assert changed_owner.value.reason_code == "mount_post_exec_substitution"


@pytest.mark.skipif(os.name != "posix", reason="Native device/inode authority is Linux-only")
def test_source_revalidation_rejects_same_bytes_at_replaced_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "bootstrap.bin"
    candidate.write_bytes(b"same")
    expected = PROBE.plain_file_authority(candidate)
    candidate.rename(tmp_path / "old-bootstrap.bin")
    candidate.write_bytes(b"same")
    with pytest.raises(ValueError, match="authority changed"):
        PROBE.revalidate_file(expected)

    monkeypatch.setattr(PROBE, "current_uid", lambda: candidate.parent.stat().st_uid)
    monkeypatch.setattr(PROBE, "current_gid", lambda: candidate.parent.stat().st_gid)
    directory_path = tmp_path / "private"
    directory_path.mkdir(mode=0o700)
    expected_directory = PROBE.directory_authority(directory_path, "state")
    directory_path.rename(tmp_path / "old-private")
    directory_path.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="authority changed"):
        PROBE.revalidate_directory(expected_directory)


def test_profile_canonical_bytes_are_stable() -> None:
    first = LinuxIsolationProfileV3.create(profile_payload())
    second = LinuxIsolationProfileV3.create(
        LinuxIsolationProfilePayloadV3.model_validate_json(
            json.dumps(profile_payload().model_dump(mode="json"), indent=2, sort_keys=False)
        )
    )
    assert first.linux_isolation_profile_id == second.linux_isolation_profile_id
