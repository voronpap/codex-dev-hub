from __future__ import annotations

import copy
import importlib.util
import json
import os
import socket
import stat
import subprocess
import threading
from pathlib import Path
from types import ModuleType
from typing import Literal, cast

import pytest
from pydantic import ValidationError

from devhub.benchmark import canonical, digest
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
    LinuxDirectoryAuthorityV1,
    LinuxFileAuthorityV1,
    LinuxHostAuthorityV3,
    LinuxHostCleanupObservationV1,
    LinuxIsolationEvidencePayloadV1,
    LinuxIsolationEvidencePayloadV2,
    LinuxIsolationEvidencePayloadV3,
    LinuxIsolationEvidencePayloadV4,
    LinuxIsolationEvidencePayloadV5,
    LinuxIsolationEvidenceV1,
    LinuxIsolationEvidenceV2,
    LinuxIsolationEvidenceV3,
    LinuxIsolationEvidenceV4,
    LinuxIsolationEvidenceV5,
    LinuxIsolationFailurePayloadV1,
    LinuxIsolationObservationV1,
    LinuxIsolationObservationV2,
    LinuxIsolationObservationV3,
    LinuxIsolationObservationV4,
    LinuxIsolationObservationV5,
    LinuxIsolationProfilePayloadV1,
    LinuxIsolationProfilePayloadV2,
    LinuxIsolationProfilePayloadV3,
    LinuxIsolationProfilePayloadV4,
    LinuxIsolationProfilePayloadV5,
    LinuxIsolationProfileV1,
    LinuxIsolationProfileV2,
    LinuxIsolationProfileV3,
    LinuxIsolationProfileV4,
    LinuxIsolationProfileV5,
    LinuxIsolationQualificationPayloadV3,
    LinuxIsolationQualificationPayloadV4,
    LinuxIsolationQualificationPayloadV5,
    LinuxIsolationQualificationV4,
    LinuxIsolationQualificationV5,
    LinuxIsolationReceiptPayloadV1,
    LinuxIsolationReceiptPayloadV2,
    LinuxIsolationReceiptPayloadV3,
    LinuxIsolationReceiptPayloadV4,
    LinuxIsolationReceiptPayloadV5,
    LinuxIsolationReceiptV1,
    LinuxIsolationReceiptV2,
    LinuxIsolationReceiptV3,
    LinuxIsolationReceiptV4,
    LinuxIsolationReceiptV5,
    LinuxMountAuthorityV1,
    LinuxNamespaceObservationV1,
    LinuxNativePathIdentityV1,
    LinuxRlimitsV1,
    LinuxSyntheticUpstreamAuthorityV1,
    LinuxSyntheticUpstreamObservationV1,
    LinuxToolAuthorityV1,
    LinuxToolAuthorityV4,
    enforced_landlock_abi,
    landlock_handled_access,
    observed_private_mount_targets,
)
from devhub.linux_ollama_broker import (
    BoundedHTTPRequest,
    LinuxBrokerPeerAuthorityV1,
    LinuxMetadataBrokerV1,
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
        ROOT / "scripts/linux_native_isolation_child.py",
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


@pytest.mark.skipif(os.name != "posix", reason="Linux finalizer requires O_NOFOLLOW")
def test_finalizer_joins_only_v5_mechanics(tmp_path: Path) -> None:
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
    mechanics_path = tmp_path / "mechanics.json"
    cleanup_path = tmp_path / "cleanup.json"
    output = tmp_path / "qualification.json"
    mechanics_path.write_text(evidence.model_dump_json(), encoding="utf-8")
    cleanup_path.write_text(cleanup.model_dump_json(), encoding="utf-8")
    FINALIZER.finalize(mechanics_path, cleanup_path, output)
    qualification = LinuxIsolationQualificationV5.model_validate_json(output.read_bytes())
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
    raw = profile_payload_v5().model_dump(mode="python")
    raw["synthetic_upstream"] = authority.model_dump(mode="python")
    raw["broker"]["broker_host_pid"] = authority.owner_pid
    raw["broker"]["broker_host_start_time_ticks"] = authority.owner_start_time_ticks
    raw["broker"]["broker_host_uid"] = authority.owner_uid
    profile = LinuxIsolationProfileV5.create(LinuxIsolationProfilePayloadV5.model_validate(raw))
    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "namespace_id", lambda kind: f"{kind}:[1]")
    monkeypatch.setattr(PROBE, "namespace_command", lambda *_args: ["unreachable"])

    def fail_launch(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic launch failure")

    monkeypatch.setattr(PROBE.subprocess, "Popen", fail_launch)
    with pytest.raises(OSError, match="synthetic launch failure"):
        PROBE.run_probe(
            profile,
            Path("/repo/scripts/linux_native_isolation_child.py"),
            tmp_path / "root",
            tmp_path / "bundle",
            tmp_path / "state",
            tmp_path / "output",
            tmp_path / "broker",
            server,
        )
    assert server.fileno() == -1


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
    source = (ROOT / "scripts/linux_native_isolation_child.py").read_text(encoding="utf-8")
    assert "kernel_abi = landlock_abi()" in source
    assert "policy_abi = enforced_landlock_abi(kernel_abi)" in source
    assert "landlock_handled_access(policy_abi)" in source


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
    with pytest.raises(ValueError, match="weaker options"):
        observed_private_mount_targets(
            raw.replace(b"ro,nosuid,nodev - ext4", b"rw - ext4", 1), MOUNT_TARGETS
        )


def test_namespace_command_uses_keep_caps_and_bound_bootstrap() -> None:
    profile = LinuxIsolationProfileV4.create(profile_payload_v4())
    command = PROBE.namespace_command(
        profile,
        Path("/repo/scripts/linux_native_isolation_child.py"),
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
    assert command[command.index("--net") + 1] == profile.payload.bootstrap_python.locator
    assert command[0] == "/opt/devfabric/libexec/unshare"
    assert command[command.index("--expected-apparmor-current") + 1] == LINUX_APPARMOR_CURRENT
    assert command[command.index("--expected-kernel-landlock-abi") + 1] == "7"
    assert command[command.index("--expected-enforced-landlock-abi") + 1] == "6"
    assert json.loads(command[command.index("--expected-mount-authority") + 1]) == (
        profile.payload.mount.model_dump(mode="json")
    )
    assert "--dependency" not in command


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


def test_workflow_checks_out_exact_head_and_manual_runs_are_main_only() -> None:
    workflow = (ROOT / ".github/workflows/linux-native-isolation.yml").read_text(encoding="utf-8")
    assert "pull_request:" not in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'" in workflow
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
def test_child_revalidates_complete_mount_authority_before_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert CHILD is not None
    candidate = (tmp_path / "mount").resolve()
    candidate.write_bytes(b"mount-v1")
    candidate.chmod(0o755)

    def version(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, b"mount version\n", b"")

    monkeypatch.setattr(PROBE.subprocess, "run", version)
    monkeypatch.setattr(CHILD.subprocess, "run", version)
    info = candidate.stat()
    complete_mode = stat.S_IMODE(info.st_mode)
    expected = {
        "schema_version": 4,
        "name": "mount",
        "locator": str(candidate),
        "sha256": PROBE.file_sha256(candidate),
        "size": info.st_size,
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "permission_bits": f"0{complete_mode & 0o777:03o}",
        "special_bits": f"0{complete_mode & 0o7000:04o}",
        "full_mode": f"0{complete_mode:04o}",
        "native_identity": {"device": info.st_dev, "inode": info.st_ino},
        "version_output_sha256": PROBE.sha256(b"mount version\n\n---stderr---\n"),
    }
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"))
    CHILD.validate_mount_authority(candidate, encoded)

    candidate.write_bytes(b"mount-v2")
    with pytest.raises(ValueError, match="changed before the first mount"):
        CHILD.validate_mount_authority(candidate, encoded)
    candidate.write_bytes(b"mount-v1")
    candidate.chmod(0o700)
    with pytest.raises(ValueError, match="changed before the first mount"):
        CHILD.validate_mount_authority(candidate, encoded)


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
