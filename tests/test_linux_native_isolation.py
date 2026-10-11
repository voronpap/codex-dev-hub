from __future__ import annotations

import copy
import importlib.util
import json
import os
import socket
import threading
from pathlib import Path
from types import ModuleType
from typing import Literal, Never, cast

import pytest
from pydantic import ValidationError

from devhub.benchmark import canonical, digest
from devhub.linux_isolation import (
    LinuxBrokerExpectationV1,
    LinuxBrokerObservationV1,
    LinuxDirectoryAuthorityV1,
    LinuxFileAuthorityV1,
    LinuxHostAuthorityV1,
    LinuxHostCleanupObservationV1,
    LinuxIsolationEvidencePayloadV1,
    LinuxIsolationEvidenceV1,
    LinuxIsolationFailurePayloadV1,
    LinuxIsolationObservationV1,
    LinuxIsolationProfilePayloadV1,
    LinuxIsolationProfileV1,
    LinuxIsolationReceiptPayloadV1,
    LinuxIsolationReceiptV1,
    LinuxMountAuthorityV1,
    LinuxNamespaceObservationV1,
    LinuxNativePathIdentityV1,
    LinuxRlimitsV1,
    LinuxToolAuthorityV1,
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


def plain_file(locator: str = "/usr/bin/python3") -> LinuxFileAuthorityV1:
    return LinuxFileAuthorityV1(
        locator=locator,
        sha256=H,
        size=1,
        owner_uid=0,
        owner_gid=0,
        mode="0755",
        native_identity=native(),
    )


def tool(name: Literal["unshare", "mount"]) -> LinuxToolAuthorityV1:
    return LinuxToolAuthorityV1(
        **plain_file(f"/usr/bin/{name}").model_dump(mode="python"),
        name=name,
        version_output_sha256=H,
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


def profile_payload() -> LinuxIsolationProfilePayloadV1:
    roles: tuple[
        Literal["broker"],
        Literal["fixture"],
        Literal["output"],
        Literal["scratch_root"],
        Literal["state"],
    ] = ("broker", "fixture", "output", "scratch_root", "state")
    sources = tuple(directory(role, index) for index, role in enumerate(roles, 2))
    source_hashes = {item.role: digest(canonical(item.model_dump(mode="json"))) for item in sources}
    return LinuxIsolationProfilePayloadV1(
        environment_instance_id=ENVIRONMENT,
        implementation_commit=COMMIT,
        native_bundle_id=H,
        bundle_manifest_sha256=H,
        bootstrap_python=plain_file(),
        probe_sha256=H,
        child_probe_sha256=H,
        host=LinuxHostAuthorityV1(
            os_release_sha256=H,
            kernel_release="6.8.0-1018-azure",
            kernel_version_sha256=H,
            apparmor_userns_restriction_present=True,
            apparmor_userns_restriction=0,
            landlock_abi=6,
            delegated_cgroup_available=False,
        ),
        unshare=tool("unshare"),
        mount=tool("mount"),
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


def observation() -> LinuxIsolationObservationV1:
    return LinuxIsolationObservationV1(
        namespaces=namespace_observation(),
        mount_table_sha256=H,
        observed_mount_targets=MOUNT_TARGETS,
        landlock_abi=6,
        landlock_handled_access=landlock_handled_access(6),
        landlock_rule_targets=RULE_TARGETS,
        landlock_ruleset_sha256=H,
        rlimits_sha256=digest(canonical(LinuxRlimitsV1().model_dump(mode="json"))),
        broker=LinuxBrokerObservationV1(socket_inode=42),
    )


def evidence_payload(
    profile: LinuxIsolationProfileV1, receipt: LinuxIsolationReceiptV1
) -> LinuxIsolationEvidencePayloadV1:
    return LinuxIsolationEvidencePayloadV1(
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


def test_linux_profile_receipt_and_composite_are_self_hashed_and_non_ready() -> None:
    profile = LinuxIsolationProfileV1.create(profile_payload())
    receipt = LinuxIsolationReceiptV1.create(
        LinuxIsolationReceiptPayloadV1(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=observation(),
        )
    )
    evidence = LinuxIsolationEvidenceV1.create(evidence_payload(profile, receipt))
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


def test_linux_composite_rejects_cross_environment_and_profile_observation_mismatch() -> None:
    profile = LinuxIsolationProfileV1.create(profile_payload())
    wrong_environment = LinuxIsolationReceiptV1.create(
        LinuxIsolationReceiptPayloadV1(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id="a" * 32,
            observation=observation(),
        )
    )
    with pytest.raises(ValidationError, match="authority differ"):
        evidence_payload(profile, wrong_environment)
    changed = observation().model_copy(update={"landlock_handled_access": 1})
    receipt = LinuxIsolationReceiptV1.create(
        LinuxIsolationReceiptPayloadV1(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=ENVIRONMENT,
            observation=changed,
        )
    )
    with pytest.raises(ValidationError, match="Landlock mask"):
        evidence_payload(profile, receipt)


def test_profile_rejects_tampering_open_bags_and_weakened_authority() -> None:
    profile = LinuxIsolationProfileV1.create(profile_payload()).model_dump(mode="json")
    profile["linux_isolation_profile_id"] = "f" * 64
    with pytest.raises(ValidationError, match="profile hash mismatch"):
        LinuxIsolationProfileV1.model_validate_json(json.dumps(profile))
    raw = profile_payload().model_dump(mode="python") | {"unexpected_authority": True}
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        LinuxIsolationProfilePayloadV1.model_validate(raw)
    raw = profile_payload().model_dump(mode="python")
    raw["mounts"] = tuple(reversed(raw["mounts"]))
    with pytest.raises(ValidationError, match="sorted and unique"):
        LinuxIsolationProfilePayloadV1.model_validate(raw)
    raw = profile_payload().model_dump(mode="python")
    raw["landlock_handled_access"] = 1
    with pytest.raises(ValidationError, match="exact reviewed host ABI"):
        LinuxIsolationProfilePayloadV1.model_validate(raw)


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


def test_occupied_stub_port_fails_before_namespace_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    occupied.bind(("127.0.0.1", 0))
    occupied.listen(1)
    occupied.setblocking(False)
    occupied_port = int(occupied.getsockname()[1])
    launched = False
    bind_stub = PROBE.bind_stub_ollama

    def forbidden_launch(*_args: object, **_kwargs: object) -> Never:
        nonlocal launched
        launched = True
        raise AssertionError("namespace child must not launch")

    monkeypatch.setattr(PROBE, "revalidate_profile_sources", lambda *_args: None)
    monkeypatch.setattr(PROBE, "bind_stub_ollama", lambda: bind_stub(port=occupied_port))
    monkeypatch.setattr(PROBE.subprocess, "Popen", forbidden_launch)
    try:
        with pytest.raises(OSError):
            PROBE.run_probe(
                LinuxIsolationProfileV1.create(profile_payload()),
                Path("/repo/scripts/linux_native_isolation_child.py"),
                tmp_path / "root",
                tmp_path / "bundle",
                tmp_path / "state",
                tmp_path / "output",
                tmp_path / "broker",
            )
        assert launched is False
        with pytest.raises(BlockingIOError):
            occupied.accept()
    finally:
        occupied.close()


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
    profile = LinuxIsolationProfileV1.create(profile_payload())
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
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert "github.event_name == 'pull_request' || github.ref == 'refs/heads/main'" in workflow
    source = (ROOT / "scripts/probe_linux_native_isolation.py").read_text(encoding="utf-8")
    assert '["git", "rev-parse", "HEAD"]' in source
    assert '["git", "status", "--porcelain"]' in source


def test_receipt_rejects_nonzero_counters_and_forged_readiness() -> None:
    profile = LinuxIsolationProfileV1.create(profile_payload())
    raw = LinuxIsolationReceiptPayloadV1(
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
            LinuxIsolationReceiptPayloadV1.model_validate(changed)
    for field in (
        "cgroup_resource_boundary_qualified",
        "syscall_filter_qualified",
        "native_executor_isolation_qualified",
        "package_readiness",
    ):
        changed = copy.deepcopy(raw)
        changed[field] = True
        with pytest.raises(ValidationError):
            LinuxIsolationReceiptPayloadV1.model_validate(changed)


def test_file_authority_rejects_relative_locator_and_missing_native_identity() -> None:
    raw = plain_file().model_dump(mode="python")
    raw["locator"] = "usr/bin/python3"
    with pytest.raises(ValidationError):
        LinuxFileAuthorityV1.model_validate(raw)
    raw = plain_file().model_dump(mode="python")
    del raw["native_identity"]
    with pytest.raises(ValidationError):
        LinuxFileAuthorityV1.model_validate(raw)


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
    first = LinuxIsolationProfileV1.create(profile_payload())
    second = LinuxIsolationProfileV1.create(
        LinuxIsolationProfilePayloadV1.model_validate_json(
            json.dumps(profile_payload().model_dump(mode="json"), indent=2, sort_keys=False)
        )
    )
    assert first.linux_isolation_profile_id == second.linux_isolation_profile_id
