from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import devhub.windows_isolation as isolation
from devhub.benchmark import canonical, digest
from devhub.windows_isolation import (
    WINDOWS_SANDBOX_SCHEMA_IDENTITY,
    NativePathIdentityV1,
    WindowsIsolationChildResultV1,
    WindowsIsolationEvidenceV1,
    WindowsIsolationProfilePayloadV1,
    WindowsIsolationProfileV1,
    WindowsIsolationReceiptPayloadV1,
    WindowsIsolationReceiptV1,
    appcontainer_identity,
    windows_sandbox_spec,
)

H = "1" * 64
ENVIRONMENT = "2" * 32


def path(name: str, index: int) -> NativePathIdentityV1:
    return NativePathIdentityV1(
        locator=rf"C:\qualification\{name}",
        volume_serial_number=123,
        file_index=f"{index:016x}",
    )


def profile_payload() -> WindowsIsolationProfilePayloadV1:
    return WindowsIsolationProfilePayloadV1(
        environment_instance_id=ENVIRONMENT,
        appcontainer_identity=appcontainer_identity(ENVIRONMENT),
        native_bundle_id=H,
        codex_executable_sha256="3" * 64,
        launcher_executable_sha256="5" * 64,
        probe_sha256="4" * 64,
        read_only_roots=(path("bundle", 1),),
        writable_roots=(path("workspace", 2),),
        denied_roots=(path("hidden", 3),),
    )


def receipt_payload(profile: WindowsIsolationProfileV1) -> dict[str, object]:
    return {
        "windows_isolation_profile_id": profile.windows_isolation_profile_id,
        "environment_instance_id": ENVIRONMENT,
        "probe_sha256": profile.payload.probe_sha256,
        "sandbox_spec_sha256": digest(windows_sandbox_spec(profile)),
        "observed_windows_build": 26200,
        "observed_architecture": "x86_64",
        "inherited_handles_blocked": True,
        "child_tree_terminated": True,
        "breakaway_blocked": True,
        "allowed_root_read_write": True,
        "hidden_root_read_denied": True,
        "hidden_root_write_denied": True,
        "reparse_substitution_rejected": True,
        "host_registry_unchanged": True,
        "direct_loopback_denied": True,
        "direct_lan_denied": True,
        "direct_dns_denied": True,
        "direct_public_denied": True,
        "appcontainer_profile_deleted": True,
    }


@pytest.mark.windows_smoke
def test_profile_and_receipt_are_canonical_strict_authority() -> None:
    profile = WindowsIsolationProfileV1.create(profile_payload())
    assert profile == WindowsIsolationProfileV1.model_validate_json(
        canonical(profile.model_dump(mode="json"))
    )
    receipt = WindowsIsolationReceiptV1.create(
        WindowsIsolationReceiptPayloadV1.model_validate(receipt_payload(profile))
    )
    assert receipt == WindowsIsolationReceiptV1.model_validate_json(
        canonical(receipt.model_dump(mode="json"))
    )

    changed = json.loads(canonical(profile.model_dump(mode="json")))
    changed["payload"]["network_mode"] = "unrestricted"
    with pytest.raises(ValidationError):
        WindowsIsolationProfileV1.model_validate_json(json.dumps(changed))
    changed = json.loads(canonical(profile.model_dump(mode="json")))
    changed["windows_isolation_profile_id"] = "f" * 64
    with pytest.raises(ValidationError, match="profile hash mismatch"):
        WindowsIsolationProfileV1.model_validate_json(json.dumps(changed))


@pytest.mark.windows_smoke
@pytest.mark.parametrize(
    "field",
    [
        "inherited_handles_blocked",
        "child_tree_terminated",
        "breakaway_blocked",
        "allowed_root_read_write",
        "hidden_root_read_denied",
        "hidden_root_write_denied",
        "reparse_substitution_rejected",
        "host_registry_unchanged",
        "direct_loopback_denied",
        "direct_lan_denied",
        "direct_dns_denied",
        "direct_public_denied",
        "appcontainer_profile_deleted",
    ],
)
def test_receipt_fails_closed_for_each_security_observation(field: str) -> None:
    profile = WindowsIsolationProfileV1.create(profile_payload())
    raw = receipt_payload(profile)
    raw[field] = False
    with pytest.raises(ValidationError, match="qualification observation failed"):
        WindowsIsolationReceiptPayloadV1.model_validate(raw)


@pytest.mark.windows_smoke
def test_profile_rejects_duplicate_roots_and_unbound_identity() -> None:
    raw = profile_payload().model_dump()
    raw["writable_roots"] = raw["read_only_roots"]
    with pytest.raises(ValidationError, match="case-insensitively unique"):
        WindowsIsolationProfilePayloadV1.model_validate(raw)
    raw = profile_payload().model_dump()
    raw["appcontainer_identity"] = f"devfabric_{'9' * 32}"
    with pytest.raises(ValidationError, match="bind the environment"):
        WindowsIsolationProfilePayloadV1.model_validate(raw)


@pytest.mark.windows_smoke
def test_sandbox_spec_is_deterministic_closed_no_network() -> None:
    profile = WindowsIsolationProfileV1.create(profile_payload())
    first = windows_sandbox_spec(profile)
    second = windows_sandbox_spec(profile)
    assert first == second
    assert first[4:8] == b"SBOX"
    assert digest(first) == digest(second)
    assert b"internetClient" not in first
    assert b"0.1.0" in first
    assert profile.payload.sandbox_schema_sha256 == WINDOWS_SANDBOX_SCHEMA_IDENTITY
    assert digest(first) == "a1ab10b1a4e20b3c5af865de9794aca9f2ad00249dc7d902907f88bda05c8133"

    root = struct.unpack_from("<I", first, 0)[0]
    vtable = root - struct.unpack_from("<i", first, root)[0]

    def slot(index: int) -> int:
        return struct.unpack_from("<H", first, vtable + 4 + index * 2)[0]

    def string(index: int) -> str:
        field = root + slot(index)
        start = field + struct.unpack_from("<I", first, field)[0]
        length = struct.unpack_from("<I", first, start)[0]
        return first[start + 4 : start + 4 + length].decode()

    def strings(index: int) -> tuple[str, ...]:
        field = root + slot(index)
        vector = field + struct.unpack_from("<I", first, field)[0]
        length = struct.unpack_from("<I", first, vector)[0]
        values: list[str] = []
        for item in range(length):
            offset = vector + 4 + item * 4
            start = offset + struct.unpack_from("<I", first, offset)[0]
            size = struct.unpack_from("<I", first, start)[0]
            values.append(first[start + 4 : start + 4 + size].decode())
        return tuple(values)

    assert string(0) == "0.1.0"
    assert first[root + slot(1)] == 1
    assert slot(2) == 0
    assert first[root + slot(3)] == 1
    assert struct.unpack_from("<Q", first, root + slot(4))[0] == 0x00FF
    assert first[root + slot(5)] == 1
    assert slot(6) == 0  # no capabilities
    assert strings(7) == (r"C:\qualification\workspace",)
    assert strings(8) == (r"C:\qualification\bundle",)
    assert slot(9) == 0  # no network/proxy policy
    assert slot(10) == 0  # system-default AppContainer integrity
    assert strings(11) == (r"C:\qualification\hidden",)


@pytest.mark.windows_smoke
def test_child_result_and_retained_evidence_are_strict() -> None:
    profile = WindowsIsolationProfileV1.create(profile_payload())
    child = {
        "allowed_root_read_write": True,
        "inherited_handles_blocked": True,
        "inherited_handle_error_code": 6,
        "hidden_read": {"denied": True, "error_code": 5},
        "hidden_write": {"denied": True, "error_code": 13},
        "registry_write_succeeded": True,
        "registry_error_code": None,
        "loopback": {"denied": True, "error_code": 10013},
        "lan": {"denied": True, "error_code": 10013},
        "public": {"denied": True, "error_code": 10013},
        "dns": {"denied": True, "error_code": 10013},
        "grandchild_pid": 123,
        "breakaway_blocked": True,
        "breakaway_error_code": 5,
        "breakaway_pid": None,
    }
    WindowsIsolationChildResultV1.model_validate(child)
    for path_to_change, value in (
        (("allowed_root_read_write",), "true"),
        (("hidden_read", "error_code"), 2),
        (("loopback", "error_code"), 11001),
    ):
        changed = json.loads(json.dumps(child))
        target = changed
        for key in path_to_change[:-1]:
            target = target[key]
        target[path_to_change[-1]] = value
        with pytest.raises(ValidationError):
            WindowsIsolationChildResultV1.model_validate(changed)
    changed = json.loads(json.dumps(child))
    changed["extra"] = True
    with pytest.raises(ValidationError):
        WindowsIsolationChildResultV1.model_validate(changed)

    receipt = WindowsIsolationReceiptV1.create(
        WindowsIsolationReceiptPayloadV1.model_validate(receipt_payload(profile))
    )
    spec = windows_sandbox_spec(profile)
    evidence = WindowsIsolationEvidenceV1.create(profile, spec, receipt)
    assert (
        WindowsIsolationEvidenceV1.model_validate_json(canonical(evidence.model_dump(mode="json")))
        == evidence
    )
    tampered = evidence.model_dump(mode="json")
    tampered["sandbox_spec_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="SandboxSpec"):
        WindowsIsolationEvidenceV1.model_validate_json(canonical(tampered))


def test_launch_assigns_non_breakaway_job_before_resume(tmp_path: Path, monkeypatch) -> None:
    if os.name != "nt":
        pytest.skip("Win32 launch ordering")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    writable = tmp_path / "workspace"
    writable.mkdir()
    payload = profile_payload().model_copy(
        update={
            "launcher_executable_sha256": digest(executable.read_bytes()),
            "read_only_roots": (
                NativePathIdentityV1(
                    locator=str(bundle), volume_serial_number=1, file_index="1" * 16
                ),
            ),
            "writable_roots": (
                NativePathIdentityV1(
                    locator=str(writable), volume_serial_number=1, file_index="2" * 16
                ),
            ),
            "denied_roots": (),
        }
    )
    profile = WindowsIsolationProfileV1.create(payload)
    calls: list[str] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *args: object) -> int:
            if self.name == "CreateJobObjectW":
                calls.append("job_created")
                return 100
            if self.name == "AssignProcessToJobObject":
                calls.append("job_assigned")
                return 1
            if self.name == "ResumeThread":
                calls.append("thread_resumed")
                return 1
            if self.name == "Experimental_CreateProcessInSandbox":
                calls.append("created_suspended")
                information = args[-1]._obj  # type: ignore[attr-defined]
                information.process = 101
                information.thread = 102
                information.process_id = 333
                return 1
            return 1

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    monkeypatch.setattr(isolation, "observed_windows_platform", lambda: (26200, "x86_64"))
    monkeypatch.setattr(isolation, "_verify_profile_paths", lambda _: None)
    monkeypatch.setattr(
        isolation,
        "_reject_reparse_chain",
        lambda value, **_: Path(value).absolute(),
    )
    monkeypatch.setattr(isolation, "_set_job_limits", lambda *_: calls.append("limits_set"))
    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    process = isolation.launch_windows_isolated(
        profile,
        executable,
        ("-c", "pass"),
        cwd=writable,
        environment={"SYSTEMROOT": r"C:\Windows"},
    )
    assert calls == [
        "job_created",
        "limits_set",
        "created_suspended",
        "job_assigned",
        "thread_resumed",
    ]
    assert process.launch_order == ("created_suspended", "job_assigned", "thread_resumed")


def test_launch_rechecks_exact_launcher_hash_before_creating_job(
    tmp_path: Path, monkeypatch
) -> None:
    if os.name != "nt":
        pytest.skip("Win32 launcher authority")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    writable = tmp_path / "workspace"
    writable.mkdir()
    payload = profile_payload().model_copy(
        update={
            "launcher_executable_sha256": "f" * 64,
            "read_only_roots": (
                NativePathIdentityV1(
                    locator=str(bundle), volume_serial_number=1, file_index="1" * 16
                ),
            ),
            "writable_roots": (
                NativePathIdentityV1(
                    locator=str(writable), volume_serial_number=1, file_index="2" * 16
                ),
            ),
            "denied_roots": (),
        }
    )
    profile = WindowsIsolationProfileV1.create(payload)
    monkeypatch.setattr(isolation, "observed_windows_platform", lambda: (26200, "x86_64"))
    monkeypatch.setattr(isolation, "_verify_profile_paths", lambda _: None)
    with pytest.raises(ValueError, match="launcher executable hash mismatch"):
        isolation.launch_windows_isolated(
            profile,
            executable,
            ("-c", "pass"),
            cwd=writable,
            environment={"SYSTEMROOT": r"C:\Windows"},
        )


@pytest.mark.parametrize("failed_call", ["AssignProcessToJobObject", "ResumeThread"])
def test_failed_launch_closes_exact_handles_and_requires_profile_cleanup(
    failed_call: str, tmp_path: Path, monkeypatch
) -> None:
    if os.name != "nt":
        pytest.skip("Win32 launch cleanup")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    writable = tmp_path / "workspace"
    writable.mkdir()
    payload = profile_payload().model_copy(
        update={
            "launcher_executable_sha256": digest(executable.read_bytes()),
            "read_only_roots": (
                NativePathIdentityV1(
                    locator=str(bundle), volume_serial_number=1, file_index="1" * 16
                ),
            ),
            "writable_roots": (
                NativePathIdentityV1(
                    locator=str(writable), volume_serial_number=1, file_index="2" * 16
                ),
            ),
            "denied_roots": (),
        }
    )
    profile = WindowsIsolationProfileV1.create(payload)
    closed: list[int] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *args: object) -> int:
            if self.name == "CreateJobObjectW":
                return 100
            if self.name == "Experimental_CreateProcessInSandbox":
                information = args[-1]._obj  # type: ignore[attr-defined]
                information.process = 101
                information.thread = 102
                information.process_id = 333
                return 1
            if self.name == "AssignProcessToJobObject":
                return 0 if failed_call == self.name else 1
            if self.name == "ResumeThread":
                return 0xFFFFFFFF if failed_call == self.name else 1
            if self.name == "CloseHandle":
                closed.append(int(args[0]))
            return 1

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    monkeypatch.setattr(isolation, "observed_windows_platform", lambda: (26200, "x86_64"))
    monkeypatch.setattr(isolation, "_verify_profile_paths", lambda _: None)
    monkeypatch.setattr(isolation, "_set_job_limits", lambda *_: None)
    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(
        isolation,
        "_reject_reparse_chain",
        lambda value, **_: Path(value).absolute(),
    )
    monkeypatch.setattr(isolation, "_delete_appcontainer_profile", lambda _: False)
    with pytest.raises(ExceptionGroup, match="launch and cleanup failed"):
        isolation.launch_windows_isolated(
            profile,
            executable,
            ("-c", "pass"),
            cwd=writable,
            environment={"SYSTEMROOT": r"C:\Windows"},
        )
    assert closed == [102, 101, 100]


def test_local_fixed_volume_contract_rejects_network_device_and_mapped_roots(
    monkeypatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Win32 volume classification")
    with pytest.raises(ValueError, match="ordinary drive-qualified"):
        isolation._require_local_fixed_volume(Path(r"\\server\share\root"))
    with pytest.raises(ValueError, match="ordinary drive-qualified"):
        isolation._require_local_fixed_volume(Path(r"\\?\C:\root"))

    class Function:
        argtypes: object = None
        restype: object = None

        def __call__(self, *_: object) -> int:
            return 4

    class Dll:
        GetDriveTypeW = Function()

    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    with pytest.raises(ValueError, match="local fixed volume"):
        isolation._require_local_fixed_volume(Path(r"Z:\mapped"))


def test_process_close_retries_profile_deletion_after_closing_handles(monkeypatch) -> None:
    calls: list[str] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *_: object) -> int:
            calls.append(self.name)
            return 1

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    deletions = iter((False, True))
    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(isolation, "_delete_appcontainer_profile", lambda _: next(deletions))
    process = isolation.WindowsSandboxProcess(101, 102, 100, 333, "devfabric_" + ENVIRONMENT, ())
    with pytest.raises(ExceptionGroup, match="cleanup failed"):
        process.close()
    assert (process.thread_handle, process.process_handle, process.job_handle) == (0, 0, 0)
    assert process.close() is True
    assert calls.count("CloseHandle") == 3


def test_probe_cleanup_attempts_every_resource_after_failures(tmp_path: Path, monkeypatch) -> None:
    if os.name != "nt":
        pytest.skip("Windows probe cleanup")
    import importlib.util

    module_spec = importlib.util.spec_from_file_location(
        "windows_isolation_probe_cleanup_test",
        Path("scripts/probe_windows_native_isolation.py"),
    )
    assert module_spec is not None and module_spec.loader is not None
    probe = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = probe
    module_spec.loader.exec_module(probe)
    calls: list[str] = []

    class FailedProcess:
        def close(self) -> None:
            calls.append("process")
            raise OSError("process cleanup")

    class FailedListener:
        def close(self) -> None:
            calls.append("listener")
            raise OSError("listener cleanup")

    scratch = tmp_path / "scratch"
    scratch.mkdir()

    def fail_handle(_: int) -> None:
        calls.append("event")
        raise OSError("event cleanup")

    def fail_registry(_: str) -> None:
        calls.append("registry")
        raise OSError("registry cleanup")

    def fail_scratch(_: Path) -> None:
        calls.append("scratch")
        raise OSError("scratch cleanup")

    monkeypatch.setattr(probe, "_close_handle", fail_handle)
    monkeypatch.setattr(probe, "_registry_exists", lambda _: True)
    monkeypatch.setattr(probe, "_delete_registry", fail_registry)
    monkeypatch.setattr(probe.shutil, "rmtree", fail_scratch)
    errors = probe._cleanup_probe_resources(
        FailedProcess(), 44, FailedListener(), "Software\\probe", scratch
    )
    assert len(errors) == 5
    assert calls == ["process", "event", "listener", "registry", "scratch"]


def test_profile_id_golden() -> None:
    profile = WindowsIsolationProfileV1.create(profile_payload())
    assert profile.windows_isolation_profile_id == digest(
        canonical(profile.payload.model_dump(mode="json"))
    )


def test_qualify_retains_strict_profile_spec_and_receipt(tmp_path: Path, monkeypatch) -> None:
    if os.name != "nt":
        pytest.skip("Windows host qualification path")
    module_spec = importlib.util.spec_from_file_location(
        "windows_isolation_probe_test", Path("scripts/probe_windows_native_isolation.py")
    )
    assert module_spec is not None and module_spec.loader is not None
    probe = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = probe
    module_spec.loader.exec_module(probe)

    bundle_root = tmp_path / "bundle"
    python = bundle_root / "python" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"MZ-native-python")
    manifest = tmp_path / "bundle.json"
    manifest.write_bytes(b"{}")
    scratch = tmp_path / "scratch"
    output = tmp_path / "evidence.json"
    bundle = SimpleNamespace(
        bundle_id=H,
        payload=SimpleNamespace(
            codex=SimpleNamespace(executable_sha256="3" * 64),
            python=SimpleNamespace(
                executable_path="python/python.exe",
                executable_sha256=digest(python.read_bytes()),
            ),
        ),
    )

    class BundleParser:
        @classmethod
        def model_validate_json(cls, _: bytes) -> object:
            return bundle

    class Listener:
        def bind(self, _: object) -> None:
            pass

        def listen(self, _: int) -> None:
            pass

        def settimeout(self, _: float) -> None:
            pass

        def getsockname(self) -> tuple[str, int]:
            return ("127.0.0.1", 32123)

        def accept(self) -> None:
            raise TimeoutError

        def close(self) -> None:
            pass

    child = {
        "allowed_root_read_write": True,
        "inherited_handles_blocked": True,
        "inherited_handle_error_code": 6,
        "hidden_read": {"denied": True, "error_code": 5},
        "hidden_write": {"denied": True, "error_code": 5},
        "registry_write_succeeded": True,
        "registry_error_code": None,
        "loopback": {"denied": True, "error_code": 10013},
        "lan": {"denied": True, "error_code": 10013},
        "public": {"denied": True, "error_code": 10013},
        "dns": {"denied": True, "error_code": 10013},
        "grandchild_pid": 1001,
        "breakaway_blocked": True,
        "breakaway_error_code": 5,
        "breakaway_pid": None,
    }

    class Process:
        process_id = 1000

        def terminate_tree(self) -> None:
            pass

        def close(self) -> bool:
            return True

    def launch(*args: object, **_: object) -> Process:
        arguments = args[2]
        assert isinstance(arguments, tuple)
        Path(arguments[-1]).write_bytes(canonical(child))
        return Process()

    def identity(path_value: Path) -> NativePathIdentityV1:
        return NativePathIdentityV1(
            locator=str(path_value.absolute()),
            volume_serial_number=1,
            file_index=f"{abs(hash(str(path_value))) & 0xFFFFFFFFFFFFFFFF:016x}",
        )

    monkeypatch.setattr(probe, "NativeBundleV1", BundleParser)
    monkeypatch.setattr(probe, "verify_native_bundle", lambda *_, **__: None)
    monkeypatch.setattr(probe, "observed_windows_platform", lambda: (26200, "x86_64"))
    monkeypatch.setattr(probe, "windows_path_identity", identity)
    monkeypatch.setattr(probe, "_reparse_rejected", lambda *_: True)
    monkeypatch.setattr(probe, "_inheritable_event", lambda: 44)
    monkeypatch.setattr(probe, "_close_handle", lambda _: None)
    monkeypatch.setattr(probe, "_delete_registry", lambda _: None)
    monkeypatch.setattr(probe, "_registry_exists", lambda _: False)
    monkeypatch.setattr(probe.socket, "socket", lambda *_: Listener())
    monkeypatch.setattr(probe, "launch_windows_isolated", launch)
    monkeypatch.setattr(probe, "_wait_gone", lambda _: True)

    assert probe._open_process_failure_proves_absent(87) is True
    with pytest.raises(OSError, match="could not prove"):
        probe._open_process_failure_proves_absent(5)

    evidence = probe.qualify(bundle_root, manifest, scratch, output, ENVIRONMENT)
    retained = WindowsIsolationEvidenceV1.model_validate_json(output.read_bytes())
    assert retained == evidence
    assert retained.receipt.payload.no_direct_network_baseline_qualified is True
    assert retained.receipt.payload.native_executor_isolation_qualified is False
    assert retained.receipt.payload.package_readiness is False
    assert not scratch.exists()
    assert not output.with_name(output.name + ".tmp").exists()

    failed_output = tmp_path / "cleanup-failed-evidence.json"
    failed_scratch = tmp_path / "cleanup-failed-scratch"
    monkeypatch.setattr(
        probe,
        "_cleanup_probe_resources",
        lambda *_: [OSError("post-observation cleanup failed")],
    )
    with pytest.raises(ExceptionGroup, match="probe cleanup failed"):
        probe.qualify(bundle_root, manifest, failed_scratch, failed_output, ENVIRONMENT)
    assert not failed_output.exists()


@pytest.mark.parametrize("failure_stage", ["listener", "event", "registry"])
def test_qualify_cleans_every_early_acquisition_failure(
    failure_stage: str, tmp_path: Path, monkeypatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows host qualification path")
    module_spec = importlib.util.spec_from_file_location(
        f"windows_isolation_probe_early_{failure_stage}",
        Path("scripts/probe_windows_native_isolation.py"),
    )
    assert module_spec is not None and module_spec.loader is not None
    probe = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = probe
    module_spec.loader.exec_module(probe)
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    manifest = tmp_path / "bundle.json"
    manifest.write_bytes(b"{}")
    scratch = tmp_path / "scratch"
    output = tmp_path / "evidence.json"
    bundle = SimpleNamespace(bundle_id=H, payload=SimpleNamespace())

    class BundleParser:
        @classmethod
        def model_validate_json(cls, _: bytes) -> object:
            return bundle

    calls: list[str] = []

    class Listener:
        def bind(self, _: object) -> None:
            if failure_stage == "listener":
                raise OSError("listener acquisition")

        def listen(self, _: int) -> None:
            pass

        def settimeout(self, _: float) -> None:
            pass

        def close(self) -> None:
            calls.append("listener")

    original_rmtree = probe.shutil.rmtree

    def remove_scratch(path: Path) -> None:
        calls.append("scratch")
        original_rmtree(path)

    def event() -> int:
        if failure_stage == "event":
            raise OSError("event acquisition")
        return 44

    def delete_registry(_: str) -> None:
        if failure_stage == "registry" and "registry-acquisition" not in calls:
            calls.append("registry-acquisition")
            raise OSError("registry acquisition")

    monkeypatch.setattr(probe, "NativeBundleV1", BundleParser)
    monkeypatch.setattr(probe, "verify_native_bundle", lambda *_, **__: None)
    monkeypatch.setattr(probe, "observed_windows_platform", lambda: (26200, "x86_64"))
    monkeypatch.setattr(probe.socket, "socket", lambda *_: Listener())
    monkeypatch.setattr(probe, "_inheritable_event", event)
    monkeypatch.setattr(probe, "_close_handle", lambda _: calls.append("event"))
    monkeypatch.setattr(probe, "_delete_registry", delete_registry)
    monkeypatch.setattr(probe, "_registry_exists", lambda _: False)
    monkeypatch.setattr(probe.shutil, "rmtree", remove_scratch)
    with pytest.raises(OSError, match=failure_stage):
        probe.qualify(bundle_root, manifest, scratch, output, ENVIRONMENT)
    assert not output.exists()
    assert not scratch.exists()
    assert "listener" in calls
    assert "scratch" in calls
    if failure_stage == "registry":
        assert "event" in calls
