from __future__ import annotations

import ctypes
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
    WindowsIsolationEvidenceV2,
    WindowsIsolationProfilePayloadV1,
    WindowsIsolationProfilePayloadV2,
    WindowsIsolationProfileV1,
    WindowsIsolationProfileV2,
    WindowsIsolationReceiptPayloadV1,
    WindowsIsolationReceiptPayloadV2,
    WindowsIsolationReceiptV1,
    WindowsIsolationReceiptV2,
    appcontainer_identity,
    windows_isolation_bootstrap_started_id,
    windows_sandbox_spec,
)

H = "1" * 64
ENVIRONMENT = "2" * 32


def load_probe_module(name: str):
    module_spec = importlib.util.spec_from_file_location(
        name, Path("scripts/probe_windows_native_isolation.py")
    )
    assert module_spec is not None and module_spec.loader is not None
    probe = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = probe
    module_spec.loader.exec_module(probe)
    return probe


def load_bootstrap_module(name: str):
    module_spec = importlib.util.spec_from_file_location(
        name, Path("scripts/windows_isolation_child_bootstrap.py")
    )
    assert module_spec is not None and module_spec.loader is not None
    bootstrap = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = bootstrap
    module_spec.loader.exec_module(bootstrap)
    return bootstrap


def test_windows_last_error_preserves_ctypes_saved_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(isolation.ctypes, "get_last_error", lambda: 12345, raising=False)
    assert isolation._windows_last_error() == 12345


def test_windows_last_error_fails_closed_when_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(isolation.ctypes, "get_last_error", None, raising=False)
    with pytest.raises(RuntimeError, match="get_last_error is unavailable"):
        isolation._windows_last_error()


def test_windows_environment_block_is_explicit_deterministic_and_path_free() -> None:
    environment = {
        "SYSTEMROOT": r"C:\Windows",
        "PYTHONNOUSERSITE": "1",
        "LOCALAPPDATA": r"C:\scratch\allowed\local-app-data",
    }
    assert isolation._windows_environment_block(environment) == (
        "LOCALAPPDATA=C:\\scratch\\allowed\\local-app-data\0"
        "PYTHONNOUSERSITE=1\0SYSTEMROOT=C:\\Windows\0\0"
    )


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"SYSTEMROOT": r"C:\Windows"}, "LOCALAPPDATA"),
        ({"LOCALAPPDATA": r"C:\private"}, "SYSTEMROOT"),
        (
            {"SYSTEMROOT": r"C:\Windows", "LOCALAPPDATA": ""},
            "LOCALAPPDATA",
        ),
        (
            {
                "SYSTEMROOT": r"C:\Windows",
                "LOCALAPPDATA": r"C:\private",
                "Path": r"C:\host-bin",
            },
            "PATH",
        ),
        (
            {
                "SYSTEMROOT": r"C:\Windows",
                "systemroot": r"D:\Windows",
                "LOCALAPPDATA": r"C:\private",
            },
            "case-insensitively unique",
        ),
        (
            {
                "SYSTEMROOT": r"C:\Windows",
                "LOCALAPPDATA": r"C:\private",
                "BAD=NAME": "value",
            },
            "invalid name",
        ),
        (
            {
                "SYSTEMROOT": r"C:\Windows",
                "LOCALAPPDATA": r"C:\private",
                "BAD": "nul\0value",
            },
            "invalid name",
        ),
    ],
)
def test_windows_environment_block_rejects_missing_or_ambient_authority(
    environment: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        isolation._windows_environment_block(environment)


def test_missing_systemroot_fails_before_native_api_acquisition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation,
        "_windows_dll",
        lambda *_: pytest.fail("native API acquired before environment validation"),
    )
    with pytest.raises(ValueError, match="SYSTEMROOT"):
        isolation.launch_windows_isolated(
            WindowsIsolationProfileV1.create(profile_payload()),
            Path(r"C:\qualification\bundle\python.exe"),
            ("-c", "pass"),
            cwd=Path(r"C:\qualification\workspace"),
            environment={},
        )


def test_caller_supplied_local_app_data_fails_before_native_api_acquisition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        isolation,
        "_windows_dll",
        lambda *_: pytest.fail("native API acquired before environment validation"),
    )
    with pytest.raises(ValueError, match="LOCALAPPDATA is host-owned"):
        isolation.launch_windows_isolated(
            WindowsIsolationProfileV1.create(profile_payload()),
            Path(r"C:\qualification\bundle\python.exe"),
            ("-c", "pass"),
            cwd=Path(r"C:\qualification\workspace"),
            environment={
                "SYSTEMROOT": r"C:\Windows",
                "LOCALAPPDATA": r"C:\caller-controlled",
            },
        )


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


def receipt_payload(
    profile: WindowsIsolationProfileV1 | WindowsIsolationProfileV2,
) -> dict[str, object]:
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


def profile_payload_v2() -> WindowsIsolationProfilePayloadV2:
    payload = profile_payload().model_dump(mode="python")
    payload["schema_version"] = 2
    return WindowsIsolationProfilePayloadV2(
        **payload,
        child_bootstrap_sha256="6" * 64,
    )


def receipt_payload_v2(profile: WindowsIsolationProfileV2) -> dict[str, object]:
    payload = receipt_payload(profile)
    payload["schema_version"] = 2
    payload["windows_isolation_profile_id"] = profile.windows_isolation_profile_id
    payload["child_bootstrap_sha256"] = profile.payload.child_bootstrap_sha256
    payload["bootstrap_started_id"] = windows_isolation_bootstrap_started_id(profile)
    payload["bootstrap_started_validated"] = True
    return payload


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
def test_v2_profile_receipt_and_evidence_bind_child_bootstrap_without_reinterpreting_v1() -> None:
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    receipt = WindowsIsolationReceiptV2.create(
        WindowsIsolationReceiptPayloadV2.model_validate(receipt_payload_v2(profile))
    )
    spec = windows_sandbox_spec(profile)
    evidence = WindowsIsolationEvidenceV2.create(profile, spec, receipt)
    assert evidence == WindowsIsolationEvidenceV2.model_validate_json(
        canonical(evidence.model_dump(mode="json"))
    )
    assert evidence.receipt.payload.child_bootstrap_sha256 == "6" * 64
    assert evidence.receipt.payload.bootstrap_started_validated is True
    assert evidence.receipt.payload.bootstrap_started_id == windows_isolation_bootstrap_started_id(
        profile
    )

    with pytest.raises(ValidationError):
        WindowsIsolationProfileV1.model_validate_json(canonical(profile.model_dump(mode="json")))
    changed = evidence.model_dump(mode="json")
    wrong_receipt_payload = receipt.payload.model_copy(update={"child_bootstrap_sha256": "f" * 64})
    changed["receipt"] = WindowsIsolationReceiptV2.create(wrong_receipt_payload).model_dump(
        mode="json"
    )
    with pytest.raises(ValidationError, match="does not bind"):
        WindowsIsolationEvidenceV2.model_validate_json(canonical(changed))

    changed = evidence.model_dump(mode="json")
    wrong_started_payload = receipt.payload.model_copy(update={"bootstrap_started_id": "e" * 64})
    changed["receipt"] = WindowsIsolationReceiptV2.create(wrong_started_payload).model_dump(
        mode="json"
    )
    with pytest.raises(ValidationError, match="does not bind"):
        WindowsIsolationEvidenceV2.model_validate_json(canonical(changed))

    missing = receipt_payload_v2(profile)
    del missing["bootstrap_started_id"]
    with pytest.raises(ValidationError):
        WindowsIsolationReceiptPayloadV2.model_validate(missing)


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
    local_app_data = tmp_path / "official-profile-local"
    local_app_data.mkdir()
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
    supplied_environment = {"SYSTEMROOT": r"C:\Windows"}
    expected_environment = {
        "SYSTEMROOT": r"C:\Windows",
        "LOCALAPPDATA": str(local_app_data),
    }
    expected_environment_block = isolation._windows_environment_block(expected_environment)

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
                assert int(args[5]) & 0x400
                assert ctypes.wstring_at(args[6], len(expected_environment_block)) == (
                    expected_environment_block
                )
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
        lambda value, **_: Path(os.path.abspath(value)),
    )
    monkeypatch.setattr(isolation, "_set_job_limits", lambda *_: calls.append("limits_set"))
    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(
        isolation,
        "_create_owned_appcontainer_profile",
        lambda identity: isolation.OwnedAppContainerProfile(
            identity, "S-1-15-2-123", local_app_data
        ),
    )
    process = isolation.launch_windows_isolated(
        profile,
        executable,
        ("-c", "pass"),
        cwd=writable,
        environment=supplied_environment,
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


def test_preexisting_appcontainer_profile_is_rejected_and_never_deleted(monkeypatch) -> None:
    class Function:
        argtypes: object = None
        restype: object = None

        def __call__(self, *_: object) -> int:
            return 0x800700B7

    class Dll:
        def __getattr__(self, _: str) -> Function:
            return Function()

    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda _: pytest.fail("foreign AppContainer profile was deleted"),
    )
    with pytest.raises(isolation.WindowsIsolationLaunchError) as failure:
        isolation._create_owned_appcontainer_profile("devfabric_" + ENVIRONMENT)
    assert failure.value.phase == "appcontainer_profile_create"
    assert failure.value.error_code == 183


def test_owned_appcontainer_profile_binds_sid_and_official_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sid_text = ctypes.create_unicode_buffer("S-1-15-2-123")
    folder = tmp_path / "official-profile-local"
    folder.mkdir()
    folder_text = ctypes.create_unicode_buffer(str(folder))
    frees: list[str] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *args: object) -> int | None:
            if self.name == "CreateAppContainerProfile":
                args[-1]._obj.value = 1234  # type: ignore[attr-defined]
                return 0
            if self.name == "ConvertSidToStringSidW":
                args[-1]._obj.value = ctypes.addressof(sid_text)  # type: ignore[attr-defined]
                return 1
            if self.name == "GetAppContainerFolderPath":
                args[-1]._obj.value = ctypes.addressof(folder_text)  # type: ignore[attr-defined]
                return 0
            if self.name in {"LocalFree", "FreeSid", "CoTaskMemFree"}:
                frees.append(self.name)
                return None
            raise AssertionError(self.name)

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(isolation, "_reject_reparse_chain", lambda value, **_: Path(value))
    owned = isolation._create_owned_appcontainer_profile("devfabric_" + ENVIRONMENT)
    assert owned == isolation.OwnedAppContainerProfile(
        "devfabric_" + ENVIRONMENT, "S-1-15-2-123", folder
    )
    assert frees == ["CoTaskMemFree", "LocalFree", "FreeSid"]


def test_partial_profile_preparation_deletes_only_the_owned_profile(monkeypatch) -> None:
    sid_text = ctypes.create_unicode_buffer("S-1-15-2-123")
    calls: list[str] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *args: object) -> int | None:
            if self.name == "CreateAppContainerProfile":
                args[-1]._obj.value = 1234  # type: ignore[attr-defined]
                return 0
            if self.name == "ConvertSidToStringSidW":
                args[-1]._obj.value = ctypes.addressof(sid_text)  # type: ignore[attr-defined]
                return 1
            if self.name == "GetAppContainerFolderPath":
                return 0x80070003
            if self.name in {"LocalFree", "FreeSid"}:
                calls.append(self.name)
                return None
            raise AssertionError(self.name)

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    identity = "devfabric_" + ENVIRONMENT
    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda observed: calls.append(f"delete:{observed}") or True,
    )
    with pytest.raises(isolation.WindowsIsolationLaunchError) as failure:
        isolation._create_owned_appcontainer_profile(identity)
    assert failure.value.phase == "appcontainer_folder_path"
    assert failure.value.error_code == 3
    assert calls == [f"delete:{identity}", "LocalFree", "FreeSid"]


@pytest.mark.parametrize("failure_phase", ["environment", "job", "processmodel"])
def test_every_post_profile_preprocess_failure_cleans_owned_profile(
    failure_phase: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    writable = tmp_path / "workspace"
    writable.mkdir()
    official = tmp_path / "official-profile-local"
    official.mkdir()
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
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
    )
    calls: list[str] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *_: object) -> int:
            if self.name == "CreateJobObjectW":
                return 0 if failure_phase == "job" else 100
            if self.name == "TerminateJobObject":
                calls.append("terminate-job")
            if self.name == "CloseHandle":
                calls.append("close-job")
            return 1

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    real_environment_block = isolation._windows_environment_block
    environment_calls = 0

    def environment_block(values: dict[str, str], *, require_local_app_data: bool = True) -> str:
        nonlocal environment_calls
        environment_calls += 1
        if failure_phase == "environment" and environment_calls == 2:
            raise ValueError("injected child environment failure")
        return real_environment_block(values, require_local_app_data=require_local_app_data)

    def dll(name: str) -> Dll:
        if name == "processmodel.dll" and failure_phase == "processmodel":
            raise OSError("injected processmodel failure")
        return Dll()

    monkeypatch.setattr(isolation, "observed_windows_platform", lambda: (26200, "x86_64"))
    monkeypatch.setattr(isolation, "_verify_profile_paths", lambda _: None)
    monkeypatch.setattr(
        isolation,
        "_reject_reparse_chain",
        lambda value, **_: Path(value).absolute(),
    )
    monkeypatch.setattr(isolation, "_windows_environment_block", environment_block)
    monkeypatch.setattr(isolation, "_windows_dll", dll)
    monkeypatch.setattr(isolation, "_windows_last_error", lambda: 183)
    monkeypatch.setattr(isolation, "_set_job_limits", lambda *_: None)
    monkeypatch.setattr(
        isolation,
        "_create_owned_appcontainer_profile",
        lambda identity: isolation.OwnedAppContainerProfile(identity, "S-1-15-2-123", official),
    )
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda observed: calls.append(f"delete:{observed}") or True,
    )
    with pytest.raises((ValueError, OSError, isolation.WindowsIsolationLaunchError)):
        isolation.launch_windows_isolated(
            profile,
            executable,
            ("-c", "pass"),
            cwd=writable,
            environment={"SYSTEMROOT": r"C:\Windows"},
        )
    assert calls[-1] == f"delete:{profile.payload.appcontainer_identity}"
    if failure_phase == "processmodel":
        assert calls == ["terminate-job", "close-job", calls[-1]]


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
    local_app_data = tmp_path / "official-profile-local"
    local_app_data.mkdir()
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
    cleanup_order: list[str] = []

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
            if self.name in {"TerminateProcess", "TerminateJobObject"}:
                cleanup_order.append(self.name)
                return 1
            if self.name == "CloseHandle":
                cleanup_order.append(f"close:{int(args[0])}")
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
        "_create_owned_appcontainer_profile",
        lambda identity: isolation.OwnedAppContainerProfile(
            identity, "S-1-15-2-123", local_app_data
        ),
    )
    monkeypatch.setattr(
        isolation,
        "_reject_reparse_chain",
        lambda value, **_: Path(value).absolute(),
    )
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda _: cleanup_order.append("delete") or False,
    )
    with pytest.raises(ExceptionGroup, match="launch and cleanup failed"):
        isolation.launch_windows_isolated(
            profile,
            executable,
            ("-c", "pass"),
            cwd=writable,
            environment={"SYSTEMROOT": r"C:\Windows"},
        )
    assert cleanup_order == [
        "TerminateProcess",
        "TerminateJobObject",
        "close:102",
        "close:101",
        "close:100",
        "delete",
    ]


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


@pytest.mark.parametrize(
    ("wait_result", "exit_code", "expected"),
    [(0x102, 0, None), (0, 0xC0000135, 0xC0000135)],
)
def test_process_poll_exit_code_uses_retained_handle_and_preserves_unsigned_status(
    wait_result: int,
    exit_code: int,
    expected: int | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name

        def __call__(self, *args: object) -> int:
            calls.append((self.name, int(args[0])))
            if self.name == "WaitForSingleObject":
                assert args[1] == 0
                return wait_result
            assert self.name == "GetExitCodeProcess"
            args[1]._obj.value = exit_code  # type: ignore[attr-defined]
            return 1

    class Dll:
        WaitForSingleObject = Function("WaitForSingleObject")
        GetExitCodeProcess = Function("GetExitCodeProcess")

    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    process = isolation.WindowsSandboxProcess(101, 102, 100, 333, "devfabric_" + ENVIRONMENT, ())
    assert process.poll_exit_code() == expected
    assert calls[0] == ("WaitForSingleObject", 101)
    assert ("GetExitCodeProcess", 101) in calls if expected is not None else len(calls) == 1


@pytest.mark.parametrize("failure", ["TerminateJobObject", "CloseHandle"])
def test_process_close_never_deletes_profile_before_process_cleanup(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name
            self.failed = False

        def __call__(self, *_: object) -> int:
            calls.append(self.name)
            if self.name == failure and not self.failed:
                self.failed = True
                return 0
            return 1

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(isolation, "_windows_last_error", lambda: 5)
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda _: pytest.fail("profile deleted before process cleanup completed"),
    )
    process = isolation.WindowsSandboxProcess(101, 102, 100, 333, "devfabric_" + ENVIRONMENT, ())
    with pytest.raises(ExceptionGroup, match="cleanup failed"):
        process.close()
    assert "DeleteAppContainerProfile" not in calls
    if failure == "TerminateJobObject":
        assert (process.thread_handle, process.process_handle, process.job_handle) == (
            102,
            101,
            100,
        )
    else:
        assert process.thread_handle == 102


@pytest.mark.parametrize("failure", ["TerminateProcess", "CloseHandle"])
def test_failed_launch_cleanup_retains_profile_when_process_cleanup_fails(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    class Function:
        argtypes: object = None
        restype: object = None

        def __init__(self, name: str) -> None:
            self.name = name
            self.failed = False

        def __call__(self, *_: object) -> int:
            calls.append(self.name)
            if self.name == failure and not self.failed:
                self.failed = True
                return 0
            return 1

    class Dll:
        def __getattr__(self, name: str) -> Function:
            return Function(name)

    monkeypatch.setattr(isolation, "_windows_last_error", lambda: 5)
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda _: pytest.fail("profile deleted after incomplete failed-launch cleanup"),
    )
    errors = isolation._cleanup_failed_launch(
        Dll(),
        process_handle=101,
        thread_handle=102,
        job_handle=100,
        appcontainer_identity="devfabric_" + ENVIRONMENT,
        appcontainer_profile_owned=True,
    )
    assert len(errors) == 2
    assert "retained because process cleanup did not complete" in str(errors[-1])
    assert "DeleteAppContainerProfile" not in calls


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


def _bootstrap_argv(
    tmp_path: Path,
    child_source: str,
) -> tuple[list[str], Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    child = tmp_path / "child.py"
    request = tmp_path / "request.json"
    result = tmp_path / "result.json"
    failure = tmp_path / "failure.json"
    status = tmp_path / "bootstrap-started.json"
    child.write_text(child_source, encoding="utf-8")
    source = Path("scripts/windows_isolation_child_bootstrap.py")
    bootstrap_sha = digest(source.read_bytes())
    probe_sha = digest(child.read_bytes())
    return (
        [
            str(source),
            str(child),
            str(request),
            str(result),
            str(failure),
            str(status),
            bootstrap_sha,
            ENVIRONMENT,
            "7" * 64,
            probe_sha,
        ],
        result,
        failure,
        status,
    )


def test_stdlib_bootstrap_writes_bound_started_frame_before_valid_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = load_bootstrap_module("windows_isolation_bootstrap_success_test")
    argv, result, failure, status = _bootstrap_argv(
        tmp_path,
        "def _child_guarded(request, result, failure):\n"
        "    result.write_bytes(b'{}')\n"
        "    return 0\n",
    )
    monkeypatch.setattr(sys, "argv", argv)

    assert bootstrap.main() == 0
    assert result.read_bytes() == b"{}"
    assert not failure.exists()
    frame = json.loads(status.read_bytes())
    payload = frame["payload"]
    assert set(frame) == {"bootstrap_started_id", "payload"}
    assert payload == {
        "child_bootstrap_sha256": argv[6],
        "environment_instance_id": ENVIRONMENT,
        "phase": "bootstrap_started",
        "probe_sha256": argv[9],
        "schema_version": 1,
        "windows_isolation_profile_id": "7" * 64,
    }
    assert frame["bootstrap_started_id"] == digest(canonical(payload))


def test_stdlib_bootstrap_distinguishes_status_import_and_failure_write_denials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status_denied = load_bootstrap_module("windows_isolation_bootstrap_status_denied_test")
    argv, _, failure, status = _bootstrap_argv(tmp_path / "status", "pass\n")
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(
        status_denied,
        "_atomic_write",
        lambda *_: (_ for _ in ()).throw(PermissionError(13, "denied")),
    )
    assert status_denied.main() == status_denied.EXIT_STATUS_WRITE_DENIED
    assert not status.exists()
    assert not failure.exists()

    import_failed = load_bootstrap_module("windows_isolation_bootstrap_import_failed_test")
    import_root = tmp_path / "import"
    import_root.mkdir()
    argv, _, failure, status = _bootstrap_argv(
        import_root, "raise ImportError('sensitive import detail')\n"
    )
    monkeypatch.setattr(sys, "argv", argv)
    assert import_failed.main() == import_failed.EXIT_IMPORT_FAILED
    assert status.is_file()
    observed = json.loads(failure.read_bytes())
    assert observed == {
        "errno": None,
        "exception_class": "ImportError",
        "phase": "bootstrap_import",
        "schema_version": 2,
        "winerror": None,
    }
    assert b"sensitive" not in failure.read_bytes()

    write_denied = load_bootstrap_module("windows_isolation_bootstrap_failure_denied_test")
    denied_root = tmp_path / "failure-write"
    denied_root.mkdir()
    argv, _, failure, status = _bootstrap_argv(denied_root, "raise ImportError('not retained')\n")
    writes = 0
    original_write = write_denied._atomic_write

    def deny_second_write(path: Path, payload: bytes) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise PermissionError(13, "denied")
        original_write(path, payload)

    monkeypatch.setattr(write_denied, "_atomic_write", deny_second_write)
    monkeypatch.setattr(sys, "argv", argv)
    assert write_denied.main() == write_denied.EXIT_IMPORT_FAILURE_WRITE_DENIED
    assert status.is_file()
    assert not failure.exists()


def test_stdlib_bootstrap_distinguishes_invoke_failure_and_self_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = load_bootstrap_module("windows_isolation_bootstrap_invoke_test")
    argv, _, failure, status = _bootstrap_argv(
        tmp_path,
        "def _child_guarded(request, result, failure):\n"
        "    raise RuntimeError('sensitive invocation detail')\n",
    )
    monkeypatch.setattr(sys, "argv", argv)
    assert bootstrap.main() == bootstrap.EXIT_INVOKE_FAILED
    assert status.is_file()
    observed = json.loads(failure.read_bytes())
    assert observed["phase"] == "bootstrap_invoke"
    assert observed["exception_class"] == "RuntimeError"
    assert b"sensitive" not in failure.read_bytes()

    tampered = load_bootstrap_module("windows_isolation_bootstrap_tamper_test")
    tamper_root = tmp_path / "tamper"
    tamper_root.mkdir()
    argv, _, failure, status = _bootstrap_argv(tamper_root, "pass\n")
    argv[6] = "f" * 64
    monkeypatch.setattr(sys, "argv", argv)
    assert tampered.main() == tampered.EXIT_SELF_HASH_MISMATCH
    assert not status.exists()
    assert not failure.exists()

    probe_tampered = load_bootstrap_module("windows_isolation_bootstrap_probe_tamper_test")
    probe_root = tmp_path / "probe-tamper"
    probe_root.mkdir()
    argv, _, failure, status = _bootstrap_argv(probe_root, "pass\n")
    Path(argv[1]).write_text("# changed after authority hash\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", argv)
    assert probe_tampered.main() == probe_tampered.EXIT_PROBE_HASH_MISMATCH
    assert not status.exists()
    assert not failure.exists()


def test_stdlib_bootstrap_bounds_failure_before_writing_and_reserves_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bootstrap = load_bootstrap_module("windows_isolation_bootstrap_oversize_test")
    oversized_name = "X" * 5000
    argv, _, failure, status = _bootstrap_argv(
        tmp_path,
        f"Oversized = type({oversized_name!r}, (Exception,), {{}})\n"
        "def _child_guarded(request, result, failure):\n"
        "    raise Oversized()\n",
    )
    monkeypatch.setattr(sys, "argv", argv)
    assert bootstrap.main() == bootstrap.EXIT_INVOKE_FAILURE_TOO_LARGE
    assert status.is_file()
    assert not failure.exists()

    exit_codes = {
        bootstrap.EXIT_ARGUMENTS_INVALID,
        bootstrap.EXIT_SELF_HASH_MISMATCH,
        bootstrap.EXIT_PROBE_HASH_MISMATCH,
        bootstrap.EXIT_STATUS_WRITE_DENIED,
        bootstrap.EXIT_IMPORT_FAILED,
        bootstrap.EXIT_IMPORT_FAILURE_WRITE_DENIED,
        bootstrap.EXIT_IMPORT_FAILURE_TOO_LARGE,
        bootstrap.EXIT_INVOKE_FAILED,
        bootstrap.EXIT_INVOKE_FAILURE_WRITE_DENIED,
        bootstrap.EXIT_INVOKE_FAILURE_TOO_LARGE,
    }
    assert len(exit_codes) == 10
    assert exit_codes == set(range(189, 199))


def test_child_exit_diagnostic_distinguishes_ntstatus_python_failure_and_malformed_data(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows child diagnostic path")
    probe = load_probe_module("windows_isolation_child_failure_test")
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    result = tmp_path / "child-result.json"
    failure = tmp_path / "child-failure.json"
    bootstrap = tmp_path / "bootstrap-started.json"

    process = SimpleNamespace(poll_exit_code=lambda: 0xC0000135)
    with pytest.raises(probe.WindowsIsolationChildExitError) as loader_failure:
        probe._raise_if_child_exited(process, result, failure, bootstrap, profile, ENVIRONMENT)
    assert loader_failure.value.exit_code == 0xC0000135
    assert loader_failure.value.diagnostic.payload.bootstrap_started_status == "absent"
    assert loader_failure.value.diagnostic.payload.child_failure_status == "absent"
    assert "0xC0000135" in str(loader_failure.value)

    started_payload = probe.WindowsIsolationBootstrapStartedPayloadV1(
        child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
        environment_instance_id=ENVIRONMENT,
        windows_isolation_profile_id=profile.windows_isolation_profile_id,
        probe_sha256=profile.payload.probe_sha256,
    )
    started = probe.WindowsIsolationBootstrapStartedV1(
        bootstrap_started_id=digest(canonical(started_payload.model_dump(mode="json"))),
        payload=started_payload,
    )
    bootstrap.write_bytes(canonical(started.model_dump(mode="json")))
    failure.write_bytes(
        canonical(
            {
                "schema_version": 2,
                "phase": "child_probe",
                "exception_class": "PermissionError",
                "winerror": 5,
                "errno": 13,
            }
        )
    )
    process = SimpleNamespace(poll_exit_code=lambda: 1)
    with pytest.raises(probe.WindowsIsolationChildExitError) as python_failure:
        probe._raise_if_child_exited(process, result, failure, bootstrap, profile, ENVIRONMENT)
    diagnostic = python_failure.value.diagnostic.payload
    assert diagnostic.process_exit_code == 1
    assert diagnostic.bootstrap_started_status == "validated"
    assert diagnostic.bootstrap_started == started
    assert diagnostic.child_failure_status == "validated"
    assert diagnostic.child_failure.exception_class == "PermissionError"
    assert diagnostic.child_failure.winerror == 5
    assert diagnostic.child_failure.errno == 13

    failure.write_bytes(b"{" + b"x" * probe.MAX_CHILD_FAILURE_BYTES)
    with pytest.raises(probe.WindowsIsolationChildExitError) as malformed:
        probe._raise_if_child_exited(process, result, failure, bootstrap, profile, ENVIRONMENT)
    assert malformed.value.diagnostic.payload.child_failure_status == "invalid"
    assert malformed.value.diagnostic.payload.child_failure is None

    tampered = json.loads(bootstrap.read_bytes())
    tampered["payload"]["probe_sha256"] = "f" * 64
    bootstrap.write_bytes(canonical(tampered))
    failure.unlink()
    with pytest.raises(probe.WindowsIsolationChildExitError) as invalid_started:
        probe._raise_if_child_exited(process, result, failure, bootstrap, profile, ENVIRONMENT)
    assert invalid_started.value.diagnostic.payload.bootstrap_started_status == "invalid"


@pytest.mark.parametrize(
    ("field", "foreign_value"),
    [
        ("environment_instance_id", "e" * 32),
        ("windows_isolation_profile_id", "8" * 64),
        ("child_bootstrap_sha256", "9" * 64),
        ("probe_sha256", "a" * 64),
    ],
)
def test_valid_foreign_bootstrap_marker_retains_cleanup_sealed_failure_diagnostic(
    field: str,
    foreign_value: str,
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows child diagnostic path")
    probe = load_probe_module(f"windows_isolation_foreign_marker_{field}_test")
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    result = tmp_path / "child-result.json"
    child_failure = tmp_path / "child-failure.json"
    bootstrap = tmp_path / "bootstrap-started.json"
    success_output = tmp_path / "success.json"
    failure_output = success_output.with_name(success_output.name + ".failure.json")
    values = {
        "child_bootstrap_sha256": profile.payload.child_bootstrap_sha256,
        "environment_instance_id": ENVIRONMENT,
        "windows_isolation_profile_id": profile.windows_isolation_profile_id,
        "probe_sha256": profile.payload.probe_sha256,
    }
    values[field] = foreign_value
    started_payload = probe.WindowsIsolationBootstrapStartedPayloadV1(**values)
    started = probe.WindowsIsolationBootstrapStartedV1(
        bootstrap_started_id=digest(canonical(started_payload.model_dump(mode="json"))),
        payload=started_payload,
    )
    bootstrap.write_bytes(canonical(started.model_dump(mode="json")))
    process = SimpleNamespace(poll_exit_code=lambda: 1)

    with pytest.raises(probe.WindowsIsolationChildExitError) as exited:
        probe._raise_if_child_exited(
            process,
            result,
            child_failure,
            bootstrap,
            profile,
            ENVIRONMENT,
        )
    diagnostic = exited.value.diagnostic
    assert diagnostic.payload.bootstrap_started_status == "invalid"
    assert diagnostic.payload.bootstrap_started is None

    with pytest.raises(probe.WindowsIsolationChildExitError):
        probe._raise_after_cleanup(exited.value, [], diagnostic, failure_output)
    assert not success_output.exists()
    retained = probe.WindowsIsolationFailureDiagnosticV2.model_validate_json(
        failure_output.read_bytes()
    )
    assert retained == diagnostic


def test_child_result_precedes_exit_diagnostic_and_running_child_remains_pending(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows child diagnostic path")
    probe = load_probe_module("windows_isolation_child_state_test")
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    result = tmp_path / "child-result.json"
    failure = tmp_path / "child-failure.json"
    bootstrap = tmp_path / "bootstrap-started.json"
    result.write_bytes(b"{}")
    process = SimpleNamespace(
        poll_exit_code=lambda: pytest.fail("exit code inspected after success result existed")
    )
    probe._raise_if_child_exited(process, result, failure, bootstrap, profile, ENVIRONMENT)

    result.unlink()
    process = SimpleNamespace(poll_exit_code=lambda: None)
    probe._raise_if_child_exited(process, result, failure, bootstrap, profile, ENVIRONMENT)


def test_child_guard_writes_only_bounded_strict_failure_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows child diagnostic path")
    probe = load_probe_module("windows_isolation_child_guard_test")
    request = tmp_path / "request.json"
    result = tmp_path / "result.json"
    failure = tmp_path / "failure.json"
    error = PermissionError(13, "sensitive path must not be retained")
    monkeypatch.setattr(probe, "_child", lambda *_: (_ for _ in ()).throw(error))

    assert probe._child_guarded(request, result, failure) == 1
    observed = probe.WindowsIsolationChildFailureV2.model_validate_json(failure.read_bytes())
    assert observed.exception_class == "PermissionError"
    assert observed.errno == 13
    assert len(failure.read_bytes()) <= probe.MAX_CHILD_FAILURE_BYTES
    assert b"sensitive" not in failure.read_bytes()
    assert not result.exists()


def test_retained_v1_failure_diagnostic_remains_strictly_parseable() -> None:
    if os.name != "nt":
        pytest.skip("Windows child diagnostic path")
    probe = load_probe_module("windows_isolation_failure_v1_compatibility_test")
    payload = probe.WindowsIsolationFailureDiagnosticPayloadV1(
        environment_instance_id=ENVIRONMENT,
        windows_isolation_profile_id="7" * 64,
        probe_sha256="4" * 64,
        process_exit_code=1,
        child_failure_status="absent",
    )
    retained = probe.WindowsIsolationFailureDiagnosticV1.create(payload)
    encoded = canonical(retained.model_dump(mode="json"))
    assert probe.WindowsIsolationFailureDiagnosticV1.model_validate_json(encoded) == retained
    with pytest.raises(ValidationError):
        probe.WindowsIsolationFailureDiagnosticV2.model_validate_json(encoded)


def test_failure_diagnostic_publishes_only_after_clean_cleanup(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows child diagnostic path")
    probe = load_probe_module("windows_isolation_failure_publish_test")
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    diagnostic = probe.WindowsIsolationFailureDiagnosticV2.create(
        probe.WindowsIsolationFailureDiagnosticPayloadV2(
            environment_instance_id=ENVIRONMENT,
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            probe_sha256=profile.payload.probe_sha256,
            child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
            process_exit_code=0xC0000135,
            bootstrap_started_status="absent",
            child_failure_status="absent",
        )
    )
    output = tmp_path / "diagnostic.json"
    error = probe.WindowsIsolationChildExitError(diagnostic)
    with pytest.raises(probe.WindowsIsolationChildExitError):
        probe._raise_after_cleanup(error, [], diagnostic, output)
    retained = probe.WindowsIsolationFailureDiagnosticV2.model_validate_json(output.read_bytes())
    assert retained == diagnostic

    blocked = tmp_path / "blocked.json"
    with pytest.raises(BaseExceptionGroup, match="probe and cleanup failed"):
        probe._raise_after_cleanup(error, [OSError("cleanup")], diagnostic, blocked)
    assert not blocked.exists()


def test_probe_child_cli_forwards_all_three_paths_and_rejects_missing_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows probe CLI child path")
    probe = load_probe_module("windows_isolation_child_cli_test")
    request = tmp_path / "request.json"
    result = tmp_path / "result.json"
    failure = tmp_path / "failure.json"
    forwarded: list[tuple[Path, Path, Path]] = []
    monkeypatch.setattr(
        probe,
        "_child_guarded",
        lambda request_path, result_path, failure_path: forwarded.append(
            (request_path, result_path, failure_path)
        )
        or 7,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["probe_windows_native_isolation.py", "--child", str(request), str(result), str(failure)],
    )
    with pytest.raises(SystemExit) as completed:
        probe.main()
    assert completed.value.code == 7
    assert forwarded == [(request, result, failure)]

    forwarded.clear()
    monkeypatch.setattr(
        sys,
        "argv",
        ["probe_windows_native_isolation.py", "--child", str(request), str(result)],
    )
    with pytest.raises(SystemExit) as rejected:
        probe.main()
    assert rejected.value.code == 2
    assert forwarded == []


def test_profile_id_golden() -> None:
    profile = WindowsIsolationProfileV1.create(profile_payload())
    assert profile.windows_isolation_profile_id == digest(
        canonical(profile.payload.model_dump(mode="json"))
    )


def test_probe_main_forwards_host_arguments_by_qualify_parameter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    if os.name != "nt":
        pytest.skip("Windows probe CLI path")
    module_spec = importlib.util.spec_from_file_location(
        "windows_isolation_probe_main_test",
        Path("scripts/probe_windows_native_isolation.py"),
    )
    assert module_spec is not None and module_spec.loader is not None
    probe = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = probe
    module_spec.loader.exec_module(probe)
    bundle_root = tmp_path / "bundle"
    bundle_manifest = tmp_path / "bundle.json"
    scratch = tmp_path / "scratch"
    output = tmp_path / "evidence.json"
    forwarded: dict[str, object] = {}

    def qualify(**kwargs: object) -> object:
        forwarded.update(kwargs)
        return SimpleNamespace(model_dump=lambda **_: {"status": "passed"})

    monkeypatch.setattr(probe, "qualify", qualify)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "probe_windows_native_isolation.py",
            "--bundle",
            str(bundle_root),
            "--bundle-manifest",
            str(bundle_manifest),
            "--scratch",
            str(scratch),
            "--output",
            str(output),
            "--environment-instance-id",
            ENVIRONMENT,
        ],
    )

    probe.main()

    assert forwarded == {
        "bundle_root": bundle_root,
        "bundle_manifest": bundle_manifest,
        "scratch": scratch,
        "output": output,
        "environment_instance_id": ENVIRONMENT,
    }
    assert json.loads(capsys.readouterr().out) == {"status": "passed"}


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

        def poll_exit_code(self) -> None:
            return None

        def terminate_tree(self) -> None:
            pass

        def close(self) -> bool:
            return True

    marker_mode = {"value": "valid"}

    def launch(*args: object, **kwargs: object) -> Process:
        arguments = args[2]
        assert isinstance(arguments, tuple)
        environment = kwargs["environment"]
        assert isinstance(environment, dict)
        assert set(environment) == {
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "PYTHONDONTWRITEBYTECODE",
            "PYTHONNOUSERSITE",
        }
        assert all(name.casefold() != "path" for name in environment)
        assert all(name.casefold() != "localappdata" for name in environment)
        bootstrap_payload = probe.WindowsIsolationBootstrapStartedPayloadV1(
            child_bootstrap_sha256=arguments[8],
            environment_instance_id=arguments[9],
            windows_isolation_profile_id=arguments[10],
            probe_sha256=arguments[11],
        )
        bootstrap_started = probe.WindowsIsolationBootstrapStartedV1(
            bootstrap_started_id=digest(canonical(bootstrap_payload.model_dump(mode="json"))),
            payload=bootstrap_payload,
        )
        if marker_mode["value"] != "missing":
            started_json = bootstrap_started.model_dump(mode="json")
            if marker_mode["value"] == "tampered":
                started_json["payload"]["probe_sha256"] = "f" * 64
            Path(arguments[7]).write_bytes(canonical(started_json))
        Path(arguments[5]).write_bytes(canonical(child))
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
    retained = WindowsIsolationEvidenceV2.model_validate_json(output.read_bytes())
    assert retained == evidence
    assert retained.receipt.payload.no_direct_network_baseline_qualified is True
    assert retained.receipt.payload.native_executor_isolation_qualified is False
    assert retained.receipt.payload.package_readiness is False
    assert not scratch.exists()
    assert not output.with_name(output.name + ".tmp").exists()

    for mode in ("missing", "tampered"):
        marker_mode["value"] = mode
        rejected_output = tmp_path / f"{mode}-marker-evidence.json"
        rejected_scratch = tmp_path / f"{mode}-marker-scratch"
        with pytest.raises(
            RuntimeError, match=f"frame is {'absent' if mode == 'missing' else 'invalid'}"
        ):
            probe.qualify(
                bundle_root,
                manifest,
                rejected_scratch,
                rejected_output,
                ENVIRONMENT,
            )
        assert not rejected_output.exists()
        assert not rejected_output.with_name(rejected_output.name + ".failure.json").exists()
        assert not rejected_scratch.exists()

    failed_output = tmp_path / "cleanup-failed-evidence.json"
    failed_scratch = tmp_path / "cleanup-failed-scratch"
    marker_mode["value"] = "valid"
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
