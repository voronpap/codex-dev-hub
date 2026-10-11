from __future__ import annotations

import ctypes
import importlib.util
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import devhub.windows_isolation as isolation
from devhub.benchmark import canonical, digest
from devhub.windows_isolation import (
    WINDOWS_RUNTIME_ACCESS_INHERITANCE,
    WINDOWS_RUNTIME_ACCESS_MASK,
    WINDOWS_SANDBOX_SCHEMA_IDENTITY,
    NativePathIdentityV1,
    WindowsIsolationChildResultV1,
    WindowsIsolationEvidenceV1,
    WindowsIsolationEvidenceV2,
    WindowsIsolationEvidenceV3,
    WindowsIsolationEvidenceV4,
    WindowsIsolationProfilePayloadV1,
    WindowsIsolationProfilePayloadV2,
    WindowsIsolationProfileV1,
    WindowsIsolationProfileV2,
    WindowsIsolationReceiptPayloadV1,
    WindowsIsolationReceiptPayloadV2,
    WindowsIsolationReceiptPayloadV3,
    WindowsIsolationReceiptPayloadV4,
    WindowsIsolationReceiptV1,
    WindowsIsolationReceiptV2,
    WindowsIsolationReceiptV3,
    WindowsIsolationReceiptV4,
    WindowsRuntimeAccessGrantPayloadV1,
    WindowsRuntimeAccessGrantPayloadV2,
    WindowsRuntimeAccessGrantV1,
    WindowsRuntimeAccessGrantV2,
    appcontainer_identity,
    windows_isolation_bootstrap_started_id,
    windows_sandbox_spec,
)

H = "1" * 64
ENVIRONMENT = "2" * 32
IMPLEMENTATION_COMMIT = "3" * 40
PACKAGE_SID = "S-1-15-2-1-2-3-4-5-6-7"


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
            verify_runtime_bundle=lambda _: H,
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
            verify_runtime_bundle=lambda _: H,
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


def runtime_access_grant(
    profile: WindowsIsolationProfileV1 | WindowsIsolationProfileV2,
    sid: str = PACKAGE_SID,
) -> WindowsRuntimeAccessGrantV1:
    return WindowsRuntimeAccessGrantV1.create(
        WindowsRuntimeAccessGrantPayloadV1(
            appcontainer_identity=profile.payload.appcontainer_identity,
            appcontainer_sid=sid,
            root=profile.payload.read_only_roots[0],
            native_bundle_id=profile.payload.native_bundle_id,
            launcher_executable_sha256=profile.payload.launcher_executable_sha256,
            verified_entry_count=3,
            acl_inventory_sha256="7" * 64,
        )
    )


def runtime_access_grant_v2(
    profile: WindowsIsolationProfileV1 | WindowsIsolationProfileV2,
    sid: str = PACKAGE_SID,
    *,
    repaired: bool = False,
) -> WindowsRuntimeAccessGrantV2:
    return WindowsRuntimeAccessGrantV2.create(
        WindowsRuntimeAccessGrantPayloadV2(
            appcontainer_identity=profile.payload.appcontainer_identity,
            appcontainer_sid=sid,
            root=profile.payload.read_only_roots[0],
            native_bundle_id=profile.payload.native_bundle_id,
            launcher_executable_sha256=profile.payload.launcher_executable_sha256,
            verified_entry_count=3,
            pre_create_acl_inventory_sha256="7" * 64,
            post_create_acl_inventory_sha256="7" * 64,
            post_create_repaired=repaired,
        )
    )


def runtime_acl_ownership(
    profile: WindowsIsolationProfileV1 | WindowsIsolationProfileV2,
    sid: str = PACKAGE_SID,
) -> isolation._WindowsRuntimeAclOwnership:
    root = profile.payload.read_only_roots[0]
    return isolation._WindowsRuntimeAclOwnership(
        root=root,
        sid=sid,
        entries=(
            isolation._WindowsRuntimeAclOwnedEntry(
                identity=root,
                relative_path=".",
                kind="directory",
                inheritance_flags=WINDOWS_RUNTIME_ACCESS_INHERITANCE,
            ),
        ),
    )


def receipt_payload_v3(profile: WindowsIsolationProfileV2) -> dict[str, object]:
    payload = receipt_payload_v2(profile)
    payload["schema_version"] = 3
    payload["runtime_access_grant"] = runtime_access_grant(profile)
    return payload


def receipt_payload_v4(profile: WindowsIsolationProfileV2) -> dict[str, object]:
    payload = receipt_payload_v2(profile)
    payload["schema_version"] = 4
    payload["runtime_access_grant"] = runtime_access_grant_v2(profile)
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
def test_runtime_access_grant_is_exact_strict_and_bound_to_v3_evidence() -> None:
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    grant = runtime_access_grant(profile)
    assert grant.payload.access_mask == 0x001200A9 == WINDOWS_RUNTIME_ACCESS_MASK
    assert grant.payload.inheritance_flags == 0x3 == WINDOWS_RUNTIME_ACCESS_INHERITANCE
    assert grant.payload.access_mode == "grant_access"
    assert grant.payload.root == profile.payload.read_only_roots[0]
    assert grant.payload.native_bundle_id == profile.payload.native_bundle_id
    assert grant.payload.verified_entry_count == 3
    assert grant.payload.acl_inventory_sha256 == "7" * 64

    changed = grant.payload.model_dump(mode="json")
    changed["access_mask"] |= 0x2 | 0x10000 | 0x40000 | 0x80000
    with pytest.raises(ValidationError):
        WindowsRuntimeAccessGrantPayloadV1.model_validate(changed)

    receipt = WindowsIsolationReceiptV3.create(
        WindowsIsolationReceiptPayloadV3.model_validate(receipt_payload_v3(profile))
    )
    wrong_root = runtime_access_grant(
        WindowsIsolationProfileV2.create(
            profile_payload_v2().model_copy(update={"read_only_roots": (path("other-bundle", 9),)})
        )
    )
    changed_receipt = WindowsIsolationReceiptV3.create(
        receipt.payload.model_copy(update={"runtime_access_grant": wrong_root})
    )
    with pytest.raises(ValidationError, match="does not bind"):
        WindowsIsolationEvidenceV3.create(profile, windows_sandbox_spec(profile), changed_receipt)

    legacy_receipt = WindowsIsolationReceiptV2.create(
        WindowsIsolationReceiptPayloadV2.model_validate(receipt_payload_v2(profile))
    )
    assert (
        WindowsIsolationReceiptV2.model_validate_json(
            canonical(legacy_receipt.model_dump(mode="json"))
        )
        == legacy_receipt
    )
    incompatible = receipt_payload_v2(profile)
    incompatible["runtime_access_grant"] = grant
    with pytest.raises(ValidationError):
        WindowsIsolationReceiptPayloadV2.model_validate(incompatible)


@pytest.mark.windows_smoke
def test_v4_evidence_binds_pre_and_post_create_acl_inventories() -> None:
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    receipt = WindowsIsolationReceiptV4.create(
        WindowsIsolationReceiptPayloadV4.model_validate(receipt_payload_v4(profile))
    )
    evidence = WindowsIsolationEvidenceV4.create(profile, windows_sandbox_spec(profile), receipt)
    retained = WindowsIsolationEvidenceV4.model_validate_json(
        canonical(evidence.model_dump(mode="json"))
    )
    grant = retained.receipt.payload.runtime_access_grant.payload
    assert grant.pre_create_acl_inventory_sha256 == "7" * 64
    assert grant.post_create_acl_inventory_sha256 == "7" * 64
    assert grant.post_create_repaired is False

    forged = evidence.model_dump(mode="json")
    forged["receipt"]["payload"]["runtime_access_grant"]["payload"][
        "post_create_acl_inventory_sha256"
    ] = "8" * 64
    with pytest.raises(ValidationError, match="inventory differs"):
        WindowsIsolationEvidenceV4.model_validate(forged)


@pytest.mark.parametrize("initial_state", ["exact", "missing"])
def test_post_create_acl_gate_rechecks_bundle_and_repairs_only_missing_exact_sid_entry(
    initial_state: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    root = NativePathIdentityV1(locator=str(bundle), volume_serial_number=11, file_index="1" * 16)
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (root,),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    entry = isolation._WindowsRuntimeAclOwnedEntry(
        identity=root,
        relative_path=".",
        kind="directory",
        inheritance_flags=WINDOWS_RUNTIME_ACCESS_INHERITANCE,
    )
    ownership = isolation._WindowsRuntimeAclOwnership(root, PACKAGE_SID, (entry,))
    expected = isolation._expected_runtime_acl(entry, PACKAGE_SID)
    active = {"value": initial_state == "exact"}
    writes: list[tuple[int, int, int]] = []
    verifies: list[Path] = []

    monkeypatch.setattr(isolation, "windows_path_identity", lambda *_args, **_kwargs: root)
    monkeypatch.setattr(
        isolation,
        "_windows_acl_snapshot",
        lambda *_: isolation._WindowsAclSnapshot(False, (expected,) if active["value"] else ()),
    )
    active["value"] = True
    _, pre_inventory_sha256 = isolation._verify_owned_runtime_acl(ownership)
    active["value"] = initial_state == "exact"

    def write(_path: Path, _sid: str, mask: int, inheritance: int, *, access_mode: int = 1):
        writes.append((mask, inheritance, access_mode))
        active["value"] = access_mode == 1

    monkeypatch.setattr(isolation, "_set_windows_sid_acl_entry", write)
    pre = WindowsRuntimeAccessGrantV1.create(
        WindowsRuntimeAccessGrantPayloadV1(
            appcontainer_identity=profile.payload.appcontainer_identity,
            appcontainer_sid=PACKAGE_SID,
            root=root,
            native_bundle_id=profile.payload.native_bundle_id,
            launcher_executable_sha256=profile.payload.launcher_executable_sha256,
            verified_entry_count=1,
            acl_inventory_sha256=pre_inventory_sha256,
        )
    )
    grant = isolation._post_create_appcontainer_runtime_access(
        profile,
        isolation.OwnedAppContainerProfile(
            profile.payload.appcontainer_identity, PACKAGE_SID, tmp_path / "local"
        ),
        ownership,
        executable,
        lambda observed: verifies.append(observed) or profile.payload.native_bundle_id,
        pre,
    )
    assert verifies == [bundle, bundle]
    assert grant.payload.pre_create_acl_inventory_sha256 == pre_inventory_sha256
    assert grant.payload.post_create_repaired is (initial_state == "missing")
    assert grant.payload.verified_entry_count == 1
    assert writes == (
        [] if initial_state == "exact" else [(0, 0, 4), (WINDOWS_RUNTIME_ACCESS_MASK, 3, 1)]
    )


def test_post_create_acl_gate_rejects_wider_entry_with_self_hashed_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    root = NativePathIdentityV1(locator=str(bundle), volume_serial_number=11, file_index="1" * 16)
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (root,),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    entry = isolation._WindowsRuntimeAclOwnedEntry(
        identity=root,
        relative_path=".",
        kind="directory",
        inheritance_flags=WINDOWS_RUNTIME_ACCESS_INHERITANCE,
    )
    ownership = isolation._WindowsRuntimeAclOwnership(root, PACKAGE_SID, (entry,))
    widened = isolation._WindowsAclEntry(
        PACKAGE_SID,
        WINDOWS_RUNTIME_ACCESS_MASK | 0x2,
        1,
        WINDOWS_RUNTIME_ACCESS_INHERITANCE,
    )
    monkeypatch.setattr(isolation, "windows_path_identity", lambda *_args, **_kwargs: root)
    monkeypatch.setattr(
        isolation,
        "_windows_acl_snapshot",
        lambda *_: isolation._WindowsAclSnapshot(False, (widened,)),
    )
    monkeypatch.setattr(
        isolation,
        "_set_windows_sid_acl_entry",
        lambda *_args, **_kwargs: pytest.fail("wider ACL must not be repaired"),
    )
    pre = WindowsRuntimeAccessGrantV1.create(
        WindowsRuntimeAccessGrantPayloadV1(
            appcontainer_identity=profile.payload.appcontainer_identity,
            appcontainer_sid=PACKAGE_SID,
            root=root,
            native_bundle_id=profile.payload.native_bundle_id,
            launcher_executable_sha256=profile.payload.launcher_executable_sha256,
            verified_entry_count=1,
            acl_inventory_sha256="7" * 64,
        )
    )
    with pytest.raises(isolation.WindowsPostCreateAclGateError) as failure:
        isolation._post_create_appcontainer_runtime_access(
            profile,
            isolation.OwnedAppContainerProfile(
                profile.payload.appcontainer_identity, PACKAGE_SID, tmp_path / "local"
            ),
            ownership,
            executable,
            lambda _: profile.payload.native_bundle_id,
            pre,
        )
    diagnostic = failure.value.diagnostic
    assert diagnostic.payload.phase == "post_create_verify"
    assert diagnostic.payload.success_evidence_published is False
    assert (
        isolation.WindowsPostCreateAclFailureV1.model_validate_json(
            canonical(diagnostic.model_dump(mode="json"))
        )
        == diagnostic
    )


@pytest.mark.parametrize(
    "invalid_sid",
    [
        "S-1-15-2-1",
        "S-1-15-2-2",
        "S-1-15-2-1-2-3-4-5-6",
        "S-1-15-2-1-2-3-4-5-6-7-8",
        "S-1-15-2-01-2-3-4-5-6-7",
        "S-1-15-2-4294967296-2-3-4-5-6-7",
        "S-1-15-3-1-2-3-4-5-6-7",
    ],
)
def test_runtime_access_grant_and_v3_evidence_reject_non_package_sid(
    invalid_sid: str,
) -> None:
    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    grant = runtime_access_grant(profile).model_dump(mode="json")
    grant_payload = grant["payload"]
    assert isinstance(grant_payload, dict)
    grant_payload["appcontainer_sid"] = invalid_sid
    grant["runtime_access_grant_id"] = digest(canonical(grant_payload))
    with pytest.raises(ValidationError, match="exact derived package SID|subauthority"):
        WindowsRuntimeAccessGrantV1.model_validate(grant)

    receipt = receipt_payload_v3(profile)
    receipt["runtime_access_grant"] = grant
    with pytest.raises(ValidationError, match="exact derived package SID|subauthority"):
        WindowsIsolationReceiptPayloadV3.model_validate(receipt)


@pytest.mark.parametrize(
    "invalid_sid",
    ["S-1-15-2-1", "S-1-15-2-2", "S-1-15-2-1-2-3-4-5-6"],
)
def test_runtime_acl_rejects_invalid_native_sid_before_any_filesystem_observation(
    invalid_sid: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (
                    NativePathIdentityV1(
                        locator=str(bundle), volume_serial_number=7, file_index="1" * 16
                    ),
                ),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    monkeypatch.setattr(
        isolation,
        "windows_path_identity",
        lambda *_args, **_kwargs: pytest.fail("path identity observed before SID validation"),
    )
    monkeypatch.setattr(
        isolation,
        "_windows_acl_snapshot",
        lambda *_: pytest.fail("DACL observed before SID validation"),
    )
    monkeypatch.setattr(
        isolation,
        "_set_windows_sid_acl_entry",
        lambda *_args, **_kwargs: pytest.fail("DACL changed before SID validation"),
    )
    owned = isolation.OwnedAppContainerProfile(
        profile.payload.appcontainer_identity, invalid_sid, tmp_path / "local"
    )
    with pytest.raises(ValueError, match="exact derived package SID"):
        isolation._install_appcontainer_runtime_access(profile, owned, executable)


def test_runtime_access_grant_applies_and_rechecks_every_entry_and_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    library = bundle / "DLLs" / "_ctypes.pyd"
    library.parent.mkdir()
    library.write_bytes(b"extension")
    root_identity = NativePathIdentityV1(
        locator=str(bundle), volume_serial_number=7, file_index="1" * 16
    )
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (root_identity,),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    identities = {
        bundle: root_identity,
        library.parent: NativePathIdentityV1(
            locator=str(library.parent), volume_serial_number=7, file_index="2" * 16
        ),
        library: NativePathIdentityV1(
            locator=str(library), volume_serial_number=7, file_index="3" * 16
        ),
        executable: NativePathIdentityV1(
            locator=str(executable), volume_serial_number=7, file_index="4" * 16
        ),
    }
    granted: set[Path] = set()
    calls: list[tuple[Path, str, int, int]] = []

    def snapshot(observed: Path) -> isolation._WindowsAclSnapshot:
        if observed not in granted:
            return isolation._WindowsAclSnapshot(False, ())
        flags = WINDOWS_RUNTIME_ACCESS_INHERITANCE if observed.is_dir() else 0
        return isolation._WindowsAclSnapshot(
            False,
            (isolation._WindowsAclEntry(PACKAGE_SID, WINDOWS_RUNTIME_ACCESS_MASK, 1, flags),),
        )

    def apply(root: Path, sid: str, mask: int, inheritance: int) -> None:
        calls.append((root, sid, mask, inheritance))
        granted.add(root)

    monkeypatch.setattr(isolation, "windows_path_identity", lambda path, **_: identities[path])
    monkeypatch.setattr(isolation, "_windows_acl_snapshot", snapshot)
    monkeypatch.setattr(isolation, "_set_windows_sid_acl_entry", apply)
    owned = isolation.OwnedAppContainerProfile(
        profile.payload.appcontainer_identity,
        PACKAGE_SID,
        tmp_path / "local",
    )
    ownership = isolation._install_appcontainer_runtime_access(
        profile,
        owned,
        executable,
    )
    grant = isolation._verified_appcontainer_runtime_access(
        profile,
        owned,
        ownership,
        executable,
        lambda root: profile.payload.native_bundle_id,
    )
    assert calls == [
        (
            bundle,
            PACKAGE_SID,
            WINDOWS_RUNTIME_ACCESS_MASK,
            WINDOWS_RUNTIME_ACCESS_INHERITANCE,
        ),
        (
            bundle / "DLLs",
            PACKAGE_SID,
            WINDOWS_RUNTIME_ACCESS_MASK,
            WINDOWS_RUNTIME_ACCESS_INHERITANCE,
        ),
        (
            library,
            PACKAGE_SID,
            WINDOWS_RUNTIME_ACCESS_MASK,
            0,
        ),
        (
            executable,
            PACKAGE_SID,
            WINDOWS_RUNTIME_ACCESS_MASK,
            0,
        ),
    ]
    assert grant.payload.root == root_identity
    assert grant.payload.appcontainer_sid == PACKAGE_SID
    assert grant.payload.verified_entry_count == 4
    assert grant.payload.post_grant_bundle_verified is True


@pytest.mark.parametrize("failure", ["set", "verify", "broad", "protected", "bundle"])
def test_runtime_access_grant_fails_closed_for_partial_or_unsafe_acl(
    failure: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    root_identity = NativePathIdentityV1(
        locator=str(bundle), volume_serial_number=7, file_index="1" * 16
    )
    executable_identity = NativePathIdentityV1(
        locator=str(executable), volume_serial_number=7, file_index="2" * 16
    )
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (root_identity,),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    granted: set[Path] = set()

    def identity(path: Path, **_: object) -> NativePathIdentityV1:
        return root_identity if path == bundle else executable_identity

    def snapshot(path: Path) -> isolation._WindowsAclSnapshot:
        if failure == "broad":
            return isolation._WindowsAclSnapshot(
                False,
                (isolation._WindowsAclEntry("S-1-15-2-1", 1, 1, 3),),
            )
        if path in granted:
            mask = (
                WINDOWS_RUNTIME_ACCESS_MASK | 0x2
                if failure == "verify"
                else WINDOWS_RUNTIME_ACCESS_MASK
            )
            return isolation._WindowsAclSnapshot(
                failure == "protected" and path == executable,
                (isolation._WindowsAclEntry(PACKAGE_SID, mask, 1, 3 if path.is_dir() else 0),),
            )
        return isolation._WindowsAclSnapshot(False, ())

    def apply(path: Path, *_: object, access_mode: int = 1, **__: object) -> None:
        if access_mode == 4:
            granted.discard(path)
        elif failure == "set":
            raise isolation.WindowsIsolationLaunchError(
                "appcontainer_runtime_acl", 5, "injected partial ACL failure"
            )
        else:
            granted.add(path)

    monkeypatch.setattr(isolation, "windows_path_identity", identity)
    monkeypatch.setattr(isolation, "_windows_acl_snapshot", snapshot)
    monkeypatch.setattr(isolation, "_set_windows_sid_acl_entry", apply)
    with pytest.raises(
        (
            ValueError,
            isolation.WindowsIsolationLaunchError,
            isolation.WindowsRuntimeAclRollbackError,
        )
    ):
        owned = isolation.OwnedAppContainerProfile(
            profile.payload.appcontainer_identity,
            PACKAGE_SID,
            tmp_path / "local",
        )
        ownership = isolation._install_appcontainer_runtime_access(
            profile,
            owned,
            executable,
        )
        isolation._verified_appcontainer_runtime_access(
            profile,
            owned,
            ownership,
            executable,
            lambda _: "0" * 64 if failure == "bundle" else profile.payload.native_bundle_id,
        )


@pytest.mark.parametrize("failure", ["root", "owned", "broad", "protected"])
def test_runtime_acl_preflight_failure_performs_no_acl_mutation(
    failure: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    child = bundle / "DLLs"
    child.mkdir()
    root_identity = NativePathIdentityV1(
        locator=str(bundle), volume_serial_number=7, file_index="1" * 16
    )
    child_identity = NativePathIdentityV1(
        locator=str(child), volume_serial_number=7, file_index="2" * 16
    )
    changed_root = root_identity.model_copy(update={"file_index": "3" * 16})
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (root_identity,),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    writes: list[Path] = []
    revocations: list[isolation._WindowsRuntimeAclOwnership] = []

    def identity(path: Path, **_: object) -> NativePathIdentityV1:
        if path == bundle:
            return changed_root if failure == "root" else root_identity
        return child_identity

    def snapshot(path: Path) -> isolation._WindowsAclSnapshot:
        if failure == "owned" and path == bundle:
            return isolation._WindowsAclSnapshot(
                False,
                (isolation._WindowsAclEntry(PACKAGE_SID, WINDOWS_RUNTIME_ACCESS_MASK, 1, 3),),
            )
        if failure == "broad" and path == bundle:
            return isolation._WindowsAclSnapshot(
                False, (isolation._WindowsAclEntry("S-1-15-2-1", 1, 1, 3),)
            )
        return isolation._WindowsAclSnapshot(failure == "protected" and path == child, ())

    monkeypatch.setattr(isolation, "windows_path_identity", identity)
    monkeypatch.setattr(isolation, "_windows_acl_snapshot", snapshot)
    monkeypatch.setattr(
        isolation,
        "_set_windows_sid_acl_entry",
        lambda path, *_args, **_kwargs: writes.append(path),
    )
    monkeypatch.setattr(
        isolation,
        "_revoke_appcontainer_runtime_access",
        lambda ownership: revocations.append(ownership),
    )
    owned = isolation.OwnedAppContainerProfile(
        profile.payload.appcontainer_identity, PACKAGE_SID, tmp_path / "local"
    )
    with pytest.raises((ValueError, isolation.WindowsIsolationLaunchError)):
        isolation._install_appcontainer_runtime_access(profile, owned, executable)
    assert writes == []
    assert revocations == []


def test_runtime_acl_partial_install_rolls_back_only_written_identity_bound_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    library = bundle / "library.dll"
    library.write_bytes(b"library")
    root_identity = NativePathIdentityV1(
        locator=str(bundle), volume_serial_number=7, file_index="1" * 16
    )
    executable_identity = NativePathIdentityV1(
        locator=str(executable), volume_serial_number=7, file_index="2" * 16
    )
    library_identity = NativePathIdentityV1(
        locator=str(library), volume_serial_number=7, file_index="3" * 16
    )
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (root_identity,),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    planned = (
        isolation._WindowsRuntimeAclOwnedEntry(
            root_identity, ".", "directory", WINDOWS_RUNTIME_ACCESS_INHERITANCE
        ),
        isolation._WindowsRuntimeAclOwnedEntry(executable_identity, "python.exe", "file", 0),
        isolation._WindowsRuntimeAclOwnedEntry(library_identity, "library.dll", "file", 0),
    )
    identities = {
        bundle: root_identity,
        executable: executable_identity,
        library: library_identity,
    }
    active: set[Path] = set()
    operations: list[tuple[str, Path]] = []

    def snapshot(path: Path) -> isolation._WindowsAclSnapshot:
        if path not in active:
            return isolation._WindowsAclSnapshot(False, ())
        entry = next(value for value in planned if Path(value.identity.locator) == path)
        return isolation._WindowsAclSnapshot(
            False, (isolation._expected_runtime_acl(entry, PACKAGE_SID),)
        )

    def apply(
        path: Path,
        _sid: str,
        _mask: int,
        _inheritance: int,
        *,
        access_mode: int = 1,
    ) -> None:
        if access_mode == 4:
            operations.append(("revoke", path))
            active.discard(path)
            return
        operations.append(("grant", path))
        if path == executable:
            raise isolation.WindowsIsolationLaunchError(
                "appcontainer_runtime_acl", 5, "injected second-entry write failure"
            )
        active.add(path)

    monkeypatch.setattr(isolation, "windows_path_identity", lambda path, **_: identities[path])
    monkeypatch.setattr(isolation, "_planned_runtime_acl_entries", lambda *_: planned)
    monkeypatch.setattr(isolation, "_windows_acl_snapshot", snapshot)
    monkeypatch.setattr(isolation, "_set_windows_sid_acl_entry", apply)
    owned = isolation.OwnedAppContainerProfile(
        profile.payload.appcontainer_identity, PACKAGE_SID, tmp_path / "local"
    )
    with pytest.raises(isolation.WindowsIsolationLaunchError, match="second-entry"):
        isolation._install_appcontainer_runtime_access(profile, owned, executable)
    assert operations == [
        ("grant", bundle),
        ("grant", executable),
        ("revoke", bundle),
    ]
    assert active == set()


def test_runtime_acl_partial_install_preserves_exact_token_when_rollback_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    root_identity = NativePathIdentityV1(
        locator=str(bundle), volume_serial_number=7, file_index="1" * 16
    )
    executable_identity = NativePathIdentityV1(
        locator=str(executable), volume_serial_number=7, file_index="2" * 16
    )
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "read_only_roots": (root_identity,),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    planned = (
        isolation._WindowsRuntimeAclOwnedEntry(
            root_identity, ".", "directory", WINDOWS_RUNTIME_ACCESS_INHERITANCE
        ),
        isolation._WindowsRuntimeAclOwnedEntry(executable_identity, "python.exe", "file", 0),
    )
    identities = {bundle: root_identity, executable: executable_identity}
    active = {bundle: False}

    def snapshot(path: Path) -> isolation._WindowsAclSnapshot:
        if not active.get(path, False):
            return isolation._WindowsAclSnapshot(False, ())
        entry = next(value for value in planned if Path(value.identity.locator) == path)
        return isolation._WindowsAclSnapshot(
            False, (isolation._expected_runtime_acl(entry, PACKAGE_SID),)
        )

    def apply(path: Path, *_args: object, **_kwargs: object) -> None:
        if path == executable:
            raise RuntimeError("install failed")
        active[path] = True

    captured: list[isolation._WindowsRuntimeAclOwnership] = []

    def failed_rollback(ownership: isolation._WindowsRuntimeAclOwnership) -> None:
        captured.append(ownership)
        raise RuntimeError("rollback failed")

    monkeypatch.setattr(isolation, "windows_path_identity", lambda path, **_: identities[path])
    monkeypatch.setattr(isolation, "_planned_runtime_acl_entries", lambda *_: planned)
    monkeypatch.setattr(isolation, "_windows_acl_snapshot", snapshot)
    monkeypatch.setattr(isolation, "_set_windows_sid_acl_entry", apply)
    monkeypatch.setattr(isolation, "_revoke_appcontainer_runtime_access", failed_rollback)
    owned = isolation.OwnedAppContainerProfile(
        profile.payload.appcontainer_identity, PACKAGE_SID, tmp_path / "local"
    )
    with pytest.raises(isolation.WindowsRuntimeAclRollbackError) as raised:
        isolation._install_appcontainer_runtime_access(profile, owned, executable)
    assert captured == [raised.value.ownership]
    assert raised.value.ownership.entries == (planned[0],)


def test_runtime_acl_revoke_validates_all_owned_identities_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    child = root / "python.exe"
    child.write_bytes(b"MZ")
    root_identity = NativePathIdentityV1(
        locator=str(root), volume_serial_number=7, file_index="1" * 16
    )
    child_identity = NativePathIdentityV1(
        locator=str(child), volume_serial_number=7, file_index="2" * 16
    )
    changed_child = child_identity.model_copy(update={"file_index": "3" * 16})
    entries = (
        isolation._WindowsRuntimeAclOwnedEntry(
            root_identity, ".", "directory", WINDOWS_RUNTIME_ACCESS_INHERITANCE
        ),
        isolation._WindowsRuntimeAclOwnedEntry(child_identity, "python.exe", "file", 0),
    )
    ownership = isolation._WindowsRuntimeAclOwnership(root_identity, PACKAGE_SID, entries)
    writes: list[Path] = []
    monkeypatch.setattr(
        isolation,
        "windows_path_identity",
        lambda path, **_: root_identity if path == root else changed_child,
    )
    monkeypatch.setattr(
        isolation,
        "_windows_acl_snapshot",
        lambda path: isolation._WindowsAclSnapshot(
            False,
            (
                isolation._expected_runtime_acl(
                    entries[0] if path == root else entries[1], ownership.sid
                ),
            ),
        ),
    )
    monkeypatch.setattr(
        isolation,
        "_set_windows_sid_acl_entry",
        lambda path, *_args, **_kwargs: writes.append(path),
    )
    with pytest.raises(ValueError, match="identity changed"):
        isolation._revoke_appcontainer_runtime_access(ownership)
    assert writes == []


def test_runtime_acl_revoke_is_retry_safe_for_already_absent_owned_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    child = root / "python.exe"
    child.write_bytes(b"MZ")
    root_identity = NativePathIdentityV1(
        locator=str(root), volume_serial_number=7, file_index="1" * 16
    )
    child_identity = NativePathIdentityV1(
        locator=str(child), volume_serial_number=7, file_index="2" * 16
    )
    entries = (
        isolation._WindowsRuntimeAclOwnedEntry(
            root_identity, ".", "directory", WINDOWS_RUNTIME_ACCESS_INHERITANCE
        ),
        isolation._WindowsRuntimeAclOwnedEntry(child_identity, "python.exe", "file", 0),
    )
    ownership = isolation._WindowsRuntimeAclOwnership(root_identity, PACKAGE_SID, entries)
    active = {root: False, child: True}
    writes: list[Path] = []

    def snapshot(path: Path) -> isolation._WindowsAclSnapshot:
        entry = entries[0] if path == root else entries[1]
        observed = (isolation._expected_runtime_acl(entry, ownership.sid),) if active[path] else ()
        return isolation._WindowsAclSnapshot(False, observed)

    def revoke(path: Path, *_args: object, **_kwargs: object) -> None:
        writes.append(path)
        active[path] = False

    monkeypatch.setattr(
        isolation,
        "windows_path_identity",
        lambda path, **_: root_identity if path == root else child_identity,
    )
    monkeypatch.setattr(isolation, "_windows_acl_snapshot", snapshot)
    monkeypatch.setattr(isolation, "_set_windows_sid_acl_entry", revoke)
    isolation._revoke_appcontainer_runtime_access(ownership)
    assert writes == [child]


@pytest.mark.windows_smoke
def test_native_runtime_acl_is_exact_recursive_revocable_and_source_unchanged(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("native Windows ACL regression")
    source = tmp_path / "source"
    source_dlls = source / "DLLs"
    source_dlls.mkdir(parents=True)
    (source / "python.exe").write_bytes(b"MZ-python")
    (source_dlls / "_ctypes.pyd").write_bytes(b"MZ-ctypes")
    (source / "libffi-8.dll").write_bytes(b"MZ-libffi")
    disposable = tmp_path / "disposable"
    shutil.copytree(source, disposable)
    source_bytes = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }
    source_acls = {
        path.relative_to(source).as_posix()
        if path != source
        else ".": isolation._windows_acl_snapshot(path)
        for path in isolation._runtime_acl_paths(source)
    }
    executable = disposable / "python.exe"
    environment = secrets.token_hex(16)
    profile = WindowsIsolationProfileV1.create(
        profile_payload().model_copy(
            update={
                "environment_instance_id": environment,
                "appcontainer_identity": appcontainer_identity(environment),
                "read_only_roots": (isolation.windows_path_identity(disposable),),
                "launcher_executable_sha256": digest(executable.read_bytes()),
            }
        )
    )
    userenv = isolation._windows_dll("userenv.dll")
    advapi = isolation._windows_dll("advapi32.dll")
    kernel = isolation._windows_dll("kernel32.dll")
    derive_sid = userenv.DeriveAppContainerSidFromAppContainerName
    derive_sid.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    derive_sid.restype = ctypes.c_long
    convert_sid = advapi.ConvertSidToStringSidW
    convert_sid.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    convert_sid.restype = ctypes.c_int
    free_sid = advapi.FreeSid
    free_sid.argtypes = [ctypes.c_void_p]
    free_sid.restype = ctypes.c_void_p
    local_free = kernel.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    sid_pointer = ctypes.c_void_p()
    sid_text_pointer = ctypes.c_void_p()
    result = (
        int(derive_sid(profile.payload.appcontainer_identity, ctypes.byref(sid_pointer)))
        & 0xFFFFFFFF
    )
    assert result == 0 and sid_pointer.value
    assert convert_sid(sid_pointer, ctypes.byref(sid_text_pointer)) and sid_text_pointer.value
    owned = isolation.OwnedAppContainerProfile(
        profile.payload.appcontainer_identity,
        ctypes.wstring_at(sid_text_pointer.value),
        tmp_path / "unused-profile-local",
    )
    ownership: isolation._WindowsRuntimeAclOwnership | None = None
    revoked = False
    try:
        ownership = isolation._install_appcontainer_runtime_access(profile, owned, executable)

        def verify_runtime(root: Path) -> str:
            assert {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            } == source_bytes
            return profile.payload.native_bundle_id

        grant = isolation._verified_appcontainer_runtime_access(
            profile, owned, ownership, executable, verify_runtime
        )
        assert grant.payload.verified_entry_count == len(isolation._runtime_acl_paths(disposable))
        for required in (
            disposable / "python.exe",
            disposable / "DLLs" / "_ctypes.pyd",
            disposable / "libffi-8.dll",
        ):
            snapshot = isolation._windows_acl_snapshot(required)
            owned_entries = tuple(entry for entry in snapshot.entries if entry.sid == owned.sid)
            assert owned_entries == (
                isolation._WindowsAclEntry(
                    owned.sid,
                    WINDOWS_RUNTIME_ACCESS_MASK,
                    1,
                    0,
                ),
            )
        isolation._revoke_appcontainer_runtime_access(ownership)
        revoked = True
        for path_value in isolation._runtime_acl_paths(disposable):
            assert all(
                entry.sid != owned.sid
                for entry in isolation._windows_acl_snapshot(path_value).entries
            )
        assert {
            path.relative_to(source).as_posix(): path.read_bytes()
            for path in source.rglob("*")
            if path.is_file()
        } == source_bytes
        assert {
            path.relative_to(source).as_posix()
            if path != source
            else ".": isolation._windows_acl_snapshot(path)
            for path in isolation._runtime_acl_paths(source)
        } == source_acls
    finally:
        cleanup_errors: list[BaseException] = []
        if not revoked and ownership is not None:
            try:
                isolation._revoke_appcontainer_runtime_access(ownership)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            shutil.rmtree(disposable)
        except BaseException as error:
            cleanup_errors.append(error)
        if sid_text_pointer.value:
            local_free(sid_text_pointer)
        if sid_pointer.value:
            free_sid(sid_pointer)
        if cleanup_errors:
            raise BaseExceptionGroup("native Windows ACL test cleanup failed", cleanup_errors)


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
        lambda identity: isolation.OwnedAppContainerProfile(identity, PACKAGE_SID, local_app_data),
    )
    monkeypatch.setattr(
        isolation,
        "_install_appcontainer_runtime_access",
        lambda *_: runtime_acl_ownership(profile),
    )
    monkeypatch.setattr(
        isolation,
        "_verified_appcontainer_runtime_access",
        lambda observed, _owned, _ownership, _executable, verifier: (
            calls.append("bundle_verified"),
            verifier(bundle),
            runtime_access_grant(observed),
        )[-1],
    )
    monkeypatch.setattr(
        isolation,
        "_post_create_appcontainer_runtime_access",
        lambda observed, *_: (
            calls.append("post_create_acl_verified"),
            runtime_access_grant_v2(observed),
        )[-1],
    )
    process = isolation.launch_windows_isolated(
        profile,
        executable,
        ("-c", "pass"),
        cwd=writable,
        environment=supplied_environment,
        verify_runtime_bundle=lambda _: profile.payload.native_bundle_id,
    )
    assert calls == [
        "job_created",
        "limits_set",
        "bundle_verified",
        "created_suspended",
        "post_create_acl_verified",
        "job_assigned",
        "thread_resumed",
    ]
    assert process.launch_order == (
        "created_suspended",
        "post_create_acl_verified",
        "job_assigned",
        "thread_resumed",
    )


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
            verify_runtime_bundle=lambda _: profile.payload.native_bundle_id,
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
    sid_text = ctypes.create_unicode_buffer(PACKAGE_SID)
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
        "devfabric_" + ENVIRONMENT, PACKAGE_SID, folder
    )
    assert frees == ["CoTaskMemFree", "LocalFree", "FreeSid"]


def test_owned_appcontainer_profile_rejects_broad_native_sid_and_deletes_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid_text = ctypes.create_unicode_buffer("S-1-15-2-1")
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
                pytest.fail("folder path queried before native SID validation")
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
    with pytest.raises(ValueError, match="exact derived package SID"):
        isolation._create_owned_appcontainer_profile(identity)
    assert calls == [f"delete:{identity}", "LocalFree", "FreeSid"]


def test_partial_profile_preparation_deletes_only_the_owned_profile(monkeypatch) -> None:
    sid_text = ctypes.create_unicode_buffer(PACKAGE_SID)
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


@pytest.mark.parametrize(
    ("failure", "message"),
    [("root", "root identity changed"), ("owned", "Unexpected owned runtime ACL")],
)
def test_runtime_acl_preflight_failure_only_deletes_newly_owned_profile(
    failure: str,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    executable = bundle / "python.exe"
    executable.write_bytes(b"MZ")
    writable = tmp_path / "workspace"
    writable.mkdir()
    local_app_data = tmp_path / "local"
    local_app_data.mkdir()
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
    root_identity = profile.payload.read_only_roots[0]
    executable_identity = NativePathIdentityV1(
        locator=str(executable), volume_serial_number=1, file_index="3" * 16
    )
    changed_root = root_identity.model_copy(update={"file_index": "4" * 16})
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

    monkeypatch.setattr(isolation, "observed_windows_platform", lambda: (26200, "x86_64"))
    monkeypatch.setattr(isolation, "_verify_profile_paths", lambda _: None)
    monkeypatch.setattr(
        isolation, "_reject_reparse_chain", lambda value, **_: Path(value).absolute()
    )
    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(
        isolation,
        "_create_owned_appcontainer_profile",
        lambda identity: isolation.OwnedAppContainerProfile(identity, PACKAGE_SID, local_app_data),
    )
    monkeypatch.setattr(
        isolation,
        "windows_path_identity",
        lambda path, **_: (
            changed_root
            if failure == "root" and path == bundle
            else root_identity
            if path == bundle
            else executable_identity
        ),
    )
    monkeypatch.setattr(
        isolation,
        "_windows_acl_snapshot",
        lambda path: isolation._WindowsAclSnapshot(
            False,
            (
                isolation._WindowsAclEntry(
                    PACKAGE_SID,
                    WINDOWS_RUNTIME_ACCESS_MASK,
                    1,
                    WINDOWS_RUNTIME_ACCESS_INHERITANCE,
                ),
            )
            if failure == "owned" and path == bundle
            else (),
        ),
    )
    monkeypatch.setattr(
        isolation,
        "_set_windows_sid_acl_entry",
        lambda *_args, **_kwargs: calls.append("write"),
    )
    monkeypatch.setattr(
        isolation,
        "_revoke_appcontainer_runtime_access",
        lambda *_: calls.append("revoke"),
    )
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda identity: calls.append(f"delete:{identity}") or True,
    )
    with pytest.raises((ValueError, isolation.WindowsIsolationLaunchError), match=message):
        isolation.launch_windows_isolated(
            profile,
            executable,
            ("-c", "pass"),
            cwd=writable,
            environment={"SYSTEMROOT": r"C:\Windows"},
            verify_runtime_bundle=lambda _: profile.payload.native_bundle_id,
        )
    assert calls == [f"delete:{profile.payload.appcontainer_identity}"]


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
        lambda identity: isolation.OwnedAppContainerProfile(identity, PACKAGE_SID, official),
    )
    monkeypatch.setattr(
        isolation,
        "_install_appcontainer_runtime_access",
        lambda *_: runtime_acl_ownership(profile),
    )
    monkeypatch.setattr(
        isolation,
        "_verified_appcontainer_runtime_access",
        lambda observed, *_: runtime_access_grant(observed),
    )
    monkeypatch.setattr(
        isolation,
        "_post_create_appcontainer_runtime_access",
        lambda observed, *_: runtime_access_grant_v2(observed),
    )
    monkeypatch.setattr(
        isolation,
        "_revoke_appcontainer_runtime_access",
        lambda *_: None,
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
            verify_runtime_bundle=lambda _: profile.payload.native_bundle_id,
        )
    assert calls[-1] == f"delete:{profile.payload.appcontainer_identity}"
    if failure_phase == "processmodel":
        assert calls == ["terminate-job", "close-job", calls[-1]]


@pytest.mark.parametrize(
    "failed_call", ["PostCreateAclGate", "AssignProcessToJobObject", "ResumeThread"]
)
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
    launch_calls: list[str] = []

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
                launch_calls.append(self.name)
                return 0 if failed_call == self.name else 1
            if self.name == "ResumeThread":
                launch_calls.append(self.name)
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
        lambda identity: isolation.OwnedAppContainerProfile(identity, PACKAGE_SID, local_app_data),
    )
    monkeypatch.setattr(
        isolation,
        "_install_appcontainer_runtime_access",
        lambda *_: runtime_acl_ownership(profile),
    )
    monkeypatch.setattr(
        isolation,
        "_verified_appcontainer_runtime_access",
        lambda observed, *_: runtime_access_grant(observed),
    )
    monkeypatch.setattr(
        isolation,
        "_post_create_appcontainer_runtime_access",
        lambda observed, *_: (
            (_ for _ in ()).throw(RuntimeError("injected post-create ACL gate failure"))
            if failed_call == "PostCreateAclGate"
            else runtime_access_grant_v2(observed)
        ),
    )
    monkeypatch.setattr(
        isolation,
        "_revoke_appcontainer_runtime_access",
        lambda *_: cleanup_order.append("revoke"),
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
            verify_runtime_bundle=lambda _: profile.payload.native_bundle_id,
        )
    assert cleanup_order == [
        "TerminateProcess",
        "TerminateJobObject",
        "close:102",
        "close:101",
        "close:100",
        "revoke",
        "delete",
    ]
    if failed_call == "PostCreateAclGate":
        assert launch_calls == []


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


def test_process_close_revokes_runtime_acl_before_profile_and_retries_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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

    revocations = iter((False, True))

    def revoke(_: isolation._WindowsRuntimeAclOwnership) -> None:
        calls.append("revoke")
        if not next(revocations):
            raise isolation.WindowsIsolationLaunchError(
                "appcontainer_runtime_acl_cleanup", 5, "injected revocation failure"
            )

    monkeypatch.setattr(isolation, "_windows_dll", lambda _: Dll())
    monkeypatch.setattr(isolation, "_revoke_appcontainer_runtime_access", revoke)
    monkeypatch.setattr(
        isolation,
        "_delete_appcontainer_profile",
        lambda _: calls.append("delete") or True,
    )
    process = isolation.WindowsSandboxProcess(
        101,
        102,
        100,
        333,
        "devfabric_" + ENVIRONMENT,
        (),
        appcontainer_sid=PACKAGE_SID,
        runtime_acl_ownership=runtime_acl_ownership(
            WindowsIsolationProfileV1.create(
                profile_payload().model_copy(
                    update={
                        "read_only_roots": (
                            NativePathIdentityV1(
                                locator=str(tmp_path),
                                volume_serial_number=1,
                                file_index="1" * 16,
                            ),
                        )
                    }
                )
            )
        ),
    )
    with pytest.raises(ExceptionGroup, match="cleanup failed"):
        process.close()
    assert "delete" not in calls
    assert process.close() is True
    assert calls[-2:] == ["revoke", "delete"]


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
    monkeypatch.setattr(isolation, "_revoke_appcontainer_runtime_access", lambda *_: None)
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
        runtime_acl_ownership=None,
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
    execution_bundle = tmp_path / "scratch.execution-bundle"
    execution_bundle.mkdir()

    def fail_handle(_: int) -> None:
        calls.append("event")
        raise OSError("event cleanup")

    def fail_registry(_: str) -> None:
        calls.append("registry")
        raise OSError("registry cleanup")

    def fail_remove(path: Path) -> None:
        calls.append("scratch" if path == scratch else "execution-bundle")
        raise OSError("directory cleanup")

    monkeypatch.setattr(probe, "_close_handle", fail_handle)
    monkeypatch.setattr(probe, "_registry_exists", lambda _: True)
    monkeypatch.setattr(probe, "_delete_registry", fail_registry)
    monkeypatch.setattr(probe.shutil, "rmtree", fail_remove)
    errors = probe._cleanup_probe_resources(
        FailedProcess(),
        44,
        FailedListener(),
        "Software\\probe",
        scratch,
        execution_bundle,
    )
    assert len(errors) == 6
    assert calls == [
        "process",
        "event",
        "listener",
        "registry",
        "scratch",
        "execution-bundle",
    ]

    profile = WindowsIsolationProfileV2.create(profile_payload_v2())
    diagnostic = probe.WindowsIsolationFailureDiagnosticV2.create(
        probe.WindowsIsolationFailureDiagnosticPayloadV2(
            environment_instance_id=ENVIRONMENT,
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            probe_sha256=profile.payload.probe_sha256,
            child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
            process_exit_code=203,
            bootstrap_started_status="absent",
            child_failure_status="absent",
        )
    )
    success_output = tmp_path / "evidence.json"
    failure_output = success_output.with_name(success_output.name + ".failure.json")
    with pytest.raises(BaseExceptionGroup, match="probe and cleanup failed"):
        probe._raise_after_cleanup(RuntimeError("primary"), errors, diagnostic, failure_output)
    assert not success_output.exists()
    assert not failure_output.exists()


def test_probe_paths_reject_source_overlap_before_copy(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows probe path boundary")
    probe = load_probe_module("windows_isolation_probe_overlap_test")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    canary = bundle / "canary.txt"
    canary.write_bytes(b"immutable")
    manifest = tmp_path / "native-bundle.json"
    manifest.write_bytes(b"{}")
    scratch = bundle / "scratch"
    execution_bundle = bundle / "scratch.execution-bundle"
    output = tmp_path / "evidence.json"
    failure = tmp_path / "evidence.json.failure.json"

    with pytest.raises(ValueError, match="cannot overlap bundle authority"):
        probe._validated_probe_paths(bundle, manifest, scratch, execution_bundle, output, failure)

    assert canary.read_bytes() == b"immutable"
    assert not scratch.exists()
    assert not execution_bundle.exists()
    assert not output.exists()
    assert not failure.exists()


def test_probe_paths_reject_junction_destination_parent(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows probe path boundary")
    probe = load_probe_module("windows_isolation_probe_junction_parent_test")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    manifest = tmp_path / "native-bundle.json"
    manifest.write_bytes(b"{}")
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    junction = tmp_path / "junction-parent"
    created = subprocess.run(
        [os.environ["COMSPEC"], "/d", "/c", "mklink", "/J", str(junction), str(real_parent)],
        capture_output=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("Junction creation is unavailable on this Windows runner")
    try:
        scratch = junction / "scratch"
        with pytest.raises(ValueError, match="reparse"):
            probe._validated_probe_paths(
                bundle,
                manifest,
                scratch,
                junction / "scratch.execution-bundle",
                tmp_path / "evidence.json",
                tmp_path / "evidence.json.failure.json",
            )
        assert not scratch.exists()
        assert not (junction / "scratch.execution-bundle").exists()
    finally:
        removed = subprocess.run(
            [os.environ["COMSPEC"], "/d", "/c", "rmdir", str(junction)],
            capture_output=True,
            check=False,
        )
        assert removed.returncode == 0


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
    assert import_failed.main() == import_failed.EXIT_IMPORT_UNKNOWN
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

    classifications = {
        "_ctypes": import_failed.EXIT_IMPORT_CTYPES,
        "_socket": import_failed.EXIT_IMPORT_SOCKET,
        "pydantic_core._pydantic_core": import_failed.EXIT_IMPORT_PYDANTIC_CORE,
        "devhub.models": import_failed.EXIT_IMPORT_DEVHUB,
        "unreviewed.module": import_failed.EXIT_IMPORT_UNKNOWN,
    }
    for name, expected in classifications.items():
        error = ImportError("sensitive import detail", name=name)
        assert import_failed._classified_import_exit(error) == expected
    assert import_failed._classified_import_exit(RuntimeError("not import")) == (
        import_failed.EXIT_IMPORT_FAILED
    )

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
        bootstrap.EXIT_IMPORT_CTYPES,
        bootstrap.EXIT_IMPORT_SOCKET,
        bootstrap.EXIT_IMPORT_PYDANTIC_CORE,
        bootstrap.EXIT_IMPORT_DEVHUB,
        bootstrap.EXIT_IMPORT_UNKNOWN,
    }
    assert len(exit_codes) == 15
    assert exit_codes == set(range(189, 204))


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

    acl_diagnostic = isolation.WindowsPostCreateAclFailureV1.create(
        isolation.WindowsPostCreateAclFailurePayloadV1(
            environment_instance_id=ENVIRONMENT,
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            appcontainer_identity=profile.payload.appcontainer_identity,
            appcontainer_sid=PACKAGE_SID,
            pre_create_acl_inventory_sha256="7" * 64,
            phase="post_create_repair",
        )
    )
    acl_output = tmp_path / "acl-diagnostic.json"
    acl_error = isolation.WindowsPostCreateAclGateError(acl_diagnostic)
    with pytest.raises(isolation.WindowsPostCreateAclGateError):
        probe._raise_after_cleanup(acl_error, [], acl_diagnostic, acl_output)
    assert (
        isolation.WindowsPostCreateAclFailureV1.model_validate_json(acl_output.read_bytes())
        == acl_diagnostic
    )


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
            "--expected-implementation-commit",
            IMPLEMENTATION_COMMIT,
        ],
    )

    probe.main()

    assert forwarded == {
        "bundle_root": bundle_root,
        "bundle_manifest": bundle_manifest,
        "scratch": scratch,
        "output": output,
        "environment_instance_id": ENVIRONMENT,
        "expected_implementation_commit": IMPLEMENTATION_COMMIT,
    }
    assert json.loads(capsys.readouterr().out) == {"status": "passed"}


def test_qualify_rejects_stale_bundle_before_platform_or_native_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "nt":
        pytest.skip("Windows host qualification path")
    probe = load_probe_module("windows_isolation_stale_bundle_test")
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    manifest = tmp_path / "bundle.json"
    manifest.write_bytes(b"{}")
    scratch = tmp_path / "scratch"
    output = tmp_path / "evidence.json"
    bundle = SimpleNamespace(
        payload=SimpleNamespace(implementation_commit="4" * 40),
    )

    class BundleParser:
        @classmethod
        def model_validate_json(cls, _: bytes) -> object:
            return bundle

    monkeypatch.setattr(probe, "NativeBundleV1", BundleParser)
    monkeypatch.setattr(probe, "verify_native_bundle", lambda *_, **__: None)
    monkeypatch.setattr(
        probe,
        "observed_windows_platform",
        lambda: pytest.fail("platform observation occurred for a stale bundle"),
    )
    monkeypatch.setattr(
        probe.socket,
        "socket",
        lambda *_: pytest.fail("native listener acquisition occurred for a stale bundle"),
    )

    with pytest.raises(ValueError, match="implementation commit differs"):
        probe.qualify(
            bundle_root,
            manifest,
            scratch,
            output,
            ENVIRONMENT,
            IMPLEMENTATION_COMMIT,
        )
    assert not scratch.exists()
    assert not output.exists()
    assert not output.with_name(output.name + ".failure.json").exists()


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
            implementation_commit=IMPLEMENTATION_COMMIT,
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
        runtime_access_grant: WindowsRuntimeAccessGrantV2 | None = None

        def poll_exit_code(self) -> None:
            return None

        def terminate_tree(self) -> None:
            pass

        def close(self) -> bool:
            return True

    marker_mode = {"value": "valid"}
    verified_roots: list[Path] = []
    security_hashes: list[str] = []

    def verify_bundle(_: object, root: Path, **__: object) -> None:
        verified_roots.append(root)

    def security_descriptor_inventory(_: Path) -> str:
        return security_hashes.pop(0) if security_hashes else "a" * 64

    def launch(*args: object, **kwargs: object) -> Process:
        profile = args[0]
        assert isinstance(profile, WindowsIsolationProfileV2)
        execution_bundle = Path(profile.payload.read_only_roots[0].locator)
        assert execution_bundle.name.endswith(".execution-bundle")
        assert Path(args[1]).is_relative_to(execution_bundle)
        assert not Path(args[1]).is_relative_to(bundle_root)
        assert Path(profile.payload.read_only_roots[0].locator) == execution_bundle.absolute()
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
        verifier = kwargs["verify_runtime_bundle"]
        assert callable(verifier)
        assert verifier(execution_bundle) == profile.payload.native_bundle_id
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
        process = Process()
        process.runtime_access_grant = runtime_access_grant_v2(profile)
        return process

    def identity(path_value: Path) -> NativePathIdentityV1:
        return NativePathIdentityV1(
            locator=str(path_value.absolute()),
            volume_serial_number=1,
            file_index=f"{abs(hash(str(path_value))) & 0xFFFFFFFFFFFFFFFF:016x}",
        )

    monkeypatch.setattr(probe, "NativeBundleV1", BundleParser)
    monkeypatch.setattr(probe, "verify_native_bundle", verify_bundle)
    monkeypatch.setattr(
        probe, "_security_descriptor_inventory_sha256", security_descriptor_inventory
    )
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

    evidence = probe.qualify(
        bundle_root, manifest, scratch, output, ENVIRONMENT, IMPLEMENTATION_COMMIT
    )
    retained = WindowsIsolationEvidenceV4.model_validate_json(output.read_bytes())
    assert retained == evidence
    assert retained.receipt.payload.no_direct_network_baseline_qualified is True
    assert retained.receipt.payload.native_executor_isolation_qualified is False
    assert retained.receipt.payload.package_readiness is False
    assert not scratch.exists()
    assert not scratch.with_name(scratch.name + ".execution-bundle").exists()
    assert python.read_bytes() == b"MZ-native-python"
    assert verified_roots[:4] == [
        bundle_root,
        scratch.with_name(scratch.name + ".execution-bundle"),
        scratch.with_name(scratch.name + ".execution-bundle"),
        bundle_root,
    ]
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
                IMPLEMENTATION_COMMIT,
            )
        assert not rejected_output.exists()
        assert not rejected_output.with_name(rejected_output.name + ".failure.json").exists()
        assert not rejected_scratch.exists()

    acl_output = tmp_path / "acl-mismatch-evidence.json"
    acl_scratch = tmp_path / "acl-mismatch-scratch"
    marker_mode["value"] = "valid"
    security_hashes.extend(["a" * 64, "b" * 64])
    with pytest.raises(ExceptionGroup, match="probe cleanup failed"):
        probe.qualify(
            bundle_root,
            manifest,
            acl_scratch,
            acl_output,
            ENVIRONMENT,
            IMPLEMENTATION_COMMIT,
        )
    assert not acl_output.exists()
    assert not acl_scratch.exists()
    assert not acl_scratch.with_name(acl_scratch.name + ".execution-bundle").exists()

    failed_output = tmp_path / "cleanup-failed-evidence.json"
    failed_scratch = tmp_path / "cleanup-failed-scratch"
    marker_mode["value"] = "valid"
    monkeypatch.setattr(
        probe,
        "_cleanup_probe_resources",
        lambda *_: [OSError("post-observation cleanup failed")],
    )
    with pytest.raises(ExceptionGroup, match="probe cleanup failed"):
        probe.qualify(
            bundle_root,
            manifest,
            failed_scratch,
            failed_output,
            ENVIRONMENT,
            IMPLEMENTATION_COMMIT,
        )
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
    bundle = SimpleNamespace(
        bundle_id=H, payload=SimpleNamespace(implementation_commit=IMPLEMENTATION_COMMIT)
    )

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
        probe.qualify(bundle_root, manifest, scratch, output, ENVIRONMENT, IMPLEMENTATION_COMMIT)
    assert not output.exists()
    assert not scratch.exists()
    assert "listener" in calls
    assert "scratch" in calls
    if failure_stage == "registry":
        assert "event" in calls
