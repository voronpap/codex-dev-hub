import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from devhub.stage3g_host import (
    DELEGATE_SCHEMA_SHA256,
    DELEGATE_TOOL,
    Stage3gHostManifestV2,
    read_stage3g_host_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/stage3g-host-manifest-v2.json"
SCHEMA = ROOT / "benchmarks/stage3g-host-manifest-v2.schema.json"
MANIFEST_SHA256 = "d31edc7cb0604ea7d2c526521adb1c59ae21a35a902a8c2a9a7c2807bc29957e"


def test_reviewed_host_manifest_has_exact_a_b_surfaces() -> None:
    manifest, raw = read_stage3g_host_manifest(MANIFEST)
    Draft202012Validator(json.loads(SCHEMA.read_bytes())).validate(json.loads(raw))
    assert manifest.expected_global_tool_mode == "CodeModeOnly"
    assert manifest.arms.arm_a.tool_ceiling == ()
    assert manifest.arms.arm_a.approved_delegate is None
    assert manifest.arms.arm_b.tool_ceiling == (DELEGATE_TOOL,)
    delegate = manifest.arms.arm_b.approved_delegate
    assert delegate is not None
    assert delegate.server_key == delegate.raw_tool == "devhub_delegate"
    assert delegate.canonical_namespace == "mcp__devhub_delegate"
    assert delegate.canonical_function == "devhub_delegate"
    assert delegate.expected_input_schema_sha256 == DELEGATE_SCHEMA_SHA256
    assert hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("arms", "arm_a", "tool_ceiling"), [DELEGATE_TOOL]),
        (("arms", "arm_a", "approved_delegate"), {}),
        (("arms", "arm_b", "tool_ceiling"), []),
        (("arms", "arm_b", "approved_delegate", "raw_tool"), "other"),
        (("expected_global_tool_mode",), "Direct"),
    ],
)
def test_host_manifest_rejects_widening_or_identity_drift(
    path: tuple[str, ...], value: object
) -> None:
    raw = json.loads(MANIFEST.read_bytes())
    target = raw
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        Stage3gHostManifestV2.model_validate(raw)


def test_host_manifest_rejects_unknown_fields() -> None:
    raw = json.loads(MANIFEST.read_bytes())
    raw["authority_from_task"] = True
    with pytest.raises(ValidationError):
        Stage3gHostManifestV2.model_validate(raw)


def test_shipping_patch_keeps_authority_out_of_client_payloads() -> None:
    patch = (ROOT / "patches/stage3g-approved-call/host-integration.patch").read_text()
    assert "devhub-stage3g-host-manifest" in patch
    assert "devhub-stage3g-arm" in patch
    assert "thread_extension_init: ExtensionDataInit" in patch
    assert "let host_thread_extension_init = self.thread_extension_init.clone();" in patch
    assert "host_thread_extension_init," in patch
    assert "mut thread_extension_init: ExtensionDataInit" in patch
    assert "let mut thread_extension_init = self.thread_extension_init.clone();" not in patch
    assert "ThreadStartParams" not in patch
    assert "Stage3gHostArm::A" in patch and "AllowedTools" in patch
    assert "Stage3gHostArm::B" in patch and "ApprovedDelegatePolicy::delegate" in patch
