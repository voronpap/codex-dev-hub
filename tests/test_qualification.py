import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.benchmark import canonical, digest
from devhub.ledger import LedgerIdentityCoreV1, ledger_identity_sha256
from devhub.qualification import (
    RECEIPT_KINDS,
    ArmExpectedV1,
    ArmsExpectedV1,
    ArtifactReferenceV1,
    BenchmarkExpectedV1,
    CodexExpectedV1,
    EvaluatorExpectedV1,
    HistoricalRuntimeBindingsV1,
    ImplementationExpectedV1,
    LedgerExpectedV1,
    ObservedArtifactHashesV2,
    OllamaExpectedV1,
    PythonRuntimeExpectedV1,
    QualificationContextPayloadV1,
    QualificationContextV1,
    QualificationGatesV2,
    QualificationManifestPayloadV2,
    QualificationManifestV2,
    QualificationReceiptSetV2,
    ReceiptReferenceV1,
    RuntimeBindings,
    RuntimeExpectedV1,
    canonical_context,
    canonical_manifest,
    verify_manifest_tree,
)

H = "a" * 64
ENVIRONMENT = "b" * 32


def context_payload() -> QualificationContextPayloadV1:
    ledger = LedgerIdentityCoreV1(
        instance_id="c" * 32,
        authority_scope_kind="qualification",
        authority_scope_id="stage3g-synthetic",
    )
    runtime = PythonRuntimeExpectedV1(
        source_commit="d" * 40,
        wheel_sha256="1" * 64,
        dependency_lock_sha256="2" * 64,
        python_version="3.12.11",
        python_executable_sha256="3" * 64,
        runtime_environment_id="4" * 64,
        distribution_version="0.1.0",
    )
    return QualificationContextPayloadV1(
        environment_instance_id=ENVIRONMENT,
        implementation=ImplementationExpectedV1(devhub_commit="d" * 40, python_runtime=runtime),
        codex=CodexExpectedV1(
            source_commit="e" * 40,
            source_archive_sha256="5" * 64,
            executable_version="codex-cli synthetic",
            executable_sha256="6" * 64,
            candidate_b_base_patch_sha256="7" * 64,
            host_integration_patch_sha256="8" * 64,
            combined_patchset_sha256="9" * 64,
        ),
        benchmark=BenchmarkExpectedV1(
            protocol_sha256="a" * 64,
            config_sha256="b" * 64,
            plan_sha256="c" * 64,
            session_bindings_sha256="d" * 64,
            fixture_oracle_manifest_sha256="e" * 64,
        ),
        runtime_expected=RuntimeExpectedV1(
            image_id="sha256:" + "f" * 64,
            image_metadata_sha256="0" * 64,
            bootstrap_sha256="1" * 64,
            approved_host_manifest_sha256="2" * 64,
        ),
        ledger_expected=LedgerExpectedV1(
            identity=ledger,
            identity_sha256=ledger_identity_sha256(ledger),
            domain_schema_version=6,
        ),
        evaluator_expected=EvaluatorExpectedV1(
            image_id="sha256:" + "3" * 64,
            artifact_sha256="4" * 64,
            runner_sha256="5" * 64,
        ),
        ollama_expected=OllamaExpectedV1(),
        arms_expected=ArmsExpectedV1(
            arm_a=ArmExpectedV1(arm="A", tool_ceiling=(), approved_delegate_policy_sha256=None),
            arm_b=ArmExpectedV1(
                arm="B",
                tool_ceiling=("mcp__devhub_delegate.devhub_delegate",),
                approved_delegate_policy_sha256="6" * 64,
            ),
        ),
    )


def materialize(root: Path) -> tuple[QualificationContextV1, QualificationManifestV2, Path]:
    context = QualificationContextV1.create(context_payload())
    expected = context.payload
    context_raw = canonical_context(context)
    (root / "context.json").write_bytes(context_raw)
    references = {}
    host_visibility_sha256 = None
    for index, kind in enumerate(RECEIPT_KINDS):
        observations = {
            "isolation": {
                "image_id": expected.runtime_expected.image_id,
                "bootstrap_sha256": expected.runtime_expected.bootstrap_sha256,
            },
            "effects_boundary": {
                "image_id": expected.runtime_expected.image_id,
                "bootstrap_sha256": expected.runtime_expected.bootstrap_sha256,
            },
            "auth_egress": {},
            "ollama_metadata": expected.ollama_expected.model_dump(
                mode="json", exclude={"schema_version"}
            ),
            "ledger_identity": {
                "ledger_identity_sha256": expected.ledger_expected.identity_sha256,
                "domain_schema_version": expected.ledger_expected.domain_schema_version,
            },
            "codex_executable": {
                "kind": "retained_build020_executable",
                "image_id": expected.runtime_expected.image_id,
                "source_commit": expected.codex.source_commit,
                "source_archive_sha256": expected.codex.source_archive_sha256,
                "executable_sha256": expected.codex.executable_sha256,
                "executable_version": expected.codex.executable_version,
                "candidate_b_base_patch_sha256": expected.codex.candidate_b_base_patch_sha256,
                "host_integration_patch_sha256": expected.codex.host_integration_patch_sha256,
                "combined_patchset_sha256": expected.codex.combined_patchset_sha256,
                "source_artifact": {
                    "schema_version": 1,
                    "workflow_run_id": 38024891950,
                    "artifact_id": 11659714382,
                    "artifact_name": "stage3g-build020-production-host-proof",
                    "artifact_zip_sha256": (
                        "c03fbe7596a95c2b667348db879c205c83d5cd74b3f9e1d2b4d2d5ab79546979"
                    ),
                    "build_evidence_sha256": (
                        "6f4fdb1aacdeef2e3446e7f2760d4f84e2832df833034befb4ce0a81997a32f0"
                    ),
                },
                "real_codex_task_executions": 0,
                "model_requests": 0,
                "provider_sends": 0,
            },
            "host_process_visibility": {
                "kind": "actual_codex_exec_pre_sampling_router_visibility",
                "image_id": expected.runtime_expected.image_id,
                "executable_sha256": expected.codex.executable_sha256,
                "executable_version": expected.codex.executable_version,
                "approved_host_manifest_sha256": (
                    expected.runtime_expected.approved_host_manifest_sha256
                ),
                "default_observation": {
                    "schema_version": 1,
                    "observer": "read_only_pre_sampling_router_v1",
                    "effective_tool_mode": "CodeModeOnly",
                    "allowed_tools_ceiling_present": False,
                    "allowed_tools": [],
                    "approved_delegate_policy_present": False,
                    "approved_identity": None,
                    "expected_schema_sha256": None,
                    "host_manifest_sha256": None,
                    "visible_model_tools": ["ordinary.tool"],
                    "nested_code_mode_map": ["ordinary=ordinary"],
                    "hosted_tools": [],
                    "dynamic_tool_count": 0,
                    "model_requests": 0,
                    "provider_sends": 0,
                    "real_codex_task_executions": 0,
                },
                "arm_a_observation": {
                    "schema_version": 1,
                    "observer": "read_only_pre_sampling_router_v1",
                    "effective_tool_mode": "CodeModeOnly",
                    "allowed_tools_ceiling_present": True,
                    "allowed_tools": [],
                    "approved_delegate_policy_present": False,
                    "approved_identity": None,
                    "expected_schema_sha256": None,
                    "host_manifest_sha256": expected.runtime_expected.approved_host_manifest_sha256,
                    "visible_model_tools": [],
                    "nested_code_mode_map": [],
                    "hosted_tools": [],
                    "dynamic_tool_count": 0,
                    "model_requests": 0,
                    "provider_sends": 0,
                    "real_codex_task_executions": 0,
                },
                "arm_b_observation": {
                    "schema_version": 1,
                    "observer": "read_only_pre_sampling_router_v1",
                    "effective_tool_mode": "CodeModeOnly",
                    "allowed_tools_ceiling_present": True,
                    "allowed_tools": ["mcp__devhub_delegate.devhub_delegate"],
                    "approved_delegate_policy_present": True,
                    "approved_identity": {
                        "schema_version": 1,
                        "server_key": "devhub_delegate",
                        "raw_tool": "devhub_delegate",
                        "canonical_namespace": "mcp__devhub_delegate",
                        "canonical_function": "devhub_delegate",
                        "schema_sha256": (
                            "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
                        ),
                        "generation_identity": "generation-0123456789abcdef",
                    },
                    "expected_schema_sha256": (
                        "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
                    ),
                    "host_manifest_sha256": expected.runtime_expected.approved_host_manifest_sha256,
                    "visible_model_tools": ["mcp__devhub_delegate.devhub_delegate"],
                    "nested_code_mode_map": [],
                    "hosted_tools": [],
                    "dynamic_tool_count": 0,
                    "model_requests": 0,
                    "provider_sends": 0,
                    "real_codex_task_executions": 0,
                },
                "b_minus_a": ["mcp__devhub_delegate.devhub_delegate"],
                "a_minus_b": [],
                "catalog_records": [
                    {
                        "schema_version": 1,
                        "event": "tools_list",
                        "schema_sha256": (
                            "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
                        ),
                        "provider_send": False,
                    }
                ],
                "catalog_tools_list_count": 1,
                "mcp_tool_call_count": 0,
                "stopped_before_sampling": True,
                "model_requests": 0,
                "provider_sends": 0,
                "real_codex_task_executions": 0,
            },
            "evaluator": {
                "artifact_sha256": expected.evaluator_expected.artifact_sha256,
                "runner_sha256": expected.evaluator_expected.runner_sha256,
            },
            "python_runtime": {
                "interpreter_sha256": (
                    expected.implementation.python_runtime.python_executable_sha256
                ),
                "wheel_sha256": expected.implementation.python_runtime.wheel_sha256,
                "dependency_lock_sha256": (
                    expected.implementation.python_runtime.dependency_lock_sha256
                ),
                "runtime_environment_id": (
                    expected.implementation.python_runtime.runtime_environment_id
                ),
            },
            "runtime_config_probe": {
                "image_id": expected.runtime_expected.image_id,
                "protocol_sha256": expected.benchmark.protocol_sha256,
                "host_process_visibility_sha256": host_visibility_sha256,
                "checks": {
                    "schema_version": 1,
                    "auth_tmpfs": True,
                    "cli_config": True,
                    "egress_runtime": True,
                },
                "arms": [
                    {
                        "schema_version": 1,
                        "arm": arm,
                        "features_exit_code": 0,
                        "mcp_list_exit_code": 0,
                        "mcp_scope_matches": True,
                        "required_feature_states": {
                            "schema_version": 1,
                            "shell_tool": "false",
                            "apps": "false",
                            "multi_agent": "false",
                            "goals": "false",
                            "hooks": "false",
                            "memories": "false",
                            "remote_plugin": "false",
                            "shell_snapshot": "false",
                        },
                        "config_error": None,
                    }
                    for arm in ("A", "B")
                ],
                "auth_material": "synthetic only; real auth presence is a separate preflight gate",
                "real_codex_executions": 0,
                "model_requests": 0,
                "provider_sends": 0,
            },
        }
        receipt_value = {
            "schema_version": 1,
            "receipt_kind": kind,
            "qualification_context_id": context.qualification_context_id,
            "environment_instance_id": ENVIRONMENT,
            "qualification_passed": True,
            **observations[kind],
        }
        if kind not in {"codex_executable", "host_process_visibility", "runtime_config_probe"}:
            receipt_value["synthetic_observation"] = index
        raw = canonical(receipt_value)
        name = f"{kind}.json"
        (root / name).write_bytes(raw)
        if kind == "host_process_visibility":
            host_visibility_sha256 = digest(raw)
        references[kind] = ReceiptReferenceV1(
            receipt_kind=kind, relative_path=name, sha256=digest(raw)
        )
    receipts = QualificationReceiptSetV2.model_validate(references)
    observed = ObservedArtifactHashesV2(
        qualification_context_sha256=digest(context_raw),
        devhub_wheel_sha256=expected.implementation.python_runtime.wheel_sha256,
        dependency_lock_sha256=expected.implementation.python_runtime.dependency_lock_sha256,
        python_executable_sha256=(expected.implementation.python_runtime.python_executable_sha256),
        python_runtime_environment_id=(
            expected.implementation.python_runtime.runtime_environment_id
        ),
        codex_executable_sha256=expected.codex.executable_sha256,
        runtime_image_metadata_sha256=expected.runtime_expected.image_metadata_sha256,
        evaluator_artifact_sha256=expected.evaluator_expected.artifact_sha256,
        ledger_identity_sha256=expected.ledger_expected.identity_sha256,
        ollama_model_digest=expected.ollama_expected.digest,
    )
    gates = QualificationGatesV2(
        **{name: True for name in QualificationGatesV2.model_fields if name != "schema_version"}
    )
    payload = QualificationManifestPayloadV2.create(
        qualification_context_id=context.qualification_context_id,
        environment_instance_id=ENVIRONMENT,
        context=ArtifactReferenceV1(relative_path="context.json", sha256=digest(context_raw)),
        receipts=receipts,
        observed_artifacts=observed,
        gates=gates,
    )
    manifest = QualificationManifestV2.create(payload)
    path = root / "manifest.json"
    path.write_bytes(canonical_manifest(manifest))
    return context, manifest, path


def rewrite_manifest(path: Path, manifest: QualificationManifestV2, **changes: object) -> str:
    raw = manifest.payload.model_dump(mode="json")
    raw.update(
        {
            key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
            for key, value in changes.items()
        }
    )
    payload = QualificationManifestPayloadV2.model_validate(raw)
    changed = QualificationManifestV2.create(payload)
    path.write_bytes(canonical_manifest(changed))
    return changed.qualification_manifest_id


def rewrite_receipt(
    root: Path,
    manifest: QualificationManifestV2,
    kind: str,
    mutate,
) -> tuple[QualificationManifestV2, Path]:
    reference = getattr(manifest.payload.receipts, kind)
    assert reference is not None
    receipt_path = root / reference.relative_path
    receipt = json.loads(receipt_path.read_bytes())
    mutate(receipt)
    raw = canonical(receipt)
    receipt_path.write_bytes(raw)
    receipts = manifest.payload.receipts.model_copy(
        update={kind: reference.model_copy(update={"sha256": digest(raw)})}
    )
    payload = QualificationManifestPayloadV2.create(
        qualification_context_id=manifest.payload.qualification_context_id,
        environment_instance_id=manifest.payload.environment_instance_id,
        context=manifest.payload.context,
        receipts=receipts,
        observed_artifacts=manifest.payload.observed_artifacts,
        gates=manifest.payload.gates,
    )
    changed = QualificationManifestV2.create(payload)
    path = root / "manifest.json"
    path.write_bytes(canonical_manifest(changed))
    return changed, path


def test_context_and_manifest_ids_are_stable_golden(tmp_path):
    first = QualificationContextV1.create(context_payload())
    second = QualificationContextV1.create(context_payload())
    assert first.qualification_context_id == second.qualification_context_id
    _, manifest, _ = materialize(tmp_path)
    assert QualificationManifestV2.create(manifest.payload).qualification_manifest_id == (
        manifest.qualification_manifest_id
    )
    assert (
        first.qualification_context_id
        == "81dc09d6460651f9459114455447e6a8440dae0bb919c78594404641fce76c79"
    )
    assert manifest.qualification_manifest_id == (
        "aebc42dafa4ba406f5ff906dc6082643eea603e63a9170c68d61ac206c8e5822"
    )


def test_complete_same_host_manifest_is_the_only_runtime_authority(tmp_path):
    context, manifest, path = materialize(tmp_path)
    verified = verify_manifest_tree(path, manifest.qualification_manifest_id)
    assert verified.context == context
    assert set(verified.receipts) == set(RECEIPT_KINDS)
    assert RuntimeBindings(qualification_manifest_id=manifest.qualification_manifest_id)


@pytest.mark.parametrize("field", ["instance_id", "authority_scope_kind", "authority_scope_id"])
def test_merged_ledger_identity_hash_rejects_drift(field):
    payload = context_payload()
    changed = payload.ledger_expected.identity.model_copy(
        update={
            field: {
                "instance_id": "0" * 32,
                "authority_scope_kind": "project",
                "authority_scope_id": "other",
            }[field]
        }
    )
    with pytest.raises(ValidationError, match="Ledger identity hash mismatch"):
        LedgerExpectedV1.model_validate(
            payload.ledger_expected.model_dump(mode="json")
            | {"identity": changed.model_dump(mode="json")}
        )


def test_context_and_manifest_reject_unknown_fields():
    raw = context_payload().model_dump(mode="json") | {"extra": True}
    with pytest.raises(ValidationError):
        QualificationContextPayloadV1.model_validate(raw)
    with pytest.raises(ValidationError):
        QualificationManifestV2.model_validate(
            {"schema_version": 2, "qualification_manifest_id": H, "payload": {}, "extra": True}
        )


def test_forged_envelope_ids_rejected(tmp_path):
    context, manifest, _ = materialize(tmp_path)
    with pytest.raises(ValidationError, match="context ID mismatch"):
        QualificationContextV1(qualification_context_id="0" * 64, payload=context.payload)
    with pytest.raises(ValidationError, match="manifest ID mismatch"):
        QualificationManifestV2(qualification_manifest_id="0" * 64, payload=manifest.payload)


def test_execution_ready_is_derived_and_cannot_be_forged(tmp_path):
    _, manifest, _ = materialize(tmp_path)
    missing = manifest.payload.receipts.model_copy(update={"host_process_visibility": None})
    gates = manifest.payload.gates.model_copy(update={"host_process_visibility": False})
    payload = QualificationManifestPayloadV2.create(
        qualification_context_id=manifest.payload.qualification_context_id,
        environment_instance_id=manifest.payload.environment_instance_id,
        context=manifest.payload.context,
        receipts=missing,
        observed_artifacts=manifest.payload.observed_artifacts,
        gates=gates,
    )
    assert payload.execution_ready is False
    with pytest.raises(ValidationError, match="execution_ready"):
        QualificationManifestPayloadV2.model_validate(
            payload.model_dump(mode="json") | {"execution_ready": True}
        )


@pytest.mark.parametrize("kind", RECEIPT_KINDS)
def test_every_missing_receipt_denies_execution(tmp_path, kind):
    _, manifest, path = materialize(tmp_path)
    receipts = manifest.payload.receipts.model_copy(update={kind: None})
    gates = manifest.payload.gates.model_copy(update={kind: False})
    identifier = rewrite_manifest(
        path,
        manifest,
        receipts=receipts,
        gates=gates,
        execution_ready=False,
    )
    expected_error = (
        "not bound to host visibility" if kind == "host_process_visibility" else "execution_ready"
    )
    with pytest.raises(ValueError, match=expected_error):
        verify_manifest_tree(path, identifier)


@pytest.mark.parametrize("header", ["qualification_context_id", "environment_instance_id"])
def test_mixed_context_or_host_receipt_rejected(tmp_path, header):
    _, manifest, path = materialize(tmp_path)
    reference = manifest.payload.receipts.isolation
    assert reference is not None
    receipt_path = tmp_path / reference.relative_path
    receipt = json.loads(receipt_path.read_bytes())
    receipt[header] = "0" * (64 if header == "qualification_context_id" else 32)
    raw = canonical(receipt)
    receipt_path.write_bytes(raw)
    receipts = manifest.payload.receipts.model_copy(
        update={"isolation": reference.model_copy(update={"sha256": digest(raw)})}
    )
    identifier = rewrite_manifest(path, manifest, receipts=receipts)
    with pytest.raises(ValueError, match="another context/environment"):
        verify_manifest_tree(path, identifier)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mcp_tool_call_count", 1),
        ("model_requests", 1),
        ("stopped_before_sampling", False),
        ("approved_host_manifest_sha256", "f" * 64),
    ],
)
def test_host_visibility_authority_cannot_be_forged(tmp_path, field, value):
    _, manifest, _ = materialize(tmp_path)
    changed, path = rewrite_receipt(
        tmp_path,
        manifest,
        "host_process_visibility",
        lambda receipt: receipt.__setitem__(field, value),
    )
    with pytest.raises((ValueError, ValidationError)):
        verify_manifest_tree(path, changed.qualification_manifest_id)


def test_host_visibility_rejects_surface_widening(tmp_path):
    _, manifest, _ = materialize(tmp_path)

    def widen(receipt):
        receipt["arm_a_observation"]["visible_model_tools"] = ["apply_patch"]

    changed, path = rewrite_receipt(tmp_path, manifest, "host_process_visibility", widen)
    with pytest.raises(ValueError, match="Arm A finalized router surface"):
        verify_manifest_tree(path, changed.qualification_manifest_id)


@pytest.mark.parametrize(
    ("surface", "value"),
    [
        ("allowed_tools", ["mcp__devhub_delegate.devhub_delegate"]),
        ("visible_model_tools", ["mcp__devhub_delegate.devhub_delegate"]),
        ("nested_code_mode_map", ["mcp__devhub_delegate=devhub_delegate"]),
        ("hosted_tools", ["mcp__devhub_delegate.devhub_delegate"]),
        ("dynamic_tool_count", 1),
    ],
)
def test_default_visibility_rejects_delegate_leakage(tmp_path, surface, value):
    _, manifest, _ = materialize(tmp_path)

    def widen(receipt):
        receipt["default_observation"][surface] = value

    changed, path = rewrite_receipt(tmp_path, manifest, "host_process_visibility", widen)
    with pytest.raises(ValueError, match="Default Codex observation"):
        verify_manifest_tree(path, changed.qualification_manifest_id)


def test_runtime_config_must_bind_exact_host_visibility_receipt(tmp_path):
    _, manifest, _ = materialize(tmp_path)
    changed, path = rewrite_receipt(
        tmp_path,
        manifest,
        "runtime_config_probe",
        lambda receipt: receipt.__setitem__("host_process_visibility_sha256", "f" * 64),
    )
    with pytest.raises(ValueError, match="not bound to host visibility"):
        verify_manifest_tree(path, changed.qualification_manifest_id)


def test_receipt_hash_and_kind_substitution_rejected(tmp_path):
    _, manifest, path = materialize(tmp_path)
    reference = manifest.payload.receipts.isolation
    assert reference is not None
    (tmp_path / reference.relative_path).write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_manifest_tree(path, manifest.qualification_manifest_id)
    with pytest.raises(ValidationError, match="Receipt kind mismatch"):
        QualificationReceiptSetV2(
            isolation=reference.model_copy(update={"receipt_kind": "evaluator"})
        )


@pytest.mark.parametrize(
    "artifact",
    [
        "devhub_wheel_sha256",
        "dependency_lock_sha256",
        "python_executable_sha256",
        "python_runtime_environment_id",
        "codex_executable_sha256",
        "runtime_image_metadata_sha256",
        "evaluator_artifact_sha256",
        "ledger_identity_sha256",
        "ollama_model_digest",
    ],
)
def test_observed_artifact_substitution_rejected(tmp_path, artifact):
    _, manifest, path = materialize(tmp_path)
    original = getattr(manifest.payload.observed_artifacts, artifact)
    changed = "f" * 64 if original != "f" * 64 else "0" * 64
    observed = manifest.payload.observed_artifacts.model_copy(update={artifact: changed})
    identifier = rewrite_manifest(path, manifest, observed_artifacts=observed)
    with pytest.raises(ValueError, match="observed artifact"):
        verify_manifest_tree(path, identifier)


def test_stage3g_ollama_identity_is_exact():
    for update in (
        {"version": "0.35.0"},
        {"model": "other"},
        {"digest": "0" * 64},
    ):
        with pytest.raises(ValidationError):
            OllamaExpectedV1.model_validate(OllamaExpectedV1().model_dump() | update)


def test_legacy_runtime_bindings_are_read_only():
    old = {
        "schema_version": 1,
        "image_id": "sha256:" + "0" * 64,
        "bootstrap_sha256": H,
        "environment": {},
        "isolation_probe_sha256": H,
        "protocol_sha256": H,
        "reviewed_plan_sha256": H,
        "boundary_reviewed": True,
        "qualification_sha256": None,
    }
    assert HistoricalRuntimeBindingsV1.model_validate(old)
    with pytest.raises(ValidationError):
        RuntimeBindings.model_validate(old)
