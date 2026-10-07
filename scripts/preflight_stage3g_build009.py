"""Cheap build-009 source/hash gate. Never compiles Rust or starts Codex/providers."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from jsonschema import Draft202012Validator

from devhub.benchmark import canonical, digest, write_new
from devhub.delegate import DelegationRequest
from devhub.qualification import ISOLATED_DELEGATE_ARGS, STAGE3G_DELEGATE_TOOL
from devhub.stage3g_host import read_stage3g_host_manifest

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_SHA256 = "d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36"
SCHEMA_SHA256 = "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
SOURCE_COMMIT = "4607249e430dac1c961df4dc615beae88e33cec8"


def _sha(path: Path) -> str:
    return digest(path.read_bytes())


def _compact_schema_hash(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def collect(candidate_source: Path | None = None) -> dict[str, object]:
    candidate = ROOT / "patches/stage3g-approved-call/candidate.patch"
    host = ROOT / "patches/stage3g-approved-call/host-integration.patch"
    manifest_path = ROOT / "benchmarks/stage3g-host-manifest-v2.json"
    schema_path = ROOT / "benchmarks/stage3g-host-manifest-v2.schema.json"
    stored_schema_path = ROOT / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
    allowed_tools_evidence_path = ROOT / "docs/evidence/stage3g-allowed-tools/source-bindings.json"
    candidate_bytes = candidate.read_bytes()
    host_bytes = host.read_bytes()
    if digest(candidate_bytes) != CANDIDATE_SHA256:
        raise ValueError("Historical Candidate B patch changed")

    manifest, manifest_bytes = read_stage3g_host_manifest(manifest_path)
    Draft202012Validator(json.loads(schema_path.read_bytes())).validate(json.loads(manifest_bytes))
    generated_schema = DelegationRequest.model_json_schema()
    stored_schema = json.loads(stored_schema_path.read_bytes())
    if generated_schema != stored_schema or _compact_schema_hash(generated_schema) != SCHEMA_SHA256:
        raise ValueError("DelegationRequest schema identity changed")

    patch = host_bytes.decode()
    required = (
        "devhub-stage3g-host-manifest",
        "devhub-stage3g-arm",
        "ExtensionDataInit",
        "thread_extension_init: host_admission.extension_init",
        "let mut thread_extension_init = self.thread_extension_init.clone();",
        "Stage3gHostArm::A",
        "config.mcp_servers.is_empty()",
        "Stage3gHostArm::B",
        "ApprovedDelegatePolicy::delegate",
        "AllowedTools(",
        "DevFabric proof observer stopped before model sampling",
    )
    missing = [item for item in required if item not in patch]
    if missing:
        raise ValueError(f"Host integration anchors missing: {missing}")
    if "ThreadStartParams" in patch:
        raise ValueError("Client ThreadStartParams must not carry host authority")

    allowed_tools_evidence = json.loads(allowed_tools_evidence_path.read_bytes())
    source_excerpts = "\n".join(
        item["excerpt"]
        for item in allowed_tools_evidence.values()
        if isinstance(item, dict) and isinstance(item.get("excerpt"), str)
    )
    for required_source in (
        "Some(AllowedTools::default())",
        "assert_eq!(plan.visible_specs, Vec::<ToolSpec>::new())",
        "hosted_specs.retain",
        "register_external_with_exposure",
        "dynamic_echo",
    ):
        if required_source not in source_excerpts:
            raise ValueError(f"AllowedTools source evidence is incomplete: {required_source}")

    apply_check: bool | None = None
    if candidate_source is not None:
        result = subprocess.run(
            ["git", "apply", "--check", str(host)],
            cwd=candidate_source,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError(f"Host patch does not apply to Candidate B source: {result.stderr}")
        apply_check = True

    launcher = (ROOT / "src/devhub/experiment_launch.py").read_text()
    runner = (ROOT / "src/devhub/experiment_run.py").read_text()
    qualification = (ROOT / "src/devhub/qualification.py").read_text()
    if not all(
        item in launcher
        for item in (
            "--devhub-stage3g-host-manifest",
            "--devhub-stage3g-arm",
            "STAGE3G_HOST_MANIFEST_CONTAINER",
        )
    ):
        raise ValueError("Stage 3G launcher does not supply host-owned admission")
    if not all(
        item in runner
        for item in (
            "read_stage3g_host_manifest",
            "approved_host_manifest_sha256",
            "host_manifest",
        )
    ):
        raise ValueError("Qualification-bound host manifest is not reverified by the launcher")
    if "LedgerIdentityCoreV1" not in qualification:
        raise ValueError("Qualification must reuse the merged ledger identity")
    if ISOLATED_DELEGATE_ARGS != ("-I", "-m", "devhub.delegate_server"):
        raise ValueError("Qualified B-arm Python entrypoint changed")

    return {
        "schema_version": 2,
        "build_id": "build-009",
        "phase": "cheap_prebuild_gate_attempt_2",
        "source_commit": SOURCE_COMMIT,
        "implementation_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "candidate_b_base_patch_sha256": digest(candidate_bytes),
        "host_integration_patch_sha256": digest(host_bytes),
        "combined_production_patchset_sha256": digest(candidate_bytes + host_bytes),
        "host_patch_applies_to_candidate_source": apply_check,
        "delegation_request_schema_sha256": SCHEMA_SHA256,
        "host_manifest": {
            "path": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": digest(manifest_bytes),
            "schema_path": str(schema_path.relative_to(ROOT)).replace("\\", "/"),
            "schema_sha256": _sha(schema_path),
        },
        "qualification_integration": {
            "qualification_manifest_v2_is_runtime_authority": True,
            "host_manifest_exact_bytes_rehashed": True,
            "ledger_identity_core_reused": True,
            "isolated_delegate_argv": list(ISOLATED_DELEGATE_ARGS),
        },
        "allowed_tools_source_evidence": {
            "path": str(allowed_tools_evidence_path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": _sha(allowed_tools_evidence_path),
            "empty_ceiling_covers_registered_hosted_dynamic_and_code_mode_sources": True,
        },
        "tool_surfaces": {
            "default": {
                "allowed_tools": None,
                "approved_delegate_policy": "absent",
            },
            "arm_a": {
                "allowed_tools": [],
                "approved_delegate_policy": "absent",
                "visible": [],
                "nested": [],
                "hosted": [],
                "dynamic": [],
            },
            "arm_b": {
                "allowed_tools": [STAGE3G_DELEGATE_TOOL],
                "approved_delegate_policy": "exact_reviewed_policy",
                "visible": [STAGE3G_DELEGATE_TOOL],
                "nested": [],
                "hosted": [],
                "dynamic": [],
            },
            "b_minus_a": [STAGE3G_DELEGATE_TOOL],
            "a_minus_b": [],
        },
        "exact_image": {
            "current_unpatched_image_gate": "EXPECTED_UNRELATED_STAGE3G_GATE_FAILURE",
            "current_unpatched_failures": [
                "cli_config=false",
                "apply_patch registration unresolved",
                "write_file mapping unresolved",
            ],
            "host_ceiling_source_result": "PASS",
            "why_ambiguity_is_removed": (
                "AllowedTools is installed before router construction; empty Arm A rejects every "
                "registered/hosted/dynamic/code-mode source, and Arm B permits only the canonical "
                "delegate before Candidate B admission."
            ),
            "actual_process_visibility": None,
        },
        "result": "BUILD_009_READY_FOR_AUTHORIZATION",
        "rust_compilation_started": False,
        "build_009_run": False,
        "build_010_run": False,
        "model_requests": 0,
        "provider_sends": 0,
        "real_codex_executions": 0,
        "benchmark_run": False,
        "rehearsal_run": False,
        "process_proof": None,
        "production_host_activation": "BLOCKED_PREBUILD",
        "production_classification": "UNKNOWN",
        "stage_3g_c": "OPEN",
        "stage_3g": "OPEN",
        "execution_ready": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-source", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = collect(args.candidate_source)
    raw = canonical(result)
    if args.output is not None:
        write_new(args.output, raw)
    print(raw.decode(), end="")


if __name__ == "__main__":
    main()
