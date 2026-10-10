"""Metadata-only Stage 3G-C qualification. Never invokes a task or inference."""

import argparse
import json
import os
import platform
import shutil
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from devhub.benchmark import canonical, clean_commit, digest, write_new
from devhub.experiment import EnvironmentManifest, ExperimentProtocol, plan
from devhub.experiment_bridge import CODEX_HOSTS, connect_target, public_resolved_addresses
from devhub.experiment_launch import DOCKER, safe_artifacts
from devhub.experiment_run import secret_strings
from devhub.experiment_tool_gate import policy_hash
from devhub.ledger import MIGRATIONS
from devhub.ollama import OllamaAdapter
from devhub.qualification import RuntimeBindings, VerifiedQualificationV2, verify_manifest_tree

ISOLATION_CHECKS = frozenset(
    {
        "host_canary_hidden",
        "other_arm_hidden",
        "source_and_oracle_hidden",
        "network_denied",
        "only_scoped_bridges",
        "fresh_home",
        "packet_readable",
        "packet_readonly",
        "nonroot",
        "capabilities_dropped",
        "no_new_privileges",
        "resource_limits_effective",
        "docker_socket_absent",
        "host_home_absent",
        "repository_absent",
    }
)


def isolation_valid(proof: dict[str, Any], image: str, bootstrap: str) -> bool:
    return (
        proof.get("image_id") == image
        and proof.get("bootstrap_sha256") == bootstrap
        and proof.get("kind") == "synthetic_oci_isolation_probe"
        and proof.get("runtime_image_qualification") is True
        and proof.get("checks") == dict.fromkeys(ISOLATION_CHECKS, True)
    )


def egress_policy_checks() -> dict[str, bool]:
    checks = {"exact_allowlist": CODEX_HOSTS == {"chatgpt.com", "api.openai.com"}}
    for host in sorted(CODEX_HOSTS):
        checks["allow_" + host] = (
            connect_target(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode()) == host
        )
    for label, host in {
        "arbitrary": "example.com",
        "private": "10.0.0.1",
        "loopback": "127.0.0.1",
        "docker_host": "host.docker.internal",
        "ollama": "127.0.0.1:11434",
        "groq": "api.groq.com",
        "gemini": "generativelanguage.googleapis.com",
        "ipv6_loopback": "[::1]",
        "suffix_bypass": "api.openai.com.evil.invalid",
    }.items():
        try:
            connect_target(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
        except ValueError:
            checks["deny_" + label] = True
        else:
            checks["deny_" + label] = False
    public = [(2, 1, 6, "", ("8.8.8.8", 443))]
    private = [(2, 1, 6, "", ("10.0.0.1", 443))]
    mixed = [*public, *private]
    checks["allow_public_resolution"] = public_resolved_addresses(public)
    checks["deny_empty_resolution"] = not public_resolved_addresses([])
    checks["deny_private_resolution"] = not public_resolved_addresses(private)
    checks["deny_mixed_resolution"] = not public_resolved_addresses(mixed)
    return checks


def validate_chatgpt_auth_bytes(raw: bytes) -> dict[str, Any]:
    """Validate one exact token-based Codex auth buffer without publishing it."""

    data = json.loads(raw)
    tokens = data.get("tokens") if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("auth_mode") not in {None, "chatgpt"}
        or data.get("OPENAI_API_KEY")
        or not isinstance(tokens, dict)
        or not isinstance(tokens.get("access_token"), str)
        or not tokens["access_token"]
    ):
        raise ValueError("Existing ChatGPT auth only")
    return data


def validated_chatgpt_auth(path: Path) -> dict[str, Any]:
    """Validate the frozen token-based Codex authority without publishing it."""

    if not path.is_file() or path.is_symlink():
        raise ValueError("Existing regular CLI auth file required")
    return validate_chatgpt_auth_bytes(path.read_bytes())


def check_auth(path: Path) -> tuple[bytes, ...]:
    data = validated_chatgpt_auth(path)
    # Used only for withholding scans, never fingerprinted/serialized.
    return secret_strings(data)


def require_ready(manifest: Path, bindings: RuntimeBindings) -> VerifiedQualificationV2:
    """Verify the sole final authority; component subsets cannot authorize execution."""

    return verify_manifest_tree(manifest, bindings.qualification_manifest_id)


REQUIRED_GATES = frozenset(
    {
        "linux_host",
        "plan_integrity",
        "runtime_image",
        "codex_identity",
        "isolation",
        "egress_policy",
        "egress_runtime",
        "auth_presence",
        "auth_tmpfs",
        "cli_config",
        "ollama_identity",
        "ledger_available",
        "evaluator_sandbox",
        "secret_scan",
        "disk_space",
    }
)


def preflight(
    repo: Path,
    protocol: ExperimentProtocol,
    frozen_plan: dict[str, Any],
    build: Path,
    isolation: Path,
    evaluator: Path,
    auth: Path,
    ledger_root: Path,
    runtime_checks: Path,
    destination: Path,
) -> dict[str, Any]:
    """Collect sanitized checks. Failed/unavailable checks are false, never inferred true.

    Image/probe files are operator-controlled evidence, not adversarial attestations.
    This does not authorize rehearsal; a separate explicit review remains necessary.
    """
    if destination.exists():
        raise ValueError("Exclusive qualification evidence required")
    gates = dict.fromkeys(REQUIRED_GATES, False)
    commit = clean_commit(repo)
    gates["linux_host"] = platform.system() == "Linux"
    gates["plan_integrity"] = plan(repo, protocol, frozen_plan["run_id"]) == frozen_plan
    bootstrap = digest((repo / "scripts/benchmark_guest.py").read_bytes())
    image: str | None = None
    kernel = platform.release()
    runtime: str | None = None
    image_python: str | None = None
    binary: str | None = None
    secrets: tuple[bytes, ...] = ()
    artifact_hashes = {}
    try:
        secrets = check_auth(auth)
        gates["auth_presence"] = True
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        build_raw = build.read_bytes()
        b = json.loads(build_raw)
        image = b["image_id"]
        artifact_hashes["image_build"] = digest(build_raw)
        lock = (repo / "benchmarks/runtime-lock.json").read_bytes()
        data = json.loads(
            subprocess.check_output([*DOCKER, "image", "inspect", image], timeout=20)
        )[0]
        gates["runtime_image"] = (
            data["Id"] == image
            and data["Os"] == "linux"
            and not data["Config"].get("Volumes")
            and b["runtime_lock_sha256"] == digest(lock)
            and all(
                e.split("=", 1)[0] in {"PATH", "HOME", "LANG"}
                for e in data["Config"].get("Env", [])
            )
        )
        args = [
            *DOCKER,
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--user=1000:1000",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--entrypoint=python3",
            image,
            "-c",
            "import hashlib,json,platform,subprocess;print(json.dumps({"
            "'version':subprocess.check_output(['codex','--version']).decode().strip(),"
            "'binary':hashlib.sha256(open('/usr/local/bin/codex','rb').read()).hexdigest(),"
            "'python':platform.python_version()}))",
        ]
        identity = json.loads(subprocess.check_output(args, timeout=30))
        image_python, binary = identity["python"], identity["binary"]
        gates["codex_identity"] = (
            identity["version"] == protocol.codex_cli_version == b["codex_version"]
            and binary == b["codex_binary_sha256"]
        )
        runtime = (
            subprocess.check_output(
                [*DOCKER, "version", "--format", "{{.Server.Version}}"], timeout=20
            )
            .decode()
            .strip()
        )
        probe_raw = isolation.read_bytes()
        artifact_hashes["isolation"] = digest(probe_raw)
        gates["isolation"] = isolation_valid(json.loads(probe_raw), image, bootstrap)
        eval_raw = (evaluator / "result.json").read_bytes()
        artifact_hashes["evaluator"] = digest(eval_raw)
        e = json.loads(eval_raw)
        gates["evaluator_sandbox"] = (
            e["tests_pass"] is True
            and e["runner_sha256"] == digest((repo / "scripts/benchmark_evaluator.py").read_bytes())
            and e["buggy_result"]["exit_status"] == 1
            and e["corrected_result"]["exit_status"] == 0
            and not e["buggy_result"]["timeout"]
            and not e["corrected_result"]["timeout"]
            and not e["buggy_result"]["output_limit_exceeded"]
            and not e["corrected_result"]["output_limit_exceeded"]
            and not e["buggy_result"]["artifact_withheld"]
            and not e["corrected_result"]["artifact_withheld"]
            and e["buggy_result"]["input_error"] is None
            and e["corrected_result"]["input_error"] is None
        )
        # Inspect existence by immutable ID, never pull an evaluator image here.
        subprocess.check_output([*DOCKER, "image", "inspect", e["image_id"]], timeout=20)
        checks_raw = runtime_checks.read_bytes()
        artifact_hashes["runtime_checks"] = digest(checks_raw)
        checks = json.loads(checks_raw)
        if (
            checks["image_id"] == image
            and checks["bootstrap_sha256"] == bootstrap
            and checks["protocol_sha256"] == protocol.hashes()["protocol"]
            and checks.get("qualification_policy_sha256") == policy_hash()
        ):
            for key in ("auth_tmpfs", "cli_config", "egress_runtime"):
                gates[key] = checks["checks"].get(key) is True
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
    gates["egress_policy"] = all(egress_policy_checks().values())
    observed_ollama = None
    try:
        OllamaAdapter(protocol.ollama).inspect()  # metadata only; never count/generate/chat
        observed_ollama = protocol.ollama.model_dump(mode="json")
        gates["ollama_identity"] = True
    except Exception:
        pass  # Do not serialize remote error bodies or local paths.
    try:
        db = ledger_root / "ledger.db"
        if db.is_file() and not db.is_symlink():
            with sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True) as conn:
                gates["ledger_available"] = (
                    conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
                    and conn.execute("PRAGMA user_version").fetchone() == (len(MIGRATIONS),)
                    and {"reservations", "events", "buckets"}
                    <= {
                        r[0]
                        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    }
                )
    except sqlite3.Error:
        pass
    gates["disk_space"] = shutil.disk_usage(destination.parent).free >= 2 * 1024**3
    # Qualification publication uses the same fail/withhold scanner as raw captures.
    gates["secret_scan"] = True
    cpu = platform.processor() or platform.machine()
    ram = None
    if hasattr(os, "sysconf"):
        ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    environment = EnvironmentManifest(
        os=platform.platform(),
        python=platform.python_version(),
        codex_cli_version=protocol.codex_cli_version,
        codex_model=protocol.codex_model,
        devhub_commit=commit,
        ollama_version=protocol.ollama.version,
        ollama_model=protocol.ollama.model,
        ollama_digest=protocol.ollama.model_digest,
        cpu=cpu,
        gpu=None,
        ram_bytes=ram,
        captured_at=datetime.now(UTC).isoformat(),
    )
    observed_host = environment.model_dump(mode="json")
    if not gates["codex_identity"]:
        observed_host["codex_cli_version"] = None
    if not gates["ollama_identity"]:
        for key in ("ollama_version", "ollama_model", "ollama_digest"):
            observed_host[key] = None
    manifest = {
        "host": observed_host,
        "kernel": kernel,
        "container_runtime": runtime,
        "runtime_image_id": image,
        "guest_python": image_python,
        "codex_binary_sha256": binary,
        "ollama_verified": observed_ollama is not None,
    }
    result = {
        "kind": "stage3g_runtime_qualification",
        "schema_version": 1,
        "implementation_commit": commit,
        "image_id": image,
        "environment": manifest,
        "environment_sha256": digest(canonical(cast(JsonValue, manifest))),
        "protocol_sha256": protocol.hashes()["protocol"],
        "plan_sha256": digest(canonical(frozen_plan)),
        "bootstrap_sha256": bootstrap,
        "artifact_hashes": artifact_hashes,
        "gates": gates,
        "execution_ready": all(gates.values()),
        "real_codex_executions": 0,
        "provider_sends": 0,
        "rehearsal_authorized": False,
        "semantic_acceptance": None,
        "quality_benchmark": None,
        "delegation_value": None,
        "savings": None,
    }
    raw = canonical(cast(JsonValue, result))
    safe_artifacts((raw,), secrets)
    write_new(destination, raw)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["preflight"])
    for name in (
        "protocol",
        "plan",
        "build",
        "isolation",
        "evaluator",
        "auth",
        "ledger-root",
        "runtime-checks",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = preflight(
        Path(__file__).resolve().parents[2],
        ExperimentProtocol.model_validate_json(args.protocol.read_bytes()),
        json.loads(args.plan.read_bytes()),
        args.build,
        args.isolation,
        args.evaluator,
        args.auth,
        args.ledger_root,
        args.runtime_checks,
        args.output,
    )
    print(
        json.dumps(
            {
                "execution_ready": result["execution_ready"],
                "gates": result["gates"],
                "real_codex_executions": 0,
                "provider_sends": 0,
            }
        )
    )
    raise SystemExit(0 if result["execution_ready"] else 1)


if __name__ == "__main__":
    main()
