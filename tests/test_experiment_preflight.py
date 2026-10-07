"""Synthetic qualification tests; no Codex task, frozen fixture execution or model call."""

import socket
import subprocess
import sys
from pathlib import Path

import pytest

from devhub.experiment_bridge import proxy
from devhub.experiment_evaluate import evaluate_bytes, evaluation_command, frozen_pair
from devhub.experiment_launch import safe_artifacts
from devhub.experiment_preflight import (
    ISOLATION_CHECKS,
    check_auth,
    egress_policy_checks,
    isolation_valid,
    require_ready,
)
from devhub.qualification import RuntimeBindings


def test_exact_image_all_checks_required():
    proof = {
        "image_id": "image",
        "bootstrap_sha256": "bootstrap",
        "kind": "synthetic_oci_isolation_probe",
        "runtime_image_qualification": True,
        "checks": dict.fromkeys(ISOLATION_CHECKS, True),
    }
    assert isolation_valid(proof, "image", "bootstrap")
    assert not isolation_valid(proof, "other", "bootstrap")
    for key in ISOLATION_CHECKS:
        broken = {**proof, "checks": {**proof["checks"], key: False}}
        assert not isolation_valid(broken, "image", "bootstrap")


def test_require_ready_accepts_only_final_manifest_authority(tmp_path, monkeypatch):
    bindings = RuntimeBindings(qualification_manifest_id="a" * 64)
    seen = []

    def verify(path, identifier):
        seen.append((path, identifier))
        return "verified"

    monkeypatch.setattr("devhub.experiment_preflight.verify_manifest_tree", verify)
    manifest = tmp_path / "manifest.json"
    assert require_ready(manifest, bindings) == "verified"
    assert seen == [(manifest, "a" * 64)]


def test_egress_exact_policy():
    assert all(egress_policy_checks().values())


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "::1", "169.254.169.254"]
)
def test_dns_private_rebinding_denied(monkeypatch, address):
    class Request:
        pending = bytearray(b"CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n")

        def settimeout(self, value):
            pass

        def recv(self, size):
            result = bytes(self.pending[:size])
            del self.pending[:size]
            return result

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))],
    )
    with pytest.raises(ValueError, match="Non-public"):
        proxy(Request())


def test_auth_no_api_key_no_fingerprint(tmp_path):
    p = tmp_path / "auth.json"
    p.write_text('{"OPENAI_API_KEY":"synthetic"}')
    with pytest.raises(ValueError):
        check_auth(p)
    p.write_text('{"tokens":{"access_token":"synthetic-only-secret"}}')
    values = check_auth(p)
    with pytest.raises(ValueError, match="withheld"):
        safe_artifacts((b"contains synthetic-only-secret",), values)


@pytest.mark.parametrize("prefix", ["sk-", "github_pat_", "ghp_", "gsk_"])
def test_publication_withholds_secret_patterns(prefix):
    with pytest.raises(ValueError):
        safe_artifacts(((prefix + "x" * 40).encode(),))


def test_evaluator_mounts_limits_and_barrier(tmp_path):
    image = "sha256:" + "a" * 64
    files = [tmp_path / name for name in ("generated", "reference", "runner")]
    for p in files:
        p.write_bytes(b"synthetic")
    argv = evaluation_command(image, *files, "synthetic-only")
    assert "--network=none" in argv and "--read-only" in argv
    assert "--user=1000:1000" in argv and "--pids-limit=32" in argv
    assert "--security-opt=no-new-privileges" in argv and "--memory=256m" in argv
    assert sum(a == "--mount" for a in argv) == 3
    assert all(
        word not in " ".join(argv) for word in ("/auth", "/bridge", "/ledger", "codex", "ollama")
    )
    with pytest.raises(ValueError, match="Immutable"):
        evaluation_command("mutable:latest", *files, "synthetic")
    with pytest.raises(ValueError, match="barrier"):
        evaluate_bytes(b"", b"", b"", image, files[2], tmp_path / "result")
    assert not (tmp_path / "result").exists()
    with pytest.raises(ValueError, match="Independent"):
        frozen_pair((tmp_path, tmp_path), ("A", "B"))


def test_generated_text_never_imported_on_host(tmp_path):
    # This payload would create a canary if an evaluator ever compiled/imported it on the host.
    canary = tmp_path / "must-not-exist"
    generated = f"from pathlib import Path; Path({str(canary)!r}).touch()".encode()
    with pytest.raises(ValueError):
        evaluate_bytes(generated, b"", b"", "mutable", Path("unused"), tmp_path / "out")
    assert not canary.exists()


@pytest.mark.parametrize("mode", ["normal", "overflow", "timeout"])
def test_evaluator_bounded_capture_uses_only_synthetic_process(monkeypatch, mode):
    import devhub.experiment_evaluate as mod
    import devhub.process_capture as capture_mod

    real_popen = subprocess.Popen
    source = {
        "normal": "print('synthetic')",
        "overflow": "print('x'*2200000)",
        "timeout": "import time; time.sleep(10)",
    }[mode]
    monkeypatch.setattr(
        mod.subprocess,
        "Popen",
        lambda *a, **kw: real_popen(
            [sys.executable, "-c", source],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ),
    )
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **kw: None)
    monkeypatch.setattr(capture_mod, "HARD_OBSERVED_BYTE_LIMIT_PER_STREAM", 2 * 1024 * 1024)
    if mode == "timeout":
        ticks = iter([0, 61])
        monkeypatch.setattr(capture_mod.time, "monotonic", lambda: next(ticks, 61))
    captured = mod.capture_evaluator("synthetic-not-a-container")
    assert len(captured.stdout.data) <= 1024 * 1024
    assert len(captured.stderr.data) <= 1024 * 1024
    assert captured.timed_out is (mode == "timeout")
    assert captured.output_limit_exceeded is (mode == "overflow")
    if mode == "normal":
        assert captured.stdout.data.strip() == b"synthetic"
