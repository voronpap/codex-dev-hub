"""Offline runner contracts; never compile or invoke real proof binaries."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "diagnostics", ROOT / "scripts/run_production_diagnostics.py"
)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_receipt_missing_empty_and_received(tmp_path):
    path = tmp_path / "receipt.jsonl"
    assert runner.receipt_observation(path)["record_count"] is None
    path.touch()
    assert runner.receipt_observation(path)["record_count"] == 0
    path.write_text('{"endpoint_identity":"synthetic"}\n', encoding="utf-8")
    observed = runner.receipt_observation(path)
    assert observed["record_count"] == 1
    assert observed["sha256"] == runner.sha(path)
    path.write_text("partial", encoding="utf-8")
    assert runner.receipt_observation(path)["record_count"] is None


def test_exact_filters_and_preserved_binary_commands(monkeypatch):
    monkeypatch.setattr(runner.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(runner.os, "getgid", lambda: 1000, raising=False)
    command = runner.isolated_command(Path("saved/core"), ["module::proof", "--exact"])
    assert "--net" in command
    assert command[-3:] == [str(Path("saved/core")), "module::proof", "--exact"]


def test_baseline_stop_and_independent_catalog(monkeypatch, tmp_path):
    import subprocess

    binary = tmp_path / "binary"
    binary.write_bytes(b"fake; not executable")
    info = {"codex_core": {"path": str(binary), "sha256": runner.sha(binary)}}
    names = [
        "devhub_production_admission_path",
        "devhub_production_admission_path_adversarial",
        "devhub_production_admission_path_catalog",
    ]
    monkeypatch.setattr(runner, "isolated_command", lambda *args: ["never-run"])
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, "".join(f"module::{n}: test\n" for n in names).encode(), b""
        ),
    )
    calls = []
    baseline_fails = True

    def fake_run(binary, digest, exact, output, label, assets, stack):
        calls.append((label, exact, stack, digest))
        return {
            "exit_code": 1 if baseline_fails else (-6 if label == "handler-normal" else 0),
            "stack_overflow": label == "handler-normal",
        }

    monkeypatch.setattr(runner, "run_one", fake_run)
    runner.run_suite(info, tmp_path / "failed", tmp_path)
    assert [c[0] for c in calls] == ["baseline"]
    calls.clear()
    baseline_fails = False
    runner.run_suite(info, tmp_path / "diagnostic", tmp_path)
    assert [c[0] for c in calls] == ["baseline", "handler-normal", "handler-large-stack", "catalog"]
    assert calls[1][2] is None
    assert calls[2][2] == "16777216"
    assert calls[1][1] == calls[2][1]
    assert len({c[3] for c in calls}) == 1
