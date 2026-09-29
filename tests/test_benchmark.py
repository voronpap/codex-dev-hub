"""Storage/integrity exercises only: no Codex, network, models or generated code."""

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.baseline import verified_cases
from devhub.benchmark import (
    BenchmarkConfig,
    Metrics,
    Record,
    SyntheticCapture,
    canonical,
    digest,
    freeze_synthetic,
    prepare,
    reviewer_packet,
    verify,
)

ROOT = Path(__file__).resolve().parents[1]


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


@pytest.fixture
def prepared(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    shutil.copytree(ROOT / "benchmarks", repo / "benchmarks")
    (repo / "src/devhub").mkdir(parents=True)
    for name in ("benchmark.py", "baseline.py", "models.py"):
        shutil.copyfile(ROOT / "src/devhub" / name, repo / "src/devhub" / name)
    git(repo, "init", "-q")
    git(repo, "config", "core.autocrlf", "false")
    git(repo, "add", ".")
    git(
        repo,
        "-c",
        "user.name=Harness Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "Frozen test repository",
    )
    config = BenchmarkConfig.model_validate_json(
        (repo / "benchmarks/harness-config.json").read_bytes()
    )
    run = tmp_path / "run"
    manifest = prepare(repo, config, run, "offline-1")
    return repo, config, run, manifest


def capture(output=b"Offline stub; no task answer"):
    result = SyntheticCapture()
    result.finish(output)
    return result


def test_twelve_frozen_pairs_isolated_equivalent_and_unmeasured(prepared):
    repo, config, run, manifest = prepared
    assert len(manifest.cases) == 12
    assert len({c.task_class for c in manifest.cases}) == 6
    assert manifest.real_execution_enabled is False
    assert manifest.routing_policy_sha256 is None
    assert manifest.config.model_digest is None
    for case in manifest.cases:
        paths = [run / "executors" / case.fixture_id / arm for arm in ("A", "B")]
        for path in paths:
            assert {p.name for p in path.iterdir()} == {"input.txt", "task.txt", "instructions.txt"}
        for name in ("input.txt", "task.txt"):
            assert (paths[0] / name).read_bytes() == (paths[1] / name).read_bytes()
            assert (paths[0] / name).stat().st_ino != (paths[1] / name).stat().st_ino
        for arm in ("A", "B"):
            raw = json.loads(
                (run / "records" / case.fixture_id / arm / "prepared.json").read_bytes()
            )
            record = Record.model_validate_json(json.dumps(raw))
            assert record.status == "not_run"
            assert record.duration_ns is None
            assert record.output_sha256 is None
            assert record.metrics == Metrics()
            assert record.quality.acceptance_pass is None
            assert record.delegation_value is None
            assert record.savings is None
            assert raw["metrics"]["provider_sends"] is None
    assert verify(repo, run, config) == manifest


@pytest.mark.parametrize("kind", ["fixture", "oracle", "manifest"])
def test_hash_change_rejected_even_with_changed_git_commit(prepared, kind):
    repo, config, run, _ = prepared
    case = verified_cases(repo / "benchmarks")[0]
    path = repo / "benchmarks" / ("manifest.json" if kind == "manifest" else case[kind])
    path.write_bytes(path.read_bytes() + b" ")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "tamper")
    with pytest.raises(ValueError, match="integrity"):
        prepare(repo, config, run.parent / "new", "new")


def test_oracle_is_reviewer_only_and_waits_for_both_outputs(prepared):
    repo, config, run, _ = prepared
    with pytest.raises(ValueError, match="Both arms"):
        reviewer_packet(repo, run, config, "review-02")
    a = freeze_synthetic(repo, run, config, "review-02", "A", capture(b"A private answer"))
    with pytest.raises(ValueError, match="Both arms"):
        reviewer_packet(repo, run, config, "review-02")
    for path in (run / "executors").rglob("*.txt"):
        assert b"A private answer" not in path.read_bytes()
        assert b"required_fix" not in path.read_bytes()
    b = freeze_synthetic(repo, run, config, "review-02", "B", capture(b"B independent answer"))
    packet = reviewer_packet(repo, run, config, "review-02")
    assert packet["outputs"] == {"A": "A private answer", "B": "B independent answer"}
    assert packet["oracle"]["id"] == "review-02"
    assert packet["comparison"] == "inconclusive"
    assert a.output_sha256 == digest(b"A private answer")
    assert b.output_sha256 == digest(b"B independent answer")
    assert a.metrics.codex_input_tokens is None
    assert a.metrics.provider_api_cost_microusd is None
    assert a.duration_ns >= 0
    assert a.ended_at >= a.started_at
    with pytest.raises(FileExistsError):
        freeze_synthetic(repo, run, config, "review-02", "A", capture())


@pytest.mark.parametrize(
    "name",
    ["executors/review-02/A/input.txt", "manifest.json", "records/review-02/A/prepared.json"],
)
def test_artifact_tamper_detected(prepared, name):
    repo, config, run, _ = prepared
    (run / name).write_bytes(b"tampered")
    with pytest.raises((ValueError, ValidationError)):
        verify(repo, run, config)


def test_output_and_final_metadata_tamper_detected(prepared):
    repo, config, run, _ = prepared
    freeze_synthetic(repo, run, config, "extract-01", "A", capture(b"frozen"))
    output = run / "records/extract-01/A/output.txt"
    output.write_bytes(b"changed")
    with pytest.raises(ValueError, match="Output integrity"):
        verify(repo, run, config)
    output.write_bytes(b"frozen")
    final = output.with_name("final.json")
    final.write_bytes(final.read_bytes() + b" ")
    with pytest.raises(ValueError, match="Artifact integrity"):
        verify(repo, run, config)


def test_extra_file_contamination_rejected(prepared):
    repo, config, run, _ = prepared
    (run / "executors/review-02/A/oracle.json").write_text("{}")
    with pytest.raises(ValueError, match="contamination"):
        verify(repo, run, config)


def test_dirty_config_commit_and_directory_reuse_refused(prepared):
    repo, config, run, _ = prepared
    with pytest.raises(FileExistsError):
        prepare(repo, config, run, "offline-1")
    with pytest.raises(ValueError, match="outside"):
        prepare(repo, config, repo / "run", "inside")
    changed = BenchmarkConfig(**{**config.model_dump(), "shared_instructions": "Changed"})
    with pytest.raises(ValueError, match="Configuration"):
        verify(repo, run, changed)
    (repo / "untracked.txt").write_text("dirty")
    with pytest.raises(ValueError, match="Dirty"):
        verify(repo, run, config)
    git(repo, "add", ".")
    git(repo, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "new")
    with pytest.raises(ValueError, match="Implementation"):
        verify(repo, run, config)


def test_loaded_code_must_match_declared_commit(prepared):
    repo, config, run, _ = prepared
    path = repo / "src/devhub/benchmark.py"
    path.write_bytes(path.read_bytes() + b"\n# changed\n")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "new")
    with pytest.raises(ValueError, match="Loaded harness"):
        prepare(repo, config, run.parent / "new", "new")


def test_synthetic_cannot_claim_real_usage_or_quality(prepared):
    repo, config, run, _ = prepared
    record = freeze_synthetic(repo, run, config, "extract-01", "A", capture())
    with pytest.raises(ValidationError, match="actual metrics"):
        Record(**{**record.model_dump(), "metrics": Metrics(codex_input_tokens=10)})
    with pytest.raises(ValidationError):
        Record(**{**record.model_dump(), "status": "completed"})
    with pytest.raises(ValidationError):
        Record(**{**record.model_dump(), "savings": 0})
    with pytest.raises(ValidationError):
        Record(**{**record.model_dump(), "ended_at": datetime(2000, 1, 1, tzinfo=UTC)})
    with pytest.raises(ValidationError):
        Record(**{**record.model_dump(), "ended_at": datetime.now(UTC).replace(tzinfo=None)})
    assert record.ended_at - record.started_at < timedelta(seconds=10)


def test_new_config_needs_new_run_and_policy_hashes_bound(prepared):
    repo, config, run, _ = prepared
    config = BenchmarkConfig(
        **{
            **config.model_dump(),
            "routing_policy": {"cloud": False},
            "context_builder_policy": {"offline_cap": 8000},
        }
    )
    manifest = prepare(repo, config, run.parent / "new", "new-version")
    assert manifest.routing_policy_sha256 == digest(canonical({"cloud": False}))
    assert manifest.context_builder_policy_sha256 == digest(canonical({"offline_cap": 8000}))


def test_config_rejects_execution_credentials_and_timing_change():
    with pytest.raises(ValidationError):
        BenchmarkConfig(shared_instructions="x", arm_b_instructions="y", api_key="canary")
    with pytest.raises(ValidationError):
        BenchmarkConfig(shared_instructions="x", arm_b_instructions="y", mode="live")
    with pytest.raises(ValidationError, match="Timing"):
        BenchmarkConfig(
            shared_instructions="x", arm_b_instructions="y", timing_boundary="inference"
        )


def test_unknown_fixture_arm_and_unfinished_capture_rejected(prepared):
    repo, config, run, _ = prepared
    with pytest.raises(ValueError, match="Unknown"):
        freeze_synthetic(repo, run, config, "../elsewhere", "A", capture())
    with pytest.raises(ValueError, match="Unknown"):
        freeze_synthetic(repo, run, config, "review-01", "C", capture())
    with pytest.raises(ValueError, match="Unfinished"):
        freeze_synthetic(repo, run, config, "review-01", "A", SyntheticCapture())
    done = capture()
    with pytest.raises(ValueError, match="already finished"):
        done.finish(b"replace")


def test_rehashed_packet_cannot_substitute_input(prepared):
    repo, config, run, _ = prepared
    name = "executors/review-02/A/input.txt"
    (run / name).write_bytes(b"hidden answer")
    path = run / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["artifacts"][name] = digest(b"hidden answer")
    raw = canonical(manifest)
    path.write_bytes(raw)
    path.with_suffix(".json.sha256").write_text(digest(raw))
    with pytest.raises(ValueError, match="Derived packet"):
        verify(repo, run, config)


def test_not_run_reason_is_terminal_and_never_zero(prepared):
    from devhub.benchmark import mark_not_run

    repo, config, run, _ = prepared
    final = mark_not_run(repo, run, config, "tests-01", "A", "Executor not implemented in 3G-A")
    assert final.status == "not_run"
    assert final.duration_ns is None
    assert final.metrics.provider_sends is None
    assert verify(repo, run, config)
    with pytest.raises(FileExistsError):
        freeze_synthetic(repo, run, config, "tests-01", "A", capture())
    assert not (run / "records/tests-01/A/output.txt").exists()


@pytest.mark.windows_smoke
def test_utf8_packets_and_exclusive_files_with_spaced_path(prepared):
    repo, config, run, _ = prepared
    config = BenchmarkConfig(
        **{
            **config.model_dump(),
            "shared_instructions": "РЈРєСЂР°С—РЅСЃСЊРєРёР№ С‚РµРєСЃС‚ вЂ” рџ§Є",
        }
    )
    target = run.parent / "РїР°РєРµС‚Рё Р· РїСЂРѕР±С–Р»Р°РјРё"
    prepare(repo, config, target, "unicode")
    assert verify(repo, target, config)
    assert (target / "executors/direct-01/A/instructions.txt").read_text(encoding="utf-8") == (
        "РЈРєСЂР°С—РЅСЃСЊРєРёР№ С‚РµРєСЃС‚ вЂ” рџ§Є"
    )
    with pytest.raises(FileExistsError):
        prepare(repo, config, target, "unicode")


def test_preparation_deterministic_and_schema_valid(prepared):
    from jsonschema import Draft202012Validator

    repo, config, run, _ = prepared
    second = run.parent / "second"
    prepare(repo, config, second, "offline-1")
    assert (run / "manifest.json").read_bytes() == (second / "manifest.json").read_bytes()
    Draft202012Validator.check_schema(Record.model_json_schema())
    record = json.loads((run / "records/review-01/A/prepared.json").read_bytes())
    Draft202012Validator(Record.model_json_schema()).validate(record)


def test_cross_fixture_final_binding_rejected(prepared):
    repo, config, run, _ = prepared
    freeze_synthetic(repo, run, config, "review-01", "A", capture())
    path = run / "records/review-01/A/final.json"
    result = json.loads(path.read_bytes())
    result["fixture_id"] = "review-02"
    raw = canonical(result)
    path.write_bytes(raw)
    path.with_suffix(".json.sha256").write_text(digest(raw))
    with pytest.raises(ValueError, match="Result binding"):
        verify(repo, run, config)


def test_symlink_artifacts_rejected(prepared):
    repo, config, run, _ = prepared
    target = run / "executors/review-01/A/input.txt"
    link = run / "executors/review-01/A/alias.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Host does not allow unprivileged symlinks")
    with pytest.raises(ValueError, match="Symlink"):
        verify(repo, run, config)
