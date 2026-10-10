"""Offline rehearsal-control tests; no Codex, provider, Docker, or oracle execution."""

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from devhub.benchmark import canonical, digest, write_sealed
from devhub.experiment import ExperimentProtocol, RuntimeBindings, plan
from devhub.experiment_rehearsal import (
    RehearsalSessionV1,
    Stage3GRehearsalPlanPayloadV1,
    Stage3GRehearsalPlanV1,
    build_rehearsal_plan,
    load_rehearsal_plan,
    rehearsal_packet_bytes,
    reject_frozen_fixture_collision,
)
from devhub.experiment_run import execute_rehearsal_pair

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
MANIFEST_ID = "b" * 64
CONTEXT_ID = "c" * 64
ENVIRONMENT_ID = "d" * 32
FROZEN_PLAN_SHA = "e" * 64


@pytest.fixture
def protocol() -> ExperimentProtocol:
    return ExperimentProtocol.model_validate_json(
        (ROOT / "benchmarks/real-protocol-v2.json").read_bytes()
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    target = tmp_path / "source"
    shutil.copytree(ROOT / "src", target / "src")
    shutil.copytree(ROOT / "benchmarks", target / "benchmarks")
    for args in (
        ["init", "-q"],
        ["config", "core.autocrlf", "false"],
        ["add", "."],
        ["-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "frozen"],
    ):
        subprocess.run(["git", "-C", str(target), *args], check=True, capture_output=True)
    return target


def qualification(protocol: ExperimentProtocol) -> SimpleNamespace:
    expected = SimpleNamespace(
        environment_instance_id=ENVIRONMENT_ID,
        implementation=SimpleNamespace(devhub_commit=COMMIT),
        benchmark=SimpleNamespace(
            protocol_sha256=protocol.hashes()["protocol"], plan_sha256=FROZEN_PLAN_SHA
        ),
        runtime_expected=SimpleNamespace(
            image_id="sha256:" + "1" * 64,
            bootstrap_sha256="2" * 64,
        ),
        codex=SimpleNamespace(executable_version=protocol.codex_cli_version),
    )
    return SimpleNamespace(
        manifest=SimpleNamespace(qualification_manifest_id=MANIFEST_ID),
        context=SimpleNamespace(qualification_context_id=CONTEXT_ID, payload=expected),
    )


def rehearsal(protocol: ExperimentProtocol) -> Stage3GRehearsalPlanV1:
    input_bytes = b"A tiny module returns an uppercase greeting."
    task_bytes = b"Explain the module behavior in two concise sentences with a source citation."
    input_sha, task_sha = digest(input_bytes), digest(task_bytes)
    from devhub.experiment_rehearsal import rehearsal_session_id

    sessions = (
        RehearsalSessionV1(
            order=1,
            arm="A",
            session_id=rehearsal_session_id(
                "rehearsal-001",
                "rehearsal-task",
                protocol.hashes()["protocol"],
                input_sha,
                task_sha,
                "A",
            ),
        ),
        RehearsalSessionV1(
            order=2,
            arm="B",
            session_id=rehearsal_session_id(
                "rehearsal-001",
                "rehearsal-task",
                protocol.hashes()["protocol"],
                input_sha,
                task_sha,
                "B",
            ),
        ),
    )
    import base64

    return Stage3GRehearsalPlanV1.create(
        Stage3GRehearsalPlanPayloadV1(
            qualification_manifest_id=MANIFEST_ID,
            qualification_context_id=CONTEXT_ID,
            environment_instance_id=ENVIRONMENT_ID,
            implementation_commit=COMMIT,
            protocol_sha256=protocol.hashes()["protocol"],
            qualified_frozen_plan_sha256=FROZEN_PLAN_SHA,
            run_id="rehearsal-001",
            task_id="rehearsal-task",
            input_base64=base64.b64encode(input_bytes).decode(),
            input_sha256=input_sha,
            task_base64=base64.b64encode(task_bytes).decode(),
            task_sha256=task_sha,
            sessions=sessions,
        )
    )


def test_rehearsal_plan_is_strict_self_hashed_exact_a_then_b(protocol, monkeypatch):
    import devhub.experiment_rehearsal as module

    monkeypatch.setattr(module, "clean_commit", lambda repo: COMMIT)
    monkeypatch.setattr(module, "verify_loaded_experiment_sources", lambda repo, commit: None)
    item = build_rehearsal_plan(
        ROOT,
        protocol,
        qualification(protocol),
        run_id="rehearsal-001",
        task_id="rehearsal-task",
        input_bytes=b"A tiny module returns an uppercase greeting.",
        task_bytes=b"Explain the module behavior in two concise sentences with a source citation.",
    )
    assert item == rehearsal(protocol)
    assert [session.arm for session in item.payload.sessions] == ["A", "B"]
    assert len({session.session_id for session in item.payload.sessions}) == 2
    dumped = item.model_dump(mode="json")
    with pytest.raises(ValidationError, match="plan ID"):
        Stage3GRehearsalPlanV1.model_validate_json(
            json.dumps(dumped | {"rehearsal_plan_id": "0" * 64})
        )
    payload = dumped["payload"] | {"unexpected": True}
    with pytest.raises(ValidationError):
        Stage3GRehearsalPlanPayloadV1.model_validate_json(json.dumps(payload))
    changed_bytes = dumped["payload"] | {"input_base64": "ZGlmZmVyZW50"}
    with pytest.raises(ValidationError, match="bytes/hash"):
        Stage3GRehearsalPlanPayloadV1.model_validate_json(json.dumps(changed_bytes))
    reversed_sessions = dumped["payload"] | {
        "sessions": list(reversed(dumped["payload"]["sessions"]))
    }
    with pytest.raises(ValidationError, match="exact distinct A then B"):
        Stage3GRehearsalPlanPayloadV1.model_validate_json(json.dumps(reversed_sessions))


def test_rehearsal_rejects_frozen_input_or_task_without_reading_oracles(tmp_path):
    benchmark = tmp_path / "benchmarks"
    shutil.copytree(ROOT / "benchmarks/fixtures", benchmark / "fixtures")
    shutil.copy2(ROOT / "benchmarks/manifest.json", benchmark / "manifest.json")
    first = json.loads((benchmark / "fixtures/direct-01.json").read_bytes())
    with pytest.raises(ValueError, match="collides"):
        reject_frozen_fixture_collision(tmp_path, first["input"].encode(), b"safe distinct task")
    with pytest.raises(ValueError, match="collides"):
        reject_frozen_fixture_collision(tmp_path, b"safe distinct input", first["prompt"].encode())
    with pytest.raises(ValueError, match="collides"):
        reject_frozen_fixture_collision(tmp_path, first["prompt"].encode(), b"safe distinct task")
    with pytest.raises(ValueError, match="collides"):
        reject_frozen_fixture_collision(tmp_path, b"safe distinct input", first["input"].encode())
    reject_frozen_fixture_collision(tmp_path, b"safe distinct input", b"safe distinct task")
    assert not (benchmark / "oracles").exists()


def test_operator_plan_requires_sealed_canonical_artifact(protocol, tmp_path):
    item = rehearsal(protocol)
    target = tmp_path / "rehearsal-plan.json"
    raw = canonical(item.model_dump(mode="json"))
    write_sealed(target, raw)
    assert load_rehearsal_plan(target) == item
    target.write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="integrity"):
        load_rehearsal_plan(target)
    target.write_bytes(raw)
    target.with_suffix(".json.sha256").unlink()
    with pytest.raises(FileNotFoundError):
        load_rehearsal_plan(target)


def test_rehearsal_packets_share_task_and_never_contain_oracle(protocol):
    item = rehearsal(protocol)
    a = rehearsal_packet_bytes(item, item.payload.sessions[0], protocol)
    b = rehearsal_packet_bytes(item, item.payload.sessions[1], protocol)
    assert a["input.txt"] == b["input.txt"] == item.payload.input_bytes()
    assert a["task.txt"] == b["task.txt"] == item.payload.task_bytes()
    assert b"oracle" not in a["input.txt"] + a["task.txt"]
    assert b"oracle" not in b["input.txt"] + b["task.txt"]
    assert b"devhub_delegate" not in a["session.json"]
    assert b"devhub_delegate" in b["session.json"]


def test_rehearsal_uses_shared_launch_path_once_per_arm_and_never_resumes(
    protocol, tmp_path, monkeypatch
):
    import devhub.experiment_run as module

    item = rehearsal(protocol)
    verified = qualification(protocol)
    monkeypatch.setattr(module, "verify_manifest_tree", lambda path, identifier: verified)
    import devhub.experiment_rehearsal as rehearsal_module

    monkeypatch.setattr(rehearsal_module, "clean_commit", lambda repo: COMMIT)
    monkeypatch.setattr(
        rehearsal_module, "verify_loaded_experiment_sources", lambda repo, commit: None
    )

    class SuccessfulB:
        delegation_success = True

    monkeypatch.setattr(module, "BArmDelegationObservationV2", SuccessfulB)
    calls = []

    def shared(*args):
        runtime, session, packets, run_root = args[3], args[4], args[5], args[6]
        calls.append((runtime.reviewed_plan_sha256, session.arm, packets))
        target = run_root / "attempts" / session.session_id
        target.mkdir(parents=True)
        write_sealed(target / "result.json", canonical({"arm": session.arm}))
        return SimpleNamespace(
            provenance=SimpleNamespace(output_sha256=digest(session.arm.encode())),
            delegation=SuccessfulB() if session.arm == "B" else SimpleNamespace(),
        )

    monkeypatch.setattr(module, "_execute_reviewed_session", shared)
    run_root = tmp_path / "run"
    result = execute_rehearsal_pair(
        ROOT,
        protocol,
        item,
        RuntimeBindings(qualification_manifest_id=MANIFEST_ID),
        run_root,
        tmp_path / "auth.json",
        tmp_path / "manifest.json",
        tmp_path / "ledger",
        operator_reviewed=True,
    )
    assert [(plan_id, arm) for plan_id, arm, _ in calls] == [
        (item.rehearsal_plan_id, "A"),
        (item.rehearsal_plan_id, "B"),
    ]
    assert calls[0][2]["input.txt"] == calls[1][2]["input.txt"]
    assert result.arm_b_delegation_success is True
    assert (run_root / "pair-summary.json").is_file()
    for artifact in ("rehearsal-plan.json", "bindings.json", "pair-summary.json"):
        assert (run_root / artifact).with_suffix(Path(artifact).suffix + ".sha256").is_file()
    with pytest.raises(ValueError, match="resume"):
        execute_rehearsal_pair(
            ROOT,
            protocol,
            item,
            RuntimeBindings(qualification_manifest_id=MANIFEST_ID),
            run_root,
            tmp_path / "auth.json",
            tmp_path / "manifest.json",
            tmp_path / "ledger",
            operator_reviewed=True,
        )


def test_rehearsal_rejects_incomplete_b_authority(protocol, tmp_path, monkeypatch):
    import devhub.experiment_run as module

    item = rehearsal(protocol)
    monkeypatch.setattr(
        module, "verify_manifest_tree", lambda path, identifier: qualification(protocol)
    )
    import devhub.experiment_rehearsal as rehearsal_module

    monkeypatch.setattr(rehearsal_module, "clean_commit", lambda repo: COMMIT)
    monkeypatch.setattr(
        rehearsal_module, "verify_loaded_experiment_sources", lambda repo, commit: None
    )

    def shared(*args):
        session, run_root = args[4], args[6]
        target = run_root / "attempts" / session.session_id
        target.mkdir(parents=True)
        write_sealed(target / "result.json", canonical({"arm": session.arm}))
        expected = SimpleNamespace(
            provider="ollama", resource="resource", model="model", ollama_version="0.34.2"
        )
        from devhub.experiment_observation import (
            BArmDelegationObservationV2,
            ProviderResourceModelIdentityV1,
        )

        delegation = (
            BArmDelegationObservationV2(
                session_id=session.session_id,
                call_count=0,
                expected_provider_resource_model=ProviderResourceModelIdentityV1(
                    **expected.__dict__, model_digest="f" * 64
                ),
            )
            if session.arm == "B"
            else SimpleNamespace()
        )
        return SimpleNamespace(
            provenance=SimpleNamespace(output_sha256=digest(session.arm.encode())),
            delegation=delegation,
        )

    monkeypatch.setattr(module, "_execute_reviewed_session", shared)
    with pytest.raises(ValueError, match="authoritative delegation"):
        execute_rehearsal_pair(
            ROOT,
            protocol,
            item,
            RuntimeBindings(qualification_manifest_id=MANIFEST_ID),
            tmp_path / "run",
            tmp_path / "auth.json",
            tmp_path / "manifest.json",
            tmp_path / "ledger",
            operator_reviewed=True,
        )


def test_rehearsal_requires_review_and_exact_manifest_binding(protocol, tmp_path, monkeypatch):
    import devhub.experiment_rehearsal as rehearsal_module
    import devhub.experiment_run as module

    item = rehearsal(protocol)
    arguments = (
        ROOT,
        protocol,
        item,
        RuntimeBindings(qualification_manifest_id=MANIFEST_ID),
        tmp_path / "run",
        tmp_path / "auth.json",
        tmp_path / "manifest.json",
        tmp_path / "ledger",
    )
    with pytest.raises(ValueError, match="review"):
        execute_rehearsal_pair(*arguments)
    monkeypatch.setattr(
        module, "verify_manifest_tree", lambda path, identifier: qualification(protocol)
    )
    monkeypatch.setattr(rehearsal_module, "clean_commit", lambda repo: COMMIT)
    monkeypatch.setattr(
        rehearsal_module, "verify_loaded_experiment_sources", lambda repo, commit: None
    )
    wrong = Stage3GRehearsalPlanV1.create(
        item.payload.model_copy(update={"qualification_manifest_id": "0" * 64})
    )
    with pytest.raises(ValueError, match="qualification authority"):
        execute_rehearsal_pair(*arguments[:2], wrong, *arguments[3:], operator_reviewed=True)


def test_rehearsal_does_not_mutate_frozen_plan_or_protocol(protocol, repo, monkeypatch):
    before = canonical(plan(repo, protocol, "unchanged-plan"))
    hashes = protocol.hashes()
    import devhub.experiment_rehearsal as module

    monkeypatch.setattr(module, "clean_commit", lambda path: COMMIT)
    monkeypatch.setattr(module, "verify_loaded_experiment_sources", lambda repo, commit: None)
    build_rehearsal_plan(
        ROOT,
        protocol,
        qualification(protocol),
        run_id="rehearsal-002",
        task_id="rehearsal-task",
        input_bytes=b"A separate non-benchmark input.",
        task_bytes=b"Summarize only this input with one citation.",
    )
    assert canonical(plan(repo, protocol, "unchanged-plan")) == before
    assert protocol.hashes() == hashes
