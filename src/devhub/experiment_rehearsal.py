"""Strict one-pair Stage 3G rehearsal contract; never reads benchmark oracles."""

import base64
import binascii
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field, JsonValue, model_validator

from devhub.baseline import verified_fixture_payloads
from devhub.benchmark import Digest, canonical, clean_commit, digest, read_sealed
from devhub.experiment import (
    ARM_A,
    ARM_B,
    COMMON,
    ExperimentProtocol,
    verify_loaded_experiment_sources,
)
from devhub.experiment_launch import TASK_PAYLOAD_BYTE_LIMIT, codex_argv
from devhub.models import Contract, Identifier
from devhub.qualification import VerifiedQualificationV2


class RehearsalSessionV1(Contract):
    order: Literal[1, 2]
    arm: Literal["A", "B"]
    session_id: Identifier


def rehearsal_session_id(
    run_id: str,
    task_id: str,
    protocol_sha256: str,
    input_sha256: str,
    task_sha256: str,
    arm: Literal["A", "B"],
) -> str:
    value = (
        f"devhub:rehearsal:{run_id}:{task_id}:{protocol_sha256}:{input_sha256}:{task_sha256}:{arm}"
    )
    return "r-" + uuid5(NAMESPACE_URL, value).hex


class Stage3GRehearsalPlanPayloadV1(Contract):
    kind: Literal["stage3g_rehearsal_plan"] = "stage3g_rehearsal_plan"
    qualification_manifest_id: Digest
    qualification_context_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    protocol_sha256: Digest
    qualified_frozen_plan_sha256: Digest
    run_id: Identifier
    task_id: Identifier
    input_base64: str = Field(min_length=4, max_length=1_398_104)
    input_sha256: Digest
    task_base64: str = Field(min_length=4, max_length=1_398_104)
    task_sha256: Digest
    sessions: tuple[RehearsalSessionV1, RehearsalSessionV1]
    benchmark_fixture: Literal[False] = False
    oracle_present: Literal[False] = False
    retries: Literal[0] = 0
    resume_allowed: Literal[False] = False

    @model_validator(mode="after")
    def exact_pair_and_bytes(self) -> "Stage3GRehearsalPlanPayloadV1":
        try:
            input_bytes = base64.b64decode(self.input_base64, validate=True)
            task_bytes = base64.b64decode(self.task_base64, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("Rehearsal task bytes must be canonical base64") from error
        if (
            not input_bytes
            or not task_bytes
            or len(input_bytes) + len(task_bytes) > TASK_PAYLOAD_BYTE_LIMIT
        ):
            raise ValueError("Rehearsal task payload is empty or exceeds the reviewed bound")
        try:
            input_bytes.decode("utf-8")
            task_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Rehearsal task payload must be UTF-8") from error
        if (
            base64.b64encode(input_bytes).decode() != self.input_base64
            or digest(input_bytes) != self.input_sha256
        ):
            raise ValueError("Rehearsal input bytes/hash mismatch")
        if (
            base64.b64encode(task_bytes).decode() != self.task_base64
            or digest(task_bytes) != self.task_sha256
        ):
            raise ValueError("Rehearsal task bytes/hash mismatch")
        expected = (
            RehearsalSessionV1(
                order=1,
                arm="A",
                session_id=rehearsal_session_id(
                    self.run_id,
                    self.task_id,
                    self.protocol_sha256,
                    self.input_sha256,
                    self.task_sha256,
                    "A",
                ),
            ),
            RehearsalSessionV1(
                order=2,
                arm="B",
                session_id=rehearsal_session_id(
                    self.run_id,
                    self.task_id,
                    self.protocol_sha256,
                    self.input_sha256,
                    self.task_sha256,
                    "B",
                ),
            ),
        )
        if self.sessions != expected or self.sessions[0].session_id == self.sessions[1].session_id:
            raise ValueError("Rehearsal must be the exact distinct A then B pair")
        return self

    def input_bytes(self) -> bytes:
        return base64.b64decode(self.input_base64, validate=True)

    def task_bytes(self) -> bytes:
        return base64.b64decode(self.task_base64, validate=True)


class Stage3GRehearsalPlanV1(Contract):
    rehearsal_plan_id: Digest
    payload: Stage3GRehearsalPlanPayloadV1

    @classmethod
    def create(cls, payload: Stage3GRehearsalPlanPayloadV1) -> "Stage3GRehearsalPlanV1":
        return cls(
            rehearsal_plan_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def canonical_id(self) -> "Stage3GRehearsalPlanV1":
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.rehearsal_plan_id != expected:
            raise ValueError("Rehearsal plan ID mismatch")
        return self


class Stage3GRehearsalPairResultV1(Contract):
    kind: Literal["stage3g_rehearsal_pair_result"] = "stage3g_rehearsal_pair_result"
    rehearsal_plan_id: Digest
    qualification_manifest_id: Digest
    qualification_context_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    arm_a_result_sha256: Digest
    arm_b_result_sha256: Digest
    arm_a_output_sha256: Digest
    arm_b_output_sha256: Digest
    arm_b_delegation_success: Literal[True]
    completed_sessions: Literal[2] = 2
    real_codex_task_executions: Literal[2] = 2
    delegate_calls: Literal[1] = 1
    devhub_provider_sends: Literal[1] = 1
    executor_retries: Literal[0] = 0
    benchmark_reruns: Literal[0] = 0
    semantic_acceptance: None = None
    quality_benchmark: None = None
    delegation_value: None = None
    savings: None = None


def load_rehearsal_plan(path: Path) -> Stage3GRehearsalPlanV1:
    raw = read_sealed(path)
    rehearsal = Stage3GRehearsalPlanV1.model_validate_json(raw)
    if raw != canonical(rehearsal.model_dump(mode="json")):
        raise ValueError("Rehearsal plan is not canonical")
    return rehearsal


def reject_frozen_fixture_collision(repo: Path, input_bytes: bytes, task_bytes: bytes) -> None:
    """Reject reuse of either frozen task component without opening any oracle."""

    frozen_components: set[bytes] = set()
    for case, fixture in verified_fixture_payloads(repo / "benchmarks"):
        frozen_input = fixture.get("input")
        frozen_task = fixture.get("prompt")
        if not isinstance(frozen_input, str) or not isinstance(frozen_task, str):
            raise ValueError(f"Frozen fixture shape changed: {case['id']}")
        frozen_components.update((frozen_input.encode(), frozen_task.encode()))
    if input_bytes in frozen_components or task_bytes in frozen_components:
        raise ValueError("Rehearsal task collides with a frozen benchmark fixture")


def build_rehearsal_plan(
    repo: Path,
    protocol: ExperimentProtocol,
    qualification: VerifiedQualificationV2,
    *,
    run_id: str,
    task_id: str,
    input_bytes: bytes,
    task_bytes: bytes,
) -> Stage3GRehearsalPlanV1:
    expected = qualification.context.payload
    commit = clean_commit(repo)
    verify_loaded_experiment_sources(repo, commit)
    if commit != expected.implementation.devhub_commit:
        raise ValueError("Rehearsal implementation differs from qualification")
    if protocol.hashes()["protocol"] != expected.benchmark.protocol_sha256:
        raise ValueError("Rehearsal protocol differs from qualification")
    reject_frozen_fixture_collision(repo, input_bytes, task_bytes)
    input_sha256, task_sha256 = digest(input_bytes), digest(task_bytes)
    sessions = (
        RehearsalSessionV1(
            order=1,
            arm="A",
            session_id=rehearsal_session_id(
                run_id,
                task_id,
                expected.benchmark.protocol_sha256,
                input_sha256,
                task_sha256,
                "A",
            ),
        ),
        RehearsalSessionV1(
            order=2,
            arm="B",
            session_id=rehearsal_session_id(
                run_id,
                task_id,
                expected.benchmark.protocol_sha256,
                input_sha256,
                task_sha256,
                "B",
            ),
        ),
    )
    return Stage3GRehearsalPlanV1.create(
        Stage3GRehearsalPlanPayloadV1(
            qualification_manifest_id=qualification.manifest.qualification_manifest_id,
            qualification_context_id=qualification.context.qualification_context_id,
            environment_instance_id=expected.environment_instance_id,
            implementation_commit=commit,
            protocol_sha256=expected.benchmark.protocol_sha256,
            qualified_frozen_plan_sha256=expected.benchmark.plan_sha256,
            run_id=run_id,
            task_id=task_id,
            input_base64=base64.b64encode(input_bytes).decode(),
            input_sha256=input_sha256,
            task_base64=base64.b64encode(task_bytes).decode(),
            task_sha256=task_sha256,
            sessions=sessions,
        )
    )


def rehearsal_packet_bytes(
    rehearsal: Stage3GRehearsalPlanV1,
    session: RehearsalSessionV1,
    protocol: ExperimentProtocol,
) -> dict[str, bytes]:
    if session not in rehearsal.payload.sessions:
        raise ValueError("Session is not part of the rehearsal plan")
    instructions = COMMON + "\n" + (ARM_A if session.arm == "A" else ARM_B)
    return {
        "input.txt": rehearsal.payload.input_bytes(),
        "task.txt": rehearsal.payload.task_bytes(),
        "instructions.txt": instructions.encode(),
        "session.json": canonical(
            {
                "project": session.session_id,
                "task_id": session.session_id,
                "request_key": session.session_id,
                "codex_argv": cast(JsonValue, codex_argv(session, protocol)),
            }
        ),
    }
