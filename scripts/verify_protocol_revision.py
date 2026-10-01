"""Canonical offline proof of the narrowly authorized v1 -> v2 revision."""

import argparse
import json
from pathlib import Path

from devhub.baseline import verified_cases
from devhub.benchmark import canonical, clean_commit, write_new
from devhub.experiment import ExperimentProtocol


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    commit = clean_commit(repo)
    old = ExperimentProtocol.model_validate_json(
        (repo / "benchmarks/real-protocol.json").read_bytes()
    )
    new = ExperimentProtocol.model_validate_json(
        (repo / "benchmarks/real-protocol-v2.json").read_bytes()
    )
    if old.model_dump(exclude={"protocol_id"}) != new.model_dump(exclude={"protocol_id"}):
        raise ValueError("Unapproved semantic change: STOP for review")
    if (old.protocol_id, new.protocol_id) != ("stage3g-seed1-paired-v1", "stage3g-seed1-paired-v2"):
        raise ValueError("Unexpected revision")
    removed = old.codex_overrides()[-2:]
    if (
        removed
        != (
            "model_providers.openai.request_max_retries=0",
            "model_providers.openai.stream_max_retries=0",
        )
        or new.codex_overrides() != old.codex_overrides()[:-2]
    ):
        raise ValueError("Unapproved override change: STOP for review")
    historical = json.loads((repo / "docs/evidence/stage3g-c/local-plan.json").read_bytes())
    if old.hashes() != historical["hashes"]:
        raise ValueError("Historical v1 hashes changed")
    unchanged = ["routing_policy", "context_policy", "output_policy", "instructions"]
    if any(old.hashes()[key] != new.hashes()[key] for key in unchanged):
        raise ValueError("Unapproved policy change")
    evidence = {
        "kind": "canonical_protocol_revision_check",
        "implementation_commit": commit,
        "protocol_ids": [old.protocol_id, new.protocol_id],
        "changed_protocol_fields": ["protocol_id"],
        "removed_overrides": list(removed),
        "added_overrides": [],
        "v1_hashes": old.hashes(),
        "v2_hashes": new.hashes(),
        "unchanged_policy_hashes": unchanged,
        "verified_cases": verified_cases(repo / "benchmarks"),
        "codex_internal_retries": None,
        "execution_ready": False,
        "real_codex_executions": 0,
        "provider_sends": 0,
    }
    write_new(args.output, canonical(evidence))
    print(
        json.dumps(
            {
                "protocol": new.hashes()["protocol"],
                "config": new.hashes()["codex_config"],
                "verified_fixtures": 12,
                "verified_oracles": 12,
            }
        )
    )


if __name__ == "__main__":
    main()
