"""Bind diagnostic CI artifacts to exact manifests; publish no generated lock file."""

import argparse
import hashlib
import json
from pathlib import Path

from derive_router_build_lock import DERIVED, ORIGINAL, derive
from diagnose_cargo_lock import write_json


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compact_diff(data, bindings):
    changes = []
    for item in data["packages_changed"]:
        bound = bindings.get(item["package"])
        change = {
            "package": item["package"],
            "old_identity": {k: item["old"].get(k) for k in ("name", "version", "source")},
            "fields": {
                k: {"old": item["old"].get(k), "new": item["new"].get(k)}
                for k in item["changed_fields"]
            },
            "reason": None,
            "requiring_manifest": None,
        }
        if bound and item["changed_fields"] == ["version"] and item["old"].get("source") is None:
            change.update(reason=bound["reason"], requiring_manifest=bound["manifest"])
        changes.append(change)
    return {
        "original_sha256": data["original_sha256"],
        "candidate_sha256": data["candidate_sha256"],
        "lock_version": data["lock_version"],
        "lock_version_changed": data["lock_version_changed"],
        "packages_added": [
            {"package": p, "reason": None, "requiring_manifest": None}
            for p in data["packages_added"]
        ],
        "packages_removed": [
            {"package": p, "reason": None, "requiring_manifest": None}
            for p in data["packages_removed"]
        ],
        "packages_changed": changes,
        "change_counts": {
            key: len(data[key])
            for key in (
                "versions_changed",
                "git_revisions_changed",
                "sources_changed",
                "checksums_changed",
                "dependency_edges_changed",
            )
        },
        "top_level_other": data["top_level_other"],
        "ordering_or_text_only": data["ordering_or_text_only"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    artifacts = args.artifacts
    receipt = json.loads((artifacts / "cargo-lock-diagnosis.json").read_bytes())
    original = (artifacts / "Cargo.lock.original").read_bytes()
    assert hashlib.sha256(original).hexdigest() == ORIGINAL
    derived, changes = derive(args.source / "codex-rs")
    assert derived == (artifacts / "Cargo.lock.minimal-candidate").read_bytes()
    inventory = json.loads((artifacts / "source-inventory.json").read_bytes())
    bindings = {c["package"]: c for c in changes}
    minimal = json.loads((artifacts / "minimal-structural-diff.json").read_bytes())
    assert not minimal["packages_added"] and not minimal["packages_removed"]
    assert len(minimal["packages_changed"]) == 152
    assert all(
        c["changed_fields"] == ["version"] and c["old"].get("source") is None
        for c in minimal["packages_changed"]
    )
    assert receipt["original_source_unchanged"] is True
    for label in ("base-metadata", "base-build", "injected-build"):
        cmd = receipt["commands"][label]
        assert cmd["exit_code"] == 101 and cmd["timed_out"] is False
        assert digest(artifacts / f"{label}.stderr") == cmd["stderr_sha256"]
        assert "cannot update the lock file" in (artifacts / f"{label}.stderr").read_text()
    context_names = [
        "codex-rs/Cargo.toml",
        "codex-rs/rust-toolchain.toml",
        "codex-rs/.cargo/config.toml",
        "justfile",
        ".github/workflows/rust-ci.yml",
        ".github/workflows/rust-ci-full-nextest-platform.yml",
    ]
    context_names += ["codex-rs/" + c["manifest"] for c in changes]
    context_hashes = {}
    for name in sorted(set(context_names)):
        actual = digest(args.source / name)
        assert actual == inventory[name]
        context_hashes[name] = actual
    write_json(args.output / "manifest-bindings.json", changes)
    write_json(args.output / "upstream-context-hashes.json", context_hashes)
    write_json(
        args.output / "cargo-lock-structural-diff.json",
        {
            "regenerated_candidate_rejected": compact_diff(
                json.loads((artifacts / "cargo-lock-structural-diff.json").read_bytes()), bindings
            ),
            "minimal_derived_proof_lock": compact_diff(minimal, bindings),
        },
    )
    for name in ("cargo-lock-original.sha256", "cargo-lock-candidate.sha256"):
        (args.output / name).write_bytes((artifacts / name).read_bytes())
    (args.output / "cargo-lock-derived.sha256").write_text(DERIVED + "\n", encoding="utf-8")
    receipt.update(
        {
            "root_cause": "STALE_UPSTREAM_LOCK",
            "safe_build_path": "LOCK_B",
            "cause": "152 local lock versions are 0.0.0; their pinned manifests require inherited "
            "workspace.package.version 0.155.0-alpha.9.2",
            "injection_is_cause": False,
            "derived_lock_scope": "Disposable test build only; production source/binary unchanged",
            "accepted_derived_lock": True,
            "accepted_derived_lock_sha256": DERIVED,
            "regenerated_candidate_accepted": False,
            "regenerated_candidate_rejection": "Unnecessary external upgrades; not used for build",
            "derivation": "Manifest-bound local version substitution; byte-identical to minimal "
            "Cargo metadata resolution; no external version/source/checksum/edge changes",
            "cargo_version": (artifacts / "cargo-version.stdout").read_text(),
            "rustc_version": (artifacts / "rustc-version.stdout").read_text(),
            "diagnostic_run_url": "https://github.com/voronpap/codex-dev-hub/actions/runs/36967187526",
            "raw_artifact_name": "pinned-cargo-lock-diagnosis",
            "raw_artifact_hashes": {
                p.name: digest(p) for p in sorted(artifacts.iterdir()) if p.is_file()
            },
            "upstream_context": {
                "resolver": "2",
                "default_members": "not specified",
                "target": "native x86_64-unknown-linux-gnu",
                "cargo_target_config": "Only Windows MSVC/GNU rustflags; no Linux overrides",
                "test_recipe": "justfile invokes cargo nextest; CI builds nextest archives using "
                "profile/target/test-threads controls; Bazel also supported",
                "difference": "Our filtered codex-core lib build is narrower; "
                "the unchanged base invocation reproduces the same stale-lock failure",
            },
            "execution_ready": False,
            "router_classification": "UNKNOWN",
        }
    )
    write_json(args.output / "cargo-lock-diagnosis.json", receipt)


if __name__ == "__main__":
    main()
