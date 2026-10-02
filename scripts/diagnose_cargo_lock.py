"""Diagnostic-only pinned Cargo resolution. Never accepts a derived lock or runs a model."""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request
from pathlib import Path

from build_full_router_proof import ARCHIVE, COMMIT

LOCK = "7bb060a9b67a22503f9d15030c22122fea38623be9077d44cbadb919896a4146"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def structural_diff(old_raw, new_raw):
    old, new = (tomllib.loads(raw.decode()) for raw in (old_raw, new_raw))

    def packages(lock):
        result = {}
        for package in lock.get("package", []):
            item = dict(package)
            item["dependencies"] = sorted(item.get("dependencies", []))
            key = (item["name"], item["version"], item.get("source"))
            if key in result:
                raise ValueError("duplicate package identity")
            result[key] = item
        return result

    before, after = packages(old), packages(new)
    removed = [before[k] for k in before.keys() - after.keys()]
    added = [after[k] for k in after.keys() - before.keys()]
    changes = []
    for key in sorted(before.keys() & after.keys(), key=str):
        if before[key] != after[key]:
            changes.append((before[key], after[key]))
    # Pair only unambiguous replacements; retain ambiguous multiversion changes as added/removed.
    for name in sorted({p["name"] for p in removed} & {p["name"] for p in added}):
        left = [p for p in removed if p["name"] == name]
        right = [p for p in added if p["name"] == name]
        if len(left) == len(right) == 1:
            changes.append((left[0], right[0]))
            removed.remove(left[0])
            added.remove(right[0])
    records = []
    for left, right in changes:
        fields = sorted(k for k in left.keys() | right.keys() if left.get(k) != right.get(k))
        records.append(
            {
                "package": left["name"],
                "old": left,
                "new": right,
                "changed_fields": fields,
                "reason": None,
                "requiring_manifest": None,
            }
        )
    return {
        "original_sha256": sha(old_raw),
        "candidate_sha256": sha(new_raw),
        "lock_version": {"old": old.get("version"), "new": new.get("version")},
        "lock_version_changed": old.get("version") != new.get("version"),
        "packages_added": sorted(added, key=lambda p: (p["name"], p["version"])),
        "packages_removed": sorted(removed, key=lambda p: (p["name"], p["version"])),
        "packages_changed": sorted(records, key=lambda p: (p["package"], p["old"]["version"])),
        "versions_changed": [r for r in records if "version" in r["changed_fields"]],
        "sources_changed": [r for r in records if "source" in r["changed_fields"]],
        "git_revisions_changed": [
            r
            for r in records
            if "source" in r["changed_fields"]
            and any(str(p.get("source", "")).startswith("git+") for p in (r["old"], r["new"]))
        ],
        "checksums_changed": [r for r in records if "checksum" in r["changed_fields"]],
        "dependency_edges_changed": [r for r in records if "dependencies" in r["changed_fields"]],
        "top_level_other": {
            "old": {k: v for k, v in old.items() if k not in ("version", "package")},
            "new": {k: v for k, v in new.items() if k not in ("version", "package")},
        },
        "ordering_or_text_only": old_raw != new_raw
        and before == after
        and {k: v for k, v in old.items() if k != "package"}
        == {k: v for k, v in new.items() if k != "package"},
    }


def inventory(root):
    return {
        str(p.relative_to(root)): sha(p.read_bytes())
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def run(label, command, root, output, env, timeout=900):
    try:
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=timeout)
        stdout, stderr, code, timed_out = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, code, timed_out = exc.stdout or b"", exc.stderr or b"", None, True
    (output / f"{label}.stdout").write_bytes(stdout)
    (output / f"{label}.stderr").write_bytes(stderr)
    record = {
        "command": command,
        "exit_code": code,
        "timed_out": timed_out,
        "stdout_sha256": sha(stdout),
        "stderr_sha256": sha(stderr),
    }
    write_json(output / f"{label}.json", record)
    print(json.dumps({"step": label, **record}), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.workspace.mkdir(parents=True, exist_ok=False)
    args.output.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[1]
    raw = urllib.request.urlopen(
        f"https://codeload.github.com/openai/codex/tar.gz/{COMMIT}", timeout=60
    ).read()
    assert sha(raw) == ARCHIVE
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(args.workspace / "original", filter="data")
    tree = args.workspace / "original" / f"codex-{COMMIT}"
    root = tree / "codex-rs"
    original = (root / "Cargo.lock").read_bytes()
    assert sha(original) == LOCK
    (args.output / "Cargo.lock.original").write_bytes(original)
    (args.output / "cargo-lock-original.sha256").write_text(LOCK + "\n")
    before = inventory(tree)
    write_json(args.output / "source-inventory.json", before)
    # Preserve exact upstream build configuration/manifests for attribution, not just snippets.
    with tarfile.open(args.output / "upstream-build-context.tar.gz", "w:gz") as archive:
        for name in before:
            p = Path(name)
            if (
                p.name
                in (
                    "Cargo.toml",
                    "rust-toolchain.toml",
                    "rust-toolchain",
                    "justfile",
                    "MODULE.bazel",
                    "BUILD.bazel",
                )
                or ".cargo" in p.parts
                or name.startswith(".github/workflows/")
            ):
                archive.add(tree / name, arcname=name)
    env = dict(
        os.environ,
        CARGO_BUILD_JOBS="2",
        CARGO_INCREMENTAL="0",
        CARGO_PROFILE_DEV_DEBUG="0",
        CARGO_PROFILE_TEST_DEBUG="0",
        CARGO_TARGET_DIR=str(args.workspace / "target"),
    )
    commands = {}
    for name, command in (
        ("cargo-version", ["cargo", "--version", "--verbose"]),
        ("rustc-version", ["rustc", "--version", "--verbose"]),
        ("base-metadata", ["cargo", "metadata", "--locked", "--format-version=1"]),
        ("base-build", ["cargo", "test", "--locked", "-p", "codex-core", "--lib", "--no-run"]),
    ):
        commands[name] = run(name, command, root, args.output, env)
    assert inventory(tree) == before, "Original source changed during locked diagnosis"
    injected = args.workspace / "injected"
    shutil.copytree(tree, injected)
    test_target = injected / "codex-rs/core/src/tools/spec_plan_tests.rs"
    test_target.write_bytes(
        test_target.read_bytes() + b"\n" + (repo / "scripts/full_router_test.rs").read_bytes()
    )
    test_target.with_name("devhub_metadata.json").write_bytes(
        (repo / "docs/evidence/stage3g-full-router/metadata.json").read_bytes()
    )
    injected_before = inventory(injected)
    injection_changes = [
        n
        for n in sorted(before.keys() | injected_before.keys())
        if before.get(n) != injected_before.get(n)
    ]
    assert injection_changes == [
        "codex-rs/core/src/tools/devhub_metadata.json",
        "codex-rs/core/src/tools/spec_plan_tests.rs",
    ]
    commands["injected-build"] = run(
        "injected-build",
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "codex-core",
            "--lib",
            "devhub_review_full_router",
            "--no-run",
        ],
        injected / "codex-rs",
        args.output,
        env,
    )
    assert inventory(injected) == injected_before
    candidate = args.workspace / "candidate"
    shutil.copytree(tree, candidate)
    commands["candidate-offline"] = run(
        "candidate-offline",
        ["cargo", "generate-lockfile", "--offline"],
        candidate / "codex-rs",
        args.output,
        env,
    )
    if commands["candidate-offline"]["exit_code"] != 0:
        error = (args.output / "candidate-offline.stderr").read_text()
        if not any(s in error for s in ("offline", "no matching package", "failed to download")):
            raise RuntimeError("Offline failure is not a cache-missing diagnosis; stop")
        commands["candidate-network"] = run(
            "candidate-network",
            ["cargo", "generate-lockfile"],
            candidate / "codex-rs",
            args.output,
            env,
        )
    generated = (candidate / "codex-rs/Cargo.lock").read_bytes()
    (args.output / "Cargo.lock.candidate").write_bytes(generated)
    (args.output / "cargo-lock-candidate.sha256").write_text(sha(generated) + "\n")
    write_json(
        args.output / "cargo-lock-structural-diff.json", structural_diff(original, generated)
    )
    # A second diagnostic preserves existing selections to distinguish broad regeneration
    # upgrades from the smallest Cargo-requested repair. Neither is an accepted build lock.
    minimal = args.workspace / "minimal-candidate"
    shutil.copytree(tree, minimal)
    commands["minimal-metadata"] = run(
        "minimal-metadata",
        ["cargo", "metadata", "--format-version=1"],
        minimal / "codex-rs",
        args.output,
        env,
    )
    minimal_raw = (minimal / "codex-rs/Cargo.lock").read_bytes()
    (args.output / "Cargo.lock.minimal-candidate").write_bytes(minimal_raw)
    write_json(args.output / "minimal-structural-diff.json", structural_diff(original, minimal_raw))
    assert inventory(tree) == before
    write_json(
        args.output / "cargo-lock-diagnosis.json",
        {
            "source_commit": COMMIT,
            "archive_sha256": ARCHIVE,
            "original_lock_sha256": LOCK,
            "candidate_lock_sha256": sha(generated),
            "minimal_candidate_lock_sha256": sha(minimal_raw),
            "original_source_unchanged": True,
            "injection_changes": injection_changes,
            "commands": commands,
            "root_cause": "UNKNOWN",
            "accepted_derived_lock": False,
            "real_codex_executions": 0,
            "provider_sends": 0,
        },
    )


if __name__ == "__main__":
    main()
