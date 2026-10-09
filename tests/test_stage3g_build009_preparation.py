import hashlib
import importlib.util
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "build_stage3g_build009", SCRIPTS / "build_stage3g_build009.py"
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
sys.path.pop(0)

CANDIDATE_PATCH = b"""\
diff --git a/codex-rs/candidate.txt b/codex-rs/candidate.txt
new file mode 100644
--- /dev/null
+++ b/codex-rs/candidate.txt
@@ -0,0 +1 @@
+candidate
"""

HOST_PATCH = b"""\
diff --git a/host.txt b/host.txt
new file mode 100644
--- /dev/null
+++ b/host.txt
@@ -0,0 +1 @@
+host
"""


def test_runner_preparation_uses_distinct_reviewed_patch_roots(tmp_path, monkeypatch) -> None:
    checkout = tmp_path / "codex-pinned"
    root = checkout / "codex-rs"
    root.mkdir(parents=True)
    original = b"pinned lock\n"
    derived = b"derived proof lock\n"
    (root / "Cargo.lock").write_bytes(original)
    evidence = tmp_path / "evidence"
    evidence.mkdir()

    monkeypatch.setattr(RUNNER, "ORIGINAL", hashlib.sha256(original).hexdigest())
    monkeypatch.setattr(RUNNER, "DERIVED", hashlib.sha256(derived).hexdigest())
    monkeypatch.setattr(RUNNER, "derive", lambda candidate_root: (derived, []))

    result = RUNNER.prepare_build_source(
        root,
        candidate_patch=CANDIDATE_PATCH,
        host_patch=HOST_PATCH,
        evidence_directory=evidence,
    )

    assert (root / "candidate.txt").read_text(encoding="utf-8") == "candidate\n"
    assert (root / "host.txt").read_text(encoding="utf-8") == "host\n"
    assert (root / "Cargo.lock").read_bytes() == derived
    assert (evidence / "Cargo.lock.original").read_bytes() == original
    assert (evidence / "Cargo.lock.proof").read_bytes() == derived
    assert result == {
        "original_cargo_lock_sha256": hashlib.sha256(original).hexdigest(),
        "proof_cargo_lock_sha256": hashlib.sha256(derived).hexdigest(),
        "candidate_patch_cwd": "pinned_source_parent",
        "host_patch_cwd": "codex-rs",
        "candidate_patch_applied": True,
        "host_patch_applied": True,
    }
