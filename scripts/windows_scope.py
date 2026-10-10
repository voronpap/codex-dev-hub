"""Conservative full-Windows trigger; stage/release reviewers can always dispatch."""

import fnmatch
import os
import subprocess

patterns = (
    "src/devhub/*server.py",
    "src/devhub/brain*.py",
    "src/devhub/ledger.py",
    "src/devhub/groq.py",
    "src/devhub/gemini.py",
    "src/devhub/local.py",
    "src/devhub/cloud.py",
    "src/devhub/ollama.py",
    "src/devhub/cli.py",
    "src/devhub/config.py",
    "tests/test_windows.py",
    "pyproject.toml",
    "uv.lock",
    "scripts/*windows*.py",
    ".github/workflows/windows-native-qualification.yml",
    "docs/NATIVE_BUNDLES.md",
)
base = os.environ.get("BASE_SHA")
changed = (
    subprocess.check_output(["git", "diff", "--name-only", base, "HEAD"]).decode().splitlines()
    if base
    else []
)
full = (
    os.environ.get("EVENT") == "workflow_dispatch"
    or os.environ.get("REF", "").startswith("refs/tags/")
    or os.environ.get("FULL_LABEL") == "true"
    or any(fnmatch.fnmatch(path, pattern) for path in changed for pattern in patterns)
)
with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
    output.write(f"windows_full={str(full).lower()}\n")
print("Full Windows required:", full)
