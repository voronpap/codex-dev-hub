"""Offline tracked-file secret patterns and immutable historical evidence gate."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

patterns = [
    rb"gsk_[A-Za-z0-9]{30,}",
    rb"AIza[0-9A-Za-z_-]{30,}",
    rb"AQ\.[A-Za-z0-9_-]{30,}",
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
]
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
)
for name in paths.decode().split("\0"):
    if not name or not Path(name).is_file():
        continue
    raw = Path(name).read_bytes()
    if any(re.search(pattern, raw) for pattern in patterns):
        raise SystemExit("credential pattern found in " + name)
    if name.startswith("docs/evidence/") and name.endswith(".json"):
        json.loads(raw.decode("utf-8-sig"))
original = Path("docs/evidence/stage3e-gemini-preflight.json").read_text(encoding="utf-8")
assert hashlib.sha256(original.encode()).hexdigest() == (
    "359995f37a3428482ab8b401c37b0ea3c7151b2c3d2a9cc89d14e4489e7bc06f"
)
print("Secret patterns, evidence JSON and historical probe integrity: PASS")
