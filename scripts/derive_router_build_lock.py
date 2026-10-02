"""Derive proof-only lock: update only local package versions required by pinned manifests."""

import hashlib
import re
import tomllib

ORIGINAL = "7bb060a9b67a22503f9d15030c22122fea38623be9077d44cbadb919896a4146"
DERIVED = "a5369b7f5d713d21c9f2481afdc27b7577e45d4b713fc84a4ab03c2833c4d48d"


def derive(root):
    raw = (root / "Cargo.lock").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ORIGINAL
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    version = workspace["workspace"]["package"]["version"]
    assert version == "0.155.0-alpha.9.2"
    manifests = {}
    for path in sorted(root.rglob("Cargo.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        if "package" not in data:
            continue
        package = data["package"]
        resolved = package.get("version")
        if resolved == {"workspace": True}:
            resolved = version
        name = package["name"]
        assert name not in manifests, f"Ambiguous manifest: {name}"
        manifests[name] = (resolved, path)
    pieces = raw.split(b"[[package]]")
    changes = []
    for i, piece in enumerate(pieces[1:], 1):
        package = tomllib.loads((b"[[package]]" + piece).decode())["package"][0]
        if "source" in package:
            continue
        name = package["name"]
        expected, manifest = manifests[name]
        assert package["version"] == "0.0.0" and expected == version
        replacement = f'\nversion = "{expected}"\n'.encode()
        pieces[i], count = re.subn(rb'\nversion = "0\.0\.0"\n', replacement, piece)
        assert count == 1
        changes.append(
            {
                "package": name,
                "old": "0.0.0",
                "new": expected,
                "reason": "Pinned local manifest inherits workspace.package.version",
                "manifest": str(manifest.relative_to(root)).replace("\\", "/"),
                "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                "workspace_manifest": "Cargo.toml",
                "workspace_manifest_sha256": hashlib.sha256(
                    (root / "Cargo.toml").read_bytes()
                ).hexdigest(),
            }
        )
    derived = b"[[package]]".join(pieces)
    assert len(changes) == 152
    assert hashlib.sha256(derived).hexdigest() == DERIVED
    return derived, changes
