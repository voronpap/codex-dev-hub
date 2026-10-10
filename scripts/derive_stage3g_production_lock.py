"""Derive the complete proof lock for the patched Stage 3G production host."""

import hashlib
import re
import tomllib
from pathlib import Path

from derive_router_build_lock import DERIVED as LOCAL_VERSION_LOCK_SHA256
from derive_router_build_lock import derive as derive_local_versions

PRODUCTION_HOST_LOCK_SHA256 = "9236f6c0b8703eaf337dd219c8fdfb6834c14fa430a0a83b938159016371bb88"
EXPECTED_WORKSPACE_SHA2_REQUIREMENT = "0.10"

_REQUIRED_DEPENDENCY_EDGES = {
    "codex-app-server-client": (("codex-extension-api", "codex-extension-api"),),
    "codex-exec": (
        ("codex-extension-api", "codex-extension-api"),
        ("codex-tools", "codex-tools"),
        ("sha2", "sha2 0.10.9"),
    ),
    "codex-tui": (("codex-extension-api", "codex-extension-api"),),
}


def _manifest_dependencies(root: Path, package: str) -> set[str]:
    manifests: dict[str, Path] = {}
    for path in root.rglob("Cargo.toml"):
        value = tomllib.loads(path.read_text(encoding="utf-8"))
        package_value = value.get("package")
        if not isinstance(package_value, dict):
            continue
        name = package_value.get("name")
        if isinstance(name, str):
            if name in manifests:
                raise ValueError(f"ambiguous package manifest: {name}")
            manifests[name] = path
    manifest = manifests.get(package)
    if manifest is None:
        raise ValueError(f"missing patched package manifest: {package}")
    value = tomllib.loads(manifest.read_text(encoding="utf-8"))
    names: set[str] = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        entries = value.get(section, {})
        if isinstance(entries, dict):
            names.update(str(name) for name in entries)
    return names


def _add_dependency_edges(raw: bytes, package: str, dependencies: tuple[str, ...]) -> bytes:
    pattern = re.compile(
        rb'(\[\[package\]\]\nname = "'
        + re.escape(package.encode())
        + rb'"\nversion = "[^"]+"\ndependencies = \[\n)(.*?)(\n\]\n)',
        re.DOTALL,
    )
    match = pattern.search(raw)
    if match is None:
        raise ValueError(f"missing lock package: {package}")
    existing = {line.strip()[1:-2].decode() for line in match.group(2).splitlines() if line.strip()}
    overlap = existing.intersection(dependencies)
    if overlap:
        raise ValueError(f"dependency edge already present for {package}: {sorted(overlap)}")
    merged = sorted(existing.union(dependencies))
    body = b"\n".join(f' "{dependency}",'.encode() for dependency in merged)
    return raw[: match.start()] + match.group(1) + body + match.group(3) + raw[match.end() :]


def derive(root: Path) -> tuple[bytes, dict[str, object]]:
    """Return the minimal complete lock after both reviewed patches are applied."""
    local_version_lock, local_changes = derive_local_versions(root)
    if hashlib.sha256(local_version_lock).hexdigest() != LOCAL_VERSION_LOCK_SHA256:
        raise ValueError("local-version proof lock identity changed")

    corrected = local_version_lock
    edge_changes: list[dict[str, str]] = []
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    sha2 = workspace["workspace"]["dependencies"]["sha2"]
    sha2_requirement = sha2 if isinstance(sha2, str) else sha2.get("version")
    if sha2_requirement != EXPECTED_WORKSPACE_SHA2_REQUIREMENT:
        raise ValueError(f"reviewed sha2 workspace requirement changed: {sha2_requirement}")

    for package, dependencies in _REQUIRED_DEPENDENCY_EDGES.items():
        manifest_dependencies = _manifest_dependencies(root, package)
        missing = {name for name, _ in dependencies}.difference(manifest_dependencies)
        if missing:
            raise ValueError(
                "reviewed dependency edges absent from patched "
                f"{package} manifest: {sorted(missing)}"
            )
        lock_edges = tuple(edge for _, edge in dependencies)
        corrected = _add_dependency_edges(corrected, package, lock_edges)
        edge_changes.extend(
            {
                "package": package,
                "manifest_dependency": manifest_dependency,
                "lock_dependency": lock_dependency,
                "reason": "reviewed host-integration manifest dependency",
            }
            for manifest_dependency, lock_dependency in dependencies
        )

    observed = hashlib.sha256(corrected).hexdigest()
    if observed != PRODUCTION_HOST_LOCK_SHA256:
        raise ValueError(f"production-host proof lock changed: {observed}")
    return corrected, {
        "base_local_version_lock_sha256": LOCAL_VERSION_LOCK_SHA256,
        "production_host_lock_sha256": observed,
        "local_version_changes": local_changes,
        "dependency_edge_changes": edge_changes,
        "packages_added": [],
        "packages_removed": [],
        "external_versions_changed": [],
        "external_sources_changed": [],
        "external_checksums_changed": [],
    }
