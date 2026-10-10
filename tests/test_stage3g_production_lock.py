import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "derive_stage3g_production_lock", SCRIPTS / "derive_stage3g_production_lock.py"
)
assert SPEC is not None and SPEC.loader is not None
production_lock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(production_lock)
sys.path.pop(0)


def _workspace(tmp_path: Path) -> Path:
    root = tmp_path / "codex-rs"
    root.mkdir()
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers = []\n\n[workspace.dependencies]\nsha2 = "0.10.9"\n',
        encoding="utf-8",
    )
    for directory, package, dependencies in (
        (
            "app-server-client",
            "codex-app-server-client",
            "codex-extension-api = { workspace = true }",
        ),
        (
            "exec",
            "codex-exec",
            "\n".join(
                (
                    "codex-extension-api = { workspace = true }",
                    "codex-tools = { workspace = true }",
                    "sha2 = { workspace = true }",
                )
            ),
        ),
        ("tui", "codex-tui", "codex-extension-api = { workspace = true }"),
    ):
        path = root / directory
        path.mkdir()
        (path / "Cargo.toml").write_text(
            f'[package]\nname = "{package}"\nversion = "1.0.0"\n\n[dependencies]\n{dependencies}\n',
            encoding="utf-8",
        )
    return root


def _local_lock() -> bytes:
    packages = []
    for package, existing in (
        ("codex-app-server-client", ("serde",)),
        ("codex-exec", ("serde",)),
        ("codex-tui", ("serde",)),
    ):
        dependencies = "\n".join(f' "{dependency}",' for dependency in existing)
        packages.append(
            f'[[package]]\nname = "{package}"\nversion = "1.0.0"\n'
            f"dependencies = [\n{dependencies}\n]\n"
        )
    return "\n".join(packages).encode()


def test_adds_only_reviewed_patched_manifest_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _workspace(tmp_path)
    local_lock = _local_lock()
    expected = local_lock
    for package, dependencies in production_lock._REQUIRED_DEPENDENCY_EDGES.items():
        expected = production_lock._add_dependency_edges(
            expected, package, tuple(edge for _, edge in dependencies)
        )
    monkeypatch.setattr(
        production_lock, "derive_local_versions", lambda _: (local_lock, [{"local": True}])
    )
    monkeypatch.setattr(
        production_lock,
        "LOCAL_VERSION_LOCK_SHA256",
        production_lock.hashlib.sha256(local_lock).hexdigest(),
    )
    monkeypatch.setattr(
        production_lock,
        "PRODUCTION_HOST_LOCK_SHA256",
        production_lock.hashlib.sha256(expected).hexdigest(),
    )

    observed, evidence = production_lock.derive(root)

    assert observed == expected
    assert evidence["packages_added"] == []
    assert evidence["external_versions_changed"] == []
    assert evidence["dependency_edge_changes"] == [
        {
            "package": package,
            "manifest_dependency": manifest_dependency,
            "lock_dependency": lock_dependency,
            "reason": "reviewed host-integration manifest dependency",
        }
        for package, dependencies in production_lock._REQUIRED_DEPENDENCY_EDGES.items()
        for manifest_dependency, lock_dependency in dependencies
    ]


def test_rejects_missing_patched_manifest_edge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _workspace(tmp_path)
    manifest = root / "exec/Cargo.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace("codex-tools = { workspace = true }\n", ""),
        encoding="utf-8",
    )
    local_lock = _local_lock()
    monkeypatch.setattr(production_lock, "derive_local_versions", lambda _: (local_lock, []))
    monkeypatch.setattr(
        production_lock,
        "LOCAL_VERSION_LOCK_SHA256",
        production_lock.hashlib.sha256(local_lock).hexdigest(),
    )

    with pytest.raises(ValueError, match="codex-tools"):
        production_lock.derive(root)


def test_rejects_preexisting_unreviewed_edge() -> None:
    raw = _local_lock().replace(b' "serde",', b' "codex-extension-api",\n "serde",', 1)

    with pytest.raises(ValueError, match="already present"):
        production_lock._add_dependency_edges(
            raw, "codex-app-server-client", ("codex-extension-api",)
        )
