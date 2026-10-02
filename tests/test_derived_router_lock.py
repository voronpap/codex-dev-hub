"""The proof lock transformer may only change pinned local manifest-required versions."""

import hashlib
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/derive_router_build_lock.py"
spec = importlib.util.spec_from_file_location("derive_router_build_lock", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def source(tmp_path, monkeypatch):
    (tmp_path / "Cargo.toml").write_text(
        '[workspace.package]\nversion="0.155.0-alpha.9.2"\n', encoding="utf-8"
    )
    chunks = [b"version = 4\n\n"]
    expected = [chunks[0]]
    for i in range(152):
        directory = tmp_path / str(i)
        directory.mkdir()
        (directory / "Cargo.toml").write_text(
            f'[package]\nname="p{i}"\nversion.workspace=true\n', encoding="utf-8"
        )
        chunk = f'[[package]]\nname = "p{i}"\nversion = "0.0.0"\n\n'.encode()
        chunks.append(chunk)
        expected.append(chunk.replace(b'"0.0.0"', b'"0.155.0-alpha.9.2"'))
    external = b'[[package]]\nname="external"\nversion="0.0.0"\nsource="registry+x"\n'
    original, derived = b"".join(chunks) + external, b"".join(expected) + external
    (tmp_path / "Cargo.lock").write_bytes(original)
    monkeypatch.setattr(module, "ORIGINAL", hashlib.sha256(original).hexdigest())
    monkeypatch.setattr(module, "DERIVED", hashlib.sha256(derived).hexdigest())
    return original, derived


def test_derivation_preserves_original_and_external_packages(tmp_path, monkeypatch):
    original, expected = source(tmp_path, monkeypatch)
    actual, bindings = module.derive(tmp_path)
    assert actual == expected
    assert (tmp_path / "Cargo.lock").read_bytes() == original
    assert len(bindings) == 152
    assert all(b["manifest_sha256"] and b["workspace_manifest_sha256"] for b in bindings)


def test_unexpected_manifest_or_original_lock_refused(tmp_path, monkeypatch):
    original, _ = source(tmp_path, monkeypatch)
    path = tmp_path / "0/Cargo.toml"
    previous = path.read_bytes()
    path.write_text('[package]\nname="p0"\nversion="2"\n', encoding="utf-8")
    with pytest.raises(AssertionError):
        module.derive(tmp_path)
    path.write_bytes(previous)
    (tmp_path / "Cargo.lock").write_bytes(original + b"# drift\n")
    with pytest.raises(AssertionError):
        module.derive(tmp_path)
