"""Structural reports must distinguish harmless serialization from dependency drift."""

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "diagnose_cargo_lock", SCRIPTS / "diagnose_cargo_lock.py"
)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
diff = module.structural_diff


def test_ordering_does_not_become_dependency_change():
    a = b'version=4\n[[package]]\nname="a"\nversion="1"\ndependencies=["b", "c"]\n'
    b = a.replace(b'["b", "c"]', b'["c", "b"]') + b"# comment\n"
    result = diff(a, b)
    assert result["ordering_or_text_only"] is True
    assert result["dependency_edges_changed"] == []
    assert result["packages_changed"] == []


def test_version_git_checksum_and_edges_are_not_noise():
    a = (
        b'version=4\n[[package]]\nname="a"\nversion="1"\nsource="git+x#111"\n'
        b'checksum="old"\ndependencies=["b"]\n'
    )
    b = a.replace(b'"1"', b'"2"').replace(b"#111", b"#222")
    b = b.replace(b'"old"', b'"new"').replace(b'["b"]', b'["b", "c"]')
    result = diff(a, b)
    for key in (
        "versions_changed",
        "git_revisions_changed",
        "checksums_changed",
        "dependency_edges_changed",
    ):
        assert len(result[key]) == 1
    assert result["ordering_or_text_only"] is False
    assert result["packages_changed"][0]["reason"] is None


def test_added_removed_and_ambiguous_versions_remain_explicit():
    a = b'version=4\n[[package]]\nname="a"\nversion="1"\n'
    b = b'version=4\n[[package]]\nname="a"\nversion="2"\n'
    b += b'[[package]]\nname="a"\nversion="3"\n'
    result = diff(a, b)
    assert len(result["packages_added"]) == 2
    assert len(result["packages_removed"]) == 1
    assert result["versions_changed"] == []


def test_lock_format_and_top_level_metadata_recorded():
    result = diff(b"version=3\n", b'version=4\n[metadata]\nx="y"\n')
    assert result["lock_version_changed"] is True
    assert result["top_level_other"]["new"] == {"metadata": {"x": "y"}}
    assert result["ordering_or_text_only"] is False


def test_duplicate_package_identity_rejected():
    package = b'[[package]]\nname="a"\nversion="1"\n'
    with pytest.raises(ValueError, match="duplicate"):
        diff(b"version=4\n" + package + package, b"version=4\n")
