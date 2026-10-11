from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

import devhub.native_bundle as NATIVE_BUNDLE
from devhub.native_bundle import (
    NativeLoaderBuildPayloadV1,
    NativeLoaderBuildV1,
    NativeLoaderDependencyV1,
    NativeLoaderPostBuildProofV1,
    NativeLoaderWorkflowV1,
    git_blob_bytes,
    git_blob_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native/windows_loader/devfabric_native_loader.c"
SPEC = importlib.util.spec_from_file_location(
    "build_windows_native_loader", ROOT / "scripts/build_windows_native_loader.py"
)
assert SPEC is not None and SPEC.loader is not None
LOADER_BUILDER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LOADER_BUILDER
SPEC.loader.exec_module(LOADER_BUILDER)
BUNDLE_SPEC = importlib.util.spec_from_file_location(
    "native_loader_bundle_builder", ROOT / "scripts/build_windows_native_bundle.py"
)
assert BUNDLE_SPEC is not None and BUNDLE_SPEC.loader is not None
BUNDLE_BUILDER = importlib.util.module_from_spec(BUNDLE_SPEC)
sys.modules[BUNDLE_SPEC.name] = BUNDLE_BUILDER
BUNDLE_SPEC.loader.exec_module(BUNDLE_BUILDER)


def _payload() -> NativeLoaderBuildPayloadV1:
    return NativeLoaderBuildPayloadV1(
        implementation_commit="a" * 40,
        source_sha256="b" * 64,
        binary_sha256="c" * 64,
        python_executable_sha256="d" * 64,
        runtime_python_executable_sha256="e" * 64,
        python_import_library_sha256="f" * 64,
        python_headers_sha256="0" * 64,
        python_header_count=42,
        compiler_path_sha256="1" * 64,
        compiler_version="Microsoft C/C++ Optimizing Compiler Version 19.44",
        linker_path_sha256="2" * 64,
        linker_version="Microsoft Incremental Linker Version 14.44",
        compile_flags=("/nologo", "/LD", "/O2", "/GS", "/guard:cf", "/sdl", "/W3", "/WX"),
        link_flags=("/DYNAMICBASE", "/NXCOMPAT"),
        dependencies=(
            NativeLoaderDependencyV1(filename="libffi-8.dll", sha256="3" * 64),
            NativeLoaderDependencyV1(filename="libcrypto-3.dll", sha256="4" * 64),
            NativeLoaderDependencyV1(filename="libssl-3.dll", sha256="5" * 64),
        ),
        workflow=NativeLoaderWorkflowV1(
            workflow_sha256="6" * 64,
            run_id=123,
            run_attempt=1,
        ),
        post_build_proof=NativeLoaderPostBuildProofV1(final_binary_sha256="c" * 64),
    )


def test_native_loader_build_receipt_is_self_hashing_and_strict() -> None:
    receipt = NativeLoaderBuildV1.create(_payload())
    assert NativeLoaderBuildV1.model_validate_json(receipt.model_dump_json()) == receipt

    raw = json.loads(receipt.model_dump_json())
    raw["payload"]["compiler_version"] = "changed"
    with pytest.raises(ValueError, match="build ID mismatch"):
        NativeLoaderBuildV1.model_validate_json(json.dumps(raw))

    raw = json.loads(receipt.model_dump_json())
    raw["payload"]["unreviewed"] = True
    with pytest.raises(ValueError, match="Extra inputs"):
        NativeLoaderBuildV1.model_validate_json(json.dumps(raw))


@pytest.mark.parametrize("mutation", ["dependency", "compile_flags", "link_flags"])
def test_native_loader_contract_rejects_authority_widening(mutation: str) -> None:
    raw = _payload().model_dump(mode="json")
    if mutation == "dependency":
        raw["dependencies"][0]["filename"] = "ambient.dll"
    elif mutation == "compile_flags":
        raw["compile_flags"].append("/DUNREVIEWED")
    else:
        raw["link_flags"].append("/LIBPATH:ambient")
    with pytest.raises(ValueError):
        NativeLoaderBuildPayloadV1.model_validate(raw)


def test_native_loader_source_has_closed_path_name_and_flag_authority() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    for name in ("libffi-8.dll", "libcrypto-3.dll", "libssl-3.dll"):
        assert source.count(name) == 1
    assert "METH_NOARGS" in source
    assert "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32" in source
    assert "LoadLibraryExW(expected_path, NULL, DEVFABRIC_LOAD_FLAGS)" in source
    assert "GetModuleFileNameW(NULL, python_path" in source
    assert "same_file_identity(expected_file, loaded_file)" in source
    assert "FILE_SHARE_READ," in source
    assert "FILE_SHARE_DELETE" not in source
    assert "open_plain_directory(directory)" in source
    for forbidden in (
        "AddDllDirectory",
        "SetDllDirectory",
        "SearchPath",
        "GetEnvironmentVariable",
    ):
        assert forbidden not in source


def test_native_loader_builder_rejects_dirty_or_wrong_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = iter(["a" * 40, "dirty\n"])
    monkeypatch.setattr(LOADER_BUILDER, "_output", lambda _argv: next(outputs))
    with pytest.raises(ValueError, match="clean commit"):
        LOADER_BUILDER._clean_commit(tmp_path, "a" * 40)

    monkeypatch.setattr(LOADER_BUILDER, "_output", lambda _argv: "b" * 40)
    with pytest.raises(ValueError, match="HEAD differs"):
        LOADER_BUILDER._clean_commit(tmp_path, "a" * 40)


def test_bundle_loader_artifact_review_rejects_substitution_and_extra_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "loader"
    artifact.mkdir()
    binary = artifact / "_devfabric_native_loader.pyd"
    binary.write_bytes(b"native-loader")
    payload = _payload().model_copy(
        update={
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
            "workflow": NativeLoaderWorkflowV1(
                workflow_sha256=hashlib.sha256(
                    (ROOT / ".github/workflows/windows-native-loader.yml").read_bytes()
                ).hexdigest(),
                run_id=123,
                run_attempt=1,
            ),
            "post_build_proof": NativeLoaderPostBuildProofV1(
                final_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()
            ),
        }
    )
    receipt = NativeLoaderBuildV1.create(payload)
    (artifact / "native-loader-build.json").write_text(receipt.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr(
        BUNDLE_BUILDER,
        "git_blob_sha256",
        lambda _repo, _commit, path: (
            payload.source_sha256
            if path == payload.source_path
            else payload.workflow.workflow_sha256
        ),
    )
    assert (
        BUNDLE_BUILDER._review_native_loader_artifact(
            ROOT, artifact, "a" * 40, 123, 1
        ).native_loader_build_id
        == receipt.native_loader_build_id
    )

    binary.write_bytes(b"substituted")
    with pytest.raises(ValueError, match="differs"):
        BUNDLE_BUILDER._review_native_loader_artifact(ROOT, artifact, "a" * 40, 123, 1)
    binary.write_bytes(b"native-loader")
    (artifact / "ambient.dll").write_bytes(b"ambient")
    with pytest.raises(ValueError, match="unexpected layout"):
        BUNDLE_BUILDER._review_native_loader_artifact(ROOT, artifact, "a" * 40, 123, 1)


@pytest.mark.parametrize("mutation", ["source", "workflow", "run", "attempt"])
def test_bundle_loader_artifact_review_rejects_forged_self_hashed_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    artifact = tmp_path / "loader"
    artifact.mkdir()
    binary = artifact / "_devfabric_native_loader.pyd"
    binary.write_bytes(b"native-loader")
    workflow = NativeLoaderWorkflowV1(
        workflow_sha256=hashlib.sha256(
            (ROOT / ".github/workflows/windows-native-loader.yml").read_bytes()
        ).hexdigest(),
        run_id=123,
        run_attempt=1,
    )
    updates: dict[str, object] = {
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "workflow": workflow,
        "post_build_proof": NativeLoaderPostBuildProofV1(
            final_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()
        ),
    }
    if mutation == "source":
        updates["source_sha256"] = "9" * 64
    elif mutation == "workflow":
        updates["workflow"] = workflow.model_copy(update={"workflow_sha256": "9" * 64})
    elif mutation == "run":
        updates["workflow"] = workflow.model_copy(update={"run_id": 999})
    else:
        updates["workflow"] = workflow.model_copy(update={"run_attempt": 2})
    receipt = NativeLoaderBuildV1.create(_payload().model_copy(update=updates))
    (artifact / "native-loader-build.json").write_text(receipt.model_dump_json(), encoding="utf-8")
    monkeypatch.setattr(
        BUNDLE_BUILDER,
        "git_blob_sha256",
        lambda _repo, _commit, path: (
            hashlib.sha256(SOURCE.read_bytes()).hexdigest()
            if path == _payload().source_path
            else hashlib.sha256(
                (ROOT / ".github/workflows/windows-native-loader.yml").read_bytes()
            ).hexdigest()
        ),
    )
    with pytest.raises(ValueError, match="differs"):
        BUNDLE_BUILDER._review_native_loader_artifact(ROOT, artifact, "a" * 40, 123, 1)


def test_historical_bundle_hash_payload_omits_only_absent_forward_loader() -> None:
    class HistoricalPayload:
        native_loader = None

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"native_loader": None, "platform_machine": None, "kind": "historical"}

    assert NATIVE_BUNDLE._native_bundle_payload_json(HistoricalPayload()) == {  # type: ignore[arg-type]
        "platform_machine": None,
        "kind": "historical",
    }


@pytest.mark.parametrize("target", ["root", "entry"])
def test_bundle_loader_artifact_rejects_reparse_or_symlink_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    artifact = tmp_path / "loader"
    artifact.mkdir()
    binary = artifact / "_devfabric_native_loader.pyd"
    binary.write_bytes(b"native-loader")
    (artifact / "native-loader-build.json").write_bytes(b"{}")
    original = Path.is_symlink
    selected = artifact.resolve() if target == "root" else binary
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == selected or original(path),
    )
    with pytest.raises(ValueError, match="symlink/reparse|plain regular"):
        BUNDLE_BUILDER._review_native_loader_artifact(ROOT, artifact, "a" * 40, 123, 1)


@pytest.mark.parametrize("mutation", ["python", "missing", "dependency"])
def test_bundle_loader_runtime_rejects_interpreter_or_dependency_mismatch(
    tmp_path: Path, mutation: str
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    files = {
        "python.exe": b"python",
        "libffi-8.dll": b"ffi",
        "libcrypto-3.dll": b"crypto",
        "libssl-3.dll": b"ssl",
    }
    for name, raw in files.items():
        (runtime / name).write_bytes(raw)
    payload = _payload().model_copy(
        update={
            "runtime_python_executable_sha256": hashlib.sha256(files["python.exe"]).hexdigest(),
            "dependencies": tuple(
                NativeLoaderDependencyV1(
                    filename=name,  # type: ignore[arg-type]
                    sha256=hashlib.sha256(files[name]).hexdigest(),
                )
                for name in ("libffi-8.dll", "libcrypto-3.dll", "libssl-3.dll")
            ),
        }
    )
    receipt = NativeLoaderBuildV1.create(payload)
    if mutation == "python":
        (runtime / "python.exe").write_bytes(b"wrong")
    elif mutation == "missing":
        (runtime / "libffi-8.dll").unlink()
    else:
        (runtime / "libssl-3.dll").write_bytes(b"wrong")
    with pytest.raises(ValueError, match="interpreter|dependency"):
        BUNDLE_BUILDER._review_native_loader_runtime(receipt, runtime)


def test_native_loader_pe_machine_is_derived_and_rejects_wrong_architecture(
    tmp_path: Path,
) -> None:
    image = bytearray(128)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    image[68:70] = (0x8664).to_bytes(2, "little")
    target = tmp_path / "loader.pyd"
    target.write_bytes(image)
    assert LOADER_BUILDER._pe_machine(target) == "0x8664"
    image[68:70] = (0x14C).to_bytes(2, "little")
    target.write_bytes(image)
    with pytest.raises(ValueError, match="not Windows AMD64"):
        LOADER_BUILDER._pe_machine(target)


def test_native_loader_header_inventory_is_content_bound(tmp_path: Path) -> None:
    include = tmp_path / "include"
    include.mkdir()
    (include / "Python.h").write_bytes(b"first")
    first, count = LOADER_BUILDER._header_inventory(include)
    assert count == 1
    (include / "Python.h").write_bytes(b"second")
    second, _ = LOADER_BUILDER._header_inventory(include)
    assert first != second


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def _committed_loader_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    (repo / "native/windows_loader").mkdir(parents=True)
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / "native/windows_loader/devfabric_native_loader.c").write_bytes(b"source\n")
    (repo / ".github/workflows/windows-native-loader.yml").write_bytes(b"workflow\n")
    _git(repo, "init")
    _git(repo, "config", "user.email", "tests@example.invalid")
    _git(repo, "config", "user.name", "DevFabric Tests")
    _git(repo, "config", "core.autocrlf", "false")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    return repo, _git(repo, "rev-parse", "HEAD")


def test_git_blob_authority_is_worktree_line_ending_independent_and_semantic(
    tmp_path: Path,
) -> None:
    repo, commit = _committed_loader_repo(tmp_path)
    source = repo / "native/windows_loader/devfabric_native_loader.c"
    expected = hashlib.sha256(b"source\n").hexdigest()
    assert (
        git_blob_sha256(repo, commit, "native/windows_loader/devfabric_native_loader.c") == expected
    )

    source.write_bytes(b"source\r\n")
    assert hashlib.sha256(source.read_bytes()).hexdigest() != expected
    assert (
        git_blob_sha256(repo, commit, "native/windows_loader/devfabric_native_loader.c") == expected
    )

    source.write_bytes(b"semantic change\n")
    _git(repo, "add", str(source.relative_to(repo)))
    _git(repo, "commit", "-m", "semantic change")
    changed = _git(repo, "rev-parse", "HEAD")
    assert (
        git_blob_sha256(repo, changed, "native/windows_loader/devfabric_native_loader.c")
        != expected
    )


def test_native_loader_materializes_exact_committed_source_snapshot(tmp_path: Path) -> None:
    repo, commit = _committed_loader_repo(tmp_path)
    source = repo / "native/windows_loader/devfabric_native_loader.c"
    source.write_bytes(b"source\r\n")
    stage = tmp_path / "stage"
    stage.mkdir()

    snapshot, observed = LOADER_BUILDER._materialize_source_snapshot(repo, commit, stage)

    committed = git_blob_bytes(repo, commit, "native/windows_loader/devfabric_native_loader.c")
    assert snapshot.read_bytes() == committed == b"source\n"
    assert observed == hashlib.sha256(committed).hexdigest()


def test_bundle_review_uses_blob_authority_and_rejects_changed_blob(tmp_path: Path) -> None:
    repo, commit = _committed_loader_repo(tmp_path)
    source_path = "native/windows_loader/devfabric_native_loader.c"
    workflow_path = ".github/workflows/windows-native-loader.yml"
    source = repo / source_path
    workflow = repo / workflow_path
    source.write_bytes(b"source\r\n")
    workflow.write_bytes(b"workflow\r\n")
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    binary = artifact / "_devfabric_native_loader.pyd"
    binary.write_bytes(b"native-loader")
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    payload = _payload().model_copy(
        update={
            "implementation_commit": commit,
            "source_sha256": git_blob_sha256(repo, commit, source_path),
            "binary_sha256": binary_sha256,
            "workflow": NativeLoaderWorkflowV1(
                workflow_sha256=git_blob_sha256(repo, commit, workflow_path),
                run_id=123,
                run_attempt=1,
            ),
            "post_build_proof": NativeLoaderPostBuildProofV1(final_binary_sha256=binary_sha256),
        }
    )
    receipt = NativeLoaderBuildV1.create(payload)
    receipt_path = artifact / "native-loader-build.json"
    receipt_path.write_text(receipt.model_dump_json(), encoding="utf-8")
    assert BUNDLE_BUILDER._review_native_loader_artifact(repo, artifact, commit, 123, 1) == receipt

    source.write_bytes(b"semantic change\n")
    _git(repo, "add", source_path)
    _git(repo, "commit", "-m", "semantic change")
    changed = _git(repo, "rev-parse", "HEAD")
    forged = NativeLoaderBuildV1.create(
        payload.model_copy(update={"implementation_commit": changed})
    )
    receipt_path.write_text(forged.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="differs"):
        BUNDLE_BUILDER._review_native_loader_artifact(repo, artifact, changed, 123, 1)
