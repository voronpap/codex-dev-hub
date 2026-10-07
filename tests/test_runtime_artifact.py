import json
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.qualification import QualificationReceiptHeaderV1
from devhub.runtime_artifact import (
    PythonRuntimeArtifactEvidenceV1,
    PythonRuntimeReceiptV1,
    file_sha256,
    inspect_runtime_environment,
    python_runtime_expected,
    verify_runtime_against_expected,
)


def runtime_files(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    root = tmp_path / "runtime"
    interpreter = root / "Scripts" / "python.exe"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"reviewed-python-launcher")
    module = root / "Lib" / "site-packages" / "devhub" / "__init__.py"
    module.parent.mkdir(parents=True)
    module.write_text('__version__ = "0.1.0"')
    wheel = tmp_path / "codex_dev_hub-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "codex_dev_hub-0.1.0.dist-info/METADATA",
            "Metadata-Version: 2.4\nName: codex-dev-hub\nVersion: 0.1.0\n",
        )
    lock = tmp_path / "uv.lock"
    lock.write_text('version = 1\n[[package]]\nname = "mcp"\nversion = "2.2.0"\n')
    return root, interpreter, module, wheel, lock


def observed(module: Path, interpreter: Path, **updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "implementation": "CPython",
        "version": "3.12.11",
        "cache_tag": "cpython-312",
        "soabi": "cp312-win_amd64",
        "platform_tag": "win-amd64",
        "system": "Windows",
        "machine": "AMD64",
        "executable": str(interpreter),
        "module_origin": str(module),
        "isolated": True,
        "ignore_environment": True,
        "no_user_site": True,
        "editable": False,
        "distributions": [
            {
                "name": "codex-dev-hub",
                "version": "0.1.0",
                "record_sha256": "1" * 64,
                "file_count": 2,
            },
            {
                "name": "mcp",
                "version": "2.2.0",
                "record_sha256": "2" * 64,
                "file_count": 3,
            },
        ],
    }
    value.update(updates)
    return value


def install_inspection(monkeypatch, value, seen=None):
    def fake(argv, *, env, timeout):
        assert argv[1:3] == ["-I", "-c"]
        assert env["PYTHONPATH"] == "untrusted-must-be-ignored"
        if seen is not None:
            seen.append((argv, env, timeout))
        return json.dumps(value).encode()

    monkeypatch.setattr("devhub.runtime_artifact.subprocess.check_output", fake)


def test_isolated_noneditable_runtime_has_stable_identity(tmp_path, monkeypatch):
    root, interpreter, module, wheel, lock = runtime_files(tmp_path)
    seen = []
    install_inspection(monkeypatch, observed(module, interpreter), seen)
    first = inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)
    second = inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)
    assert first == second
    assert first.payload.python_platform_tag == "win-amd64"
    assert first.payload.python_soabi == "cp312-win_amd64"
    assert first.payload.platform_machine == "AMD64"
    assert first.payload.devhub_module_origin == "Lib/site-packages/devhub/__init__.py"
    assert first.payload.python_executable_sha256 == file_sha256(interpreter)
    assert len(seen) == 2
    assert root.is_dir()


def test_nullable_platform_observations_keep_required_stable_tag(tmp_path, monkeypatch):
    _, interpreter, module, wheel, lock = runtime_files(tmp_path)
    install_inspection(
        monkeypatch,
        observed(module, interpreter, soabi=None, machine="", platform_tag="win-amd64"),
    )

    environment = inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)

    assert environment.payload.python_platform_tag == "win-amd64"
    assert environment.payload.python_soabi is None
    assert environment.payload.platform_machine is None


def test_empty_stable_platform_tag_is_rejected(tmp_path, monkeypatch):
    _, interpreter, module, wheel, lock = runtime_files(tmp_path)
    install_inspection(monkeypatch, observed(module, interpreter, platform_tag=""))

    with pytest.raises(ValidationError, match="python_platform_tag"):
        inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"isolated": False}, "not isolated"),
        ({"ignore_environment": False}, "not isolated"),
        ({"no_user_site": False}, "not isolated"),
        ({"editable": True}, "not isolated"),
        ({"implementation": "PyPy"}, "CPython 3.12"),
        ({"version": "3.13.0"}, "CPython 3.12"),
    ],
)
def test_ambient_or_wrong_python_is_rejected(tmp_path, monkeypatch, updates, message):
    _, interpreter, module, wheel, lock = runtime_files(tmp_path)
    install_inspection(monkeypatch, observed(module, interpreter, **updates))
    with pytest.raises(ValueError, match=message):
        inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)


def test_module_origin_and_dependency_set_are_bound(tmp_path, monkeypatch):
    _, interpreter, module, wheel, lock = runtime_files(tmp_path)
    outside = tmp_path / "ambient" / "devhub.py"
    outside.parent.mkdir()
    outside.write_text("ambient")
    install_inspection(monkeypatch, observed(outside, interpreter))
    with pytest.raises(ValueError, match="escapes dedicated environment"):
        inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)
    bad = observed(module, interpreter)
    bad["distributions"] = [
        *bad["distributions"],
        {"name": "ambient", "version": "9", "record_sha256": "3" * 64, "file_count": 1},
    ]
    install_inspection(monkeypatch, bad)
    with pytest.raises(ValueError, match="absent from exact lock"):
        inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)


def test_runtime_receipt_binds_wheel_lock_interpreter_and_flat_header(tmp_path, monkeypatch):
    _, interpreter, module, wheel, lock = runtime_files(tmp_path)
    install_inspection(monkeypatch, observed(module, interpreter))
    environment = inspect_runtime_environment(interpreter, wheel, lock, "a" * 40)
    evidence = PythonRuntimeArtifactEvidenceV1(
        implementation_commit="a" * 40,
        source_archive_sha256="0" * 64,
        wheel_filename=wheel.name,
        wheel_sha256=file_sha256(wheel),
        package_version="0.1.0",
        dependency_lock_sha256=file_sha256(lock),
        build_python_version="3.12.11",
        build_python_executable_sha256="1" * 64,
        build_tool="uv 0.8.22",
        build_tool_sha256="2" * 64,
        runtime_environment=environment,
    )
    expected = python_runtime_expected(evidence)
    header = QualificationReceiptHeaderV1(
        receipt_kind="python_runtime",
        qualification_context_id="3" * 64,
        environment_instance_id="4" * 32,
    )
    receipt = verify_runtime_against_expected(interpreter, wheel, lock, expected, header)
    assert receipt.receipt_kind == "python_runtime"
    assert "header" not in receipt.model_dump()
    assert receipt.interpreter_sha256 == file_sha256(interpreter)
    assert receipt.wheel_sha256 == file_sha256(wheel)
    assert receipt.lock_path == str(lock.resolve())

    for field in (
        "wheel_sha256",
        "dependency_lock_sha256",
        "python_executable_sha256",
        "runtime_environment_id",
    ):
        wrong = expected.model_copy(update={field: "f" * 64})
        with pytest.raises(ValueError, match="differs from qualification context"):
            verify_runtime_against_expected(interpreter, wheel, lock, wrong, header)


def test_python_runtime_receipt_rejects_wrong_kind():
    with pytest.raises(ValidationError, match="wrong kind"):
        PythonRuntimeReceiptV1(
            receipt_kind="isolation",
            qualification_context_id="3" * 64,
            environment_instance_id="4" * 32,
            interpreter_path="/runtime/python",
            wheel_path="/runtime/devhub.whl",
            lock_path="/runtime/uv.lock",
            interpreter_sha256="1" * 64,
            python_implementation="CPython",
            python_version="3.12.11",
            wheel_sha256="2" * 64,
            dependency_lock_sha256="3" * 64,
            module_origin="site-packages/devhub/__init__.py",
            runtime_environment_id="4" * 64,
        )
