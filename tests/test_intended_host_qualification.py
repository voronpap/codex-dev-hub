import hashlib
import importlib.util
import json
import shutil
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from devhub.experiment_preflight import validated_chatgpt_auth
from devhub.ledger import Ledger, LedgerIdentityCoreV1
from devhub.qualification import (
    OllamaNetworkIsolationObservationV1,
    QualificationContextV1,
)
from devhub.runtime_artifact import PythonRuntimeReceiptV1

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def qualification_tree(root: Path):
    root.mkdir(parents=True)
    module = load_script("../tests/test_qualification")
    return module.materialize(root)


def test_auth_qualifier_rejects_api_key_and_unsupported_authority(tmp_path, monkeypatch):
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({"OPENAI_API_KEY": "withheld"}))
    with pytest.raises(ValueError, match="ChatGPT auth"):
        validated_chatgpt_auth(auth)
    auth.write_text(
        json.dumps(
            {
                "auth_mode": "api_key",
                "OPENAI_API_KEY": None,
                "tokens": {"access_token": "withheld"},
            }
        )
    )
    with pytest.raises(ValueError, match="ChatGPT auth"):
        validated_chatgpt_auth(auth)
    auth.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {"access_token": "withheld"},
            }
        )
    )
    assert validated_chatgpt_auth(auth)["auth_mode"] == "chatgpt"
    script = load_script("qualify_auth_egress")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    assert script._proxy_environment_inherited()
    monkeypatch.delenv("HTTPS_PROXY")
    for key in script.PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)
    assert not script._proxy_environment_inherited()


def test_ollama_route_parser_uses_interface_and_rejects_default_routes():
    script = load_script("qualify_ollama_network_isolation")
    ipv4_header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
    ipv4_loopback = ipv4_header + "lo 0000007F 00000000 0001 0 0 0 000000FF 0 0 0\n"
    ipv6_loopback = (
        "0" * 31
        + "1 80 "
        + "0" * 32
        + " 00 "
        + "0" * 32
        + " 00000000 00000000 00000000 00000001 lo\n"
    )
    assert script._non_loopback_routes_from_text(ipv4_loopback, ipv6_loopback) == 0
    ipv4_eth = ipv4_header + "eth0 00000000 010011AC 0003 0 0 0 00000000 0 0 0\n"
    assert script._non_loopback_routes_from_text(ipv4_eth, ipv6_loopback) == 1
    ipv4_default_on_lo = ipv4_header + "lo 00000000 00000000 0001 0 0 0 00000000 0 0 0\n"
    assert script._non_loopback_routes_from_text(ipv4_default_on_lo, ipv6_loopback) == 1
    ipv6_default = (
        "0" * 32
        + " 00 "
        + "0" * 32
        + " 00 "
        + "0" * 32
        + " 00000000 00000000 00000000 00000001 lo\n"
    )
    assert script._non_loopback_routes_from_text(ipv4_loopback, ipv6_default) == 1

    ipv6_kernel_rejects = (
        "0" * 32
        + " 00 "
        + "0" * 32
        + " 00 "
        + "0" * 32
        + " ffffffff 00000001 00000000 00200200 lo\n"
    ) * 2
    assert script._non_loopback_routes_from_text(ipv4_loopback, ipv6_kernel_rejects) == 0

    ipv6_non_loopback = (
        "20010db8000000000000000000000000 40 "
        + "0" * 32
        + " 00 "
        + "0" * 32
        + " 00000000 00000000 00000000 00000001 eth0\n"
    )
    assert script._non_loopback_routes_from_text(ipv4_loopback, ipv6_non_loopback) == 1
    ipv6_rejected_non_loopback = ipv6_non_loopback.replace("00000001 eth0", "00000200 eth0")
    assert script._non_loopback_routes_from_text(ipv4_loopback, ipv6_rejected_non_loopback) == 0
    assert script._non_loopback_routes_from_text(ipv4_loopback, "malformed route\n") == 1


def test_ollama_metadata_rejects_network_namespace_mismatch():
    script = load_script("qualify_ollama_metadata")
    network = OllamaNetworkIsolationObservationV1(
        executable_sha256="a" * 64,
        network_namespace_id="net:[123]",
        separate_network_namespace=True,
        loopback_bind_available=True,
        non_loopback_route_count=0,
        outbound_probe_denied=True,
        proxy_environment_inherited=False,
    )
    environment = {"OLLAMA_NO_CLOUD": "1", "OLLAMA_HOST": "127.0.0.1:11434"}
    assert script._server_identity_matches("a" * 64, network, "a" * 64, "net:[123]", environment)
    assert not script._server_identity_matches(
        "a" * 64, network, "a" * 64, "net:[456]", environment
    )


def test_context_builder_requires_clean_exact_head_and_strict_build_shapes(monkeypatch):
    script = load_script("build_intended_host_qualification_context")
    artifact = SimpleNamespace(implementation_commit="a" * 40)
    monkeypatch.setattr(script, "clean_commit", lambda _: "b" * 40)
    with pytest.raises(ValueError, match="exact clean repository HEAD"):
        script._require_implementation_head(ROOT, artifact)
    monkeypatch.setattr(
        script,
        "clean_commit",
        lambda _: (_ for _ in ()).throw(ValueError("Dirty working tree")),
    )
    with pytest.raises(ValueError, match="Dirty working tree"):
        script._require_implementation_head(ROOT, artifact)
    with pytest.raises(ValidationError):
        script.RuntimeImageBuildEvidenceV1.model_validate(
            {"kind": "runtime_image_build", "unexpected": True}
        )
    with pytest.raises(ValidationError):
        script.EvaluatorImageBuildEvidenceV1.model_validate(
            {"kind": "evaluator_image_build", "unexpected": True}
        )
    protocol = SimpleNamespace()
    monkeypatch.setattr(script, "build_plan", lambda *_: {"run_id": "expected"})
    with pytest.raises(ValueError, match="Reviewed plan"):
        script._require_exact_plan(ROOT, protocol, {"run_id": "wrong"})


def test_context_builder_rejects_symlinked_input(tmp_path):
    script = load_script("build_intended_host_qualification_context")
    target = tmp_path / "target.json"
    target.write_text("{}")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="non-symlink"):
        script._regular(link, "Input")


def test_failed_manifest_assembly_leaves_no_output(tmp_path, monkeypatch):
    script = load_script("assemble_intended_host_manifest")
    output = tmp_path / "qualification-manifest.json"
    manifest = SimpleNamespace(qualification_manifest_id="a" * 64)
    monkeypatch.setattr(script, "canonical_manifest", lambda _: b"{}")
    monkeypatch.setattr(
        script,
        "verify_manifest_tree",
        lambda *_: (_ for _ in ()).throw(ValueError("invalid tree")),
    )
    with pytest.raises(ValueError, match="invalid tree"):
        script._publish_verified_manifest(output, manifest)
    assert not output.exists()
    assert not output.with_name(output.name + ".tmp").exists()


def test_auth_and_ledger_qualifier_main_paths(tmp_path, monkeypatch, capsys):
    context, manifest, _ = qualification_tree(tmp_path / "tree")
    context_path = tmp_path / "tree" / manifest.payload.context.relative_path
    auth_script = load_script("qualify_auth_egress")
    monkeypatch.setattr(auth_script.platform, "system", lambda: "Linux")
    for key in auth_script.PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)
    auth = tmp_path / "auth.json"
    secret = "token-must-never-appear"
    auth.write_text(
        json.dumps(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {"access_token": secret},
            }
        )
    )
    output = tmp_path / "auth-receipt.json"
    original_read = Path.read_bytes
    original_stat = Path.stat
    reads = 0

    def counted_read(path):
        nonlocal reads
        if path == auth:
            reads += 1
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", counted_read)

    def linux_mode_stat(path, *args, **kwargs):
        observed = original_stat(path, *args, **kwargs)
        if path.name == "auth.json" and path.parent.name.startswith("devhub-auth-stage-"):
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
        return observed

    monkeypatch.setattr(Path, "stat", linux_mode_stat)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_auth_egress.py",
            "--context",
            str(context_path),
            "--auth-file",
            str(auth),
            "--output",
            str(output),
        ],
    )
    auth_script.main()
    published = output.read_bytes() + capsys.readouterr().out.encode()
    assert reads == 1
    assert secret.encode() not in published

    ledger_script = load_script("qualify_ledger_identity")
    ledger_root = tmp_path / "ledger"
    Ledger.initialize_state_root(ledger_root, context.payload.ledger_expected.identity)
    before = (ledger_root / "ledger.db").read_bytes()
    ledger_output = tmp_path / "ledger-receipt.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_ledger_identity.py",
            "--context",
            str(context_path),
            "--ledger-root",
            str(ledger_root),
            "--output",
            str(ledger_output),
        ],
    )
    ledger_script.main()
    assert (ledger_root / "ledger.db").read_bytes() == before
    assert json.loads(ledger_output.read_bytes())["ledger_identity_sha256"] == (
        context.payload.ledger_expected.identity_sha256
    )


def test_ledger_qualifier_rejects_symlink_before_database_read(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.db"
    expected = LedgerIdentityCoreV1(
        instance_id="0" * 32,
        authority_scope_kind="project",
        authority_scope_id="test",
    )
    Ledger.initialize(outside, expected)
    link = root / "ledger.db"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")
    original_read = Path.read_bytes
    touched = False

    def watched_read(path):
        nonlocal touched
        if path == link:
            touched = True
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", watched_read)
    with pytest.raises(Exception, match="UNSAFE_STATE_ROOT"):
        Ledger.inspect_read_only(link, expected, state_root=root)
    assert not touched


def test_ollama_qualifier_main_paths(tmp_path, monkeypatch):
    _, manifest, _ = qualification_tree(tmp_path / "tree")
    context_path = tmp_path / "tree" / manifest.payload.context.relative_path
    context = QualificationContextV1.model_validate_json(context_path.read_bytes())
    executable = tmp_path / "ollama"
    executable.write_bytes(b"reviewed-ollama")
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    network_script = load_script("qualify_ollama_network_isolation")
    monkeypatch.setattr(network_script.platform, "system", lambda: "Linux")
    monkeypatch.setattr(network_script, "_non_loopback_routes", lambda: 0)
    monkeypatch.setattr(
        network_script.os,
        "readlink",
        lambda path: "net:[123]" if "self" in path else "net:[1]",
    )

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def bind(self, _):
            pass

        def getsockname(self):
            return ("127.0.0.1", 12345)

        def settimeout(self, _):
            pass

        def connect(self, _):
            raise OSError("isolated")

    monkeypatch.setattr(network_script.socket, "socket", FakeSocket)
    for key in network_script.PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)
    network_output = tmp_path / "network.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_ollama_network_isolation.py",
            "--executable",
            str(executable),
            "--output",
            str(network_output),
        ],
    )
    network_script.main()

    metadata_script = load_script("qualify_ollama_metadata")
    monkeypatch.setattr(metadata_script.platform, "system", lambda: "Linux")
    release = tmp_path / "ollama-linux-amd64.tar.zst"
    release.write_bytes(b"release")
    real_sha256 = hashlib.sha256

    class OfficialDigest:
        def hexdigest(self):
            return metadata_script.STAGE3G_OLLAMA_RELEASE_SHA256

    monkeypatch.setattr(
        metadata_script.hashlib,
        "sha256",
        lambda raw=b"": OfficialDigest() if raw == b"release" else real_sha256(raw),
    )
    monkeypatch.setattr(metadata_script, "_archive_executable_sha256", lambda _: executable_sha)
    environ = tmp_path / "environ"
    environ.write_bytes(b"OLLAMA_NO_CLOUD=1\0OLLAMA_HOST=127.0.0.1:11434\0")
    bridge_environ = tmp_path / "bridge-environ"
    bridge_environ.write_bytes(b"PATH=/usr/bin\0")
    interpreter = tmp_path / "python"
    interpreter.write_bytes(b"python")
    wheel = tmp_path / "devhub.whl"
    wheel.write_bytes(b"wheel")
    lock = tmp_path / "uv.lock"
    lock.write_bytes(b"lock")
    runtime_receipt = PythonRuntimeReceiptV1(
        receipt_kind="python_runtime",
        qualification_context_id=context.qualification_context_id,
        environment_instance_id=context.payload.environment_instance_id,
        interpreter_path=str(interpreter),
        wheel_path=str(wheel),
        lock_path=str(lock),
        interpreter_sha256="3" * 64,
        python_implementation="CPython",
        python_version="3.12.11",
        wheel_sha256=context.payload.implementation.python_runtime.wheel_sha256,
        dependency_lock_sha256=(
            context.payload.implementation.python_runtime.dependency_lock_sha256
        ),
        module_origin="lib/python3.12/site-packages/devhub/__init__.py",
        runtime_environment_id=context.payload.implementation.python_runtime.runtime_environment_id,
    )
    runtime_receipt_path = tmp_path / "python-runtime.json"
    runtime_receipt_path.write_text(runtime_receipt.model_dump_json())
    module = tmp_path / "ollama_transport.py"
    module.write_bytes(b"bridge")
    bridge_socket = tmp_path / "bridge" / "ollama.sock"
    bridge_socket.parent.mkdir(mode=0o700)
    bridge_cmdline = tmp_path / "bridge-cmdline"
    bridge_cmdline.write_bytes(
        b"\0".join(
            item.encode()
            for item in (
                str(interpreter),
                "-I",
                "-m",
                "devhub.ollama_transport",
                "--socket",
                str(bridge_socket),
                "",
            )
        )
    )
    original_path = metadata_script.Path

    def mapped_path(value):
        if str(value) == "/proc/123/exe":
            return executable
        if str(value) == "/proc/123/environ":
            return environ
        if str(value) == "/proc/124/cmdline":
            return bridge_cmdline
        if str(value) == "/proc/124/exe":
            return interpreter
        return original_path(value)

    monkeypatch.setattr(metadata_script, "Path", mapped_path)
    monkeypatch.setattr(metadata_script.os, "readlink", lambda _: "net:[123]")
    monkeypatch.setattr(
        metadata_script,
        "_environment",
        lambda pid: (
            {"OLLAMA_NO_CLOUD": "1", "OLLAMA_HOST": "127.0.0.1:11434"}
            if pid == 123
            else {"PATH": "/usr/bin"}
        ),
    )
    monkeypatch.setattr(metadata_script, "_start_time_ticks", lambda pid: 1000 + pid)
    monkeypatch.setattr(metadata_script, "_process_uid", lambda _: 1000)
    monkeypatch.setattr(
        metadata_script,
        "_bridge_module",
        lambda _: ("lib/python3.12/site-packages/devhub/ollama_transport.py", module),
    )
    original_lstat = metadata_script.os.lstat

    def fake_lstat(path):
        if path == bridge_socket.parent:
            return SimpleNamespace(st_mode=0o40700, st_uid=1000, st_dev=1, st_ino=1)
        if path == bridge_socket:
            return SimpleNamespace(st_mode=0o140600, st_uid=1000, st_dev=1, st_ino=2)
        return original_lstat(path)

    monkeypatch.setattr(metadata_script.os, "lstat", fake_lstat)
    monkeypatch.setattr(metadata_script, "validate_ollama_bridge", lambda _: None)
    monkeypatch.setattr(metadata_script, "server_listener_inode", lambda _: 42)
    monkeypatch.setattr(
        metadata_script, "verify_runtime_against_expected", lambda *args: runtime_receipt
    )
    monkeypatch.setattr(
        metadata_script,
        "file_sha256",
        lambda path: (
            "3" * 64 if path == interpreter else hashlib.sha256(path.read_bytes()).hexdigest()
        ),
    )
    evidence = SimpleNamespace(metadata_hash="b" * 64, context_tokens=8192)

    class FakeAdapter:
        def __init__(self, _, **kwargs):
            pass

        def inspect(self):
            return evidence, None

    monkeypatch.setattr(metadata_script, "OllamaAdapter", FakeAdapter)
    metadata_output = tmp_path / "ollama-metadata.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_ollama_metadata.py",
            "--context",
            str(context_path),
            "--release-artifact",
            str(release),
            "--executable",
            str(executable),
            "--server-pid",
            "123",
            "--bridge-pid",
            "124",
            "--bridge-socket",
            str(bridge_socket),
            "--python-runtime",
            str(runtime_receipt_path),
            "--network-isolation",
            str(network_output),
            "--output",
            str(metadata_output),
        ],
    )
    metadata_script.main()
    receipt = json.loads(metadata_output.read_bytes())
    assert receipt["network_isolation"]["network_namespace_id"] == "net:[123]"
    assert receipt["network_isolation"]["executable_sha256"] == executable_sha
    assert receipt["bridge"]["destination_host"] == "127.0.0.1"


def test_context_builder_and_manifest_assembler_main_paths(tmp_path, monkeypatch):
    source = ROOT / "docs/evidence/stage3g-runtime-qualification-dfa5649"
    builder = load_script("build_intended_host_qualification_context")
    artifact = json.loads((source / "python-artifact/runtime-artifact.json").read_bytes())
    plan_path = ROOT / "docs/evidence/stage3g-v2-host-config/plan.json"
    plan_value = json.loads(plan_path.read_bytes())
    monkeypatch.setattr(builder, "clean_commit", lambda _: artifact["implementation_commit"])
    monkeypatch.setattr(builder, "build_plan", lambda *_: plan_value)
    existing_context = QualificationContextV1.model_validate_json(
        (source / "context.json").read_bytes()
    )
    ledger_path = tmp_path / "ledger-identity.json"
    ledger_path.write_text(
        json.dumps(existing_context.payload.ledger_expected.identity.model_dump(mode="json"))
    )
    context_output = tmp_path / "context.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "build_intended_host_qualification_context.py",
            "--environment",
            str(source / "environment.json"),
            "--runtime-artifact",
            str(source / "python-artifact/runtime-artifact.json"),
            "--runtime-build",
            str(source / "build.json"),
            "--evaluator-build",
            str(source / "evaluator-build.json"),
            "--protocol",
            str(ROOT / "benchmarks/real-protocol-v2.json"),
            "--plan",
            str(plan_path),
            "--ledger-identity",
            str(ledger_path),
            "--output",
            str(context_output),
        ],
    )
    builder.main()
    QualificationContextV1.model_validate_json(context_output.read_bytes())

    tree = tmp_path / "manifest-tree"
    _, manifest, original_manifest = qualification_tree(tree)
    assembler = load_script("assemble_intended_host_manifest")
    for kind, relative in assembler.RECEIPTS.items():
        reference = getattr(manifest.payload.receipts, kind)
        assert reference is not None
        target = tree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        source_receipt = tree / reference.relative_path
        if source_receipt != target:
            shutil.copyfile(source_receipt, target)
    original_manifest.unlink()
    output = tree / "final-manifest.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "assemble_intended_host_manifest.py",
            "--root",
            str(tree),
            "--context",
            str(tree / manifest.payload.context.relative_path),
            "--output",
            str(output),
        ],
    )
    assembler.main()
    assert json.loads(output.read_bytes())["payload"]["execution_ready"] is True
