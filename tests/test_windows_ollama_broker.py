import hashlib
import io
import json
import os
import platform
import secrets
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from devhub import windows_ollama_broker as BROKER
from devhub.native_bundle import (
    NATIVE_LOADER_FAILURE_STAGES,
    NativeLoaderAuthorityV2,
    NativeLoaderDependencyV1,
)
from devhub.windows_isolation import (
    NativePathIdentityV1,
    WindowsIsolationProfilePayloadV4,
    WindowsIsolationProfileV4,
    WindowsLauncherAuthorityV1,
    WindowsNativeImportExpectationV1,
    WindowsRuntimeAccessGrantPayloadV2,
    WindowsRuntimeAccessGrantV2,
    windows_launcher_locator_sha256,
)
from devhub.windows_ollama_broker import (
    _REQUEST_HEADER,
    WINDOWS_OLLAMA_DESTINATION_HOST,
    WINDOWS_OLLAMA_DESTINATION_PORT,
    WINDOWS_OLLAMA_MAX_REQUEST_BYTES,
    WINDOWS_OLLAMA_PROTOCOL_SHA256,
    WindowsOllamaBrokerAuthorityPayloadV1,
    WindowsOllamaBrokerAuthorityV1,
    WindowsOllamaBrokerObservationV1,
    WindowsOllamaBrokerProbePayloadV1,
    WindowsOllamaBrokerProbeV1,
    WindowsOllamaBrokerRuntimePayloadV1,
    WindowsOllamaBrokerRuntimeV1,
    WindowsOllamaListenerPayloadV1,
    WindowsOllamaListenerV1,
    WindowsOllamaMetadataQualificationV1,
    WindowsOllamaResponseFrame,
    WindowsProcessIdentityV1,
    _accept_pipe_client,
    _await_overlapped,
    _close_handle,
    _create_pipe,
    _fixed_ollama_request,
    _pipe_security_sddl,
    create_windows_ollama_broker_authority,
    decode_windows_ollama_request,
    decode_windows_ollama_response,
    encode_windows_ollama_request,
    encode_windows_ollama_response,
    qualify_windows_ollama_metadata,
    read_bounded_frame,
    windows_ollama_broker_launch_id,
    windows_ollama_pipe_sddl,
    windows_ollama_pipe_sddl_sha256,
)

pytestmark = pytest.mark.windows_smoke

ENVIRONMENT = "1" * 32
SID = "S-1-15-2-1-2-3-4-5-6-7"


class WinCall:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


def path_identity(locator: str, index: int) -> NativePathIdentityV1:
    return NativePathIdentityV1(
        locator=locator,
        volume_serial_number=123,
        file_index=f"{index:016x}",
    )


def broker_profile(
    *,
    native_bundle_id: str = "2" * 64,
    launcher_sha256: str = "4" * 64,
) -> WindowsIsolationProfileV4:
    loader = NativeLoaderAuthorityV2(
        build_receipt_sha256="1" * 64,
        native_loader_build_id="2" * 64,
        accepted_workflow_run_id=123,
        accepted_workflow_run_attempt=1,
        implementation_commit="3" * 40,
        source_sha256="4" * 64,
        binary_sha256="5" * 64,
        dependencies=tuple(
            NativeLoaderDependencyV1(filename=name, sha256=value * 64)
            for name, value in (
                ("libffi-8.dll", "6"),
                ("libcrypto-3.dll", "7"),
                ("libssl-3.dll", "8"),
            )
        ),
        failure_stages=NATIVE_LOADER_FAILURE_STAGES,
    )
    bundle_root = r"C:\qualification\bundle"
    launcher_locator = bundle_root + r"\python.exe"
    launcher = WindowsLauncherAuthorityV1(
        locator=launcher_locator,
        locator_sha256=windows_launcher_locator_sha256(launcher_locator),
        path_identity=path_identity(launcher_locator, 4),
        executable_sha256=launcher_sha256,
    )
    imports = tuple(
        WindowsNativeImportExpectationV1(
            module=module,
            relative_path=relative_path,
            expected_sha256=value * 64,
        )
        for module, relative_path, value in (
            ("_ctypes", "python/_ctypes.pyd", "9"),
            ("_socket", "python/_socket.pyd", "a"),
            ("_overlapped", "python/_overlapped.pyd", "b"),
            ("select", "python/select.pyd", "c"),
            ("_hashlib", "python/_hashlib.pyd", "d"),
            ("_ssl", "python/_ssl.pyd", "e"),
        )
    )
    return WindowsIsolationProfileV4.create(
        WindowsIsolationProfilePayloadV4(
            environment_instance_id=ENVIRONMENT,
            appcontainer_identity=f"devfabric_{ENVIRONMENT}",
            native_bundle_id=native_bundle_id,
            codex_executable_sha256="3" * 64,
            launcher_executable_sha256=launcher_sha256,
            probe_sha256="5" * 64,
            child_bootstrap_sha256="6" * 64,
            native_loader=loader,
            native_import_expectations=imports,
            launcher=launcher,
            read_only_roots=(path_identity(bundle_root, 1),),
            writable_roots=(path_identity(r"C:\qualification\workspace", 2),),
            denied_roots=(path_identity(r"C:\qualification\hidden", 3),),
        )
    )


def authority() -> WindowsOllamaBrokerAuthorityV1:
    profile = broker_profile()
    return WindowsOllamaBrokerAuthorityV1.create(
        WindowsOllamaBrokerAuthorityPayloadV1(
            environment_instance_id=ENVIRONMENT,
            native_bundle_id="2" * 64,
            baseline_windows_isolation_profile_id=profile.windows_isolation_profile_id,
            baseline_windows_isolation_receipt_id="9" * 64,
            baseline_windows_isolation_evidence_id="a" * 64,
            baseline_isolation_profile=profile,
            broker_isolation_profile=profile,
            host_control_root=profile.payload.denied_roots[0],
            appcontainer_identity=f"devfabric_{ENVIRONMENT}",
            appcontainer_sid=SID,
            pipe_name=r"\\.\pipe\devfabric-ollama-" + "3" * 32,
            pipe_sddl_sha256=windows_ollama_pipe_sddl_sha256(SID),
            broker_python_executable_sha256="4" * 64,
            broker_module_sha256="5" * 64,
            listener=WindowsOllamaListenerV1.create(
                WindowsOllamaListenerPayloadV1(
                    process=WindowsProcessIdentityV1(
                        process_id=123,
                        creation_time_100ns=456,
                        executable_sha256="6" * 64,
                        user_sid="S-1-5-21-1-2-3-1001",
                    )
                )
            ),
            ollama_version="0.34.2",
            ollama_model="qwen2.5:14b-instruct",
            ollama_model_digest="7" * 64,
        )
    )


def runtime_access_grant(
    value: WindowsOllamaBrokerAuthorityV1,
) -> WindowsRuntimeAccessGrantV2:
    profile = value.payload.broker_isolation_profile.payload
    return WindowsRuntimeAccessGrantV2.create(
        WindowsRuntimeAccessGrantPayloadV2(
            appcontainer_identity=profile.appcontainer_identity,
            appcontainer_sid=value.payload.appcontainer_sid,
            root=profile.read_only_roots[0],
            native_bundle_id=profile.native_bundle_id,
            launcher_executable_sha256=profile.launcher_executable_sha256,
            verified_entry_count=3,
            pre_create_acl_inventory_sha256="f" * 64,
            post_create_acl_inventory_sha256="f" * 64,
            post_create_repaired=False,
        )
    )


def runtime(value: WindowsOllamaBrokerAuthorityV1) -> WindowsOllamaBrokerRuntimeV1:
    return WindowsOllamaBrokerRuntimeV1.create(
        WindowsOllamaBrokerRuntimePayloadV1(
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            broker_launch_id=windows_ollama_broker_launch_id(value),
            broker_module_sha256=value.payload.broker_module_sha256,
            process=WindowsProcessIdentityV1(
                process_id=321,
                creation_time_100ns=654,
                executable_sha256=value.payload.broker_python_executable_sha256,
                user_sid=value.payload.listener.payload.process.user_sid,
            ),
            listener_id=value.payload.listener.windows_ollama_listener_id,
            pipe_name_sha256=hashlib.sha256(value.payload.pipe_name.encode()).hexdigest(),
        )
    )


def metadata_evidence(
    value: WindowsOllamaBrokerAuthorityV1,
    runtime_value: WindowsOllamaBrokerRuntimeV1,
) -> tuple[
    tuple[
        WindowsOllamaBrokerObservationV1,
        WindowsOllamaBrokerObservationV1,
        WindowsOllamaBrokerObservationV1,
    ],
    tuple[
        WindowsOllamaResponseFrame,
        WindowsOllamaResponseFrame,
        WindowsOllamaResponseFrame,
    ],
]:
    bodies = (
        b'{"version":"0.34.2"}',
        b'{"models":[{"name":"qwen2.5:14b-instruct","digest":"' + b"7" * 64 + b'"}]}',
        b'{"capabilities":["completion"],"model_info":{"qwen2.context_length":32768}}',
    )
    endpoints = (
        (1, "GET", "/api/version"),
        (2, "GET", "/api/tags"),
        (3, "POST", "/api/show"),
    )
    pipe_hash = hashlib.sha256(value.payload.pipe_name.encode()).hexdigest()
    observations = tuple(
        WindowsOllamaBrokerObservationV1(
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            windows_ollama_broker_runtime_id=runtime_value.windows_ollama_broker_runtime_id,
            pipe_name_sha256=pipe_hash,
            appcontainer_sid=SID,
            endpoint_code=code,
            method=method,
            path=path,
            request_bytes=44,
            response_bytes=len(body) + 44,
            response_status=200,
            response_body_sha256=hashlib.sha256(body).hexdigest(),
        )
        for (code, method, path), body in zip(endpoints, bodies, strict=True)
    )
    responses = tuple(WindowsOllamaResponseFrame(status=200, body=body) for body in bodies)
    return observations, responses  # type: ignore[return-value]


def test_broker_authority_is_self_hashed_and_fixed_destination():
    value = authority()
    assert value.payload.destination_host == WINDOWS_OLLAMA_DESTINATION_HOST
    assert value.payload.destination_port == WINDOWS_OLLAMA_DESTINATION_PORT
    assert value.payload.protocol_sha256 == WINDOWS_OLLAMA_PROTOCOL_SHA256
    assert value == WindowsOllamaBrokerAuthorityV1.model_validate_json(value.model_dump_json())
    changed = value.model_dump(mode="python")
    changed["windows_ollama_broker_authority_id"] = "f" * 64
    with pytest.raises(ValidationError, match="authority hash mismatch"):
        WindowsOllamaBrokerAuthorityV1.model_validate(changed)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("destination_host", "127.0.0.2", "Input should be '127.0.0.1'"),
        ("destination_port", 11435, "Input should be 11434"),
        ("protocol_sha256", "f" * 64, "Unsupported Windows Ollama broker protocol"),
        ("pipe_sddl_sha256", "f" * 64, "pipe DACL identity mismatch"),
        (
            "pipe_name",
            (r"\\.\pipe\devfabric-ollama-" + "3" * 32).replace("ollama", "ollamx"),
            "random locator form",
        ),
        ("appcontainer_sid", "S-1-15-2-1", "exact derived package SID"),
    ],
)
def test_broker_authority_rejects_substituted_authority(field, value, message):
    raw = authority().payload.model_dump(mode="python")
    raw[field] = value
    with pytest.raises(ValidationError, match=message):
        WindowsOllamaBrokerAuthorityPayloadV1.model_validate(raw)


def test_broker_authority_requires_exact_baseline_delta_and_denied_control_root():
    value = authority()
    raw = value.payload.model_dump(mode="python")
    changed_limits = value.payload.broker_isolation_profile.payload.job_limits.model_copy(
        update={"active_process_limit": 15}
    )
    changed_profile = WindowsIsolationProfileV4.create(
        value.payload.broker_isolation_profile.payload.model_copy(
            update={"job_limits": changed_limits}
        )
    )
    raw["broker_isolation_profile"] = changed_profile
    with pytest.raises(ValidationError, match="differs from its authority"):
        WindowsOllamaBrokerAuthorityPayloadV1.model_validate(raw)

    raw = value.payload.model_dump(mode="python")
    raw["host_control_root"] = path_identity(r"C:\qualification\other-hidden", 30)
    with pytest.raises(ValidationError, match="differs from its authority"):
        WindowsOllamaBrokerAuthorityPayloadV1.model_validate(raw)


def test_pipe_dacl_names_only_the_exact_package_sid():
    assert windows_ollama_pipe_sddl(SID) == f"D:P(A;;0x12019f;;;{SID})"
    assert "S-1-15-2-1" not in windows_ollama_pipe_sddl(SID).replace(SID, "")


@pytest.mark.skipif(platform.system() != "Windows", reason="requires Windows named pipes")
def test_pipe_creation_reads_back_exact_dacl_and_connect_timeout_cleans_pending_io():
    raw = authority().payload.model_dump(mode="python")
    raw["pipe_name"] = r"\\.\pipe\devfabric-ollama-" + secrets.token_hex(16)
    value = WindowsOllamaBrokerAuthorityV1.create(
        WindowsOllamaBrokerAuthorityPayloadV1.model_validate(raw)
    )
    handle = _create_pipe(value)
    try:
        assert _pipe_security_sddl(handle) == windows_ollama_pipe_sddl(SID)
        with pytest.raises(TimeoutError, match="connect timed out"):
            _accept_pipe_client(handle, 0)
    finally:
        _close_handle(handle)


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PROBE", "", b""),
        ("GET", "/api/version", b""),
        ("GET", "/api/tags", b""),
        (
            "POST",
            "/api/show",
            b'{"model":"qwen2.5:14b-instruct","verbose":true}',
        ),
    ],
)
def test_closed_request_frames_round_trip(method, path, body):
    value = authority()
    frame = encode_windows_ollama_request(value, method, path, body)
    observed = decode_windows_ollama_request(value, frame)
    assert (observed.endpoint.method, observed.endpoint.path, observed.body) == (
        method,
        path,
        body,
    )


def test_request_frame_rejects_endpoint_body_authority_and_length_substitution():
    value = authority()
    with pytest.raises(ValueError, match="not allowlisted"):
        encode_windows_ollama_request(value, "GET", "/api/delete", b"")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not allowlisted"):
        encode_windows_ollama_request(
            value,
            "POST",
            "/api/generate",  # type: ignore[arg-type]
            b'{"model":"qwen2.5:14b-instruct"}',
        )
    with pytest.raises(ValueError, match="metadata body differs"):
        encode_windows_ollama_request(
            value, "POST", "/api/show", b'{"model":"another","verbose":true}'
        )
    with pytest.raises(ValueError, match="body differs"):
        encode_windows_ollama_request(value, "GET", "/api/tags", b"x")
    with pytest.raises(json.JSONDecodeError):
        encode_windows_ollama_request(value, "POST", "/api/show", b"not-json")
    with pytest.raises(ValueError, match="byte bound"):
        encode_windows_ollama_request(
            value, "POST", "/api/show", b"{" + b" " * WINDOWS_OLLAMA_MAX_REQUEST_BYTES
        )

    frame = bytearray(encode_windows_ollama_request(value, "GET", "/api/version"))
    frame.extend(b"x")
    with pytest.raises(ValueError, match="length mismatch"):
        decode_windows_ollama_request(value, bytes(frame))
    frame = bytearray(encode_windows_ollama_request(value, "GET", "/api/version"))
    frame[16] ^= 1
    with pytest.raises(ValueError, match="authority mismatch"):
        decode_windows_ollama_request(value, bytes(frame))


def test_response_frame_is_bounded_and_authority_bound():
    value = authority()
    frame = encode_windows_ollama_response(value, 200, b'{"version":"0.34.2"}')
    assert decode_windows_ollama_response(value, frame).body == b'{"version":"0.34.2"}'
    wrong = bytearray(frame)
    wrong[16] ^= 1
    with pytest.raises(ValueError, match="authority mismatch"):
        decode_windows_ollama_response(value, bytes(wrong))
    with pytest.raises(ValueError, match="status is invalid"):
        encode_windows_ollama_response(value, 99, b"")


def test_bounded_reader_rejects_partial_and_oversized_frames():
    value = authority()
    frame = encode_windows_ollama_request(value, "GET", "/api/tags")
    assert (
        read_bounded_frame(
            io.BytesIO(frame),
            header=_REQUEST_HEADER,
            length_index=4,
            body_limit=WINDOWS_OLLAMA_MAX_REQUEST_BYTES,
        )
        == frame
    )
    with pytest.raises(ValueError, match="header is incomplete"):
        read_bounded_frame(
            io.BytesIO(frame[:4]),
            header=_REQUEST_HEADER,
            length_index=4,
            body_limit=WINDOWS_OLLAMA_MAX_REQUEST_BYTES,
        )
    oversized = bytearray(frame)
    oversized[8:12] = (WINDOWS_OLLAMA_MAX_REQUEST_BYTES + 1).to_bytes(4, "big")
    with pytest.raises(ValueError, match="body length is invalid"):
        read_bounded_frame(
            io.BytesIO(oversized),
            header=_REQUEST_HEADER,
            length_index=4,
            body_limit=WINDOWS_OLLAMA_MAX_REQUEST_BYTES,
        )


def test_live_message_reader_rejects_trailing_data():
    value = authority()
    frame = encode_windows_ollama_request(value, "GET", "/api/tags")

    class MessageStream:
        message_continues = False

        def __init__(self):
            self.offset = 0

        def read(self, size=-1):
            result = frame[self.offset : self.offset + size]
            self.offset += len(result)
            if self.offset == len(frame):
                self.message_continues = True
            return result

    with pytest.raises(ValueError, match="trailing data"):
        read_bounded_frame(
            MessageStream(),
            header=_REQUEST_HEADER,
            length_index=4,
            body_limit=WINDOWS_OLLAMA_MAX_REQUEST_BYTES,
        )


def test_metadata_probe_cannot_claim_model_or_provider_execution():
    value = authority()
    probe = WindowsOllamaBrokerProbeV1.create(
        WindowsOllamaBrokerProbePayloadV1(
            environment_instance_id=ENVIRONMENT,
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            windows_ollama_broker_runtime_id="b" * 64,
            appcontainer_sid=SID,
            pipe_name_sha256="6" * 64,
            pipe_sddl_sha256=value.payload.pipe_sddl_sha256,
            protocol_sha256=value.payload.protocol_sha256,
            observation=WindowsOllamaBrokerObservationV1(
                windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
                windows_ollama_broker_runtime_id="b" * 64,
                pipe_name_sha256="6" * 64,
                appcontainer_sid=SID,
                endpoint_code=0,
                method="PROBE",
                path="",
                request_bytes=44,
                response_bytes=44,
                response_status=204,
                response_body_sha256=(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
            ),
        )
    )
    assert probe.payload.ollama_requests == 0
    assert probe.payload.generation_requests == 0
    assert probe.payload.model_requests == 0
    assert probe.payload.provider_sends == 0
    assert probe == WindowsOllamaBrokerProbeV1.model_validate_json(probe.model_dump_json())
    raw = probe.payload.model_dump(mode="json")
    raw["provider_sends"] = 1
    with pytest.raises(ValidationError):
        WindowsOllamaBrokerProbePayloadV1.model_validate(raw)


def test_metadata_probe_endpoint_never_opens_ollama(monkeypatch):
    monkeypatch.setattr(
        "devhub.windows_ollama_broker.http.client.HTTPConnection",
        lambda *_args, **_kwargs: pytest.fail("metadata-only probe contacted Ollama"),
    )
    value = authority()
    frame = decode_windows_ollama_request(value, encode_windows_ollama_request(value, "PROBE", ""))
    response = _fixed_ollama_request(value, frame)
    assert response.status == 204
    assert response.body == b""


def test_overlapped_timeout_waits_for_terminal_cancellation(monkeypatch):
    calls: list[tuple[str, int]] = []

    class Kernel:
        WaitForSingleObject = WinCall(lambda _event, _timeout: BROKER._WAIT_TIMEOUT)
        CancelIoEx = WinCall(lambda _handle, _overlapped: calls.append(("cancel", 0)) or 1)
        GetOverlappedResult = WinCall(
            lambda _handle, _overlapped, _transferred, wait: calls.append(("complete", int(wait)))
            or 0
        )

    monkeypatch.setattr(BROKER, "_windows_dll", lambda _name: Kernel())
    monkeypatch.setattr(BROKER, "_last_error", lambda: BROKER._ERROR_OPERATION_ABORTED)
    monkeypatch.setattr(BROKER, "_close_handle", lambda handle: calls.append(("close", handle)))
    overlapped = BROKER._Overlapped(0, 0, 0, 0, 99)
    with pytest.raises(TimeoutError, match="timed out"):
        _await_overlapped(
            7,
            overlapped,
            started=False,
            error_code=BROKER._ERROR_IO_PENDING,
            timeout_seconds=1,
            operation="test",
        )
    assert calls == [("cancel", 0), ("complete", 1), ("close", 99)]


def test_wrong_appcontainer_sid_fails_and_cleans_exact_pipe(monkeypatch):
    value = authority()
    raw = value.payload.model_dump(mode="python")
    executable_sha256 = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    raw["broker_python_executable_sha256"] = executable_sha256
    changed_profile = broker_profile(launcher_sha256=executable_sha256)
    raw["baseline_windows_isolation_profile_id"] = changed_profile.windows_isolation_profile_id
    raw["baseline_isolation_profile"] = changed_profile
    raw["broker_isolation_profile"] = changed_profile
    raw["broker_module_sha256"] = hashlib.sha256(Path(BROKER.__file__).read_bytes()).hexdigest()
    value = WindowsOllamaBrokerAuthorityV1.create(
        WindowsOllamaBrokerAuthorityPayloadV1.model_validate(raw)
    )
    runtime_value = WindowsOllamaBrokerRuntimeV1.create(
        WindowsOllamaBrokerRuntimePayloadV1(
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            broker_launch_id=windows_ollama_broker_launch_id(value),
            broker_module_sha256=value.payload.broker_module_sha256,
            process=WindowsProcessIdentityV1(
                process_id=os.getpid(),
                creation_time_100ns=1,
                executable_sha256=value.payload.broker_python_executable_sha256,
                user_sid=value.payload.listener.payload.process.user_sid,
            ),
            listener_id=value.payload.listener.windows_ollama_listener_id,
            pipe_name_sha256=hashlib.sha256(value.payload.pipe_name.encode()).hexdigest(),
        )
    )
    calls: list[tuple[str, int]] = []

    class Kernel:
        DisconnectNamedPipe = WinCall(lambda handle: calls.append(("disconnect", int(handle))) or 1)

    monkeypatch.setattr(BROKER.platform, "system", lambda: "Windows")
    monkeypatch.setattr(BROKER, "validate_windows_ollama_broker_runtime", lambda *_args: None)
    monkeypatch.setattr(BROKER, "_create_pipe", lambda _authority: 77)
    monkeypatch.setattr(BROKER, "_accept_pipe_client", lambda *_args: None)
    monkeypatch.setattr(BROKER, "_pipe_client_sid", lambda _handle: "S-1-15-2-9-9-9-9-9-9-9")
    monkeypatch.setattr(BROKER, "_windows_dll", lambda _name: Kernel())
    monkeypatch.setattr(BROKER, "_close_handle", lambda handle: calls.append(("close", handle)))
    with pytest.raises(ValueError, match="SID mismatch"):
        BROKER.serve_one_windows_ollama_request(value, runtime_value)
    assert calls == [("disconnect", 77), ("close", 77)]


def test_runtime_validation_rejects_changed_server_process(monkeypatch):
    value = authority()
    runtime_value = runtime(value)
    changed = runtime_value.payload.process.model_copy(update={"creation_time_100ns": 655})
    monkeypatch.setattr(BROKER, "_process_identity", lambda _pid: changed)
    with pytest.raises(ValueError, match="runtime identity changed"):
        BROKER.validate_windows_ollama_broker_runtime(value, runtime_value)


def test_authority_builder_joins_bundle_isolation_listener_and_exact_bytes(
    tmp_path: Path, monkeypatch
):
    python = tmp_path / "python/python.exe"
    module = tmp_path / "python/site-packages/devhub/windows_ollama_broker.py"
    python.parent.mkdir(parents=True)
    module.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    module.write_bytes(b"broker")
    python_hash = hashlib.sha256(python.read_bytes()).hexdigest()
    module_hash = hashlib.sha256(module.read_bytes()).hexdigest()
    reviewed_profile = broker_profile(launcher_sha256=python_hash)
    root_identity = reviewed_profile.payload.read_only_roots[0]
    bundle = SimpleNamespace(
        bundle_id="2" * 64,
        payload=SimpleNamespace(
            python=SimpleNamespace(
                executable_path="python/python.exe",
                executable_sha256=python_hash,
            ),
            files=(
                SimpleNamespace(path="python/python.exe", sha256=python_hash),
                SimpleNamespace(
                    path="python/site-packages/devhub/windows_ollama_broker.py",
                    sha256=module_hash,
                ),
            ),
        ),
    )
    grant = SimpleNamespace(
        appcontainer_identity=f"devfabric_{ENVIRONMENT}",
        appcontainer_sid=SID,
        native_bundle_id=bundle.bundle_id,
    )
    isolation = SimpleNamespace(
        windows_isolation_evidence_id="a" * 64,
        profile=reviewed_profile,
        receipt=SimpleNamespace(
            windows_isolation_receipt_id="9" * 64,
            payload=SimpleNamespace(
                runtime_access_grant=SimpleNamespace(payload=grant),
                environment_instance_id=ENVIRONMENT,
                windows_isolation_profile_id=reviewed_profile.windows_isolation_profile_id,
            ),
        ),
    )
    verified: list[tuple[object, Path]] = []
    monkeypatch.setattr(
        "devhub.windows_ollama_broker.verify_native_bundle",
        lambda value, root, **_kwargs: verified.append((value, root)),
    )
    monkeypatch.setattr(
        "devhub.windows_ollama_broker.windows_path_identity", lambda _root: root_identity
    )
    monkeypatch.setattr(
        "devhub.windows_ollama_broker.validate_windows_ollama_listener", lambda _value: None
    )
    listener = authority().payload.listener
    result = create_windows_ollama_broker_authority(
        bundle=bundle,  # type: ignore[arg-type]
        bundle_root=tmp_path,
        isolation=isolation,  # type: ignore[arg-type]
        broker_profile=reviewed_profile,
        listener=listener,
        pipe_name=r"\\.\pipe\devfabric-ollama-" + "b" * 32,
        ollama_version="0.34.2",
        ollama_model="qwen2.5:14b-instruct",
        ollama_model_digest="7" * 64,
    )
    assert verified == [(bundle, tmp_path)]
    assert result.payload.native_bundle_id == bundle.bundle_id
    assert result.payload.broker_python_executable_sha256 == python_hash
    assert result.payload.broker_module_sha256 == module_hash
    isolation.receipt.payload.environment_instance_id = "f" * 32
    with pytest.raises(ValueError, match="one retained authority"):
        create_windows_ollama_broker_authority(
            bundle=bundle,  # type: ignore[arg-type]
            bundle_root=tmp_path,
            isolation=isolation,  # type: ignore[arg-type]
            broker_profile=reviewed_profile,
            listener=listener,
            pipe_name=r"\\.\pipe\devfabric-ollama-" + "c" * 32,
            ollama_version="0.34.2",
            ollama_model="qwen2.5:14b-instruct",
            ollama_model_digest="7" * 64,
        )


def test_disposable_profile_and_authority_use_real_windows_path_identities(
    tmp_path: Path, monkeypatch
):
    if platform.system() != "Windows":
        pytest.skip("Windows native path identity regression")
    source = tmp_path / "source"
    execution = tmp_path / "execution"
    writable = tmp_path / "writable"
    denied = tmp_path / "denied"
    python = source / "python/python.exe"
    module = source / "python/site-packages/devhub/windows_ollama_broker.py"
    python.parent.mkdir(parents=True)
    module.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    module.write_bytes(b"broker")
    shutil.copytree(source, execution)
    writable.mkdir()
    denied.mkdir()
    python_hash = hashlib.sha256(python.read_bytes()).hexdigest()
    module_hash = hashlib.sha256(module.read_bytes()).hexdigest()
    bundle_id = "2" * 64
    baseline_profile = broker_profile(
        native_bundle_id=bundle_id,
        launcher_sha256=python_hash,
    )
    grant = SimpleNamespace(
        appcontainer_identity=f"devfabric_{ENVIRONMENT}",
        appcontainer_sid=SID,
        native_bundle_id=bundle_id,
    )
    isolation = SimpleNamespace(
        windows_isolation_evidence_id="a" * 64,
        profile=baseline_profile,
        receipt=SimpleNamespace(
            windows_isolation_receipt_id="9" * 64,
            payload=SimpleNamespace(
                runtime_access_grant=SimpleNamespace(payload=grant),
                environment_instance_id=ENVIRONMENT,
                windows_isolation_profile_id=baseline_profile.windows_isolation_profile_id,
            ),
        ),
    )
    bundle = SimpleNamespace(
        bundle_id=bundle_id,
        payload=SimpleNamespace(
            python=SimpleNamespace(
                executable_path="python/python.exe",
                executable_sha256=python_hash,
            ),
            files=(
                SimpleNamespace(path="python/python.exe", sha256=python_hash),
                SimpleNamespace(
                    path="python/site-packages/devhub/windows_ollama_broker.py",
                    sha256=module_hash,
                ),
            ),
        ),
    )
    monkeypatch.setattr(BROKER, "verify_native_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(BROKER, "validate_windows_ollama_listener", lambda _value: None)
    profile = BROKER.create_windows_ollama_broker_profile(
        bundle=bundle,  # type: ignore[arg-type]
        execution_bundle_root=execution,
        writable_root=writable,
        denied_root=denied,
        isolation=isolation,  # type: ignore[arg-type]
    )
    retained = BROKER.create_windows_ollama_broker_authority(
        bundle=bundle,  # type: ignore[arg-type]
        bundle_root=execution,
        isolation=isolation,  # type: ignore[arg-type]
        broker_profile=profile,
        listener=authority().payload.listener,
        pipe_name=r"\\.\pipe\devfabric-ollama-" + "d" * 32,
        ollama_version="0.34.2",
        ollama_model="qwen2.5:14b-instruct",
        ollama_model_digest="7" * 64,
    )
    assert profile.payload.read_only_roots == (BROKER.windows_path_identity(execution),)
    assert profile.payload.writable_roots == (BROKER.windows_path_identity(writable),)
    assert profile.payload.denied_roots == (BROKER.windows_path_identity(denied),)
    assert retained.payload.broker_isolation_profile == profile
    assert retained.payload.baseline_windows_isolation_evidence_id == "a" * 64


def test_metadata_qualification_is_derived_from_exact_observed_sequence(monkeypatch):
    value = authority()
    runtime_value = runtime(value)
    monkeypatch.setattr(
        "devhub.windows_ollama_broker.validate_windows_ollama_broker_runtime",
        lambda *_args: None,
    )
    bodies = (
        b'{"version":"0.34.2"}',
        b'{"models":[{"name":"qwen2.5:14b-instruct","digest":"' + b"7" * 64 + b'"}]}',
        b'{"capabilities":["completion"],"model_info":{"qwen2.context_length":32768}}',
    )
    endpoint_values = (
        (1, "GET", "/api/version"),
        (2, "GET", "/api/tags"),
        (3, "POST", "/api/show"),
    )
    observations = tuple(
        WindowsOllamaBrokerObservationV1(
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            windows_ollama_broker_runtime_id=runtime_value.windows_ollama_broker_runtime_id,
            pipe_name_sha256=hashlib.sha256(value.payload.pipe_name.encode()).hexdigest(),
            appcontainer_sid=SID,
            endpoint_code=code,
            method=method,
            path=path,
            request_bytes=44,
            response_bytes=len(body) + 44,
            response_status=200,
            response_body_sha256=hashlib.sha256(body).hexdigest(),
        )
        for (code, method, path), body in zip(endpoint_values, bodies, strict=True)
    )
    responses = tuple(WindowsOllamaResponseFrame(status=200, body=body) for body in bodies)
    receipt = qualify_windows_ollama_metadata(
        value,
        runtime_value,
        observations,  # type: ignore[arg-type]
        responses,  # type: ignore[arg-type]
    )
    assert receipt.payload.ollama_metadata_requests == 3
    assert receipt.payload.generation_requests == 0
    assert receipt.payload.model_requests == 0
    assert receipt.payload.provider_sends == 0
    assert receipt == WindowsOllamaMetadataQualificationV1.model_validate_json(
        receipt.model_dump_json()
    )
    wrong = list(responses)
    wrong[0] = WindowsOllamaResponseFrame(status=200, body=b'{"version":"0.35.0"}')
    with pytest.raises(ValueError, match="differs from broker observation"):
        qualify_windows_ollama_metadata(
            value,
            runtime_value,
            observations,  # type: ignore[arg-type]
            tuple(wrong),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("windows_ollama_broker_authority_id", "f" * 64),
        ("broker_launch_id", "f" * 64),
        ("broker_module_sha256", "f" * 64),
        ("listener_id", "f" * 64),
        ("pipe_name_sha256", "f" * 64),
    ],
)
def test_runtime_validation_rejects_every_authority_substitution(monkeypatch, field, changed):
    value = authority()
    runtime_value = runtime(value)
    payload = runtime_value.payload.model_copy(update={field: changed})
    substituted = WindowsOllamaBrokerRuntimeV1.create(payload)
    monkeypatch.setattr(BROKER, "_process_identity", lambda _pid: substituted.payload.process)
    with pytest.raises(ValueError, match="runtime identity changed"):
        BROKER.validate_windows_ollama_broker_runtime(value, substituted)


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("executable_sha256", "f" * 64),
        ("user_sid", "S-1-5-21-9-9-9-1001"),
    ],
)
def test_runtime_validation_rejects_process_authority_substitution(monkeypatch, field, changed):
    value = authority()
    runtime_value = runtime(value)
    process = runtime_value.payload.process.model_copy(update={field: changed})
    substituted = WindowsOllamaBrokerRuntimeV1.create(
        runtime_value.payload.model_copy(update={"process": process})
    )
    monkeypatch.setattr(BROKER, "_process_identity", lambda _pid: process)
    with pytest.raises(ValueError, match="runtime identity changed"):
        BROKER.validate_windows_ollama_broker_runtime(value, substituted)


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("windows_ollama_broker_authority_id", "f" * 64),
        ("windows_ollama_broker_runtime_id", "f" * 64),
        ("pipe_name_sha256", "f" * 64),
        ("appcontainer_sid", "S-1-15-2-9-9-9-9-9-9-9"),
    ],
)
def test_metadata_rejects_observation_authority_substitution(monkeypatch, field, changed):
    value = authority()
    runtime_value = runtime(value)
    observations, responses = metadata_evidence(value, runtime_value)
    replaced = list(observations)
    replaced[0] = replaced[0].model_copy(update={field: changed})
    monkeypatch.setattr(BROKER, "validate_windows_ollama_broker_runtime", lambda *_args: None)
    with pytest.raises(ValueError, match="differs from broker observation"):
        qualify_windows_ollama_metadata(
            value,
            runtime_value,
            tuple(replaced),  # type: ignore[arg-type]
            responses,
        )


def test_server_process_requires_typed_exact_completion_ack(tmp_path: Path, monkeypatch):
    value = authority()
    runtime_value = runtime(value)
    observations, _responses = metadata_evidence(value, runtime_value)
    authority_path = tmp_path / "authority.json"
    runtime_path = tmp_path / "runtime.json"
    server_path = tmp_path / "server.json"
    ack_path = tmp_path / "ack.json"
    BROKER._write_contract_exclusive(authority_path, value)
    expected = BROKER.WindowsOllamaBrokerServerResultV1.create(
        BROKER.WindowsOllamaBrokerServerResultPayloadV1(
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            windows_ollama_broker_runtime_id=runtime_value.windows_ollama_broker_runtime_id,
            observations=observations,
        )
    )
    BROKER._write_contract_exclusive(
        ack_path,
        BROKER._CompletionAckV1(value=expected.windows_ollama_broker_server_result_id),
    )
    monkeypatch.setattr(
        BROKER, "observe_windows_ollama_broker_runtime", lambda *_args: runtime_value
    )
    monkeypatch.setattr(
        BROKER, "serve_windows_ollama_metadata_sequence", lambda *_args: observations
    )
    assert BROKER._serve_metadata_process(authority_path, runtime_path, server_path, ack_path) == 0
    assert (
        BROKER._read_contract(
            server_path, BROKER.WindowsOllamaBrokerServerResultV1, byte_limit=1024 * 1024
        )
        == expected
    )


def test_native_qualification_uses_exact_bundled_module_and_appcontainer_launcher(
    tmp_path: Path, monkeypatch
):
    value = authority()
    runtime_value = runtime(value)
    observations, responses = metadata_evidence(value, runtime_value)
    server_result = BROKER.WindowsOllamaBrokerServerResultV1.create(
        BROKER.WindowsOllamaBrokerServerResultPayloadV1(
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            windows_ollama_broker_runtime_id=runtime_value.windows_ollama_broker_runtime_id,
            observations=observations,
        )
    )
    response_evidence = tuple(
        BROKER.WindowsOllamaResponseEvidenceV1.create(response) for response in responses
    )
    client_result = BROKER.WindowsOllamaBrokerClientResultV1.create(
        BROKER.WindowsOllamaBrokerClientResultPayloadV1(
            windows_ollama_broker_authority_id=value.windows_ollama_broker_authority_id,
            windows_ollama_broker_runtime_id=runtime_value.windows_ollama_broker_runtime_id,
            responses=response_evidence,  # type: ignore[arg-type]
        )
    )
    monkeypatch.setattr(BROKER, "validate_windows_ollama_broker_runtime", lambda *_args: None)
    metadata = qualify_windows_ollama_metadata(value, runtime_value, observations, responses)
    bundle_root = tmp_path / "bundle"
    control_root = tmp_path / "control"
    client_root = tmp_path / "client"
    bundle_root.mkdir()
    control_root.mkdir()
    client_root.mkdir()
    interpreter = bundle_root / "python.exe"
    interpreter.write_bytes(b"python")
    bundle = SimpleNamespace(
        bundle_id=value.payload.native_bundle_id,
        payload=SimpleNamespace(
            python=SimpleNamespace(
                executable_path="python.exe",
                executable_sha256=value.payload.broker_python_executable_sha256,
            )
        ),
    )
    isolation = SimpleNamespace(
        windows_isolation_evidence_id=value.payload.baseline_windows_isolation_evidence_id,
        profile=SimpleNamespace(
            payload=SimpleNamespace(
                read_only_roots=(),
                writable_roots=(),
            )
        ),
    )
    isolation.profile.windows_isolation_profile_id = "8" * 64
    isolation.receipt = SimpleNamespace(
        windows_isolation_receipt_id="9" * 64,
        payload=SimpleNamespace(environment_instance_id=ENVIRONMENT),
    )
    commands: list[tuple[object, ...]] = []
    broker_process = SimpleNamespace(
        pid=321,
        poll=lambda: None,
        wait=lambda timeout=None: 0,
        terminate=lambda: pytest.fail("successful broker was terminated"),
        kill=lambda: pytest.fail("successful broker was killed"),
    )

    def popen(command, **kwargs):
        commands.append(("broker", tuple(command), kwargs))
        return broker_process

    class ClientProcess:
        appcontainer_sid = SID
        runtime_access_grant = runtime_access_grant(value)

        @staticmethod
        def wait(_timeout):
            return 0

        @staticmethod
        def close():
            return True

    def launch(profile, executable, arguments, **kwargs):
        commands.append(("client", profile, executable, arguments, kwargs))
        assert kwargs["verify_runtime_bundle"](bundle_root) == bundle.bundle_id
        output = Path(arguments[arguments.index("--client-result-output") + 1])
        BROKER._write_contract_exclusive(output, client_result)
        return ClientProcess()

    def wait_for(path, _model, _process, **_kwargs):
        return runtime_value if path.name == "runtime.json" else server_result

    monkeypatch.setattr(BROKER.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        BROKER,
        "windows_path_identity",
        lambda root, **_kwargs: SimpleNamespace(locator=str(Path(root).resolve())),
    )
    monkeypatch.setattr(
        BROKER,
        "create_windows_ollama_broker_profile",
        lambda **_kwargs: value.payload.broker_isolation_profile,
    )
    monkeypatch.setattr(BROKER, "create_windows_ollama_broker_authority", lambda **_kw: value)
    monkeypatch.setattr(BROKER.subprocess, "Popen", popen)
    monkeypatch.setattr(BROKER, "_wait_for_contract", wait_for)
    monkeypatch.setattr(BROKER, "verify_native_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(BROKER, "launch_windows_isolated", launch)
    monkeypatch.setattr(BROKER, "qualify_windows_ollama_metadata", lambda *_args: metadata)
    result = BROKER.qualify_windows_ollama_native(
        bundle=bundle,  # type: ignore[arg-type]
        bundle_root=bundle_root,
        isolation=isolation,  # type: ignore[arg-type]
        listener=value.payload.listener,
        control_root=control_root,
        client_root=client_root,
        ollama_version="0.34.2",
        ollama_model="qwen2.5:14b-instruct",
        ollama_model_digest="7" * 64,
    )
    broker_command = commands[0][1]
    assert Path(broker_command[0]).name == interpreter.name
    assert Path(broker_command[0]) != interpreter
    assert broker_command[1:5] == (
        "-I",
        "-B",
        "-m",
        "devhub.windows_ollama_broker",
    )
    client_arguments = commands[1][3]
    assert client_arguments[:5] == (
        "-I",
        "-B",
        "-m",
        "devhub.windows_ollama_broker",
        "client-metadata",
    )
    assert result.payload.native_executor_isolation_qualified is False
    assert result.payload.package_readiness is False
    assert result.payload.metadata.payload.model_requests == 0
    assert result.payload.metadata.payload.provider_sends == 0

    replaced_responses = list(result.payload.client_result.payload.responses)
    replaced_responses[0] = BROKER.WindowsOllamaResponseEvidenceV1.create(
        WindowsOllamaResponseFrame(status=200, body=b'{"version":"0.35.0"}')
    )
    substituted_client = BROKER.WindowsOllamaBrokerClientResultV1.create(
        result.payload.client_result.payload.model_copy(
            update={"responses": tuple(replaced_responses)}
        )
    )
    with pytest.raises(ValidationError, match="version differs from authority"):
        BROKER.WindowsOllamaNativeQualificationPayloadV1.model_validate(
            result.payload.model_copy(update={"client_result": substituted_client}).model_dump(
                mode="python"
            )
        )

    changed_observations = list(result.payload.metadata.payload.observations)
    changed_observations[0] = changed_observations[0].model_copy(
        update={"request_bytes": changed_observations[0].request_bytes + 1}
    )
    substituted_metadata = WindowsOllamaMetadataQualificationV1.create(
        result.payload.metadata.payload.model_copy(
            update={"observations": tuple(changed_observations)}
        )
    )
    with pytest.raises(ValidationError, match="mixes authorities"):
        BROKER.WindowsOllamaNativeQualificationPayloadV1.model_validate(
            result.payload.model_copy(update={"metadata": substituted_metadata}).model_dump(
                mode="python"
            )
        )

    substituted_grant = WindowsRuntimeAccessGrantV2.create(
        result.payload.runtime_access_grant.payload.model_copy(
            update={"root": path_identity(r"C:\qualification\substituted-runtime", 31)}
        )
    )
    with pytest.raises(ValidationError, match="mixes authorities"):
        BROKER.WindowsOllamaNativeQualificationPayloadV1.model_validate(
            result.payload.model_copy(
                update={"runtime_access_grant": substituted_grant}
            ).model_dump(mode="python")
        )

    substituted_show = (
        b'{"capabilities":["completion"],"remote_host":"remote.example",'
        b'"model_info":{"qwen2.context_length":32768}}'
    )
    semantic_responses = list(result.payload.client_result.payload.responses)
    semantic_responses[2] = BROKER.WindowsOllamaResponseEvidenceV1.create(
        WindowsOllamaResponseFrame(status=200, body=substituted_show)
    )
    semantic_client = BROKER.WindowsOllamaBrokerClientResultV1.create(
        result.payload.client_result.payload.model_copy(
            update={"responses": tuple(semantic_responses)}
        )
    )
    semantic_observations = list(result.payload.server_result.payload.observations)
    semantic_observations[2] = semantic_observations[2].model_copy(
        update={
            "response_bytes": len(substituted_show) + 44,
            "response_body_sha256": hashlib.sha256(substituted_show).hexdigest(),
        }
    )
    semantic_server = BROKER.WindowsOllamaBrokerServerResultV1.create(
        result.payload.server_result.payload.model_copy(
            update={"observations": tuple(semantic_observations)}
        )
    )
    semantic_metadata = WindowsOllamaMetadataQualificationV1.create(
        result.payload.metadata.payload.model_copy(
            update={
                "observations": tuple(semantic_observations),
                "show_metadata_sha256": result.payload.metadata.payload.show_metadata_sha256,
            }
        )
    )
    with pytest.raises(ValidationError, match="capability or locality is invalid"):
        BROKER.WindowsOllamaNativeQualificationPayloadV1.model_validate(
            result.payload.model_copy(
                update={
                    "client_result": semantic_client,
                    "server_result": semantic_server,
                    "metadata": semantic_metadata,
                }
            ).model_dump(mode="python")
        )


def _native_staging_inputs(tmp_path: Path):
    source = tmp_path / "source"
    control = tmp_path / "control"
    client = tmp_path / "client"
    source.mkdir()
    control.mkdir()
    client.mkdir()
    interpreter = source / "python.exe"
    interpreter.write_bytes(b"reviewed-python")
    interpreter_sha256 = hashlib.sha256(interpreter.read_bytes()).hexdigest()
    bundle = SimpleNamespace(
        bundle_id="2" * 64,
        payload=SimpleNamespace(
            python=SimpleNamespace(
                executable_path="python.exe",
                executable_sha256=interpreter_sha256,
            )
        ),
    )
    isolation = SimpleNamespace(
        profile=broker_profile(
            native_bundle_id=bundle.bundle_id,
            launcher_sha256=interpreter_sha256,
        )
    )
    return bundle, isolation, source, control, client, interpreter.read_bytes()


@pytest.mark.skipif(platform.system() != "Windows", reason="requires Windows path identity")
def test_native_staging_removes_every_disposable_root_and_reverifies_source(
    tmp_path: Path, monkeypatch
):
    bundle, isolation, source, control, client, source_bytes = _native_staging_inputs(tmp_path)
    verified: list[Path] = []
    monkeypatch.setattr(
        BROKER,
        "verify_native_bundle",
        lambda _bundle, root, **_kwargs: verified.append(Path(root)),
    )
    retained = object()
    monkeypatch.setattr(
        BROKER,
        "_qualify_windows_ollama_native_staged",
        lambda **_kwargs: retained,
    )
    result = BROKER.qualify_windows_ollama_native(
        bundle=bundle,  # type: ignore[arg-type]
        bundle_root=source,
        isolation=isolation,  # type: ignore[arg-type]
        listener=authority().payload.listener,
        control_root=control,
        client_root=client,
        ollama_version="0.34.2",
        ollama_model="qwen2.5:14b-instruct",
        ollama_model_digest="7" * 64,
    )
    assert result is retained
    assert list(control.iterdir()) == []
    assert list(client.iterdir()) == []
    assert (source / "python.exe").read_bytes() == source_bytes
    assert verified.count(source) == 2
    assert len([root for root in verified if root != source]) == 3


@pytest.mark.skipif(platform.system() != "Windows", reason="requires Windows path identity")
def test_native_staging_failure_cleans_all_roots_and_preserves_source(tmp_path: Path, monkeypatch):
    bundle, isolation, source, control, client, source_bytes = _native_staging_inputs(tmp_path)
    monkeypatch.setattr(BROKER, "verify_native_bundle", lambda *_args, **_kwargs: None)

    def fail_staged(**_kwargs):
        raise RuntimeError("injected staged failure")

    monkeypatch.setattr(BROKER, "_qualify_windows_ollama_native_staged", fail_staged)
    with pytest.raises(RuntimeError, match="injected staged failure"):
        BROKER.qualify_windows_ollama_native(
            bundle=bundle,  # type: ignore[arg-type]
            bundle_root=source,
            isolation=isolation,  # type: ignore[arg-type]
            listener=authority().payload.listener,
            control_root=control,
            client_root=client,
            ollama_version="0.34.2",
            ollama_model="qwen2.5:14b-instruct",
            ollama_model_digest="7" * 64,
        )
    assert list(control.iterdir()) == []
    assert list(client.iterdir()) == []
    assert (source / "python.exe").read_bytes() == source_bytes


@pytest.mark.skipif(platform.system() != "Windows", reason="requires Windows path identity")
def test_native_staging_aggregates_operation_and_cleanup_failures(tmp_path: Path, monkeypatch):
    bundle, isolation, source, control, client, source_bytes = _native_staging_inputs(tmp_path)
    monkeypatch.setattr(BROKER, "verify_native_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        BROKER,
        "_qualify_windows_ollama_native_staged",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("injected staged failure")),
    )
    original_rmtree = shutil.rmtree

    def remove_then_fail(path, *args, **kwargs):
        original_rmtree(path, *args, **kwargs)
        if str(path).endswith("-runtime"):
            raise OSError("injected cleanup failure")

    monkeypatch.setattr(BROKER.shutil, "rmtree", remove_then_fail)
    with pytest.raises(BaseExceptionGroup) as captured:
        BROKER.qualify_windows_ollama_native(
            bundle=bundle,  # type: ignore[arg-type]
            bundle_root=source,
            isolation=isolation,  # type: ignore[arg-type]
            listener=authority().payload.listener,
            control_root=control,
            client_root=client,
            ollama_version="0.34.2",
            ollama_model="qwen2.5:14b-instruct",
            ollama_model_digest="7" * 64,
        )
    messages = [str(error) for error in captured.value.exceptions]
    assert any("staged failure" in message for message in messages)
    assert any("cleanup failure" in message for message in messages)
    assert list(control.iterdir()) == []
    assert list(client.iterdir()) == []
    assert (source / "python.exe").read_bytes() == source_bytes


@pytest.mark.skipif(platform.system() != "Windows", reason="requires Windows path identity")
def test_native_staging_rejects_parent_identity_substitution_after_cleanup(
    tmp_path: Path, monkeypatch
):
    bundle, isolation, source, control, client, source_bytes = _native_staging_inputs(tmp_path)
    monkeypatch.setattr(BROKER, "verify_native_bundle", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        BROKER,
        "_qualify_windows_ollama_native_staged",
        lambda **_kwargs: object(),
    )
    original_identity = BROKER.windows_path_identity
    calls: dict[Path, int] = {}

    def substituted_parent_identity(path, **kwargs):
        resolved = Path(path).resolve()
        identity = original_identity(path, **kwargs)
        if resolved in {control.resolve(), client.resolve()}:
            calls[resolved] = calls.get(resolved, 0) + 1
            if calls[resolved] == 2:
                return identity.model_copy(update={"file_index": "f" * 16})
        return identity

    monkeypatch.setattr(BROKER, "windows_path_identity", substituted_parent_identity)
    with pytest.raises(BaseExceptionGroup, match="disposable-root cleanup failed"):
        BROKER.qualify_windows_ollama_native(
            bundle=bundle,  # type: ignore[arg-type]
            bundle_root=source,
            isolation=isolation,  # type: ignore[arg-type]
            listener=authority().payload.listener,
            control_root=control,
            client_root=client,
            ollama_version="0.34.2",
            ollama_model="qwen2.5:14b-instruct",
            ollama_model_digest="7" * 64,
        )
    assert list(control.iterdir()) == []
    assert list(client.iterdir()) == []
    assert (source / "python.exe").read_bytes() == source_bytes
