"""Fixed-destination Windows transport for an isolated DevFabric runtime.

The AppContainer never receives a network capability.  It connects to one
host-created named pipe whose DACL names the exact package SID.  The broker
maps a closed endpoint code to the fixed Ollama loopback listener; neither the
pipe client nor repository data can select a destination.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import http.client
import json
import os
import platform
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Protocol, cast

from pydantic import Field, field_validator, model_validator

from devhub.benchmark import canonical, digest
from devhub.brain_models import Digest
from devhub.models import Contract
from devhub.native_bundle import NativeBundleV1, verify_native_bundle
from devhub.windows_identity import validate_appcontainer_package_sid
from devhub.windows_isolation import (
    NativePathIdentityV1,
    WindowsIsolationEvidenceV6,
    WindowsIsolationProfileV4,
    WindowsLauncherAuthorityV1,
    WindowsRuntimeAccessGrantV2,
    launch_windows_isolated,
    windows_launcher_locator_sha256,
    windows_path_identity,
)

WINDOWS_OLLAMA_DESTINATION_HOST: Literal["127.0.0.1"] = "127.0.0.1"
WINDOWS_OLLAMA_DESTINATION_PORT: Literal[11434] = 11434
WINDOWS_OLLAMA_PIPE_PREFIX = r"\\.\pipe\devfabric-ollama-"
WINDOWS_OLLAMA_MAX_REQUEST_BYTES = 16_000_000
WINDOWS_OLLAMA_MAX_RESPONSE_BYTES = 16_000_000
WINDOWS_OLLAMA_IO_TIMEOUT_SECONDS = 60

_PIPE_NAME = re.compile(r"^\\\\\.\\pipe\\devfabric-ollama-[a-f0-9]{32}$")
_REQUEST_MAGIC = b"DFOB"
_RESPONSE_MAGIC = b"DFOR"
_ACK_MAGIC = b"DFOA"
_REQUEST_HEADER = struct.Struct("!4sBBHII32s")
_RESPONSE_HEADER = struct.Struct("!4sB3xII32s")
_ACK = struct.Struct("!4sB3x32s")

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_SECURITY_SQOS_PRESENT = 0x00100000
_SECURITY_IDENTIFICATION = 0x00010000
_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_FILE_FLAG_OVERLAPPED = 0x40000000
_PIPE_TYPE_MESSAGE = 0x00000004
_PIPE_READMODE_MESSAGE = 0x00000002
_PIPE_WAIT = 0
_PIPE_REJECT_REMOTE_CLIENTS = 0x8
_ERROR_PIPE_CONNECTED = 535
_ERROR_BROKEN_PIPE = 109
_ERROR_MORE_DATA = 234
_ERROR_OPERATION_ABORTED = 995
_ERROR_IO_PENDING = 997
_ERROR_NOT_FOUND = 1168
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_SE_KERNEL_OBJECT = 6
_DACL_SECURITY_INFORMATION = 0x00000004
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_IS_APPCONTAINER = 29
_TOKEN_APPCONTAINER_SID = 31
_SDDL_REVISION_1 = 1
_AF_INET = 2
_TCP_TABLE_OWNER_PID_LISTENER = 3
_MIB_TCP_STATE_LISTEN = 2
_ERROR_INSUFFICIENT_BUFFER = 122


@dataclass(frozen=True)
class WindowsOllamaEndpoint:
    code: int
    method: Literal["PROBE", "GET", "POST"]
    path: Literal["", "/api/version", "/api/tags", "/api/show"]


WINDOWS_OLLAMA_ENDPOINTS = (
    WindowsOllamaEndpoint(0, "PROBE", ""),
    WindowsOllamaEndpoint(1, "GET", "/api/version"),
    WindowsOllamaEndpoint(2, "GET", "/api/tags"),
    WindowsOllamaEndpoint(3, "POST", "/api/show"),
)
_ENDPOINT_BY_CODE = {item.code: item for item in WINDOWS_OLLAMA_ENDPOINTS}
_ENDPOINT_BY_REQUEST = {(item.method, item.path): item for item in WINDOWS_OLLAMA_ENDPOINTS}

WINDOWS_OLLAMA_PROTOCOL_SHA256 = digest(
    canonical(
        {
            "destination": [WINDOWS_OLLAMA_DESTINATION_HOST, WINDOWS_OLLAMA_DESTINATION_PORT],
            "endpoints": [
                {
                    "code": item.code,
                    "method": item.method,
                    "path": item.path,
                }
                for item in WINDOWS_OLLAMA_ENDPOINTS
            ],
            "request_header": "!4sBBHII32s",
            "request_magic": _REQUEST_MAGIC.decode("ascii"),
            "response_header": "!4sB3xII32s",
            "response_magic": _RESPONSE_MAGIC.decode("ascii"),
            "ack_header": "!4sB3x32s",
            "ack_magic": _ACK_MAGIC.decode("ascii"),
            "pipe_mode": "message",
            "max_request_bytes": WINDOWS_OLLAMA_MAX_REQUEST_BYTES,
            "max_response_bytes": WINDOWS_OLLAMA_MAX_RESPONSE_BYTES,
            "io_timeout_seconds": WINDOWS_OLLAMA_IO_TIMEOUT_SECONDS,
        }
    )
)


class WindowsProcessIdentityV1(Contract):
    process_id: Annotated[int, Field(ge=1)]
    creation_time_100ns: Annotated[int, Field(ge=1)]
    executable_sha256: Digest
    user_sid: Annotated[str, Field(pattern=r"^S-1-(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*)){1,14}$")]


class WindowsOllamaListenerPayloadV1(Contract):
    process: WindowsProcessIdentityV1
    destination_host: Literal["127.0.0.1"] = WINDOWS_OLLAMA_DESTINATION_HOST
    destination_port: Literal[11434] = WINDOWS_OLLAMA_DESTINATION_PORT
    listener_owner_verified: Literal[True] = True


class WindowsOllamaListenerV1(Contract):
    windows_ollama_listener_id: Digest
    payload: WindowsOllamaListenerPayloadV1

    @classmethod
    def create(cls, payload: WindowsOllamaListenerPayloadV1) -> WindowsOllamaListenerV1:
        return cls(
            windows_ollama_listener_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaListenerV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_listener_id != expected:
            raise ValueError("Windows Ollama listener hash mismatch")
        return self


def windows_ollama_pipe_sddl(appcontainer_sid: str) -> str:
    """Return the protected DACL granting only the exact package SID pipe access."""

    sid = validate_appcontainer_package_sid(appcontainer_sid)
    # FILE_GENERIC_READ | FILE_GENERIC_WRITE after Windows generic-rights
    # mapping. It deliberately excludes WRITE_DAC, WRITE_OWNER and DELETE.
    return f"D:P(A;;0x12019f;;;{sid})"


def windows_ollama_pipe_sddl_sha256(appcontainer_sid: str) -> str:
    return hashlib.sha256(windows_ollama_pipe_sddl(appcontainer_sid).encode()).hexdigest()


class WindowsOllamaBrokerAuthorityPayloadV1(Contract):
    """Host-owned expected authority for one disposable named-pipe broker."""

    platform: Literal["windows"] = "windows"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    native_bundle_id: Digest
    baseline_windows_isolation_profile_id: Digest
    baseline_windows_isolation_receipt_id: Digest
    baseline_windows_isolation_evidence_id: Digest
    baseline_isolation_profile: WindowsIsolationProfileV4
    broker_isolation_profile: WindowsIsolationProfileV4
    host_control_root: NativePathIdentityV1
    appcontainer_identity: Annotated[str, Field(pattern=r"^devfabric_[a-f0-9]{32}$")]
    appcontainer_sid: str
    pipe_name: Annotated[str, Field(min_length=58, max_length=58)]
    pipe_sddl_sha256: Digest
    protocol_sha256: Digest = WINDOWS_OLLAMA_PROTOCOL_SHA256
    broker_python_executable_sha256: Digest
    broker_module_sha256: Digest
    listener: WindowsOllamaListenerV1
    ollama_version: Literal["0.34.2", "0.35.0"]
    ollama_model: Annotated[str, Field(min_length=1, max_length=200)]
    ollama_model_digest: Digest
    destination_host: Literal["127.0.0.1"] = WINDOWS_OLLAMA_DESTINATION_HOST
    destination_port: Literal[11434] = WINDOWS_OLLAMA_DESTINATION_PORT
    max_request_bytes: Literal[16000000] = 16000000
    max_response_bytes: Literal[16000000] = 16000000
    io_timeout_seconds: Literal[60] = 60

    @field_validator("appcontainer_sid")
    @classmethod
    def exact_package_sid(cls, value: str) -> str:
        return validate_appcontainer_package_sid(value)

    @field_validator("pipe_name")
    @classmethod
    def exact_pipe_locator(cls, value: str) -> str:
        if _PIPE_NAME.fullmatch(value) is None:
            raise ValueError("Ollama broker pipe must use the exact random locator form")
        return value

    @field_validator("protocol_sha256")
    @classmethod
    def exact_protocol(cls, value: str) -> str:
        if value != WINDOWS_OLLAMA_PROTOCOL_SHA256:
            raise ValueError("Unsupported Windows Ollama broker protocol")
        return value

    @model_validator(mode="after")
    def exact_authority(self) -> WindowsOllamaBrokerAuthorityPayloadV1:
        if self.appcontainer_identity != f"devfabric_{self.environment_instance_id}":
            raise ValueError("Broker AppContainer identity differs from its environment")
        baseline_profile = self.baseline_isolation_profile.payload
        broker_profile = self.broker_isolation_profile.payload
        baseline_values = baseline_profile.model_dump(mode="python")
        broker_values = broker_profile.model_dump(mode="python")
        for field in ("launcher", "read_only_roots", "writable_roots", "denied_roots"):
            baseline_values.pop(field)
            broker_values.pop(field)
        if (
            self.baseline_isolation_profile.windows_isolation_profile_id
            != self.baseline_windows_isolation_profile_id
            or baseline_values != broker_values
            or broker_profile.environment_instance_id != self.environment_instance_id
            or broker_profile.native_bundle_id != self.native_bundle_id
            or broker_profile.appcontainer_identity != self.appcontainer_identity
            or broker_profile.launcher_executable_sha256 != self.broker_python_executable_sha256
            or len(broker_profile.read_only_roots) != 1
            or len(broker_profile.writable_roots) != 1
            or len(broker_profile.denied_roots) != 1
            or broker_profile.denied_roots[0] != self.host_control_root
        ):
            raise ValueError("Broker isolation profile differs from its authority")
        if self.pipe_sddl_sha256 != windows_ollama_pipe_sddl_sha256(self.appcontainer_sid):
            raise ValueError("Broker pipe DACL identity mismatch")
        if (
            self.listener.payload.destination_host != self.destination_host
            or self.listener.payload.destination_port != self.destination_port
        ):
            raise ValueError("Broker listener differs from its fixed destination")
        return self


class WindowsOllamaBrokerAuthorityV1(Contract):
    windows_ollama_broker_authority_id: Digest
    payload: WindowsOllamaBrokerAuthorityPayloadV1

    @classmethod
    def create(
        cls, payload: WindowsOllamaBrokerAuthorityPayloadV1
    ) -> WindowsOllamaBrokerAuthorityV1:
        return cls(
            windows_ollama_broker_authority_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaBrokerAuthorityV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_broker_authority_id != expected:
            raise ValueError("Windows Ollama broker authority hash mismatch")
        return self


def windows_ollama_broker_launch_id(authority: WindowsOllamaBrokerAuthorityV1) -> str:
    """Identify the sole reviewed host broker entrypoint and immutable bytes."""

    return digest(
        canonical(
            {
                "python_executable_sha256": authority.payload.broker_python_executable_sha256,
                "module": "devhub.windows_ollama_broker",
                "module_sha256": authority.payload.broker_module_sha256,
                "argv_prefix": ["-I", "-B", "-m", "devhub.windows_ollama_broker"],
                "mode": "serve-metadata",
                "protocol_sha256": authority.payload.protocol_sha256,
            }
        )
    )


def create_windows_ollama_broker_authority(
    *,
    bundle: NativeBundleV1,
    bundle_root: Path,
    isolation: WindowsIsolationEvidenceV6,
    broker_profile: WindowsIsolationProfileV4,
    listener: WindowsOllamaListenerV1,
    pipe_name: str,
    ollama_version: Literal["0.34.2", "0.35.0"],
    ollama_model: str,
    ollama_model_digest: str,
) -> WindowsOllamaBrokerAuthorityV1:
    """Derive broker authority from exact retained production evidence.

    Callers cannot independently supply the bundle, SID, interpreter, broker
    module, or isolation identities.  The path is only a locator and is
    re-inventoried before any authority is returned.
    """

    verify_native_bundle(
        bundle,
        bundle_root,
        expected_platform="windows",
        expected_architecture="x86_64",
    )
    validate_windows_ollama_listener(listener)
    baseline_profile = isolation.profile.payload
    receipt = isolation.receipt.payload
    grant = receipt.runtime_access_grant.payload
    profile = broker_profile.payload
    if (
        baseline_profile.native_bundle_id != bundle.bundle_id
        or grant.native_bundle_id != bundle.bundle_id
        or baseline_profile.environment_instance_id != receipt.environment_instance_id
        or baseline_profile.appcontainer_identity != grant.appcontainer_identity
        or isolation.profile.windows_isolation_profile_id != receipt.windows_isolation_profile_id
        or profile.native_bundle_id != bundle.bundle_id
        or profile.environment_instance_id != baseline_profile.environment_instance_id
        or profile.appcontainer_identity != baseline_profile.appcontainer_identity
        or windows_path_identity(bundle_root) != profile.read_only_roots[0]
    ):
        raise ValueError("Windows broker inputs do not form one retained authority")
    interpreter_path = bundle_root.joinpath(*bundle.payload.python.executable_path.split("/"))
    broker_module_relative = "python/site-packages/devhub/windows_ollama_broker.py"
    broker_module_path = bundle_root.joinpath(*broker_module_relative.split("/"))
    inventory = {item.path: item.sha256 for item in bundle.payload.files}
    if (
        inventory.get(bundle.payload.python.executable_path)
        != bundle.payload.python.executable_sha256
        or inventory.get(broker_module_relative) != _file_sha256(broker_module_path)
        or _file_sha256(interpreter_path) != bundle.payload.python.executable_sha256
    ):
        raise ValueError("Windows broker runtime bytes differ from the native bundle")
    return WindowsOllamaBrokerAuthorityV1.create(
        WindowsOllamaBrokerAuthorityPayloadV1(
            environment_instance_id=profile.environment_instance_id,
            native_bundle_id=bundle.bundle_id,
            baseline_windows_isolation_profile_id=(isolation.profile.windows_isolation_profile_id),
            baseline_windows_isolation_receipt_id=(isolation.receipt.windows_isolation_receipt_id),
            baseline_windows_isolation_evidence_id=isolation.windows_isolation_evidence_id,
            baseline_isolation_profile=isolation.profile,
            broker_isolation_profile=broker_profile,
            host_control_root=profile.denied_roots[0],
            appcontainer_identity=profile.appcontainer_identity,
            appcontainer_sid=grant.appcontainer_sid,
            pipe_name=pipe_name,
            pipe_sddl_sha256=windows_ollama_pipe_sddl_sha256(grant.appcontainer_sid),
            broker_python_executable_sha256=bundle.payload.python.executable_sha256,
            broker_module_sha256=inventory[broker_module_relative],
            listener=listener,
            ollama_version=ollama_version,
            ollama_model=ollama_model,
            ollama_model_digest=ollama_model_digest,
        )
    )


def create_windows_ollama_broker_profile(
    *,
    bundle: NativeBundleV1,
    execution_bundle_root: Path,
    writable_root: Path,
    denied_root: Path,
    isolation: WindowsIsolationEvidenceV6,
) -> WindowsIsolationProfileV4:
    """Derive one fresh broker-client profile from the retained V6 baseline."""

    verify_native_bundle(
        bundle,
        execution_bundle_root,
        expected_platform="windows",
        expected_architecture="x86_64",
    )
    baseline = isolation.profile.payload
    if baseline.native_bundle_id != bundle.bundle_id:
        raise ValueError("Windows broker baseline differs from the native bundle")
    interpreter = execution_bundle_root.joinpath(*bundle.payload.python.executable_path.split("/"))
    launcher_identity = windows_path_identity(interpreter, require_directory=False)
    launcher = WindowsLauncherAuthorityV1(
        locator=launcher_identity.locator,
        locator_sha256=windows_launcher_locator_sha256(launcher_identity.locator),
        path_identity=launcher_identity,
        executable_sha256=bundle.payload.python.executable_sha256,
    )
    payload_values = baseline.model_dump(mode="python")
    payload_values.update(
        {
            "launcher": launcher,
            "read_only_roots": (windows_path_identity(execution_bundle_root),),
            "writable_roots": (windows_path_identity(writable_root),),
            "denied_roots": (windows_path_identity(denied_root),),
        }
    )
    payload = type(baseline).model_validate(payload_values)
    return WindowsIsolationProfileV4.create(payload)


class WindowsOllamaBrokerRuntimePayloadV1(Contract):
    windows_ollama_broker_authority_id: Digest
    broker_launch_id: Digest
    broker_module_sha256: Digest
    process: WindowsProcessIdentityV1
    listener_id: Digest
    pipe_name_sha256: Digest


class WindowsOllamaBrokerRuntimeV1(Contract):
    windows_ollama_broker_runtime_id: Digest
    payload: WindowsOllamaBrokerRuntimePayloadV1

    @classmethod
    def create(cls, payload: WindowsOllamaBrokerRuntimePayloadV1) -> WindowsOllamaBrokerRuntimeV1:
        return cls(
            windows_ollama_broker_runtime_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaBrokerRuntimeV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_broker_runtime_id != expected:
            raise ValueError("Windows Ollama broker runtime hash mismatch")
        return self


class WindowsOllamaBrokerProbePayloadV1(Contract):
    """Metadata-only observation; it cannot represent an Ollama request."""

    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_ollama_broker_authority_id: Digest
    windows_ollama_broker_runtime_id: Digest
    appcontainer_sid: str
    pipe_name_sha256: Digest
    pipe_sddl_sha256: Digest
    protocol_sha256: Digest
    observation: WindowsOllamaBrokerObservationV1
    pipe_cleanup_verified: Literal[True] = True
    destination_host: Literal["127.0.0.1"] = WINDOWS_OLLAMA_DESTINATION_HOST
    destination_port: Literal[11434] = WINDOWS_OLLAMA_DESTINATION_PORT
    ollama_requests: Literal[0] = 0
    generation_requests: Literal[0] = 0
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0

    @field_validator("appcontainer_sid")
    @classmethod
    def exact_package_sid(cls, value: str) -> str:
        return validate_appcontainer_package_sid(value)

    @model_validator(mode="after")
    def exact_probe(self) -> WindowsOllamaBrokerProbePayloadV1:
        if (
            self.observation.windows_ollama_broker_authority_id
            != self.windows_ollama_broker_authority_id
            or self.observation.windows_ollama_broker_runtime_id
            != self.windows_ollama_broker_runtime_id
            or self.observation.pipe_name_sha256 != self.pipe_name_sha256
            or self.observation.appcontainer_sid != self.appcontainer_sid
            or self.observation.method != "PROBE"
            or self.observation.path != ""
            or self.observation.endpoint_code != 0
            or self.observation.response_status != 204
            or self.observation.response_body_sha256 != hashlib.sha256(b"").hexdigest()
        ):
            raise ValueError("Windows broker probe observation is invalid")
        return self


class WindowsOllamaBrokerProbeV1(Contract):
    windows_ollama_broker_probe_id: Digest
    payload: WindowsOllamaBrokerProbePayloadV1

    @classmethod
    def create(cls, payload: WindowsOllamaBrokerProbePayloadV1) -> WindowsOllamaBrokerProbeV1:
        return cls(
            windows_ollama_broker_probe_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @classmethod
    def from_observation(
        cls,
        authority: WindowsOllamaBrokerAuthorityV1,
        runtime: WindowsOllamaBrokerRuntimeV1,
        observation: WindowsOllamaBrokerObservationV1,
    ) -> WindowsOllamaBrokerProbeV1:
        validate_windows_ollama_broker_runtime(authority, runtime)
        return cls.create(
            WindowsOllamaBrokerProbePayloadV1(
                environment_instance_id=authority.payload.environment_instance_id,
                windows_ollama_broker_authority_id=(authority.windows_ollama_broker_authority_id),
                windows_ollama_broker_runtime_id=(runtime.windows_ollama_broker_runtime_id),
                appcontainer_sid=authority.payload.appcontainer_sid,
                pipe_name_sha256=hashlib.sha256(authority.payload.pipe_name.encode()).hexdigest(),
                pipe_sddl_sha256=authority.payload.pipe_sddl_sha256,
                protocol_sha256=authority.payload.protocol_sha256,
                observation=observation,
            )
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaBrokerProbeV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_broker_probe_id != expected:
            raise ValueError("Windows Ollama broker probe hash mismatch")
        return self


@dataclass(frozen=True)
class WindowsOllamaRequestFrame:
    endpoint: WindowsOllamaEndpoint
    body: bytes


@dataclass(frozen=True)
class WindowsOllamaResponseFrame:
    status: int
    body: bytes


class WindowsOllamaBrokerObservationV1(Contract):
    windows_ollama_broker_authority_id: Digest
    windows_ollama_broker_runtime_id: Digest
    pipe_name_sha256: Digest
    appcontainer_sid: str
    endpoint_code: Annotated[int, Field(ge=0, le=3)]
    method: Literal["PROBE", "GET", "POST"]
    path: Literal["", "/api/version", "/api/tags", "/api/show"]
    request_bytes: Annotated[int, Field(ge=1, le=16_001_000)]
    response_bytes: Annotated[int, Field(ge=1, le=16_001_000)]
    response_status: Annotated[int, Field(ge=100, le=599)]
    response_body_sha256: Digest

    @field_validator("appcontainer_sid")
    @classmethod
    def exact_package_sid(cls, value: str) -> str:
        return validate_appcontainer_package_sid(value)

    @model_validator(mode="after")
    def exact_endpoint(self) -> WindowsOllamaBrokerObservationV1:
        endpoint = _ENDPOINT_BY_CODE.get(self.endpoint_code)
        if endpoint is None or (endpoint.method, endpoint.path) != (self.method, self.path):
            raise ValueError("Windows broker observation endpoint is inconsistent")
        return self


class WindowsOllamaMetadataQualificationPayloadV1(Contract):
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_ollama_broker_authority_id: Digest
    windows_ollama_broker_runtime_id: Digest
    windows_ollama_listener_id: Digest
    windows_isolation_evidence_id: Digest
    pipe_name_sha256: Digest
    observations: Annotated[
        tuple[
            WindowsOllamaBrokerObservationV1,
            WindowsOllamaBrokerObservationV1,
            WindowsOllamaBrokerObservationV1,
        ],
        Field(min_length=3, max_length=3),
    ]
    ollama_version: Literal["0.34.2", "0.35.0"]
    ollama_model: Annotated[str, Field(min_length=1, max_length=200)]
    ollama_model_digest: Digest
    show_metadata_sha256: Digest
    ollama_metadata_requests: Literal[3] = 3
    generation_requests: Literal[0] = 0
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0

    @model_validator(mode="after")
    def exact_metadata_sequence(self) -> WindowsOllamaMetadataQualificationPayloadV1:
        expected = ((1, "GET", "/api/version"), (2, "GET", "/api/tags"), (3, "POST", "/api/show"))
        observed = tuple((item.endpoint_code, item.method, item.path) for item in self.observations)
        if (
            observed != expected
            or any(item.response_status != 200 for item in self.observations)
            or any(
                item.windows_ollama_broker_authority_id != self.windows_ollama_broker_authority_id
                or item.windows_ollama_broker_runtime_id != self.windows_ollama_broker_runtime_id
                or item.pipe_name_sha256 != self.pipe_name_sha256
                for item in self.observations
            )
        ):
            raise ValueError("Windows Ollama metadata sequence is incomplete")
        return self


class WindowsOllamaMetadataQualificationV1(Contract):
    windows_ollama_metadata_qualification_id: Digest
    payload: WindowsOllamaMetadataQualificationPayloadV1

    @classmethod
    def create(
        cls, payload: WindowsOllamaMetadataQualificationPayloadV1
    ) -> WindowsOllamaMetadataQualificationV1:
        return cls(
            windows_ollama_metadata_qualification_id=digest(
                canonical(payload.model_dump(mode="json"))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaMetadataQualificationV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_metadata_qualification_id != expected:
            raise ValueError("Windows Ollama metadata qualification hash mismatch")
        return self


class WindowsOllamaResponseEvidenceV1(Contract):
    status: Annotated[int, Field(ge=100, le=599)]
    body_base64: str
    body_sha256: Digest

    @classmethod
    def create(cls, response: WindowsOllamaResponseFrame) -> WindowsOllamaResponseEvidenceV1:
        return cls(
            status=response.status,
            body_base64=base64.b64encode(response.body).decode("ascii"),
            body_sha256=hashlib.sha256(response.body).hexdigest(),
        )

    @model_validator(mode="after")
    def exact_body(self) -> WindowsOllamaResponseEvidenceV1:
        try:
            body = base64.b64decode(self.body_base64, validate=True)
        except ValueError as error:
            raise ValueError("Windows Ollama response is not canonical base64") from error
        if (
            base64.b64encode(body).decode("ascii") != self.body_base64
            or len(body) > WINDOWS_OLLAMA_MAX_RESPONSE_BYTES
            or hashlib.sha256(body).hexdigest() != self.body_sha256
        ):
            raise ValueError("Windows Ollama response evidence differs from its body")
        return self

    def response(self) -> WindowsOllamaResponseFrame:
        return WindowsOllamaResponseFrame(
            status=self.status,
            body=base64.b64decode(self.body_base64, validate=True),
        )


class WindowsOllamaBrokerServerResultPayloadV1(Contract):
    windows_ollama_broker_authority_id: Digest
    windows_ollama_broker_runtime_id: Digest
    observations: Annotated[
        tuple[
            WindowsOllamaBrokerObservationV1,
            WindowsOllamaBrokerObservationV1,
            WindowsOllamaBrokerObservationV1,
        ],
        Field(min_length=3, max_length=3),
    ]
    pipe_cleanup_verified: Literal[True] = True

    @model_validator(mode="after")
    def exact_joins(self) -> WindowsOllamaBrokerServerResultPayloadV1:
        if any(
            item.windows_ollama_broker_authority_id != self.windows_ollama_broker_authority_id
            or item.windows_ollama_broker_runtime_id != self.windows_ollama_broker_runtime_id
            for item in self.observations
        ):
            raise ValueError("Windows broker server result mixes authorities")
        return self


class WindowsOllamaBrokerServerResultV1(Contract):
    windows_ollama_broker_server_result_id: Digest
    payload: WindowsOllamaBrokerServerResultPayloadV1

    @classmethod
    def create(
        cls, payload: WindowsOllamaBrokerServerResultPayloadV1
    ) -> WindowsOllamaBrokerServerResultV1:
        return cls(
            windows_ollama_broker_server_result_id=digest(
                canonical(payload.model_dump(mode="json"))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaBrokerServerResultV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_broker_server_result_id != expected:
            raise ValueError("Windows broker server result hash mismatch")
        return self


class WindowsOllamaBrokerClientResultPayloadV1(Contract):
    windows_ollama_broker_authority_id: Digest
    windows_ollama_broker_runtime_id: Digest
    responses: Annotated[
        tuple[
            WindowsOllamaResponseEvidenceV1,
            WindowsOllamaResponseEvidenceV1,
            WindowsOllamaResponseEvidenceV1,
        ],
        Field(min_length=3, max_length=3),
    ]
    generation_requests: Literal[0] = 0
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0


class WindowsOllamaBrokerClientResultV1(Contract):
    windows_ollama_broker_client_result_id: Digest
    payload: WindowsOllamaBrokerClientResultPayloadV1

    @classmethod
    def create(
        cls, payload: WindowsOllamaBrokerClientResultPayloadV1
    ) -> WindowsOllamaBrokerClientResultV1:
        return cls(
            windows_ollama_broker_client_result_id=digest(
                canonical(payload.model_dump(mode="json"))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaBrokerClientResultV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_broker_client_result_id != expected:
            raise ValueError("Windows broker client result hash mismatch")
        return self


class WindowsOllamaNativeQualificationPayloadV1(Contract):
    authority: WindowsOllamaBrokerAuthorityV1
    runtime: WindowsOllamaBrokerRuntimeV1
    server_result: WindowsOllamaBrokerServerResultV1
    client_result: WindowsOllamaBrokerClientResultV1
    metadata: WindowsOllamaMetadataQualificationV1
    runtime_access_grant: WindowsRuntimeAccessGrantV2
    windows_isolation_evidence_id: Digest
    appcontainer_sid: str
    broker_exit_code: Literal[0] = 0
    client_exit_code: Literal[0] = 0
    appcontainer_cleanup_verified: Literal[True] = True
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False

    @field_validator("appcontainer_sid")
    @classmethod
    def exact_package_sid(cls, value: str) -> str:
        return validate_appcontainer_package_sid(value)

    @model_validator(mode="after")
    def exact_joins(self) -> WindowsOllamaNativeQualificationPayloadV1:
        authority_id = self.authority.windows_ollama_broker_authority_id
        runtime_id = self.runtime.windows_ollama_broker_runtime_id
        authority = self.authority.payload
        metadata = self.metadata.payload
        grant = self.runtime_access_grant.payload
        responses = self.client_result.payload.responses
        response_observations_match = all(
            response.status == observation.response_status
            and response.body_sha256 == observation.response_body_sha256
            for response, observation in zip(
                responses, self.server_result.payload.observations, strict=True
            )
        )
        retained_responses = cast(
            tuple[
                WindowsOllamaResponseFrame,
                WindowsOllamaResponseFrame,
                WindowsOllamaResponseFrame,
            ],
            tuple(item.response() for item in responses),
        )
        retained_show_metadata_sha256 = validate_windows_ollama_retained_metadata(
            self.authority,
            retained_responses,
        )
        if (
            self.runtime.payload.windows_ollama_broker_authority_id != authority_id
            or self.server_result.payload.windows_ollama_broker_authority_id != authority_id
            or self.client_result.payload.windows_ollama_broker_authority_id != authority_id
            or self.metadata.payload.windows_ollama_broker_authority_id != authority_id
            or self.server_result.payload.windows_ollama_broker_runtime_id != runtime_id
            or self.client_result.payload.windows_ollama_broker_runtime_id != runtime_id
            or self.metadata.payload.windows_ollama_broker_runtime_id != runtime_id
            or authority.baseline_windows_isolation_evidence_id
            != self.windows_isolation_evidence_id
            or authority.appcontainer_sid != self.appcontainer_sid
            or grant.appcontainer_identity != authority.appcontainer_identity
            or grant.appcontainer_sid != self.appcontainer_sid
            or grant.root != authority.broker_isolation_profile.payload.read_only_roots[0]
            or grant.native_bundle_id != authority.native_bundle_id
            or grant.launcher_executable_sha256 != authority.broker_python_executable_sha256
            or grant.pre_create_acl_inventory_sha256 != grant.post_create_acl_inventory_sha256
            or metadata.environment_instance_id != authority.environment_instance_id
            or metadata.windows_ollama_listener_id != authority.listener.windows_ollama_listener_id
            or metadata.windows_isolation_evidence_id
            != authority.baseline_windows_isolation_evidence_id
            or metadata.pipe_name_sha256 != hashlib.sha256(authority.pipe_name.encode()).hexdigest()
            or metadata.observations != self.server_result.payload.observations
            or any(
                observation.appcontainer_sid != authority.appcontainer_sid
                for observation in metadata.observations
            )
            or metadata.ollama_version != authority.ollama_version
            or metadata.ollama_model != authority.ollama_model
            or metadata.ollama_model_digest != authority.ollama_model_digest
            or metadata.show_metadata_sha256 != retained_show_metadata_sha256
            or not response_observations_match
            or metadata.generation_requests != 0
            or metadata.model_requests != 0
            or metadata.provider_sends != 0
            or self.client_result.payload.generation_requests != 0
            or self.client_result.payload.model_requests != 0
            or self.client_result.payload.provider_sends != 0
        ):
            raise ValueError("Windows Ollama native qualification mixes authorities")
        return self


class WindowsOllamaNativeQualificationV1(Contract):
    windows_ollama_native_qualification_id: Digest
    payload: WindowsOllamaNativeQualificationPayloadV1

    @classmethod
    def create(
        cls, payload: WindowsOllamaNativeQualificationPayloadV1
    ) -> WindowsOllamaNativeQualificationV1:
        return cls(
            windows_ollama_native_qualification_id=digest(
                canonical(payload.model_dump(mode="json"))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsOllamaNativeQualificationV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_ollama_native_qualification_id != expected:
            raise ValueError("Windows Ollama native qualification hash mismatch")
        return self


def validate_windows_ollama_retained_metadata(
    authority: WindowsOllamaBrokerAuthorityV1,
    responses: tuple[
        WindowsOllamaResponseFrame,
        WindowsOllamaResponseFrame,
        WindowsOllamaResponseFrame,
    ],
) -> str:
    """Re-parse retained Ollama responses and return exact show metadata identity."""

    try:
        version = json.loads(responses[0].body)
        tags = json.loads(responses[1].body)
        show = json.loads(responses[2].body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Windows Ollama metadata response is not valid JSON") from error
    if version != {"version": authority.payload.ollama_version}:
        raise ValueError("Windows Ollama version differs from authority")
    models = tags.get("models") if isinstance(tags, dict) else None
    matches = (
        [
            item
            for item in models
            if isinstance(item, dict) and item.get("name") == authority.payload.ollama_model
        ]
        if isinstance(models, list)
        else []
    )
    if (
        len(matches) != 1
        or matches[0].get("digest") != authority.payload.ollama_model_digest
        or matches[0].get("remote_host")
        or matches[0].get("remote_model")
    ):
        raise ValueError("Windows Ollama model identity differs from authority")
    if (
        not isinstance(show, dict)
        or show.get("remote_host")
        or show.get("remote_model")
        or "completion" not in show.get("capabilities", [])
        or not isinstance(show.get("model_info"), dict)
    ):
        raise ValueError("Windows Ollama metadata capability or locality is invalid")
    return digest(canonical(show["model_info"]))


def qualify_windows_ollama_metadata(
    authority: WindowsOllamaBrokerAuthorityV1,
    runtime: WindowsOllamaBrokerRuntimeV1,
    observations: tuple[
        WindowsOllamaBrokerObservationV1,
        WindowsOllamaBrokerObservationV1,
        WindowsOllamaBrokerObservationV1,
    ],
    responses: tuple[
        WindowsOllamaResponseFrame,
        WindowsOllamaResponseFrame,
        WindowsOllamaResponseFrame,
    ],
) -> WindowsOllamaMetadataQualificationV1:
    """Validate the actual closed metadata sequence and derive its receipt."""

    validate_windows_ollama_broker_runtime(authority, runtime)
    expected_pipe = hashlib.sha256(authority.payload.pipe_name.encode()).hexdigest()
    for observation, response in zip(observations, responses, strict=True):
        if (
            observation.windows_ollama_broker_authority_id
            != authority.windows_ollama_broker_authority_id
            or observation.windows_ollama_broker_runtime_id
            != runtime.windows_ollama_broker_runtime_id
            or observation.pipe_name_sha256 != expected_pipe
            or observation.appcontainer_sid != authority.payload.appcontainer_sid
            or observation.response_status != response.status
            or observation.response_body_sha256 != hashlib.sha256(response.body).hexdigest()
        ):
            raise ValueError("Windows Ollama metadata response differs from broker observation")
    show_metadata_sha256 = validate_windows_ollama_retained_metadata(authority, responses)
    return WindowsOllamaMetadataQualificationV1.create(
        WindowsOllamaMetadataQualificationPayloadV1(
            environment_instance_id=authority.payload.environment_instance_id,
            windows_ollama_broker_authority_id=(authority.windows_ollama_broker_authority_id),
            windows_ollama_broker_runtime_id=runtime.windows_ollama_broker_runtime_id,
            windows_ollama_listener_id=authority.payload.listener.windows_ollama_listener_id,
            windows_isolation_evidence_id=(
                authority.payload.baseline_windows_isolation_evidence_id
            ),
            pipe_name_sha256=expected_pipe,
            observations=observations,
            ollama_version=authority.payload.ollama_version,
            ollama_model=authority.payload.ollama_model,
            ollama_model_digest=authority.payload.ollama_model_digest,
            show_metadata_sha256=show_metadata_sha256,
        )
    )


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("inherit_handle", ctypes.c_int),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _MibTcpRowOwnerPid(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32),
        ("local_address", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_address", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
        ("owning_process_id", ctypes.c_uint32),
    ]


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("internal_high", ctypes.c_size_t),
        ("offset", ctypes.c_uint32),
        ("offset_high", ctypes.c_uint32),
        ("event", ctypes.c_void_p),
    ]


class _Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def _windows_dll(name: str) -> ctypes.CDLL:
    if platform.system() != "Windows":
        raise OSError("Windows Ollama broker requires Windows")
    loader = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        raise OSError("Windows DLL loader is unavailable")
    return cast(ctypes.CDLL, loader(name, use_last_error=True))


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    if not callable(getter):
        return 0
    return int(getter())


def _close_handle(handle: int) -> None:
    if not handle or handle == _INVALID_HANDLE_VALUE:
        return
    kernel = _windows_dll("kernel32.dll")
    close = kernel.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    if not close(handle):
        raise OSError(_last_error(), "CloseHandle failed")


def _raise_operation_and_cleanup(
    operation_error: BaseException | None,
    cleanup_errors: list[BaseException],
    label: str,
) -> None:
    if operation_error is not None and cleanup_errors:
        raise BaseExceptionGroup(label, [operation_error, *cleanup_errors])
    if operation_error is not None:
        raise operation_error
    if cleanup_errors:
        raise BaseExceptionGroup(label, cleanup_errors)


def _local_free(pointer: ctypes.c_void_p) -> None:
    if not pointer.value:
        return
    kernel = _windows_dll("kernel32.dll")
    local_free = kernel.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    if local_free(pointer):
        raise OSError(_last_error(), "LocalFree failed")


def _new_overlapped() -> _Overlapped:
    kernel = _windows_dll("kernel32.dll")
    create_event = kernel.CreateEventW
    create_event.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    create_event.restype = ctypes.c_void_p
    event = int(create_event(None, 1, 0, None) or 0)
    if not event:
        raise OSError(_last_error(), "CreateEventW failed")
    return _Overlapped(0, 0, 0, 0, event)


def _await_overlapped(
    handle: int,
    overlapped: _Overlapped,
    *,
    started: bool,
    error_code: int,
    timeout_seconds: int,
    operation: str,
) -> tuple[int, bool]:
    """Finish one exact overlapped pipe operation with a hard timeout."""

    kernel = _windows_dll("kernel32.dll")
    try:
        if not started and error_code not in {_ERROR_IO_PENDING, _ERROR_MORE_DATA}:
            raise OSError(error_code, f"Windows broker {operation} failed")
        transferred = ctypes.c_uint32()
        complete = kernel.GetOverlappedResult
        complete.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Overlapped),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_int,
        ]
        complete.restype = ctypes.c_int
        if not started and error_code == _ERROR_IO_PENDING:
            wait = kernel.WaitForSingleObject
            wait.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            wait.restype = ctypes.c_uint32
            outcome = int(wait(overlapped.event, timeout_seconds * 1000))
            if outcome == _WAIT_TIMEOUT:
                cancel = kernel.CancelIoEx
                cancel.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Overlapped)]
                cancel.restype = ctypes.c_int
                cancelled = bool(cancel(handle, ctypes.byref(overlapped)))
                cancel_error = 0 if cancelled else _last_error()
                if not cancelled and cancel_error != _ERROR_NOT_FOUND:
                    raise OSError(cancel_error, f"Windows broker {operation} cancellation failed")
                terminal = bool(
                    complete(handle, ctypes.byref(overlapped), ctypes.byref(transferred), 1)
                )
                terminal_error = 0 if terminal else _last_error()
                if not terminal and terminal_error != _ERROR_OPERATION_ABORTED:
                    raise OSError(
                        terminal_error,
                        f"Windows broker {operation} cancellation did not complete",
                    )
                raise TimeoutError(f"Windows broker {operation} timed out")
            if outcome != _WAIT_OBJECT_0:
                raise OSError(_last_error(), f"Windows broker {operation} wait failed")
        completed = bool(complete(handle, ctypes.byref(overlapped), ctypes.byref(transferred), 0))
        completion_error = 0 if completed else _last_error()
        if not completed and completion_error != _ERROR_MORE_DATA:
            raise OSError(completion_error, f"Windows broker {operation} completion failed")
        return int(transferred.value), completion_error == _ERROR_MORE_DATA
    finally:
        _close_handle(int(overlapped.event or 0))


class _WindowsPipeStream:
    """Small bounded overlapped named-pipe stream; no ambient file objects."""

    def __init__(self, handle: int, timeout_seconds: int) -> None:
        self.handle = handle
        self.timeout_seconds = timeout_seconds
        self.closed = False
        self.message_continues = False

    def read(self, size: int = -1) -> bytes:
        if self.closed or size < 0:
            raise ValueError("Windows broker pipe reads require one explicit bound")
        kernel = _windows_dll("kernel32.dll")
        read = kernel.ReadFile
        read.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        read.restype = ctypes.c_int
        result = bytearray()
        while len(result) < size:
            amount = min(size - len(result), 64 * 1024)
            buffer = ctypes.create_string_buffer(amount)
            overlapped = _new_overlapped()
            started = bool(read(self.handle, buffer, amount, None, ctypes.byref(overlapped)))
            error_code = 0 if started else _last_error()
            if not started and error_code == _ERROR_BROKEN_PIPE:
                _close_handle(int(overlapped.event or 0))
                break
            observed, more_data = _await_overlapped(
                self.handle,
                overlapped,
                started=started,
                error_code=error_code,
                timeout_seconds=self.timeout_seconds,
                operation="read",
            )
            if observed == 0:
                break
            result.extend(buffer.raw[:observed])
            self.message_continues = more_data
            if not more_data:
                break
        return bytes(result)

    def write(self, data: bytes) -> int:
        if self.closed:
            raise ValueError("Windows broker pipe is closed")
        kernel = _windows_dll("kernel32.dll")
        write = kernel.WriteFile
        write.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        write.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(data)
        overlapped = _new_overlapped()
        started = bool(write(self.handle, buffer, len(data), None, ctypes.byref(overlapped)))
        error_code = 0 if started else _last_error()
        observed, more_data = _await_overlapped(
            self.handle,
            overlapped,
            started=started,
            error_code=error_code,
            timeout_seconds=self.timeout_seconds,
            operation="write",
        )
        if observed != len(data) or more_data:
            raise OSError("Windows broker WriteFile completed partially")
        return observed

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            _close_handle(self.handle)


def _create_pipe(authority: WindowsOllamaBrokerAuthorityV1) -> int:
    advapi = _windows_dll("advapi32.dll")
    kernel = _windows_dll("kernel32.dll")
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    convert.restype = ctypes.c_int
    descriptor = ctypes.c_void_p()
    if not convert(
        windows_ollama_pipe_sddl(authority.payload.appcontainer_sid),
        _SDDL_REVISION_1,
        ctypes.byref(descriptor),
        None,
    ):
        raise OSError(_last_error(), "Broker pipe security descriptor creation failed")
    handle = 0
    operation_error: BaseException | None = None
    try:
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, 0)
        create = kernel.CreateNamedPipeW
        create.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(_SecurityAttributes),
        ]
        create.restype = ctypes.c_void_p
        handle = int(
            create(
                authority.payload.pipe_name,
                _PIPE_ACCESS_DUPLEX | _FILE_FLAG_FIRST_PIPE_INSTANCE | _FILE_FLAG_OVERLAPPED,
                _PIPE_TYPE_MESSAGE
                | _PIPE_READMODE_MESSAGE
                | _PIPE_WAIT
                | _PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64 * 1024,
                64 * 1024,
                authority.payload.io_timeout_seconds * 1000,
                ctypes.byref(attributes),
            )
            or 0
        )
        if not handle or handle == _INVALID_HANDLE_VALUE:
            raise OSError(_last_error(), "CreateNamedPipeW failed")
        observed_sddl = _pipe_security_sddl(handle)
        if observed_sddl != windows_ollama_pipe_sddl(authority.payload.appcontainer_sid):
            raise ValueError("Broker pipe observed DACL differs from authority")
    except BaseException as error:
        operation_error = error
    cleanup_errors: list[BaseException] = []
    try:
        _local_free(descriptor)
    except BaseException as error:
        cleanup_errors.append(error)
    if operation_error is not None or cleanup_errors:
        if handle and handle != _INVALID_HANDLE_VALUE:
            try:
                _close_handle(handle)
            except BaseException as error:
                cleanup_errors.append(error)
        _raise_operation_and_cleanup(
            operation_error,
            cleanup_errors,
            "Windows broker pipe creation and cleanup failed",
        )
    return handle


def _pipe_security_sddl(handle: int) -> str:
    """Read back only the protected pipe DACL for exact qualification."""

    advapi = _windows_dll("advapi32.dll")
    descriptor = ctypes.c_void_p()
    get_security = advapi.GetSecurityInfo
    get_security.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security.restype = ctypes.c_uint32
    code = int(
        get_security(
            handle,
            _SE_KERNEL_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
    )
    if code != 0 or not descriptor.value:
        acquisition_error = OSError(code, "GetSecurityInfo failed for broker pipe")
        acquisition_cleanup_errors: list[BaseException] = []
        try:
            _local_free(descriptor)
        except BaseException as error:
            acquisition_cleanup_errors.append(error)
        _raise_operation_and_cleanup(
            acquisition_error,
            acquisition_cleanup_errors,
            "Windows broker DACL acquisition and cleanup failed",
        )
    text = ctypes.c_void_p()
    result: str | None = None
    operation_error: BaseException | None = None
    try:
        convert = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        convert.restype = ctypes.c_int
        if (
            not convert(
                descriptor,
                _SDDL_REVISION_1,
                _DACL_SECURITY_INFORMATION,
                ctypes.byref(text),
                None,
            )
            or not text.value
        ):
            raise OSError(_last_error(), "Broker pipe DACL serialization failed")
        result = ctypes.wstring_at(text.value)
    except BaseException as error:
        operation_error = error
    cleanup_errors: list[BaseException] = []
    for pointer in (text, descriptor):
        try:
            _local_free(pointer)
        except BaseException as error:
            cleanup_errors.append(error)
    _raise_operation_and_cleanup(
        operation_error,
        cleanup_errors,
        "Windows broker DACL readback and cleanup failed",
    )
    if result is None:
        raise AssertionError("Windows broker DACL readback returned no descriptor")
    return result


def _file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _sid_text(pointer: int) -> str:
    advapi = _windows_dll("advapi32.dll")
    convert = advapi.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    convert.restype = ctypes.c_int
    text = ctypes.c_void_p()
    if not convert(pointer, ctypes.byref(text)) or not text.value:
        raise OSError(_last_error(), "Windows SID conversion failed")
    try:
        return ctypes.wstring_at(text.value)
    finally:
        _local_free(text)


def _process_identity(process_id: int) -> WindowsProcessIdentityV1:
    kernel = _windows_dll("kernel32.dll")
    advapi = _windows_dll("advapi32.dll")
    open_process = kernel.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    process = int(open_process(_PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) or 0)
    if not process:
        raise OSError(_last_error(), "OpenProcess failed for Windows authority")
    token = ctypes.c_void_p()
    result: WindowsProcessIdentityV1 | None = None
    operation_error: BaseException | None = None
    try:
        created = _FileTime()
        exited = _FileTime()
        kernel_time = _FileTime()
        user_time = _FileTime()
        get_times = kernel.GetProcessTimes
        get_times.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
        ]
        get_times.restype = ctypes.c_int
        if not get_times(
            process,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise OSError(_last_error(), "GetProcessTimes failed for Windows authority")
        length = ctypes.c_uint32(32768)
        executable = ctypes.create_unicode_buffer(length.value)
        query_path = kernel.QueryFullProcessImageNameW
        query_path.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        query_path.restype = ctypes.c_int
        if not query_path(process, 0, executable, ctypes.byref(length)):
            raise OSError(_last_error(), "QueryFullProcessImageNameW failed")
        open_token = advapi.OpenProcessToken
        open_token.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        open_token.restype = ctypes.c_int
        if not open_token(process, _TOKEN_QUERY, ctypes.byref(token)):
            raise OSError(_last_error(), "OpenProcessToken failed for Windows authority")
        query = advapi.GetTokenInformation
        query.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        query.restype = ctypes.c_int
        size = ctypes.c_uint32()
        query(token, _TOKEN_USER, None, 0, ctypes.byref(size))
        if size.value == 0:
            raise OSError(_last_error(), "Windows process user SID size is unavailable")
        buffer = ctypes.create_string_buffer(size.value)
        if not query(token, _TOKEN_USER, buffer, size.value, ctypes.byref(size)):
            raise OSError(_last_error(), "Windows process user SID query failed")
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
        if not sid_pointer:
            raise ValueError("Windows process user SID is absent")
        creation_time = (int(created.high) << 32) | int(created.low)
        result = WindowsProcessIdentityV1(
            process_id=process_id,
            creation_time_100ns=creation_time,
            executable_sha256=_file_sha256(Path(executable.value)),
            user_sid=_sid_text(sid_pointer),
        )
    except BaseException as error:
        operation_error = error
    cleanup_errors: list[BaseException] = []
    if token.value:
        try:
            _close_handle(int(token.value))
        except BaseException as error:
            cleanup_errors.append(error)
    try:
        _close_handle(process)
    except BaseException as error:
        cleanup_errors.append(error)
    _raise_operation_and_cleanup(
        operation_error, cleanup_errors, "Windows process identity and cleanup failed"
    )
    if result is None:
        raise AssertionError("Windows process identity operation returned no result")
    return result


def _ollama_listener_process_id() -> int:
    iphlp = _windows_dll("iphlpapi.dll")
    get_table = iphlp.GetExtendedTcpTable
    get_table.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    get_table.restype = ctypes.c_uint32
    size = ctypes.c_uint32()
    code = int(
        get_table(
            None,
            ctypes.byref(size),
            0,
            _AF_INET,
            _TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    )
    if code != _ERROR_INSUFFICIENT_BUFFER or size.value < ctypes.sizeof(ctypes.c_uint32):
        raise OSError(code, "Windows TCP owner table size query failed")
    buffer = ctypes.create_string_buffer(size.value)
    code = int(
        get_table(
            buffer,
            ctypes.byref(size),
            0,
            _AF_INET,
            _TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    )
    if code != 0:
        raise OSError(code, "Windows TCP owner table query failed")
    count = ctypes.c_uint32.from_buffer(buffer).value
    row_size = ctypes.sizeof(_MibTcpRowOwnerPid)
    offset = ctypes.sizeof(ctypes.c_uint32)
    if offset + count * row_size > size.value:
        raise ValueError("Windows TCP owner table is truncated")
    matches: list[int] = []
    for index in range(count):
        row = _MibTcpRowOwnerPid.from_buffer_copy(buffer, offset + index * row_size)
        address = socket.inet_ntoa(struct.pack("<I", row.local_address))
        port = socket.ntohs(row.local_port & 0xFFFF)
        if (
            row.state == _MIB_TCP_STATE_LISTEN
            and address == WINDOWS_OLLAMA_DESTINATION_HOST
            and port == WINDOWS_OLLAMA_DESTINATION_PORT
        ):
            matches.append(int(row.owning_process_id))
    if len(matches) != 1 or matches[0] == 0:
        raise ValueError("Exact Windows Ollama loopback listener identity is unavailable")
    return matches[0]


def observe_windows_ollama_listener() -> WindowsOllamaListenerV1:
    if platform.system() != "Windows":
        raise OSError("Windows Ollama listener observation requires Windows")
    process = _process_identity(_ollama_listener_process_id())
    return WindowsOllamaListenerV1.create(WindowsOllamaListenerPayloadV1(process=process))


def validate_windows_ollama_listener(listener: WindowsOllamaListenerV1) -> None:
    observed = observe_windows_ollama_listener()
    if observed != listener:
        raise ValueError("Windows Ollama listener identity changed")


def observe_windows_ollama_broker_runtime(
    authority: WindowsOllamaBrokerAuthorityV1, process_id: int
) -> WindowsOllamaBrokerRuntimeV1:
    process = _process_identity(process_id)
    if process.executable_sha256 != authority.payload.broker_python_executable_sha256:
        raise ValueError("Windows broker process executable differs from authority")
    if process.user_sid != authority.payload.listener.payload.process.user_sid:
        raise ValueError("Windows broker and Ollama listener users differ")
    return WindowsOllamaBrokerRuntimeV1.create(
        WindowsOllamaBrokerRuntimePayloadV1(
            windows_ollama_broker_authority_id=(authority.windows_ollama_broker_authority_id),
            broker_launch_id=windows_ollama_broker_launch_id(authority),
            broker_module_sha256=authority.payload.broker_module_sha256,
            process=process,
            listener_id=authority.payload.listener.windows_ollama_listener_id,
            pipe_name_sha256=hashlib.sha256(authority.payload.pipe_name.encode()).hexdigest(),
        )
    )


def validate_windows_ollama_broker_runtime(
    authority: WindowsOllamaBrokerAuthorityV1, runtime: WindowsOllamaBrokerRuntimeV1
) -> None:
    if (
        runtime.payload.windows_ollama_broker_authority_id
        != authority.windows_ollama_broker_authority_id
        or runtime.payload.broker_launch_id != windows_ollama_broker_launch_id(authority)
        or runtime.payload.broker_module_sha256 != authority.payload.broker_module_sha256
        or runtime.payload.process.executable_sha256
        != authority.payload.broker_python_executable_sha256
        or runtime.payload.process.user_sid != authority.payload.listener.payload.process.user_sid
        or runtime.payload.listener_id != authority.payload.listener.windows_ollama_listener_id
        or runtime.payload.pipe_name_sha256
        != hashlib.sha256(authority.payload.pipe_name.encode()).hexdigest()
        or _process_identity(runtime.payload.process.process_id) != runtime.payload.process
    ):
        raise ValueError("Windows Ollama broker runtime identity changed")


def _connect_pipe_client(
    authority: WindowsOllamaBrokerAuthorityV1,
    runtime: WindowsOllamaBrokerRuntimeV1,
) -> _WindowsPipeStream:
    validate_windows_ollama_broker_runtime(authority, runtime)
    kernel = _windows_dll("kernel32.dll")
    wait = kernel.WaitNamedPipeW
    wait.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    wait.restype = ctypes.c_int
    if not wait(authority.payload.pipe_name, authority.payload.io_timeout_seconds * 1000):
        raise OSError(_last_error(), "WaitNamedPipeW failed")
    create = kernel.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    handle = int(
        create(
            authority.payload.pipe_name,
            _GENERIC_READ | _GENERIC_WRITE,
            0,
            None,
            _OPEN_EXISTING,
            _SECURITY_SQOS_PRESENT | _SECURITY_IDENTIFICATION | _FILE_FLAG_OVERLAPPED,
            None,
        )
        or 0
    )
    if not handle or handle == _INVALID_HANDLE_VALUE:
        raise OSError(_last_error(), "Broker pipe CreateFileW failed")
    set_state = kernel.SetNamedPipeHandleState
    set_state.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    set_state.restype = ctypes.c_int
    mode = ctypes.c_uint32(_PIPE_READMODE_MESSAGE)
    if not set_state(handle, ctypes.byref(mode), None, None):
        error_code = _last_error()
        _close_handle(handle)
        raise OSError(error_code, "Broker pipe message mode setup failed")
    get_pid = kernel.GetNamedPipeServerProcessId
    get_pid.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    get_pid.restype = ctypes.c_int
    process_id = ctypes.c_uint32()
    if (
        not get_pid(handle, ctypes.byref(process_id))
        or process_id.value != runtime.payload.process.process_id
    ):
        _close_handle(handle)
        raise OSError(_last_error(), "Broker pipe server identity is invalid")
    return _WindowsPipeStream(handle, authority.payload.io_timeout_seconds)


def _pipe_client_sid(handle: int) -> str:
    advapi = _windows_dll("advapi32.dll")
    kernel = _windows_dll("kernel32.dll")
    impersonate = advapi.ImpersonateNamedPipeClient
    impersonate.argtypes = [ctypes.c_void_p]
    impersonate.restype = ctypes.c_int
    revert = advapi.RevertToSelf
    revert.argtypes = []
    revert.restype = ctypes.c_int
    if not impersonate(handle):
        raise OSError(_last_error(), "Named-pipe client impersonation failed")
    token = ctypes.c_void_p()
    result: str | None = None
    operation_error: BaseException | None = None
    try:
        open_token = advapi.OpenThreadToken
        open_token.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        open_token.restype = ctypes.c_int
        current_thread = kernel.GetCurrentThread
        current_thread.argtypes = []
        current_thread.restype = ctypes.c_void_p
        if not open_token(current_thread(), _TOKEN_QUERY, 1, ctypes.byref(token)):
            raise OSError(_last_error(), "Named-pipe client token open failed")
        query = advapi.GetTokenInformation
        query.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        query.restype = ctypes.c_int
        appcontainer = ctypes.c_uint32()
        size = ctypes.c_uint32()
        if (
            not query(
                token,
                _TOKEN_IS_APPCONTAINER,
                ctypes.byref(appcontainer),
                ctypes.sizeof(appcontainer),
                ctypes.byref(size),
            )
            or appcontainer.value != 1
        ):
            raise ValueError("Named-pipe client is not an AppContainer")
        query(token, _TOKEN_APPCONTAINER_SID, None, 0, ctypes.byref(size))
        if size.value == 0:
            raise OSError(_last_error(), "AppContainer SID size is unavailable")
        buffer = ctypes.create_string_buffer(size.value)
        if not query(
            token,
            _TOKEN_APPCONTAINER_SID,
            buffer,
            size.value,
            ctypes.byref(size),
        ):
            raise OSError(_last_error(), "AppContainer SID query failed")
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
        if not sid_pointer:
            raise ValueError("AppContainer SID is absent")
        result = validate_appcontainer_package_sid(_sid_text(sid_pointer))
    except BaseException as error:
        operation_error = error
    cleanup_errors: list[BaseException] = []
    if token.value:
        try:
            _close_handle(int(token.value))
        except BaseException as error:
            cleanup_errors.append(error)
    try:
        if not revert():
            raise OSError(_last_error(), "Named-pipe client impersonation cleanup failed")
    except BaseException as error:
        cleanup_errors.append(error)
    _raise_operation_and_cleanup(
        operation_error,
        cleanup_errors,
        "Named-pipe client identity and cleanup failed",
    )
    if result is None:
        raise AssertionError("Named-pipe client identity returned no SID")
    return result


def _accept_pipe_client(handle: int, timeout_seconds: int) -> None:
    kernel = _windows_dll("kernel32.dll")
    connect = kernel.ConnectNamedPipe
    connect.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Overlapped)]
    connect.restype = ctypes.c_int
    overlapped = _new_overlapped()
    started = bool(connect(handle, ctypes.byref(overlapped)))
    error_code = 0 if started else _last_error()
    if not started and error_code == _ERROR_PIPE_CONNECTED:
        _close_handle(int(overlapped.event or 0))
        return
    _await_overlapped(
        handle,
        overlapped,
        started=started,
        error_code=error_code,
        timeout_seconds=timeout_seconds,
        operation="connect",
    )


def _fixed_ollama_request(
    authority: WindowsOllamaBrokerAuthorityV1, frame: WindowsOllamaRequestFrame
) -> WindowsOllamaResponseFrame:
    endpoint = frame.endpoint
    if endpoint.method == "PROBE":
        return WindowsOllamaResponseFrame(status=204, body=b"")
    # The first check rejects a known-stale authority before opening a socket.
    validate_windows_ollama_listener(authority.payload.listener)
    connection = http.client.HTTPConnection(
        authority.payload.destination_host,
        authority.payload.destination_port,
        timeout=authority.payload.io_timeout_seconds,
    )
    try:
        # Connect without sending HTTP bytes, then close the listener-identity race.
        # HTTPConnection.request() reuses this retained socket and cannot retarget it.
        connection.connect()
        validate_windows_ollama_listener(authority.payload.listener)
        connection.request(
            endpoint.method,
            endpoint.path,
            body=None if endpoint.method == "GET" else frame.body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        body = response.read(authority.payload.max_response_bytes + 1)
        if len(body) > authority.payload.max_response_bytes:
            raise ValueError("Ollama response exceeds the broker byte bound")
        return WindowsOllamaResponseFrame(status=response.status, body=body)
    finally:
        connection.close()


def serve_one_windows_ollama_request(
    authority: WindowsOllamaBrokerAuthorityV1,
    runtime: WindowsOllamaBrokerRuntimeV1,
) -> WindowsOllamaBrokerObservationV1:
    """Serve one verified AppContainer frame and remove its only pipe instance."""

    if platform.system() != "Windows":
        raise OSError("Windows Ollama broker requires Windows")
    validate_windows_ollama_broker_runtime(authority, runtime)
    if runtime.payload.process.process_id != os.getpid():
        raise ValueError("Windows broker runtime does not identify this process")
    if hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest() != (
        authority.payload.broker_python_executable_sha256
    ):
        raise ValueError("Broker interpreter bytes differ from authority")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != (
        authority.payload.broker_module_sha256
    ):
        raise ValueError("Broker module bytes differ from authority")
    handle = _create_pipe(authority)
    kernel = _windows_dll("kernel32.dll")
    connected = False
    result: WindowsOllamaBrokerObservationV1 | None = None
    operation_error: BaseException | None = None
    try:
        _accept_pipe_client(handle, authority.payload.io_timeout_seconds)
        connected = True
        client_sid = _pipe_client_sid(handle)
        if client_sid != authority.payload.appcontainer_sid:
            raise ValueError("Named-pipe client AppContainer SID mismatch")
        stream = _WindowsPipeStream(handle, authority.payload.io_timeout_seconds)
        request_data = read_bounded_frame(
            stream,
            header=_REQUEST_HEADER,
            length_index=4,
            body_limit=authority.payload.max_request_bytes,
        )
        frame = decode_windows_ollama_request(authority, request_data)
        response = _fixed_ollama_request(authority, frame)
        response_data = encode_windows_ollama_response(authority, response.status, response.body)
        stream.write(response_data)
        acknowledgement = stream.read(_ACK.size)
        if stream.message_continues or acknowledgement != _encode_ack(authority):
            raise ValueError("Windows Ollama broker acknowledgement is invalid")
        result = WindowsOllamaBrokerObservationV1(
            windows_ollama_broker_authority_id=(authority.windows_ollama_broker_authority_id),
            windows_ollama_broker_runtime_id=runtime.windows_ollama_broker_runtime_id,
            pipe_name_sha256=hashlib.sha256(authority.payload.pipe_name.encode()).hexdigest(),
            appcontainer_sid=client_sid,
            endpoint_code=frame.endpoint.code,
            method=frame.endpoint.method,
            path=frame.endpoint.path,
            request_bytes=len(request_data),
            response_bytes=len(response_data),
            response_status=response.status,
            response_body_sha256=hashlib.sha256(response.body).hexdigest(),
        )
    except BaseException as error:
        operation_error = error
    cleanup_errors: list[BaseException] = []
    if connected:
        try:
            disconnect = kernel.DisconnectNamedPipe
            disconnect.argtypes = [ctypes.c_void_p]
            disconnect.restype = ctypes.c_int
            if not disconnect(handle):
                raise OSError(_last_error(), "DisconnectNamedPipe cleanup failed")
        except BaseException as error:
            cleanup_errors.append(error)
    try:
        _close_handle(handle)
    except BaseException as error:
        cleanup_errors.append(error)
    _raise_operation_and_cleanup(
        operation_error, cleanup_errors, "Windows broker operation and cleanup failed"
    )
    if result is None:
        raise AssertionError("Windows broker operation returned no result")
    return result


def serve_windows_ollama_metadata_sequence(
    authority: WindowsOllamaBrokerAuthorityV1,
    runtime: WindowsOllamaBrokerRuntimeV1,
) -> tuple[
    WindowsOllamaBrokerObservationV1,
    WindowsOllamaBrokerObservationV1,
    WindowsOllamaBrokerObservationV1,
]:
    """Serve exactly version, tags and show in one retained broker process."""

    observed: list[WindowsOllamaBrokerObservationV1] = []
    for expected in WINDOWS_OLLAMA_ENDPOINTS[1:]:
        item = serve_one_windows_ollama_request(authority, runtime)
        if (item.endpoint_code, item.method, item.path) != (
            expected.code,
            expected.method,
            expected.path,
        ):
            raise ValueError("Windows Ollama metadata requests arrived out of order")
        observed.append(item)
    return cast(
        tuple[
            WindowsOllamaBrokerObservationV1,
            WindowsOllamaBrokerObservationV1,
            WindowsOllamaBrokerObservationV1,
        ],
        tuple(observed),
    )


def request_windows_ollama_broker(
    authority: WindowsOllamaBrokerAuthorityV1,
    runtime: WindowsOllamaBrokerRuntimeV1,
    method: Literal["PROBE", "GET", "POST"],
    path: Literal["", "/api/version", "/api/tags", "/api/show"],
    body: bytes = b"",
) -> WindowsOllamaResponseFrame:
    """Send one exact frame from the isolated client without a TCP capability."""

    frame = encode_windows_ollama_request(authority, method, path, body)
    stream = _connect_pipe_client(authority, runtime)
    result: WindowsOllamaResponseFrame | None = None
    operation_error: BaseException | None = None
    try:
        stream.write(frame)
        response = read_bounded_frame(
            stream,
            header=_RESPONSE_HEADER,
            length_index=3,
            body_limit=authority.payload.max_response_bytes,
        )
        decoded = decode_windows_ollama_response(authority, response)
        stream.write(_encode_ack(authority))
        result = decoded
    except BaseException as error:
        operation_error = error
    cleanup_errors: list[BaseException] = []
    try:
        stream.close()
    except BaseException as error:
        cleanup_errors.append(error)
    _raise_operation_and_cleanup(
        operation_error,
        cleanup_errors,
        "Windows broker client operation and cleanup failed",
    )
    if result is None:
        raise AssertionError("Windows broker client returned no response")
    return result


def request_windows_ollama_metadata_sequence(
    authority: WindowsOllamaBrokerAuthorityV1,
    runtime: WindowsOllamaBrokerRuntimeV1,
) -> tuple[
    WindowsOllamaResponseFrame,
    WindowsOllamaResponseFrame,
    WindowsOllamaResponseFrame,
]:
    """Request the exact qualification metadata sequence; no generation endpoint exists."""

    show = canonical({"model": authority.payload.ollama_model, "verbose": True})
    return (
        request_windows_ollama_broker(authority, runtime, "GET", "/api/version"),
        request_windows_ollama_broker(authority, runtime, "GET", "/api/tags"),
        request_windows_ollama_broker(authority, runtime, "POST", "/api/show", show),
    )


def _authority_bytes(authority_id: str) -> bytes:
    return bytes.fromhex(authority_id)


def _encode_ack(authority: WindowsOllamaBrokerAuthorityV1) -> bytes:
    return _ACK.pack(
        _ACK_MAGIC,
        1,
        _authority_bytes(authority.windows_ollama_broker_authority_id),
    )


def encode_windows_ollama_request(
    authority: WindowsOllamaBrokerAuthorityV1,
    method: Literal["PROBE", "GET", "POST"],
    path: Literal["", "/api/version", "/api/tags", "/api/show"],
    body: bytes = b"",
) -> bytes:
    endpoint = _ENDPOINT_BY_REQUEST.get((method, path))
    if endpoint is None:
        raise ValueError("Windows Ollama broker endpoint is not allowlisted")
    if len(body) > authority.payload.max_request_bytes:
        raise ValueError("Windows Ollama broker request exceeds its byte bound")
    if (endpoint.method in {"PROBE", "GET"}) != (body == b""):
        raise ValueError("Windows Ollama broker request body differs from its endpoint")
    if endpoint.method == "POST":
        parsed = json.loads(body)
        if parsed != {"model": authority.payload.ollama_model, "verbose": True}:
            raise ValueError("Windows Ollama metadata body differs from authority")
    return (
        _REQUEST_HEADER.pack(
            _REQUEST_MAGIC,
            1,
            endpoint.code,
            0,
            len(body),
            authority.payload.max_response_bytes,
            _authority_bytes(authority.windows_ollama_broker_authority_id),
        )
        + body
    )


def decode_windows_ollama_request(
    authority: WindowsOllamaBrokerAuthorityV1, data: bytes
) -> WindowsOllamaRequestFrame:
    if len(data) < _REQUEST_HEADER.size:
        raise ValueError("Windows Ollama broker request header is incomplete")
    magic, version, code, flags, length, response_limit, authority_id = _REQUEST_HEADER.unpack(
        data[: _REQUEST_HEADER.size]
    )
    if (
        magic != _REQUEST_MAGIC
        or version != 1
        or flags != 0
        or response_limit != authority.payload.max_response_bytes
        or authority_id != _authority_bytes(authority.windows_ollama_broker_authority_id)
    ):
        raise ValueError("Windows Ollama broker request authority mismatch")
    endpoint = _ENDPOINT_BY_CODE.get(code)
    if endpoint is None:
        raise ValueError("Windows Ollama broker endpoint code is unknown")
    body = data[_REQUEST_HEADER.size :]
    if length != len(body) or length > authority.payload.max_request_bytes:
        raise ValueError("Windows Ollama broker request length mismatch")
    # Reuse the single encoder validation path for endpoint/body semantics.
    encode_windows_ollama_request(authority, endpoint.method, endpoint.path, body)
    return WindowsOllamaRequestFrame(endpoint=endpoint, body=body)


def encode_windows_ollama_response(
    authority: WindowsOllamaBrokerAuthorityV1, status: int, body: bytes
) -> bytes:
    if not 100 <= status <= 599:
        raise ValueError("Windows Ollama broker response status is invalid")
    if len(body) > authority.payload.max_response_bytes:
        raise ValueError("Windows Ollama broker response exceeds its byte bound")
    return (
        _RESPONSE_HEADER.pack(
            _RESPONSE_MAGIC,
            1,
            status,
            len(body),
            _authority_bytes(authority.windows_ollama_broker_authority_id),
        )
        + body
    )


def decode_windows_ollama_response(
    authority: WindowsOllamaBrokerAuthorityV1, data: bytes
) -> WindowsOllamaResponseFrame:
    if len(data) < _RESPONSE_HEADER.size:
        raise ValueError("Windows Ollama broker response header is incomplete")
    magic, version, status, length, authority_id = _RESPONSE_HEADER.unpack(
        data[: _RESPONSE_HEADER.size]
    )
    body = data[_RESPONSE_HEADER.size :]
    if (
        magic != _RESPONSE_MAGIC
        or version != 1
        or authority_id != _authority_bytes(authority.windows_ollama_broker_authority_id)
        or length != len(body)
        or length > authority.payload.max_response_bytes
    ):
        raise ValueError("Windows Ollama broker response authority mismatch")
    if not 100 <= status <= 599:
        raise ValueError("Windows Ollama broker response status is invalid")
    return WindowsOllamaResponseFrame(status=status, body=body)


def read_bounded_frame(
    stream: _Readable, *, header: struct.Struct, length_index: int, body_limit: int
) -> bytes:
    """Read one bounded length-delimited frame without accepting partial data."""

    raw_header = stream.read(header.size)
    if len(raw_header) != header.size:
        raise ValueError("Windows Ollama broker frame header is incomplete")
    values = header.unpack(raw_header)
    try:
        length = values[length_index]
    except IndexError as error:
        raise ValueError("Windows Ollama broker length field is unavailable") from error
    if type(length) is not int or length < 0 or length > body_limit:
        raise ValueError("Windows Ollama broker frame body length is invalid")
    body = stream.read(length)
    if len(body) != length:
        raise ValueError("Windows Ollama broker frame body is incomplete")
    if bool(getattr(stream, "message_continues", False)):
        raise ValueError("Windows Ollama broker frame contains trailing data")
    return raw_header + body


def _write_contract_exclusive(path: Path, value: Contract) -> None:
    if path.parent.is_symlink() or path.exists() or path.is_symlink():
        raise ValueError("Windows broker evidence path is not a new plain file")
    data = canonical(value.model_dump(mode="json"))
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    published = False
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            # os.rename maps to a non-replacing atomic move on Windows.
            os.rename(temporary, path)
        else:
            # Unit tests run on Linux too: a same-directory hard-link publish is
            # atomic and fails rather than replacing an existing final path.
            os.link(temporary, path)
            temporary.unlink()
        published = True
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
    if not published or path.is_symlink() or not path.is_file():
        raise ValueError("Windows broker evidence publication failed")


def _read_contract[ContractT: Contract](
    path: Path, model: type[ContractT], *, byte_limit: int
) -> ContractT:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Windows broker evidence path is not a plain file")
    if path.stat().st_size > byte_limit:
        raise ValueError("Windows broker evidence exceeds its byte bound")
    return model.model_validate_json(path.read_bytes())


def _wait_for_contract[ContractT: Contract](
    path: Path,
    model: type[ContractT],
    process: subprocess.Popen[bytes],
    *,
    byte_limit: int,
    timeout_seconds: int,
) -> ContractT:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return _read_contract(path, model, byte_limit=byte_limit)
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"Windows broker exited before evidence publication ({code})")
        time.sleep(0.05)
    raise TimeoutError("Windows broker evidence publication timed out")


def _serve_metadata_process(
    authority_path: Path,
    runtime_output: Path,
    server_result_output: Path,
    completion_ack: Path,
) -> int:
    authority = _read_contract(
        authority_path, WindowsOllamaBrokerAuthorityV1, byte_limit=512 * 1024
    )
    runtime = observe_windows_ollama_broker_runtime(authority, os.getpid())
    _write_contract_exclusive(runtime_output, runtime)
    observations = serve_windows_ollama_metadata_sequence(authority, runtime)
    result = WindowsOllamaBrokerServerResultV1.create(
        WindowsOllamaBrokerServerResultPayloadV1(
            windows_ollama_broker_authority_id=(authority.windows_ollama_broker_authority_id),
            windows_ollama_broker_runtime_id=runtime.windows_ollama_broker_runtime_id,
            observations=observations,
        )
    )
    _write_contract_exclusive(server_result_output, result)
    deadline = time.monotonic() + authority.payload.io_timeout_seconds
    while time.monotonic() < deadline:
        if completion_ack.is_file():
            acknowledgement = _read_contract(completion_ack, _CompletionAckV1, byte_limit=1024)
            if acknowledgement.value != result.windows_ollama_broker_server_result_id:
                raise ValueError("Windows broker completion acknowledgement mismatch")
            return 0
        time.sleep(0.05)
    raise TimeoutError("Windows broker completion acknowledgement timed out")


def _run_metadata_client(
    authority_path: Path,
    runtime_path: Path,
    result_output: Path,
) -> int:
    authority = _read_contract(
        authority_path, WindowsOllamaBrokerAuthorityV1, byte_limit=512 * 1024
    )
    runtime = _read_contract(runtime_path, WindowsOllamaBrokerRuntimeV1, byte_limit=128 * 1024)
    responses = request_windows_ollama_metadata_sequence(authority, runtime)
    response_evidence = cast(
        tuple[
            WindowsOllamaResponseEvidenceV1,
            WindowsOllamaResponseEvidenceV1,
            WindowsOllamaResponseEvidenceV1,
        ],
        tuple(WindowsOllamaResponseEvidenceV1.create(item) for item in responses),
    )
    result = WindowsOllamaBrokerClientResultV1.create(
        WindowsOllamaBrokerClientResultPayloadV1(
            windows_ollama_broker_authority_id=(authority.windows_ollama_broker_authority_id),
            windows_ollama_broker_runtime_id=runtime.windows_ollama_broker_runtime_id,
            responses=response_evidence,
        )
    )
    _write_contract_exclusive(result_output, result)
    return 0


def _qualify_windows_ollama_native_staged(
    *,
    bundle: NativeBundleV1,
    execution_bundle_root: Path,
    isolation: WindowsIsolationEvidenceV6,
    broker_profile: WindowsIsolationProfileV4,
    listener: WindowsOllamaListenerV1,
    host_run: Path,
    client_run: Path,
    token: str,
    ollama_version: Literal["0.34.2", "0.35.0"],
    ollama_model: str,
    ollama_model_digest: str,
) -> WindowsOllamaNativeQualificationV1:
    """Run one broker against already verified fresh disposable roots."""

    authority = create_windows_ollama_broker_authority(
        bundle=bundle,
        bundle_root=execution_bundle_root,
        isolation=isolation,
        broker_profile=broker_profile,
        listener=listener,
        pipe_name=WINDOWS_OLLAMA_PIPE_PREFIX + token,
        ollama_version=ollama_version,
        ollama_model=ollama_model,
        ollama_model_digest=ollama_model_digest,
    )
    host_authority = host_run / "authority.json"
    runtime_output = host_run / "runtime.json"
    server_output = host_run / "server-result.json"
    completion_ack = host_run / "complete.ack"
    client_authority = client_run / "authority.json"
    client_runtime = client_run / "runtime.json"
    client_output = client_run / "client-result.json"
    _write_contract_exclusive(host_authority, authority)
    _write_contract_exclusive(client_authority, authority)
    interpreter = execution_bundle_root.joinpath(*bundle.payload.python.executable_path.split("/"))
    broker = subprocess.Popen(
        [
            str(interpreter),
            "-I",
            "-B",
            "-m",
            "devhub.windows_ollama_broker",
            "serve-metadata",
            "--authority",
            str(host_authority),
            "--runtime-output",
            str(runtime_output),
            "--server-result-output",
            str(server_output),
            "--completion-ack",
            str(completion_ack),
        ],
        cwd=execution_bundle_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    broker_completed = False
    try:
        runtime = _wait_for_contract(
            runtime_output,
            WindowsOllamaBrokerRuntimeV1,
            broker,
            byte_limit=128 * 1024,
            timeout_seconds=authority.payload.io_timeout_seconds,
        )
        if runtime.payload.process.process_id != broker.pid:
            raise ValueError("Windows broker runtime does not match the spawned process")
        validate_windows_ollama_broker_runtime(authority, runtime)
        _write_contract_exclusive(client_runtime, runtime)

        def verify_runtime(path: Path) -> str:
            verify_native_bundle(
                bundle,
                path,
                expected_platform="windows",
                expected_architecture="x86_64",
            )
            return bundle.bundle_id

        environment = {
            key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ
        }
        environment.update({"PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"})
        process = launch_windows_isolated(
            broker_profile,
            interpreter,
            (
                "-I",
                "-B",
                "-m",
                "devhub.windows_ollama_broker",
                "client-metadata",
                "--authority",
                str(client_authority),
                "--runtime",
                str(client_runtime),
                "--client-result-output",
                str(client_output),
            ),
            cwd=client_run,
            environment=environment,
            verify_runtime_bundle=verify_runtime,
        )
        client_exit = -1
        cleanup_verified = False
        runtime_access_grant: WindowsRuntimeAccessGrantV2 | None = None
        client_error: BaseException | None = None
        try:
            if (
                process.appcontainer_sid != authority.payload.appcontainer_sid
                or not isinstance(process.runtime_access_grant, WindowsRuntimeAccessGrantV2)
                or process.runtime_access_grant.payload.native_bundle_id != bundle.bundle_id
            ):
                raise ValueError("Windows broker client process differs from isolation authority")
            runtime_access_grant = process.runtime_access_grant
            client_exit = process.wait(authority.payload.io_timeout_seconds)
        except BaseException as error:
            client_error = error
        client_cleanup_errors: list[BaseException] = []
        try:
            cleanup_verified = process.close()
        except BaseException as error:
            client_cleanup_errors.append(error)
        _raise_operation_and_cleanup(
            client_error,
            client_cleanup_errors,
            "Windows broker AppContainer operation and cleanup failed",
        )
        if client_exit != 0:
            raise RuntimeError(f"Windows broker client exited unsuccessfully ({client_exit})")
        if not cleanup_verified:
            raise RuntimeError("Windows broker AppContainer cleanup was not verified")
        if runtime_access_grant is None:
            raise AssertionError("Windows broker runtime access grant was not retained")
        client_result = _read_contract(
            client_output, WindowsOllamaBrokerClientResultV1, byte_limit=64 * 1024 * 1024
        )
        server_result = _wait_for_contract(
            server_output,
            WindowsOllamaBrokerServerResultV1,
            broker,
            byte_limit=2 * 1024 * 1024,
            timeout_seconds=authority.payload.io_timeout_seconds,
        )
        responses = cast(
            tuple[
                WindowsOllamaResponseFrame,
                WindowsOllamaResponseFrame,
                WindowsOllamaResponseFrame,
            ],
            tuple(item.response() for item in client_result.payload.responses),
        )
        metadata = qualify_windows_ollama_metadata(
            authority,
            runtime,
            server_result.payload.observations,
            responses,
        )
        _write_contract_exclusive(
            completion_ack,
            _CompletionAckV1(value=server_result.windows_ollama_broker_server_result_id),
        )
        broker_exit = broker.wait(timeout=authority.payload.io_timeout_seconds)
        broker_completed = True
        if broker_exit != 0:
            raise RuntimeError(f"Windows broker exited unsuccessfully ({broker_exit})")
        return WindowsOllamaNativeQualificationV1.create(
            WindowsOllamaNativeQualificationPayloadV1(
                authority=authority,
                runtime=runtime,
                server_result=server_result,
                client_result=client_result,
                metadata=metadata,
                runtime_access_grant=runtime_access_grant,
                windows_isolation_evidence_id=isolation.windows_isolation_evidence_id,
                appcontainer_sid=authority.payload.appcontainer_sid,
                broker_exit_code=0,
                client_exit_code=0,
                appcontainer_cleanup_verified=True,
            )
        )
    finally:
        if not broker_completed and broker.poll() is None:
            broker.terminate()
            try:
                broker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=10)


def qualify_windows_ollama_native(
    *,
    bundle: NativeBundleV1,
    bundle_root: Path,
    isolation: WindowsIsolationEvidenceV6,
    listener: WindowsOllamaListenerV1,
    control_root: Path,
    client_root: Path,
    ollama_version: Literal["0.34.2", "0.35.0"],
    ollama_model: str,
    ollama_model_digest: str,
) -> WindowsOllamaNativeQualificationV1:
    """Stage, run, and exhaustively remove one native broker qualification."""

    if platform.system() != "Windows":
        raise OSError("Windows Ollama native qualification requires Windows")
    source_identity = windows_path_identity(bundle_root)
    control_identity = windows_path_identity(control_root)
    client_parent_identity = windows_path_identity(client_root)
    roots = tuple(
        Path(item.locator).resolve()
        for item in (source_identity, control_identity, client_parent_identity)
    )
    if any(
        left.is_relative_to(right) or right.is_relative_to(left)
        for index, left in enumerate(roots)
        for right in roots[index + 1 :]
    ):
        raise ValueError("Windows broker source, control, and client roots must not overlap")
    verify_native_bundle(
        bundle,
        bundle_root,
        expected_platform="windows",
        expected_architecture="x86_64",
    )
    token = secrets.token_hex(16)
    host_run = control_root / f"windows-ollama-{token}"
    execution_bundle = client_root / f"windows-ollama-{token}-runtime"
    client_run = client_root / f"windows-ollama-{token}-client"
    owned_identities: dict[Path, object] = {}
    operation_error: BaseException | None = None
    result: WindowsOllamaNativeQualificationV1 | None = None
    staged_verified = False
    try:
        host_run.mkdir()
        owned_identities[host_run] = windows_path_identity(host_run)
        client_run.mkdir()
        owned_identities[client_run] = windows_path_identity(client_run)
        shutil.copytree(bundle_root, execution_bundle)
        owned_identities[execution_bundle] = windows_path_identity(execution_bundle)
        verify_native_bundle(
            bundle,
            execution_bundle,
            expected_platform="windows",
            expected_architecture="x86_64",
        )
        staged_verified = True
        broker_profile = create_windows_ollama_broker_profile(
            bundle=bundle,
            execution_bundle_root=execution_bundle,
            writable_root=client_run,
            denied_root=host_run,
            isolation=isolation,
        )
        result = _qualify_windows_ollama_native_staged(
            bundle=bundle,
            execution_bundle_root=execution_bundle,
            isolation=isolation,
            broker_profile=broker_profile,
            listener=listener,
            host_run=host_run,
            client_run=client_run,
            token=token,
            ollama_version=ollama_version,
            ollama_model=ollama_model,
            ollama_model_digest=ollama_model_digest,
        )
        verify_native_bundle(
            bundle,
            execution_bundle,
            expected_platform="windows",
            expected_architecture="x86_64",
        )
    except BaseException as error:
        operation_error = error
    cleanup_errors: list[BaseException] = []
    for path in (client_run, execution_bundle, host_run):
        if not path.exists() and not path.is_symlink():
            continue
        try:
            expected = owned_identities.get(path)
            if expected is None or windows_path_identity(path) != expected:
                raise ValueError("Windows broker disposable root identity changed")
            shutil.rmtree(path)
            if path.exists():
                raise RuntimeError("Windows broker disposable root cleanup was not confirmed")
        except BaseException as error:
            cleanup_errors.append(error)
    try:
        if windows_path_identity(bundle_root) != source_identity:
            raise ValueError("Windows broker source bundle identity changed")
        if windows_path_identity(control_root) != control_identity:
            raise ValueError("Windows broker control root identity changed")
        if windows_path_identity(client_root) != client_parent_identity:
            raise ValueError("Windows broker client root identity changed")
        verify_native_bundle(
            bundle,
            bundle_root,
            expected_platform="windows",
            expected_architecture="x86_64",
        )
    except BaseException as error:
        cleanup_errors.append(error)
    if result is not None and not staged_verified:
        cleanup_errors.append(RuntimeError("Windows broker staged bundle was not verified"))
    _raise_operation_and_cleanup(
        operation_error,
        cleanup_errors,
        "Windows broker qualification and disposable-root cleanup failed",
    )
    if result is None:
        raise AssertionError("Windows broker qualification returned no result")
    return result


class _CompletionAckV1(Contract):
    value: Digest


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Closed Windows Ollama metadata broker")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    server = subparsers.add_parser("serve-metadata")
    server.add_argument("--authority", type=Path, required=True)
    server.add_argument("--runtime-output", type=Path, required=True)
    server.add_argument("--server-result-output", type=Path, required=True)
    server.add_argument("--completion-ack", type=Path, required=True)
    client = subparsers.add_parser("client-metadata")
    client.add_argument("--authority", type=Path, required=True)
    client.add_argument("--runtime", type=Path, required=True)
    client.add_argument("--client-result-output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == "serve-metadata":
        return _serve_metadata_process(
            args.authority,
            args.runtime_output,
            args.server_result_output,
            args.completion_ack,
        )
    if args.mode == "client-metadata":
        return _run_metadata_client(args.authority, args.runtime, args.client_result_output)
    raise AssertionError("Unsupported Windows Ollama broker mode")


if __name__ == "__main__":
    raise SystemExit(_main())
