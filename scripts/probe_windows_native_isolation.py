"""Qualify the Windows no-direct-network sandbox without running a task or model."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import winreg
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn, cast

from pydantic import Field, JsonValue, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.experiment_launch import durable_publish
from devhub.models import Contract, ContractV2
from devhub.native_bundle import NativeBundleV1, verify_native_bundle
from devhub.windows_isolation import (
    WindowsIsolationChildResultV2,
    WindowsIsolationEvidenceV5,
    WindowsIsolationProfilePayloadV3,
    WindowsIsolationProfileV2,
    WindowsIsolationProfileV3,
    WindowsIsolationReceiptPayloadV5,
    WindowsIsolationReceiptV5,
    WindowsNativeImportExpectationV1,
    WindowsNativeImportSuccessV1,
    WindowsNativeLoaderActivationV1,
    WindowsPostCreateAclFailureV1,
    WindowsPostCreateAclGateError,
    WindowsRuntimeAccessGrantV2,
    _reject_reparse_chain,
    appcontainer_identity,
    launch_windows_isolated,
    observed_windows_platform,
    windows_path_identity,
    windows_sandbox_spec,
)

ACCESS_DENIED_ERRORS = {5, 13, 10013}
MAX_CHILD_FAILURE_BYTES = 4096
MAX_BOOTSTRAP_STATUS_BYTES = 4096


class WindowsIsolationChildFailureV1(Contract):
    schema_version: Literal[1] = 1
    phase: Literal["child_probe"] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None


class WindowsIsolationChildFailureV2(ContractV2):
    phase: Literal["bootstrap_import", "bootstrap_invoke", "child_probe"] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None


NativeLoaderReason = Literal[
    "access_denied",
    "dependency_not_found",
    "bad_image",
    "procedure_not_found",
    "unknown",
]
NativeLoaderReasonV4 = Literal[
    "access_denied",
    "dependency_not_found",
    "bad_image",
    "procedure_not_found",
    "initialization_failed",
    "unknown",
]
NativeImportBoundary = Literal["ctypes", "socket", "pydantic_core", "devhub", "unknown"]
NativeLoaderPath = Literal["python/_ctypes.pyd", "python/libffi-8.dll"]
NativeMatrixModule = Literal["_socket", "_overlapped", "select", "_ssl"]
NativeMatrixPath = Literal[
    "python/_socket.pyd",
    "python/_overlapped.pyd",
    "python/select.pyd",
    "python/_ssl.pyd",
]
NativeMatrixModuleV5 = Literal["_socket", "_overlapped", "select", "_hashlib", "_ssl"]
NativeMatrixPathV5 = Literal[
    "python/_socket.pyd",
    "python/_overlapped.pyd",
    "python/select.pyd",
    "python/_hashlib.pyd",
    "python/_ssl.pyd",
]
NativeMatrixModuleV6 = Literal["_ctypes", "_socket", "_overlapped", "select", "_hashlib", "_ssl"]
NativeMatrixPathV6 = Literal[
    "python/_ctypes.pyd",
    "python/_socket.pyd",
    "python/_overlapped.pyd",
    "python/select.pyd",
    "python/_hashlib.pyd",
    "python/_ssl.pyd",
]
NativeCryptoPath = Literal[
    "python/_hashlib.pyd",
    "python/_ssl.pyd",
    "python/libcrypto-3.dll",
    "python/libssl-3.dll",
]
NativeLoaderStatus = Literal["readable", "missing", "access_denied", "other_error"]
NativeLoaderEvidenceStatus = Literal[
    "readable", "missing", "access_denied", "other_error", "not_observed"
]
NativeImportStatus = Literal["imported", "failed", "not_attempted"]
NativeImportEvidenceStatus = Literal["imported", "failed", "not_attempted", "not_observed"]
NativeLoaderCode = Literal[5, 126, 127, 193, 1114]


class WindowsNativeLoaderObservationV1(Contract):
    relative_path: NativeLoaderPath
    status: NativeLoaderStatus
    observed_sha256: Digest | None = None

    @model_validator(mode="after")
    def exact_hash_presence(self) -> WindowsNativeLoaderObservationV1:
        if (self.observed_sha256 is not None) != (self.status == "readable"):
            raise ValueError("Native loader observation hash does not match readability")
        return self


class WindowsIsolationChildFailureV3(Contract):
    schema_version: Literal[3] = 3
    phase: Literal["bootstrap_import", "bootstrap_invoke", "child_probe"] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None
    import_boundary: NativeImportBoundary | None = None
    loader_reason: NativeLoaderReason | None = None
    native_loader_observations: Annotated[
        tuple[WindowsNativeLoaderObservationV1, ...], Field(max_length=2)
    ] = ()

    @model_validator(mode="after")
    def strict_import_observation(self) -> WindowsIsolationChildFailureV3:
        is_import = self.phase == "bootstrap_import"
        if (self.import_boundary is not None) != is_import or (
            (self.loader_reason is not None) != is_import
        ):
            raise ValueError("Native loader category must exist only for bootstrap import")
        if is_import:
            paths = [item.relative_path for item in self.native_loader_observations]
            if paths != ["python/_ctypes.pyd", "python/libffi-8.dll"]:
                raise ValueError("Native loader observations must use the exact reviewed files")
        elif self.native_loader_observations:
            raise ValueError("Native loader observations require a bootstrap import failure")
        return self


class WindowsNativeMatrixFileObservationV1(Contract):
    relative_path: NativeMatrixPath
    status: NativeLoaderStatus
    observed_sha256: Digest | None = None

    @model_validator(mode="after")
    def exact_hash_presence(self) -> WindowsNativeMatrixFileObservationV1:
        if (self.observed_sha256 is not None) != (self.status == "readable"):
            raise ValueError("Native matrix observation hash does not match readability")
        return self


class WindowsNativeImportMatrixObservationV1(Contract):
    module: NativeMatrixModule
    file: WindowsNativeMatrixFileObservationV1
    import_status: NativeImportStatus

    @model_validator(mode="after")
    def exact_module_path(self) -> WindowsNativeImportMatrixObservationV1:
        expected = {
            "_socket": "python/_socket.pyd",
            "_overlapped": "python/_overlapped.pyd",
            "select": "python/select.pyd",
            "_ssl": "python/_ssl.pyd",
        }
        if self.file.relative_path != expected[self.module]:
            raise ValueError("Native matrix module differs from its reviewed file")
        return self


class WindowsIsolationChildFailureV4(Contract):
    schema_version: Literal[4] = 4
    phase: Literal[
        "bootstrap_native_matrix", "bootstrap_import", "bootstrap_invoke", "child_probe"
    ] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None
    failed_matrix_module: NativeMatrixModule | None = None
    import_boundary: NativeImportBoundary | None = None
    loader_code: NativeLoaderCode | None = None
    loader_reason: NativeLoaderReasonV4 | None = None
    native_import_matrix: Annotated[
        tuple[WindowsNativeImportMatrixObservationV1, ...], Field(max_length=4)
    ] = ()
    native_loader_observations: Annotated[
        tuple[WindowsNativeLoaderObservationV1, ...], Field(max_length=2)
    ] = ()

    @model_validator(mode="after")
    def strict_forward_diagnostic(self) -> WindowsIsolationChildFailureV4:
        matrix_phases = {"bootstrap_native_matrix", "bootstrap_import", "bootstrap_invoke"}
        loader_phases = {"bootstrap_native_matrix", "bootstrap_import"}
        if self.phase in matrix_phases:
            pairs = [(item.module, item.file.relative_path) for item in self.native_import_matrix]
            if pairs != [
                ("_socket", "python/_socket.pyd"),
                ("_overlapped", "python/_overlapped.pyd"),
                ("select", "python/select.pyd"),
                ("_ssl", "python/_ssl.pyd"),
            ]:
                raise ValueError("Native import matrix differs from the reviewed order")
        elif self.native_import_matrix:
            raise ValueError("Native import matrix requires a bootstrap phase")
        if self.phase == "bootstrap_native_matrix":
            if self.failed_matrix_module is None or self.import_boundary is not None:
                raise ValueError("Native matrix failure lacks its exact failed module")
            statuses = [item.import_status for item in self.native_import_matrix]
            failed_index = next(
                (
                    index
                    for index, item in enumerate(self.native_import_matrix)
                    if item.module == self.failed_matrix_module
                ),
                None,
            )
            if failed_index is None or statuses != [
                *(["imported"] * failed_index),
                "failed",
                *(["not_attempted"] * (3 - failed_index)),
            ]:
                raise ValueError("Native matrix statuses do not bind the failed module")
        else:
            if self.failed_matrix_module is not None:
                raise ValueError("Failed matrix module requires a native matrix failure")
            if self.phase in {"bootstrap_import", "bootstrap_invoke"} and any(
                item.import_status != "imported" for item in self.native_import_matrix
            ):
                raise ValueError("Full probe phases require a completed native import matrix")
        if self.phase == "bootstrap_import":
            if self.import_boundary is None:
                raise ValueError("Bootstrap import failure lacks its import boundary")
            paths = [item.relative_path for item in self.native_loader_observations]
            if paths != ["python/_ctypes.pyd", "python/libffi-8.dll"]:
                raise ValueError("Native loader observations must use the exact reviewed files")
        elif self.import_boundary is not None or self.native_loader_observations:
            raise ValueError("Native loader files require a full probe import failure")
        if self.phase in loader_phases:
            if self.loader_reason is None:
                raise ValueError("Native loader failure lacks a bounded reason")
            expected_codes: dict[str, int | None] = {
                "access_denied": 5,
                "dependency_not_found": 126,
                "procedure_not_found": 127,
                "bad_image": 193,
                "initialization_failed": 1114,
                "unknown": None,
            }
            if self.loader_code != expected_codes[self.loader_reason]:
                raise ValueError("Native loader code differs from its bounded reason")
        elif self.loader_reason is not None or self.loader_code is not None:
            raise ValueError("Native loader classification requires an import failure")
        return self


class WindowsDllDirectoryActivationV1(Contract):
    schema_version: Literal[1] = 1
    directory_kind: Literal["launcher_parent"] = "launcher_parent"
    status: Literal["active", "failed"]
    error_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)] | None = None

    @model_validator(mode="after")
    def bounded_status(self) -> WindowsDllDirectoryActivationV1:
        if self.status == "active" and self.error_code is not None:
            raise ValueError("Active DLL directory binding cannot retain an error code")
        return self


class WindowsNativeMatrixFileObservationV2(Contract):
    schema_version: Literal[2] = 2
    relative_path: NativeMatrixPathV5
    status: NativeLoaderStatus
    observed_sha256: Digest | None = None

    @model_validator(mode="after")
    def exact_hash_presence(self) -> WindowsNativeMatrixFileObservationV2:
        if (self.observed_sha256 is not None) != (self.status == "readable"):
            raise ValueError("Native matrix observation hash does not match readability")
        return self


class WindowsNativeImportMatrixObservationV2(Contract):
    schema_version: Literal[2] = 2
    module: NativeMatrixModuleV5
    file: WindowsNativeMatrixFileObservationV2
    import_status: NativeImportStatus

    @model_validator(mode="after")
    def exact_module_path(self) -> WindowsNativeImportMatrixObservationV2:
        expected = {
            "_socket": "python/_socket.pyd",
            "_overlapped": "python/_overlapped.pyd",
            "select": "python/select.pyd",
            "_hashlib": "python/_hashlib.pyd",
            "_ssl": "python/_ssl.pyd",
        }
        if self.file.relative_path != expected[self.module]:
            raise ValueError("Native matrix module differs from its reviewed file")
        return self


class WindowsNativeCryptoObservationV1(Contract):
    schema_version: Literal[1] = 1
    relative_path: NativeCryptoPath
    status: NativeLoaderStatus
    observed_sha256: Digest | None = None

    @model_validator(mode="after")
    def exact_hash_presence(self) -> WindowsNativeCryptoObservationV1:
        if (self.observed_sha256 is not None) != (self.status == "readable"):
            raise ValueError("Native crypto observation hash does not match readability")
        return self


class WindowsIsolationChildFailureV5(Contract):
    schema_version: Literal[5] = 5
    phase: Literal[
        "bootstrap_dll_directory",
        "bootstrap_native_matrix",
        "bootstrap_import",
        "bootstrap_invoke",
        "child_probe",
    ] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None
    dll_directory_activation: WindowsDllDirectoryActivationV1
    failed_matrix_module: NativeMatrixModuleV5 | None = None
    import_boundary: NativeImportBoundary | None = None
    loader_code: NativeLoaderCode | None = None
    loader_reason: NativeLoaderReasonV4 | None = None
    native_import_matrix: Annotated[
        tuple[WindowsNativeImportMatrixObservationV2, ...], Field(min_length=5, max_length=5)
    ]
    native_crypto_observations: Annotated[
        tuple[WindowsNativeCryptoObservationV1, ...], Field(min_length=4, max_length=4)
    ]
    native_loader_observations: Annotated[
        tuple[WindowsNativeLoaderObservationV1, ...], Field(max_length=2)
    ] = ()

    @model_validator(mode="after")
    def strict_forward_diagnostic(self) -> WindowsIsolationChildFailureV5:
        matrix_pairs = [
            (item.module, item.file.relative_path) for item in self.native_import_matrix
        ]
        if matrix_pairs != [
            ("_socket", "python/_socket.pyd"),
            ("_overlapped", "python/_overlapped.pyd"),
            ("select", "python/select.pyd"),
            ("_hashlib", "python/_hashlib.pyd"),
            ("_ssl", "python/_ssl.pyd"),
        ]:
            raise ValueError("Native import matrix differs from the reviewed V5 order")
        crypto_paths = [item.relative_path for item in self.native_crypto_observations]
        if crypto_paths != [
            "python/_hashlib.pyd",
            "python/_ssl.pyd",
            "python/libcrypto-3.dll",
            "python/libssl-3.dll",
        ]:
            raise ValueError("Native crypto observations differ from the reviewed set")
        statuses = [item.import_status for item in self.native_import_matrix]
        if self.phase == "bootstrap_dll_directory":
            if self.dll_directory_activation.status != "failed":
                raise ValueError("DLL directory failure requires a failed binding")
            if any(status != "not_attempted" for status in statuses):
                raise ValueError("DLL directory failure cannot authorize native imports")
            if self.failed_matrix_module is not None:
                raise ValueError("DLL directory failure cannot name a matrix module")
        else:
            if self.dll_directory_activation.status != "active":
                raise ValueError("Native import phases require an active DLL directory binding")
        if self.phase == "bootstrap_native_matrix":
            if self.failed_matrix_module is None:
                raise ValueError("Native matrix failure lacks its exact failed module")
            failed_index = next(
                (
                    index
                    for index, item in enumerate(self.native_import_matrix)
                    if item.module == self.failed_matrix_module
                ),
                None,
            )
            if failed_index is None or statuses != [
                *(["imported"] * failed_index),
                "failed",
                *(["not_attempted"] * (4 - failed_index)),
            ]:
                raise ValueError("Native matrix statuses do not bind the failed module")
        elif self.failed_matrix_module is not None:
            raise ValueError("Failed matrix module requires a native matrix failure")
        elif self.phase != "bootstrap_dll_directory" and any(
            status != "imported" for status in statuses
        ):
            raise ValueError("Post-matrix phases require a completed native import matrix")
        if self.phase == "bootstrap_import":
            if self.import_boundary is None:
                raise ValueError("Bootstrap import failure lacks its import boundary")
            paths = [item.relative_path for item in self.native_loader_observations]
            if paths != ["python/_ctypes.pyd", "python/libffi-8.dll"]:
                raise ValueError("Native loader observations must use the exact reviewed files")
        elif self.import_boundary is not None or self.native_loader_observations:
            raise ValueError("Native loader files require a full probe import failure")
        loader_failure = self.phase in {"bootstrap_native_matrix", "bootstrap_import"}
        if loader_failure:
            if self.loader_reason is None:
                raise ValueError("Native loader failure lacks a bounded reason")
            expected_codes: dict[str, int | None] = {
                "access_denied": 5,
                "dependency_not_found": 126,
                "procedure_not_found": 127,
                "bad_image": 193,
                "initialization_failed": 1114,
                "unknown": None,
            }
            if self.loader_code != expected_codes[self.loader_reason]:
                raise ValueError("Native loader code differs from its bounded reason")
        elif self.loader_reason is not None or self.loader_code is not None:
            raise ValueError("Loader classification requires an import failure")
        return self


class WindowsNativeLoaderActivationObservationV2(ContractV2):
    module_path: Literal["python/_devfabric_native_loader.pyd"] = (
        "python/_devfabric_native_loader.pyd"
    )
    status: Literal["active", "failed"]
    module_sha256: Digest | None = None
    activated_dependencies: tuple[str, ...] = Field(max_length=3)
    error_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)] | None = None

    @model_validator(mode="after")
    def exact_activation(self) -> WindowsNativeLoaderActivationObservationV2:
        expected = ("libffi-8.dll", "libcrypto-3.dll", "libssl-3.dll")
        if self.status == "active":
            if (
                self.module_sha256 is None
                or self.activated_dependencies != expected
                or self.error_code is not None
            ):
                raise ValueError("Active native loader differs from reviewed contract")
        elif self.module_sha256 is not None or self.activated_dependencies:
            raise ValueError("Failed native loader cannot authorize activation")
        return self


class WindowsNativeMatrixFileObservationV3(Contract):
    schema_version: Literal[3] = 3
    relative_path: NativeMatrixPathV6
    status: NativeLoaderStatus
    observed_sha256: Digest | None = None

    @model_validator(mode="after")
    def exact_hash_presence(self) -> WindowsNativeMatrixFileObservationV3:
        if (self.observed_sha256 is not None) != (self.status == "readable"):
            raise ValueError("Native matrix observation hash does not match readability")
        return self


class WindowsNativeImportMatrixObservationV3(Contract):
    schema_version: Literal[3] = 3
    module: NativeMatrixModuleV6
    file: WindowsNativeMatrixFileObservationV3
    import_status: NativeImportStatus

    @model_validator(mode="after")
    def exact_module_path(self) -> WindowsNativeImportMatrixObservationV3:
        expected = {
            "_ctypes": "python/_ctypes.pyd",
            "_socket": "python/_socket.pyd",
            "_overlapped": "python/_overlapped.pyd",
            "select": "python/select.pyd",
            "_hashlib": "python/_hashlib.pyd",
            "_ssl": "python/_ssl.pyd",
        }
        if self.file.relative_path != expected[self.module]:
            raise ValueError("Native matrix module differs from its reviewed file")
        return self


class WindowsIsolationChildFailureV6(Contract):
    schema_version: Literal[6] = 6
    phase: Literal[
        "bootstrap_native_loader",
        "bootstrap_native_matrix",
        "bootstrap_import",
        "bootstrap_invoke",
        "child_probe",
    ] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None
    native_loader_activation: WindowsNativeLoaderActivationObservationV2
    failed_matrix_module: NativeMatrixModuleV6 | None = None
    import_boundary: NativeImportBoundary | None = None
    loader_code: NativeLoaderCode | None = None
    loader_reason: NativeLoaderReasonV4 | None = None
    native_import_matrix: Annotated[
        tuple[WindowsNativeImportMatrixObservationV3, ...], Field(min_length=6, max_length=6)
    ]
    native_crypto_observations: Annotated[
        tuple[WindowsNativeCryptoObservationV1, ...], Field(min_length=4, max_length=4)
    ]

    @model_validator(mode="after")
    def strict_forward_diagnostic(self) -> WindowsIsolationChildFailureV6:
        expected_pairs = [
            ("_ctypes", "python/_ctypes.pyd"),
            ("_socket", "python/_socket.pyd"),
            ("_overlapped", "python/_overlapped.pyd"),
            ("select", "python/select.pyd"),
            ("_hashlib", "python/_hashlib.pyd"),
            ("_ssl", "python/_ssl.pyd"),
        ]
        if [(item.module, item.file.relative_path) for item in self.native_import_matrix] != (
            expected_pairs
        ):
            raise ValueError("Native import matrix differs from reviewed V6 order")
        if [item.relative_path for item in self.native_crypto_observations] != [
            "python/_hashlib.pyd",
            "python/_ssl.pyd",
            "python/libcrypto-3.dll",
            "python/libssl-3.dll",
        ]:
            raise ValueError("Native crypto observations differ from reviewed set")
        statuses = [item.import_status for item in self.native_import_matrix]
        if self.phase == "bootstrap_native_loader":
            if self.native_loader_activation.status != "failed":
                raise ValueError("Native-loader failure requires a failed activation")
            if any(status != "not_attempted" for status in statuses):
                raise ValueError("Native-loader failure cannot authorize native imports")
        elif self.native_loader_activation.status != "active":
            raise ValueError("Post-activation phases require an active native loader")
        if self.phase == "bootstrap_native_matrix":
            if self.failed_matrix_module is None:
                raise ValueError("Native matrix failure lacks its exact failed module")
            failed_index = next(
                index
                for index, item in enumerate(self.native_import_matrix)
                if item.module == self.failed_matrix_module
            )
            if statuses != [
                *("imported" for _ in range(failed_index)),
                "failed",
                *("not_attempted" for _ in range(5 - failed_index)),
            ]:
                raise ValueError("Native matrix statuses do not bind the failed module")
        elif self.failed_matrix_module is not None:
            raise ValueError("Failed matrix module requires a native matrix failure")
        elif self.phase != "bootstrap_native_loader" and any(
            status != "imported" for status in statuses
        ):
            raise ValueError("Post-matrix phases require a completed native import matrix")
        if self.phase == "bootstrap_import":
            if self.import_boundary is None:
                raise ValueError("Bootstrap import failure lacks its import boundary")
        elif self.import_boundary is not None:
            raise ValueError("Import boundary requires a bootstrap import failure")
        loader_failure = self.phase in {
            "bootstrap_native_loader",
            "bootstrap_native_matrix",
            "bootstrap_import",
        }
        if loader_failure:
            if self.loader_reason is None:
                raise ValueError("Native loader failure lacks a bounded reason")
            expected_codes: dict[str, int | None] = {
                "access_denied": 5,
                "dependency_not_found": 126,
                "procedure_not_found": 127,
                "bad_image": 193,
                "initialization_failed": 1114,
                "unknown": None,
            }
            if self.loader_code != expected_codes[self.loader_reason]:
                raise ValueError("Native loader code differs from its bounded reason")
        elif self.loader_reason is not None or self.loader_code is not None:
            raise ValueError("Loader classification requires an import failure")
        return self


class WindowsNativeLoaderFileEvidenceV1(Contract):
    relative_path: NativeLoaderPath
    expected_sha256: Digest
    child_status: NativeLoaderEvidenceStatus
    child_observed_sha256: Digest | None = None

    @model_validator(mode="after")
    def exact_manifest_join(self) -> WindowsNativeLoaderFileEvidenceV1:
        if (self.child_observed_sha256 is not None) != (self.child_status == "readable"):
            raise ValueError("Native loader evidence hash does not match readability")
        if (
            self.child_observed_sha256 is not None
            and self.child_observed_sha256 != self.expected_sha256
        ):
            raise ValueError("Native loader child hash differs from immutable manifest")
        return self


class WindowsNativeImportMatrixEvidenceV1(Contract):
    module: NativeMatrixModule
    relative_path: NativeMatrixPath
    expected_sha256: Digest
    child_file_status: NativeLoaderEvidenceStatus
    child_observed_sha256: Digest | None = None
    child_import_status: NativeImportEvidenceStatus

    @model_validator(mode="after")
    def exact_manifest_join(self) -> WindowsNativeImportMatrixEvidenceV1:
        expected = {
            "_socket": "python/_socket.pyd",
            "_overlapped": "python/_overlapped.pyd",
            "select": "python/select.pyd",
            "_ssl": "python/_ssl.pyd",
        }
        if self.relative_path != expected[self.module]:
            raise ValueError("Native matrix evidence module differs from reviewed file")
        if (self.child_observed_sha256 is not None) != (self.child_file_status == "readable"):
            raise ValueError("Native matrix evidence hash does not match readability")
        if (
            self.child_observed_sha256 is not None
            and self.child_observed_sha256 != self.expected_sha256
        ):
            raise ValueError("Native matrix child hash differs from immutable manifest")
        return self


class WindowsNativeImportMatrixEvidenceV2(Contract):
    schema_version: Literal[2] = 2
    module: NativeMatrixModuleV5
    relative_path: NativeMatrixPathV5
    expected_sha256: Digest
    child_file_status: NativeLoaderEvidenceStatus
    child_observed_sha256: Digest | None = None
    child_import_status: NativeImportEvidenceStatus

    @model_validator(mode="after")
    def exact_manifest_join(self) -> WindowsNativeImportMatrixEvidenceV2:
        expected = {
            "_socket": "python/_socket.pyd",
            "_overlapped": "python/_overlapped.pyd",
            "select": "python/select.pyd",
            "_hashlib": "python/_hashlib.pyd",
            "_ssl": "python/_ssl.pyd",
        }
        if self.relative_path != expected[self.module]:
            raise ValueError("Native matrix evidence module differs from reviewed file")
        if (self.child_observed_sha256 is not None) != (self.child_file_status == "readable"):
            raise ValueError("Native matrix evidence hash does not match readability")
        if (
            self.child_observed_sha256 is not None
            and self.child_observed_sha256 != self.expected_sha256
        ):
            raise ValueError("Native matrix child hash differs from immutable manifest")
        return self


class WindowsNativeImportMatrixEvidenceV3(Contract):
    schema_version: Literal[3] = 3
    module: NativeMatrixModuleV6
    relative_path: NativeMatrixPathV6
    expected_sha256: Digest
    child_file_status: NativeLoaderEvidenceStatus
    child_observed_sha256: Digest | None = None
    child_import_status: NativeImportEvidenceStatus

    @model_validator(mode="after")
    def exact_manifest_join(self) -> WindowsNativeImportMatrixEvidenceV3:
        expected = {
            "_ctypes": "python/_ctypes.pyd",
            "_socket": "python/_socket.pyd",
            "_overlapped": "python/_overlapped.pyd",
            "select": "python/select.pyd",
            "_hashlib": "python/_hashlib.pyd",
            "_ssl": "python/_ssl.pyd",
        }
        if self.relative_path != expected[self.module]:
            raise ValueError("Native matrix evidence module differs from reviewed file")
        if (self.child_observed_sha256 is not None) != (self.child_file_status == "readable"):
            raise ValueError("Native matrix evidence hash does not match readability")
        if (
            self.child_observed_sha256 is not None
            and self.child_observed_sha256 != self.expected_sha256
        ):
            raise ValueError("Native matrix child hash differs from immutable manifest")
        return self


class WindowsNativeCryptoFileEvidenceV1(Contract):
    schema_version: Literal[1] = 1
    relative_path: NativeCryptoPath
    expected_sha256: Digest
    child_status: NativeLoaderEvidenceStatus
    child_observed_sha256: Digest | None = None

    @model_validator(mode="after")
    def exact_manifest_join(self) -> WindowsNativeCryptoFileEvidenceV1:
        if (self.child_observed_sha256 is not None) != (self.child_status == "readable"):
            raise ValueError("Native crypto evidence hash does not match readability")
        if (
            self.child_observed_sha256 is not None
            and self.child_observed_sha256 != self.expected_sha256
        ):
            raise ValueError("Native crypto child hash differs from immutable manifest")
        return self


class WindowsIsolationBootstrapStartedPayloadV1(Contract):
    schema_version: Literal[1] = 1
    phase: Literal["bootstrap_started"] = "bootstrap_started"
    child_bootstrap_sha256: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    probe_sha256: Digest


class WindowsIsolationBootstrapStartedV1(Contract):
    bootstrap_started_id: Digest
    payload: WindowsIsolationBootstrapStartedPayloadV1

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationBootstrapStartedV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.bootstrap_started_id != expected:
            raise ValueError("Windows isolation bootstrap-started hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV1(Contract):
    schema_version: Literal[1] = 1
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    probe_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV1 | None = None
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_child_failure_status(self) -> WindowsIsolationFailureDiagnosticPayloadV1:
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match the validated diagnostic")
        return self


class WindowsIsolationFailureDiagnosticV1(Contract):
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV1

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV1
    ) -> WindowsIsolationFailureDiagnosticV1:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV2(ContractV2):
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    probe_sha256: Digest
    child_bootstrap_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    bootstrap_started_status: Literal["absent", "validated", "invalid"]
    bootstrap_started: WindowsIsolationBootstrapStartedV1 | None = None
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV2 | None = None
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_status_and_bindings(self) -> WindowsIsolationFailureDiagnosticPayloadV2:
        if (self.bootstrap_started is not None) != (self.bootstrap_started_status == "validated"):
            raise ValueError("Bootstrap-started status does not match the validated frame")
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match the validated diagnostic")
        if self.bootstrap_started is not None:
            started = self.bootstrap_started.payload
            if (
                started.child_bootstrap_sha256 != self.child_bootstrap_sha256
                or started.environment_instance_id != self.environment_instance_id
                or started.windows_isolation_profile_id != self.windows_isolation_profile_id
                or started.probe_sha256 != self.probe_sha256
            ):
                raise ValueError("Bootstrap-started frame does not bind the failed child")
        return self


class WindowsIsolationFailureDiagnosticV2(ContractV2):
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV2

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV2
    ) -> WindowsIsolationFailureDiagnosticV2:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV3(Contract):
    schema_version: Literal[3] = 3
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    profile: WindowsIsolationProfileV2
    native_bundle_id: Digest
    launcher_executable_sha256: Digest
    runtime_access_grant: WindowsRuntimeAccessGrantV2
    probe_sha256: Digest
    child_bootstrap_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    bootstrap_started_status: Literal["absent", "validated", "invalid"]
    bootstrap_started: WindowsIsolationBootstrapStartedV1 | None = None
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV3 | None = None
    loader_reason: NativeLoaderReason | None = None
    native_loader_files: Annotated[
        tuple[WindowsNativeLoaderFileEvidenceV1, ...], Field(min_length=2, max_length=2)
    ]
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_authority_joins(self) -> WindowsIsolationFailureDiagnosticPayloadV3:
        if (self.bootstrap_started is not None) != (self.bootstrap_started_status == "validated"):
            raise ValueError("Bootstrap-started status does not match the validated frame")
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match the validated diagnostic")
        profile = self.profile
        expected_profile_id = profile.windows_isolation_profile_id
        if self.windows_isolation_profile_id != expected_profile_id:
            raise ValueError("Failure diagnostic profile identity mismatch")
        profile_payload = profile.payload
        if (
            self.environment_instance_id != profile_payload.environment_instance_id
            or self.native_bundle_id != profile_payload.native_bundle_id
            or self.launcher_executable_sha256 != profile_payload.launcher_executable_sha256
            or self.probe_sha256 != profile_payload.probe_sha256
            or self.child_bootstrap_sha256 != profile_payload.child_bootstrap_sha256
        ):
            raise ValueError("Failure diagnostic authority differs from isolation profile")
        grant = self.runtime_access_grant.payload
        if (
            grant.appcontainer_identity != profile_payload.appcontainer_identity
            or grant.native_bundle_id != self.native_bundle_id
            or grant.launcher_executable_sha256 != self.launcher_executable_sha256
            or len(profile_payload.read_only_roots) != 1
            or grant.root != profile_payload.read_only_roots[0]
        ):
            raise ValueError("Failure diagnostic runtime grant differs from isolation profile")
        if self.bootstrap_started is not None:
            started = self.bootstrap_started.payload
            if (
                started.child_bootstrap_sha256 != self.child_bootstrap_sha256
                or started.environment_instance_id != self.environment_instance_id
                or started.windows_isolation_profile_id != self.windows_isolation_profile_id
                or started.probe_sha256 != self.probe_sha256
            ):
                raise ValueError("Bootstrap-started frame does not bind the failed child")
        paths = [item.relative_path for item in self.native_loader_files]
        if paths != ["python/_ctypes.pyd", "python/libffi-8.dll"]:
            raise ValueError("Failure diagnostic native loader files differ from reviewed set")
        if self.child_failure is None:
            if self.loader_reason is not None:
                raise ValueError("Loader reason requires a validated child failure")
        else:
            failure = self.child_failure
            if self.loader_reason != failure.loader_reason:
                raise ValueError("Loader reason differs from validated child failure")
            if failure.phase == "bootstrap_import":
                boundary = failure.import_boundary
                if boundary is None:
                    raise ValueError("Bootstrap import failure lacks an import boundary")
                exit_codes = {
                    "ctypes": 199,
                    "socket": 200,
                    "pydantic_core": 201,
                    "devhub": 202,
                    "unknown": 203,
                }
                if self.process_exit_code != exit_codes[boundary]:
                    raise ValueError("Process exit code differs from import boundary")
                observations = {
                    item.relative_path: item for item in failure.native_loader_observations
                }
                for item in self.native_loader_files:
                    child = observations[item.relative_path]
                    if (
                        item.child_status != child.status
                        or item.child_observed_sha256 != child.observed_sha256
                    ):
                        raise ValueError("Native loader evidence differs from child observation")
        return self


class WindowsIsolationFailureDiagnosticV3(Contract):
    schema_version: Literal[3] = 3
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV3

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV3
    ) -> WindowsIsolationFailureDiagnosticV3:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV4(Contract):
    schema_version: Literal[4] = 4
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    profile: WindowsIsolationProfileV2
    native_bundle_id: Digest
    launcher_executable_sha256: Digest
    runtime_access_grant: WindowsRuntimeAccessGrantV2
    probe_sha256: Digest
    child_bootstrap_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    bootstrap_started_status: Literal["absent", "validated", "invalid"]
    bootstrap_started: WindowsIsolationBootstrapStartedV1 | None = None
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV4 | None = None
    loader_reason: NativeLoaderReasonV4 | None = None
    loader_code: NativeLoaderCode | None = None
    native_loader_files: Annotated[
        tuple[WindowsNativeLoaderFileEvidenceV1, ...], Field(min_length=2, max_length=2)
    ]
    native_import_matrix: Annotated[
        tuple[WindowsNativeImportMatrixEvidenceV1, ...], Field(min_length=4, max_length=4)
    ]
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_authority_joins(self) -> WindowsIsolationFailureDiagnosticPayloadV4:
        if (self.bootstrap_started is not None) != (self.bootstrap_started_status == "validated"):
            raise ValueError("Bootstrap-started status does not match the validated frame")
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match the validated diagnostic")
        profile = self.profile
        profile_payload = profile.payload
        if self.windows_isolation_profile_id != profile.windows_isolation_profile_id:
            raise ValueError("Failure diagnostic profile identity mismatch")
        if (
            self.environment_instance_id != profile_payload.environment_instance_id
            or self.native_bundle_id != profile_payload.native_bundle_id
            or self.launcher_executable_sha256 != profile_payload.launcher_executable_sha256
            or self.probe_sha256 != profile_payload.probe_sha256
            or self.child_bootstrap_sha256 != profile_payload.child_bootstrap_sha256
        ):
            raise ValueError("Failure diagnostic authority differs from isolation profile")
        grant = self.runtime_access_grant.payload
        if (
            grant.appcontainer_identity != profile_payload.appcontainer_identity
            or grant.native_bundle_id != self.native_bundle_id
            or grant.launcher_executable_sha256 != self.launcher_executable_sha256
            or len(profile_payload.read_only_roots) != 1
            or grant.root != profile_payload.read_only_roots[0]
        ):
            raise ValueError("Failure diagnostic runtime grant differs from isolation profile")
        if self.bootstrap_started is not None:
            started = self.bootstrap_started.payload
            if (
                started.child_bootstrap_sha256 != self.child_bootstrap_sha256
                or started.environment_instance_id != self.environment_instance_id
                or started.windows_isolation_profile_id != self.windows_isolation_profile_id
                or started.probe_sha256 != self.probe_sha256
            ):
                raise ValueError("Bootstrap-started frame does not bind the failed child")
        loader_paths = [item.relative_path for item in self.native_loader_files]
        if loader_paths != ["python/_ctypes.pyd", "python/libffi-8.dll"]:
            raise ValueError("Failure diagnostic native loader files differ from reviewed set")
        matrix_pairs = [(item.module, item.relative_path) for item in self.native_import_matrix]
        if matrix_pairs != [
            ("_socket", "python/_socket.pyd"),
            ("_overlapped", "python/_overlapped.pyd"),
            ("select", "python/select.pyd"),
            ("_ssl", "python/_ssl.pyd"),
        ]:
            raise ValueError("Failure diagnostic native import matrix differs from reviewed set")
        if self.child_failure is None:
            if self.loader_reason is not None or self.loader_code is not None:
                raise ValueError("Loader classification requires a validated child failure")
            if any(
                item.child_file_status != "not_observed"
                or item.child_import_status != "not_observed"
                for item in self.native_import_matrix
            ):
                raise ValueError("Unvalidated child cannot authorize native matrix observations")
        else:
            failure = self.child_failure
            if (
                self.loader_reason != failure.loader_reason
                or self.loader_code != failure.loader_code
            ):
                raise ValueError("Loader classification differs from validated child failure")
            if failure.phase == "bootstrap_import":
                if failure.import_boundary is None:
                    raise ValueError("Validated bootstrap import lacks its import boundary")
                exit_codes = {
                    "ctypes": 199,
                    "socket": 200,
                    "pydantic_core": 201,
                    "devhub": 202,
                    "unknown": 203,
                }
                if self.process_exit_code != exit_codes[failure.import_boundary]:
                    raise ValueError("Process exit code differs from import boundary")
            elif failure.phase == "bootstrap_native_matrix":
                if failure.failed_matrix_module is None:
                    raise ValueError("Validated matrix failure lacks its failed module")
                matrix_exit_codes = {
                    "_socket": 204,
                    "_overlapped": 205,
                    "select": 206,
                    "_ssl": 207,
                }
                if self.process_exit_code != matrix_exit_codes[failure.failed_matrix_module]:
                    raise ValueError("Process exit code differs from native matrix failure")
            elif failure.phase == "bootstrap_invoke" and self.process_exit_code != 196:
                raise ValueError("Process exit code differs from bootstrap invoke failure")
            elif failure.phase == "child_probe" and self.process_exit_code != 1:
                raise ValueError("Process exit code differs from guarded child failure")
            loader_observations = {
                item.relative_path: item for item in failure.native_loader_observations
            }
            for item in self.native_loader_files:
                child = loader_observations.get(item.relative_path)
                expected_status = child.status if child is not None else "not_observed"
                expected_hash = child.observed_sha256 if child is not None else None
                if (
                    item.child_status != expected_status
                    or item.child_observed_sha256 != expected_hash
                ):
                    raise ValueError("Native loader evidence differs from child observation")
            matrix_observations = {item.module: item for item in failure.native_import_matrix}
            for item in self.native_import_matrix:
                child = matrix_observations.get(item.module)
                if child is None:
                    if (
                        item.child_file_status != "not_observed"
                        or item.child_import_status != "not_observed"
                    ):
                        raise ValueError(
                            "Native matrix evidence lacks a validated child observation"
                        )
                    continue
                if (
                    item.relative_path != child.file.relative_path
                    or item.child_file_status != child.file.status
                    or item.child_observed_sha256 != child.file.observed_sha256
                    or item.child_import_status != child.import_status
                ):
                    raise ValueError("Native matrix evidence differs from child observation")
        return self


class WindowsIsolationFailureDiagnosticV4(Contract):
    schema_version: Literal[4] = 4
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV4

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV4
    ) -> WindowsIsolationFailureDiagnosticV4:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV4:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV5(Contract):
    schema_version: Literal[5] = 5
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    profile: WindowsIsolationProfileV2
    native_bundle_id: Digest
    launcher_executable_sha256: Digest
    runtime_access_grant: WindowsRuntimeAccessGrantV2
    probe_sha256: Digest
    child_bootstrap_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    bootstrap_started_status: Literal["absent", "validated", "invalid"]
    bootstrap_started: WindowsIsolationBootstrapStartedV1 | None = None
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV5 | None = None
    dll_directory_activation: WindowsDllDirectoryActivationV1 | None = None
    loader_reason: NativeLoaderReasonV4 | None = None
    loader_code: NativeLoaderCode | None = None
    native_loader_files: Annotated[
        tuple[WindowsNativeLoaderFileEvidenceV1, ...], Field(min_length=2, max_length=2)
    ]
    native_import_matrix: Annotated[
        tuple[WindowsNativeImportMatrixEvidenceV2, ...], Field(min_length=5, max_length=5)
    ]
    native_crypto_files: Annotated[
        tuple[WindowsNativeCryptoFileEvidenceV1, ...], Field(min_length=4, max_length=4)
    ]
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_authority_joins(self) -> WindowsIsolationFailureDiagnosticPayloadV5:
        if (self.bootstrap_started is not None) != (self.bootstrap_started_status == "validated"):
            raise ValueError("Bootstrap-started status does not match the validated frame")
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match the validated diagnostic")
        profile_payload = self.profile.payload
        if self.windows_isolation_profile_id != self.profile.windows_isolation_profile_id:
            raise ValueError("Failure diagnostic profile identity mismatch")
        if (
            self.environment_instance_id != profile_payload.environment_instance_id
            or self.native_bundle_id != profile_payload.native_bundle_id
            or self.launcher_executable_sha256 != profile_payload.launcher_executable_sha256
            or self.probe_sha256 != profile_payload.probe_sha256
            or self.child_bootstrap_sha256 != profile_payload.child_bootstrap_sha256
        ):
            raise ValueError("Failure diagnostic authority differs from isolation profile")
        grant = self.runtime_access_grant.payload
        if (
            grant.appcontainer_identity != profile_payload.appcontainer_identity
            or grant.native_bundle_id != self.native_bundle_id
            or grant.launcher_executable_sha256 != self.launcher_executable_sha256
            or len(profile_payload.read_only_roots) != 1
            or grant.root != profile_payload.read_only_roots[0]
        ):
            raise ValueError("Failure diagnostic runtime grant differs from isolation profile")
        if self.bootstrap_started is not None:
            started = self.bootstrap_started.payload
            if (
                started.child_bootstrap_sha256 != self.child_bootstrap_sha256
                or started.environment_instance_id != self.environment_instance_id
                or started.windows_isolation_profile_id != self.windows_isolation_profile_id
                or started.probe_sha256 != self.probe_sha256
            ):
                raise ValueError("Bootstrap-started frame does not bind the failed child")
        if [item.relative_path for item in self.native_loader_files] != [
            "python/_ctypes.pyd",
            "python/libffi-8.dll",
        ]:
            raise ValueError("Failure diagnostic native loader files differ from reviewed set")
        if [(item.module, item.relative_path) for item in self.native_import_matrix] != [
            ("_socket", "python/_socket.pyd"),
            ("_overlapped", "python/_overlapped.pyd"),
            ("select", "python/select.pyd"),
            ("_hashlib", "python/_hashlib.pyd"),
            ("_ssl", "python/_ssl.pyd"),
        ]:
            raise ValueError("Failure diagnostic native import matrix differs from reviewed set")
        if [item.relative_path for item in self.native_crypto_files] != [
            "python/_hashlib.pyd",
            "python/_ssl.pyd",
            "python/libcrypto-3.dll",
            "python/libssl-3.dll",
        ]:
            raise ValueError("Failure diagnostic native crypto files differ from reviewed set")
        failure = self.child_failure
        if failure is None:
            if (
                self.dll_directory_activation is not None
                or self.loader_reason is not None
                or self.loader_code is not None
            ):
                raise ValueError("Unvalidated child cannot authorize DLL-loader observations")
            if any(
                item.child_file_status != "not_observed"
                or item.child_import_status != "not_observed"
                for item in self.native_import_matrix
            ) or any(
                item.child_status != "not_observed"
                for item in (*self.native_loader_files, *self.native_crypto_files)
            ):
                raise ValueError("Unvalidated child cannot authorize native observations")
            return self
        if self.dll_directory_activation != failure.dll_directory_activation:
            raise ValueError("DLL directory activation differs from validated child failure")
        if self.loader_reason != failure.loader_reason or self.loader_code != failure.loader_code:
            raise ValueError("Loader classification differs from validated child failure")
        expected_exit: int
        if failure.phase == "bootstrap_dll_directory":
            expected_exit = 208
        elif failure.phase == "bootstrap_native_matrix":
            if failure.failed_matrix_module is None:
                raise ValueError("Validated matrix failure lacks its failed module")
            expected_exit = {
                "_socket": 204,
                "_overlapped": 205,
                "select": 206,
                "_hashlib": 209,
                "_ssl": 210,
            }[failure.failed_matrix_module]
        elif failure.phase == "bootstrap_import":
            if failure.import_boundary is None:
                raise ValueError("Validated bootstrap import lacks its import boundary")
            expected_exit = {
                "ctypes": 199,
                "socket": 200,
                "pydantic_core": 201,
                "devhub": 202,
                "unknown": 203,
            }[failure.import_boundary]
        elif failure.phase == "bootstrap_invoke":
            expected_exit = 196
        else:
            expected_exit = 1
        if self.process_exit_code != expected_exit:
            raise ValueError("Process exit code differs from validated child failure")
        loader_observations = {
            item.relative_path: item for item in failure.native_loader_observations
        }
        for item in self.native_loader_files:
            child = loader_observations.get(item.relative_path)
            expected_status = child.status if child is not None else "not_observed"
            expected_hash = child.observed_sha256 if child is not None else None
            if item.child_status != expected_status or item.child_observed_sha256 != expected_hash:
                raise ValueError("Native loader evidence differs from child observation")
        matrix_observations = {item.module: item for item in failure.native_import_matrix}
        for item in self.native_import_matrix:
            child = matrix_observations[item.module]
            if (
                item.relative_path != child.file.relative_path
                or item.child_file_status != child.file.status
                or item.child_observed_sha256 != child.file.observed_sha256
                or item.child_import_status != child.import_status
            ):
                raise ValueError("Native matrix evidence differs from child observation")
        crypto_observations = {
            item.relative_path: item for item in failure.native_crypto_observations
        }
        for item in self.native_crypto_files:
            child = crypto_observations[item.relative_path]
            if (
                item.child_status != child.status
                or item.child_observed_sha256 != child.observed_sha256
            ):
                raise ValueError("Native crypto evidence differs from child observation")
        return self


class WindowsIsolationFailureDiagnosticV5(Contract):
    schema_version: Literal[5] = 5
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV5

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV5
    ) -> WindowsIsolationFailureDiagnosticV5:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV5:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV6(Contract):
    schema_version: Literal[6] = 6
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    profile: WindowsIsolationProfileV3
    native_bundle_id: Digest
    launcher_executable_sha256: Digest
    runtime_access_grant: WindowsRuntimeAccessGrantV2
    probe_sha256: Digest
    child_bootstrap_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    bootstrap_started_status: Literal["absent", "validated", "invalid"]
    bootstrap_started: WindowsIsolationBootstrapStartedV1 | None = None
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV6 | None = None
    native_loader_activation: WindowsNativeLoaderActivationObservationV2 | None = None
    loader_reason: NativeLoaderReasonV4 | None = None
    loader_code: NativeLoaderCode | None = None
    native_import_matrix: Annotated[
        tuple[WindowsNativeImportMatrixEvidenceV3, ...], Field(min_length=6, max_length=6)
    ]
    native_crypto_files: Annotated[
        tuple[WindowsNativeCryptoFileEvidenceV1, ...], Field(min_length=4, max_length=4)
    ]
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_authority_joins(self) -> WindowsIsolationFailureDiagnosticPayloadV6:
        if (self.bootstrap_started is not None) != (self.bootstrap_started_status == "validated"):
            raise ValueError("Bootstrap-started status does not match validated frame")
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match validated diagnostic")
        profile = self.profile.payload
        if (
            self.windows_isolation_profile_id != self.profile.windows_isolation_profile_id
            or self.environment_instance_id != profile.environment_instance_id
            or self.native_bundle_id != profile.native_bundle_id
            or self.launcher_executable_sha256 != profile.launcher_executable_sha256
            or self.probe_sha256 != profile.probe_sha256
            or self.child_bootstrap_sha256 != profile.child_bootstrap_sha256
        ):
            raise ValueError("Failure diagnostic authority differs from V6 profile")
        grant = self.runtime_access_grant.payload
        if (
            grant.appcontainer_identity != profile.appcontainer_identity
            or grant.native_bundle_id != self.native_bundle_id
            or grant.launcher_executable_sha256 != self.launcher_executable_sha256
            or len(profile.read_only_roots) != 1
            or grant.root != profile.read_only_roots[0]
        ):
            raise ValueError("Failure diagnostic runtime grant differs from V6 profile")
        if self.bootstrap_started is not None:
            started = self.bootstrap_started.payload
            if (
                started.child_bootstrap_sha256 != self.child_bootstrap_sha256
                or started.environment_instance_id != self.environment_instance_id
                or started.windows_isolation_profile_id != self.windows_isolation_profile_id
                or started.probe_sha256 != self.probe_sha256
            ):
                raise ValueError("Bootstrap-started frame does not bind failed V6 child")
        expected_pairs = [
            ("_ctypes", "python/_ctypes.pyd"),
            ("_socket", "python/_socket.pyd"),
            ("_overlapped", "python/_overlapped.pyd"),
            ("select", "python/select.pyd"),
            ("_hashlib", "python/_hashlib.pyd"),
            ("_ssl", "python/_ssl.pyd"),
        ]
        if [
            (item.module, item.relative_path) for item in self.native_import_matrix
        ] != expected_pairs:
            raise ValueError("Failure diagnostic native import matrix differs from reviewed V6 set")
        if [item.relative_path for item in self.native_crypto_files] != [
            "python/_hashlib.pyd",
            "python/_ssl.pyd",
            "python/libcrypto-3.dll",
            "python/libssl-3.dll",
        ]:
            raise ValueError("Failure diagnostic native crypto files differ from reviewed set")
        if [
            (item.module, item.relative_path, item.expected_sha256)
            for item in self.native_import_matrix
        ] != [
            (item.module, item.relative_path, item.expected_sha256)
            for item in profile.native_import_expectations
        ]:
            raise ValueError("Failure diagnostic native matrix differs from V6 profile authority")
        matrix_authority = {
            item.relative_path: item.expected_sha256 for item in profile.native_import_expectations
        }
        dependency_authority = {
            f"python/{item.filename}": item.sha256 for item in profile.native_loader.dependencies
        }
        crypto_authority = {
            "python/_hashlib.pyd": matrix_authority["python/_hashlib.pyd"],
            "python/_ssl.pyd": matrix_authority["python/_ssl.pyd"],
            "python/libcrypto-3.dll": dependency_authority["python/libcrypto-3.dll"],
            "python/libssl-3.dll": dependency_authority["python/libssl-3.dll"],
        }
        if any(
            item.expected_sha256 != crypto_authority[item.relative_path]
            for item in self.native_crypto_files
        ):
            raise ValueError("Failure diagnostic native crypto differs from V6 profile authority")
        failure = self.child_failure
        if failure is None:
            if (
                self.native_loader_activation is not None
                or self.loader_reason is not None
                or self.loader_code is not None
            ):
                raise ValueError("Unvalidated child cannot authorize native-loader observations")
            if any(
                item.child_file_status != "not_observed"
                or item.child_import_status != "not_observed"
                for item in self.native_import_matrix
            ) or any(item.child_status != "not_observed" for item in self.native_crypto_files):
                raise ValueError("Unvalidated child cannot authorize native observations")
            return self
        if self.native_loader_activation != failure.native_loader_activation:
            raise ValueError("Native-loader activation differs from validated child failure")
        if self.loader_reason != failure.loader_reason or self.loader_code != failure.loader_code:
            raise ValueError("Loader classification differs from validated child failure")
        if failure.native_loader_activation.status == "active" and (
            failure.native_loader_activation.module_sha256 != profile.native_loader.binary_sha256
        ):
            raise ValueError("Child activated a native loader outside reviewed authority")
        expected_exit: int
        if failure.phase == "bootstrap_native_loader":
            expected_exit = 211
        elif failure.phase == "bootstrap_native_matrix":
            if failure.failed_matrix_module is None:
                raise ValueError("Validated matrix failure lacks failed module")
            expected_exit = {
                "_ctypes": 212,
                "_socket": 204,
                "_overlapped": 205,
                "select": 206,
                "_hashlib": 209,
                "_ssl": 210,
            }[failure.failed_matrix_module]
        elif failure.phase == "bootstrap_import":
            if failure.import_boundary is None:
                raise ValueError("Validated bootstrap import lacks import boundary")
            expected_exit = {
                "ctypes": 199,
                "socket": 200,
                "pydantic_core": 201,
                "devhub": 202,
                "unknown": 203,
            }[failure.import_boundary]
        elif failure.phase == "bootstrap_invoke":
            expected_exit = 196
        else:
            expected_exit = 1
        if self.process_exit_code != expected_exit:
            raise ValueError("Process exit code differs from validated V6 child failure")
        observed = {item.module: item for item in failure.native_import_matrix}
        for item in self.native_import_matrix:
            child = observed[item.module]
            if (
                item.relative_path != child.file.relative_path
                or item.child_file_status != child.file.status
                or item.child_observed_sha256 != child.file.observed_sha256
                or item.child_import_status != child.import_status
            ):
                raise ValueError("V6 native matrix evidence differs from child observation")
        crypto = {item.relative_path: item for item in failure.native_crypto_observations}
        for item in self.native_crypto_files:
            child = crypto[item.relative_path]
            if (
                item.child_status != child.status
                or item.child_observed_sha256 != child.observed_sha256
            ):
                raise ValueError("V6 native crypto evidence differs from child observation")
        return self


class WindowsIsolationFailureDiagnosticV6(Contract):
    schema_version: Literal[6] = 6
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV6

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV6
    ) -> WindowsIsolationFailureDiagnosticV6:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV6:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationChildExitError(RuntimeError):
    phase = "child_before_evidence"

    def __init__(
        self,
        diagnostic: (
            WindowsIsolationFailureDiagnosticV2
            | WindowsIsolationFailureDiagnosticV3
            | WindowsIsolationFailureDiagnosticV4
            | WindowsIsolationFailureDiagnosticV5
            | WindowsIsolationFailureDiagnosticV6
        ),
    ) -> None:
        self.diagnostic = diagnostic
        self.exit_code = diagnostic.payload.process_exit_code
        super().__init__(
            "Windows isolation child exited before evidence "
            f"(exit_code={self.exit_code}, hex=0x{self.exit_code:08X}, "
            f"bootstrap_started={diagnostic.payload.bootstrap_started_status}, "
            f"child_failure={diagnostic.payload.child_failure_status})"
        )


def _error_code(error: BaseException) -> int | None:
    for name in ("winerror", "errno"):
        value = getattr(error, name, None)
        if isinstance(value, int):
            return value
    return None


def _socket_denied(address: tuple[str, int], *, tcp: bool) -> dict[str, object]:
    family = socket.AF_INET
    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    try:
        with socket.socket(family, kind) as client:
            client.settimeout(1)
            client.connect(address)
        return {"denied": False, "error_code": None}
    except OSError as error:
        code = _error_code(error)
        return {"denied": code in ACCESS_DENIED_ERRORS, "error_code": code}


def _dns_denied() -> dict[str, object]:
    try:
        socket.getaddrinfo("devfabric-isolation.invalid", 443, type=socket.SOCK_STREAM)
        return {"denied": False, "error_code": None}
    except OSError as error:
        code = _error_code(error)
        return {"denied": code in ACCESS_DENIED_ERRORS, "error_code": code}


def _path_denied(path: Path, *, write: bool) -> dict[str, object]:
    try:
        if write:
            path.write_bytes(b"forbidden")
        else:
            path.read_bytes()
        return {"denied": False, "error_code": None}
    except OSError as error:
        return {"denied": True, "error_code": _error_code(error)}


def _child(
    request_path: Path,
    result_path: Path,
    native_loader_activation: WindowsNativeLoaderActivationV1 | None = None,
    native_import_matrix: tuple[WindowsNativeImportSuccessV1, ...] | None = None,
) -> int:
    if (native_loader_activation is None) != (native_import_matrix is None):
        raise ValueError("Native loader success evidence must be supplied together")
    request = json.loads(request_path.read_bytes())
    allowed = Path(request["allowed_root"])
    hidden = Path(request["hidden_canary"])
    marker = allowed / "sandbox-write.txt"
    marker.write_text("isolated", encoding="ascii")
    allowed_ok = marker.read_text(encoding="ascii") == "isolated"

    inherited_handle = int(request["forbidden_handle"])
    flags = ctypes.c_uint32()
    get_handle_information = ctypes.windll.kernel32.GetHandleInformation
    get_handle_information.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    get_handle_information.restype = ctypes.c_int
    ctypes.set_last_error(0)
    inherited_visible = bool(get_handle_information(inherited_handle, ctypes.byref(flags)))
    inherited_error = None if inherited_visible else ctypes.get_last_error()

    registry_path = request["registry_path"]
    registry_write_succeeded = False
    registry_error = None
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(key, "probe", 0, winreg.REG_SZ, "sandbox")
            registry_write_succeeded = True
        finally:
            winreg.CloseKey(key)
    except OSError as error:
        registry_error = _error_code(error)

    normal = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"],
        close_fds=True,
    )
    (allowed / "grandchild.pid").write_text(str(normal.pid), encoding="ascii")
    breakaway_blocked = False
    breakaway_error = None
    breakaway_pid = None
    try:
        escaped = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"],
            close_fds=True,
            creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB,
        )
        breakaway_pid = escaped.pid
        escaped.terminate()
        escaped.wait(timeout=5)
    except OSError as error:
        breakaway_blocked = True
        breakaway_error = _error_code(error)

    result = {
        "allowed_root_read_write": allowed_ok,
        "inherited_handles_blocked": not inherited_visible,
        "inherited_handle_error_code": inherited_error,
        "hidden_read": _path_denied(hidden, write=False),
        "hidden_write": _path_denied(hidden.with_name("created.txt"), write=True),
        "registry_write_succeeded": registry_write_succeeded,
        "registry_error_code": registry_error,
        "loopback": _socket_denied(("127.0.0.1", int(request["loopback_port"])), tcp=True),
        "lan": _socket_denied(("192.0.2.1", 9), tcp=False),
        "public": _socket_denied(("203.0.113.1", 9), tcp=False),
        "dns": _dns_denied(),
        "grandchild_pid": normal.pid,
        "breakaway_blocked": breakaway_blocked,
        "breakaway_error_code": breakaway_error,
        "breakaway_pid": breakaway_pid,
    }
    if native_loader_activation is not None and native_import_matrix is not None:
        result.update(
            {
                "schema_version": 2,
                "native_loader_activation": native_loader_activation.model_dump(mode="json"),
                "native_import_matrix": [
                    item.model_dump(mode="json") for item in native_import_matrix
                ],
            }
        )
    temporary = result_path.with_suffix(".tmp")
    temporary.write_bytes(canonical(cast(JsonValue, result)))
    os.replace(temporary, result_path)
    time.sleep(60)
    return 0


def _child_native_crypto_observations() -> tuple[WindowsNativeCryptoObservationV1, ...]:
    runtime_root = Path(sys.executable).resolve().parent
    expected: tuple[tuple[NativeCryptoPath, str], ...] = (
        ("python/_hashlib.pyd", "_hashlib.pyd"),
        ("python/_ssl.pyd", "_ssl.pyd"),
        ("python/libcrypto-3.dll", "libcrypto-3.dll"),
        ("python/libssl-3.dll", "libssl-3.dll"),
    )
    observations: list[WindowsNativeCryptoObservationV1] = []
    for relative_path, filename in expected:
        try:
            observed_sha256 = digest((runtime_root / filename).read_bytes())
            status: NativeLoaderStatus = "readable"
        except FileNotFoundError:
            observed_sha256 = None
            status = "missing"
        except PermissionError:
            observed_sha256 = None
            status = "access_denied"
        except OSError:
            observed_sha256 = None
            status = "other_error"
        observations.append(
            WindowsNativeCryptoObservationV1(
                relative_path=relative_path,
                status=status,
                observed_sha256=observed_sha256,
            )
        )
    return tuple(observations)


def _child_guarded(
    request_path: Path,
    result_path: Path,
    failure_path: Path,
    dll_directory_activation: dict[str, object] | None = None,
    native_import_matrix: list[dict[str, object]] | None = None,
) -> int:
    if (dll_directory_activation is None) != (native_import_matrix is None):
        return 1
    try:
        return _child(request_path, result_path)
    except BaseException as error:
        if dll_directory_activation is None or native_import_matrix is None:
            failure: WindowsIsolationChildFailureV4 | WindowsIsolationChildFailureV5 = (
                WindowsIsolationChildFailureV4(
                    phase="child_probe",
                    exception_class=type(error).__name__,
                    winerror=getattr(error, "winerror", None),
                    errno=getattr(error, "errno", None),
                    failed_matrix_module=None,
                    import_boundary=None,
                    loader_code=None,
                    loader_reason=None,
                    native_import_matrix=(),
                    native_loader_observations=(),
                )
            )
        else:
            failure = WindowsIsolationChildFailureV5(
                phase="child_probe",
                exception_class=type(error).__name__,
                winerror=getattr(error, "winerror", None),
                errno=getattr(error, "errno", None),
                dll_directory_activation=WindowsDllDirectoryActivationV1.model_validate(
                    dll_directory_activation
                ),
                failed_matrix_module=None,
                import_boundary=None,
                loader_code=None,
                loader_reason=None,
                native_import_matrix=tuple(
                    WindowsNativeImportMatrixObservationV2.model_validate(item)
                    for item in native_import_matrix
                ),
                native_crypto_observations=_child_native_crypto_observations(),
                native_loader_observations=(),
            )
        encoded = canonical(failure.model_dump(mode="json"))
        if len(encoded) > MAX_CHILD_FAILURE_BYTES:
            return 1
        temporary = failure_path.with_name(failure_path.name + ".tmp")
        temporary.write_bytes(encoded)
        os.replace(temporary, failure_path)
        return 1


def _child_guarded_v6(
    request_path: Path,
    result_path: Path,
    failure_path: Path,
    native_loader_activation: dict[str, object],
    native_import_matrix: list[dict[str, object]],
) -> int:
    """Run the child only after strict native-loader activation and matrix validation."""

    try:
        activation_observation = WindowsNativeLoaderActivationObservationV2.model_validate(
            native_loader_activation
        )
        if activation_observation.status != "active":
            raise ValueError("Child probe requires active native-loader authority")
        activation = WindowsNativeLoaderActivationV1(
            module_sha256=cast(str, activation_observation.module_sha256),
            activated_dependencies=cast(
                tuple[Literal["libffi-8.dll"], Literal["libcrypto-3.dll"], Literal["libssl-3.dll"]],
                activation_observation.activated_dependencies,
            ),
        )
        observations = tuple(
            WindowsNativeImportMatrixObservationV3.model_validate(item)
            for item in native_import_matrix
        )
        expected_modules = ["_ctypes", "_socket", "_overlapped", "select", "_hashlib", "_ssl"]
        if [item.module for item in observations] != expected_modules or any(
            item.import_status != "imported"
            or item.file.status != "readable"
            or item.file.observed_sha256 is None
            for item in observations
        ):
            raise ValueError("Child probe requires the complete reviewed native import matrix")
        success_matrix = tuple(
            WindowsNativeImportSuccessV1(
                module=item.module,
                relative_path=item.file.relative_path,
                observed_sha256=cast(str, item.file.observed_sha256),
            )
            for item in observations
        )
        return _child(request_path, result_path, activation, success_matrix)
    except BaseException as error:
        try:
            failure = WindowsIsolationChildFailureV6(
                phase="child_probe",
                exception_class=type(error).__name__,
                winerror=getattr(error, "winerror", None),
                errno=getattr(error, "errno", None),
                native_loader_activation=WindowsNativeLoaderActivationObservationV2.model_validate(
                    native_loader_activation
                ),
                failed_matrix_module=None,
                import_boundary=None,
                loader_code=None,
                loader_reason=None,
                native_import_matrix=tuple(
                    WindowsNativeImportMatrixObservationV3.model_validate(item)
                    for item in native_import_matrix
                ),
                native_crypto_observations=_child_native_crypto_observations(),
            )
            encoded = canonical(failure.model_dump(mode="json"))
        except BaseException:
            return 1
        if len(encoded) > MAX_CHILD_FAILURE_BYTES:
            return 1
        temporary = failure_path.with_name(failure_path.name + ".tmp")
        temporary.write_bytes(encoded)
        os.replace(temporary, failure_path)
        return 1


def _read_child_failure(
    failure_path: Path,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationChildFailureV4 | None]:
    if not failure_path.is_file():
        return "absent", None
    try:
        _reject_reparse_chain(failure_path, require_directory=False)
        with failure_path.open("rb") as stream:
            encoded = stream.read(MAX_CHILD_FAILURE_BYTES + 1)
        if len(encoded) > MAX_CHILD_FAILURE_BYTES:
            return "invalid", None
        return "validated", WindowsIsolationChildFailureV4.model_validate_json(encoded)
    except (OSError, ValueError):
        return "invalid", None


def _read_child_failure_v5(
    failure_path: Path,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationChildFailureV5 | None]:
    if not failure_path.is_file():
        return "absent", None
    try:
        _reject_reparse_chain(failure_path, require_directory=False)
        with failure_path.open("rb") as stream:
            encoded = stream.read(MAX_CHILD_FAILURE_BYTES + 1)
        if len(encoded) > MAX_CHILD_FAILURE_BYTES:
            return "invalid", None
        return "validated", WindowsIsolationChildFailureV5.model_validate_json(encoded)
    except (OSError, ValueError):
        return "invalid", None


def _read_child_failure_v6(
    failure_path: Path,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationChildFailureV6 | None]:
    if not failure_path.is_file():
        return "absent", None
    try:
        _reject_reparse_chain(failure_path, require_directory=False)
        with failure_path.open("rb") as stream:
            encoded = stream.read(MAX_CHILD_FAILURE_BYTES + 1)
        if len(encoded) > MAX_CHILD_FAILURE_BYTES:
            return "invalid", None
        return "validated", WindowsIsolationChildFailureV6.model_validate_json(encoded)
    except (OSError, ValueError):
        return "invalid", None


def _read_bootstrap_started(
    status_path: Path,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationBootstrapStartedV1 | None]:
    if not status_path.is_file():
        return "absent", None
    try:
        _reject_reparse_chain(status_path, require_directory=False)
        with status_path.open("rb") as stream:
            encoded = stream.read(MAX_BOOTSTRAP_STATUS_BYTES + 1)
        if len(encoded) > MAX_BOOTSTRAP_STATUS_BYTES:
            return "invalid", None
        return "validated", WindowsIsolationBootstrapStartedV1.model_validate_json(encoded)
    except (OSError, ValueError):
        return "invalid", None


def _read_bound_bootstrap_started(
    status_path: Path,
    profile: WindowsIsolationProfileV2 | WindowsIsolationProfileV3,
    environment_instance_id: str,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationBootstrapStartedV1 | None]:
    status, started = _read_bootstrap_started(status_path)
    if status != "validated" or started is None:
        return status, None
    payload = started.payload
    if (
        payload.child_bootstrap_sha256 != profile.payload.child_bootstrap_sha256
        or payload.environment_instance_id != environment_instance_id
        or payload.windows_isolation_profile_id != profile.windows_isolation_profile_id
        or payload.probe_sha256 != profile.payload.probe_sha256
    ):
        return "invalid", None
    return "validated", started


def _require_bootstrap_started(
    status_path: Path,
    profile: WindowsIsolationProfileV2 | WindowsIsolationProfileV3,
    environment_instance_id: str,
) -> WindowsIsolationBootstrapStartedV1:
    status, started = _read_bound_bootstrap_started(status_path, profile, environment_instance_id)
    if status != "validated" or started is None:
        raise RuntimeError(f"Windows isolation bootstrap-started frame is {status}")
    return started


def _native_loader_file_evidence(
    bundle: NativeBundleV1,
    child_failure: (
        WindowsIsolationChildFailureV3
        | WindowsIsolationChildFailureV4
        | WindowsIsolationChildFailureV5
        | None
    ),
) -> tuple[WindowsNativeLoaderFileEvidenceV1, WindowsNativeLoaderFileEvidenceV1]:
    expected_paths: tuple[NativeLoaderPath, NativeLoaderPath] = (
        "python/_ctypes.pyd",
        "python/libffi-8.dll",
    )
    inventory = {item.path: item.sha256 for item in bundle.payload.files}
    if any(path not in inventory for path in expected_paths):
        raise ValueError("Immutable bundle lacks a reviewed native loader file")
    observed = (
        {item.relative_path: item for item in child_failure.native_loader_observations}
        if child_failure is not None and child_failure.phase == "bootstrap_import"
        else {}
    )
    evidence: list[WindowsNativeLoaderFileEvidenceV1] = []
    for path in expected_paths:
        item = observed.get(path)
        evidence.append(
            WindowsNativeLoaderFileEvidenceV1(
                relative_path=path,
                expected_sha256=inventory[path],
                child_status=item.status if item is not None else "not_observed",
                child_observed_sha256=(item.observed_sha256 if item is not None else None),
            )
        )
    return cast(
        tuple[WindowsNativeLoaderFileEvidenceV1, WindowsNativeLoaderFileEvidenceV1],
        tuple(evidence),
    )


def _native_import_matrix_evidence(
    bundle: NativeBundleV1,
    child_failure: WindowsIsolationChildFailureV4 | None,
) -> tuple[
    WindowsNativeImportMatrixEvidenceV1,
    WindowsNativeImportMatrixEvidenceV1,
    WindowsNativeImportMatrixEvidenceV1,
    WindowsNativeImportMatrixEvidenceV1,
]:
    expected: tuple[tuple[NativeMatrixModule, NativeMatrixPath], ...] = (
        ("_socket", "python/_socket.pyd"),
        ("_overlapped", "python/_overlapped.pyd"),
        ("select", "python/select.pyd"),
        ("_ssl", "python/_ssl.pyd"),
    )
    inventory = {item.path: item.sha256 for item in bundle.payload.files}
    if any(path not in inventory for _, path in expected):
        raise ValueError("Immutable bundle lacks a reviewed native matrix file")
    observed = (
        {item.module: item for item in child_failure.native_import_matrix}
        if child_failure is not None
        else {}
    )
    evidence: list[WindowsNativeImportMatrixEvidenceV1] = []
    for module, path in expected:
        item = observed.get(module)
        evidence.append(
            WindowsNativeImportMatrixEvidenceV1(
                module=module,
                relative_path=path,
                expected_sha256=inventory[path],
                child_file_status=item.file.status if item is not None else "not_observed",
                child_observed_sha256=(item.file.observed_sha256 if item is not None else None),
                child_import_status=item.import_status if item is not None else "not_observed",
            )
        )
    return cast(
        tuple[
            WindowsNativeImportMatrixEvidenceV1,
            WindowsNativeImportMatrixEvidenceV1,
            WindowsNativeImportMatrixEvidenceV1,
            WindowsNativeImportMatrixEvidenceV1,
        ],
        tuple(evidence),
    )


def _native_import_matrix_evidence_v5(
    bundle: NativeBundleV1,
    child_failure: WindowsIsolationChildFailureV5 | None,
) -> tuple[
    WindowsNativeImportMatrixEvidenceV2,
    WindowsNativeImportMatrixEvidenceV2,
    WindowsNativeImportMatrixEvidenceV2,
    WindowsNativeImportMatrixEvidenceV2,
    WindowsNativeImportMatrixEvidenceV2,
]:
    expected: tuple[tuple[NativeMatrixModuleV5, NativeMatrixPathV5], ...] = (
        ("_socket", "python/_socket.pyd"),
        ("_overlapped", "python/_overlapped.pyd"),
        ("select", "python/select.pyd"),
        ("_hashlib", "python/_hashlib.pyd"),
        ("_ssl", "python/_ssl.pyd"),
    )
    inventory = {item.path: item.sha256 for item in bundle.payload.files}
    if any(path not in inventory for _, path in expected):
        raise ValueError("Immutable bundle lacks a reviewed V5 native matrix file")
    observed = (
        {item.module: item for item in child_failure.native_import_matrix}
        if child_failure is not None
        else {}
    )
    evidence: list[WindowsNativeImportMatrixEvidenceV2] = []
    for module, path in expected:
        item = observed.get(module)
        evidence.append(
            WindowsNativeImportMatrixEvidenceV2(
                module=module,
                relative_path=path,
                expected_sha256=inventory[path],
                child_file_status=item.file.status if item is not None else "not_observed",
                child_observed_sha256=(item.file.observed_sha256 if item is not None else None),
                child_import_status=item.import_status if item is not None else "not_observed",
            )
        )
    return cast(
        tuple[
            WindowsNativeImportMatrixEvidenceV2,
            WindowsNativeImportMatrixEvidenceV2,
            WindowsNativeImportMatrixEvidenceV2,
            WindowsNativeImportMatrixEvidenceV2,
            WindowsNativeImportMatrixEvidenceV2,
        ],
        tuple(evidence),
    )


def _native_import_matrix_evidence_v6(
    bundle: NativeBundleV1,
    child_failure: WindowsIsolationChildFailureV6 | None,
) -> tuple[
    WindowsNativeImportMatrixEvidenceV3,
    WindowsNativeImportMatrixEvidenceV3,
    WindowsNativeImportMatrixEvidenceV3,
    WindowsNativeImportMatrixEvidenceV3,
    WindowsNativeImportMatrixEvidenceV3,
    WindowsNativeImportMatrixEvidenceV3,
]:
    expected: tuple[tuple[NativeMatrixModuleV6, NativeMatrixPathV6], ...] = (
        ("_ctypes", "python/_ctypes.pyd"),
        ("_socket", "python/_socket.pyd"),
        ("_overlapped", "python/_overlapped.pyd"),
        ("select", "python/select.pyd"),
        ("_hashlib", "python/_hashlib.pyd"),
        ("_ssl", "python/_ssl.pyd"),
    )
    inventory = {item.path: item.sha256 for item in bundle.payload.files}
    if any(path not in inventory for _, path in expected):
        raise ValueError("Immutable bundle lacks a reviewed V6 native matrix file")
    observed = (
        {item.module: item for item in child_failure.native_import_matrix}
        if child_failure is not None
        else {}
    )
    evidence = tuple(
        WindowsNativeImportMatrixEvidenceV3(
            module=module,
            relative_path=path,
            expected_sha256=inventory[path],
            child_file_status=(
                observed[module].file.status if module in observed else "not_observed"
            ),
            child_observed_sha256=(
                observed[module].file.observed_sha256 if module in observed else None
            ),
            child_import_status=(
                observed[module].import_status if module in observed else "not_observed"
            ),
        )
        for module, path in expected
    )
    return cast(
        tuple[
            WindowsNativeImportMatrixEvidenceV3,
            WindowsNativeImportMatrixEvidenceV3,
            WindowsNativeImportMatrixEvidenceV3,
            WindowsNativeImportMatrixEvidenceV3,
            WindowsNativeImportMatrixEvidenceV3,
            WindowsNativeImportMatrixEvidenceV3,
        ],
        evidence,
    )


def _native_import_expectations_v6(
    bundle: NativeBundleV1,
) -> tuple[
    WindowsNativeImportExpectationV1,
    WindowsNativeImportExpectationV1,
    WindowsNativeImportExpectationV1,
    WindowsNativeImportExpectationV1,
    WindowsNativeImportExpectationV1,
    WindowsNativeImportExpectationV1,
]:
    expected: tuple[tuple[NativeMatrixModuleV6, NativeMatrixPathV6], ...] = (
        ("_ctypes", "python/_ctypes.pyd"),
        ("_socket", "python/_socket.pyd"),
        ("_overlapped", "python/_overlapped.pyd"),
        ("select", "python/select.pyd"),
        ("_hashlib", "python/_hashlib.pyd"),
        ("_ssl", "python/_ssl.pyd"),
    )
    inventory = {item.path: item.sha256 for item in bundle.payload.files}
    if any(path not in inventory for _, path in expected):
        raise ValueError("Immutable bundle lacks a reviewed V6 native matrix file")
    return cast(
        tuple[
            WindowsNativeImportExpectationV1,
            WindowsNativeImportExpectationV1,
            WindowsNativeImportExpectationV1,
            WindowsNativeImportExpectationV1,
            WindowsNativeImportExpectationV1,
            WindowsNativeImportExpectationV1,
        ],
        tuple(
            WindowsNativeImportExpectationV1(
                module=module,
                relative_path=path,
                expected_sha256=inventory[path],
            )
            for module, path in expected
        ),
    )


def _native_crypto_file_evidence(
    bundle: NativeBundleV1,
    child_failure: WindowsIsolationChildFailureV5 | WindowsIsolationChildFailureV6 | None,
) -> tuple[
    WindowsNativeCryptoFileEvidenceV1,
    WindowsNativeCryptoFileEvidenceV1,
    WindowsNativeCryptoFileEvidenceV1,
    WindowsNativeCryptoFileEvidenceV1,
]:
    expected_paths: tuple[NativeCryptoPath, ...] = (
        "python/_hashlib.pyd",
        "python/_ssl.pyd",
        "python/libcrypto-3.dll",
        "python/libssl-3.dll",
    )
    inventory = {item.path: item.sha256 for item in bundle.payload.files}
    if any(path not in inventory for path in expected_paths):
        raise ValueError("Immutable bundle lacks a reviewed native crypto file")
    observed = (
        {item.relative_path: item for item in child_failure.native_crypto_observations}
        if child_failure is not None
        else {}
    )
    evidence = tuple(
        WindowsNativeCryptoFileEvidenceV1(
            relative_path=path,
            expected_sha256=inventory[path],
            child_status=(observed[path].status if path in observed else "not_observed"),
            child_observed_sha256=(observed[path].observed_sha256 if path in observed else None),
        )
        for path in expected_paths
    )
    return cast(
        tuple[
            WindowsNativeCryptoFileEvidenceV1,
            WindowsNativeCryptoFileEvidenceV1,
            WindowsNativeCryptoFileEvidenceV1,
            WindowsNativeCryptoFileEvidenceV1,
        ],
        evidence,
    )


def _raise_if_child_exited(
    process: Any,
    child_result: Path,
    child_failure: Path,
    bootstrap_status: Path,
    profile: WindowsIsolationProfileV2 | WindowsIsolationProfileV3,
    environment_instance_id: str,
    bundle: NativeBundleV1,
) -> None:
    if child_result.is_file():
        return
    exit_code = process.poll_exit_code()
    if exit_code is None:
        return
    if isinstance(profile, WindowsIsolationProfileV2):
        bootstrap_started_status, validated_bootstrap_started = _read_bound_bootstrap_started(
            bootstrap_status, profile, environment_instance_id
        )
        child_failure_status, validated_child_failure = _read_child_failure_v5(child_failure)
        runtime_access_grant = process.runtime_access_grant
        if not isinstance(runtime_access_grant, WindowsRuntimeAccessGrantV2):
            raise RuntimeError("Failed child lacks the reviewed post-create runtime ACL grant")
        diagnostic = WindowsIsolationFailureDiagnosticV5.create(
            WindowsIsolationFailureDiagnosticPayloadV5(
                environment_instance_id=environment_instance_id,
                windows_isolation_profile_id=profile.windows_isolation_profile_id,
                profile=profile,
                native_bundle_id=bundle.bundle_id,
                launcher_executable_sha256=profile.payload.launcher_executable_sha256,
                runtime_access_grant=runtime_access_grant,
                probe_sha256=profile.payload.probe_sha256,
                child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
                process_exit_code=exit_code,
                bootstrap_started_status=bootstrap_started_status,
                bootstrap_started=validated_bootstrap_started,
                child_failure_status=child_failure_status,
                child_failure=validated_child_failure,
                dll_directory_activation=(
                    validated_child_failure.dll_directory_activation
                    if validated_child_failure is not None
                    else None
                ),
                loader_reason=(
                    validated_child_failure.loader_reason
                    if validated_child_failure is not None
                    else None
                ),
                loader_code=(
                    validated_child_failure.loader_code
                    if validated_child_failure is not None
                    else None
                ),
                native_loader_files=_native_loader_file_evidence(bundle, validated_child_failure),
                native_import_matrix=_native_import_matrix_evidence_v5(
                    bundle, validated_child_failure
                ),
                native_crypto_files=_native_crypto_file_evidence(bundle, validated_child_failure),
            )
        )
        raise WindowsIsolationChildExitError(diagnostic)
    bootstrap_started_status, validated_bootstrap_started = _read_bound_bootstrap_started(
        bootstrap_status, profile, environment_instance_id
    )
    child_failure_status, validated_child_failure = _read_child_failure_v6(child_failure)
    runtime_access_grant = process.runtime_access_grant
    if not isinstance(runtime_access_grant, WindowsRuntimeAccessGrantV2):
        raise RuntimeError("Failed child lacks the reviewed post-create runtime ACL grant")
    native_import_matrix = _native_import_matrix_evidence_v6(bundle, validated_child_failure)
    native_crypto_files = _native_crypto_file_evidence(bundle, validated_child_failure)
    diagnostic = WindowsIsolationFailureDiagnosticV6.create(
        WindowsIsolationFailureDiagnosticPayloadV6(
            environment_instance_id=environment_instance_id,
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            profile=profile,
            native_bundle_id=bundle.bundle_id,
            launcher_executable_sha256=profile.payload.launcher_executable_sha256,
            runtime_access_grant=runtime_access_grant,
            probe_sha256=profile.payload.probe_sha256,
            child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
            process_exit_code=exit_code,
            bootstrap_started_status=bootstrap_started_status,
            bootstrap_started=validated_bootstrap_started,
            child_failure_status=child_failure_status,
            child_failure=validated_child_failure,
            native_loader_activation=(
                validated_child_failure.native_loader_activation
                if validated_child_failure is not None
                else None
            ),
            loader_reason=(
                validated_child_failure.loader_reason
                if validated_child_failure is not None
                else None
            ),
            loader_code=(
                validated_child_failure.loader_code if validated_child_failure is not None else None
            ),
            native_import_matrix=native_import_matrix,
            native_crypto_files=native_crypto_files,
        )
    )
    raise WindowsIsolationChildExitError(diagnostic)


def _raise_after_cleanup(
    primary_error: BaseException,
    cleanup_errors: list[Exception],
    failure_diagnostic: (
        WindowsIsolationFailureDiagnosticV2
        | WindowsIsolationFailureDiagnosticV3
        | WindowsIsolationFailureDiagnosticV4
        | WindowsIsolationFailureDiagnosticV5
        | WindowsIsolationFailureDiagnosticV6
        | WindowsPostCreateAclFailureV1
        | None
    ),
    failure_output: Path,
) -> NoReturn:
    if cleanup_errors:
        raise BaseExceptionGroup(
            "Windows isolation probe and cleanup failed",
            [primary_error, *cleanup_errors],
        ) from primary_error
    if failure_diagnostic is not None:
        failure_output.parent.mkdir(parents=True, exist_ok=True)
        durable_publish(
            failure_output,
            canonical(failure_diagnostic.model_dump(mode="json")),
        )
    raise primary_error


def _pid_active(pid: int) -> bool:
    open_process = ctypes.windll.kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    handle = open_process(0x1000, False, pid)
    if not handle:
        return not _open_process_failure_proves_absent(ctypes.get_last_error())
    try:
        code = ctypes.c_uint32()
        get_exit = ctypes.windll.kernel32.GetExitCodeProcess
        get_exit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        get_exit.restype = ctypes.c_int
        if not get_exit(handle, ctypes.byref(code)):
            raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
        return code.value == 259
    finally:
        close_handle = ctypes.windll.kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        close_handle(handle)


def _open_process_failure_proves_absent(error: int) -> bool:
    if error == 87:
        return True
    raise OSError(error, "OpenProcess could not prove the process terminated")


def _wait_gone(pid: int, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while _pid_active(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not _pid_active(pid)


def _close_handle(handle: int) -> None:
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if not close_handle(handle):
        raise OSError(ctypes.get_last_error(), "CloseHandle failed")


def _registry_exists(path: str) -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False


def _delete_registry(path: str) -> None:
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def _cleanup_probe_resources(
    process: Any | None,
    event: int | None,
    listener: socket.socket | None,
    registry_path: str,
    scratch: Path,
    execution_bundle: Path | None = None,
) -> list[Exception]:
    errors: list[Exception] = []
    operations: list[tuple[str, Callable[[], object]]] = [
        ("sandbox process", lambda: process.close() if process is not None else None),
        ("event handle", lambda: _close_handle(event) if event is not None else None),
        ("listener", lambda: listener.close() if listener is not None else None),
        (
            "registry canary",
            lambda: _delete_registry(registry_path) if _registry_exists(registry_path) else None,
        ),
        ("scratch directory", lambda: shutil.rmtree(scratch) if scratch.exists() else None),
        (
            "disposable execution bundle",
            lambda: shutil.rmtree(execution_bundle)
            if execution_bundle is not None and execution_bundle.exists()
            else None,
        ),
    ]
    for name, operation in operations:
        try:
            operation()
        except Exception as error:
            error.add_note(f"cleanup operation: {name}")
            errors.append(error)
    return errors


def _security_descriptor(path: Path) -> bytes:
    security_information = 0x00000001 | 0x00000002 | 0x00000004
    loader = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        raise RuntimeError("Windows DLL loader is unavailable")
    advapi = loader("advapi32.dll", use_last_error=True, winmode=0x00000800)
    get_security = advapi.GetFileSecurityW
    get_security.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    get_security.restype = ctypes.c_int
    required = ctypes.c_uint32()
    if get_security(str(path), security_information, None, 0, ctypes.byref(required)):
        raise RuntimeError("GetFileSecurityW unexpectedly accepted an empty buffer")
    error = ctypes.get_last_error()
    if error != 122 or required.value == 0:
        raise OSError(error, "GetFileSecurityW size query failed")
    descriptor = ctypes.create_string_buffer(required.value)
    if not get_security(
        str(path),
        security_information,
        descriptor,
        required.value,
        ctypes.byref(required),
    ):
        raise OSError(ctypes.get_last_error(), "GetFileSecurityW failed")
    return descriptor.raw[: required.value]


def _security_descriptor_inventory_sha256(root: Path) -> str:
    """Hash owner/group/DACL bytes for the exact source bundle tree."""

    entries = [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]
    accumulator = hashlib.sha256()
    for item in entries:
        relative = "." if item == root else item.relative_to(root).as_posix()
        descriptor = _security_descriptor(item)
        accumulator.update(relative.encode("utf-8"))
        accumulator.update(b"\0")
        accumulator.update(len(descriptor).to_bytes(8, "big"))
        accumulator.update(descriptor)
    return accumulator.hexdigest()


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _validated_probe_paths(
    bundle_root: Path,
    bundle_manifest: Path,
    scratch: Path,
    execution_bundle: Path,
    output: Path,
    failure_output: Path,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    source_root = _reject_reparse_chain(bundle_root)
    source_manifest = _reject_reparse_chain(bundle_manifest, require_directory=False)
    mutable = tuple(
        Path(os.path.abspath(path)) for path in (scratch, execution_bundle, output, failure_output)
    )
    for parent in {path.parent for path in mutable}:
        _reject_reparse_chain(parent)
    for path in mutable:
        if _paths_overlap(path, source_root) or _paths_overlap(path, source_manifest):
            raise ValueError("Probe mutable paths cannot overlap bundle authority")
    for index, left in enumerate(mutable):
        if any(_paths_overlap(left, right) for right in mutable[index + 1 :]):
            raise ValueError("Probe mutable paths cannot overlap each other")
    return (
        source_root,
        source_manifest,
        mutable[0],
        mutable[1],
        mutable[2],
        mutable[3],
    )


def _reparse_rejected(root: Path, target: Path) -> bool:
    link = root / "reparse-link"
    command = [os.environ["COMSPEC"], "/d", "/c", "mklink", "/J", str(link), str(target)]
    created = subprocess.run(command, capture_output=True, check=False)
    if created.returncode != 0:
        raise RuntimeError("Junction creation unavailable; reparse qualification cannot proceed")
    try:
        try:
            windows_path_identity(link)
        except ValueError:
            return True
        return False
    finally:
        subprocess.run(
            [os.environ["COMSPEC"], "/d", "/c", "rmdir", str(link)],
            capture_output=True,
            check=False,
        )


def _inheritable_event() -> int:
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_uint32),
            ("security_descriptor", ctypes.c_void_p),
            ("inherit_handle", ctypes.c_int),
        ]

    attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), None, True)
    create_event = ctypes.windll.kernel32.CreateEventW
    create_event.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    create_event.restype = ctypes.c_void_p
    handle = create_event(ctypes.byref(attributes), True, False, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateEventW failed")
    return int(handle)


def qualify(
    bundle_root: Path,
    bundle_manifest: Path,
    scratch: Path,
    output: Path,
    environment_instance_id: str,
    expected_implementation_commit: str,
) -> WindowsIsolationEvidenceV5:
    scratch = Path(os.path.abspath(scratch))
    output = Path(os.path.abspath(output))
    failure_output = output.with_name(output.name + ".failure.json")
    execution_bundle = scratch.with_name(scratch.name + ".execution-bundle")
    if scratch.exists() or execution_bundle.exists() or output.exists() or failure_output.exists():
        raise FileExistsError("Scratch, disposable bundle and output paths must not already exist")
    (
        bundle_root,
        bundle_manifest,
        scratch,
        execution_bundle,
        output,
        failure_output,
    ) = _validated_probe_paths(
        bundle_root,
        bundle_manifest,
        scratch,
        execution_bundle,
        output,
        failure_output,
    )
    bundle = NativeBundleV1.model_validate_json(bundle_manifest.read_bytes())
    verify_native_bundle(
        bundle,
        bundle_root,
        expected_platform="windows",
        expected_architecture="x86_64",
    )
    if len(expected_implementation_commit) != 40 or any(
        character not in "0123456789abcdef" for character in expected_implementation_commit
    ):
        raise ValueError(
            "Expected implementation commit must be 40 lowercase hexadecimal characters"
        )
    if bundle.payload.implementation_commit != expected_implementation_commit:
        raise ValueError("Native bundle implementation commit differs from expected authority")
    if bundle.payload.native_loader is None:
        raise ValueError("V6 Windows isolation requires reviewed native-loader authority")
    native_import_expectations = _native_import_expectations_v6(bundle)
    source_security_descriptor_sha256 = _security_descriptor_inventory_sha256(bundle_root)
    registry_path = rf"Software\DevFabric\IsolationProbe\{environment_instance_id}"
    listener: socket.socket | None = None
    event: int | None = None
    process: Any | None = None
    evidence: WindowsIsolationEvidenceV5 | None = None
    primary_error: BaseException | None = None
    failure_diagnostic: (
        WindowsIsolationFailureDiagnosticV2
        | WindowsIsolationFailureDiagnosticV3
        | WindowsIsolationFailureDiagnosticV4
        | WindowsIsolationFailureDiagnosticV5
        | WindowsIsolationFailureDiagnosticV6
        | WindowsPostCreateAclFailureV1
        | None
    ) = None
    try:
        shutil.copytree(bundle_root, execution_bundle)
        verify_native_bundle(
            bundle,
            execution_bundle,
            expected_platform="windows",
            expected_architecture="x86_64",
        )
        _reject_reparse_chain(execution_bundle)
        observed_build, observed_architecture = observed_windows_platform()
        scratch.mkdir(parents=True)
        allowed = scratch / "allowed"
        hidden = scratch / "hidden"
        allowed.mkdir()
        hidden.mkdir()
        hidden_canary = hidden / "canary.txt"
        hidden_canary.write_text("private", encoding="ascii")
        bootstrap_source = Path(__file__).with_name("windows_isolation_child_bootstrap.py")
        bootstrap_bytes = bootstrap_source.read_bytes()
        child_bootstrap = allowed / "child-bootstrap.py"
        child_bootstrap.write_bytes(bootstrap_bytes)
        probe_bytes = Path(__file__).read_bytes()
        child_script = allowed / "probe-child.py"
        child_script.write_bytes(probe_bytes)
        child_result = allowed / "child-result.json"
        child_failure = allowed / "child-failure.json"
        bootstrap_status = allowed / "bootstrap-started.json"
        request_path = allowed / "request.json"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)
        event = _inheritable_event()
        _delete_registry(registry_path)
        reparse_rejected = _reparse_rejected(scratch, hidden)
        profile = WindowsIsolationProfileV3.create(
            WindowsIsolationProfilePayloadV3(
                environment_instance_id=environment_instance_id,
                appcontainer_identity=appcontainer_identity(environment_instance_id),
                native_bundle_id=bundle.bundle_id,
                codex_executable_sha256=bundle.payload.codex.executable_sha256,
                launcher_executable_sha256=bundle.payload.python.executable_sha256,
                probe_sha256=digest(probe_bytes),
                child_bootstrap_sha256=digest(bootstrap_bytes),
                native_loader=bundle.payload.native_loader,
                native_import_expectations=native_import_expectations,
                read_only_roots=(windows_path_identity(execution_bundle),),
                writable_roots=(windows_path_identity(allowed),),
                denied_roots=(windows_path_identity(hidden),),
            )
        )
        request_path.write_bytes(
            canonical(
                {
                    "allowed_root": str(allowed),
                    "hidden_canary": str(hidden_canary),
                    "forbidden_handle": event,
                    "registry_path": registry_path,
                    "loopback_port": listener.getsockname()[1],
                }
            )
        )
        python = execution_bundle / bundle.payload.python.executable_path
        environment = {
            "SYSTEMROOT": os.environ["SYSTEMROOT"],
            "TEMP": str(allowed),
            "TMP": str(allowed),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }

        def verify_execution_bundle(root: Path) -> str:
            verify_native_bundle(
                bundle,
                root,
                expected_platform="windows",
                expected_architecture="x86_64",
            )
            return bundle.bundle_id

        process = launch_windows_isolated(
            profile,
            python,
            (
                "-I",
                "-B",
                str(child_bootstrap),
                str(child_script),
                str(request_path),
                str(child_result),
                str(child_failure),
                str(bootstrap_status),
                profile.payload.child_bootstrap_sha256,
                environment_instance_id,
                profile.windows_isolation_profile_id,
                profile.payload.probe_sha256,
                profile.payload.native_loader.binary_sha256,
            ),
            cwd=allowed,
            environment=environment,
            verify_runtime_bundle=verify_execution_bundle,
        )
        if process.runtime_access_grant is None:
            raise RuntimeError("Windows sandbox launch did not retain its runtime access grant")
        if not isinstance(process.runtime_access_grant, WindowsRuntimeAccessGrantV2):
            raise RuntimeError("Windows sandbox launch retained a pre-create-only ACL grant")
        deadline = time.monotonic() + 30
        while not child_result.is_file() and time.monotonic() < deadline:
            try:
                _raise_if_child_exited(
                    process,
                    child_result,
                    child_failure,
                    bootstrap_status,
                    profile,
                    environment_instance_id,
                    bundle,
                )
            except WindowsIsolationChildExitError as error:
                failure_diagnostic = error.diagnostic
                raise
            time.sleep(0.05)
        if not child_result.is_file():
            raise TimeoutError("Isolation probe did not produce evidence")
        bootstrap_started = _require_bootstrap_started(
            bootstrap_status, profile, environment_instance_id
        )
        child = WindowsIsolationChildResultV2.model_validate_json(child_result.read_bytes())
        if (
            child.native_loader_activation.module_sha256
            != profile.payload.native_loader.binary_sha256
        ):
            raise RuntimeError("Child native-loader activation differs from V6 profile")
        for expected, observed in zip(
            profile.payload.native_import_expectations,
            child.native_import_matrix,
            strict=True,
        ):
            if (
                expected.module != observed.module
                or expected.relative_path != observed.relative_path
                or expected.expected_sha256 != observed.observed_sha256
            ):
                raise RuntimeError("Child native import differs from immutable bundle")
        try:
            listener.accept()
            loopback_reached = True
        except TimeoutError:
            loopback_reached = False
        process.terminate_tree()
        child_tree_terminated = _wait_gone(child.grandchild_pid) and _wait_gone(process.process_id)
        profile_deleted = process.close()
        host_registry_unchanged = not _registry_exists(registry_path)
        spec = windows_sandbox_spec(profile)
        payload = WindowsIsolationReceiptPayloadV5(
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            environment_instance_id=environment_instance_id,
            probe_sha256=profile.payload.probe_sha256,
            child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
            bootstrap_started_id=bootstrap_started.bootstrap_started_id,
            bootstrap_started_validated=True,
            runtime_access_grant=process.runtime_access_grant,
            native_loader=profile.payload.native_loader,
            native_loader_activation=child.native_loader_activation,
            native_import_expectations=profile.payload.native_import_expectations,
            native_import_matrix=child.native_import_matrix,
            sandbox_spec_sha256=digest(spec),
            observed_windows_build=observed_build,
            observed_architecture=observed_architecture,
            inherited_handles_blocked=child.inherited_handles_blocked,
            child_tree_terminated=child_tree_terminated,
            breakaway_blocked=child.breakaway_blocked,
            allowed_root_read_write=child.allowed_root_read_write,
            hidden_root_read_denied=child.hidden_read.denied,
            hidden_root_write_denied=child.hidden_write.denied,
            reparse_substitution_rejected=reparse_rejected,
            host_registry_unchanged=host_registry_unchanged,
            direct_loopback_denied=child.loopback.denied and not loopback_reached,
            direct_lan_denied=child.lan.denied,
            direct_dns_denied=child.dns.denied,
            direct_public_denied=child.public.denied,
            appcontainer_profile_deleted=profile_deleted,
        )
        receipt = WindowsIsolationReceiptV5.create(payload)
        evidence = WindowsIsolationEvidenceV5.create(profile, spec, receipt)
    except BaseException as error:
        if isinstance(error, WindowsPostCreateAclGateError):
            failure_diagnostic = error.diagnostic
        primary_error = error
    cleanup_errors = _cleanup_probe_resources(
        process,
        event,
        listener,
        registry_path,
        scratch,
        execution_bundle,
    )
    try:
        verify_native_bundle(
            bundle,
            bundle_root,
            expected_platform="windows",
            expected_architecture="x86_64",
        )
    except Exception as error:
        error.add_note("post-probe source bundle byte verification")
        cleanup_errors.append(error)
    try:
        observed_source_security_descriptor_sha256 = _security_descriptor_inventory_sha256(
            bundle_root
        )
        if observed_source_security_descriptor_sha256 != source_security_descriptor_sha256:
            raise RuntimeError("Source bundle security descriptor changed during qualification")
    except Exception as error:
        error.add_note("post-probe source bundle security descriptor verification")
        cleanup_errors.append(error)
    if primary_error is not None:
        _raise_after_cleanup(primary_error, cleanup_errors, failure_diagnostic, failure_output)
    if cleanup_errors:
        raise ExceptionGroup("Windows isolation probe cleanup failed", cleanup_errors)
    if evidence is None:
        raise AssertionError("Windows isolation evidence was not constructed")
    output.parent.mkdir(parents=True, exist_ok=True)
    durable_publish(output, canonical(evidence.model_dump(mode="json")))
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("child_request", nargs="?", type=Path)
    parser.add_argument("child_result", nargs="?", type=Path)
    parser.add_argument("child_failure", nargs="?", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--bundle-manifest", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--environment-instance-id")
    parser.add_argument("--expected-implementation-commit")
    args = parser.parse_args()
    if args.child:
        if args.child_request is None or args.child_result is None or args.child_failure is None:
            parser.error("child mode requires request, result and failure paths")
        raise SystemExit(_child_guarded(args.child_request, args.child_result, args.child_failure))
    required: dict[str, Any] = {
        "bundle_root": args.bundle,
        "bundle_manifest": args.bundle_manifest,
        "scratch": args.scratch,
        "output": args.output,
        "environment_instance_id": args.environment_instance_id,
        "expected_implementation_commit": args.expected_implementation_commit,
    }
    if any(value is None for value in required.values()):
        parser.error("host mode requires bundle, manifest, scratch, output and environment ID")
    receipt = qualify(**required)
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
