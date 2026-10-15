"""T-01: the frozen `teecustody` public API (docs/tasks/INC-1/API.md §B) exists as transcribed."""

from __future__ import annotations

import dataclasses
import importlib
import importlib.metadata
import inspect
import logging
import re
from collections.abc import Callable
from enum import StrEnum
from typing import TextIO

import pytest

from teecustody.attest import (
    DEFAULT_LAUNCHER_SOCKET,
    AttestationLifecycle,
    AttestationToken,
    ConfidentialSpaceLauncher,
    Launcher,
    LauncherError,
    LauncherErrorCode,
    RefreshOutcome,
    identity_nonce,
    launcher_nonce,
    parse_token_metadata,
)
from teecustody.channel import IdentityKey
from teecustody.obs import (
    ALLOWED_FIELDS,
    OUTCOME_PATTERN,
    AllowListedLogger,
    FieldValue,
    configure_logging,
    get_logger,
)
from teecustody.wire import (
    PROTO,
    CanonicalValue,
    DecodeLimits,
    WireError,
    WireErrorCode,
    decode,
    encode,
)

PUBLIC_NAMES: dict[str, tuple[str, ...]] = {
    "teecustody.attest": (
        "LauncherErrorCode",
        "LauncherError",
        "AttestationToken",
        "Launcher",
        "identity_nonce",
        "launcher_nonce",
        "parse_token_metadata",
        "DEFAULT_LAUNCHER_SOCKET",
        "ConfidentialSpaceLauncher",
        "RefreshOutcome",
        "AttestationLifecycle",
    ),
    "teecustody.channel": ("IdentityKey",),
    "teecustody.wire": (
        "PROTO",
        "CanonicalValue",
        "DecodeLimits",
        "WireErrorCode",
        "WireError",
        "encode",
        "decode",
    ),
    "teecustody.obs": (
        "ALLOWED_FIELDS",
        "OUTCOME_PATTERN",
        "FieldValue",
        "AllowListedLogger",
        "get_logger",
        "JsonLogFormatter",
        "configure_logging",
    ),
}


@pytest.mark.parametrize(
    ("package", "name"),
    [(package, name) for package, names in PUBLIC_NAMES.items() for name in names],
)
def test_public_name_is_importable_from_package_root(package: str, name: str) -> None:
    module = importlib.import_module(package)
    assert hasattr(module, name), f"{package}.{name}"


def test_package_root_exports_only_version() -> None:
    module = importlib.import_module("teecustody")
    public = {name for name in vars(module) if not name.startswith("_")}
    assert public <= {
        "attest",
        "channel",
        "wire",
        "obs",
        "secrets",
        "config",
        "queue",
        "audit",
        "runtime",
    }
    assert module.__version__ == "0.1.0"


def test_constants_equal_api() -> None:
    assert PROTO == "tee-chan-v1"
    assert DEFAULT_LAUNCHER_SOCKET == "/run/container_launcher/teeserver.sock"
    assert frozenset({"client_id", "request_id", "session_id", "prekey_id", "epoch"}) == (
        ALLOWED_FIELDS
    )
    assert isinstance(ALLOWED_FIELDS, frozenset)
    assert OUTCOME_PATTERN.pattern == r"^[A-Z][A-Z0-9_]{0,63}$"


@pytest.mark.parametrize(
    ("enum", "values"),
    [
        (LauncherErrorCode, ["UNAVAILABLE", "INVALID_CONFIGURATION", "TOKEN_REJECTED"]),
        (RefreshOutcome, ["NOT_DUE", "REFRESHED", "FAILED_KEPT_CURRENT"]),
        (
            WireErrorCode,
            ["TOO_LARGE", "MALFORMED", "NONCANONICAL", "UNSUPPORTED_TYPE", "LIMIT_EXCEEDED"],
        ),
    ],
)
def test_enum_values_equal_api(enum: type[StrEnum], values: list[str]) -> None:
    assert [(member.name, member.value) for member in enum] == [(v, v) for v in values]


@pytest.mark.parametrize(
    ("cls", "fields"),
    [
        (AttestationToken, ["value", "issued_at", "expires_at"]),
        (DecodeLimits, ["max_bytes", "max_depth", "max_items"]),
    ],
)
def test_frozen_dataclass_fields_equal_api(cls: type, fields: list[str]) -> None:
    params = cls.__dataclass_params__
    assert params.frozen
    assert [f.name for f in dataclasses.fields(cls)] == fields
    assert all(f.default is dataclasses.MISSING for f in dataclasses.fields(cls))


# API.md §B transcribed verbatim. Each spec is compared by `inspect.Signature` equality, which
# covers parameter names, order, kinds, defaults, annotations and the return annotation.
def _spec_identity_nonce(identity_public_key: bytes) -> bytes: ...
def _spec_launcher_nonce(identity_nonce: bytes) -> str: ...
def _spec_parse_token_metadata(
    token: str, *, audience: str, expected_nonce: str, max_token_bytes: int
) -> AttestationToken: ...
def _spec_encode(value: CanonicalValue) -> bytes: ...
def _spec_decode(data: bytes, limits: DecodeLimits) -> CanonicalValue: ...
def _spec_get_logger(name: str) -> AllowListedLogger: ...
def _spec_configure_logging(stream: TextIO, level: int = logging.INFO) -> None: ...


class _LauncherErrorSpec:
    def __init__(self, code: LauncherErrorCode) -> None: ...


class _WireErrorSpec:
    def __init__(self, code: WireErrorCode) -> None: ...


class _LauncherSpec:
    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken: ...


class _ConfidentialSpaceLauncherSpec:
    def __init__(
        self,
        socket_path: str = DEFAULT_LAUNCHER_SOCKET,
        *,
        timeout_s: float,
        max_response_bytes: int,
    ) -> None: ...
    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken: ...


class _AttestationLifecycleSpec:
    def __init__(
        self,
        launcher: Launcher,
        *,
        audience: str,
        token_type: str,
        identity_public_key: bytes,
        refresh_margin_s: int,
        clock: Callable[[], float],
        logger: AllowListedLogger,
    ) -> None: ...
    @property
    def identity_nonce(self) -> bytes: ...
    def start(self) -> AttestationToken: ...
    def current(self) -> AttestationToken: ...
    def refresh_if_due(self) -> RefreshOutcome: ...


class _IdentityKeySpec:
    @classmethod
    def generate(cls) -> IdentityKey: ...
    def public_bytes(self) -> bytes: ...


class _AllowListedLoggerSpec:
    def info(self, outcome: str, **fields: FieldValue) -> None: ...
    def warning(self, outcome: str, **fields: FieldValue) -> None: ...
    def error(self, outcome: str, **fields: FieldValue) -> None: ...


def _signature(obj: object) -> inspect.Signature:
    target = obj.fget if isinstance(obj, property) else obj
    assert callable(target)
    return inspect.signature(target, eval_str=True)


FROZEN_SIGNATURES: dict[str, tuple[object, object]] = {
    "LauncherError.__init__": (LauncherError.__init__, _LauncherErrorSpec.__init__),
    "Launcher.get_attestation_token": (
        Launcher.get_attestation_token,
        _LauncherSpec.get_attestation_token,
    ),
    "identity_nonce": (identity_nonce, _spec_identity_nonce),
    "launcher_nonce": (launcher_nonce, _spec_launcher_nonce),
    "parse_token_metadata": (parse_token_metadata, _spec_parse_token_metadata),
    "ConfidentialSpaceLauncher.__init__": (
        ConfidentialSpaceLauncher.__init__,
        _ConfidentialSpaceLauncherSpec.__init__,
    ),
    "ConfidentialSpaceLauncher.get_attestation_token": (
        ConfidentialSpaceLauncher.get_attestation_token,
        _ConfidentialSpaceLauncherSpec.get_attestation_token,
    ),
    "AttestationLifecycle.__init__": (
        AttestationLifecycle.__init__,
        _AttestationLifecycleSpec.__init__,
    ),
    "AttestationLifecycle.identity_nonce": (
        vars(AttestationLifecycle)["identity_nonce"],
        vars(_AttestationLifecycleSpec)["identity_nonce"],
    ),
    "AttestationLifecycle.start": (AttestationLifecycle.start, _AttestationLifecycleSpec.start),
    "AttestationLifecycle.current": (
        AttestationLifecycle.current,
        _AttestationLifecycleSpec.current,
    ),
    "AttestationLifecycle.refresh_if_due": (
        AttestationLifecycle.refresh_if_due,
        _AttestationLifecycleSpec.refresh_if_due,
    ),
    "IdentityKey.generate": (IdentityKey.generate, _IdentityKeySpec.generate),
    "IdentityKey.public_bytes": (IdentityKey.public_bytes, _IdentityKeySpec.public_bytes),
    "WireError.__init__": (WireError.__init__, _WireErrorSpec.__init__),
    "encode": (encode, _spec_encode),
    "decode": (decode, _spec_decode),
    "AllowListedLogger.info": (AllowListedLogger.info, _AllowListedLoggerSpec.info),
    "AllowListedLogger.warning": (AllowListedLogger.warning, _AllowListedLoggerSpec.warning),
    "AllowListedLogger.error": (AllowListedLogger.error, _AllowListedLoggerSpec.error),
    "get_logger": (get_logger, _spec_get_logger),
    "configure_logging": (configure_logging, _spec_configure_logging),
}


@pytest.mark.parametrize(
    ("actual", "spec"), FROZEN_SIGNATURES.values(), ids=FROZEN_SIGNATURES.keys()
)
def test_full_signature_equals_api_transcription(actual: object, spec: object) -> None:
    assert _signature(actual) == _signature(spec)


@pytest.mark.parametrize("code", list(LauncherErrorCode))
def test_launcher_error_str_is_code_value_only(code: LauncherErrorCode) -> None:
    err = LauncherError(code)
    assert err.code is code
    assert str(err) == code.value
    assert err.args == (code.value,)


@pytest.mark.parametrize("code", list(WireErrorCode))
def test_wire_error_str_is_code_value_only(code: WireErrorCode) -> None:
    err = WireError(code)
    assert err.code is code
    assert str(err) == code.value
    assert err.args == (code.value,)


def test_attestation_token_repr_omits_the_token_value() -> None:
    token = AttestationToken(value="SENTINEL", issued_at=1, expires_at=2)
    assert "SENTINEL" not in repr(token)
    assert "SENTINEL" not in str(token)
    assert repr(token) == "AttestationToken(issued_at=1, expires_at=2)"


def _requirement_names(distribution: str) -> list[str]:
    return [
        re.split(r"[\s;<>=!~\[]", r, maxsplit=1)[0].lower()
        for r in importlib.metadata.requires(distribution) or []
    ]


def test_teecustody_never_requires_the_simulator() -> None:
    names = _requirement_names("teecustody")
    assert "teecustody-sim" not in names
    assert "teecustody_sim" not in names


def test_teecustody_runtime_requirements_are_exact_pinned_crypto_and_cbor_only() -> None:
    assert sorted(importlib.metadata.requires("teecustody") or []) == [
        "cbor2==6.1.4",
        "cryptography==50.0.2",
        "pyhpke==0.6.5",
    ]
