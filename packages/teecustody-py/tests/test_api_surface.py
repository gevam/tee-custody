"""T-01: the frozen `teecustody` public API (docs/tasks/INC-1/API.md §B) exists as transcribed."""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import io
import logging
from collections.abc import Callable
from enum import StrEnum

import pytest

from teecustody.attest import (
    DEFAULT_LAUNCHER_SOCKET,
    AttestationLifecycle,
    AttestationToken,
    ConfidentialSpaceLauncher,
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
    FieldValue,
    JsonLogFormatter,
    configure_logging,
    get_logger,
)
from teecustody.wire import PROTO, DecodeLimits, WireErrorCode, decode, encode

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
    assert public <= {"attest", "channel", "wire", "obs"}
    assert module.__version__ == "0.1.0"


class _FakeLauncher:
    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        return AttestationToken(value="x", issued_at=0, expires_at=1)


class _FakeLogger:
    def info(self, outcome: str, **fields: FieldValue) -> None:
        return None

    def warning(self, outcome: str, **fields: FieldValue) -> None:
        return None

    def error(self, outcome: str, **fields: FieldValue) -> None:
        return None


NONCE = bytes(32)
LIMITS = DecodeLimits(max_bytes=16, max_depth=4, max_items=16)


def _bare[T](cls: type[T]) -> T:
    """An instance whose stub `__init__` has not run, so each method stub can be called."""
    return object.__new__(cls)


def _lifecycle() -> AttestationLifecycle:
    return AttestationLifecycle(
        _FakeLauncher(),
        audience="https://aud.test",
        token_type="OIDC",
        identity_public_key=bytes(32),
        refresh_margin_s=300,
        clock=lambda: 0.0,
        logger=_FakeLogger(),
    )


STUBS: list[tuple[str, str, Callable[[], object]]] = [
    ("identity_nonce", "T-06", lambda: identity_nonce(bytes(32))),
    ("launcher_nonce", "T-06", lambda: launcher_nonce(NONCE)),
    (
        "parse_token_metadata",
        "T-06",
        lambda: parse_token_metadata(
            "a.b.c", audience="https://aud.test", expected_nonce="00" * 32, max_token_bytes=8192
        ),
    ),
    (
        "ConfidentialSpaceLauncher.__init__",
        "T-06",
        lambda: ConfidentialSpaceLauncher(timeout_s=1.0, max_response_bytes=65536),
    ),
    (
        "ConfidentialSpaceLauncher.get_attestation_token",
        "T-06",
        lambda: _bare(ConfidentialSpaceLauncher).get_attestation_token(
            "https://aud.test", "OIDC", NONCE
        ),
    ),
    ("AttestationLifecycle.__init__", "T-06", _lifecycle),
    (
        "AttestationLifecycle.identity_nonce",
        "T-06",
        lambda: _bare(AttestationLifecycle).identity_nonce,
    ),
    ("AttestationLifecycle.start", "T-06", lambda: _bare(AttestationLifecycle).start()),
    ("AttestationLifecycle.current", "T-06", lambda: _bare(AttestationLifecycle).current()),
    (
        "AttestationLifecycle.refresh_if_due",
        "T-06",
        lambda: _bare(AttestationLifecycle).refresh_if_due(),
    ),
    ("IdentityKey.generate", "T-06", IdentityKey.generate),
    ("IdentityKey.public_bytes", "T-06", lambda: _bare(IdentityKey).public_bytes()),
    ("encode", "T-04", lambda: encode({"a": [1, b"x", None, True]})),
    ("decode", "T-04", lambda: decode(b"\xa0", LIMITS)),
    ("get_logger", "T-05", lambda: get_logger("teecustody.test")),
    (
        "JsonLogFormatter.format",
        "T-05",
        lambda: JsonLogFormatter().format(
            logging.LogRecord("n", logging.INFO, __file__, 1, "OUTCOME", None, None)
        ),
    ),
    ("configure_logging", "T-05", lambda: configure_logging(io.StringIO())),
]


@pytest.mark.parametrize(
    ("owner", "call"), [(o, c) for _, o, c in STUBS], ids=[n for n, _, _ in STUBS]
)
def test_stub_raises_not_implemented_naming_its_owner(
    owner: str, call: Callable[[], object]
) -> None:
    with pytest.raises(NotImplementedError) as raised:
        call()
    assert str(raised.value) == owner


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


P = inspect.Parameter
POS = P.POSITIONAL_OR_KEYWORD
KW = P.KEYWORD_ONLY
EMPTY = P.empty


@pytest.mark.parametrize(
    ("func", "params"),
    [
        (identity_nonce, [("identity_public_key", POS, EMPTY)]),
        (launcher_nonce, [("identity_nonce", POS, EMPTY)]),
        (
            parse_token_metadata,
            [
                ("token", POS, EMPTY),
                ("audience", KW, EMPTY),
                ("expected_nonce", KW, EMPTY),
                ("max_token_bytes", KW, EMPTY),
            ],
        ),
        (
            ConfidentialSpaceLauncher.__init__,
            [
                ("self", POS, EMPTY),
                ("socket_path", POS, DEFAULT_LAUNCHER_SOCKET),
                ("timeout_s", KW, EMPTY),
                ("max_response_bytes", KW, EMPTY),
            ],
        ),
        (
            ConfidentialSpaceLauncher.get_attestation_token,
            [
                ("self", POS, EMPTY),
                ("audience", POS, EMPTY),
                ("token_type", POS, EMPTY),
                ("identity_nonce", POS, EMPTY),
            ],
        ),
        (
            AttestationLifecycle.__init__,
            [
                ("self", POS, EMPTY),
                ("launcher", POS, EMPTY),
                ("audience", KW, EMPTY),
                ("token_type", KW, EMPTY),
                ("identity_public_key", KW, EMPTY),
                ("refresh_margin_s", KW, EMPTY),
                ("clock", KW, EMPTY),
                ("logger", KW, EMPTY),
            ],
        ),
        (encode, [("value", POS, EMPTY)]),
        (decode, [("data", POS, EMPTY), ("limits", POS, EMPTY)]),
        (get_logger, [("name", POS, EMPTY)]),
        (configure_logging, [("stream", POS, EMPTY), ("level", POS, logging.INFO)]),
    ],
)
def test_signature_equals_api(
    func: Callable[..., object], params: list[tuple[str, object, object]]
) -> None:
    actual = [(p.name, p.kind, p.default) for p in inspect.signature(func).parameters.values()]
    assert actual == params
