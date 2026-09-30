"""T-01: the frozen `teecustody` public API (docs/tasks/INC-1/API.md §B) exists as transcribed."""

from __future__ import annotations

import importlib

import pytest

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
