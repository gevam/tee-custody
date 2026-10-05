"""NFR-8 / NFR-3 / SR-11 Allow-listed structured logging and redaction (INC-1).

Expected failure on trunk: NotImplementedError('T-05' | 'T-06' | 'T-07' | 'T-08').
"""

import hashlib
import io
import json
import logging

import pytest

from acc_support import AUDIENCE, RunningSim
from teecustody.attest import AttestationLifecycle, ConfidentialSpaceLauncher, RefreshOutcome
from teecustody.attest.ports import LauncherError
from teecustody.channel import IdentityKey
from teecustody.obs import ALLOWED_FIELDS, configure_logging, get_logger

SENTINEL = "SENTINEL-SECRET-7f3a9c"


def _lines(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_NFR08_log_lines_are_json_with_only_allow_listed_fields() -> None:
    # Given logging configured to a stream
    stream = io.StringIO()
    configure_logging(stream, logging.INFO)
    log = get_logger("acceptance.nfr08")
    # When logging with allow-listed fields on every level
    log.info("SESSION_OPENED", client_id="c-1", request_id="r-1", session_id="s-1", epoch=3)
    log.warning("PREKEY_UNKNOWN", prekey_id="p-1")
    log.error("FAILED")
    # Then every line is JSON, carries the outcome code, and has no key beyond the allow-list
    records = _lines(stream)
    assert len(records) == 3
    framework_keys = {"outcome", "timestamp", "level", "logger", "ts", "time", "name", "severity"}
    for rec in records:
        assert rec["outcome"] == "FAILED" or rec["outcome"] in {"SESSION_OPENED", "PREKEY_UNKNOWN"}
        assert set(rec) <= ALLOWED_FIELDS | framework_keys, set(rec) - ALLOWED_FIELDS


def test_NFR08_non_allow_listed_fields_never_reach_output() -> None:
    # Given a caller that passes a secret under a non-allow-listed field name
    stream = io.StringIO()
    configure_logging(stream, logging.INFO)
    log = get_logger("acceptance.nfr08.deny")
    # When logging it
    try:
        log.info("SESSION_OPENED", payload=SENTINEL, token=SENTINEL)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        pass  # rejecting the call is as acceptable as dropping the field
    # Then the sentinel never appears
    assert SENTINEL not in stream.getvalue()


def test_NFR08_invalid_outcome_codes_are_not_logged_verbatim() -> None:
    # Given an outcome that is free text rather than a code
    stream = io.StringIO()
    configure_logging(stream, logging.INFO)
    log = get_logger("acceptance.nfr08.outcome")
    # When logging it
    try:
        log.info(f"bad outcome {SENTINEL}")
    except (TypeError, ValueError):
        pass
    # Then free text never reaches output
    assert SENTINEL not in stream.getvalue()


def test_NFR03_attestation_lifecycle_logs_contain_no_token_nonce_or_key(
    running_sim: RunningSim,
) -> None:
    # Given logging captured while a workload attests
    stream = io.StringIO()
    configure_logging(stream, logging.DEBUG)
    ik = IdentityKey.generate()
    lifecycle = AttestationLifecycle(
        ConfidentialSpaceLauncher(
            str(running_sim.config.socket_path), timeout_s=5.0, max_response_bytes=65536
        ),
        audience=AUDIENCE,
        token_type="OIDC",
        identity_public_key=ik.public_bytes(),
        refresh_margin_s=600,
        clock=running_sim.clock,
        logger=get_logger("acceptance.nfr03"),
    )
    # When it starts, then fails a refresh while the token is still valid (kept), then fails
    # again at expiry (API.md / T-06: at/after expires_at the error is logged and re-raised)
    token = lifecycle.start()
    running_sim.sim.stop()
    running_sim.clock.now = token.expires_at - 1
    assert lifecycle.refresh_if_due() is RefreshOutcome.FAILED_KEPT_CURRENT
    running_sim.clock.now = token.expires_at
    with pytest.raises(LauncherError):
        lifecycle.refresh_if_due()
    assert "ATTESTATION_REFRESH_FAILED" in stream.getvalue()
    assert "ATTESTATION_TOKEN_EXPIRED" in stream.getvalue()
    # Then no log line contains the token, a token segment, the nonce or the public key
    out = stream.getvalue()
    for secret in (
        token.value,
        token.value.split(".")[1],
        token.value.split(".")[2],
        hashlib.sha256(ik.public_bytes()).hexdigest(),
        ik.public_bytes().hex(),
    ):
        assert secret not in out
    for rec in _lines(stream):
        assert set(rec) <= ALLOWED_FIELDS | {
            "outcome",
            "timestamp",
            "level",
            "logger",
            "ts",
            "time",
            "name",
            "severity",
        }


def test_NFR03_identity_key_repr_is_redacted() -> None:
    # Given an identity key
    ik = IdentityKey.generate()
    # Then repr/str reveal nothing
    assert repr(ik) == "IdentityKey(<redacted>)"
    assert ik.public_bytes().hex() not in repr(ik) + str(ik)
    assert len(ik.public_bytes()) == 32
