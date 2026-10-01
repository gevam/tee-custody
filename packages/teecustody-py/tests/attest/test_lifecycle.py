"""T-06 criteria 6 and 9: attestation start and refresh lifecycle (FR-1, NFR-8)."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from teecustody.attest import (
    AttestationLifecycle,
    AttestationToken,
    LauncherError,
    LauncherErrorCode,
    RefreshOutcome,
    identity_nonce,
)
from teecustody.obs import FieldValue

AUD = "https://workload.teecustody.test/aud"
IK_PUB = bytes(range(32))
MARGIN = 300
FIRST = AttestationToken("first.token.value", issued_at=1_000, expires_at=4_600)
SECOND = AttestationToken("second.token.value", issued_at=4_300, expires_at=7_900)
UNAVAILABLE = LauncherError(LauncherErrorCode.UNAVAILABLE)


@dataclass
class ScriptedLauncher:
    """Answers each request with the next scripted token or error and records the request."""

    script: list[AttestationToken | LauncherError]
    calls: list[tuple[str, str, bytes]] = field(default_factory=list)

    def get_attestation_token(
        self, audience: str, token_type: str, identity_nonce: bytes
    ) -> AttestationToken:
        self.calls.append((audience, token_type, identity_nonce))
        result = self.script.pop(0)
        if isinstance(result, LauncherError):
            raise result
        return result


@dataclass
class Clock:
    now: float = 1_000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class RecordingLogger:
    records: list[tuple[str, str, dict[str, FieldValue]]] = field(default_factory=list)

    def info(self, outcome: str, **fields: FieldValue) -> None:
        self.records.append(("info", outcome, fields))

    def warning(self, outcome: str, **fields: FieldValue) -> None:
        self.records.append(("warning", outcome, fields))

    def error(self, outcome: str, **fields: FieldValue) -> None:
        self.records.append(("error", outcome, fields))

    @property
    def outcomes(self) -> list[str]:
        return [outcome for _, outcome, _ in self.records]


@dataclass
class Rig:
    launcher: ScriptedLauncher
    clock: Clock
    logger: RecordingLogger
    lifecycle: AttestationLifecycle


def make_rig(*script: AttestationToken | LauncherError) -> Rig:
    launcher = ScriptedLauncher(list(script))
    clock = Clock()
    logger = RecordingLogger()
    lifecycle = AttestationLifecycle(
        launcher,
        audience=AUD,
        token_type="OIDC",
        identity_public_key=IK_PUB,
        refresh_margin_s=MARGIN,
        clock=clock,
        logger=logger,
    )
    return Rig(launcher, clock, logger, lifecycle)


def started(*script: AttestationToken | LauncherError) -> Rig:
    rig = make_rig(FIRST, *script)
    assert rig.lifecycle.start() == FIRST
    return rig


def _assert_same_nonce_everywhere(rig: Rig) -> None:
    assert rig.launcher.calls
    assert set(rig.launcher.calls) == {(AUD, "OIDC", identity_nonce(IK_PUB))}


# Construction and start ----------------------------------------------------------------------


@pytest.mark.parametrize("margin", [0, -1])
def test_refresh_margin_below_one_second_is_refused(margin: int) -> None:
    with pytest.raises(ValueError, match="REFRESH_MARGIN"):
        AttestationLifecycle(
            ScriptedLauncher([]),
            audience=AUD,
            token_type="OIDC",
            identity_public_key=IK_PUB,
            refresh_margin_s=margin,
            clock=Clock(),
            logger=RecordingLogger(),
        )


@pytest.mark.parametrize("length", [0, 31, 33])
def test_identity_key_of_the_wrong_length_is_refused(length: int) -> None:
    with pytest.raises(ValueError, match="IDENTITY_KEY_LENGTH"):
        AttestationLifecycle(
            ScriptedLauncher([]),
            audience=AUD,
            token_type="OIDC",
            identity_public_key=bytes(length),
            refresh_margin_s=MARGIN,
            clock=Clock(),
            logger=RecordingLogger(),
        )


def test_identity_nonce_is_derived_from_the_identity_key() -> None:
    assert make_rig().lifecycle.identity_nonce == identity_nonce(IK_PUB)


def test_current_before_start_is_an_error() -> None:
    with pytest.raises(RuntimeError, match="NOT_STARTED"):
        make_rig().lifecycle.current()


def test_start_requests_one_nonce_bound_token_and_keeps_it() -> None:
    rig = make_rig(FIRST)

    assert rig.lifecycle.start() == FIRST

    assert rig.lifecycle.current() == FIRST
    assert rig.launcher.calls == [(AUD, "OIDC", identity_nonce(IK_PUB))]
    assert rig.logger.records == [("info", "ATTESTATION_TOKEN_OBTAINED", {})]


def test_start_fails_when_no_token_can_be_obtained() -> None:
    rig = make_rig(UNAVAILABLE)

    with pytest.raises(LauncherError) as caught:
        rig.lifecycle.start()

    assert caught.value is UNAVAILABLE
    assert rig.logger.records == [("error", "ATTESTATION_TOKEN_FAILED", {})]
    with pytest.raises(RuntimeError, match="NOT_STARTED"):
        rig.lifecycle.current()


# Criterion 6: refresh boundaries ------------------------------------------------------------


def test_refresh_is_not_due_one_second_before_the_margin() -> None:
    rig = started()
    rig.clock.now = FIRST.expires_at - MARGIN - 1

    assert rig.lifecycle.refresh_if_due() is RefreshOutcome.NOT_DUE

    assert len(rig.launcher.calls) == 1
    assert rig.lifecycle.current() == FIRST
    assert rig.logger.outcomes == ["ATTESTATION_TOKEN_OBTAINED"]


def test_refresh_at_the_margin_replaces_the_token() -> None:
    rig = started(SECOND)
    rig.clock.now = FIRST.expires_at - MARGIN

    assert rig.lifecycle.refresh_if_due() is RefreshOutcome.REFRESHED

    assert rig.lifecycle.current() == SECOND
    assert rig.logger.records[-1] == ("info", "ATTESTATION_TOKEN_REFRESHED", {})
    _assert_same_nonce_everywhere(rig)


def test_failed_refresh_before_expiry_keeps_the_current_token() -> None:
    rig = started(UNAVAILABLE)
    rig.clock.now = FIRST.expires_at - 1

    assert rig.lifecycle.refresh_if_due() is RefreshOutcome.FAILED_KEPT_CURRENT

    assert rig.lifecycle.current() == FIRST
    assert rig.logger.records[-1] == ("warning", "ATTESTATION_REFRESH_FAILED", {})
    _assert_same_nonce_everywhere(rig)


def test_failed_refresh_at_expiry_is_raised() -> None:
    rig = started(UNAVAILABLE)
    rig.clock.now = FIRST.expires_at

    with pytest.raises(LauncherError) as caught:
        rig.lifecycle.refresh_if_due()

    assert caught.value is UNAVAILABLE
    assert rig.logger.records[-1] == ("error", "ATTESTATION_TOKEN_EXPIRED", {})
    _assert_same_nonce_everywhere(rig)


def test_successful_refresh_at_expiry_recovers() -> None:
    rig = started(SECOND)
    rig.clock.now = FIRST.expires_at

    assert rig.lifecycle.refresh_if_due() is RefreshOutcome.REFRESHED

    assert rig.lifecycle.current() == SECOND


def test_refresh_schedule_follows_the_newest_token() -> None:
    third = AttestationToken("third.token.value", issued_at=7_600, expires_at=11_200)
    rig = started(SECOND, third)
    rig.clock.now = FIRST.expires_at - MARGIN
    assert rig.lifecycle.refresh_if_due() is RefreshOutcome.REFRESHED

    rig.clock.now = SECOND.expires_at - MARGIN - 1
    assert rig.lifecycle.refresh_if_due() is RefreshOutcome.NOT_DUE
    rig.clock.now = SECOND.expires_at - MARGIN
    assert rig.lifecycle.refresh_if_due() is RefreshOutcome.REFRESHED

    assert rig.lifecycle.current() == third
    assert len(rig.launcher.calls) == 3
    _assert_same_nonce_everywhere(rig)
