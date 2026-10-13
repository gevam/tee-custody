"""NFR-3 / NFR-8 / SR-11 secret hygiene and NFR-4 / SR-9 dependency pins for the INC-2 channel.

Owning tasks: T-28 (server logging), T-12 (audit fields), T-14 (gateway logging), T-29 (run loop),
T-08 (`pyhpke` pin and hashes), T-25 (simulator pin). Expected failure on trunk:
NotImplementedError('T-24'|'T-14'...) for the behavioural tests, an assertion on the missing pin for
the manifest tests (the pins are the deliverable of T-08 and T-25).
"""

import base64
import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
from notes_gateway import create_app
from starlette.testclient import TestClient

from acc_channel import (
    CLIENT_ID,
    SENTINEL_CS,
    flip_ct_bit,
    make_world,
    read_open_result,
    seal_frame,
)
from acc_runloop import IID, OCTET, SpyRelay
from teecustody.audit import AuditClass, audit_json

REPO = Path(__file__).resolve().parents[2]
SENTINEL_TEXT = "SENTINEL-PAYLOAD-4c1e9a"
ALLOWED_LOG_FIELDS = {"client_id", "request_id", "session_id", "prekey_id", "epoch"}
OUTCOME = re.compile(r"[A-Z][A-Z0-9_]*")


def _forms(raw: bytes) -> list[str]:
    return [
        raw.hex(),
        raw.hex().upper(),
        base64.b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode(),
        base64.urlsafe_b64encode(raw).decode().rstrip("="),
        repr(raw)[2:-1],
    ]


def _exercise(world: Any) -> list[str]:
    """Success and failure paths that touch the sentinel; returns every observable string."""
    seen: list[str] = []
    sent, opened = world.established(cs=SENTINEL_CS)
    assert opened.session_id is not None
    for i, payload in enumerate([SENTINEL_TEXT, {"k": SENTINEL_TEXT}, SENTINEL_CS]):
        result = world.server.process(
            seal_frame(sent.c2t, opened.session_id, i, "test.echo", payload)
        )
        seen += [repr(result), repr(result.response)]
    # failure paths: wrong share (sentinel share is the right one, so use a mismatching copy),
    # tampered frame, garbage, unknown session
    bad = world.open_session(cs=SENTINEL_CS[:-1] + b"\x00")
    seen.append(repr(world.server.process(bad.body)))
    seen.append(repr(world.server.process(flip_ct_bit(
        seal_frame(sent.c2t, opened.session_id, 9, "test.echo", SENTINEL_TEXT)))))  # fmt: skip
    seen.append(repr(world.server.process(seal_frame(bytes(32), bytes(16), 0, "t", SENTINEL_TEXT))))
    seen.append(repr(world.server.process(b"\xff" + SENTINEL_TEXT.encode())))
    seen.append(repr(world.opener.requests))
    return seen


def test_NFR03_sentinel_share_and_payload_never_reach_logs_audit_or_reprs() -> None:
    # Given a channel whose client share and payloads are recognisable sentinels
    world = make_world(shares={CLIENT_ID: SENTINEL_CS})
    # When success and failure paths run, and the audit interval is flushed
    observable = _exercise(world)
    world.flush_aggregates()
    observable.append(world.logger.text())
    observable += [audit_json(record).decode() + repr(key) for key, record in world.sink.records()]
    haystack = "\n".join(observable)
    # Then neither the share (in any common encoding) nor the payload text appears anywhere
    assert SENTINEL_TEXT not in haystack
    for form in _forms(SENTINEL_CS):
        assert form not in haystack, form


def test_NFR08_log_calls_use_only_allow_listed_fields_and_outcome_codes() -> None:
    # Given the same traffic
    world = make_world(shares={CLIENT_ID: SENTINEL_CS})
    _exercise(world)
    # Then every log call has an UPPER_SNAKE outcome and only allow-listed scalar fields
    assert world.logger.calls
    for _level, outcome, fields in world.logger.calls:
        assert OUTCOME.fullmatch(outcome), outcome
        assert set(fields) <= ALLOWED_LOG_FIELDS, set(fields) - ALLOWED_LOG_FIELDS
        assert all(isinstance(v, str | int) and not isinstance(v, bool) for v in fields.values())
    # And the opened session is logged with the principal and hex ids only
    opened = [f for _l, o, f in world.logger.calls if o == "SESSION_OPENED"]
    assert opened and opened[0]["client_id"] == CLIENT_ID
    assert re.fullmatch(r"[0-9a-f]{32}", str(opened[0]["session_id"]))


def test_SR06_pre_principal_aggregates_carry_no_identifiers() -> None:
    # Given failures before any principal exists
    world = make_world(shares={CLIENT_ID: SENTINEL_CS})
    for _ in range(3):
        world.server.process(b"\xff")
    world.server.process(seal_frame(bytes(32), bytes(16), 0, "t", 1))
    world.flush_aggregates()
    # Then each AGGREGATE has a count and no client, session, request or recovery identifier
    aggregates = world.sink.records(AuditClass.AGGREGATE)
    assert aggregates
    for _key, record in aggregates:
        assert record.count is not None and record.count >= 1
        assert record.actor_client_id is None and record.subject_client_id is None
        assert record.recovery_id is None and record.session_id is None
        assert record.request_id is None and record.prekey_id is None


def test_SR11_a_refused_open_reveals_only_a_stable_error_category() -> None:
    # Given a workload whose opener raises with provider text inside it
    class Exploding:
        requests: list[Any] = []  # noqa: RUF012

        def open(self, request: Any) -> Any:
            raise RuntimeError("SENTINEL-PROVIDER-TEXT-77aa")

        def closed(self, session: Any, reason: Any) -> None:
            raise RuntimeError("SENTINEL-PROVIDER-TEXT-77aa")

    world = make_world(opener=Exploding())
    sent = world.open_session()
    # When the open is processed
    result = world.server.process(sent.body)
    # Then the client sees a stable code only, and the provider text is nowhere
    assert result.response is not None
    opened = read_open_result(result.response.body, sent.t2c)
    assert not opened.ok and opened.error == "BACKEND_UNAVAILABLE"
    assert "SENTINEL-PROVIDER-TEXT-77aa" not in repr(result) + world.logger.text()
    world.flush_aggregates()
    assert "SENTINEL-PROVIDER-TEXT-77aa" not in repr(world.sink.records())


def test_SR11_gateway_never_logs_or_echoes_request_bodies(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given a gateway handling a request whose body is a sentinel
    caplog.set_level("DEBUG")
    client = TestClient(create_app(SpyRelay()), raise_server_exceptions=False)
    body = SENTINEL_TEXT.encode()
    # When it is posted (accepted) and posted oversize (rejected)
    ok = client.post(f"/requests/{IID}", content=body, headers=OCTET)
    big = client.post(f"/requests/{IID}", content=body * 10_000, headers=OCTET)
    # Then neither response nor log contains the body
    assert ok.status_code == 202 and big.status_code == 400
    assert SENTINEL_TEXT not in ok.text + big.text + caplog.text


# ---------------------------------------------------------------- NFR-4 / SR-9 pins (static)
def _toml(path: str) -> dict[str, Any]:
    return tomllib.loads((REPO / path).read_text())


def test_NFR04_python_crypto_dependencies_are_exactly_pinned_with_hashes() -> None:
    # Given the teecustody manifest and the lock file
    deps = _toml("packages/teecustody-py/pyproject.toml")["project"]["dependencies"]
    lock = (REPO / "uv.lock").read_text()
    # Then pyhpke is pinned with == (ADR 0011 C1/C3) and the lock holds its registry hashes
    pins = [d for d in deps if re.match(r"pyhpke\b", d)]
    assert len(pins) == 1 and re.fullmatch(r"pyhpke==\d+(\.\d+)*", pins[0]), deps
    assert "e8d794724e43053fe04e8971be55033225d6da904effc748b303cece763a3f3c" in lock
    # And every cryptography/cbor2 dependency is an exact pin, and no forbidden package is locked
    for d in deps:
        if re.match(r"(cryptography|cbor2)\b", d):
            assert "==" in d, d
    for forbidden in ("pycrypto", "pyaes", "tinyec", "pycryptodome"):
        assert not re.search(rf'^name = "{forbidden}"', lock, re.MULTILINE), forbidden
    # And the simulator is not a dependency of the workload package (NFR-6)
    assert not any("teecustody-sim" in d for d in deps)


def test_NFR04_simulator_pins_pyhpke_exactly_and_is_not_a_workload_dependency() -> None:
    # Given the simulator manifest (the first simulator importer of pyhpke is T-25)
    sim = _toml("packages/teecustody-sim/pyproject.toml")["project"]["dependencies"]
    pins = [d for d in sim if re.match(r"pyhpke\b", d)]
    # Then it pins the same exact version as teecustody
    py = _toml("packages/teecustody-py/pyproject.toml")["project"]["dependencies"]
    assert len(pins) == 1 and pins[0] in py, (sim, py)
