"""T-05 acceptance tests for the allow-listed JSON logger."""

import io
import json
import logging
import re
from collections.abc import Iterator

import pytest

from teecustody.obs import JsonLogFormatter, configure_logging, get_logger


@pytest.fixture
def buf() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    configure_logging(stream)
    yield stream
    base = logging.getLogger("teecustody")
    for handler in list(base.handlers):
        base.removeHandler(handler)


def _only_line(buf: io.StringIO) -> dict[str, object]:
    lines = buf.getvalue().splitlines()
    assert len(lines) == 1
    parsed: dict[str, object] = json.loads(lines[0])
    return parsed


def test_line_has_exactly_expected_keys(buf: io.StringIO) -> None:
    get_logger("attest").info("ATTESTATION_TOKEN_OBTAINED", request_id="r1", epoch=3)
    obj = _only_line(buf)
    assert set(obj) == {"ts", "level", "logger", "outcome", "request_id", "epoch"}
    assert obj["logger"] == "teecustody.attest"
    assert obj["level"] == "INFO"
    assert obj["outcome"] == "ATTESTATION_TOKEN_OBTAINED"
    assert obj["request_id"] == "r1"
    assert obj["epoch"] == 3


def test_non_allow_listed_field_is_dropped(buf: io.StringIO) -> None:
    get_logger("attest").info("SOME_OUTCOME", request_id="r1", token="SENTINEL")  # type: ignore[arg-type]
    obj = _only_line(buf)
    assert "token" not in obj
    assert "SENTINEL" not in buf.getvalue()


def test_non_conforming_outcome_is_replaced(buf: io.StringIO) -> None:
    get_logger("attest").info("token=SENTINEL")
    assert _only_line(buf)["outcome"] == "INVALID_OUTCOME_CODE"
    assert "SENTINEL" not in buf.getvalue()


@pytest.mark.parametrize(
    ("field", "value"),
    [("request_id", b"SENTINEL"), ("epoch", True), ("session_id", "x" * 129)],
)
def test_non_conforming_field_value_is_omitted(buf: io.StringIO, field: str, value: object) -> None:
    get_logger("attest").info("SOME_OUTCOME", **{field: value})  # type: ignore[arg-type]
    obj = _only_line(buf)
    assert field not in obj
    assert "SENTINEL" not in buf.getvalue()


def test_boundary_128_char_string_is_kept(buf: io.StringIO) -> None:
    get_logger("attest").info("SOME_OUTCOME", client_id="x" * 128)
    assert _only_line(buf)["client_id"] == "x" * 128


def test_stdlib_call_args_and_exception_never_reach_output(buf: io.StringIO) -> None:
    logging.getLogger("teecustody.x").error(
        "OK_CODE %s", "SENTINEL", exc_info=ValueError("SENTINEL"), stack_info=True
    )
    obj = _only_line(buf)
    assert obj["outcome"] == "INVALID_OUTCOME_CODE"
    assert "SENTINEL" not in buf.getvalue()
    assert "Traceback" not in buf.getvalue()


def test_non_string_msg_is_replaced(buf: io.StringIO) -> None:
    logging.getLogger("teecustody.x").error(ValueError("SENTINEL"))
    assert _only_line(buf)["outcome"] == "INVALID_OUTCOME_CODE"
    assert "SENTINEL" not in buf.getvalue()


def test_malformed_tc_fields_do_not_raise(buf: io.StringIO) -> None:
    logging.getLogger("teecustody.x").info("OK_CODE", extra={"tc_fields": "SENTINEL"})
    assert _only_line(buf)["outcome"] == "OK_CODE"
    assert "SENTINEL" not in buf.getvalue()


def test_reconfigure_keeps_single_handler(buf: io.StringIO) -> None:
    second = io.StringIO()
    configure_logging(second)
    configure_logging(second)
    get_logger("attest").info("ONCE")
    ours = [
        h
        for h in logging.getLogger("teecustody").handlers
        if isinstance(h.formatter, JsonLogFormatter)
    ]
    assert len(ours) == 1
    assert buf.getvalue() == ""
    assert len(second.getvalue().splitlines()) == 1
    assert logging.getLogger("teecustody").propagate is False


def test_level_threshold_applies() -> None:
    stream = io.StringIO()
    configure_logging(stream, logging.ERROR)
    get_logger("attest").info("QUIET")
    get_logger("attest").error("LOUD")
    base = logging.getLogger("teecustody")
    for handler in list(base.handlers):
        base.removeHandler(handler)
    assert [json.loads(x)["outcome"] for x in stream.getvalue().splitlines()] == ["LOUD"]


def test_timestamp_format(buf: io.StringIO) -> None:
    get_logger("attest").warning("SOME_OUTCOME")
    ts = _only_line(buf)["ts"]
    assert isinstance(ts, str)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", ts)
