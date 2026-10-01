"""T-05 acceptance tests for the allow-listed JSON logger."""

import io
import json
import logging
import re
import subprocess
import sys
from collections.abc import Iterator

import pytest

from teecustody.obs import JsonLogFormatter, configure_logging, get_logger
from teecustody.obs import logger as logger_module


@pytest.fixture
def buf(monkeypatch: pytest.MonkeyPatch) -> Iterator[io.StringIO]:
    base = logging.getLogger("teecustody")
    saved = (list(base.handlers), base.level, base.propagate)
    monkeypatch.setattr(logger_module, "_handler", None)
    stream = io.StringIO()
    configure_logging(stream)
    yield stream
    base.handlers[:] = saved[0]
    base.setLevel(saved[1])
    base.propagate = saved[2]


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
    streams = [
        h
        for h in logging.getLogger("teecustody").handlers
        if isinstance(h, logging.StreamHandler) and isinstance(h.formatter, JsonLogFormatter)
    ]
    assert len(streams) == 1
    assert isinstance(streams[0].formatter, JsonLogFormatter)
    assert buf.getvalue() == ""
    assert len(second.getvalue().splitlines()) == 1
    assert logging.getLogger("teecustody").propagate is False


def test_level_threshold_applies(buf: io.StringIO) -> None:
    stream = io.StringIO()
    configure_logging(stream, logging.ERROR)
    get_logger("attest").info("QUIET")
    get_logger("attest").error("LOUD")
    assert [json.loads(x)["outcome"] for x in stream.getvalue().splitlines()] == ["LOUD"]


def test_timestamp_format(buf: io.StringIO) -> None:
    get_logger("attest").warning("SOME_OUTCOME")
    ts = _only_line(buf)["ts"]
    assert isinstance(ts, str)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", ts)


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(10**5000, id="huge"),
        pytest.param(-1, id="negative"),
        pytest.param(2**64, id="2^64"),
    ],
)
def test_out_of_range_int_is_dropped_without_stderr(
    buf: io.StringIO, capsys: pytest.CaptureFixture[str], value: int
) -> None:
    get_logger("attest").info("SOME_OUTCOME", epoch=value)
    assert "epoch" not in _only_line(buf)
    assert capsys.readouterr().err == ""


def test_int_upper_bound_is_kept(buf: io.StringIO) -> None:
    get_logger("attest").info("SOME_OUTCOME", epoch=2**64 - 1)
    assert _only_line(buf)["epoch"] == 2**64 - 1


def test_formatter_failure_yields_safe_line_and_no_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    record = logging.makeLogRecord({"msg": "OK_CODE", "args": ("SENTINEL",), "created": None})
    obj = json.loads(JsonLogFormatter().format(record))
    assert obj == {"outcome": "LOG_FORMAT_FAILED"}
    assert "SENTINEL" not in capsys.readouterr().err


def test_unconfigured_logging_writes_nothing_to_stderr() -> None:
    code = (
        "import logging\n"
        "from teecustody.obs import get_logger\n"
        "get_logger('x').error('token=SENTINEL', epoch=1)\n"
        "err = ValueError('SENTINEL')\n"
        "logging.getLogger('teecustody.y').error('OK %s', 'SENTINEL', exc_info=err)\n"
    )
    done = subprocess.run(  # noqa: S603 - fixed argv, no untrusted input
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert done.stderr == ""
    assert done.stdout == ""


def test_str_and_int_subclasses_are_dropped(buf: io.StringIO) -> None:
    class ShortLen(str):
        __slots__ = ()

        def __len__(self) -> int:
            return 1

    class MyInt(int):
        __slots__ = ()

    class SpoofKey(str):
        __slots__ = ()

        def __hash__(self) -> int:
            return hash("epoch")

        def __eq__(self, other: object) -> bool:
            return other == "epoch"

    logging.getLogger("teecustody.x").info(
        "SOME_OUTCOME",
        extra={
            "tc_fields": {
                "request_id": ShortLen("y" * 500),
                "session_id": MyInt(5),
                SpoofKey("zzz"): 7,
            }
        },
    )
    obj = _only_line(buf)
    assert set(obj) == {"ts", "level", "logger", "outcome"}


def test_outcome_with_trailing_newline_is_invalid(buf: io.StringIO) -> None:
    get_logger("attest").info("OK\n")
    assert _only_line(buf)["outcome"] == "INVALID_OUTCOME_CODE"


class _FailingStream(io.StringIO):
    def write(self, s: str) -> int:
        raise OSError("WRITEFAIL_SECRET")


def test_stream_write_failure_leaks_nothing_to_stderr(
    buf: io.StringIO, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging(_FailingStream())
    logging.getLogger("teecustody.x").error("token=%s", "WRITEFAIL_SECRET_ARG")
    get_logger("attest").error("SOME_OUTCOME", request_id="r1")
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""
