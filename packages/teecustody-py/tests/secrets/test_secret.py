"""T-04 criteria 3-5: `teecustody.secrets.Secret` (INC-2-API §4.1; NFR-3, SR-11)."""

from __future__ import annotations

import copy
import pickle
from collections.abc import Callable

import pytest

from teecustody.secrets import Secret, SecretError, SecretErrorCode

KEY = b"k" * 32
REDACTED = "Secret(<redacted>)"


def _code(excinfo: pytest.ExceptionInfo[SecretError]) -> SecretErrorCode:
    return excinfo.value.code


# --- criterion 3: redaction, forbidden implicit conversions, len/reveal/equals ---------------


def test_repr_str_and_format_are_redacted() -> None:
    s = Secret(KEY)

    assert repr(s) == REDACTED
    assert str(s) == REDACTED
    assert f"{s}" == REDACTED
    assert f"{s!r}" == REDACTED
    assert format(s, "x") == REDACTED
    assert "6b" not in repr([s])


FORBIDDEN: dict[str, Callable[[Secret], object]] = {
    "pickle": pickle.dumps,
    "copy": copy.copy,
    "deepcopy": copy.deepcopy,
    "bytes": bytes,
    "eq": lambda s: s == s,
    "ne": lambda s: s != Secret(KEY),
    "iter": iter,
    "getitem": lambda s: s[0],
    "slice": lambda s: s[0:4],
    "reduce": lambda s: s.__reduce__(),
    "reduce_ex": lambda s: s.__reduce_ex__(4),
    "getstate": lambda s: s.__getstate__(),
}


@pytest.mark.parametrize("operation", FORBIDDEN.values(), ids=FORBIDDEN.keys())
def test_implicit_conversions_raise_forbidden(operation: Callable[[Secret], object]) -> None:
    s = Secret(KEY)

    with pytest.raises(SecretError) as excinfo:
        operation(s)

    assert _code(excinfo) is SecretErrorCode.FORBIDDEN
    assert str(excinfo.value) == "FORBIDDEN"
    assert excinfo.value.args == ("FORBIDDEN",)


def test_secret_is_unhashable() -> None:
    assert Secret.__hash__ is None
    with pytest.raises(TypeError):
        hash(Secret(KEY))


def test_len_reveal_and_equals() -> None:
    s = Secret(bytearray(KEY))

    assert len(s) == 32
    assert s.reveal() == KEY
    assert type(s.reveal()) is bytes
    assert s.equals(KEY)
    assert s.equals(Secret(KEY))
    assert not s.equals(b"j" * 32)
    assert not s.equals(Secret(b"k" * 31))
    assert not s.wiped


def test_input_is_copied_not_aliased() -> None:
    source = bytearray(KEY)
    s = Secret(memoryview(source))

    source[0] = 0

    assert s.reveal() == KEY


def test_equals_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    import teecustody.secrets as module

    calls: list[tuple[object, object]] = []

    def recording(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return True

    monkeypatch.setattr(module.hmac, "compare_digest", recording)

    assert Secret(KEY).equals(b"other")
    assert len(calls) == 1


def test_equals_secret_uses_constant_time_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    import teecustody.secrets as module

    calls: list[tuple[object, object]] = []

    def recording(a: bytes, b: bytes) -> bool:
        calls.append((bytes(a), bytes(b)))
        return True

    monkeypatch.setattr(module.hmac, "compare_digest", recording)

    assert Secret(KEY).equals(Secret(b"other"))
    assert calls == [(KEY, b"other")]


def test_bytearray_input_is_copied_and_wipe_leaves_the_source_alone() -> None:
    source = bytearray(KEY)
    s = Secret(source)

    source[0] = ord("j")
    assert s.reveal() == KEY

    s.wipe()
    assert source == bytearray(b"j" + KEY[1:])


def test_secret_error_carries_only_its_code() -> None:
    for code in SecretErrorCode:
        err = SecretError(code)
        assert err.code is code
        assert str(err) == code.value
        assert err.args == (code.value,)


# --- criterion 4: explicit wipe ---------------------------------------------------------------


class _RecordingBuffer(bytearray):
    """Test-only stand-in for the private buffer: snapshots its bytes when it is emptied."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.at_clear: list[bytes] = []

    def clear(self) -> None:
        self.at_clear.append(bytes(self))
        super().clear()

    def __delitem__(self, index: int | slice) -> None:
        self.at_clear.append(bytes(self))
        super().__delitem__(index)


def test_wipe_zeroes_every_byte_before_emptying_the_buffer() -> None:
    s = Secret(KEY)
    buffer = _RecordingBuffer(KEY)
    s._buf = buffer  # test-only reference to the private buffer

    s.wipe()

    assert buffer.at_clear == [bytes(32)]
    assert len(buffer) == 0
    assert len(s) == 0
    assert s.wiped


def test_wiped_secret_refuses_reveal_and_equals_and_rewipe_is_a_noop() -> None:
    s = Secret(KEY)
    other = Secret(KEY)
    s.wipe()

    for operation in (s.reveal, lambda: s.equals(KEY), lambda: other.equals(s)):
        with pytest.raises(SecretError) as excinfo:
            operation()
        assert _code(excinfo) is SecretErrorCode.WIPED

    s.wipe()
    assert s.wiped
    assert repr(s) == REDACTED


def test_context_manager_wipes_on_exit_including_on_error() -> None:
    with Secret(KEY) as s:
        assert s.reveal() == KEY
    assert s.wiped

    with pytest.raises(RuntimeError), Secret(KEY) as t:
        raise RuntimeError("boom")
    assert t.wiped


# --- criterion 5: length bounds and random ----------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [b"", bytearray(), memoryview(b""), b"\x00" * 65537],
    ids=["bytes-0", "bytearray-0", "memoryview-0", "bytes-65537"],
)
def test_length_outside_bounds_is_rejected(data: bytes | bytearray | memoryview) -> None:
    with pytest.raises(SecretError) as excinfo:
        Secret(data)
    assert _code(excinfo) is SecretErrorCode.INVALID_LENGTH


@pytest.mark.parametrize("length", [1, 65536])
def test_length_bounds_are_inclusive(length: int) -> None:
    assert len(Secret(b"\x01" * length)) == length
    assert len(Secret.random(length)) == length


@pytest.mark.parametrize("length", [0, -1, 65537, True, False, 32.0])
def test_random_length_outside_bounds_is_rejected(length: int) -> None:
    with pytest.raises(SecretError) as excinfo:
        Secret.random(length)
    assert _code(excinfo) is SecretErrorCode.INVALID_LENGTH


def test_random_secrets_differ() -> None:
    first = Secret.random(32)
    second = Secret.random(32)

    assert isinstance(first, Secret)
    assert len(first) == 32
    assert not first.equals(second)


def test_random_draws_from_os_urandom(monkeypatch: pytest.MonkeyPatch) -> None:
    import teecustody.secrets as module

    requested: list[int] = []

    def recording(n: int) -> bytes:
        requested.append(n)
        return b"\x5a" * n

    monkeypatch.setattr(module.os, "urandom", recording)

    s = Secret.random(32)

    assert requested == [32]
    assert s.reveal() == b"\x5a" * 32
