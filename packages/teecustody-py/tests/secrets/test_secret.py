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


def test_secret_error_carries_only_its_code() -> None:
    for code in SecretErrorCode:
        err = SecretError(code)
        assert err.code is code
        assert str(err) == code.value
        assert err.args == (code.value,)
