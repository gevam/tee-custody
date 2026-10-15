"""T-23 criterion 8: no sealing API takes a seq, a nonce or a key (R-5, D2-16; §4.9 A1)."""

import importlib
import inspect
import pkgutil
import typing
from collections.abc import Callable, Iterator
from types import ModuleType

import teecustody.channel
from teecustody.channel import session as session_module
from teecustody.channel.codec import FrameAad
from teecustody.channel.session import Session, SessionTable, T2cSealer
from teecustody.secrets import Secret

FORBIDDEN_PARAMETERS = frozenset({"seq", "nonce"})
# Exact allow-list (INC-2-API §4.9, 2026-10-13): codec wire records that hold AAD values and
# perform no encryption. Any other constructor with a `seq` or `nonce` parameter fails.
CONSTRUCTOR_ALLOW_LIST: frozenset[type] = frozenset({FrameAad})
CONSTRUCTORS = ("__init__", "__new__")
SESSION_CLASSES: tuple[type, ...] = (T2cSealer, Session, SessionTable)
KEY_TYPES: tuple[type, ...] = (Secret, T2cSealer)
KEY_TAKERS = frozenset({"T2cSealer.__init__", "SessionTable.create", "open_frame"})


def _channel_modules() -> Iterator[ModuleType]:
    yield teecustody.channel
    for info in pkgutil.iter_modules(teecustody.channel.__path__, "teecustody.channel."):
        yield importlib.import_module(info.name)


def _functions_of(cls: type, *, every_method: bool) -> Iterator[tuple[str, Callable[..., object]]]:
    for name, member in vars(cls).items():
        function = member.__func__ if isinstance(member, classmethod | staticmethod) else member
        if not inspect.isfunction(function):
            continue
        if every_method or name in CONSTRUCTORS or not name.startswith("_"):
            yield f"{cls.__qualname__}.{name}", function


def _channel_callables(
    classes: tuple[type, ...] = (),
) -> Iterator[tuple[type | None, str, Callable[..., object]]]:
    seen: set[object] = set()
    for module in _channel_modules():
        for name, obj in vars(module).items():
            if name.startswith("_") or getattr(obj, "__module__", None) != module.__name__:
                continue
            if obj in seen:
                continue
            seen.add(obj)
            if inspect.isfunction(obj):
                yield None, name, obj
            elif inspect.isclass(obj):
                for qualname, function in _functions_of(obj, every_method=obj in SESSION_CLASSES):
                    yield obj, qualname, function
    for cls in classes:
        for qualname, function in _functions_of(cls, every_method=True):
            yield cls, qualname, function


def _seq_violations(
    classes: tuple[type, ...] = (), allow: frozenset[type] = CONSTRUCTOR_ALLOW_LIST
) -> set[str]:
    found: set[str] = set()
    for owner, qualname, function in _channel_callables(classes):
        if owner in allow and qualname.rsplit(".", 1)[-1] in CONSTRUCTORS:
            continue
        if FORBIDDEN_PARAMETERS & set(inspect.signature(function).parameters):
            found.add(qualname)
    return found


def test_no_channel_callable_has_a_seq_or_nonce_parameter() -> None:
    assert _seq_violations() == set()


def test_the_allow_list_is_exact_and_not_stale() -> None:
    assert _seq_violations(allow=frozenset()) == {"FrameAad.__init__"}


def test_a_new_constructor_taking_seq_fails_the_check() -> None:
    class RogueSealer:
        def __init__(self, seq: int) -> None:
            self.start = seq

    class RogueNonce:
        def emit(self, nonce: bytes) -> bytes:
            return nonce

    assert _seq_violations((RogueSealer, RogueNonce)) == {
        f"{RogueSealer.__qualname__}.__init__",
        f"{RogueNonce.__qualname__}.emit",
    }


def test_every_method_of_the_session_classes_is_checked_including_private_ones() -> None:
    checked = {qualname for _owner, qualname, _function in _channel_callables()}
    for cls in SESSION_CLASSES:
        for name, member in vars(cls).items():
            if inspect.isfunction(member):
                assert f"{cls.__qualname__}.{name}" in checked


def _is_key_type(hint: object) -> bool:
    if isinstance(hint, type) and issubclass(hint, KEY_TYPES):
        return True
    return any(_is_key_type(arg) for arg in typing.get_args(hint))


def _takes_a_key(function: Callable[..., object]) -> bool:
    hints = typing.get_type_hints(function)
    return any(_is_key_type(hint) for name, hint in hints.items() if name != "return")


def test_a_key_hidden_in_a_union_or_container_is_still_a_key() -> None:
    def optional(key: Secret | None) -> None: ...
    def nested(keys: list[tuple[int, T2cSealer]]) -> None: ...
    def plain(data: bytes, count: int | None) -> Secret: ...

    assert _takes_a_key(optional)
    assert _takes_a_key(nested)
    assert not _takes_a_key(plain)


def test_only_the_sealer_constructor_table_create_and_open_frame_take_a_key() -> None:
    takers: set[str] = set()
    for name, obj in vars(session_module).items():
        if inspect.isfunction(obj) and obj.__module__ == session_module.__name__:
            if _takes_a_key(obj):
                takers.add(name)
        elif inspect.isclass(obj) and obj.__module__ == session_module.__name__:
            for qualname, function in _functions_of(obj, every_method=True):
                if _takes_a_key(function):
                    takers.add(qualname)
    assert takers == KEY_TAKERS


def test_the_nonce_builder_is_not_exported_from_the_channel_package() -> None:
    assert "_nonce" not in teecustody.channel.__all__
    assert not hasattr(teecustody.channel, "_nonce")
    assert "open_frame" not in teecustody.channel.__all__
