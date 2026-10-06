"""T-01: the frozen `notes_gateway` public API (INC-2-API §6, API-TL TL-5) and its packaging."""

from __future__ import annotations

import ast
import inspect
import os
import time
import types
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import fastapi

import notes_gateway
from notes_gateway import GatewayLimits, create_app

if TYPE_CHECKING:
    from teecustody.queue.ports import RelayQueue


def _spec_create_app(
    queue: RelayQueue,
    *,
    limits: GatewayLimits = GatewayLimits(),
    rng: Callable[[int], bytes] = os.urandom,
    clock: Callable[[], float] = time.monotonic,
) -> fastapi.FastAPI: ...


def test_package_exports_exactly_create_app_and_gateway_limits() -> None:
    assert sorted(notes_gateway.__all__) == ["GatewayLimits", "create_app"]
    public = sorted(
        name
        for name, value in vars(notes_gateway).items()
        if not name.startswith("_") and not isinstance(value, types.ModuleType)
    )
    assert public == ["GatewayLimits", "create_app"]


def test_create_app_signature_equals_api_transcription() -> None:
    assert inspect.signature(create_app) == inspect.signature(_spec_create_app)


def _spec_dev_main(argv: Sequence[str] | None = None) -> int: ...


def test_dev_main_signature_equals_api_tl_transcription() -> None:
    from notes_gateway import dev

    assert inspect.signature(dev.main, eval_str=True) == inspect.signature(
        _spec_dev_main, eval_str=True
    )


def test_dev_module_runs_main_as_its_exit_status() -> None:
    from notes_gateway import dev

    tree = ast.parse(Path(inspect.getfile(dev)).read_text(encoding="utf-8"))
    last = ast.unparse(tree.body[-1])
    assert last == "if __name__ == '__main__':\n    raise SystemExit(main())"
