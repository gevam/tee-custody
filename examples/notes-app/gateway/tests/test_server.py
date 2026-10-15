"""T-40: gateway uvicorn server hardening (INC-2-API §6 "Server hardening"; SR-3, SR-4, SR-11).

Live tests run `uvicorn.Server(uvicorn_config(...))` in a thread on 127.0.0.1:0 and talk raw
sockets. Every wait is bounded, every socket is closed and every server is stopped on teardown.
"""

from __future__ import annotations

from typing import Any

import pytest
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from notes_gateway import GatewayLimits, create_app
from notes_gateway import server as gateway_server
from teecustody.queue import PublishedBundle, ResponsePage


class Relay:
    """A RelayQueue fake that counts calls."""

    def __init__(self) -> None:
        self.calls = 0

    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]:
        self.calls += 1
        return []

    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str:
        self.calls += 1
        return "11" * 16

    def pull_responses(self, client_id: str, after: str | None, max_messages: int) -> ResponsePage:
        self.calls += 1
        return ResponsePage((), None)


# ------------------------------------------------------------- criterion 10: the uvicorn settings
@pytest.fixture
def config_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real_config = uvicorn.Config

    class RecordingConfig(real_config):  # type: ignore[valid-type,misc]
        def __init__(self, app: Any, **kwargs: Any) -> None:
            calls.append(kwargs)
            super().__init__(app, **kwargs)

    monkeypatch.setattr(uvicorn, "Config", RecordingConfig)
    return calls


def test_uvicorn_config_has_every_section_6_setting(config_calls: list[dict[str, Any]]) -> None:
    app = create_app(Relay())

    config = gateway_server.uvicorn_config(app, host="127.0.0.1", port=0)

    assert len(config_calls) == 1
    assert config.app is app
    assert (config.host, config.port) == ("127.0.0.1", 0)
    assert isinstance(config.http, type)
    assert issubclass(config.http, H11Protocol)
    assert config.http is not H11Protocol
    assert config.ws == "none"
    assert config.proxy_headers is False
    assert config.server_header is False
    assert config.access_log is False
    assert config.h11_max_incomplete_event_size == 16384
    assert config.timeout_keep_alive == 5
    assert config.log_level == "warning"
    assert config.limit_concurrency is None
    assert "forwarded_allow_ips" not in config_calls[0]
    assert "limit_concurrency" not in config_calls[0]


def test_uvicorn_config_loads_the_gateway_protocol_and_no_websocket_protocol() -> None:
    config = gateway_server.uvicorn_config(create_app(Relay()), host="127.0.0.1", port=0)

    config.load()

    assert config.http_protocol_class is config.http
    assert config.ws_protocol_class is None


# ------------------------------------------------------------- criterion 9: limits validation
INVALID_LIMITS: list[dict[str, object]] = [
    {"header_read_timeout_s": 0.5},
    {"header_read_timeout_s": 60.5},
    {"header_read_timeout_s": float("nan")},
    {"header_read_timeout_s": float("inf")},
    {"header_read_timeout_s": True},
    {"header_read_timeout_s": "10"},
    {"max_connections": 0},
    {"max_connections": True},
    {"max_connections": 3.0},
    {"max_connections": 63},
    {"max_header_bytes": 1023},
    {"max_header_bytes": 12289},
    {"max_header_bytes": True},
    {"max_header_count": 15},
    {"max_header_count": 257},
    {"max_header_count": True},
    {"max_page": 0},
    {"cors_origins": ("*",)},
]
BOUNDARY_LIMITS: list[dict[str, object]] = [
    {"header_read_timeout_s": 1.0},
    {"header_read_timeout_s": 60.0},
    {"max_connections": 64},
    {"max_header_bytes": 1024},
    {"max_header_bytes": 12288},
    {"max_header_count": 16},
    {"max_header_count": 256},
]


@pytest.mark.parametrize("fields", INVALID_LIMITS, ids=repr)
def test_uvicorn_config_refuses_limits_that_create_app_refuses(fields: dict[str, object]) -> None:
    limits = GatewayLimits(**fields)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"^INVALID_(LIMITS|CORS_ORIGIN)$") as refused:
        create_app(Relay(), limits=limits)
    app = create_app(Relay())

    with pytest.raises(ValueError, match=r"^INVALID_(LIMITS|CORS_ORIGIN)$") as also_refused:
        gateway_server.uvicorn_config(app, limits=limits, host="127.0.0.1", port=0)

    assert str(also_refused.value) == str(refused.value)


@pytest.mark.parametrize("fields", BOUNDARY_LIMITS, ids=repr)
def test_uvicorn_config_accepts_boundary_limits(fields: dict[str, object]) -> None:
    limits = GatewayLimits(**fields)  # type: ignore[arg-type]
    app = create_app(Relay(), limits=limits)

    config = gateway_server.uvicorn_config(app, limits=limits, host="127.0.0.1", port=0)

    assert issubclass(config.http, H11Protocol)
