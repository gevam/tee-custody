"""T-28 criteria 1-8, 10, 13: the open path of `ChannelServer` (INC-2-API §4.8, §4.10; R-4, R-5)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from support_server import (
    CLIENT_ID,
    INSTANCE_ID,
    read_open_result,
)
from support_server import make_world as _make_world

ALLOWED_LOG_FIELDS = {"client_id", "session_id", "prekey_id", "request_id"}


# ---------------------------------------------------------------- criterion 1
def test_valid_open_session_opens_a_session_and_answers_on_the_aad_route() -> None:
    world = _make_world()
    sent = world.open_session()

    result = world.process(sent.body)

    assert str(result.outcome) == "SESSION_OPENED"
    assert result.response is not None
    assert result.response.client_id == CLIENT_ID
    view = read_open_result(result.response.body, sent.t2c)
    assert view.kind == "open_result"
    assert view.body == {"ok": True, "payload": {"hello": 1}}
    assert view.request_id == sent.aad["request_id"]
    assert view.session_id is not None
    session = world.sessions.get(view.session_id)
    assert session is not None
    assert session.client_id == CLIENT_ID
    request = world.opener.requests[0]
    assert request.claimed_client_id == CLIENT_ID
    assert request.instance_id == INSTANCE_ID
    assert request.session_id == view.session_id
    assert world.logger.calls == [
        (
            "info",
            "SESSION_OPENED",
            {
                "client_id": CLIENT_ID,
                "session_id": view.session_id.hex(),
                "prekey_id": sent.aad["prekey_id"],
                "request_id": sent.aad["request_id"].hex(),
            },
        )
    ]
    assert set(world.logger.calls[0][2]) <= ALLOWED_LOG_FIELDS
    assert not world.audit.counts
