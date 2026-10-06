"""Reference queue gateway for the notes-app example (INC-2-API §6): an untrusted HTTP relay."""

from notes_gateway.app import create_app
from notes_gateway.limits import GatewayLimits

__all__ = ["GatewayLimits", "create_app"]
