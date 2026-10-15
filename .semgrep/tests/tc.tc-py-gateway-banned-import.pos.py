# Positive fixture: gateway src relays opaque bytes (no cbor2) and imports the simulator only in
# dev.py (SR-3, NFR-6).
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
import teecustody_sim
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
from teecustody_sim.queue import InMemoryQueue
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
import teecustody_sim.launcher as launcher
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
import os, teecustody_sim
# ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
import cbor2
# ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
from cbor2 import loads
# ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
import cbor2 as cbor
# ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
import json as j, cbor2.types


def handler() -> None:
    # ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
    import cbor2
    # ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
    from teecustody_sim import cli
