# Negative fixture: dev.py may import the simulator lazily.
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
from teecustody_sim.queue import InMemoryQueue
import cbor2x


def main() -> None:
    # ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
    from teecustody_sim import cli
