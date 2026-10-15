# Positive fixture: teecustody never imports the simulator (NFR-6).
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
import teecustody_sim
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
import teecustody_sim.constants as sim_constants
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
from teecustody_sim import SIM_ISSUER
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
from teecustody_sim.constants import SIM_ISSUER as ISSUER
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire, tc-py-gateway-banned-import
import os, teecustody_sim as sim
