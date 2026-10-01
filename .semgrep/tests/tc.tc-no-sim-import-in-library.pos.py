# Positive fixture: teecustody never imports the simulator (NFR-6).
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire
import teecustody_sim
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire
import teecustody_sim.constants as sim_constants
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire
from teecustody_sim import SIM_ISSUER
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire
from teecustody_sim.constants import SIM_ISSUER as ISSUER
# ruleid: tc-no-sim-import-in-library, tc-py-banned-import, tc-py-banned-import-wire
import os, teecustody_sim as sim
