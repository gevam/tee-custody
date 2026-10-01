# Positive fixture: teecustody never imports the simulator (NFR-6).
# ruleid: tc-no-sim-import-in-library
import teecustody_sim
# ruleid: tc-no-sim-import-in-library
import teecustody_sim.constants as sim_constants
# ruleid: tc-no-sim-import-in-library
from teecustody_sim import SIM_ISSUER
# ruleid: tc-no-sim-import-in-library
from teecustody_sim.constants import SIM_ISSUER as ISSUER
# ruleid: tc-no-sim-import-in-library
import os, teecustody_sim as sim
