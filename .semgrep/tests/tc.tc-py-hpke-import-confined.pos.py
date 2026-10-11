# Positive fixture: pyhpke is imported only by teecustody/channel/hpke.py (SR-14, INC-2-API §9.5).
# ruleid: tc-py-hpke-import-confined
import pyhpke
# ruleid: tc-py-hpke-import-confined
import pyhpke as hpke
# ruleid: tc-py-hpke-import-confined
import pyhpke.kem
# ruleid: tc-py-hpke-import-confined
import os, pyhpke
# ruleid: tc-py-hpke-import-confined
from pyhpke import CipherSuite, KEMId
# ruleid: tc-py-hpke-import-confined
from pyhpke.kem import KEM
# ruleid: tc-py-hpke-import-confined
from pyhpke import (
    AEADId,
)

SUITES = (pyhpke, hpke, os, CipherSuite, KEMId, KEM, AEADId)
