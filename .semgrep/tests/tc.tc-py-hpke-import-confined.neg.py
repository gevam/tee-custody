# Negative fixture: neighbouring names and the teecustody HPKE facade are not pyhpke imports.
import pyhpkex
# ruleid: tc-py-gateway-banned-import
from teecustody.channel import hpke
# ruleid: tc-py-gateway-banned-import
from teecustody.channel.hpke import open_base

NAMES = (pyhpkex, hpke, open_base, "pyhpke")
