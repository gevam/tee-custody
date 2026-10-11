# Negative fixture: neighbouring names and the teecustody HPKE facade are not pyhpke imports.
import pyhpkex
from teecustody.channel import hpke
from teecustody.channel.hpke import open_base

NAMES = (pyhpkex, hpke, open_base, "pyhpke")
