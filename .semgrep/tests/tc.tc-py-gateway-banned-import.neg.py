# Negative fixture: near names and prose are not banned imports.
import cbor2x
# ruleid: tc-py-gateway-banned-import
import teecustody
from teecustody.queue.ports import RelayQueue
from mypkg import cbor2
x = "import cbor2"
# The gateway never imports teecustody_sim outside dev.py.
from teecustody.queue import ports
from teecustody.queue.ports import RelayQueue as Queue
from teecustody.obs import logger
import teecustody.obs
import teecustody_simple
