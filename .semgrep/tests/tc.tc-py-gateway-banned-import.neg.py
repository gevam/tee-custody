# Negative fixture: near names and prose are not banned imports.
import cbor2x
import teecustody
from teecustody.queue.ports import RelayQueue
from mypkg import cbor2
x = "import cbor2"
# The gateway never imports teecustody_sim outside dev.py.
