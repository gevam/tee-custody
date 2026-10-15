# Negative fixture: static imports, and local functions that merely share an importer's name.
import json

# ruleid: tc-py-gateway-banned-import
from teecustody.wire import cbor


def import_module(name):
    return name


import_module("teecustody.wire")
loaded = json.loads("{}")
encoder = cbor


class Settings:
    debug = False


# ruleid: tc-py-hpke-module-confined
fields = vars(Settings())
codes = {"ok": 0}
