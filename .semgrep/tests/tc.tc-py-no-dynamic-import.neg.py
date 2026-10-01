# Negative fixture: static imports, and local functions that merely share an importer's name.
import json

from teecustody.wire import cbor


def import_module(name):
    return name


import_module("teecustody.wire")
loaded = json.loads("{}")
encoder = cbor


class Settings:
    debug = False


fields = vars(Settings())
codes = {"ok": 0}
