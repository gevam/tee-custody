# Positive fixture: dev.py never imports cbor2 (SR-3).
# ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
import cbor2
# ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
from cbor2 import dumps


def main() -> None:
    # ruleid: tc-py-banned-import, tc-py-banned-import-sim, tc-py-gateway-banned-import, tc-py-gateway-dev-banned-import
    import os, cbor2
