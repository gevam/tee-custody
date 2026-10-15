# Positive fixture: no dynamic import in teecustody or teecustody-sim source (NFR-2, NFR-6, SR-3).
import builtins
import importlib
import importlib as il
import importlib.util
import runpy
from importlib import import_module as im
from importlib.util import spec_from_file_location
from runpy import run_path

# ruleid: tc-py-no-dynamic-import
importlib.import_module("http.server")
# ruleid: tc-py-no-dynamic-import
__import__("cbor2")
# ruleid: tc-py-no-dynamic-import
im("socketserver")
# ruleid: tc-py-no-dynamic-import
il.import_module("wsgiref.simple_server")
# ruleid: tc-py-no-dynamic-import, tc-py-hpke-module-confined
importlib.__import__("cbor2")
# ruleid: tc-py-no-dynamic-import
importlib.util.spec_from_file_location("x", "/srv/x.py")
# ruleid: tc-py-no-dynamic-import
spec_from_file_location("x", "/srv/x.py")
# ruleid: tc-py-no-dynamic-import
runpy.run_module("http.server")
# ruleid: tc-py-no-dynamic-import
run_path("/srv/x.py")
# ruleid: tc-py-no-dynamic-import, tc-py-hpke-module-confined
builtins.__import__("cbor2")
# ruleid: tc-py-no-dynamic-import
loader = __import__
# ruleid: tc-py-no-dynamic-import, tc-py-hpke-module-confined
getattr(il, "import_module")("socketserver")
# ruleid: tc-py-no-dynamic-import
exec("import socketserver")
# ruleid: tc-py-no-dynamic-import
eval("1")

import code
import pkgutil
import zipimport

# ruleid: tc-py-no-dynamic-import
vars(builtins)["__import__"]("cbor2")
# ruleid: tc-py-no-dynamic-import
__builtins__["__import__"]("cbor2")
# ruleid: tc-py-no-dynamic-import, tc-py-hpke-module-confined
__builtins__.__import__("cbor2")
# ruleid: tc-py-no-dynamic-import, tc-py-hpke-module-confined
builtins.__dict__["__import__"]("cbor2")
# ruleid: tc-py-no-dynamic-import
pkgutil.resolve_name("http.server:HTTPServer")
# ruleid: tc-py-no-dynamic-import
importlib.util.find_spec("socketserver").loader
# ruleid: tc-py-no-dynamic-import
code.InteractiveInterpreter().runsource("import socketserver")
# ruleid: tc-py-no-dynamic-import
code.InteractiveConsole().push("import socketserver")
# ruleid: tc-py-no-dynamic-import
code.interact()
# ruleid: tc-py-no-dynamic-import
zipimport.zipimporter("/srv/x.zip")
