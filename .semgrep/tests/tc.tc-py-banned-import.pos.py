# Positive fixture: banned modules in every import form (SR-3, NFR-2, NFR-6).
# ruleid: tc-py-banned-import, tc-py-banned-import-sim
import cbor2
# ruleid: tc-py-banned-import, tc-py-banned-import-sim
import cbor2 as c
# ruleid: tc-py-banned-import, tc-py-banned-import-sim
from cbor2 import loads
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import http.server
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import http.server as hs
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from http import server
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from http.server import HTTPServer
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import socketserver
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from socketserver import TCPServer as T
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import wsgiref.simple_server
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from wsgiref import simple_server
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from xmlrpc.server import SimpleXMLRPCServer
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import xmlrpc.server
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import multiprocessing.connection
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from multiprocessing.connection import Listener
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from multiprocessing import connection
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from multiprocessing.managers import BaseManager
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import os, socketserver as ss
# ruleid: tc-py-banned-import, tc-py-banned-import-wire, tc-no-sim-import-in-library
import teecustody_sim.constants
# ruleid: tc-py-banned-import, tc-py-banned-import-wire, tc-no-sim-import-in-library
from teecustody_sim.constants import SIM_ISSUER
