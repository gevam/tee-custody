# Positive fixture: banned modules in every import form (SR-3, NFR-2, NFR-6).
# ruleid: tc-py-banned-import
import cbor2
# ruleid: tc-py-banned-import
import cbor2 as c
# ruleid: tc-py-banned-import
from cbor2 import loads
# ruleid: tc-py-banned-import
import http.server
# ruleid: tc-py-banned-import
import http.server as hs
# ruleid: tc-py-banned-import
from http import server
# ruleid: tc-py-banned-import
from http.server import HTTPServer
# ruleid: tc-py-banned-import
import socketserver
# ruleid: tc-py-banned-import
from socketserver import TCPServer as T
# ruleid: tc-py-banned-import
import wsgiref.simple_server
# ruleid: tc-py-banned-import
from wsgiref import simple_server
# ruleid: tc-py-banned-import
from xmlrpc.server import SimpleXMLRPCServer
# ruleid: tc-py-banned-import
import xmlrpc.server
# ruleid: tc-py-banned-import
import multiprocessing.connection
# ruleid: tc-py-banned-import
from multiprocessing.connection import Listener
# ruleid: tc-py-banned-import
from multiprocessing import connection
# ruleid: tc-py-banned-import
from multiprocessing.managers import BaseManager
# ruleid: tc-py-banned-import
import os, socketserver as ss
# ruleid: tc-py-banned-import, tc-no-sim-import-in-library
import teecustody_sim.constants
# ruleid: tc-py-banned-import, tc-no-sim-import-in-library
from teecustody_sim.constants import SIM_ISSUER
