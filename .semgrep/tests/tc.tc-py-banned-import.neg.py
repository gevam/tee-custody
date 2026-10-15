# Negative fixture: neighbouring modules that are not banned.
import http.client
import multiprocessing
import xmlrpc.client
from http import HTTPStatus
from multiprocessing import Pool

# ruleid: tc-py-gateway-banned-import
from teecustody.wire import cbor

STATUS = HTTPStatus.OK
POOL = Pool
CLIENTS = (http.client, xmlrpc.client, multiprocessing, cbor)
