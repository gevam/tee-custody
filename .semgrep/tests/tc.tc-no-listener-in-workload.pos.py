# Positive fixture: the workload opens no inbound listener (NFR-2).
import asyncio
import socket
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
import multiprocessing.connection
# ruleid: tc-py-banned-import, tc-py-banned-import-wire
from multiprocessing.connection import Listener as L
from socket import create_server as cs

sock = socket.socket()
# ruleid: tc-no-listener-in-workload
sock.bind(("0.0.0.0", 8080))
# ruleid: tc-no-listener-in-workload
sock.listen(5)
# ruleid: tc-no-listener-in-workload
socket.create_server(("0.0.0.0", 1))
# ruleid: tc-no-listener-in-workload
cs(("0.0.0.0", 1))
# ruleid: tc-no-listener-in-workload
multiprocessing.connection.Listener(("0.0.0.0", 1))
# ruleid: tc-no-listener-in-workload
L(("0.0.0.0", 1))


async def serve(handler, factory):
    # ruleid: tc-no-listener-in-workload
    await asyncio.start_server(handler, port=1)
    # ruleid: tc-no-listener-in-workload
    await asyncio.start_unix_server(handler, path="/run/s")
    loop = asyncio.get_running_loop()
    # ruleid: tc-no-listener-in-workload
    await loop.create_server(factory, port=1)
    # ruleid: tc-no-listener-in-workload
    await loop.create_unix_server(factory, path="/run/s")
