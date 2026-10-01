# Positive fixture: the workload opens no inbound listener (NFR-2).
import asyncio
import socket

sock = socket.socket()
# ruleid: tc-no-listener-in-workload
sock.bind(("0.0.0.0", 8080))
# ruleid: tc-no-listener-in-workload
sock.listen(5)


async def serve(handler):
    # ruleid: tc-no-listener-in-workload
    await asyncio.start_server(handler, port=1)
    # ruleid: tc-no-listener-in-workload
    await asyncio.start_unix_server(handler, path="/tmp/s")
