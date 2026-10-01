# Negative fixture: outbound connections and unrelated method names are fine.
import socket

conn = socket.create_connection(("pubsub.googleapis.com", 443))
conn.connect(("pubsub.googleapis.com", 443))
conn.sendall(b"x")
binding = "bind"
listener_count = 0
