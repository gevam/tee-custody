# Negative fixture: default verification and explicit CA bundles are fine.
import ssl

import httpx

httpx.get("https://example.test")
httpx.get("https://example.test", verify="/etc/ssl/ca.pem")
context = ssl.create_default_context()
context.verify_mode = ssl.CERT_REQUIRED
