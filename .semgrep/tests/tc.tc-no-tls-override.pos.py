# Positive fixture: TLS verification is never disabled (SR-5).
import ssl

import httpx

# ruleid: tc-no-tls-override
httpx.get("https://example.test", verify=False)
# ruleid: tc-no-tls-override
context = ssl._create_unverified_context()
# ruleid: tc-no-tls-override
context.verify_mode = ssl.CERT_NONE
# ruleid: tc-no-tls-override
context.check_hostname = False
