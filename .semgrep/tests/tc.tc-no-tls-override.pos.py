# Positive fixture: TLS verification is never disabled (SR-5).
import ssl

import httpx

# ruleid: tc-no-tls-override, tc-no-tls-override-cli
httpx.get("https://example.test", verify=False)
# ruleid: tc-no-tls-override, tc-py-hpke-module-confined, tc-no-tls-override-cli
context = ssl._create_unverified_context()
# ruleid: tc-no-tls-override, tc-no-tls-override-cli
context.verify_mode = ssl.CERT_NONE
# ruleid: tc-no-tls-override, tc-no-tls-override-cli
context.check_hostname = False
