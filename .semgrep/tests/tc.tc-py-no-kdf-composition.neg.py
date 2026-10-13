# Negative fixture: constant-time comparison and the library HKDF are allowed.
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SAME = hmac.compare_digest(b"a", b"a")
KDF = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"teecustody")
