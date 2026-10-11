# Positive fixture: project code never composes HKDF/HPKE from HMAC (ADR 0011 C2).
import hmac
import hmac as stdlib_hmac
from hmac import digest, new

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.hmac import HMAC

# ruleid: tc-py-no-kdf-composition
block = hmac.new(prk, info + bytes([1]), "sha256").digest()
# ruleid: tc-py-no-kdf-composition
block = hmac.digest(prk, info, "sha256")
# ruleid: tc-py-no-kdf-composition
mac = hmac.HMAC(prk, info, "sha256")
# ruleid: tc-py-no-kdf-composition
mac = stdlib_hmac.new(prk, info, "sha256")
# ruleid: tc-py-no-kdf-composition
block = digest(prk, info, "sha256")
# ruleid: tc-py-no-kdf-composition
mac = new(prk, info, "sha256")
# ruleid: tc-py-no-kdf-composition
mac = crypto_hmac.HMAC(prk, hashes.SHA256())
# ruleid: tc-py-no-kdf-composition
mac = HMAC(prk, hashes.SHA256())
