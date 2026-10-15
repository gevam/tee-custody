# Positive fixture: signing happens only in channel/identity.py and channel/prekeys.py (SR-14).
# ruleid: tc-py-identity-sign-confined
signature = identity.sign(bundle_bytes)
# ruleid: tc-py-identity-sign-confined, tc-py-hpke-module-confined
signature = self._identity.sign(b"any message")
# ruleid: tc-py-identity-sign-confined
signature = private_key.sign(payload)
# ruleid: tc-py-identity-sign-confined
signature = make_key().sign(
    payload,
)
