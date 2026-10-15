# Negative fixture: what channel/hpke.py does today.
recipient_key = _SUITE.kem.deserialize_private_key(b)
context = _SUITE.create_recipient_context(enc, recipient_key, info)
secret = context.export(label, 32)
plaintext = context.open(ct, aad=aad)
_PRIVATE_KEY_LENGTH = 32


class HpkeError(Exception):
    def __init__(self, code: object) -> None:
        super().__init__(code)
