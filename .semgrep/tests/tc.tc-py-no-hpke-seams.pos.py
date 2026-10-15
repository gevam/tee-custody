# Positive fixture: no sender-key injection, PSK or auth-mode argument in production (ADR 0011 C5).
# ruleid: tc-py-no-hpke-seams
enc, sender = suite.create_sender_context(pkr, eks=fixed_ephemeral)
# ruleid: tc-py-no-hpke-seams
recipient = suite.create_recipient_context(enc, skr, psk=b"k" * 32, psk_id=b"id")
# ruleid: tc-py-no-hpke-seams
recipient = suite.create_recipient_context(enc, skr, psk_id=b"id")
# ruleid: tc-py-no-hpke-seams
recipient = suite.create_recipient_context(enc, skr, pks=sender_public)
# ruleid: tc-py-no-hpke-seams
enc, sender = suite.create_sender_context(pkr, sks=sender_private)
# ruleid: tc-py-no-hpke-seams
opened = open_base(
    enc,
    ciphertext,
    eks=fixed_ephemeral,
)
# A3: pyhpke also takes psk, psk_id, sks, pks and eks positionally or through a ** splat.
# ruleid: tc-py-no-hpke-seams
enc, sender = suite.create_sender_context(pk, b"", b"psk", b"id")
# ruleid: tc-py-no-hpke-seams
enc, sender = suite.create_sender_context(pk, b"info", b"psk")
# ruleid: tc-py-no-hpke-seams
enc, sender = suite.create_sender_context(pk, **{"pks": p})
# ruleid: tc-py-no-hpke-seams
recipient = suite.create_recipient_context(enc, sk, b"", b"psk")
# ruleid: tc-py-no-hpke-seams
recipient = suite.create_recipient_context(enc, sk, info, **opts)
# ruleid: tc-py-no-hpke-seams
recipient = suite.create_recipient_context(enc, sk, **opts)
# A4: a * splat can carry the positional seams.
# ruleid: tc-py-no-hpke-seams
enc, sender = suite.create_sender_context(*args)
# ruleid: tc-py-no-hpke-seams
recipient = suite.create_recipient_context(enc, *rest)
# A4/A6: low-level KEM access bypasses Base mode; only kem.deserialize_private_key(...) is allowed.
# ruleid: tc-py-no-hpke-seams
shared = suite.kem.decap(enc, skr, pks)
# ruleid: tc-py-no-hpke-seams
k = SUITE.kem
# ruleid: tc-py-no-hpke-seams
shared = _SUITE.kem.decap(enc, skr, pks)
# ruleid: tc-py-no-hpke-seams
k = _SUITE.kem
# ruleid: tc-py-no-hpke-seams
decap = getattr(_SUITE.kem, "decap")
# ruleid: tc-py-no-hpke-seams
y = _SUITE.kem.deserialize_private_key
# ruleid: tc-py-no-hpke-seams
key = _SUITE.kem.deserialize_private_key(_SUITE.kem.decap(enc, skr, pks))
