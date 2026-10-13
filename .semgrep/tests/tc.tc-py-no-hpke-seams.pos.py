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
