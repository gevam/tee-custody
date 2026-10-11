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
