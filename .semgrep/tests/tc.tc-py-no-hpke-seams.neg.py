# Negative fixture: Base mode without seams; the names as data or locals are not arguments.
enc, sender = suite.create_sender_context(pkr, info=b"teecustody")
recipient = suite.create_recipient_context(enc, skr, info=b"teecustody")
eks = None
FORBIDDEN_KEYWORDS = {"eks": 1, "psk": 2, "psk_id": 3, "pks": 4, "sks": 5}
opened = open_base(enc, ciphertext, eks, info=b"x")
enc, sender = suite.create_sender_context(pk, info)
enc, sender = suite.create_sender_context(pk, info=b"x")
recipient = suite.create_recipient_context(enc, sk, info)
recipient = suite.create_recipient_context(enc, sk, info=info)
