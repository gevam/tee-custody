# Positive fixture: channel/hpke.py, the only pyhpke importer, reaches pyhpke only by plain,
# called public names (A7, SR Low 6; ADR 0011 C5).
import operator

# ruleid: tc-py-hpke-module-confined
shared = getattr(_SUITE, "kem").decap(enc, skr)
# ruleid: tc-py-hpke-module-confined
shared = _SUITE._kem.decap(enc, skr)
# ruleid: tc-py-hpke-module-confined
kem_of = operator.attrgetter("kem")
# ruleid: tc-py-hpke-module-confined
decap_of = operator.methodcaller("decap", enc, skr)
# ruleid: tc-py-hpke-module-confined
f = _SUITE.create_recipient_context
# ruleid: tc-py-hpke-module-confined
g = _SUITE.create_sender_context
# ruleid: tc-py-hpke-module-confined
wrapped = _SUITE.wrap(_SUITE.create_recipient_context)
# ruleid: tc-py-hpke-module-confined
private = context.__dict__
# ruleid: tc-py-hpke-module-confined
super().__init__(context._kem)
# ruleid: tc-py-hpke-module-confined
base = super().__class__
