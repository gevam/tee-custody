# Positive fixture: no verification-skip switch in any build (NFR-5, I13).
# ruleid: tc-no-verification-skip
skip_verify = True


# ruleid: tc-no-verification-skip
def verify(token, disableVerification=False):
    return token


# ruleid: tc-no-verification-skip
INSECURE_MODE = False
