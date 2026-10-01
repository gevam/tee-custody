# Negative fixture: verification vocabulary without a skip switch.
def verify_token(token, profile):
    return token


verification_result = verify_token("t", {})
NOT_VERIFIED = "NOT_VERIFIED"
