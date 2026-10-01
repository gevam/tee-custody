# Positive fixture: the workload never reads the launcher's default token file (spec §6.1).
# ruleid: tc-no-default-token-file
TOKEN_PATH = "/run/container_launcher/attestation_verifier_claims_token"
# ruleid: tc-no-default-token-file
NAME = "attestation_verifier_claims_token"
