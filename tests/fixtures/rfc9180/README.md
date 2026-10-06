# RFC 9180 (HPKE) CFRG test vectors

`test-vectors.json` is the CFRG HPKE test-vector file, committed byte for byte. It is never
modified and never fetched at test time (ADR 0011 C4).

| Field             | Value                                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Source repository | https://github.com/cfrg/draft-irtf-cfrg-hpke                                                                                   |
| Fixed commit      | `5f503c564da00b0687b3de75f1dfbdfc4079ad31` (the commit RFC 9180 cites as [TestVectors])                                        |
| Source URL        | https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json         |
| File SHA-256      | `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`                                                             |
| Git blob SHA-1    | `514dd8bbcc4339f99ad9cf527007523f94668582`                                                                                     |
| Size              | 5892257 bytes                                                                                                                  |
| Retrieved         | 2026-10-06                                                                                                                     |
| Licence           | IETF Contribution under BCP 78/79 and the IETF Trust Legal Provisions (code components: BSD licence); see repo CONTRIBUTING.md |

The file is unchanged from the fixed commit to the repository head at retrieval
(`b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb`).

Check: `sha256sum tests/fixtures/rfc9180/test-vectors.json` must print the SHA-256 above.

The file contains published test keys only (no secrets). The gitleaks allow-list for this path is
owned by T-05.
