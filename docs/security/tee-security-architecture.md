# Security architecture: client–TEE channel and split-key data custody

**Status:** Normative. Draft 1.0 for implementation.
**Applies to:** the TEE workload (Python, Google Cloud Confidential Space), the web client (TypeScript), future mobile clients, the queue, the storage/KMS/IAM configuration, and the development simulator (§15).

---

## 0. How to read this document

- MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119. Every MUST is an acceptance criterion.
- This document defines the security properties and the cryptographic arrangement. It does not choose frameworks, storage engines or queue products except where security requires it.
- If a requirement here conflicts with convenience, performance or a library default, this document wins. Any deviation MUST be raised as an explicit design decision and approved before implementation. Never downgrade silently.
- Before implementing anything that touches Google Cloud Attestation, Confidential Space token claims, Cloud KMS, Workload Identity, or a cryptographic library, verify the details against the current official documentation and record the source and version you relied on. Claim names, endpoints and APIs change.
- Do not invent cryptography. Where this document names a standard (HPKE, HKDF, Shamir, Feldman VSS), use an audited library that implements it. Do not compose primitives by hand where a standard construction exists.

---

## 1. System context

| Component | Runs | Trust | Role |
|---|---|---|---|
| **TEE workload** | Python container in a Confidential Space VM | Trusted only after attestation | The only place plaintext data, SK, or any reconstructed share may exist |
| **Google Cloud Attestation** | Google-operated | Trust root for attestation | Issues the attestation token (OIDC JWT) for the workload |
| **Client** | Web app (TypeScript) now; iOS/Android later | Trusted for its own data only | Holds the client share; verifies attestation; wraps secrets to the TEE |
| **Queue** | Any message broker | Untrusted | Store-and-forward transport in both directions. Carries only public values and ciphertext |
| **Server storage** | Cloud storage / database | Untrusted | Holds encrypted records, KMS-wrapped server shares, sealed trustee shares, client directory |
| **Cloud KMS** | Google-operated | Trusted to enforce its access policy | Wraps server shares; unwraps only for the attested workload |
| **Trustees** | Other clients of the platform | Untrusted individually; trusted only below threshold k | Hold shares of a user's client share for recovery |
| **Web-app origin** | Server that delivers the client JavaScript | Untrusted for data; partially trusted for code delivery (§10) | Serves the client application |

**Topology constraint.** Nothing may open an inbound connection to the TEE. The TEE pulls requests from the queue and pushes responses to it. Clients never address the TEE directly.

---

## 2. Threat model

### Trusted
- The confidential-computing hardware (AMD SEV-SNP or Intel TDX) and the Google attestation service.
- The approved workload image, but only the specific digests on the allow-list, built reproducibly and signed by the required signers (§12).
- The client's own device and runtime, for that client's own data.

### Untrusted (assume compromised)
- Host OS, hypervisor, cloud control plane.
- Everyone with credentials on the project: DevOps, SREs, DBAs, IAM admins. Assume they can read all server storage, all queue traffic, all logs, and hold the server share of every client.
- The queue, the network, server storage.
- Other clients, including trustees, up to any coalition of k−1.

### Security goals
- **G1.** Plaintext records and SK for a client exist only inside an attested TEE instance, only while that client's session is open.
- **G2.** An adversary with full control of the server side (storage, queue, IAM, logs, KMS administration) but not of an approved image cannot decrypt any client's data.
- **G3.** A client cannot decrypt its own data without the TEE and the server share.
- **G4.** Recording queue traffic and later compromising any long-lived key does not reveal past session contents (forward secrecy).
- **G5.** Compromise of one client's secrets affects only that client's data.
- **G6.** Recovery of a lost client share is possible without weakening G1–G3.

### Non-goals (out of scope for this document)
- Availability. The operator can always deny service.
- Micro-architectural side channels inside the TEE.
- Compromise of a client's own device. It exposes that client's data only.
- The policy that triggers recovery. The client defines it. This document specifies only what happens once it has been triggered.
- Application-layer authentication and authorization of clients. Assume every request carries an authenticated `client_id`; a separate specification covers how.

---

## 3. Invariants

Each invariant MUST hold at all times and MUST map to at least one automated test or review-checklist item (§13).

| # | Invariant |
|---|---|
| I1 | SK, DEKs, plaintext records, the client share and any reconstructed share exist only in TEE process memory. They are never written to disk, logs, environment, crash dumps, metrics or error messages, and never leave the TEE except as ciphertext. |
| I2 | SK is per client. No key material is shared between clients. |
| I3 | SK is never stored. It is reconstructed from shares inside the TEE at session start and destroyed at session end. |
| I4 | The server share is stored only wrapped by a Cloud KMS key whose decrypt permission is granted exclusively to the attested workload identity (§7.3). No human principal, CI identity or service-account key has decrypt on that key. |
| I5 | The client share is sent only to an attested TEE, only after the client has verified the attestation token per §6, and only sealed under HPKE to a pre-key bound to that token. |
| I6 | Every private key used for the channel is generated by the party that uses it, held in memory only, and destroyed on the schedule in §4. Pre-keys are single-use. |
| I7 | Queue messages contain only attestation tokens, public keys, identifiers, ciphertext and AEAD associated data. Anything else in a queue message is a defect. |
| I8 | Recovery reconstructs the **client share**, never SK, and reconstruction happens only inside the TEE with the owner's participation. |
| I9 | Parties under operator control MUST hold fewer than k trustee shares for any user. The client enforces this by verifying trustee identities out of band (§8.2). |
| I10 | Every share carries `key_id`, `epoch` and an integrity value. Shares from different epochs are never combined. A share that fails its integrity check is rejected and reported. |
| I11 | After any recovery the client share is re-issued under a new epoch. SK itself is rotated if compromise is suspected. |
| I12 | Only images whose digest is on the allow-list and which carry the required signatures can obtain the server share. Changing the allow-list or the signer set is a security event that goes through the approval flow in §12. |
| I13 | No build of any component contains a switch that skips or relaxes a check in §6. Development against a non-TEE uses the simulator with a different trust profile (§15), never a weaker code path. |

---

## 4. Key inventory

All symmetric keys are 256-bit. Key agreement is X25519. Signatures are Ed25519. Hashing is SHA-256. AEAD is AES-256-GCM with 96-bit nonces that are never reused under the same key.

| Key | Type | Created by | Lives in | Lifetime | Destroyed when |
|---|---|---|---|---|---|
| **IK** (identity key) | Ed25519 keypair | TEE, at boot | TEE memory | Instance lifetime | Instance shutdown. Never persisted, never shared between instances |
| **PK_i** (pre-keys) | X25519 keypairs, signed by IK | TEE, in batches | TEE memory | Until used or `PREKEY_TTL` | Immediately after one `Open`, successful or not, or at expiry. Single-use |
| **EK** (client ephemeral KEM key) | X25519 keypair, internal to HPKE | Client, per `Seal` | Client memory | One `Seal` | Immediately after `Seal`; the HPKE context is kept only until session keys are exported (§5.5) |
| **sk_c2t, sk_t2c** (session keys) | AES-256-GCM, exported from the HPKE context | Both sides, from the same exporter secret | Memory on both sides | One session | Session end, `IDLE_TIMEOUT`, or instance shutdown |
| **SK** (client data key) | AES-256 | TEE, at enrolment | TEE memory only | Per session | Session end. Rotated per §7.5 |
| **cs** (client share) | 32 random bytes | TEE, at enrolment and on re-issue | Client device, protected per §10; TEE memory during a session | Until re-issued under a new epoch | TEE: session end. Client: on re-issue |
| **ss** (server share) | 32 random bytes | TEE, at enrolment and on re-split | Server storage, KMS-wrapped; TEE memory during a session | Until re-split | TEE: session end. Storage: superseded epochs deleted once the new epoch is confirmed |
| **DEK** (data encryption keys) | AES-256-GCM, one per record or record group | TEE | Server storage, wrapped under SK; TEE memory while in use | Long-lived | Unwrapped copies dropped at session end; rotated with the record |
| **IB** (inbox key) | X25519 keypair, one per client | TEE, at enrolment | Private half in server storage, wrapped under the client's SK; public half in the client directory with a fingerprint | Until rotated | Rotated on recovery (§8.4) |
| **ts_j** (trustee shares of cs) | Feldman VSS shares | TEE, during the owner's session | Server storage, HPKE-sealed to trustee j's IB_pub | Until the owner re-splits | On re-split; on owner-initiated removal |
| **RIB** (recovery inbox key) | X25519 keypair | Owner's new client, at recovery start | Owner's new device only | One recovery | When recovery completes or is cancelled |
| **KMS key** | Cloud KMS symmetric key, HSM-backed | Infrastructure as code | Cloud KMS | Long-lived, rotated by policy | Per KMS rotation policy |

---

## 5. Protocol A: channel establishment and session traffic

Notation: `H()` is SHA-256. `Sig_IK()` is an Ed25519 signature under IK. `HPKE.Seal`, `HPKE.Open` and `Context.Export` are as defined in RFC 9180 with ciphersuite DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM in **Base mode**. Serialized structures use canonical CBOR (or JSON with sorted keys, no whitespace; pick one and use it everywhere).

### 5.1 TEE boot
1. Generate IK. Generate the first batch of `PREKEY_BATCH` pre-keys.
2. Request an attestation token from the Confidential Space launcher (Unix socket) with audience `AUDIENCE` and a custom nonce equal to `H(IK_pub)` in the encoding the launcher requires. The client MUST use the same encoding when comparing. The default token file, which carries no custom nonce, MUST NOT be used for this purpose.
3. Publish a **pre-key bundle** to the bundle topic:
   ```
   {
     instance_id, token, IK_pub, published_at,
     prekeys: [
       { id, pub, not_after,
         sig: Sig_IK(H("prekey-v1" || instance_id || id || pub || not_after || image_digest)) },
       ...
     ]
   }
   ```
   `image_digest` is the workload's own digest as reported in the token, so a pre-key can never be re-attached to a different token.
4. Refresh: publish a new bundle with a freshly requested token (same nonce, same IK) whenever the token approaches expiry or unused pre-keys fall below `PREKEY_LOW_WATER`. Consumed and expired pre-keys are removed from the bundle and their private halves destroyed.

### 5.2 Client fetch and verify
5. Fetch current bundles. For each: verify the token per §6; verify `H(IK_pub)` equals the token nonce; verify every pre-key signature under IK_pub; verify `not_after` is in the future and `image_digest` in the signed data matches the token. Discard bundles that fail. If none pass, stop and surface a fatal error. Never fall back to an unverified bundle.
6. Select one unused pre-key `PK_i` from a verified bundle and remember `instance_id` and IK_pub for the session.

### 5.3 Client: open session
7. Build the payload `pt = { op: "open_session", cs, key_id, epoch }` (or `{ op: "enroll" }` for a new client, §7.4).
8. Build `aad = { proto: "tee-chan-v1", client_id, instance_id, prekey_id, request_id, timestamp }`. `request_id` is 16 random bytes.
9. `(enc, ct) = HPKE.Seal(PK_i_pub, info = "tee-chan-v1" || H(IK_pub) || prekey_id, aad, pt)`.
10. From the same HPKE context, export `sk_c2t = Export("c2t", 32)` and `sk_t2c = Export("t2c", 32)`. Then destroy EK and the context. Destroy `cs` from working memory (it remains in the share vault, §10).
11. Post `{ aad, enc, ct }` to the request topic, partitioned by `instance_id`.

### 5.4 TEE: open session
12. Pull the message. Reject if: `instance_id` is not this instance; `prekey_id` is unknown or already consumed; `timestamp` is outside `REQUEST_SKEW`; `request_id` was seen before (replay cache per `client_id`, retained for `REQUEST_SKEW`).
13. `pt = HPKE.Open(PK_i_priv, enc, info, aad, ct)`. Export `sk_c2t` and `sk_t2c` from the context.
14. Destroy `PK_i_priv` and the HPKE context immediately, whether or not `Open` succeeded. On failure: log the failure without any payload detail and stop.
15. Perform the operation (§7.4). Create `session_id`. Build the response `rpt`.
16. Encrypt the response: `ct_r = AES-GCM(sk_t2c, nonce = seq_t2c, aad_r = { session_id, request_id, seq_t2c }, rpt)`. Post `{ aad_r, ct_r }` to the response topic for `client_id`.

Response authenticity follows from the session key: only the holder of `PK_i_priv`, which the client verified belongs to the attested instance, can derive `sk_t2c`. No separate signature is needed.

### 5.5 Session traffic
17. All further requests in the session use `sk_c2t`, and all responses use `sk_t2c`, with AES-256-GCM, a 96-bit nonce formed from a per-direction monotonically increasing 64-bit counter (`seq`), and `aad = { session_id, seq, op }`. A receiver MUST reject any `seq` it has already accepted or that goes backwards.
18. The session ends on explicit `close`, on `IDLE_TIMEOUT`, or on instance shutdown. At session end both sides destroy the session keys; the TEE also destroys SK, `cs`, `ss` and every unwrapped DEK for that client.

### 5.6 Multi-instance and failure rules
- A request sealed to instance A's pre-key can only be opened by instance A. If A is gone the request is lost; the client times out, fetches a fresh bundle and retries with a new `request_id`.
- Instances share no key material. Each has its own IK, token, pre-keys and sessions.
- All requests in a session go to the instance that opened it. If it disappears, the client opens a new session.

---

## 6. Attestation verification: client-side requirements

The client MUST perform every check below on every bundle before using any key from it. Failure of any single check is fatal for that bundle. The checks are one code path, parameterized by the trust profile compiled into the build (§15.4); the logic never varies between builds, only the trust anchors.

1. **Signature.** OIDC token type: verify against the JWKS at the `jwks_uri` obtained from `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration`, fetched over TLS from that exact origin. PKI token type: validate the `x5c` chain up to Google's published Confidential Space root and confirm the root matches a copy embedded in the client. Choose one token type (`TOKEN_TYPE`, §14) and implement only that path.
2. **Issuer.** `iss` equals `https://confidentialcomputing.googleapis.com`.
3. **Audience.** `aud` equals `AUDIENCE`.
4. **Time.** `exp` is in the future and `iat` is within `TOKEN_MAX_AGE` of the client's clock.
5. **Nonce.** `eat_nonce` contains exactly `H(IK_pub)` in the agreed encoding.
6. **Platform.** `hwmodel` is in `ALLOWED_HWMODELS`; `swname` equals `CONFIDENTIAL_SPACE`; `secboot` is true; `dbgstat` equals `disabled-since-boot`. Debug-mode tokens MUST be rejected in every build. Development without a real TEE is done with the simulator (§15), whose tokens carry production-shaped values here but are trusted only through the development profile.
7. **Support attributes.** `submods.confidential_space.support_attributes` contains `STABLE`.
8. **Image.** `submods.container.image_digest` is on the allow-list embedded in the client at build time, and `submods.container.image_signatures` contains valid signatures from at least `SIGNERS_REQUIRED` of the signer public keys embedded in the client. The client enforces this independently. "The server enforces it" is not an acceptable reason to skip it.
9. **Launch configuration.** `submods.container.args` and `submods.container.env` match the expected values or the expected hash. An image can be neutered by its launch arguments; the token exposes them so the client can check.

The claim paths above reflect the documentation at the time of writing. The implementer MUST confirm them against the current Confidential Space token-claims reference and record which version was consulted.

---

## 7. Data at rest: SK, envelope encryption, split custody

### 7.1 Per-client SK and envelope encryption
- Each client has its own SK. SK is a key-encryption key only. It wraps DEKs; DEKs encrypt records.
- Record encryption: AES-256-GCM under a DEK, random 96-bit nonce, `aad = { client_id, record_id, schema_version }`. The wrapped DEK, nonce and tag are stored with the record.
- DEK wrapping: AES-256-GCM under SK, random 96-bit nonce, `aad = { client_id, key_id, epoch, record_id }`.
- Rotating SK re-wraps DEKs; it never re-encrypts records.

### 7.2 Splitting SK
- At enrolment the TEE generates SK and splits it with Shamir secret sharing over a prime field, using `SPLIT_SCHEME` (§14): 2-of-2 by default. A 2-of-3 scheme MAY be enabled to give the owner an additional offline share; that share is treated as a second client share and protected under the same rules as `cs`. It never lives on the server.
- Share records: `{ client_id, key_id, epoch, index, value }`.
- Key-check value: `kcv = HMAC-SHA256(SK, "kcv-v1" || client_id || key_id || epoch)[0:16]`, stored next to `ss`. After every reconstruction the TEE MUST recompute `kcv` and compare in constant time before using SK. A mismatch aborts the session and raises a security alert. For the SK split, `kcv` is the integrity check required by I10.

### 7.3 Server share custody
- `ss` is stored encrypted under the Cloud KMS key with `aad = client_id || key_id || epoch`.
- The KMS key's decrypt permission is granted to exactly one principal: the Workload Identity Pool provider for Confidential Space, with an attribute condition of the following form (confirm exact syntax against current documentation):
  ```
  assertion.swname == "CONFIDENTIAL_SPACE" &&
  "STABLE" in assertion.submods.confidential_space.support_attributes &&
  assertion.dbgstat == "disabled-since-boot" &&
  assertion.submods.container.image_digest in ALLOWED_DIGESTS
  ```
  or an equivalent condition on `submods.container.image_signatures`.
- No human, CI identity or service-account key holds decrypt on this key. Key administration and key usage MUST be held by different principals. KMS audit logs MUST be enabled and exported to a sink that project administrators cannot modify.
- The workload obtains its Google credential through the launcher's attestation flow. It MUST NOT be given a long-lived service-account key.

### 7.4 Operations inside a session
- `enroll`: TEE generates SK, IB, splits SK into `cs` and `ss`, stores `ss` (KMS-wrapped), `kcv` and `IB_priv` (wrapped under SK), publishes `IB_pub` with its fingerprint to the client directory, and returns `cs`, `key_id`, `epoch` and the IB fingerprint in the response. The session is open with SK in memory.
- `open_session`: TEE fetches `ss` for `(client_id, key_id, epoch)`, decrypts via KMS, combines with `cs`, verifies `kcv`, and holds SK for the session.
- Data operations, `set_trustees`, `release_share`, `rotate` and `recover` run inside an open session and are specified in §8.

### 7.5 Rotation
- `rotate_share`: re-split SK into a new `cs`/`ss` under a new epoch, store the new `ss` and `kcv`, return the new `cs`. Delete the previous `ss` after the client acknowledges. Re-split `cs` to trustees under the new epoch (§8.1).
- `rotate_sk`: generate a new SK, re-wrap all DEKs, then perform `rotate_share`. Required after any suspected compromise. Both rotations are owner-initiated inside the owner's session.

---

## 8. Recovery: k-of-n over the client share

### 8.1 Layout (Option B)
```
SK = combine(cs, ss)                      2-of-2, always
cs = combine(any k of n trustee shares)   Feldman VSS, recovery only
```
Recovery rebuilds `cs`. It still requires `ss`, the TEE, and the owner's participation. There is no path to SK that avoids the TEE, and no path that the server side can walk alone.

`set_trustees` (in the owner's session): the owner supplies `trustee_ids`, `k`, `n`, and the IB fingerprint the owner verified for each trustee. The TEE:
1. Checks each supplied fingerprint against the directory's `IB_pub` for that trustee. Any mismatch aborts the whole operation.
2. Splits `cs` with Feldman VSS over the Ristretto255 group (`VSS_GROUP`, §14), producing shares `ts_j` and public commitments `C`.
3. Seals each `ts_j` to trustee j: `HPKE.Seal(IB_j_pub, info = "trustee-share-v1", aad = { owner_id, trustee_id, key_id, epoch, index }, ts_j)`.
4. Stores the sealed shares and `C` in server storage, tagged with `epoch`. Deletes sealed shares of any previous epoch.

Constraints: `k ≥ 2`, `n ≥ k + 1` (RECOMMENDED: 3-of-5). The owner SHOULD be warned when the number of reachable trustees drops to `k`.

### 8.2 Trustee identity verification
The operator controls account creation and the directory, so a fake or impersonated trustee is the primary threat to I9. The client MUST require the owner to verify each trustee's IB fingerprint out of band (safety-number comparison or QR scan between the two clients) before nominating them, and MUST send the verified fingerprint in `set_trustees` so the TEE can check it against the directory. The client MUST re-verify if a trustee's fingerprint changes.

### 8.3 Recovery flow
The trigger policy is defined by the owner and is out of scope. Once triggered, the flow is:

1. **Start.** The owner's new client generates RIB and opens a recovery session with the TEE via Protocol A: `{ op: "recover_start", owner_id, RIB_pub, trigger_evidence }`. The TEE records a pending recovery `{ owner_id, recovery_id, RIB_pub, epoch, started_at }` and notifies the trustees.
2. **Release.** Each trustee, inside their own session (so their SK and hence `IB_priv` are available), reviews the pending request and calls `release_share(recovery_id)`. The TEE opens `ts_j` with `IB_j_priv`, verifies it against the commitments `C`, and immediately re-seals it to `RIB_pub` with `aad = { recovery_id, index }`. The re-sealed share is stored server-side; the plaintext share is destroyed. A trustee share that fails verification is rejected and reported, and the owner is notified of which index failed.
3. **Complete.** When at least `k` re-sealed shares exist, the owner's new client sends `{ op: "recover_complete", recovery_id, RIB_priv }` via Protocol A. The TEE opens the shares, combines them to `cs`, fetches `ss`, reconstructs SK, and verifies `kcv`. It then immediately performs `rotate_share`, rotates IB, returns the new `cs`, `key_id`, `epoch` and IB fingerprint to the new client, deletes all recovery material, and marks the old epoch invalid. The owner MUST then re-run `set_trustees`.
4. **Cancel / expire.** A pending recovery expires after `RECOVERY_TTL` and can be cancelled by the owner's existing client at any time. Re-sealed shares are deleted on cancel or expiry.

Because every re-sealed share is encrypted to RIB, whose private half exists only on the owner's new device, a full set of released shares sitting in server storage is useless to the operator and to any TEE instance without the owner.

### 8.4 Trustee churn
- If a trustee deletes their account, loses their own key, or is removed by the owner, their share is dead. The owner's client MUST show the live trustee count and prompt for a re-split when it reaches `k`.
- Re-splitting is `set_trustees` under a new epoch. It requires an open owner session, so it is only possible while the owner still holds `cs`.

---

## 9. Queue requirements
- The queue is untrusted. It MUST NOT be able to break confidentiality, integrity, or freshness of any message; all three come from the cryptography, not from the broker.
- Topics: `bundles` (public, read by all clients), `requests/{instance_id}`, `responses/{client_id}`. Access control on the queue is defence in depth only.
- Every message is bound to its context through AEAD associated data as specified in §5. A message replayed, re-ordered, or moved between clients or instances MUST fail to open.
- Broker-side logging of message bodies MUST be disabled. Ciphertext is still sensitive metadata.
- Message retention SHOULD be short (≤ `REQUEST_SKEW` for requests). Bundles may be retained until their token expires.

---

## 10. Client requirements

### 10.1 Share vault
- `cs` is stored only through a `ShareVault` abstraction with implementations per platform:
  - **Web:** `cs` is AES-256-GCM-encrypted under a key derived (HKDF) from the WebAuthn PRF extension output of the user's passkey, and the ciphertext is stored in IndexedDB. If PRF is unavailable on the platform, enrolment MUST fail closed with a clear message rather than fall back to weaker storage.
  - **Mobile:** platform keystore (iOS Secure Enclave via CryptoKit; Android Keystore with StrongBox where available), user-presence-gated.
- `cs` MUST never appear in `localStorage`, cookies, URLs, analytics, crash reports, or any request to the web-app origin.

### 10.2 Cryptography
- HPKE via a maintained library (`@hpke/core` on web using WebCrypto X25519 where available). Ed25519 verification and SHA-256 via WebCrypto. Do not ship a hand-written X25519, HKDF or GCM.
- The attestation issuer, JWKS origin or pinned root, `AUDIENCE`, `TOKEN_TYPE`, allowed `hwmodel` values, digest allow-list, signer public keys and expected launch-configuration hashes together form the client's **trust profile** (§15.4). It is compiled into the client at build time and MUST NOT be fetched from the server at runtime.

### 10.3 Code delivery (web)
The web client's attestation checks run in JavaScript served by the web-app origin. A compromised origin can serve a client that skips checks or trusts a different digest. This is a limit of the web platform, not of the protocol, and the threat model MUST say so. Required mitigations:
- Reproducible build with a published hash of every shipped bundle.
- Subresource integrity on every script and a strict Content-Security-Policy (no inline scripts, no `eval`, `script-src` restricted to hashed or SRI-tagged resources).
- No third-party scripts on the pages that handle keys.
- Mobile apps, whose code is signed at install time, are the long-term answer for high-assurance clients.

### 10.4 Multi-device
A user's second device enrols as the same `client_id` by obtaining `cs` through the vault's platform sync (passkey sync) or, if that is not possible, through the recovery flow. `cs` MUST NOT be transferred device-to-device by any custom channel.

---

## 11. TEE workload requirements (Python)

- **Libraries:** HPKE via `pyhpke` or Tink; X25519, Ed25519, AES-GCM, HKDF, HMAC via `cryptography`; Shamir and Feldman VSS via an audited library over the chosen field and group. Pin versions. Verify each library's HPKE test vectors (RFC 9180 Appendix A) in the test suite.
- **Secret handling:** hold secrets in `bytearray`, zero them explicitly when done, and avoid string formatting, logging, `repr`, or exception messages that could capture them. Python cannot guarantee zeroisation; TEE memory encryption mitigates host access, but hygiene is still required. Constant-time comparison (`hmac.compare_digest`) for every tag, `kcv` and fingerprint check.
- **Attestation:** request tokens only through the launcher socket with the custom nonce (§5.1). Never accept a token from any other source. The workload has exactly one launcher client and no environment detection; in development the simulator provides the socket (§15.2), and the workload cannot tell the difference.
- **Pluggable custody backends:** the share-wrapping (§7.3) and queue (§9) integrations sit behind interfaces with a production implementation (Cloud KMS, the production broker) and a simulator implementation. Selection is by injected configuration at container start, not by code that inspects its environment.
- **Image hardening:** distroless or minimal base, non-root user, read-only root filesystem, no shell, no debugger, no SSH, no environment-variable secrets, no dynamic code loading. Egress allowed only to the attestation service, KMS, storage and the queue.
- **No inbound ports.** The container exposes nothing. Health signalling, if needed, goes through the queue.
- **Replay and freshness:** replay cache keyed by `(client_id, request_id)` bounded by `REQUEST_SKEW`; per-session `seq` tracking; pre-key consumption tracking.
- **Logging:** structured logs with an explicit allow-list of fields. Identifiers (`client_id`, `request_id`, `session_id`, `prekey_id`, `epoch`), timestamps and outcome codes are permitted. Payloads, keys, shares, nonces and ciphertext are not.
- **Concurrency:** sessions are keyed by `(client_id, instance_id)`. A second `open_session` for a client that already has a live session on this instance closes the old one first.

---

## 12. Image policy and operations
- The workload image MUST be built reproducibly. The build recipe and expected digest are published.
- Images MUST be signed by at least `SIGNERS_REQUIRED` independent signers whose keys are held outside the cloud project and outside the CI system. Confidential Space's multi-signer policy is used on the KMS/WIP side; the client embeds the same signer set.
- Rollout of a new image: (1) build, reproduce, sign; (2) add the digest to the WIP condition and ship a client release that includes the new digest; (3) deploy the image; (4) remove the old digest from both after `IMAGE_GRACE`. Removing an old digest is what actually revokes it.
- Every change to the digest allow-list, signer set, WIP condition or KMS IAM is a security event: it requires sign-off by two named owners, is logged to the protected audit sink, and is announced to clients.
- Alerting: any KMS decrypt attempt denied by the WIP condition, any `kcv` mismatch, any rejected trustee share, and any debug-mode token seen by a client MUST raise an alert.

---

## 13. Deliverables and acceptance tests

The implementation team MUST deliver, in addition to the code:

1. **Traceability matrix** mapping every invariant in §3 and every check in §6 to at least one test or review item.
2. **Negative tests for §6.** For each check, a test showing that a token failing only that check is rejected by the client: bad signature, wrong `iss`, wrong `aud`, expired, stale `iat`, wrong nonce, debug `dbgstat`, missing `STABLE`, digest not on the list, insufficient signatures, unexpected launch args.
3. **Protocol tests.** Pre-key reuse rejected; message replayed rejected; message moved between instances or clients rejected; `seq` reuse rejected; a modified `aad` rejected; forward-secrecy test that a captured transcript cannot be decrypted after pre-key and session-key destruction even given IK.
4. **Share tests.** `kcv` mismatch aborts; a corrupted trustee share fails Feldman verification and is identified by index; shares from different epochs cannot be combined; fewer than k shares cannot reconstruct; a fingerprint mismatch aborts `set_trustees`.
5. **Recovery tests.** Full recovery on a new device; recovery with one malicious trustee; cancel and expiry delete recovery material; completed recovery invalidates the old epoch and old trustee shares.
6. **Infrastructure tests.** A non-attested principal (including project owner) is denied KMS decrypt; a debug-mode workload is denied; KMS audit logs land in the protected sink.
7. **Hygiene review.** A checklist review of the Python workload for I1: grep-level and runtime checks that no secret reaches a log, exception, metric or disk.
8. **Threat model document** kept current with this specification, including the web-code-delivery limitation in §10.3.
9. **Simulator conformance.** A simulator token with default values passes every §6 check under the development profile. The same token fails the issuer and signature checks under the production profile. Every negative vector in item 2 is produced by the simulator's claim-alteration mode (§15.3), so the test suite and the simulator cannot drift apart.
10. **Build separation.** The production client bundle contains none of `SIM_ISSUER`, the simulator root or JWKS, or the development signer keys (CI greps the shipped bundle for the issuer string and the key fingerprints). The workload image contains no simulator-only code path.
11. **Environment split.** Items 2, 3, 4, 5 and 7 run against the simulator in CI on every change. Item 6, plus a smoke run of items 2 to 5, run against real Confidential Space on a schedule and before every release. A release MUST NOT ship on simulator results alone.

---

## 14. Parameters to confirm before implementation

| Parameter | Suggested default | Notes |
|---|---|---|
| `AUDIENCE` | project-specific URI | Must match between launcher request and client |
| `TOKEN_TYPE` | OIDC | PKI if clients must verify offline against a pinned root |
| `ALLOWED_HWMODELS` | `GCP_AMD_SEV`, `GCP_INTEL_TDX` | Confirm current values |
| `PREKEY_TTL` | 1 hour | Bounded by token lifetime |
| `PREKEY_BATCH` / `PREKEY_LOW_WATER` | 100 / 20 | Tune to load |
| `TOKEN_MAX_AGE` | 1 hour | |
| `REQUEST_SKEW` | 5 minutes | Also bounds replay-cache retention |
| `IDLE_TIMEOUT` | 15 minutes | Session end triggers destruction of SK |
| `SPLIT_SCHEME` | 2-of-2 | 2-of-3 adds an owner-held offline share |
| Trustee `k` / `n` | 3 / 5 | `k ≥ 2`, `n ≥ k+1` |
| `VSS_GROUP` | Ristretto255 | Any prime-order group with an audited Feldman implementation |
| `SIGNERS_REQUIRED` | 2 | Independent, off-project key holders |
| `RECOVERY_TTL` | 7 days | Pending recovery expiry |
| `IMAGE_GRACE` | 14 days | Before old digests are removed |
| Serialization | canonical CBOR | One format everywhere |
| `SIM_ISSUER` | `https://tee-sim.localhost` | Must differ from the Google issuer |
| `SIM_HWMODEL` | `SIMULATED` | Never in production `ALLOWED_HWMODELS` |
| `SIM_TOKEN_TTL` | same as the real token lifetime | Confirm the real value |

---

## 15. Development simulator

### 15.1 Purpose and limits
- The simulator lets the workload, the clients and the tests run end to end on a developer machine and in CI without Confidential Space. It reproduces the **interfaces** of Confidential Space: the launcher token socket, the attestation token format, the OpenID discovery and JWKS endpoints, and the image-signature claims.
- The simulator is not a TEE. It provides no confidentiality or integrity against the host. It MUST be impossible to mistake for production: its tokens never verify under the production trust profile, and production builds contain none of its trust anchors (§15.5).
- Everything that runs in the simulator MUST run unchanged in Confidential Space. The workload image used with the simulator is the same image, same entrypoint, same launcher client. If a feature needs simulator-specific code inside the workload, the design is wrong; fix the interface instead.

### 15.2 Components
1. **Simulated launcher.** A local process that mounts the same Unix socket path the real launcher exposes and implements the same token endpoint, with the same request schema (`audience`, `nonces`, `token_type`) and the same constraints on nonce count and length (confirm against current launcher documentation). It also writes the default token file at the same path. It runs the workload container with plain Docker or Podman.
2. **Simulated attestation issuer.** Signs tokens with a locally generated key using the same JOSE algorithm as the real service. For `TOKEN_TYPE = OIDC` it serves an OpenID discovery document and JWKS on a loopback origin. For `TOKEN_TYPE = PKI` it issues a self-signed root and an `x5c` chain from it. The signing key is generated fresh per developer environment and per CI job. It is never committed and never shared.
3. **Development signers.** `SIGNERS_REQUIRED` development image-signing keys. The simulator signs the local image digest with them and places the signatures in `submods.container.image_signatures`, so the client's signature check exercises its normal code path.
4. **Custody stand-in.** A simulator implementation of the share-wrapping interface (§7.3) that wraps `ss` under a local key. It enforces no attestation gating. The gating tests in §13.6 MUST run against real GCP; the simulator never stands in for them.
5. **Local queue.** A local broker or in-memory implementation of the three topics in §9, namespaced so a simulator workload cannot subscribe to or publish on production topics.

### 15.3 Token format
- The simulator token MUST carry every claim the client verifies (§6) with the same name, nesting and value type as the real token: `iss`, `aud`, `exp`, `iat`, `eat_nonce`, `hwmodel`, `swname`, `secboot`, `dbgstat`, `submods.confidential_space.support_attributes`, `submods.container.image_digest`, `submods.container.image_signatures`, `submods.container.args`, `submods.container.env`. All other claims of the real token (`sub`, `nbf`, `submods.gce.*`, `google_service_accounts`, and so on) are OPTIONAL and MAY be omitted or filled with placeholders.
- Default values are production-shaped so the same checks pass: `swname = CONFIDENTIAL_SPACE`, `secboot = true`, `dbgstat = disabled-since-boot`, `support_attributes` containing `STABLE`, `image_digest` equal to the actual digest of the local image, `args` and `env` equal to the actual launch configuration, `eat_nonce` echoing the nonce from the request, `exp` at `iat + SIM_TOKEN_TTL`.
- The values that identify the trust anchor are simulator-specific, so a simulator token can never pass as real: `iss = SIM_ISSUER`, `hwmodel = SIM_HWMODEL`, the token signing key, and the signer keys.
- The simulator MUST offer a claim-alteration mode that emits a token with any single claim changed or removed: expired, stale `iat`, wrong `aud`, wrong or missing nonce, `dbgstat = enabled`, missing `STABLE`, unknown digest, fewer than `SIGNERS_REQUIRED` signatures, a signature from an unknown signer, altered `args`, and a corrupted signature. This is the only source of negative vectors for §13.2.

### 15.4 Trust profiles
- The client's verification is a single code path parameterized by a **trust profile**: `{ issuer, jwks_origin | pinned_root, expected_audience, allowed_hwmodels, allowed_digests, signer_keys, signers_required, expected_args_hash, expected_env_hash }`.
- Exactly two profiles exist. **Production:** Google issuer, Google JWKS or root, production signer keys, production digests. **Development:** `SIM_ISSUER`, the simulator's loopback JWKS origin or root, development signer keys, local digests. The profile is selected at build time. There is no runtime switch and no flag that disables any check, in either profile.
- The workload has no profile. It talks to whichever launcher socket is mounted and uses whichever custody and queue backends are injected (§11).

### 15.5 Separation
- Production client builds MUST NOT contain the development profile, `SIM_ISSUER`, the simulator root or JWKS, or the development signer keys. The build MUST fail if any is present (§13.10).
- A simulator token MUST fail production-profile verification on at least two independent checks, issuer and signature, and this is a required test (§13.9).
- The simulator binds to loopback only. Binding elsewhere requires an explicit flag and prints a warning on every start.
- The simulator environment MUST NOT contain production credentials, production queue configuration or the production KMS key resource name.
- Data created under the simulator is test data. It MUST never be migrated to production: a simulator-wrapped `ss` was never protected.

### 15.6 Uses
- Local development of the workload and the clients, with the real end-to-end protocol.
- CI on every change: the protocol, share and recovery suites (§13.2 to §13.5) and the hygiene review (§13.7).
- Generating attestation test vectors, positive and negative, from one source.
- Demonstrating client behaviour on attestation failure without touching production.
