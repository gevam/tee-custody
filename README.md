# tee-custody

An attested, forward-secret channel into a Google Cloud Confidential Space workload, plus split-key custody of per-user data. Neither the operator nor the user alone can read the data; only the attested workload, with both of them, can.

Two libraries and a simulator:

| Package | Language | Runs | Purpose |
|---|---|---|---|
| `teecustody` | Python | inside the TEE container | attestation, channel, custody, recovery; your handlers plug in |
| `@teecustody/core` | TypeScript | anywhere | attestation verification, HPKE channel, custody client |
| `@teecustody/web` | TypeScript | browser | WebAuthn-PRF share vault, fetch transport, trust-profile build tool |
| `teecustody-sim` | Python | dev machines and CI | simulated launcher and attestation issuer, local backends |

## Quick start (simulator)

```bash
# backend: write a handler
pip install teecustody
```

```python
from teecustody import Workload, Config, SessionContext

app = Workload(Config.from_env())

@app.operation("notes.put")
def put_note(ctx: SessionContext, payload):
    ctx.records.put(payload["id"], payload["body"].encode())
    return {"ok": True}

app.run()
```

```bash
# run it under the simulator
pip install teecustody-sim
teecustody-sim up --image my-workload:dev --audience https://example.test/tee
teecustody-sim profile --out dev-profile.json
```

```bash
# frontend
npm i @teecustody/core @teecustody/web
npx teecustody-profile dev-profile.json --out src/trust-profile.ts
```

```ts
import { TeeClient } from "@teecustody/core";
import { PrfShareVault, FetchTransport, WebCrypto } from "@teecustody/web";
import { trustProfile } from "./trust-profile";

const client = new TeeClient({
  trustProfile,
  transport: new FetchTransport("http://localhost:8080"),
  vault: new PrfShareVault(),
  crypto: WebCrypto,
});
const { clientId } = await client.enroll();
const session = await client.openSession();
await session.request("notes.put", { id: "1", body: "hello" });
await session.close();
```

## Going to production

1. Build your workload image reproducibly and sign it with your signer keys (spec §12).
2. Put its digest and your signer public keys in `trust-profile.json` (production profile), generate the module, and run `teecustody-profile check` on the shipped bundle.
3. Create the Cloud KMS key and the Workload Identity Pool condition that admits only your digest (spec §7.3).
4. Deploy with `Config.from_env()` pointing at the GCP backends.

`examples/notes-app` does all of this end to end.

## Security

The design is specified in `docs/security/tee-security-architecture.md`. It is normative for this repo; see `docs/security/README.md`. The simulator is not a TEE and provides no protection; its tokens can never verify against a production trust profile.

## Status

Pre-release. See `PROJECT.md` for scope and milestones.
