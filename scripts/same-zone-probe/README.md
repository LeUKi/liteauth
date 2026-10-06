# Same-zone probe

Temporary protected Worker used to prove LiteAuth API access from another Worker in the same Cloudflare zone.

## Worker interface

Deploy `worker.js` with these vars:

- `TARGET_ORIGIN`: `https://staging.example.com` or `https://app.example.com`
- `PROBE_TOKEN`: random secret, at least 24 characters; upload as a Worker Secret, never a plaintext configuration variable
- `PROBE_EXPIRES_AT`: Unix seconds; the Worker refuses calls after this time

Call only `POST .../run` with header `X-Probe-Token: <PROBE_TOKEN>`.

The Worker has no LiteAuth Service Binding and no arbitrary URL proxy. It only fetches fixed LiteAuth paths under `TARGET_ORIGIN`, follows redirects manually, and returns sanitized status-level evidence.

Suggested temporary same-zone routes:

- `https://staging.example.com/__routing-proof-<id>/private/run`
- `https://staging.example.com/__routing-proof-<id>/public/run`

Use one caller Worker with `global_fetch_private_origin` and one with `global_fetch_strictly_public`.

## Runner

Create a protected credential file:

```json
{"probe_token":"replace-with-random-probe-token"}
```

The file must be owned by the current user and mode `0600`.

Baseline check, useful before the Web Worker forwarding fix:

```sh
node scripts/same-zone-probe/runner.mjs \
  --env staging \
  --probe-url 'https://staging.example.com/__routing-proof-<id>/private/run' \
  --credentials-file .secrets/same-zone-probe.json \
  --mode baseline \
  --allow-failures
```

Protocol proof after the fix:

```sh
node scripts/same-zone-probe/runner.mjs \
  --env staging \
  --probe-url 'https://staging.example.com/__routing-proof-<id>/private/run' \
  --credentials-file .secrets/same-zone-probe.json \
  --mode protocol
```

`protocol` mode creates a scoped synthetic Lite session through remote D1 SQL, asks the probe Worker to create a temporary app through the real API, completes authorization-code exchange and UserInfo checks, verifies bad and replayed codes are rejected, then deletes only rows tied to the synthetic user.

It also checks Lite-only admission and a raised trust-level requirement. An independent, unreplayed token remains usable after the policy change; the provider can revoke tokens derived from a deliberately replayed code. This probe checks ID Token presence, not full JWT verification or real upstream Connect authentication.

The Worker has a 45-second execution budget; the runner waits up to 90 seconds. A timeout or cleanup failure produces a nonzero exit and recovery identifiers, never a successful cleanup claim. Remote SQL files contain synthetic credentials while seeding, are mode `0600`, and are replaced with scoped cleanup SQL before deletion. Wrangler file imports return aggregate execution summaries; a separate read-only query verifies cleanup. Delete both temporary Workers, their routes and probe secrets after verification. They are not permanent infrastructure.
