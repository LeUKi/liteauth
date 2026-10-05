# Implementation Plan

This document keeps the public implementation plan without private deployment evidence, local machine paths, Cloudflare resource identifiers, or real user account details.

## Architecture

LiteAuth is split into three workspaces:

- `apps/api`: Cloudflare Worker API, auth facade, OAuth/OIDC provider, D1 schema, policy enforcement, audit, cleanup jobs.
- `apps/web`: React management UI served by a Cloudflare Worker with static assets.
- `packages/contracts`: shared Zod schemas and TypeScript contracts.

The API is the security boundary. The web app improves workflow ergonomics but does not make authorization decisions.

## Core Contracts

- Linux.do numeric ID is the stable account key. Username is display and lookup help only.
- Each session is tied to an `auth_event`; authorization claims use the event snapshot, not the current mutable profile.
- Lite self-app credentials can be hosted only after a successful upstream authentication proves the returned identity.
- Public downstream clients must use PKCE.
- Confidential downstream client secrets are hashed for provider validation and encrypted separately only for owner re-display.
- Upstream Connect secrets are encrypted for use by the service and are never re-displayed.
- Tightening application policy cancels incompatible pending work; already issued self-contained claims keep their original event snapshot until expiry.
- Revocation boundaries differ for local sessions, online UserInfo/introspection, access tokens, and already-consumed downstream sessions.

## Work Areas

1. API route hardening
   - Keep CSRF/origin protection before state-changing browser routes.
   - Keep protocol routes cookie-free when forwarding to the provider.
   - Keep request body limits before any full body read.

2. OAuth/OIDC provider behavior
   - Keep dynamic client registration disabled.
   - Keep resource indicators unsupported unless a full resource model is added.
   - Keep metadata aligned with exposed endpoints and supported auth methods.

3. Connect flow
   - Bind upstream transactions to browser state.
   - Check credential version, owner, app policy, disabled state, and request expiry before completing a session.
   - Keep audit actor identity separate from target identity when a callback proves a different account.

4. Management UI
   - Treat all data as server-provided text; do not use unsafe DOM sinks.
   - Do not persist secrets to localStorage, sessionStorage, URLs, or durable client caches.
   - Keep owner-only secret viewing and rotation server-enforced.

5. Deployment
   - Keep public Wrangler config free of real Cloudflare resources.
   - Keep environment config and secrets local or in Cloudflare.
   - Reuse the validated staging web artifact for production.

## Deferred Work

- NewAPI integration remains deferred.
- Automated key rotation for encrypted stored secrets is not implemented.
- Backup restore and rollback drills must be validated before being represented as proven recovery capability.
- Manual account rename testing can be exempted for a release only when explicitly accepted by the maintainer; automated rename and stable-ID regression coverage still remains required.
