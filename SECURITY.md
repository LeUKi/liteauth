# Security Policy

## Reporting a Vulnerability

Please use GitHub private vulnerability reporting for this repository once it is enabled:

<https://github.com/LeUKi/liteauth/security/advisories/new>

Private vulnerability reporting has not been confirmed enabled in this snapshot. If the link is unavailable, contact the maintainer through a private channel and do not publish exploit details in a public issue.

## What to Include

Please include:

- affected commit or release,
- affected route or component,
- impact,
- reproduction steps,
- whether credentials or special roles are required,
- any suggested fix.

Do not include real secrets, access tokens, cookies, private keys, production database exports, or personal data in the report.

## Scope

In scope:

- authentication and session handling,
- OAuth/OIDC authorization, token, UserInfo, introspection, and revocation behavior,
- access control for applications, secrets, admin routes, and audit records,
- CSRF, XSS, SSRF, open redirect, credential leakage, privacy leakage, and denial of service,
- deployment documentation that could cause secret exposure.

Out of scope:

- social engineering,
- denial-of-service testing against public infrastructure without prior approval,
- findings that require control of a user's browser or device without another vulnerability,
- dependency advisories already fixed upstream but not yet reachable in LiteAuth.

## Supported Versions

The public repository is the source of truth. Security fixes are made against the default branch unless a release branch is explicitly announced.
