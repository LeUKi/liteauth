# Contributing

Thank you for considering a contribution to LiteAuth.

## Development Setup

Requirements:

- Node.js 22 or newer
- pnpm 10.8.1
- Wrangler for Workers/D1 development

Install and run:

```sh
pnpm install
cp apps/api/.dev.vars.example apps/api/.dev.vars
pnpm db:migrate:local
pnpm dev
```

Fill `.dev.vars` with local development secrets only. Never commit secrets, local Wrangler config, tokens, or exported production data.

## Checks

Run the relevant checks before opening a pull request:

```sh
pnpm typecheck
pnpm lint
pnpm test
pnpm build
pnpm check
pnpm test:e2e
pnpm audit
```

Use `pnpm check` as the normal full local gate. `pnpm test:e2e` may require browser dependencies. `pnpm audit` should be reviewed for dependency risk.

## Documentation Rules

Public docs must not include:

- real Cloudflare account IDs, database IDs, route zones, deployment version IDs, or secret names with values;
- local absolute paths;
- private evidence archive links;
- callback URLs containing authorization codes;
- cookies, bearer tokens, client secrets, or encryption keys;
- real user account details, except `lafish` as the author/maintainer name.

Keep product contracts and validation boundaries honest. Do not claim NewAPI compatibility, backup recovery, key rotation, rollback safety, or real account rename testing unless that exact workflow has been performed.

## Pull Requests

Prefer small, reviewable changes. Include:

- what changed,
- why it changed,
- how it was tested,
- any security or migration impact.

The root `package.json` has `"private": true` to prevent accidental npm publishing. It does not mean the repository is private or that contributions cannot be accepted.

## License

By contributing, you agree that your contribution is licensed under the MIT License for LiteAuth-owned code.
