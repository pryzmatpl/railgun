# Contributing to RailGun

RailGun is the open Mailgun alternative: a self-hosted, agent-first email
delivery service that talks **directly to recipient MX servers** by default,
with MCP, HTTP and SMTP submission surfaces.

Thank you for considering a contribution. This document covers the development
setup and the house rules.

## Development setup

RailGun is a **standalone npm package**. It does not depend on the Jaisiu
monorepo, on pnpm, or on a workspace root. You need Node.js **22.12 or
newer**.

```bash
git clone https://github.com/pryzmatpl/railgun.git
cd railgun
npm install
npm run build
npm test
```

That is the whole setup. There is no `pnpm install`, no workspace protocol and
no root `tsconfig.json` to wire up.

### Everyday commands

| Command | What it does |
|---|---|
| `npm run build` | Compile TypeScript into `dist/` |
| `npm run check` | Type-check without emitting |
| `npm test` | Run the Vitest suite |
| `npm run test:watch` | Run the suite in watch mode |
| `npm run lint:licence` | Verify the SPDX headers and the licence files |

## House rules

### 1. Every source file carries the licence header

Every file under `src/`, `test/`, `tests/` and `scripts/` must begin with:

```ts
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors
```

YAML files use `#` for the same two lines. `npm run lint:licence` enforces
this, and the test suite asserts it too.

### 2. No import may leave this package

RailGun is standalone by design. A source file may not import anything
outside `packages/railgun` — no `@jaisiu/*` specifier, no `../../..` escape,
no path that reaches the monorepo root. If you need a capability that lives
outside, copy it in under an appropriate licence and record its provenance in
`NOTICE`.

### 3. Secrets never enter the source tree

- Never commit a credential, a token, a private key or a `.env` file.
- Secrets reach RailGun through an environment variable or a mounted file
  (the `*_FILE` indirection).
- A secret value must never appear in a log line, an error message, a
  `doctor` report, a JSON projection or the audit chain. Report the *name* and
  the *presence*, never the value.
- A credential that arrives wrapped in quotes, or with leading or trailing
  whitespace, must be **rejected** rather than used. A silently wrong
  credential produces an opaque `535` at authentication time.

### 4. Fail closed

An invalid configuration must stop the process before any listener binds.
Silently degrading to a default is a bug: it turns a typo into a disabled
control.

### 5. Tests accompany behaviour

A behaviour change ships with a test in the same commit. A source change and
its test are one commit, not two.

## Commit convention

```
<type>(<scope>): <what changed and why>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `build`, `chore`, `perf`.
Scopes: `config`, `smtp`, `mcp`, `http`, `outbound`, `signer`, `spam`,
`persistence`, `cli`, `foundation`.

## Proposing a change

1. Open an issue describing the problem and the intended behaviour. A design
   question is better discussed before it is implemented.
2. For anything that changes a protocol surface (SMTP replies, HTTP status
   codes, MCP tool schemas, CLI exit codes), describe the compatibility
   impact explicitly. These surfaces are contracts.
3. Keep one concern per pull request. Unrelated refactors make a change hard
   to review and hard to revert.

## Reporting a security issue

Do **not** open a public issue. Follow the disclosure process in
[SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Licence

By contributing you agree that your contribution is licensed under the
GNU General Public License v3.0 or later, the same licence as the rest of
RailGun.
