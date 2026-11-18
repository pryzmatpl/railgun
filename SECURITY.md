# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes |

RailGun is pre-1.0. The `0.1.x` line receives security fixes. There is no
long-term-support branch yet.

## Reporting a vulnerability

**Do not open a public issue, and do not post the details in a discussion.**

Use the repository's private security-advisory channel
("Report a vulnerability" on the repository's Security tab). If that channel
is unavailable, open a public issue that contains **only** a one-line summary
and a request for a private contact channel — no technical detail.

Please include:

- the affected version,
- what an attacker can achieve,
- the steps to reproduce,
- any known workaround.

We aim to acknowledge a report within 72 hours and to publish a fix or a
mitigation plan within 14 days. We will credit the reporter in the release
notes unless you prefer otherwise.

## Secret handling policy

RailGun treats a leaked credential as a deployment incident, not a code
defect.

### How secrets reach RailGun

Secrets enter through exactly two channels:

1. **An environment variable** — for example `RAILGUN_OUTBOUND_RELAY_PASSWORD`.
2. **A mounted file** — the `*_FILE` indirection, for example
   `RAILGUN_OUTBOUND_RELAY_PASSWORD_FILE=/run/secrets/relay_password`.

A secret is **never** stored in the configuration file, and never written to
the configuration object that is logged, serialised for `doctor --json`, or
written into the audit chain. The resolved configuration holds a *reference*
— the variable name or the file path, plus a presence flag — not the value.

### The quote/whitespace hazard

A credential that arrives wrapped in quotes (`"hunter2"`) or with leading or
trailing whitespace is **rejected at startup** rather than used. This is a
deliberate safeguard: a shell quoting mistake produces a credential that
fails SMTP authentication with an opaque `535`, which is very hard to
diagnose from the server log. When the secret is rejected, the error names
the **variable** and never the value.

### Rules for operators

- Never commit a `.env` file, a key file or a credential into the repository.
- Mount secrets read-only, and prefer the `*_FILE` indirection over an inline
  variable.
- Rotate a credential immediately if it appears in a log, an issue, a chat
  message or a commit.
- If a secret reaches a commit, rotating it is the fix. Removing the commit
  from history alone is **not** sufficient.

### Rules for contributors

- Never print a secret value — not even in a test fixture, not even a
  placeholder that looks real. Use an obvious sentinel such as
  `test-sentinel-value`.
- Never commit a credential, a private key, a certificate, a `.env` file or
  a populated `data/` directory.
- The test suite scans the package tree for credential patterns and fails on a
  match.

## Transport security

- Outbound SMTP requires TLS 1.2 or newer with certificate verification. A
  configuration that disables verification while outbound TLS is required is
  rejected at startup.
- `tls.reject_unauthorized: false` is accepted only as an explicit operator
  decision, and `railgun doctor` reports it as a warning.

## Reporting a problem that is not a vulnerability

A crash, a wrong SMTP reply code or a configuration that will not load is a
**bug**, not a security issue. Open a normal issue. If you are unsure which
it is, report it privately and let the maintainers classify it.
