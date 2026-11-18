# RailGun

**The open Mailgun alternative.** A self-contained, self-hosted mail delivery service that
agents drive over MCP — with no external provider required.

<p align="center">
  <img src="./railgun-logo.jpg" alt="RailGun — a railgun firing email envelopes at full speed" width="760">
</p>

RailGun accepts email submissions from agents and services, applies authentication,
authorization, policy, rate limiting, spam prevention and audit, durably queues accepted
messages, and delivers them **straight to the recipient's mail servers**.

- **Self-contained** — one npm package plus Docker. No external provider, no SaaS relay, no
  account to sign up for.
- **Agent-first** — MCP is a first-class surface. Any harness that speaks MCP, HTTP, or plain
  SMTP can use it.
- **Direct by default** — RailGun resolves the recipient domain's MX records and talks to
  them itself. An operator relay is an explicit fallback, not the default path.
- **Explainable** — every rejection, deferral and suppression carries a stable reason code.
- **Enterprise-ready** — anti-spam, rate limiting, audit and observability ship in v1.
- **GPL-3.0-or-later** — free software, forever.

---

## Status

RailGun v0.1.0 is implemented and tested. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the canonical service contract and
[`docs/CONTRACT-IMPLEMENTATION-CHECKLIST.md`](docs/CONTRACT-IMPLEMENTATION-CHECKLIST.md)
for the requirement-by-requirement implementation status.

| Area | Status |
|---|---|
| Architecture & service contract | ✅ implemented |
| Package foundation & configuration | ✅ implemented |
| SMTP submission pipeline | ✅ implemented |
| Outbound delivery engine (direct-to-MX) | ✅ implemented |
| DKIM signing, SPF/DMARC policy, rate limiting | ✅ implemented |
| MCP surface (stdio + streamable HTTP) | ✅ implemented |
| HTTP API surface | ✅ implemented |
| Operator CLI & tooling | ✅ implemented |
| Durable persistence backend | ⚠️ in-memory store shipped; the store port is pluggable and a durable backend is the next milestone |

---

## Quick start

### 60 seconds, from a clone

```bash
git clone https://github.com/pryzmatpl/railgun.git
cd railgun
npm install
npm run build
npx railgun doctor
```

`railgun doctor` loads the configuration, validates it, and reports the state of every
subsystem. It prints one line per check and never prints a secret.

There is nothing else to configure. With no configuration file and no environment variable,
RailGun starts with a local SQLite store, a file-backed queue, and direct-to-MX outbound.

> **Building with `NODE_ENV=production`?** npm skips `devDependencies` in that mode, so the
> TypeScript compiler is not installed. Use `npm install --include=dev` before `npm run build`.

### Send from your own domain

RailGun talks straight to the recipient's mail servers, so **your** domain has to be
provably yours. One command produces the keypair and every DNS record to publish:

```bash
railgun dkim new --domain example.com --selector mail --ipv4 203.0.113.10
```

It writes the private key with mode `0600`, never prints it, and prints the MX, SPF, DKIM
and DMARC records with the real values filled in. Publish them in your DNS provider —
RailGun verifies DNS, it never changes it — then:

```bash
export RAILGUN_DKIM_ENABLED=true
export RAILGUN_DKIM_SELECTOR=mail
export RAILGUN_DKIM_PRIVATE_KEY_ENV=RAILGUN_DKIM_PRIVATE_KEY
export RAILGUN_DKIM_PRIVATE_KEY="$(cat secrets/dkim-mail.pem)"
export RAILGUN_SENDING_DOMAINS=example.com

railgun doctor
```

`railgun doctor` confirms each record is live and that the selector matches the signer.

> **Direct-to-MX needs outbound port 25.** Many ISPs block it. See
> [`docs/DNS-SETUP.md`](docs/DNS-SETUP.md) for the one-line check.

### With Docker

```bash
docker compose up --build
curl -s http://localhost:2526/ready
```

The image runs as a non-root user (uid 10001) and carries a shell-free `HEALTHCHECK`.

### Install from npm

```bash
npm install -g railgun
railgun doctor
```

---

## Send your first email

### Over HTTP

```bash
curl -X POST http://localhost:2526/v1/email/send \
  -H 'Authorization: Bearer <your-api-key>' \
  -H 'Content-Type: application/json' \
  -d '{
    "to": ["someone@example.com"],
    "subject": "Hello from RailGun",
    "text": "Delivered straight to the recipient MX.",
    "from": "hello@example.com"
  }'
```

The request schema is a strict superset of the Jaisiu `email_send` schema: `to`, `subject`,
`text`, `html`, `from`, `replyTo`, `cc`, `bcc` and `requestId`. An `Idempotency-Key` header
makes a retry safe — a replay returns the original result without sending twice.

### Over MCP

RailGun exposes the same operations as MCP tools — `email_send`, `email_status`,
`email_bounces` and `email_stats` — over stdio or streamable HTTP.

### Over SMTP

```
EHLO client.example
MAIL FROM:<hello@example.com>
RCPT TO:<someone@example.com>
DATA
Subject: Hello from RailGun

Delivered straight to the recipient MX.
.
```

Port 25 is never bound. The submission listener defaults to `0.0.0.0:2525`.

---

## Configuration

Configuration comes from three layers, in ascending priority:

1. **Shipped defaults** — a working, secure configuration with no file and no environment.
2. **A YAML file** — `--config <path>`, `RAILGUN_CONFIG`, or the default search order
   (`./railgun.yaml` → `./config/railgun.yaml` → `./config/railgun.example.yaml`).
3. **The environment overlay** — `RAILGUN_*` variables. Always wins.

```yaml
# railgun.yaml
outbound:
  mode: direct          # direct-to-MX (default); "relay" is the explicit fallback
  direct:
    mx_lookup: true
    require_tls: true

dkim:
  enabled: true
  selector: mail
  private_key_env: RAILGUN_DKIM_PRIVATE_KEY
```

```bash
export RAILGUN_OUTBOUND_MODE=direct
export RAILGUN_DKIM_PRIVATE_KEY_FILE=/run/secrets/dkim.pem
```

RailGun **fails closed**: an invalid configuration stops the process before any listener
binds. It never silently degrades to a default, because that would turn a typo into a
disabled control.

The full reference — every section, every key, its type, its default and its environment
variable — is in [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

### Secrets

Never put a secret in the configuration file. Secrets reach RailGun through an environment
variable or a mounted file:

```bash
export RAILGUN_OUTBOUND_RELAY_PASSWORD='…'                 # inline
export RAILGUN_OUTBOUND_RELAY_PASSWORD_FILE=/run/secrets/pw # preferred: mounted file
```

A resolved configuration holds a *reference* — the variable name or file path, plus a
presence flag — never the value. A credential that arrives quote-wrapped or with stray
whitespace is **rejected by name** rather than used, because a silently wrong credential
produces an opaque `535` at authentication time.

---

## Security posture

- Outbound SMTP requires **TLS 1.2+** with certificate verification.
- **DKIM signing** for outbound mail, with a configurable selector and key file.
- **SPF-aligned From** enforcement and **DMARC-aware** policy.
- **Rate limiting** per tenant and per recipient, with warmup limits for new recipients.
- **Suppression lists** and hard-bounce handling, so a bad address is not mailed twice.
- **Append-only, tamper-evident audit chain** (hash-chained NDJSON). Recipient addresses
  are hashed with a rotating salt by default.
- **No open relay.** Only authorised domains may submit.
- **Telemetry is off** and stays off unless an operator explicitly enables it.
- Bodies are encrypted at rest by default.

Report a vulnerability privately — see [`SECURITY.md`](SECURITY.md).

---

## Documentation

| Document | What it covers |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The canonical service contract |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Every configuration key and its environment variable |
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure and secret-handling policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Development setup and the house rules |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Community expectations |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |

---

## Licence

RailGun is free software, released under the **GNU General Public License v3.0 or later**.
The full text is in [`LICENSE`](LICENSE); every source file carries an SPDX header.
