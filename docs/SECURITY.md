# RailGun Security

The canonical service contract — including the full security model — is
[`ARCHITECTURE.md`](ARCHITECTURE.md) §5 (authentication & authorization), §6 (rate limiting &
quotas), §7 (spam prevention), §8 (auditing), and §14 (controlled delivery testing).

This document is the operator-facing summary and the disclosure policy.

---

## Security model in brief

### Authentication

| Surface | Mechanism |
|---|---|
| SMTP submission | `AUTH PLAIN` / `AUTH LOGIN` against an Argon2id hash or opaque API token |
| HTTP API | `Authorization: Bearer …` or `X-Api-Key`, looked up by hash |
| MCP tools | Same principal/tenant model as the HTTP API |
| Enterprise | Optional mTLS client certificate, mapped by fingerprint |
| Local | Unix socket or loopback-only listener; **default deny**; still subject to policy and quotas |

### Authorization

Four roles — `admin`, `operator`, `sender`, `auditor` — with the sender allow-list, recipient
domain policy, and tenant isolation enforced at the transaction level. Unauthorized recipients
are rejected **at `RCPT TO`**, not silently dropped.

**Fail closed.** A missing, malformed, expired, or revoked credential produces an error that
does not reveal whether the account exists.

### Secret handling

**The single rule that matters:** a secret must never appear in source, fixtures, configuration
examples, logs, metric labels, error messages, audit payloads, HTTP responses, or MCP outputs.

- Secrets enter **only** via environment variables, Docker secrets, mounted files, or a
  secret-provider port.
- Secrets are **never** written to `config/railgun.example.yaml` or any committed file.
- Redaction at the logging boundary is defense-in-depth — never a substitute for not logging
  the value.
- `railgun doctor` reports configuration **names** and redacted **presence**, never values.
- **Quote-wrapped and whitespace-wrapped credential values are rejected at startup.** A quoted
  `.env` value becomes a literal quote and causes SMTP `535` authentication failures; RailGun
  fails fast instead of retrying against the upstream relay with a malformed password.

### Auditing

Append-only, tamper-evident, hash-chained NDJSON. Recipient addresses are stored as **salted
hashes with a rotating salt**, not in the clear. Every record carries a correlation ID, so an
agent action, an HTTP request, an SMTP transaction, a queue row, and an outbound attempt are
traceable end to end.

### Rate limiting and abuse control

Two layers: protocol/edge limits (per connection) and tenant quotas (sliding window). New
recipients are limited far more tightly than established ones, and rate-limit state is shared
across replicas rather than held per-process.

---

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Report privately to the maintainers. Include:

- what you found, and which version/commit is affected;
- how to reproduce it;
- the impact you believe it has.

We will acknowledge the report, and we will credit you in the fix unless you ask us not to.

---

## What is *not* a vulnerability

These are expected behaviours, not bugs:

- RailGun reports SMTP **acceptance** (`accepted`) without a DSN. `delivered` requires a
  confirmation. This is deliberate and matches the semantics of the surrounding ecosystem.
- A rejected or quarantined message exposes only a **rule ID and reason class**, never the
  content that triggered it.
- The audit trail stores salted recipient hashes, not raw addresses. That is the design.
- RailGun does not accept inbound mail on port 25 by default. Enabling it is an explicit
  operator decision.

---

## Handling a leaked credential

If a secret is ever observed in output — a log line, a CI transcript, a ticket, a chat message:

1. **Stop.**
2. **Rotate** the credential at the provider.
3. **Remove** the exposure — the log, the artifact, the commit.
4. **Revoke** anything derived from it (API keys, tokens).
5. Then continue.

Never echo, slice, or print a credential — including partial prefixes — to check whether it is
set. Print a boolean, or nothing at all.
