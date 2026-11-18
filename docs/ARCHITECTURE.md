# RailGun — Architecture & Service Contract

**Status:** canonical architecture specification (semantic — no implementation code in this document)
**License:** GPL-3.0-only
**Ticket:** JAISIU-4915
**Upstream IR:** `docs/design/railgun-architecture-ir.md` (unit `0fec1139`)
**Design artifact:** design unit `59f61b60` (12-section UI/UX + API design)

> RailGun — the open Mailgun alternative. A self-contained, Rust + Dockerized mail
> delivery service that agents drive over MCP, with no external provider required.

This document is the **canonical contract** for the RailGun service. It defines *what* the
service is and *what it guarantees*, so that the implementation units (SMTP pipeline,
persistence, anti-spam, MCP/HTTP surfaces, operator tooling) all bind to one authoritative
description instead of each guessing.

It is deliberately **implementation-independent**. Where a behaviour is already fixed by a
more granular IR, this document **references** that IR rather than restating it.

---

## 0. Document map

| § | Section | Defines |
|---|---|---|
| 1 | [Purpose & boundaries](#1-purpose--boundaries) | What RailGun is; what it must not duplicate |
| 2 | [Canonical locations](#2-canonical-locations) | Package and service locations; the non-duplication boundary |
| 3 | [Service contract](#3-service-contract) | The three public surfaces and their vocabulary |
| 4 | [Message model & persistence](#4-message-model--persistence) | Durable record, ports, retention, restart safety |
| 5 | [Authentication & authorization](#5-authentication--authorization) | Principals, mechanisms, RBAC, secret handling |
| 6 | [Rate limiting & quotas](#6-rate-limiting--quotas) | Two layers, burst protection, shared state |
| 7 | [Spam prevention](#7-spam-prevention) | Layered controls, explainability, blocklists |
| 8 | [Auditing](#8-auditing) | Append-only, tamper-evident, PII-minimized |
| 9 | [Observability](#9-observability) | Logs, metrics, health, CLI |
| 10 | [Operator workflows](#10-operator-workflows) | The 10 operator procedures |
| 11 | [Integration with existing harnesses](#11-integration-with-existing-harnesses) | Jaisiu, other harnesses, the Go backend |
| 12 | [Deployment model](#12-deployment-model) | Binary, Docker, config precedence |
| 13 | [Compliance & data handling](#13-compliance--data-handling) | Retention, export, residency |
| 14 | [Controlled delivery testing](#14-controlled-delivery-testing-with-jaisiu-smtp-credentials) | Live verification without secret exposure |
| 15 | [Out of scope](#15-out-of-scope) | Explicit non-goals |
| 16 | [Acceptance criteria map](#16-acceptance-criteria-map) | Criterion → section |

### Related specifications

| Document | Scope | Relationship |
|---|---|---|
| `docs/design/railgun-architecture-ir.md` | Neutral IR for the whole service | **Upstream.** This document is its committed, canonical form. |
| `docs/design/JAISIU-4915-RAILGUN-SMTP-PIPELINE-IR.md` | Transaction state machine, retry algebra, response contract | **Specializes §3, §4, §7.** Referenced, not restated. |
| `docs/design/9b5afdc7-…-railgun-outbound-delivery-engine-ir.md` | MX resolution, TLS negotiation, SMTP response classification | **Specializes §3, §4.** Referenced, not restated. |

---

## 1. Purpose & boundaries

### 1.1 Purpose

RailGun accepts email submissions from agents and services, applies authentication,
authorization, policy, rate limiting, spam prevention and audit, **durably queues** accepted
messages, and delivers them via outbound SMTP with bounded retry, bounce and suppression
handling.

It is a **mail service**, not a sending adapter. The existing Jaisiu email code are sending
adapters that terminate at Mailgun / SendGrid / an SMTP relay
(`src/mcp/email-shared/ports/email.port.ts:3-5` defines a one-method `send` seam;
`src/mcp/email/adapters/smtp.ts:29-100` is a Nodemailer relay client). RailGun becomes the
thing those adapters *talk to*, and can additionally deliver directly to recipient MX.

### 1.2 What RailGun is

- **Standalone.** No import of, or dependency on, Jaisiu harness application code. The
  `packages/railgun/` tree must build and pass its tests with no private Jaisiu dependency, so
  the public GitHub mirror stays self-contained.
- **Agent-first.** MCP is a first-class surface, not an afterthought. Any harness that speaks
  MCP, HTTP, or plain SMTP can use it.
- **Explainable.** Every rejection, deferral, and suppression carries a stable reason code, so
  an operator can diagnose "why did this not send?" without reading source.
- **Enterprise-ready.** Anti-spam, authentication, authorization, rate limiting, audit, and
  observability are in scope from v1, not deferred.

### 1.3 What RailGun must **not** duplicate

| Existing Jaisiu asset | RailGun's relationship |
|---|---|
| Gateway / server-methods (`src/gateway/server-methods.ts:162-164`) | Consume the pattern; do not reimplement the gateway. |
| Redis shared-memory bus | RailGun defines its own store port; a Redis adapter is optional. |
| License broker (`src/agents/license-client.ts`, `license-assertion.ts`) | Not applicable — GPL service, no broker. |
| IronLoop runtime (`src/agents/iron-loop/`) | Not applicable. |
| Control UI (`ui/`) | RailGun ships a CLI and a status page; no separate UI subsystem. |
| Audit hash-chain writer (`src/security/audit.ts`) | RailGun ships its **own** append-only NDJSON hash-chain writer in the package, following the shape of `src/security/compliance-evidence-log.ts:1-4`, so the mirror has no harness dependency. |
| Python / Go web backends | Not duplicated; RailGun exposes stable HTTP/MCP contracts instead. |

---

## 2. Canonical locations

### 2.1 Package tree

```
packages/railgun/
├── Cargo.toml                  # crate manifest, GPL-3.0-only
├── rust-toolchain.toml         # pinned toolchain (match PDC convention)
├── README.md                   # public-facing repo README
├── LICENSE                     # GPL-3.0
├── SECURITY.md                 # vulnerability disclosure + secret-handling policy
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── Dockerfile                  # multi-stage, non-root, no shell
├── docker-compose.yml          # railgun + db + optional redis
├── config/
│   └── railgun.example.yaml    # shipped, non-secret defaults only
├── src/
│   ├── main.rs                 # entrypoint + subcommand dispatch
│   ├── lib.rs
│   ├── domain/                 # message, envelope, status, policy types
│   ├── ports/                  # store, transport, clock, id, secret provider
│   ├── application/            # send pipeline, policy gate, queue worker
│   ├── adapters/
│   │   ├── transport/          # smtp.rs, mx.rs
│   │   ├── store/              # sqlite.rs, postgres.rs
│   │   └── interface/          # mcp.rs, http.rs, cli.rs
│   ├── spam/                   # scoring, blocklists, reputation
│   ├── security/               # authn, authz, redaction
│   └── signer/                 # dkim.rs, arc.rs
├── tests/                      # integration + conformance
├── docs/
│   ├── OPERATIONS.md
│   ├── SECURITY.md
│   ├── SMTP.md
│   ├── DNS-SETUP.md
│   └── API.md
└── examples/
    └── jaisiu/                 # harness wiring example — no secrets
```

The Rust/Axum/Tokio/`tracing` conventions follow the existing Rust package
(`packages/prizm-desktop-controller/` — `Cargo.toml:19-56`, `README.md:23`).

### 2.2 Jaisiu-side integration points (thin, optional)

- `src/mcp/railgun/` — Jaisiu client adapter registering RailGun as an MCP server and/or an
  `email_send` provider.
- `src/config/env-register.ts` — register `RAILGUN_*` variables when Jaisiu consumes RailGun
  (registry pattern at `src/config/env-register.ts:372-530`).
- `docker-compose.example.yml` — optional RailGun sidecar profile.

These are **the only** places Jaisiu code may change for RailGun. Everything else lives in
the package.

### 2.3 Canonical external contract

There are currently **two** disagreeing email stacks in the repo
(`src/mcp/email-shared/setup.ts` reads `SMTP_*`/`MAILGUN_*`;
`src/mcp/email/env-config.ts:45-110` reads `PRYZM_*` with relay failover). RailGun defines
**one** canonical external contract and the Jaisiu-side adapters are pointed at it:

| Surface | Canonical form |
|---|---|
| SMTP | RFC 5321 subset — see §3.2 |
| HTTP | `POST /v1/email/send` with `x-api-key` — see §3.3 |
| MCP | `email_send`, `email_status`, `email_bounces`, `email_stats` — see §3.4 |

The HTTP form is chosen because the existing Jaisiu remote client already speaks it
(`src/mcp/email/pryzmat-email-service.ts:29-72`: `POST {base}/v1/email/send` with
`x-api-key: token`). **The existing client works against RailGun with a URL swap and zero
code change.**

---

## 3. Service contract

### 3.1 Result vocabulary

Per-message status:

```
received → policy_evaluated → (rejected | suppressed | queued)
         → delivering → (delivered | deferred | bounced | failed)
```

| Status | Meaning |
|---|---|
| `received` | Accepted by a surface, not yet evaluated. |
| `policy_evaluated` | Authn/authz/policy/spam decisions made. |
| `queued` | Durably persisted, not yet attempted. |
| `accepted` | Upstream SMTP returned a final `250` for `DATA`. **Acceptance, not proof of mailbox delivery.** |
| `delivered` | Confirmed by DSN / provider event / verified round-trip. |
| `deferred` | Upstream returned `4xx`; will retry with bounded backoff. |
| `bounced` | Permanent failure (`5xx`) or DSN hard bounce. |
| `failed` | RailGun exhausted retries, or hit an unrecoverable internal error. |
| `rejected` | Refused before queueing (auth, policy, spam, size, invalid address). |
| `suppressed` | Destination on the suppression list, or the tenant is paused. |

**Invariant (must not be violated):** the contract never conflates acceptance with delivery.
`delivery_confirmed` is `true` **only** for `delivered`. This preserves the existing repo
semantics at `src/mcp/email-shared/domain/models.ts:27-45` (`EmailSendResult.deliveryConfirmed`)
and `src/mcp/email/adapters/smtp.ts:81-89`, where a successful Nodemailer return is explicitly
documented as "SMTP 250 OK from the DATA terminal — the strongest signal we have without DSN
polling."

### 3.2 SMTP submission (RFC 5321 subset)

- Listener: configurable, default `0.0.0.0:2525`. Optional submission TLS on `465`. Port `25` is
  **never** bound by default; it requires explicit operator opt-in.
- Commands: `EHLO`, `HELO`, `STARTTLS`, `AUTH PLAIN`, `AUTH LOGIN` (`AUTH XOAUTH2` optional),
  `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT`.
- `PIPELINING` is advertised **after** TLS only. `8BITMIME` is accepted but the message is
  normalized to canonical RFC 5322/5321 bytes before storage. `SMTPUTF8` is advertised only when
  UTF-8 addresses are configured; otherwise non-ASCII envelope addresses are rejected.
- Response codes:

  | Code | Meaning |
  |---|---|
  | `250` | Accepted and durably queued. |
  | `450` / `451` | Transient failure (rate limited, queue unavailable, resolver/DNS issue). Retryable. |
  | `550` / `551` / `553` | Permanent failure (unauthenticated on a restricted listener, unauthorized sender, invalid recipient syntax). |
  | `552` | Message exceeds the configured size limit. |
  | `554` | Transaction rejected by policy / spam controls. |

- **Envelope/header separation is mandatory.** The envelope sender and recipient list are
  authoritative for delivery. `From:` / `To:` headers never widen the recipient set.
- `RCPT TO` may repeat; each recipient is authorized and rate-limited **individually**.
  Partial acceptance is allowed and must be reported **per recipient** in the final response and
  the audit record.
- `DATA` terminates with `.` and performs dot-unstuffing. A message must contain a valid `From`
  or `Return-Path` context and at least one syntactically valid recipient.

The precise state machine, retry algebra, and idempotency boundary for this surface are
specified in `docs/design/JAISIU-4915-RAILGUN-SMTP-PIPELINE-IR.md`. **That document is
authoritative for transaction semantics; this document is authoritative for the contract shape.**

### 3.3 HTTP API

Base path `/v1`. JSON in/out. Authenticated by bearer token (`Authorization: Bearer …`) or
`X-Api-Key`, for parity with `PRYZM_EMAIL_SERVICE_TOKEN`
(`src/mcp/email/pryzmat-email-service.ts:47-55`).

| Method | Path | Semantics |
|---|---|---|
| `GET` | `/health` | Liveness only. No auth, no secrets. `{"status":"ok"}`. |
| `GET` | `/ready` | Readiness: store reachable, queue writable, outbound config present. Auth optional. No secrets. |
| `POST` | `/v1/email/send` | Submit a message. Fields: `to[]`, `cc[]`, `bcc[]`, `subject`, `text`, `html`, `from`, `reply_to`, `idempotency_key`, optional `metadata`. Returns `202` with `{id, status:"queued", …}` when durably queued; `4xx`/`5xx` otherwise. |
| `GET` | `/v1/messages/{id}` | Message status by RailGun ID: envelope recipients, timestamps, attempt count, status, last SMTP response code (sanitized). **Never** returns the body or a secret unless `include_body=true` **and** the caller is authorized. |
| `GET` | `/v1/messages` | Paginated list/filter by status, recipient hash, time window, tenant. |
| `POST` | `/v1/messages/{id}/retry` | Operator-only requeue of a failed/deferred message. |
| `POST` | `/v1/messages/{id}/suppress` | Operator-only suppression of a destination or message. |
| `GET` | `/v1/bounces` | Bounce list with sanitized DSN reason codes. |
| `GET` | `/v1/stats` | Aggregates: queued, sent, delivered, deferred, bounced, suppressed, rejected. |
| `POST` | `/v1/events` | Inbound webhook (provider/DSN events), authenticated by shared secret / HMAC. |

All mutating endpoints require a valid `Idempotency-Key`. A replayed key returns the original
result rather than creating a second message.

### 3.4 MCP surface

| Tool | Purpose |
|---|---|
| `email_send` | Submit a message. Field names match the existing Jaisiu tool exactly (`src/mcp/email-shared/mcp-tools.ts:4-37`: `to`, `subject`, `text`, `html`, `from`, `replyTo`, `cc`, `bcc`, `requestId`). |
| `email_status` | Status of a message by RailGun ID. |
| `email_bounces` | Bounce list with sanitized DSN codes. |
| `email_stats` | Tenant sending statistics. |

Transports: **stdio** (local harness embedding) and **HTTP/streamable** (service deployment).
Tool authorization uses the same principal/tenant model as the HTTP API. The MCP server must be
discoverable by an ordinary MCP client with **no Jaisiu-specific coupling**.

Jaisiu already exposes MCP tool listing and invocation
(`src/gateway/server-methods.ts:162-164` — `mcp.tools.list`, `mcp.tools.call`), so registering
RailGun as an MCP server reuses that surface rather than adding another in-process provider.

---

## 4. Message model & persistence

### 4.1 Stored record

```
Message {
  id: UUIDv7
  tenant_id: String
  principal_id: String
  idempotency_key: String             // unique per tenant
  envelope: { sender, recipients[] }   // envelope-only, normalized
  headers: Map<String,String>
  subject_hash: String                // policy/logging without body exposure
  body_ref: String | null             // opaque storage key, not inline in audit
  raw_size_bytes: u64
  sha256: String                      // canonical message digest
  status: MessageStatus
  attempts: u32
  next_attempt_at: Timestamp | null
  created_at, updated_at, queued_at, accepted_at, delivered_at
  last_smtp_code: String | null       // e.g. "421", "550"
  last_error_class: String | null     // classified, sanitized
  suppression_reason: String | null
  metadata: Map<String,String>        // operator-supplied, size-limited
}
```

### 4.2 Ports

Storage-agnostic ports: `MessageStore`, `OutboxStore`, `IdempotencyStore`,
`SuppressionStore`, `BounceStore`, `AuditStore`, plus `Clock`, `IdGenerator`, `SecretProvider`.
A first implementation targets **SQLite** for single-node dev and **PostgreSQL** for
production; the interface must not leak either into the domain layer.

> There is **no** `packages/shared/README.md` in the tree, so no shared package contract can be
> claimed. RailGun defines its own local ports.

### 4.3 Durability guarantees

- A message is reported `queued` **only** after a single transaction commits message +
  envelope + idempotency reservation together.
- Bodies may be stored inline, in encrypted object storage, or omitted entirely by policy
  (metadata-only mode). At-rest encryption is required in production; key material comes from a
  secret provider, **never** a database column.
- Retention: metadata default 30 days, bodies default 7 days. Audit records have a separate,
  longer retention and remain tamper-evident.
- **Restart safety:** all in-flight work is reconstructable from durable state. A crash between
  "remote accepted" and "local commit" may cause one duplicate; this is mitigated by the
  idempotency key and a deterministic `Message-ID`, and the API documents **at-least-once
  semantics per recipient**.

The outbox lease / "attempt in progress" mechanism and the per-recipient attempt accounting
are specified in `docs/design/9b5afdc7-…-railgun-outbound-delivery-engine-ir.md`.

---

## 5. Authentication & authorization

### 5.1 Principals

```
Principal { id, tenant_id, roles[], allowed_senders[], allowed_domains[],
            rate_limit_profile, active }
```

### 5.2 Roles (four, mirroring the existing RBAC precedent in `packages/security/README.md:41-46`)

| Role | Capabilities |
|---|---|
| `admin` | Full tenant administration: principals, domains, policy, suppression, stats, retries. |
| `operator` | Inspect messages, stats, bounces; retry/suppress; manage policy. |
| `sender` | Submit and inspect only its own principal/tenant messages. |
| `auditor` | Read-only access to messages, audit trail, stats. **No message body** unless explicitly granted. |

### 5.3 Authentication mechanisms

1. **SMTP AUTH** — username maps to a principal; password is an Argon2id salted hash or an
   opaque API token. Plaintext passwords are never stored. Constant-time comparison; failures
   rate-limited per source IP **and** per principal.
2. **HTTP bearer / API key** — token looked up by hash. A token *prefix* may be displayed; the
   secret never is. Tokens are rotatable and revocable.
3. **mTLS client certificate** — optional for enterprise deployments; certificate fingerprint
   maps to a principal.
4. **Local trusted submission** — a Unix socket or loopback-only listener may permit an explicit
   `local` principal. **Default deny.** The local principal still obeys policy and quotas.

### 5.4 Authorization rules

- The sender identity must match the principal's `allowed_senders` unless the principal holds
  the `sender_override` capability (**admin only**).
- Recipient domains may be restricted by tenant policy. Unauthorized destinations are rejected
  **at `RCPT TO`**, not silently dropped.
- Administrative endpoints require `admin`/`operator` and are audited.
- **Fail closed.** A missing, malformed, expired, or revoked credential produces an
  authentication error that does **not** reveal whether the account exists.

### 5.5 Secret handling

- Secrets enter **only** via environment variables, Docker secrets, mounted files, or a
  broker-backed `SecretProvider` port.
- **No secret may appear** in source, fixtures, configuration examples, logs, metric labels,
  error messages, audit payloads, HTTP responses, or MCP outputs. Redaction at the logging
  boundary is defense-in-depth — never a substitute for not logging the value.
- Startup validation **rejects** quote-wrapped or whitespace-wrapped credential values instead
  of sending them upstream. This is a documented, real hazard in this repo:
  `docs/infrastructure/production-pryzm-at.md:113-115` records quoted `.env` values becoming
  literal quotes and causing SMTP `535` authentication failures.

---

## 6. Rate limiting & quotas

Two layers, **both required**:

1. **Protocol / edge limits** — per connection: max recipients per transaction, max recipients
   per message, max message size, max command rate, max unauthenticated attempts, connection
   lifetime. Exceeding a *hard* protocol limit yields a permanent SMTP error; exceeding a
   *soft* limit yields `451`.
2. **Tenant quotas** — sliding-window counters for: messages per minute/hour/day, recipients per
   message, total bytes per day, concurrent in-flight deliveries, distinct new recipients per
   period. Per tenant, and where configured, per sender address.

Additional abuse controls:

- **Recipient-rate / burst protection** — a sharply lower limit for first-time recipients than
  for established allowlisted recipients, so a compromised agent cannot mail arbitrary new
  addresses rapidly.
- **Recipient confirmation** — optional mode where new destinations receive a confirmation
  challenge before the message is released. RailGun never sends on behalf of an unknown domain
  without an authorized sender.
- **Global concurrency cap** protecting shared outbound capacity.
- Every limit decision produces a structured reason code (e.g. `rate.tenant.messages_per_hour`)
  for metrics and audit.
- Rate-limit state is **shared across replicas** (a Postgres/Redis-backed port), never
  per-process.

---

## 7. Spam prevention

Layered, independently configurable, and independently observable controls.

### 7.1 Submission-time controls

- **Authentication** — only authenticated principals may relay. An open relay is impossible by
  construction.
- **Authorization** — sender and recipient allow/deny lists; verified-domain policy.
- **Size / shape limits** — max message bytes, max recipients, max header count, max header size.
  Malformed MIME is rejected rather than guessed at.
- **Header hygiene** — normalize CRLF; strip `Bcc` from the stored/displayed header set;
  enforce `Date`, `Message-ID`, and `From` where required; reject header injection (CR/LF in a
  subject or address field).
- **Content policy (spam scoring)** — deterministic rules plus optional pluggable classifiers.
  Signals: spam keyword/score, link and domain reputation, suspicious URL shorteners, excessive
  image-only HTML, suspicious headers, credential/attachment types, new-domain and
  disposable-mail indicators, known malicious patterns.
- **Spam score threshold** decides: accept, tag-and-accept, quarantine (hold for operator
  review), or reject. Thresholds are tenant-configurable.
- **Content disarm / reconstruction** (optional) — strip active content and tracking pixels,
  convert HTML to safe text, remove dangerous attachments, re-encode images.
- **Blocklists** — local and optionally remote URIBL-style lists for domains, IPs, and senders.
  Lists are cached with a bounded TTL and a per-list fail-open/fail-closed policy: a DNS/URI
  failure must not silently block all mail.
- **Recipient verification** — role addresses (`postmaster@`, `abuse@`, `security@`) and known
  traps are protected; unverified bulk destinations are refused.

### 7.2 Delivery-time controls

- **Blocklist re-check at delivery** — a destination that was blocklisted after queueing is
  suppressed, not delivered.
- **MX validation** — invalid or wildcard MX handling.
- **Reputation & feedback loops** — bounce and complaint rates per sender/domain/IP feed back
  into the score.
- **Bounce & complaint suppression** — a hard-bounced or complained destination is suppressed
  with a reason and expiry.
- **Warmup / first-send protection** — new tenants are limited to verified destinations until
  they complete a warm-up / verification step.

### 7.3 Explainability (hard requirement)

No content-based filtering of legitimate business mail beyond tenant policy, and no dark
patterns. **Every rejection or quarantine records the rule ID and reason class.** A rejection must
be diagnosable by an operator without reading source code.

---

## 8. Auditing

- Every submission, authentication event, authorization denial, policy decision, suppression,
  retry, bounce, and operator mutation produces an audit event.
- Schema: `{ts, actor, tenant_id, action, subject_type, subject_id, outcome, reason_code,
  metadata}`. Metadata excludes secrets and, by default, message bodies and raw recipient
  addresses. Recipient identity is stored as a **salted hash with a rotating salt** — the
  precedent in this repo is `packages/pryzm.at/backend/api/nda_audit.go:14-30`.
- The audit log is **append-only and tamper-evident**. RailGun implements its own hash-chained
  NDJSON writer (following the shape of `src/security/compliance-evidence-log.ts:1-4`) rather
  than importing harness code into the publishable package.
- Every record carries a stable request/correlation ID so an agent action, HTTP request, SMTP
  transaction, queue row, and outbound attempt are traceable end to end.
- Audit storage is configurable. A failed audit write for a security-relevant event must be
  **visible** (warn/error) and, in strict mode, must **fail the operation closed**.

---

## 9. Observability

- **Logs** — structured JSON via `tracing`. Every line carries correlation ID, tenant ID,
  message ID, and outcome. **Never** log credentials, auth material, full message bodies, or
  unredacted recipient lists at INFO.
- **Metrics** (Prometheus-compatible):

  ```
  railgun_messages_total{status,tenant}
  railgun_message_size_bytes                (histogram)
  railgun_smtp_submission_duration_seconds
  railgun_delivery_attempts_total{result,smtp_code_class}
  railgun_delivery_duration_seconds
  railgun_queue_depth{state}
  railgun_queue_oldest_age_seconds
  railgun_rate_limit_rejections_total{scope}
  railgun_spam_rejections_total{rule_id}
  railgun_auth_failures_total{mechanism}
  railgun_bounces_total{dsn_class}
  railgun_suppressed_total{reason}
  ```

- **Health / readiness** — `/health` and `/ready`, suitable for Docker and Kubernetes probes.
- **Operator CLI** — `railgun doctor`, `railgun queue inspect`, `railgun message show <id>`,
  `railgun bounce list`, `railgun stats`, `railgun test-smtp` (no external delivery unless
  explicitly confirmed). Diagnostics show configuration **names** and redacted **presence**,
  never values.

---

## 10. Operator workflows

| # | Workflow | Notes |
|---|---|---|
| 1 | **Install & run** | `docker compose up -d` from `packages/railgun/docker-compose.yml`. Persistent volumes for store, queue, audit. Secrets via `.env` (**unquoted**) or Docker secrets. Health check waits for `/ready`. |
| 2 | **Initial bootstrap** | Create the first `admin` principal with a one-time setup token printed to stdout **exactly once**, or supplied via env. Force credential rotation. |
| 3 | **Domain onboarding** | Add sending domains, configure DKIM/SPF/DMARC records, verify DNS, publish a human-readable alignment report. No automatic DNS mutation. |
| 4 | **Credential rotation** | SMTP AUTH users, HTTP API keys, and outbound provider credentials rotate independently, with an overlap window and immediate revocation. |
| 5 | **Policy management** | Per-tenant and global policy (rate limits, spam thresholds, allow/deny lists, attachment policy) edited via the HTTP admin API / CLI, with audit. |
| 6 | **Queue operations** | Inspect depth and oldest age; pause/resume a tenant or destination; retry; cancel; suppress. |
| 7 | **Bounce / complaint review** | Inspect DSN class, suppress with reason and expiry, export. |
| 8 | **Incident response** | Disable a principal, revoke tokens, pause sending globally, export audit, verify the hash chain. |
| 9 | **Backup / restore** | Back up metadata and (if enabled) bodies; documented restore procedure. |
| 10 | **Upgrade** | Versioned migrations, backward-compatible or the service refuses to start with a clear error. |

---

## 11. Integration with existing harnesses

### 11.1 Jaisiu

- Jaisiu's `email_send` tool keeps its current JSON shape and `deliveryConfirmed` semantics
  (`src/mcp/email-shared/domain/models.ts:27-45`). Under the hood, a RailGun adapter replaces
  the direct Mailgun/SMTP adapters and maps RailGun statuses back onto the existing vocabulary.
- RailGun is exposed to Jaisiu as an **MCP server**, registered via the existing MCP tooling
  surface (`src/gateway/server-methods.ts:162-164`).
- The existing remote email client already speaks `POST /v1/email/send` with `x-api-key`
  (`src/mcp/email/pryzmat-email-service.ts:29-72`), so **it works unchanged** against RailGun.
- Jaisiu keeps its own idempotency and audit
  (`src/mcp/email-shared/application/email-mcp-service.ts:46-91`: idempotency key
  `email:idempotency:{prismId}:{action}:{requestId}`, audit key `audit:email:{ts}:{uuid}`).
  RailGun adds server-side idempotency and audit. Jaisiu's `requestId` becomes RailGun's
  idempotency key. **The duplication is intentional and cheap**: Jaisiu protects its tool-call
  layer, RailGun protects the protocol layer. Both use the same logical key shape so the two
  systems dedupe against the same logical request.
- The Go backend (`packages/pryzm.at/backend/api/email.go:38-132`) may be migrated to RailGun
  later. **Out of scope** — RailGun must not require changing it.

### 11.2 Other harnesses

Because RailGun is a standalone Rust service with standard SMTP, HTTP, and MCP surfaces, any
harness integrates by one of:

- **MCP client** — register the RailGun MCP server and call `email_send`.
- **HTTP client** — `POST /v1/email/send` with a bearer token.
- **SMTP client** — point any SMTP library at the submission listener with SMTP AUTH.

**No Jaisiu-specific imports are required for any path.**

### 11.3 Public mirror layout

The GitHub mirror should include the whole `packages/railgun/` tree plus a root-level `README.md`,
`LICENSE` (GPL-3.0), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, CI,
`docker-compose.yml`, and an `examples/` directory. It must build and pass tests with **no
private Jaisiu dependency**.

---

## 12. Deployment model

- A single binary (`railgun`) with subcommands: `serve`, `doctor`, `migrate`, `queue`, `admin`.
- Docker image from `packages/railgun/Dockerfile`: multi-stage Rust build, non-root runtime
  user, read-only-root-filesystem compatible, **no shell** in the runtime image.
- Compose profile provides RailGun, PostgreSQL (optional; SQLite for dev), and optional Redis
  for shared rate-limit state. Mailbox DNS, ports 25/465/587, and reputation management remain
  the operator's responsibility — documented, not automated.
- **Configuration precedence**, matching repo convention: shipped YAML defaults → explicit
  config path → environment overlay. RailGun validates all configuration at startup and
  **refuses to start** on invalid configuration rather than degrading silently.
- Secrets are never written to the shipped YAML. A credential check reports only
  presence/absence.

---

## 13. Compliance & data handling

- Minimize retained personal data: store recipients as hashes where operationally sufficient;
  bodies have a short retention.
- Provide export and deletion endpoints for tenant data.
- Audit trail supports tamper detection and SIEM export (NDJSON / CSV / CEF), consistent with
  `packages/security/README.md:24-32`.
- Data residency: all storage is operator-chosen. **No telemetry leaves the deployment by
  default.** Telemetry is opt-in and redacted.

---

## 14. Controlled delivery testing with Jaisiu SMTP credentials

**Purpose:** prove RailGun's SMTP submission, queueing, outbound relay, and status reporting
work end to end against a real upstream provider, using the SMTP credentials already configured
for Jaisiu, **without ever placing those credentials in source, logs, or the public
repository.**

### 14.1 Credential sources (runtime only, never committed)

- Jaisiu `PRYZM_SMTP_*` variables (host, port, username, password, secure) as read by
  `src/mcp/email/env-config.ts:71-108`; registered at `src/config/env-register.ts:475-530`.
- Legacy `SMTP_*` aliases as read by `packages/pryzm.at/backend/api/email.go:65-105`.
- The Jaisiu state directory (`~/.jaisiu/`) or Docker secret mounts — outside the repository
  tree per `AGENTS.md:44-55`.

### 14.2 Procedure

1. Start RailGun with the outbound relay configured **from environment variables only**. Never
   place the secret in `config/railgun.example.yaml`, a test fixture, a committed Compose file,
   or an MCP argument.
2. Confirm configuration using `railgun doctor`. Output shows only the **credential source** and
   a **redacted presence indicator**.
3. Use a **dedicated test recipient approved by the operator** (not a harvested or public
   address). Send one plain-text and one HTML/multipart message through **each** surface:
   - SMTP submission (`swaks` / `openssl s_client` with SMTP AUTH) → expect `250` and a RailGun
     message ID.
   - HTTP `POST /v1/email/send` → expect `202` and `queued`.
   - MCP `email_send` → expect a queued result with the same status vocabulary.
4. **Verify persistence** — restart RailGun; confirm queued/accepted state and attempt history
   survive.
5. **Verify outbound** — observe a `250` acceptance from the upstream relay, then confirm the
   message ID and status transitions (`queued` → `accepted`; `delivered` only if a DSN or
   equivalent confirmation is available).
6. **Verify failure handling in a controlled way** — point RailGun at an unroutable test host
   (or a deliberately invalid recipient on the approved test domain) and confirm **bounded**
   retry plus a terminal `failed`/`bounced` state. **No hot loop.**
7. **Verify anti-abuse** — attempt an unauthenticated submission, an unauthorized sender, an
   over-quota submission, and a known-spam test payload. Each must be rejected or quarantined
   with a **recorded reason code**.
8. **Verify secrecy** — grep the source tree, container logs, audit log, metrics endpoint, and
   MCP output for the literal secret and for the credential variable's value. **Zero matches
   required.** Also check the repository for committed `.env` files and accidental secret
   fragments.
9. **Record the evidence** in a redacted test report containing message IDs, timestamps, status
   transitions, SMTP response codes, and the secret-check result — **never the credential**.

### 14.3 Safety constraints

- Test only to **explicitly approved** recipients. No bulk or unsolicited sends.
- Do **not** print, echo, slice, or otherwise reveal the credential — including partial prefixes —
  in command output, logs, tickets, or handoffs. If a credential's presence must be checked,
  print **only a boolean**.
- Never commit the credential, a `.env` file containing it, or a captured SMTP session
  containing `AUTH` material.
- If a secret is ever observed in output, **treat it as compromised**: stop, rotate the
  credential, and remove the exposure before continuing.
- Because quoted `.env` values are a known cause of SMTP `535` in this repo
  (`docs/infrastructure/production-pryzm-at.md:113-115`), testing must explicitly detect
  quote-wrapped values and **fail fast** rather than repeatedly authenticating with a malformed
  password.

---

## 15. Out of scope

- An IMAP inbox or webmail UI. Jaisiu's existing `email_receive` remains the IMAP path.
- Replacing the Jaisiu license broker, IronLoop, or the Control UI.
- Automatic DNS record mutation for SPF/DKIM/DMARC — guidance and verification only.
- A general-purpose spam-filtering research engine — use pluggable, documented classifiers.
- Migrating `packages/pryzm.at/backend/api/email.go` or other existing producers.
- Inbound MX / receiving mail — inbound is out of scope except the DSN feedback loop.

---

## 16. Acceptance criteria map

| Acceptance criterion | Where satisfied |
|---|---|
| Canonical package and service locations under `packages/railgun`; no duplication of existing Jaisiu infrastructure | §1.3, §2.1, §2.2 |
| SMTP submission | §3.2 |
| Outbound delivery | §3.1, §4.3, and the outbound delivery engine IR |
| Message persistence | §4 |
| Authentication | §5.3 |
| Authorization | §5.2, §5.4 |
| Rate limiting | §6 |
| Spam prevention | §7 |
| Auditing | §8 |
| Observability | §9 |
| Operator management | §10 |
| Integration with existing harnesses | §11 |
| Controlled delivery testing with Jaisiu SMTP credentials, no secret exposure | §14 |
| Deployment / configuration conventions | §12 |
| Compliance and data handling | §13 |
