# RailGun Contract Implementation Checklist (TypeScript)

**Ticket:** JAISIU-4916 (comment only)
**Plan:** `7fcaa999-aeee-4359-b064-1311d6505709` — synthesize unit
**Status:** normative checklist. Derived from the canonical contracts and the granular IRs.
**Implementation profile:** TypeScript on Node.js 22+, ESM, standalone npm package `packages/railgun`, GPL-3.0-or-later.
**Primary outbound mode:** direct-to-MX. Operator-configured relay is an explicit fallback.

This document is the **contract index and obligation checklist** for the RailGun implementation.
It does not define new behaviour, does not restate a second architecture, and does not create an
implementation parallel to the canonical contracts. Where it lists obligations, each one is
traceable to a named source section; where sources disagree, §3 records the resolution instead of
silently choosing.

Companion documents:

- `packages/railgun/docs/ARCHITECTURE.md` — canonical service contract (committed).
- `packages/railgun/docs/TYPESCRIPT-IMPLEMENTATION-IR.md` — the extract-phase semantic IR this
  checklist was synthesised from (same directory, indexed here as `TS-IR`).
- `docs/design/*-railgun-*.md` — the granular IRs listed in §1.

---

## 1. Contract resolution — every document accounted for

### 1.1 Canonical contract

| # | Document | Path | Role in this checklist |
|---|---|---|---|
| C1 | Canonical architecture & service contract | `packages/railgun/docs/ARCHITECTURE.md` | **Rank 1** for contract shape: surfaces, vocabulary, persistence, auth, policy, audit, operator, deployment, controlled testing. §16 maps its acceptance criteria. |
| C2 | Whole-service IR (upstream) | `docs/design/railgun-architecture-ir.md` | Earlier, coarser statement of the same contract. Rank 6 — superseded by C1 where they differ. Its Rust/Axum/Tokio layout is illustrative only. |
| C3 | Repository map | `CODEMAP.md` | Confirms `packages/` is the publishable/service boundary; harness `src/` is not a RailGun dependency. |
| C4 | Repository architecture | `ARCHITECTURE.md` | Confirms monorepo boundaries and service conventions. |
| C5 | TypeScript design note | `docs/design/748e1599-56a5-469c-acbd-ff022d0e72a1.md` (plan artifact under `.openclaw/fleet-artifacts/`) | The frozen delta: TypeScript/Node 22+, direct-MX-primary, standalone install. |
| C6 | Extract-phase semantic IR | `packages/railgun/docs/TYPESCRIPT-IMPLEMENTATION-IR.md` | The input to this synthesize unit; indexed as `TS-IR`. |

### 1.2 Granular IRs — all abbreviated paths resolved

The plan brief named the IRs by abbreviation. Every abbreviation resolves to exactly one file
(verified on disk at `/home/node/.jaisiu/workspace/jaisiu`):

| Brief abbreviation | Resolved path | Subject | Rank |
|---|---|---|---|
| `docs/design/railgun-architecture-ir.md` | `docs/design/railgun-architecture-ir.md` | Whole-service IR | 6 |
| `docs/design/JAISIU-4915-RAILGUN-SMTP-PIPELINE-IR.md` | `docs/design/JAISIU-4915-RAILGUN-SMTP-PIPELINE-IR.md` | SMTP transaction state machine, identifier vocabulary, idempotency boundary, retry algebra, normalization, safe-failure rules | 2 |
| `docs/design/9b5afdc7-…-railgun-outbound-delivery-engine-ir.md` | `docs/design/9b5afdc7-6199-4078-a4db-40b1435b66a4-railgun-outbound-delivery-engine-ir.md` | MX resolution, TLS, SMTP response classification, per-recipient outcomes, retry, observability | 2 (outbound) |
| `docs/design/ca1f5105-…md` (anti-spam) | `docs/design/ca1f5105-1de3-47ae-a45f-0cdfd618537a.md` | Authn/authz, quotas, rate limits, warmup, spam scoring, blocklists, feedback, auditability | 3 |
| `docs/design/252d0e90-…md` (operator API/CLI) | `docs/design/252d0e90-dbf6-4e9d-ba46-1ea3eccede40.md` | Operator projections, shared security envelope, management HTTP + CLI behaviour | 2 (HTTP semantics) |
| `docs/design/3019b185-…md` (validation) | `docs/design/3019b185-7284-4c91-8b28-d9d61d3f44ce.md` | Scenario matrix, fake-MX fixture requirements, live gate, leak scan | 4 (verification) |

### 1.3 Additional contract documents found on disk (not named in the brief)

These two per-surface IRs exist in `docs/design/` and are **more specific** than the
whole-service IR for their surface. They are therefore binding for their subject and were **not**
listed in the brief's abbreviated path list. Both are now accounted for:

| # | Document | Path | Subject | Rank |
|---|---|---|---|---|
| C7 | SMTP submission server IR | `docs/design/84df18ec-8e87-47cb-9d64-b804c4205cb3-railgun-smtp-submission-server-ir.md` | Inbound SMTP wire protocol: listeners, TLS, session state machine, command gating, reason codes, reply-code mapping, policy hooks | 2 (submission protocol) |
| C8 | HTTP API surface IR | `docs/design/railgun-http-api-ir.md` | Route table, public manifest, request/response envelopes, status discipline, error-code aliases, cross-surface compatibility | 2 (HTTP wire contract) |

> **Gap closed by this checklist:** the extract-phase `TS-IR` §0 resolution table did not list C7
> or C8. An implementer following `TS-IR` alone would miss the binding submission-server rules
> (C7) and the HTTP route/envelope contract (C8). Both are folded into §§4–7 below.

### 1.4 Authority order

Applied when two documents appear to disagree (this is the union of the authority hierarchies
declared in C1 §0, C7 §0.2, C8 §0.4, C6 §0.2 and the validation IR §0.2):

1. `packages/railgun/docs/ARCHITECTURE.md` — contract shape.
2. The most specific granular IR for the subject in hand:
   - SMTP submission protocol → C7
   - HTTP wire contract and cross-cutting HTTP semantics → C8 and the operator IR
   - Transaction/idempotency/retry semantics → the SMTP-pipeline IR
   - Outbound delivery → the outbound-delivery IR
   - Policy ordering, quotas, scoring → the anti-spam IR
   - What is tested → the validation IR
3. The frozen plan deltas — language, packaging, licensing, direct-MX default.
4. `docs/design/railgun-architecture-ir.md` — earliest and coarsest; loses to everything above.
5. `TS-IR` (C6) — the synthesis index; it points at the above and never overrides them.

---

## 2. Canonical vocabulary and identifiers (binding)

Source: SMTP-pipeline IR §2 (V-1…V-4), ARCHITECTURE §3.1, anti-spam IR §4.

- [ ] **D-1** `request_id` — caller-supplied idempotency key; required and non-empty; bounded length.
- [ ] **D-2** `prism_id` / principal / tenant — authenticated identity scope; derived from the
      credential, never chosen by the caller.
- [ ] **D-3** `message_id` — RailGun's own durable message identifier, generated **before**
      journalling, server-generated, opaque, and embedded in the outbound RFC `Message-ID`.
- [ ] **D-4** RFC `Message-ID` — deterministic and stable for one logical request; **distinct**
      from `message_id`.
- [ ] **D-5** `queue_id` — durable queue row identifier; distinct from `message_id`.
- [ ] **D-6** `envelope_id` — one per SMTP transaction for a (message, recipient-set) pair.
- [ ] **D-7** Per-recipient delivery-attempt identifier — one per attempt; attempt start and
      outcome are recorded separately.
- [ ] **D-8** The stored idempotency key is **byte-identical** to
      `email:idempotency:{prism_id}:{action}:{request_id}` so a migration cannot double-send.
- [ ] **D-9** Public status vocabulary: `queued`, `accepted`/`sent`, `delivered`, `deferred`,
      `bounced`, `failed`, `rejected`, `suppressed`. `deliveryConfirmed` is true **only** after an
      observed terminal SMTP `250` for that delivery (or a DSN proof of delivery). Queue
      acceptance is never confirmation.
- [ ] **D-10** State monotonicity (pipeline IR Rule S-3): legal paths are
      `rejected`/`suppressed` (pre-transaction terminals), `queued → sent`,
      `queued → deferred → … → sent|bounced`, `queued → bounced`, `queued → suppressed`.
      `sent → anything` and `deferred → queued` are illegal. `deferred` describes the current
      attempt's outcome and the visible state does not revert to `queued`.
- [ ] **D-11** Terminal attempt exhaustion is **not** an SMTP `5xx`; it has its own stable reason
      and the last observed SMTP code is preserved unchanged.
- [ ] **D-12** Every rejection, deferral, and suppression carries a **stable machine-readable
      reason code** (C7 §1: `auth.failed`, `policy.sender_not_allowed`,
      `limit.message_size`, …).

---

## 3. Resolved ambiguities (recorded, not redesigned)

The following source tensions are resolved by the frozen TypeScript delta or by the declared
authority order. The implementation MUST follow the resolution and MUST NOT treat it as licence
to alter the underlying behaviour.

| # | Tension | Resolution | Authority |
|---|---|---|---|
| A-1 | Language/layout: sources specify Rust, Cargo, Axum, Tokio, `rust-toolchain`. | TypeScript on Node 22+, native Node networking, standalone npm package. File-layout illustrations in the IRs are non-binding. | Plan delta (C5); TS-IR §12.1 |
| A-2 | Outbound default: older design treated relay as the normal path. | Direct-to-MX is **primary**; relay remains fully supported as an operator-selected fallback. | Plan delta; ARCHITECTURE §12 |
| A-3 | Licence wording: some sources say "GPL-3.0-only". | The package is **GPL-3.0-or-later**. | Plan delta |
| A-4 | Health paths: `/health`+`/ready` (ARCHITECTURE §3.3, operator IR §4.10) vs `/healthz`+`/readyz` (validation IR H1/H2, operator IR §3.2). | **Both.** `/health`/`/ready` are canonical; `/healthz`/`/readyz` are exact-match aliases. Never prefix-match (operator IR §6.8 prefix-shadowing hazard). | C8 §0.4 resolved-conflicts table |
| A-5 | Error codes: validation IR `UNAUTHORIZED`/`FORBIDDEN` vs operator IR `UNAUTHENTICATED`/`INSUFFICIENT_SCOPE`. | Operator-IR registry is canonical (`UNAUTHENTICATED`, `INSUFFICIENT_SCOPE`, `ACTION_NOT_PERMITTED`); the validation spellings are accepted **aliases** in the `code` field. HTTP status identical (`401`/`403`). | C8 §0.4 |
| A-6 | `IDEMPOTENCY_CONFLICT` (anti-spam §14) vs `IDEMPOTENCY_KEY_REUSED` (operator §8.2). | Canonical `IDEMPOTENCY_KEY_REUSED`; `IDEMPOTENCY_CONFLICT` accepted as an alias. | C8 §0.4 |
| A-7 | `QUOTA_EXCEEDED` (anti-spam) vs `RATE_LIMITED` / `RATE_LIMITED_BY_POLICY` (operator). | Operator codes canonical; `RATE_LIMITED` carries `details.limit` ∈ {`daily_cap`,`recipient_hourly_cap`,`api_key_minute`}; `QUOTA_EXCEEDED` is an accepted alias for the quota-exhausted case only. | C8 §0.4 |
| A-8 | `Idempotency-Key` header vs `request_id` body field. | **Independent keys, both enforced when present.** `Idempotency-Key` = transport-layer replay protection; `request_id` = logical-send identity bound to the byte-shape in D-8. A send must carry at least one. | C8 §0.4 |
| A-9 | Send route: `POST /v1/email/send` (frozen Jaisiu client) vs `POST /send` (operator mailer). | **Both are required** and are aliases of the same operation. | C8 §0.4, goals G1 |
| A-10 | Suppression route/command naming: `POST /v1/messages/{id}/suppress` vs `/v1/suppressions`; `railgun suppress` vs `railgun suppressed`. | Canonical `POST /v1/messages/{id}/suppress` and `POST /v1/suppressions` both exist; CLI has one canonical spelling with an alias. All aliases converge on **one** application path. | TS-IR §12.5 |
| A-11 | Status naming: canonical API `accepted` vs pipeline IR `sent`. | `accepted` may be exposed publicly; internally `sent` is used. **Never** conflated with DSN-confirmed `delivered`. | ARCHITECTURE §3.1; TS-IR §12 |
| A-12 | MCP exposure: older architecture described one transport; the frozen plan requires both. | stdio **and** streamable HTTP are both required. | Plan delta; TS-IR §12.8 |
| A-13 | Test location: monorepo root vitest configs exist. | Tests live in the package and use Vitest; root configs may be reused only as an integration convenience, never as a runtime dependency. | TS-IR §12.9 |
| A-14 | Route ownership: C7 owns submission protocol, C8 owns HTTP wire contract, operator IR owns management resources. | Where they overlap, the more specific IR wins **for its subject only**. Operator management semantics (domains, identities, policies, queue, suppressions, API keys, reports) remain owned by the operator IR; C8 only fixes the shared envelope/auth/idempotency/pagination/error semantics. | C8 §0.3 |

### 3.1 Ambiguities that remain open (implementation decisions, not contract gaps)

SQLite binding, YAML parser, CLI library, HTTP/MCP framework, SMTP parser library, metrics
exposition format, and internal folder names are free choices. Implementations MUST NOT change
observable semantics to accommodate them. (TS-IR §12.)

Two items need an explicit written decision in the owning unit's evidence because a later reader
cannot infer them:

- [ ] **AMB-1** Whether `GET /v1/messages/{id}` exposes `include_body=true` to a `sender`
      principal, or only to `operator`/`auditor`. The architecture (§3.3) permits it "unless the
      caller is authorized" but does not enumerate the roles. Default to the narrowest reading
      (`operator`/`auditor` only) until the unit documents otherwise.
- [ ] **AMB-2** The concrete backoff curve (base, multiplier, cap, jitter distribution). The
      pipeline IR fixes the *properties* — bounded, jittered, monotonic, finite attempts — and not
      the formula. The implementation MUST publish the curve in configuration so the operator can
      see it.

---

## 4. Domain, ports, and persistence obligations

Sources: ARCHITECTURE §4; SMTP-pipeline IR §3–§6; anti-spam IR §6; TS-IR §2.

- [ ] **P-1** Domain types: message, envelope/recipient, status, policy decision, delivery
      attempt, bounce, suppression, quota, idempotency, audit event.
- [ ] **P-2** Three recipient sets `to`, `cc`, `bcc` are preserved. **Bcc is envelope-only** and
      MUST NOT appear in transmitted headers or in normal operator projections.
- [ ] **P-3** The **envelope is authoritative** for delivery; `From:`/`To:` headers never widen the
      envelope recipient set.
- [ ] **P-4** Ports for store, queue, clock, ID generation, transport, secret provider, DNS, and
      audit. Production adapters MUST NOT depend on Jaisiu harness modules.
- [ ] **P-5** A SQLite store (Node 22 built-ins or a self-contained dependency) **plus** an
      in-memory store for tests. The package installs and builds without the monorepo root.
- [ ] **P-6** Persisted state: messages, per-recipient outcomes, durable outbox entries,
      idempotency records, suppression, bounce records, quota/rate counters, policy/audit state.
- [ ] **P-7** **Atomic commit** of idempotency result and queue admission. A replay with the same
      normalized fingerprint returns the original result and causes zero additional SMTP
      transactions; a different fingerprint fails with `IDEMPOTENCY_KEY_REUSED`
      (`IDEMPOTENCY_CONFLICT` alias).
- [ ] **P-8** Queue claims are **atomic compare-and-set/lease** based. One message MUST NOT be
      attempted concurrently by two workers.
- [ ] **P-9** Queue entries survive restart and preserve ordering/priority semantics; expose
      `available_at`, attempt count, max attempts, and a stable last-error code.
- [ ] **P-10** Attempt **start and outcome are recorded separately**. A crash after a remote
      `250` but before outcome persistence leaves an explicit unresolved/uncertain record;
      recovery MUST NOT silently duplicate or erase it.
- [ ] **P-11** Audit is **append-only NDJSON, hash-chained**, durable before a final policy
      decision, PII-minimized, retention-aware, and supports verification and retention cleanup.
- [ ] **P-12** Retention/export/deletion semantics apply to bodies, recipient data, idempotency,
      queue/journal data, quotas, and audit records per configuration. Bodies at rest are
      encrypted; key material comes from the secret provider, never a database column.
- [ ] **P-13** Restart safety: all in-flight work is reconstructable from durable state. The
      documented at-least-once boundary is per recipient and is covered by the idempotency key
      plus the deterministic `Message-ID`.
- [ ] **P-14** `message_id` format is `<rg-{ULID}@railgun>` (pipeline IR §2) and is generated
      before journalling.

---

## 5. SMTP submission server obligations

Sources: C7 (binding for protocol); ARCHITECTURE §3.2; SMTP-pipeline IR §3.2.

### 5.1 Transport and listeners

- [ ] **S-1** Submission (plain, `STARTTLS` upgrade) binds the configured address; default
      `0.0.0.0:2525`.
- [ ] **S-2** Implicit-TLS submission is available only when the bind address **and** both
      cert and key are configured (typically port 465).
- [ ] **S-3** **Port 25 is never bound** without explicit operator opt-in; a configuration naming
      port 25 MUST be rejected at startup unless the opt-in flag is present.
- [ ] **S-4** A listener that fails to bind causes **startup failure** with a sanitized error — no
      silent reduced listener set.
- [ ] **S-5** The `local` principal is reachable only via a Unix socket or a loopback-only
      listener, and only when `auth.allow_local_submission` is explicitly true. Default deny.
- [ ] **S-6** `STARTTLS` is advertised in `EHLO` **only** on a plain listener with a usable
      certificate/key; on an implicit-TLS listener it is not advertised and is rejected `502`.
- [ ] **S-7** Before the handshake completes, the server MUST NOT advertise `PIPELINING` or
      `AUTH` mechanisms requiring a protected channel.
- [ ] **S-8** A failed handshake terminates the session with a sanitized `454` (transient) or
      `550` (permanent) and MUST NOT reveal paths, library error text, or certificate contents.
- [ ] **S-9** A successful `STARTTLS` **resets the session** to pre-`EHLO` state: fresh `EHLO`
      required before `MAIL FROM`; any command other than `EHLO`/`HELO`/`NOOP`/`RSET`/`QUIT`
      immediately after `STARTTLS` is rejected `503`. All pre-TLS state (partial transaction, auth
      attempt, accumulated recipients) is discarded.
- [ ] **S-10** Client source IP and negotiated TLS parameters are recorded in the session audit
      record; absence of TLS is never treated as a different identity for rate limiting.
- [ ] **S-11** Inbound TLS below 1.2 is rejected; `tls.min_version` is the source of truth.

### 5.2 Session state machine and command gating

- [ ] **S-12** States: `GREETING_SENT`, `GREETED`, `TLS_ACTIVE`, `AUTHENTICATED`,
      `MAIL_RECEIVED`, `RCPT_RECEIVED`, `DATA_RECEIVED`, `CLOSED`.
- [ ] **S-13** A command issued where it is not permitted is rejected `503` (bad sequence); the
      server MUST NOT guess intent or partially apply a rejected command.
- [ ] **S-14** Supported commands: `EHLO`, `HELO`, `STARTTLS`, `AUTH PLAIN`, `AUTH LOGIN`
      (`AUTH XOAUTH2` optional), `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT`.
- [ ] **S-15** `PIPELINING` is advertised **only after TLS**.
- [ ] **S-16** `8BITMIME` is accepted and the message is normalized to canonical SMTP/MIME bytes
      before storage; `SMTPUTF8` is advertised only when UTF-8 addresses are configured, otherwise
      non-ASCII envelope addresses are rejected.
- [ ] **S-17** `DATA` termination is `.` with **dot-unstuffing**; the exact transmitted bytes are
      preserved across retries.
- [ ] **S-18** Enforce command syntax, transaction ordering, size limits, and timeouts, with safe
      failures.
- [ ] **S-19** The transaction requires a valid sender context and **at least one** valid
      recipient.

### 5.3 Reply-code semantics

- [ ] **S-20** `250` durable acceptance; `450`/`451` transient; `550`/`551`/`553` permanent; `552`
      size exceeded; `554` policy/spam rejection; `502` command not implemented; `503` bad
      sequence; `454` transient TLS failure.

### 5.4 Recipients, authorization, and relay safety

- [ ] **S-21** `RCPT TO` may repeat; **each** recipient is authorized and rate-limited
      individually; partial acceptance is reported per recipient in the final response and in the
      audit record.
- [ ] **S-22** Unauthorized destinations are rejected **at `RCPT TO`**, never silently dropped.
- [ ] **S-23** Authentication is required on restricted listeners; `AUTH` is never accepted over
      an insecure channel unless explicitly configured for local/test use.
- [ ] **S-24** **No open relay**: submission is limited to authenticated/authorized principals
      and configured/allow-listed sending domains.
- [ ] **S-25** Submission and outbound SMTP are **separate protocol roles**; they MUST NOT share
      transaction state, and inbound delivery MUST NOT be mistaken for an outbound queue action.

---

## 6. Direct-to-MX outbound delivery obligations

Sources: outbound-delivery IR (binding); ARCHITECTURE §3.1/§4.3; TS-IR §4.

- [ ] **X-1** Direct MX is the default outbound mode; relay mode is operator-selected fallback and
      is not required for normal operation.
- [ ] **X-2** Resolve the recipient domain with `node:dns/promises`: query MX, order by ascending
      preference then a deterministic tiebreak, resolve A and AAAA for selected hosts, and cache
      only within TTL / configured maximum.
- [ ] **X-3** IPv4 and IPv6 fallback with a **documented deterministic preference**. Implicit MX
      for address literals only when policy permits.
- [ ] **X-4** Temporary DNS failure defers (`dns_temporary`); no MX / null MX is permanent
      (`dns_no_mx` / `mailbox_unavailable`).
- [ ] **X-5** Never connect to a host outside the resolved MX set.
- [ ] **X-6** Configured timeouts and per-host connection limits. Timeout, refusal, reset, and
      transient network failures **defer** and never appear successful.
- [ ] **X-7** SMTP dialogue: greet, `EHLO`/`HELO`, `MAIL FROM`, per-recipient `RCPT TO`, `DATA`,
      and `QUIT` when the session is alive.
- [ ] **X-8** Opportunistic STARTTLS by default, TLS ≥ 1.2, full certificate-chain **and**
      hostname verification. Invalid certificates MUST NOT be accepted. A configurable hard-fail
      mode prevents plaintext fallback; policy MUST never silently bypass TLS.
- [ ] **X-9** Record TLS mode/protocol/cipher and safe certificate fingerprint metadata.
- [ ] **X-10** **Per-recipient transactional delivery** — one recipient's failure MUST NOT corrupt
      another recipient's outcome.
- [ ] **X-11** Classify SMTP `4xx` as transient deferral and `5xx` as permanent bounce; relay,
      auth, and TLS failures use the outbound IR's stable error vocabulary.
- [ ] **X-12** Retry deferred recipients with **bounded exponential backoff plus jitter**, honouring
      retry hints. Maximum attempts is finite and configurable; exhaustion is terminal without
      inventing a `5xx` (see D-11 and AMB-2).
- [ ] **X-13** Rotate to the next eligible MX host after a host failure; apply per-host cooldown
      and quarantine for persistent TLS-policy rejection.
- [ ] **X-14** Preserve request ID, message ID, and **exact bytes** across retries without
      duplicating the idempotency record.
- [ ] **X-15** Deterministic RFC `Message-ID`, stable for a logical request.
- [ ] **X-16** Parse DSN/feedback sufficiently to produce delivery confirmation or
      recipient-scoped suppression. Hard DSN `5.1.1` / `5.1.10` suppresses that recipient; soft
      DSN MAY increment a soft-bounce counter and MAY create only a time-bounded suppression.
- [ ] **X-17** A DSN MUST NOT create wildcard/domain-wide suppression.
- [ ] **X-18** Feedback ingest MUST be authenticated or HMAC/token-signed.
- [ ] **X-19** Detect and reject delivery loops.
- [ ] **X-20** Emit durable structured attempt events and metrics: attempts, outcomes, TLS
      failures, queue depth, in-flight work, cooldowns, duration, end-to-end latency.

---

## 7. Anti-spam, compliance, and policy obligations

Sources: anti-spam IR (binding for policy ordering); ARCHITECTURE §5–§7; TS-IR §5.

### 7.1 Authentication and authorization

- [ ] **A-1** Default configuration **denies sending**. Missing identity/auth configuration fails
      closed.
- [ ] **A-2** Bearer API key and JWT. JWT validation verifies signature, expiry, issuer, and
      **exact audience**; a token for another service/audience is rejected.
- [ ] **A-3** API keys compared in **constant time**, stored as salted Argon2id hashes (never
      plaintext or reversible), identified by a non-secret key ID for audit attribution.
- [ ] **A-4** Credentials accepted via `_FILE` / secret-file indirection / secret mounts. Secrets
      MUST NOT appear in logs, audit, metrics, queue rows, URLs, errors, or source.
- [ ] **A-5** Authentication failures use generic responses and MUST NOT disclose whether a key,
      token, sender, or tenant exists.
- [ ] **A-6** Scopes: send, batch send, status read, suppression write, policy read, quarantine
      read/release, blocklist write, feedback ingest. Ordinary clients MUST NOT perform operator
      mutations.
- [ ] **A-7** Tenant is derived from the authenticated principal; a caller cannot select a
      tenant. A client may send only from sender domains assigned to its tenant; otherwise
      `DENY_SENDER_NOT_ALLOWED`.
- [ ] **A-8** Four operator roles (`admin`, `operator`, `sender`, `auditor`) with the capabilities
      of ARCHITECTURE §5.2. Admin endpoints are audited.

### 7.2 Policy ordering and precedence

- [ ] **A-9** Gates run in this exact order: parse/validate shape+size+`request_id` → authenticate →
      authorize → idempotency replay → recipient validation → block/suppression → quota → rate
      limit → content/identity checks → warmup/reputation → final decision → atomic
      decision/queue commit.
- [ ] **A-10** Decision precedence: `reject` > `deny` > `quarantine` > `throttle` > `allow`; **all**
      matched rule IDs are auditable.
- [ ] **A-11** A denied, quarantined, or throttled request causes **zero SMTP transactions**.

### 7.3 Quotas, rate limits, warmup

- [ ] **A-12** Independently enforced, durable quota dimensions: tenant messages/day, tenant
      recipients/day, sender-domain messages/day, recipient messages/hour, principal messages/day,
      optional batch/recipient ceiling. Concurrent requests MUST NOT overshoot (atomic check).
- [ ] **A-13** A quota denial returns `429` with the exhausted dimension, applicable reset time,
      and a `Retry-After` value, and MUST NOT reveal other tenants' usage.
- [ ] **A-14** Per-key/per-principal token buckets enforce request rate **before** expensive content
      parsing; per-domain and per-recipient buckets limit delivery frequency. An unset limit MUST
      NOT mean unlimited for abuse-sensitive dimensions.
- [ ] **A-15** A rate-limit denial returns `429`, code `RATE_LIMITED`, and `Retry-After`; it MUST
      NOT attempt SMTP.
- [ ] **A-16** Sender/domain warmup schedule and new-recipient limits are enforced.

### 7.4 Content, compliance, and signing

- [ ] **A-17** Blocklists and suppressions across global, tenant, domain, recipient, sender, IP,
      content/hash, and feedback-derived scopes.
- [ ] **A-18** Role-address protection, plaintext alternative, `List-Unsubscribe` requirements,
      maximum recipients/body/attachment/batch sizes, and CR/LF header-injection rejection.
- [ ] **A-19** SPF alignment enforced against the configured sending domain. DMARC policy is
      DMARC-aware and fail-closed per configured policy. DNS records are **verified and reported**,
      never automatically mutated.
- [ ] **A-20** DKIM signing supports the contracted RSA and/or ed25519 key types, signs the exact
      bytes transmitted, never exposes private keys; key rotation and selector/domain alignment are
      observable.
- [ ] **A-21** Spam/content scoring returns an **explainable** score and rule set. Quarantine
      review/release re-evaluates current policy and is narrow, expiring, attributable, and
      revocable.
- [ ] **A-22** Every policy decision is attributable, durable, tamper-evident, PII-minimized, and
      free of subject/body/MIME/private-key/credential material.

---

## 8. MCP surface obligations

Sources: ARCHITECTURE §3.4; validation IR §3.1; TS-IR §6.

- [ ] **M-1** Standalone MCP server with **stdio and streamable HTTP** transports (A-12).
- [ ] **M-2** Tools `email_send`, `email_status`, `email_bounces`, `email_stats` with stable
      schemas.
- [ ] **M-3** `email_send` accepts a **strict superset** of the Jaisiu schema: `to`, `subject`,
      `text`, `html`, `from`, `replyTo`, `cc`, `bcc`, `requestId`; `requestId` is **required**.
- [ ] **M-4** Tool calls resolve a principal/tenant and traverse the same authz → policy →
      idempotency path as HTTP. No tool bypasses policy.
- [ ] **M-5** MCP errors use stable codes with sanitized details; secrets never appear in error
      payloads.
- [ ] **M-6** Results preserve `deliveryConfirmed` semantics and the shared status vocabulary.
- [ ] **M-7** The stdio principal identity/tenant is explicit in configuration and audit even
      though the caller is local.
- [ ] **M-8** The MCP surface is discoverable by an ordinary MCP client with no Jaisiu-specific
      coupling.

---

## 9. HTTP API obligations

Sources: C8 (binding for the wire contract); operator IR §3–§8; ARCHITECTURE §3.3; TS-IR §7.

### 9.1 Route table (canonical)

| Method | Path | Scope | Idempotent | Semantics |
|---|---|---|---|---|
| GET | `/health` | public | n/a | Liveness `200 {"status":"ok"}`; touches no DNS, SMTP, or store |
| GET | `/healthz` | public | n/a | Exact-match alias of `/health` |
| GET | `/ready` | `read` (optional) | n/a | Readiness per dependency; sanitized |
| GET | `/readyz` | `read` (optional) | n/a | Exact-match alias of `/ready` |
| POST | `/v1/email/send` | `send` | **required** | Submit one message → `202 {id,status:"queued",…}` only after durable admission |
| POST | `/send` | `send` | **required** | Compatibility alias of `/v1/email/send` (A-9) |
| GET | `/v1/messages` | `read` | n/a | Paginated list/filter (status, recipient hash, window, tenant) |
| GET | `/v1/messages/{id}` | `read` | n/a | Envelope recipients, timestamps, attempts, status, sanitized last SMTP code |
| POST | `/v1/messages/{id}/retry` | `admin` | **required** | Operator requeue of a failed/deferred/bounced message |
| POST | `/v1/messages/{id}/suppress` | `admin` | **required** | Operator suppression |
| GET | `/v1/bounces` | `read` | n/a | Paginated bounce list, sanitized DSN reasons |
| GET | `/v1/stats` | `read` | n/a | Tenant status aggregates |
| POST | `/v1/events` | `feedback` | **required** | Authenticated DSN/provider feedback intake |
| GET | `/metrics` | `read` or config-public | n/a | Prometheus exposition; disabled by default |

### 9.2 Operator management routes (operator IR §3.2)

- [ ] **H-1** `GET|POST /v1/domains`, `GET|PATCH|DELETE /v1/domains/{domain}`,
      `POST /v1/domains/{domain}/verify`, `GET /v1/domains/{domain}/dns`.
- [ ] **H-2** `GET|POST /v1/identities`, `GET|PATCH|DELETE /v1/identities/{id}`,
      `POST /v1/identities/{id}/rotate`.
- [ ] **H-3** `GET|POST /v1/policies`, `GET|PATCH|DELETE /v1/policies/{id}` — including
      unlimited-cap confirmation and contradictory-policy rejection.
- [ ] **H-4** `GET /v1/queue`, `GET /v1/queue/{id}`, `POST /v1/queue/{id}/cancel`,
      `POST /v1/queue/retry-failed` — idempotent mutation semantics.
- [ ] **H-5** `GET|POST /v1/suppressions`, `DELETE /v1/suppressions/{email}`.
- [ ] **H-6** `GET|POST /v1/api-keys`, `DELETE /v1/api-keys/{id}` — returns identifiers, never raw
      secrets.
- [ ] **H-7** `GET /v1/reports/delivery`, `GET /v1/reports/reputation`, `GET /v1/reports/audit`.
- [ ] **H-8** `POST /v1/feedback/dsn`, `POST /v1/feedback/fbl`.
- [ ] **H-9** `POST /v1/email/batch`.
- [ ] **H-10** `GET /v1/unsubscribe?t=` — token-signed RFC 8058 one-click endpoint; public.
- [ ] **H-11** `GET /v1/openapi.json`.

### 9.3 Cross-cutting HTTP semantics

- [ ] **H-12** Every route except the public manifest requires authentication. The public manifest
      is enumerable at runtime so `railgun doctor` can report the public surface.
- [ ] **H-13** Bearer and `X-Api-Key` accepted; API keys compared in constant time.
- [ ] **H-14** `Idempotency-Key` handled on mutating routes; independent from body `request_id`
      (A-8).
- [ ] **H-15** Tenant isolation: every principal maps to exactly one tenant; cross-tenant access
      returns `404` (never `403` — no existence oracle).
- [ ] **H-16** Error envelope is exactly `{error:{code,message,details?},request_id}` with a
      stable uppercase `code` from the published registry (A-5, A-6, A-7).
- [ ] **H-17** Status discipline includes `401 UNAUTHORIZED`, `403 FORBIDDEN`,
      `400 INVALID_REQUEST`, `409 IDEMPOTENCY_CONFLICT`, `429 QUOTA_EXCEEDED`/`RATE_LIMITED` with
      `Retry-After` and `reset_at`, `422 SPAM_POLICY_DENIED`, `202 QUARANTINED`.
- [ ] **H-18** Pagination is stable and cursor-based where the operator IR specifies it.
- [ ] **H-19** No secret, private key, SMTP AUTH transcript, message body, or stack trace appears in
      any response, log, metric label, audit payload, or `Location`/`ETag` header.
- [ ] **H-20** One semantic model behind HTTP, CLI, and MCP; the CLI does not duplicate policy
      logic.

---

## 10. Operator CLI obligations

Sources: operator IR §3.3/§8.3/§9; ARCHITECTURE §10; TS-IR §8.

### 10.1 Command tree (canonical)

```
railgun
├── serve            --stdio | --http [--host] [--port] [--smtp]
├── doctor                              # readiness + checklist
├── health                              # liveness summary
├── send              --to --subject [--body-file|--text|--html] [--request-id] ...
├── send --batch --file <json>
├── admin create-admin                  # first-admin bootstrap
├── domains        list|add|show|update|remove|verify|dns
├── identities     list|create|show|update|rotate|remove
├── policies       list|create|show|update|remove
├── messages       list|show|retry
├── queue          list|show|cancel|retry-failed
├── suppressed     list|add|remove
├── keys           list|create|revoke
├── report         delivery|reputation|audit
└── unsub          test
```

- [ ] **C-1** All commands above exist. `railgun serve --stdio`, `--http`, and `--smtp` are
      available; flags may be combined.
- [ ] **C-2** `railgun doctor` validates configuration, store, queue writability, outbound
      mode/DNS/TLS prerequisites, identity/policy consistency, and credential **presence only**;
      it never prints secret values and returns non-zero for blocking failures.
- [ ] **C-3** `railgun admin create-admin` bootstraps the first admin using a one-time setup token
      or an approved environment/secret-file input, and forces credential rotation.
- [ ] **C-4** Aliases are permitted but **one canonical spelling must exist** for each command
      (`suppress` vs `suppressed`, `bounce list` vs `bounces list`) and every alias converges on
      one application path.
- [ ] **C-5** `--json` emits exactly one JSON document whose shape matches the HTTP projection.
- [ ] **C-6** Global flags `--json`, `--url`, `--api-key`, `--profile`, `--yes`, `--timeout`,
      `--verbose`, `--no-color` behave as specified in operator IR §3.4. `--verbose` NEVER contains
      secrets.
- [ ] **C-7** Destructive operations support `--yes`; the CLI never prompts when stdin is not a
      TTY; exit codes are stable for usage/auth/policy/not-found failures.
- [ ] **C-8** Secrets are accepted only via `--secret-file` or `--secret-stdin` — never as a
      literal command-line value — and are never echoed.
- [ ] **C-9** The CLI is a thin client over the same application services. `--url` uses HTTP;
      local mode uses in-process services with identical results.

---

## 11. Testing and verification obligations

Sources: validation IR §4–§9 (binding for what is tested); TS-IR §9.

- [ ] **V-1** Vitest unit, integration, end-to-end, and live levels live in the standalone package
      and run without the monorepo root.
- [ ] **V-2** An in-package **fake MX/SMTP sink** supports scripted greetings, TLS, `STARTTLS`,
      per-recipient responses, and `4xx`/`5xx` outcomes.
- [ ] **V-3** SMTP conformance coverage: transaction states, dot-unstuffing, limits,
      `PIPELINING`, partial acceptance, reply codes, post-`STARTTLS` reset, command gating.
- [ ] **V-4** Direct MX coverage: resolution/selection, IPv4/IPv6 fallback, TLS enforcement and
      certificate failure, per-recipient delivery, `4xx` deferral, `5xx` bounce, backoff, host
      rotation, DSN parsing.
- [ ] **V-5** Every policy gate is covered with an assertion of **zero SMTP transactions** on
      rejection.
- [ ] **V-6** Authn/authz coverage: JWT audience/expiry, constant-time API-key behaviour, tenant
      isolation, quotas, rate limits, warmup, suppression, quarantine, operator-scope enforcement.
- [ ] **V-7** HTTP route/status/body coverage, MCP schema/transport coverage, CLI exit-code and
      JSON coverage.
- [ ] **V-8** Restart durability for queue, attempt history, idempotency, suppression, quotas, and
      audit; an idempotent replay produces **zero** extra SMTP transactions.
- [ ] **V-9** Crash-window/uncertain-attempt visibility; no concurrent duplicate worker claims.
- [ ] **V-10** The validation IR scenario matrix **S1–S26** is covered, including header
      injection, payload caps, malformed addresses, TLS-required sink, relay failover, and Bcc
      non-transmission. (The validation IR's own coverage table is the authority for what each
      scenario asserts.)
- [ ] **V-11** Every test run performs a **leak scan** over logs, reports, snapshots, fixtures,
      audit rows, and other artifacts for SMTP passwords, API keys/tokens, DKIM private keys, and
      their encodings. Failures report only artifact path, needle label, and byte offset — never
      the secret or the matched line.
- [ ] **V-12** The controlled live-delivery gate uses only operator-approved recipients,
      environment/secret-file credentials, a fixed synthetic body, and a temporary store. Missing
      credentials or recipient cause an explicit **skip**, never a pass.
- [ ] **V-13** Live evidence records message IDs, timestamps, status transitions, SMTP codes, and
      the leak-scan result only, and is honestly described as **provider acceptance** (terminal
      SMTP `250`), not mailbox-observed delivery, unless a DSN proves delivery.
- [ ] **V-14** The repository-wide credential scan (validation IR §7.1, AC12) is satisfied for
      the package tree.

---

## 12. Packaging and deployment obligations

Sources: ARCHITECTURE §2/§12/§13/§14; plan delta; TS-IR §10.

- [ ] **K-1** `packages/railgun/package.json` is standalone: name `railgun`, ESM (`type: module`),
      bin `railgun`, GPL-3.0-or-later licence metadata, build/test/start scripts, and all runtime
      dependencies declared locally.
- [ ] **K-2** `packages/railgun/tsconfig.json` builds TypeScript to runnable Node 22+ output. **No**
      Cargo, `rust-toolchain`, Rust source, or Rust-only build step exists anywhere in the
      package.
- [ ] **K-3** `npm install && npm run build` succeeds from a fresh clone of the package with zero
      Jaisiu configuration, followed by an immediately usable `railgun` command.
- [ ] **K-4** GPL-3.0 `LICENSE` present; **every** source file carries a GPL-3.0-or-later header.
- [ ] **K-5** `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `docs/SECURITY.md`,
      `.gitignore`, `.dockerignore` are present and aimed at a standalone TS/npm audience.
- [ ] **K-6** `config/railgun.example.yaml` contains non-secret defaults only; `outbound.mode`
      defaults to `direct`; the rest of the config vocabulary stays compatible with the IRs.
- [ ] **K-7** Config precedence: shipped YAML defaults → explicit config path → environment
      overlay. Invalid configuration prevents startup/readiness rather than silently degrading.
- [ ] **K-8** Secrets are accepted via environment / secret file / secret mount and never
      committed.
- [ ] **K-9** Dockerfile is multi-stage `node:22-slim`, runs as a **non-root** user, includes a
      `HEALTHCHECK`, and contains no build-time secrets. Compose provides persistent state and
      optional dependencies without requiring Jaisiu.
- [ ] **K-10** The public README explains direct-MX DNS/port-25/reputation responsibilities and
      the optional relay fallback.
- [ ] **K-11** Retention, export, and residency behaviour per ARCHITECTURE §13 is configured and
      documented.

---

## 13. Cross-cutting invariants

These hold across every surface. A change that violates one is a defect, not a design choice.

1. **No open relay.** Default configuration cannot send as an arbitrary principal, domain, or to
   an arbitrary destination.
2. **Durability before acknowledgement.** `queued`/`202` is returned only after the message, the
   decision, and the idempotency result are durably committed.
3. **One logical request, one send.** A replay returns the stored outcome and causes no second
   SMTP transaction.
4. **Truthful delivery reporting.** Queue acceptance, remote acceptance, and DSN-confirmed
   delivery remain distinct.
5. **Policy before transport.** Every deny/throttle/quarantine/suppress decision precedes any
   SMTP transaction.
6. **Exact bytes on retry.** Retries never mutate the transmitted message or duplicate
   idempotency.
7. **Recipient-scoped feedback.** A DSN or complaint suppresses only the affected recipient.
8. **Fail closed.** Missing/invalid auth, policy, store, or audit state prevents delivery rather
   than permitting an unaudited send.
9. **Secret and content hygiene.** No credential, private key, body, or MIME content appears in
   logs, errors, audit, metrics, status responses, or test artifacts.
10. **No harness dependency.** The package builds, tests, and runs standalone; Jaisiu is an
    optional consumer, never a runtime requirement.

---

## 14. Implementation unit order (dependency order)

| Unit | Scope | Depends on |
|---|---|---|
| A | Foundation: package metadata, TS build, config/env overlay/validation, doctor support, docs, licence, Docker/Compose | — |
| B | Domain/persistence: types, ports, SQLite + memory stores, outbox leases, idempotency, suppression, bounces, audit chain, retention | A |
| C | SMTP submission: server, RFC 5321 subset, policy integration, partial acceptance | B |
| D | Direct MX delivery: DNS, TLS, per-recipient transaction, classification, retry, DSN | B, C |
| E | Anti-spam/compliance: authn/authz, quotas, rate limits, warmup, suppression/blocklists, content scoring, DKIM/SPF/DMARC | B, C |
| F | MCP: stdio + streamable HTTP transports and the four tools | B, E |
| G | HTTP API: canonical routes plus operator projections | B, E |
| H | Operator CLI: serve modes, doctor, admin, messages, stats, bounces, suppression, queue | F, G |
| I | Verification/hardening: unit/integration/E2E/live matrix, fake MX, leak scan, restart and concurrency tests, standalone install/build verification | C, D, E, F, G, H |

---

## 15. Traceability index

Obligation ID → primary source. Use this to confirm every checklist row is anchored.

| ID range | Primary source | Anchor |
|---|---|---|
| D-1…D-12 | SMTP-pipeline IR §2–§3; ARCHITECTURE §3.1 | Identifier vocabulary, state machine |
| P-1…P-14 | ARCHITECTURE §4; SMTP-pipeline IR §3–§6; anti-spam IR §6 | Message model, ports, durability |
| S-1…S-25 | SMTP submission server IR §2–§9; ARCHITECTURE §3.2 | Listener, TLS, session, codes, recipients |
| X-1…X-20 | Outbound delivery engine IR §2–§9; ARCHITECTURE §3.1/§4.3 | MX, TLS, classification, retry, DSN |
| A-1…A-22 | Anti-spam IR §3–§14; ARCHITECTURE §5–§7 | Auth, policy order, quotas, signing |
| M-1…M-8 | ARCHITECTURE §3.4; validation IR §3.1 | MCP surface |
| H-1…H-20 | HTTP API IR §2–§6; operator IR §3–§8; ARCHITECTURE §3.3 | Routes, envelopes, auth, errors |
| C-1…C-9 | Operator IR §3.3/§8.3/§9; ARCHITECTURE §10 | CLI tree, flags, exit codes |
| V-1…V-14 | Validation IR §4–§9 | Scenario matrix, leak scan, live gate |
| K-1…K-11 | ARCHITECTURE §2/§12/§13; plan delta | Packaging, config, deployment |
| A-1…A-14 (§3) | C7 §0.2, C8 §0.4, operator IR §6–§8, validation IR §0.2 | Conflict resolutions |

---

## 16. Completion criteria

RailGun is contract-complete only when:

- [ ] Every obligation in §§2–12 is implemented or explicitly waived in the owning unit's
      evidence.
- [ ] A fresh package-only clone passes `npm install`, `npm run build`, `npm test`, and a
      zero-configuration startup/`railgun doctor` smoke test.
- [ ] The fake-MX suite proves direct delivery, deferral, bounce, suppression, retry, and restart
      semantics with truthful `deliveryConfirmed`.
- [ ] HTTP, MCP, SMTP, and CLI surfaces expose the same message/status truth and idempotency
      behaviour.
- [ ] Leak scans pass for every test artifact set, including live-gate artifacts.
- [ ] No source file depends on Jaisiu harness imports, and every source file carries the
      GPL-3.0-or-later header.
- [ ] AMB-1 and AMB-2 are decided in writing by the owning unit's evidence.
