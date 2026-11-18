# RailGun TypeScript Implementation Contract IR

**Status:** normative implementation checklist for JAISIU-4916
**Type:** language-neutral semantic IR; no implementation code
**Canonical package:** `packages/railgun`
**Implementation profile:** TypeScript on Node.js 22+, ESM, standalone npm package, GPL-3.0-or-later
**Primary outbound mode:** direct-to-MX; operator-configured relay is an explicit fallback

This document translates the canonical architecture and granular IRs into a binding checklist for
the TypeScript implementation. It does not create a second architecture and does not replace the
source contracts. Where an older source mentions Rust, Cargo, Axum, Tokio, Axum/Axum-era file
names, or a Rust-specific deployment layout, only the implementation technology changes; the
behaviour, identifiers, state transitions, policies, and acceptance obligations remain binding.

## 0. Source-contract resolution

Every abbreviated IR path resolves to the following repository document. These are the complete
authoritative inputs for this checklist.

| Contract | Resolved path | Role |
|---|---|---|
| Canonical architecture | `packages/railgun/docs/ARCHITECTURE.md` | Primary service, persistence, auth, policy, audit, operator, deployment, and controlled-test contract |
| Whole-service IR | `docs/design/railgun-architecture-ir.md` | Upstream neutral service IR; specializes the architecture's surface contract |
| SMTP pipeline IR | `docs/design/JAISIU-4915-RAILGUN-SMTP-PIPELINE-IR.md` | Transaction state machine, identifier vocabulary, idempotency boundary, retry algebra, normalization, safe-failure rules |
| Outbound delivery IR | `docs/design/9b5afdc7-6199-4078-a4db-40b1435b66a4-railgun-outbound-delivery-engine-ir.md` | MX resolution, TLS, SMTP response classification, per-recipient outcomes, retry and observability |
| Anti-spam IR | `docs/design/ca1f5105-1de3-47ae-a45f-0cdfd618537a.md` | Authentication/authorization, quotas, rate limits, warmup, spam scoring, blocklists, feedback, auditability |
| Operator API/CLI IR | `docs/design/252d0e90-dbf6-4e9d-ba46-1ea3eccede40.md` | Operator projections, shared security envelope, management HTTP and CLI behaviour |
| Validation IR | `docs/design/3019b185-7284-4c91-8b28-d9d61d3f44ce.md` | Scenario matrix, local fake-MX fixture requirements, live gate and leak scan |
| TypeScript design | `docs/design/748e1599-56a5-469c-acbd-ff022d0e72a1.md` (design handoff resolves it to the workspace-level artifact) | TypeScript/Node 22+, direct-MX-primary, standalone-install delta |
| Repository map | `CODEMAP.md` | Confirms `packages/` is the publishable/service boundary and harness `src/` is not a RailGun dependency |
| Repository architecture | `ARCHITECTURE.md` | Confirms monorepo boundaries and existing service conventions |

**Authority.** In a conflict, the more specific granular IR controls its subject; the canonical
architecture controls the overall service contract; the frozen plan deltas control language,
packaging, licensing, and the direct-MX default. This IR only indexes and makes those obligations
checkable.

## 1. Canonical identifiers and result vocabulary

The implementation MUST preserve these distinct concepts:

- `request_id`: caller-supplied idempotency key; required and non-empty.
- `prism_id` / principal / tenant: authenticated identity scope.
- RailGun message ID: durable internal message identifier.
- RFC `Message-ID`: deterministic message identifier, distinct from the RailGun ID.
- Queue ID and per-recipient delivery-attempt ID.

The legacy logical idempotency key MUST remain byte-identical to
`email:idempotency:{prism_id}:{action}:{request_id}` so migration cannot double-send. HTTP
`Idempotency-Key` and MCP `requestId` map to the same logical identity.

Public status vocabulary MUST distinguish: `queued`, `accepted`/`sent`, `delivered`, `deferred`,
`bounced`, `failed`, `rejected`, and `suppressed`. `deliveryConfirmed` is true only after an
observed terminal SMTP `250` for the relevant delivery; queued acceptance is never confirmation.
Where the canonical API uses `accepted`, the implementation MAY expose `sent` internally but MUST
not conflate it with DSN-confirmed `delivered`.

## 2. Domain, ports, and persistence checklist

- [ ] Define message, envelope/recipient, status, policy decision, delivery attempt, bounce,
      suppression, quota, idempotency, and audit-event types.
- [ ] Preserve the three recipient sets `to`, `cc`, `bcc`; Bcc recipients are envelope-only and
      MUST NOT appear in transmitted headers or normal operator projections.
- [ ] Keep the envelope authoritative for delivery. Header recipients MUST NOT widen the envelope.
- [ ] Define ports for store, queue, clock, ID generation, transport, secret provider, DNS, and
      audit; production adapters MUST NOT depend on Jaisiu harness modules.
- [ ] Provide a SQLite store using Node 22 built-ins or a self-contained dependency, plus an
      in-memory store for tests. The package MUST install and build without the monorepo root.
- [ ] Persist messages, per-recipient outcomes, durable outbox entries, idempotency records,
      suppression, bounce records, quota/rate counters, and policy/audit state.
- [ ] Atomically commit idempotency result and queue admission. A repeated request with the same
      normalized fingerprint MUST replay the original result and cause no second send; a different
      fingerprint MUST fail with `IDEMPOTENCY_CONFLICT`.
- [ ] Queue claims MUST be atomic compare-and-set/lease based. A single message MUST NOT be
      attempted concurrently by two workers.
- [ ] Queue entries MUST survive restart, preserve ordering/priority semantics, expose
      `available_at`, attempts, maximum attempts, and stable last-error code.
- [ ] Record attempt start and outcome separately. A crash after remote `250` but before outcome
      persistence leaves an explicit unresolved/uncertain record; recovery MUST NOT silently
      duplicate or erase it.
- [ ] Attempt exhaustion is a terminal reason distinct from an SMTP `5xx`; the last observed SMTP
      code remains unchanged.
- [ ] Audit is append-only NDJSON, hash-chained, durable before a final policy decision, PII
      minimized, retention-aware, and supports verification/retention cleanup.
- [ ] Retention, export, and deletion semantics apply to bodies, recipient data, idempotency,
      queue/journal data, quotas, and audit records according to configuration.

## 3. SMTP submission checklist

- [ ] Listen on configurable submission address; default `0.0.0.0:2525`. Implicit TLS submission
      may be separately configured, typically on `465`. Port `25` requires explicit operator
      opt-in.
- [ ] Implement the RFC 5321 subset: `EHLO`, `HELO`, `STARTTLS`, `AUTH PLAIN`, `AUTH LOGIN`,
      `MAIL FROM`, `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT`. `AUTH XOAUTH2` remains optional.
- [ ] Advertise `PIPELINING` only after TLS; accept `8BITMIME` and normalize stored bytes to
      canonical SMTP/MIME bytes; advertise `SMTPUTF8` only when supported and configured.
- [ ] Enforce command syntax, transaction ordering, size limits, timeouts, and safe failures.
- [ ] Use stable response semantics: `250` durable acceptance; `450/451` transient; `550/551/553`
      permanent; `552` size exceeded; `554` policy/spam rejection.
- [ ] Dot-unstuff DATA terminator handling correctly and preserve exact transmitted bytes across
      retries.
- [ ] Accept repeated `RCPT TO`; authorize and rate-limit each recipient; report partial
      acceptance per recipient; require at least one valid recipient and valid sender context.
- [ ] Authentication is required on restricted listeners. AUTH is never accepted over an
      insecure channel unless explicitly configured for local/test use.
- [ ] The listener is not an open relay: submission is limited to authenticated/authorized
      principals and configured/allow-listed sending domains.
- [ ] SMTP submission and outbound SMTP are separate protocol roles and MUST NOT share transaction
      state or accidentally accept inbound delivery as an outbound queue action.

## 4. Direct-to-MX outbound delivery checklist

- [ ] Direct MX is the default outbound mode; relay mode is operator-selected fallback, not the
      default and not required for normal operation.
- [ ] Resolve the recipient domain with `node:dns/promises`: query MX records, order by ascending
      preference then deterministic tiebreak, resolve A and AAAA for selected hosts, and cache only
      within TTL/configured maximum.
- [ ] Support IPv4 and IPv6 fallback with a documented deterministic preference. Support implicit
      MX for address literals only when policy permits.
- [ ] Temporary DNS failure defers (`dns_temporary`); no MX/null MX is a permanent classification
      (`dns_no_mx`/`mailbox_unavailable`).
- [ ] Do not connect to a host outside the resolved MX set.
- [ ] Connect using configured timeouts and per-host connection limits. Timeout, refusal, reset,
      and transient network failures defer and never appear successful.
- [ ] SMTP dialogue: greet, `EHLO`/`HELO`, `MAIL FROM`, per-recipient `RCPT TO`, `DATA`, and
      `QUIT` when the session is alive.
- [ ] Opportunistic STARTTLS by default, with TLS >= 1.2 and full certificate-chain and hostname
      verification. Invalid certificates MUST NOT be accepted. A configurable hard-fail mode MUST
      prevent plaintext fallback; at minimum, documented policy must never silently bypass TLS.
- [ ] Record TLS mode/protocol/cipher and safe certificate fingerprint metadata.
- [ ] Perform per-recipient transactional delivery so one recipient's failure does not corrupt
      another recipient's outcome.
- [ ] Classify SMTP `4xx` as transient deferral, `5xx` as permanent bounce, and relay/auth/TLS
      failures according to the outbound IR's stable error vocabulary.
- [ ] Retry deferred recipients with bounded exponential backoff plus jitter, honoring retry hints.
      Maximum attempts is finite/configurable; exhaustion becomes terminal without inventing a `5xx`.
- [ ] Rotate to the next eligible MX host after a host failure; apply per-host cooldown and
      quarantine for persistent TLS-policy rejection.
- [ ] Preserve request ID, message ID, and exact bytes across retries without duplicating the
      idempotency record.
- [ ] Generate a deterministic RFC `Message-ID` that is stable for a logical request.
- [ ] Parse DSN/feedback sufficiently to produce delivery confirmation or recipient-scoped
      suppression. Hard DSN `5.1.1`/`5.1.10` suppresses that recipient; soft DSN MAY increment a
      soft-bounce counter and MAY create only a time-bounded suppression.
- [ ] A DSN MUST NOT create wildcard/domain-wide suppression. Feedback ingest MUST be
      authenticated or HMAC/token-signed.
- [ ] Detect and reject delivery loops.
- [ ] Emit durable structured attempt events and metrics for attempts, outcomes, TLS failures,
      queue depth, in-flight work, cooldowns, duration, and end-to-end latency.

## 5. Anti-spam, compliance, and policy checklist

- [ ] Default configuration denies sending. Missing identity/auth configuration fails closed.
- [ ] Authentication supports bearer API key and JWT. JWT validation MUST verify signature, expiry,
      issuer, and exact audience. API keys are compared in constant time and stored as salted
      Argon2id hashes with non-secret key IDs for audit attribution.
- [ ] Credential input supports secret-file/`_FILE` indirection and secret mounts. Secrets MUST NOT
      appear in logs, audit, metrics, queue rows, URLs, errors, or source.
- [ ] Principal roles/scopes include send, batch send, status read, suppression write, policy read,
      quarantine read/release, blocklist write, and feedback ingest. Ordinary clients MUST NOT
      perform operator mutations.
- [ ] Tenant is derived from the authenticated principal; a caller cannot select an arbitrary
      tenant. A client may send only from sender domains assigned to its tenant.
- [ ] Run policy gates in the canonical order: parse/validate, authenticate, authorize, idempotency
      replay, recipient validation, block/suppression, quota, rate limit, content/identity checks,
      warmup/reputation, final decision, then atomic decision/queue commit.
- [ ] Decision precedence is `reject` > `deny` > `quarantine` > `throttle` > `allow`; all matched rule
      IDs are auditable.
- [ ] A denied/quarantined/throttled request MUST cause zero SMTP transactions.
- [ ] Enforce independently durable quota dimensions: tenant messages/recipients per rolling day,
      sender-domain messages, recipient messages per rolling hour, principal messages, and optional
      batch/recipient ceilings.
- [ ] Enforce tenant/principal and per-recipient rate limits; concurrent bursts MUST NOT overshoot
      limits.
- [ ] Enforce sender/domain warmup schedule and new-recipient limits.
- [ ] Apply global, tenant, domain, recipient, sender, IP, content/hash, and feedback-derived
      blocklists and suppressions.
- [ ] Enforce role-address protection, plaintext alternative, List-Unsubscribe requirements,
      maximum recipients/body/attachment/batch sizes, and header-injection rejection.
- [ ] SPF alignment must be enforced against the configured sending domain; DMARC policy is
      DMARC-aware and fail-closed according to configured policy. DNS records are verified/reported,
      not automatically mutated.
- [ ] DKIM signing MUST support the contracted RSA and/or ed25519 key types, sign the exact bytes
      transmitted, and never expose private keys. Key rotation and selector/domain alignment are
      observable.
- [ ] Spam/content scoring returns an explainable score/rule set; quarantine review/release
      re-evaluates current policy and is narrow, expiring, attributable, and revocable.
- [ ] No-open-relay invariant: arbitrary sender, arbitrary recipient, unauthenticated HTTP/MCP/SMTP
      submission, and direct transport access are denied by default.
- [ ] Every policy decision is attributable, durable, tamper-evident, PII-minimized, and free of
      subject/body/MIME/private-key/credential material.

## 6. MCP surface checklist

- [ ] Provide a standalone MCP server with stdio and streamable HTTP transports.
- [ ] Expose `email_send`, `email_status`, `email_bounces`, and `email_stats` with stable schemas.
- [ ] `email_send` accepts a strict superset of the Jaisiu schema: `to`, `subject`, `text`, `html`,
      `from`, `replyTo`, `cc`, `bcc`, `requestId`; the request ID is required.
- [ ] Tool calls resolve a principal/tenant, apply the same authz/policy/idempotency path as HTTP,
      and do not bypass policy.
- [ ] MCP errors use stable codes and sanitized details; secrets never appear in error payloads.
- [ ] MCP status/results preserve `deliveryConfirmed` semantics and the shared status vocabulary.
- [ ] Stdio principal identity/tenant is explicit in configuration and audit even when local.

## 7. HTTP API checklist

The canonical client-facing surface is:

- [ ] `GET /health`: unauthenticated liveness, `{"status":"ok"}`, no secrets.
- [ ] `GET /ready`: store reachable, queue writable, outbound config present; no secrets.
- [ ] `POST /v1/email/send`: protocol-compatible with the Jaisiu client (`to`, `cc`, `bcc`,
      `subject`, `text`, `html`, `from`, `reply_to`/compatible alias, `idempotency_key`), returning
      `202` and `{id,status:"queued",...}` only after durable queue admission.
- [ ] `GET /v1/messages`: paginated/filterable by status, recipient hash, time window, and tenant.
- [ ] `GET /v1/messages/{id}`: envelope recipients, timestamps, attempts, status, sanitized last SMTP
      code/response; body only with explicit authorization and `include_body=true`.
- [ ] `POST /v1/messages/{id}/retry`: operator-only requeue.
- [ ] `POST /v1/messages/{id}/suppress`: operator-only suppression.
- [ ] `GET /v1/bounces`: sanitized DSN reasons.
- [ ] `GET /v1/stats`: queued, accepted/sent, delivered, deferred, bounced, failed/rejected, and
      suppressed aggregates.
- [ ] `POST /v1/events`: authenticated provider/DSN feedback intake.
- [ ] Bearer and `X-Api-Key` authentication; `Idempotency-Key` handling; stable sanitized errors.
- [ ] HTTP status/code contract includes `401 UNAUTHORIZED`, `403 FORBIDDEN`, `400
      INVALID_REQUEST`, `409 IDEMPOTENCY_CONFLICT`, `429 QUOTA_EXCEEDED`/`RATE_LIMITED` with
      `Retry-After` and `reset_at`, `422 SPAM_POLICY_DENIED`, and `202 QUARANTINED`.

The granular operator IR additionally specifies management projections and routes for domains,
identities, policies, queue, suppressions, API keys, reports, and health. The implementation MUST
provide the operator capabilities required by that IR, including at minimum:

- [ ] Domain/sending-identity management, DNS/DKIM/SPF/DMARC verification projection, and policy
      binding.
- [ ] Policy CRUD with validation (including unlimited-cap confirmation and contradictory-policy
      rejection).
- [ ] Queue list/show/cancel/retry-failed operations with idempotent mutation semantics.
- [ ] Suppression list/add/remove operations.
- [ ] API-key lifecycle that returns identifiers, never raw secrets.
- [ ] Operator report/stat projections and authenticated feedback/DSN ingestion.
- [ ] One semantic model behind HTTP, CLI, and MCP; the CLI does not duplicate policy logic.

Route-name differences in older IRs (`/healthz`/`/readyz`, `/v1/suppressions`) are compatibility
aliases only where cheap. The canonical `/health` and `/ready` paths MUST exist and are authoritative.

## 8. Operator CLI checklist

Required top-level commands:

- [ ] `railgun serve --stdio`, `railgun serve --http`, `railgun serve --smtp` (flags may be combined
      according to the TypeScript design) to run the corresponding surfaces.
- [ ] `railgun doctor`: validates configuration, store, queue writability, outbound mode/DNS/TLS
      prerequisites, identity/policy consistency, and credential presence only; never prints secret
      values; returns non-zero for blocking failures.
- [ ] `railgun admin create-admin`: secure first-admin bootstrap using a one-time setup token or
      approved environment/secret-file input; forces credential rotation.
- [ ] `railgun messages list`, `railgun messages show <id>`, and `railgun messages retry <id>`.
- [ ] `railgun stats`.
- [ ] `railgun bounce list` (or the operator-IR-compatible `railgun bounces list`).
- [ ] `railgun suppress add` and `railgun suppress remove` (operator IR also names
      `railgun suppressed list`); aliasing is permitted but one canonical spelling MUST exist.
- [ ] `railgun queue stats`, `railgun queue list`, `railgun queue show`, `railgun queue cancel`, and
      `railgun queue retry-failed`.

CLI behaviour:

- [ ] It is a thin client over the same application services; `--url` uses HTTP and local mode uses
      in-process services with identical results.
- [ ] `--json` emits exactly one JSON document with the same projection shape as HTTP.
- [ ] Support `--yes` for destructive operations, never prompt when stdin is not a TTY, and use
      stable non-zero exit codes for usage/auth/policy/not-found failures.
- [ ] Secrets are accepted only through `--secret-file` or `--secret-stdin`, never directly as a
      command-line value, and are never echoed.

## 9. Testing and verification checklist

- [ ] Vitest unit, integration, end-to-end, and live test levels are provided in the standalone
      package and runnable without the monorepo root.
- [ ] A local fake MX/SMTP sink is shipped in-package and supports scripted greetings, TLS,
      STARTTLS, per-recipient responses, and `4xx`/`5xx` outcomes.
- [ ] Cover SMTP transaction conformance, dot-unstuffing, limits, PIPELINING, partial acceptance,
      and response codes.
- [ ] Cover direct MX resolution/selection, IPv4/IPv6 fallback, TLS enforcement/certificate
      failure, per-recipient delivery, 4xx deferral, 5xx bounce, backoff, host rotation, and DSN.
- [ ] Cover every policy gate with an assertion of zero SMTP transactions on rejection.
- [ ] Cover authn/authz, JWT audience/expiry, constant-time API key behavior, tenant isolation,
      quotas, rate limits, warmup, suppression, quarantine, and operator-scope enforcement.
- [ ] Cover HTTP routes/status/code bodies, MCP schemas/transports, and CLI exit/JSON contracts.
- [ ] Cover restart durability for queue, attempt history, idempotency, suppression, quotas, and
      audit; cover idempotent replay producing zero extra SMTP transactions.
- [ ] Cover crash-window/uncertain-attempt visibility and no concurrent duplicate worker claims.
- [ ] Cover the validation IR scenario matrix S1-S26, including header injection, payload caps,
      malformed addresses, TLS-required sink, relay failover, and Bcc non-transmission.
- [ ] Every test run performs a leak scan over logs, reports, snapshots, fixtures, audit rows, and
      other artifacts for SMTP passwords, API keys/tokens, DKIM private keys, and their encodings.
      Failures report only artifact path, needle label, and byte offset—not the secret or matched
      line.
- [ ] The controlled live-delivery gate uses only operator-approved recipients, environment/secret
      file credentials, a fixed synthetic body, and a temporary store. Missing credentials or
      recipient cause an explicit skip, never a pass. Evidence records message IDs, timestamps,
      status transitions, SMTP codes, and leak-scan result only.
- [ ] Live evidence is honestly described as provider acceptance (terminal SMTP `250`), not
      mailbox-observed delivery, unless a DSN proves delivery.

## 10. Packaging and deployment checklist

- [ ] `packages/railgun/package.json` is standalone: name `railgun`, ESM (`type: module`), bin
      `railgun`, GPL-3.0-or-later license metadata, build/test/start scripts, and all runtime
      dependencies declared locally.
- [ ] `packages/railgun/tsconfig.json` builds TypeScript to a runnable Node 22+ output. No Cargo,
      `rust-toolchain`, Rust source, or Rust-only build step exists.
- [ ] `npm install && npm run build` works from a fresh clone of the package with zero Jaisiu
      configuration, followed by an immediately usable `railgun` command.
- [ ] GPL-3.0 license file is present and every source file carries a GPL-3.0-or-later header.
- [ ] README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, `.gitignore`, and `.dockerignore` are present
      and aimed at a standalone TS/npm audience.
- [ ] `config/railgun.example.yaml` contains non-secret defaults only; `outbound.mode` defaults to
      `direct` and the rest of the config vocabulary remains compatible.
- [ ] Config precedence is shipped YAML defaults, then explicit config path, then environment
      overlay. Invalid configuration prevents startup/readiness rather than silently degrading.
- [ ] Secrets are accepted via environment/secret file/secret mount and never committed.
- [ ] Dockerfile is multi-stage `node:22-slim`, runs as non-root, includes a health check, and
      contains no build-time secrets. Docker Compose provides persistent state and optional
      dependencies without requiring Jaisiu.
- [ ] Public README explains direct-MX DNS/port-25/reputation responsibilities and the optional
      relay fallback.

## 11. Cross-cutting invariants

1. **No open relay.** Default configuration cannot send as an arbitrary principal, domain, or to an
   arbitrary destination.
2. **Durability before acknowledgement.** `queued`/`202` is returned only after the message,
   decision, and idempotency result are durably committed.
3. **One logical request, one send.** Replay returns the stored outcome and causes no second SMTP
   transaction.
4. **Truthful delivery reporting.** Queue acceptance, remote acceptance, and DSN-confirmed delivery
   remain distinct.
5. **Policy before transport.** Every deny/throttle/quarantine/suppress decision precedes any
   SMTP transaction.
6. **Exact bytes on retry.** Retries never mutate the transmitted message or duplicate idempotency.
7. **Recipient-scoped feedback.** A DSN/complaint suppresses only the affected recipient.
8. **Fail closed.** Missing/invalid auth, policy, store, or audit state prevents delivery rather
   than permitting an unaudited send.
9. **Secret and content hygiene.** No credential, private key, body, or MIME content appears in
   logs, errors, audit, metrics, status responses, or test artifacts.
10. **No harness dependency.** The package builds, tests, and runs standalone; Jaisiu is an optional
    consumer, never a runtime requirement.

## 12. Resolved ambiguities and required implementation decisions

The following older-contract tensions are resolved by the frozen TypeScript delta without
redesigning behaviour:

1. **Language and layout:** Rust/Cargo/Axum/Tokio references become TypeScript/Node 22+/native
   Node networking and a standalone npm package. File-layout illustrations are non-binding.
2. **Outbound default:** direct-to-MX is primary. Relay mode remains fully supported but is
   opt-in/fallback.
3. **License wording:** the package uses GPL-3.0-or-later, superseding older “GPL-3.0-only” text.
4. **Health paths:** `/health` and `/ready` are canonical; `/healthz` and `/readyz` are optional
   compatibility aliases.
5. **Suppression route/command:** canonical `POST /v1/messages/{id}/suppress` remains; operator list
   management may also use `/v1/suppressions`. CLI aliases must converge on one application path.
6. **Attempt exhaustion:** terminal attempt exhaustion is not recorded as a bounce; it has its own
   stable reason while preserving the last observed SMTP code.
7. **CLI mode:** HTTP `--url` and local in-process operation are both supported; both call the same
   application services.
8. **MCP transports:** both stdio and streamable HTTP are required by the frozen plan even where an
   older architecture described only one MCP exposure.
9. **Test location:** tests live in the package and use Vitest; root monorepo test configs may be
   reused only as an integration convenience, never as a runtime/dependency requirement.

The following remain implementation choices, not contract gaps: SQLite binding, YAML parser, CLI
library, HTTP/MCP framework, SMTP parser library, metrics exposition format, and exact internal
folder names. Implementations MUST NOT change the observable semantics above to accommodate those
choices.

## 13. Unit dependency order

Implement and validate in this order so later units have stable contracts:

1. **A — Foundation:** package metadata, TS build, config/env overlay/validation, doctor support,
   standalone docs, license, Docker/Compose.
2. **B — Domain/persistence:** types, ports, SQLite/memory stores, outbox leases, idempotency,
   suppression, bounces, audit chain, retention.
3. **C — SMTP submission:** server and RFC 5321 subset, policy integration, partial acceptance.
4. **D — Direct MX delivery:** DNS, TLS, per-recipient transaction, classification, retry, DSN.
5. **E — Anti-spam/compliance:** authn/authz, quotas/rate limits/warmup, suppression/blocklists,
   content scoring, DKIM/SPF/DMARC policy.
6. **F — MCP:** stdio and HTTP transports and the four tools.
7. **G — HTTP API:** canonical routes plus operator projections.
8. **H — Operator CLI:** serve modes, doctor, admin, messages, stats, bounces, suppression, queue.
9. **I — Verification/hardening:** unit/integration/E2E/live matrix, fake MX, leak scan, restart
   and concurrency tests, standalone install/build verification.

## 14. Completion checklist

RailGun is contract-complete only when:

- [ ] Every checked item in §§1-13 is implemented or explicitly waived in the owning unit's
      evidence.
- [ ] A fresh package-only clone passes `npm install`, `npm run build`, `npm test`, and a
      zero-configuration startup/doctor smoke test.
- [ ] The fake-MX suite proves direct delivery, deferral, bounce, suppression, retry, and restart
      semantics with truthful `deliveryConfirmed`.
- [ ] HTTP, MCP, SMTP, and CLI surfaces expose the same message/status truth and idempotency
      behaviour.
- [ ] Leak scans pass for every test artifact set, including live-gate artifacts.
- [ ] No source file depends on Jaisiu harness imports and every source file carries the required
      GPL-3.0-or-later header.
