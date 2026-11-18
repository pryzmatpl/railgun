<!--
  RailGun HTTP API documentation.
  Copyright (C) 2026 RailGun contributors.
  SPDX-License-Identifier: GPL-3.0-or-later
-->

# RailGun HTTP API

The versioned operator API of RailGun. It is a standalone service: it depends
only on the ports under `src/http/`, never on the Jaisiu monorepo.

The normative contract is `docs/design/railgun-http-api-ir.md`; this document
describes the shipped implementation.

## Base paths

| Path | Purpose |
|---|---|
| `/v1` | Stable operator API. Additive response fields and new filters are permitted within `/v1`. |
| `/send`, `/v1/email/send` | Email submission. `/send` is a first-class alias with identical semantics. |
| `/health`, `/healthz`, `/ready`, `/readyz` | Liveness and readiness. Exact path match only — `/health/anything` is a `404`. |

## Authentication

Three credential presentations are accepted:

| Presentation | Form |
|---|---|
| API key | `Authorization: Bearer <api-key>` or `x-api-key: <api-key>` |
| JWT | `Authorization: Bearer <jwt>`, audience **must** be `/railgun` (an `/mcp` token is rejected) |
| Webhook HMAC | `X-RailGun-Signature: sha256=<hex>` + `X-RailGun-Timestamp`, only on `POST /v1/events` |

Resolution rules:

- An `x-api-key` header wins over a simultaneous `Authorization: Bearer`
  header — this is the exact shape the frozen Jaisiu client sends.
- A credential matching neither the `rgk_` API-key shape nor the three-segment
  JWT shape is `401 UNAUTHENTICATED`.
- The presented credential is never echoed in a response, a header or a log.

Scopes are additive: `send`, `read`, `admin`, `feedback`, `body:read`.
`admin` does **not** imply `send`. A missing scope is
`403 INSUFFICIENT_SCOPE` with `error.details.required_scope`.

Every principal maps to exactly one tenant, derived from the credential. A
request that names a different tenant is rejected (`400 INVALID_REQUEST`),
and a cross-tenant resource access returns `404 NOT_FOUND` — never `403`, so
the API is not an existence oracle.

## Sending an email

```bash
curl -X POST http://localhost:8080/v1/email/send \
  -H 'x-api-key: rgk_…' \
  -H 'content-type: application/json' \
  -d '{
        "to": "recipient@example.com",
        "subject": "Hello",
        "text": "plain body",
        "request_id": "probe-1"
      }'
```

Response (`202 Accepted`):

```json
{
  "success": true,
  "id": "rg-01J8YQ3M7N2P4R6T8V0W1X3Y5",
  "messageId": "<rg-01J8YQ3M7N2P4R6T8V0W1X3Y5@railgun>",
  "status": "queued",
  "delivery": "queued",
  "deliveryConfirmed": false,
  "request_id": "probe-1",
  "tenant_id": "tenant_acme",
  "created_at": "2026-11-18T10:31:04.123Z",
  "queued_at": "2026-11-18T10:31:04.140Z",
  "accepted_at": null,
  "relayHost": null,
  "mode": "direct"
}
```

**Acceptance is never delivery.** `deliveryConfirmed` is `true` only when the
upstream MX returned a final `250` after `DATA`. A `202 queued` response always
carries `false`.

### Request fields

`to`, `cc`, `bcc`, `subject`, `text`, `html`, `from`, `reply_to`/`replyTo`,
`request_id`/`requestId`, `idempotency_key`, `schedule_at`/`scheduleAt`,
`metadata`, `content_base64`/`contentBase64`, `content_type`/`contentType`.

Snake_case is canonical; the listed camelCase aliases are accepted. Supplying
both spellings with **different** values is `400 AMBIGUOUS_FIELD`; equal values
are accepted.

Recipients accept a single address, an array, or a comma-separated string. A
comma inside a quoted display name is not a separator.

`to`/`cc`/`bcc` define the **envelope** recipient set. Message headers never
widen it and `Bcc` recipients never appear in read projections.

### Partial acceptance

A request with several recipients may accept some and reject others. When at
least one recipient is accepted the response is `202` and carries a
`recipients[]` breakdown; rejected recipients produce no queue row and no
outbound SMTP transaction. When every recipient is rejected, the request fails
with the highest-severity rejection (`SUPPRESSED`, `BLOCKED`, …).

## Idempotency

Two independent identities are enforced:

1. **`Idempotency-Key` header** — a transport-level replay guard on every
   mutating route. The scope is
   `(principal, method, path template, key)`, so two tenants may use the same
   key. A replay with the same body returns the stored response verbatim with
   `Idempotency-Replayed: true`; a replay with a **different** body is
   `409 IDEMPOTENCY_KEY_REUSED`.
2. **`request_id`** — the logical-send identity, joined to the message journal
   row and the audit stream. A repeated `request_id` returns the stored result
   and produces zero additional outbound transactions.

Bodies are compared by their canonical SHA-256 digest, so field order and
dialect spelling do not matter. Authentication and authorization are evaluated
**before** the idempotency lookup, so an unauthenticated request never consumes
an idempotency key.

When a client supplies neither identity (the legacy Jaisiu body), the service
derives one from the canonical body digest, so a repeated identical submission
still produces exactly one durable message.

## Reading

| Route | Scope | Notes |
|---|---|---|
| `GET /v1/messages` | `read` | Paginated, filterable by `status`, `delivery`, `recipient_hash`, `from`, `to`, `domain`, `request_id`, `tag`. Unknown parameters are `400 UNKNOWN_FILTER`. `limit` is 1…200 (`limit=0` is `400 INVALID_LIMIT`). Cursors are signed and bound to their filter set. |
| `GET /v1/messages/{id}` | `read` | Single resource. The body is returned only with `?include_body=true` **and** the `body:read` scope; otherwise the body field is omitted entirely. |
| `GET /v1/bounces` | `read` | Sanitized DSN projections — the raw remote response text is never returned. |
| `GET /v1/stats` | `read` | Totals and buckets. `delivery_rate` is `null` when the terminal denominator is zero. |

Cross-tenant identifiers behave exactly like unknown identifiers (`404`).

## Operator actions

| Route | Scope | Notes |
|---|---|---|
| `POST /v1/messages/{id}/retry` | `admin` | Requires `Idempotency-Key`. Requeues a `bounced`/`deferred`/`failed` message with a fresh attempt chain; the message id never changes. |
| `POST /v1/messages/{id}/suppress` | `admin` | Requires `Idempotency-Key`. Idempotent on `(email, scope, domain)` — re-adding returns `200` with `created:false` and the original `created_at`. |

## Feedback intake

`POST /v1/events` accepts a JSON event list or a raw RFC 3464 DSN. It
authenticates by HMAC and is idempotent on the original message id plus
recipient, so a redelivered DSN neither double-counts nor double-suppresses.
The raw body is never echoed back.

## Errors

Every non-2xx response has exactly one shape:

```json
{
  "error": { "code": "SUPPRESSED", "message": "…", "details": { "reason": "hard_bounce" } },
  "request_id": "rq_01J8YQ3M7N2P4R6T8V0W1X3Y5"
}
```

`error.code` is a stable token from the registry in
`src/http/errors.ts` (`INVALID_REQUEST`, `AMBIGUOUS_FIELD`, `AMBIGUOUS_AUTH`,
`UNKNOWN_FILTER`, `INVALID_CURSOR`, `INVALID_LIMIT`, `UNAUTHENTICATED`,
`INSUFFICIENT_SCOPE`, `ACTION_NOT_PERMITTED`, `NOT_FOUND`,
`METHOD_NOT_ALLOWED`, `DOMAIN_NOT_VERIFIED`, `MESSAGE_NOT_RETRYABLE`,
`SUPPRESSION_CONFLICT`, `IDEMPOTENCY_KEY_REUSED`, `PAYLOAD_TOO_LARGE`,
`SUPPRESSED`, `BLOCKED`, `SPAM_POLICY_DENIED`, `POLICY_CONTRADICTION`,
`RATE_LIMITED`, `RATE_LIMITED_BY_POLICY`, `INTERNAL_ERROR`,
`UPSTREAM_UNAVAILABLE`, `NOT_READY`, `UPSTREAM_TIMEOUT`).

The anti-spam spellings `UNAUTHORIZED`, `FORBIDDEN`, `IDEMPOTENCY_CONFLICT` and
`QUOTA_EXCEEDED` are accepted aliases.

Stack traces, file paths, credentials, raw SMTP transcripts, raw DSN bodies and
message bodies never appear in a response, a log line or an audit record.

## Rate limiting

A per-credential token bucket is checked **before** the request body is
parsed. On `429` the response carries `Retry-After` and
`error.details.limit` (`api_key_minute`, `daily_cap`, `recipient_hourly_cap`,
`warmup_daily_cap`). Successful responses carry `X-RateLimit-Limit`,
`X-RateLimit-Remaining` and `X-RateLimit-Reset`.

## Implementation map

```
src/http/
  types.ts        # domain records, ports and configuration
  errors.ts       # error registry and the sanitized envelope
  crypto.ts       # digests, HMAC, signed cursors, recipient hashing
  router.ts       # exact-path route table
  auth.ts         # API key / JWT / webhook HMAC resolution
  authorize.ts    # scopes, tenant isolation, sender authorization
  server.ts       # node:http server, pipeline, idempotency guard, rate limit
  service.ts      # the service container and shared helpers
  responses.ts    # JSON/text writers, ETags, error rendering
  memory.ts       # in-memory port implementations (tests and local mode)
  schemas/send.ts # dual-dialect request normalization and validation
  schemas/projection.ts
  routes/         # health, email, messages, actions, bounces, stats, events
```

Tests live in `test/http/` and boot the real service over a real socket with a
real HTTP client.
