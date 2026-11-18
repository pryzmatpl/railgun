// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Resolutions of the anti-spam IR's open items (IR §18).
//
// Each item below was an explicit question the extraction phase left to the
// implementing unit. The resolution is recorded here so that the choice is
// auditable and so that a later reader does not have to re-derive it.
//
// Reference: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §18.

/**
 * **Item 1 — DKIM implementation dependency.**
 *
 * Resolved: the Node `crypto` built-in. `src/signer/dkim.ts` uses
 * `createSign`/`createHash` for RSA-SHA256 and `sign(null, ...)` for
 * ed25519. No third-party DKIM package is added, which keeps the package
 * standalone-installable with zero configuration.
 *
 * The verifier is independent of the signer: `verifyDkim` re-parses the raw
 * header block, re-derives the body hash from the raw body, re-selects the
 * signed headers from the `h=` tag, and re-computes the signature. It never
 * reads a digest produced by the signer (IR R-7.1.9, V-1).
 *
 * The verification obligation is met by `test/dkim.test.ts`, which signs a
 * message with the production signer and verifies it with the production
 * verifier after re-reading the raw bytes.
 */
export const DKIM_DEPENDENCY_RESOLUTION =
  "node:crypto built-in; no third-party DKIM package; verifier re-derives the hash from the raw message";

/**
 * **Item 2 — public-suffix handling.**
 *
 * Resolved: a small curated multi-label suffix list shipped inside
 * `src/security/address.ts` (`organizationalDomain`). A dependency on a
 * public-suffix list would mean either a package dependency or a bundled data
 * file, and the package must install and run with zero configuration.
 *
 * The list covers the multi-label suffixes that matter for alignment
 * decisions; an unknown suffix falls back to the last two labels, which is
 * the conservative strict-alignment answer.
 *
 * The alignment **default is `strict`** (exact match), as the IR requires.
 * `relaxed` compares organizational domains and accepts a subdomain
 * relationship. Both are configurable per sending domain.
 */
export const PUBLIC_SUFFIX_RESOLUTION =
  "curated in-package multi-label suffix list; strict alignment is the default";

/**
 * **Item 3 — DNS resolver port contract.**
 *
 * Resolved: the `DnsResolver` port in `src/ports/index.ts` exposes a single
 * `resolveTxt(name)` method. The production adapter is backed by
 * `node:dns/promises`; tests substitute `StaticDnsResolver`, so SPF, DMARC and
 * DKIM-record lookups are fully mockable without a network.
 *
 * DNS is the only permitted network egress in the policy path (IR R-4.2).
 */
export const DNS_RESOLVER_RESOLUTION =
  "DnsResolver port with resolveTxt; node:dns/promises in production, a static zone map in tests";

/**
 * **Item 4 — shared rate-limit store.**
 *
 * Resolved: the `RateLimitStore` port in `src/ports/index.ts` exposes
 * `consume` (token bucket) and `reserveQuota` (durable rolling window).
 * The semantics are fixed by the port — atomic check-and-charge, so a
 * concurrent burst cannot overshoot (IR R-9.2.3) — but the storage is not:
 * an in-memory adapter serves a single node, and a shared adapter (Redis or
 * the SQL store) serves a multi-replica deployment.
 *
 * Unit B owns the durable adapters; unit E owns the port contract and the
 * token-bucket / quota arithmetic in `src/spam/limits.ts`.
 */
export const RATE_LIMIT_STORE_RESOLUTION =
  "RateLimitStore port; in-memory adapter for one node, shared adapter for many replicas";

/**
 * **Item 5 — `spam.warmup.*` versus `warmup.*`.**
 *
 * Resolved with an explicit precedence: **the `warmup.*` block wins**, and it
 * overrides `spam.warmup.*` whenever it is present in the configuration.
 *
 * `spam.warmup.enabled` and `spam.warmup.verified_only_until_verified` remain
 * the shipped on/off switches for the warmup subsystem as a whole;
 * `warmup.*` carries the per-domain ramp parameters (`warmup_days`,
 * `ramp_multiplier`, `warmup_daily_cap`, `warmup_recipient_cap`) and the
 * `verified_only` flag. When a `warmup.*` block is present, its
 * `verified_only` value is authoritative for the verified-only scope.
 *
 * The precedence is implemented in the config layer that builds
 * `PolicyConfig.warmup` from the YAML; the validation in
 * `src/spam/config.ts` then rejects an inconsistent combination (for example
 * `warmup_days <= 0`).
 */
export const WARMUP_PRECEDENCE_RESOLUTION =
  "warmup.* overrides spam.warmup.*; spam.warmup.* keeps the subsystem on/off switches";

/**
 * **Item 6 — `relay.default_scope: all` in the shipped example.**
 *
 * Resolved: **not present.** The shipped example uses `default_scope: "none"`.
 *
 * A configuration value meaning "any recipient" must never be the shipped
 * default: the IR states that the set of domains a principal may send to is
 * empty unless explicitly configured (IR R-8.1.1), and an operator must set
 * `all` deliberately, with the `admin` role and an audit record (IR R-8.1.2).
 */
export const RELAY_DEFAULT_SCOPE_RESOLUTION =
  'the shipped example uses default_scope: "none"; "all" is never a default';

/**
 * **Item 7 — SMTP status code for a throttle.**
 *
 * Resolved: **`450 4.7.1`** for a throttle and **`452 4.5.3`** for a quota
 * exhaustion.
 *
 * This matches the anti-spam IR's response table (§12.1), where `RATE_LIMITED`
 * and `WARMUP_LIMITED` map to `450 4.7.1` and `QUOTA_EXCEEDED` maps to
 * `452 4.5.3`. The SMTP surface's `PolicyHookOutcome` carries a `defer`
 * action for both, and `src/spam/smtp-hooks.ts` uses
 * `SMTP_POLICY_CODES.defer = 450`.
 *
 * A quota denial is reported separately from a rate denial so that the two
 * remain distinguishable in the SMTP reply text, while the HTTP surface
 * returns `429` with a `Retry-After` for both.
 */
export const SMTP_THROTTLE_CODE_RESOLUTION =
  "450 4.7.1 for a throttle; 452 4.5.3 for a quota exhaustion";
