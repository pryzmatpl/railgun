// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Suppression, blocklist, warmup and sending-domain identity types.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §7.4, §9.3,
// §10.1, §10.2, §10.3 and §10.4.
//
// Pure module — no runtime imports (IR R-4.1).

/**
 * The exact set of suppression reasons (IR R-10.1.1). No other value is legal.
 */
export const SUPPRESSION_REASONS = Object.freeze([
  "hard_bounce",
  "soft_bounce",
  "complaint",
  "manual",
  "unsubscribe",
] as const);

export type SuppressionReason = (typeof SUPPRESSION_REASONS)[number];

export function isSuppressionReason(value: string): value is SuppressionReason {
  return (SUPPRESSION_REASONS as readonly string[]).includes(value);
}

/**
 * Suppression scope (IR R-10.1.2). A `domain`-scoped entry belongs to one
 * tenant's sending domain and MUST NOT apply to another tenant's domain.
 */
export type SuppressionScope = "global" | "domain";

/** A suppression entry. */
export interface SuppressionEntry {
  readonly id: string;
  readonly tenant_id: string;
  readonly scope: SuppressionScope;
  /** The sending domain for `domain` scope; `null` for `global`. */
  readonly domain: string | null;
  /** The suppressed recipient address (hashed at rest by the store). */
  readonly recipient: string;
  readonly reason: SuppressionReason;
  readonly created_at: string;
  /** ISO timestamp; `null` means indefinite (IR R-10.1.3). */
  readonly expires_at: string | null;
  /** Whether feedback created this entry or an operator did. */
  readonly source: "feedback" | "operator" | "bounce";
}

/**
 * Default expiry per suppression reason (IR R-10.1.3).
 *
 * `hard_bounce`, `complaint` and `unsubscribe` are indefinite until an
 * operator releases them; `soft_bounce` gets a cooling period.
 */
export const DEFAULT_SUPPRESSION_EXPIRY_HOURS: Readonly<
  Record<SuppressionReason, number | null>
> = Object.freeze({
  hard_bounce: null,
  soft_bounce: 24,
  complaint: null,
  manual: null,
  unsubscribe: null,
});

/** The kinds of blocklist entry (IR R-10.2.1). */
export const BLOCKLIST_ENTRY_KINDS = Object.freeze([
  "recipient_address",
  "recipient_domain",
  "sender_address",
  "sender_domain",
  "tenant",
  "source_ip",
  "feedback_source",
  "content_hash",
  "url_hash",
] as const);

export type BlocklistEntryKind = (typeof BLOCKLIST_ENTRY_KINDS)[number];

export function isBlocklistEntryKind(value: string): value is BlocklistEntryKind {
  return (BLOCKLIST_ENTRY_KINDS as readonly string[]).includes(value);
}

/** A local blocklist entry, held in the durable store. */
export interface BlocklistEntry {
  readonly id: string;
  readonly kind: BlocklistEntryKind;
  readonly value: string;
  /** `null` applies the entry to every tenant. */
  readonly tenant_id: string | null;
  readonly created_at: string;
  readonly expires_at: string | null;
  readonly note?: string;
}

/** Per-list failure policy for a remote blocklist (IR R-10.2.2). */
export type RemoteFailPolicy = "fail_open" | "fail_closed";

/** A configured remote blocklist source. */
export interface RemoteBlocklistConfig {
  readonly name: string;
  /** Zone/domain to query, e.g. `zen.spamhaus.org`. */
  readonly zone: string;
  readonly fail_policy: RemoteFailPolicy;
  readonly cache_ttl_seconds: number;
}

/**
 * Protection mode for role addresses (IR R-10.3.2).
 */
export type RoleAddressMode = "allow" | "throttle" | "deny" | "require_verified";

export const ROLE_ADDRESS_MODES: readonly RoleAddressMode[] = Object.freeze([
  "allow",
  "throttle",
  "deny",
  "require_verified",
]);

export function isRoleAddressMode(value: string): value is RoleAddressMode {
  return (ROLE_ADDRESS_MODES as readonly string[]).includes(value);
}

/**
 * The default protected role local-parts (IR R-10.3.1).
 */
export const DEFAULT_ROLE_ADDRESSES: readonly string[] = Object.freeze([
  "postmaster",
  "abuse",
  "security",
  "hostmaster",
  "webmaster",
  "noc",
  "mailer-daemon",
  "usenet",
  "news",
  "uucp",
  "ftp",
  "sysadmin",
  "root",
  "admin",
  "administrator",
  "info",
  "sales",
  "support",
  "billing",
  "careers",
  "legal",
  "privacy",
  "compliance",
  "dpo",
]);

/** The role-address protection configuration. */
export interface RoleAddressConfig {
  readonly mode: RoleAddressMode;
  readonly list: readonly string[];
  /** Trap/honeypot recipients, denied unconditionally (IR R-10.3.3). */
  readonly trap_recipients: readonly string[];
}

/** Warmup state machine states (IR R-9.3.6). */
export type WarmupState =
  | "cold"
  | "warming"
  | "warm"
  | "limited"
  | "suspended";

export const WARMUP_STATES: readonly WarmupState[] = Object.freeze([
  "cold",
  "warming",
  "warm",
  "limited",
  "suspended",
]);

/** Reputation escalation states (IR R-9.4.1). */
export type ReputationState = "normal" | "throttled" | "quarantined" | "suspended";

export const REPUTATION_STATES: readonly ReputationState[] = Object.freeze([
  "normal",
  "throttled",
  "quarantined",
  "suspended",
]);

/** The lifecycle status of a sending domain (IR §7.4). */
export type SendingDomainStatus = "pending" | "verified" | "disabled";

/** SPF requirement attached to a sending domain. */
export type SpfRequirement = "disabled" | "warn" | "required";

/** Alignment mode (IR §7.2.2). `strict` is the default. */
export type AlignmentMode = "strict" | "relaxed";

/** DMARC posture of a sending domain (IR §7.3.3). */
export type DmarcPosture = "aligned" | "relaxed_only" | "mismatched" | "unknown";

export const DMARC_POSTURES: readonly DmarcPosture[] = Object.freeze([
  "aligned",
  "relaxed_only",
  "mismatched",
  "unknown",
]);

/** Per-domain DNS failure policy when a record cannot be fetched. */
export type DnsFailurePolicy = "fail_open" | "fail_closed";

/** The sending-domain identity registry record (IR §7.4). */
export interface SendingDomain {
  readonly domain: string;
  readonly tenant_id: string;
  readonly status: SendingDomainStatus;
  readonly dkim_selector: string;
  readonly dkim_algorithm: DkimAlgorithm;
  /** Reference to the private key material — never the material itself. */
  readonly dkim_key_ref: string;
  readonly spf_requirement: SpfRequirement;
  readonly dmarc_posture: DmarcPosture;
  readonly dmarc_failure_policy: DnsFailurePolicy;
  readonly alignment_mode: AlignmentMode;
  /** Explicit list — never inferred by wildcard (IR §7.4). */
  readonly authorized_subdomains: readonly string[];
  readonly warmup_state: WarmupState;
  readonly created_at: string;
}

/** Supported DKIM signing algorithms (IR R-7.1.1). */
export type DkimAlgorithm = "rsa-sha256" | "ed25519";

export const DKIM_ALGORITHMS: readonly DkimAlgorithm[] = Object.freeze([
  "rsa-sha256",
  "ed25519",
]);

export function isDkimAlgorithm(value: string): value is DkimAlgorithm {
  return (DKIM_ALGORITHMS as readonly string[]).includes(value);
}

/** Status of a DKIM key record (IR R-7.1.2). */
export type DkimKeyStatus = "active" | "pending" | "revoked";

/**
 * A DKIM key record. It holds a **secret reference**, never the private
 * material (IR R-7.1.2, R-7.1.3).
 */
export interface DkimKeyRecord {
  readonly domain: string;
  readonly selector: string;
  readonly algorithm: DkimAlgorithm;
  /** PEM (RSA) or raw base64 (ed25519) public key. */
  readonly public_key_pem: string;
  /** Reference to where the private key can be loaded from. */
  readonly secret_ref: string;
  readonly status: DkimKeyStatus;
  readonly created_at: string;
  readonly not_after: string | null;
}

/** The per-domain warmup ramp (IR §9.3.2). */
export interface WarmupPolicy {
  readonly warmup_days: number;
  readonly ramp_multiplier: number;
  readonly warmup_daily_cap: number;
  readonly warmup_recipient_cap: number;
  /** Restricts sends to the tenant's verified-recipient set (IR R-9.3.4). */
  readonly verified_only: boolean;
}

/**
 * Computes the deterministic ramp for a given warmup day (IR R-9.3.2).
 *
 *     day 1 → warmup_daily_cap
 *     day 2 → ceil(cap × ramp_multiplier)
 *     …
 *     day N → full quota
 */
export function warmupCapForDay(policy: WarmupPolicy, day: number): number {
  if (day <= 1) {
    return policy.warmup_daily_cap;
  }
  const capped = Math.min(day, policy.warmup_days);
  return Math.ceil(policy.warmup_daily_cap * policy.ramp_multiplier ** (capped - 1));
}

/** Reputation counters for a tenant or sending domain (IR §9.4). */
export interface ReputationCounters {
  readonly sends: number;
  readonly complaints: number;
  readonly hard_bounces: number;
  readonly defers: number;
  /** Trap-recipient hits recorded for the subject (IR R-10.3.3). */
  readonly trap_hits: number;
}
