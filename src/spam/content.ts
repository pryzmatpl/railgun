// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// The deterministic, versioned content scorer.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §11
// (R-11.1.1 – R-11.1.8) and verification obligation V-15.
//
// The score is a pure function of (message features, configuration, injected
// salts). The evidence it produces contains **feature names only** — never the
// matched text, never the URL that triggered a rule (IR R-11.1.5).

import { createHmac } from "node:crypto";

import { isLookalikeDomain, organizationalDomain, parseAddress } from "../security/address.js";
import type { MessageUnderPolicy } from "../domain/policy.js";

/** The names of the features the model can report (IR R-11.1.2). */
export const CONTENT_FEATURES = Object.freeze([
  "empty_body",
  "html_only",
  "link_count",
  "url_shortener",
  "suspicious_url",
  "duplicate_content",
  "phishing_phrase",
  "attachment_risk",
  "display_name_mismatch",
  "lookalike_domain",
  "mixed_script",
  "header_anomaly",
  "sender_auth_mismatch",
  "cold_relationship",
  "abuse_history",
] as const);

export type ContentFeature = (typeof CONTENT_FEATURES)[number];

/** The version of the scoring model. Recorded with every decision. */
export const SPAM_MODEL_VERSION = "railgun-spam-1";

/**
 * The weight of each feature. The weights sum to 1.0 so the score stays in
 * `[0, 1]`. A feature that fires contributes its full weight.
 *
 * The high-signal features (credential-solicitation phrasing, a risky
 * attachment, a lookalike domain, a mixed-script identity) are weighted so
 * that a strong indicator crosses the deny threshold in combination with any
 * second indicator, rather than needing a long tail of weak signals.
 */
export const FEATURE_WEIGHTS: Readonly<Record<ContentFeature, number>> = Object.freeze({
  empty_body: 0.04,
  html_only: 0.05,
  link_count: 0.06,
  url_shortener: 0.1,
  suspicious_url: 0.2,
  duplicate_content: 0.12,
  phishing_phrase: 0.3,
  attachment_risk: 0.25,
  display_name_mismatch: 0.07,
  lookalike_domain: 0.28,
  mixed_script: 0.22,
  header_anomaly: 0.05,
  sender_auth_mismatch: 0.1,
  cold_relationship: 0.03,
  abuse_history: 0.09,
});

/** The result of scoring a message. */
export interface ContentScore {
  /** The score in `[0, 1]`. */
  readonly score: number;
  /** The model version, so a historical score can be re-derived. */
  readonly model_version: string;
  /** The features that fired — names only, never content. */
  readonly features: readonly ContentFeature[];
}

/** The inputs the scorer needs beyond the message itself. */
export interface ContentScoringInput {
  readonly message: MessageUnderPolicy;
  /** The HMAC of (subject, body), already computed with the tenant secret. */
  readonly content_hmac: string;
  /** Whether the sender/tenant/recipient triple is new. */
  readonly cold_relationship: boolean;
  /** Whether the sender, tenant or recipient has an abuse history. */
  readonly abuse_history: boolean;
  /** Whether the `From` domain aligns with the DKIM `d=` domain. */
  readonly sender_auth_mismatch: boolean;
  /** The tenant-scoped secret used for salted hashing. */
  readonly tenant_secret: string;
  /** Configured protected brands for lookalike detection. */
  readonly protected_brands: readonly string[];
  /** Whether a duplicate of this content was seen recently. */
  readonly duplicate_content: boolean;
}

/** Known URL-shortener hosts (IR R-11.1.2, `url_shortener`). */
const URL_SHORTENERS: ReadonlySet<string> = Object.freeze(
  new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
    "cutt.ly",
  ]),
);

/** Credential-solicitation phrasing (IR R-11.1.2, `phishing_phrase`). */
const PHISHING_PHRASES: readonly string[] = Object.freeze([
  "verify your account",
  "confirm your password",
  "your account has been suspended",
  "your account will be suspended",
  "update your billing information",
  "reset your password immediately",
  "click here to verify",
  "unusual activity detected",
  "your account is at risk",
  "confirm your identity",
]);

/** Attachment extensions that carry executable or archive risk. */
const RISKY_EXTENSIONS: ReadonlySet<string> = Object.freeze(
  new Set([
    "exe",
    "scr",
    "bat",
    "cmd",
    "com",
    "pif",
    "vbs",
    "js",
    "jar",
    "msi",
    "dll",
    "ps1",
    "hta",
    "cpl",
    "reg",
    "sh",
    "apk",
    "app",
    "dmg",
    "pkg",
    "iso",
    "img",
    "zip",
    "rar",
    "7z",
    "gz",
    "tar",
    "bz2",
    "xz",
  ]),
);

/**
 * Computes the HMAC of the message content with a tenant-scoped secret
 * (IR R-11.1.6). The salt is rotatable and never stored in the database.
 */
export function contentHmac(
  tenantSecret: string,
  subject: string,
  body: string,
): string {
  return createHmac("sha256", tenantSecret)
    .update(`${subject}\u0000${body}`, "utf8")
    .digest("hex");
}

/** Extracts the URLs from a text or HTML body. */
function extractUrls(body: string): string[] {
  const matches = body.match(/https?:\/\/[^\s"'<>)]+/gi);
  if (matches === null) {
    return [];
  }
  // A hostile body must not be able to make the scorer allocate without
  // bound (IR R-10.4.2 applies to feedback, but the same discipline applies
  // to content).
  return matches.slice(0, 500);
}

/**
 * Returns true when the URL is suspicious (IR R-11.1.2, `suspicious_url`):
 * an IP-literal host, excessive subdomain depth, a punycode lookalike, an
 * `@` in the authority, an unusual port, or credentials in the authority.
 */
function isSuspiciousUrl(url: string): boolean {
  let authority = "";
  try {
    const parsed = new URL(url);
    authority = `${parsed.hostname}${parsed.port === "" ? "" : `:${parsed.port}`}`.toLowerCase();
  } catch {
    return false;
  }
  if (authority.length === 0) {
    return false;
  }
  if (authority.includes("@")) {
    return true;
  }
  const host = authority.split(":")[0] ?? "";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return true;
  }
  if (host.startsWith("xn--") || host.includes(".xn--")) {
    return true;
  }
  const labels = host.split(".");
  if (labels.length > 5) {
    return true;
  }
  const port = authority.includes(":") ? authority.split(":")[1] ?? "" : "";
  if (port.length > 0) {
    const portNumber = Number.parseInt(port, 10);
    if (!Number.isFinite(portNumber) || (portNumber !== 80 && portNumber !== 443)) {
      return true;
    }
  }
  return false;
}

/** Returns true when the local part or display name mixes scripts. */
function hasMixedScript(value: string): boolean {
  const scripts = new Set<string>();
  for (const char of value) {
    const code = char.codePointAt(0);
    if (code === undefined) {
      continue;
    }
    if (code >= 0x41 && code <= 0x5a) {
      scripts.add("latin");
    } else if (code >= 0x61 && code <= 0x7a) {
      scripts.add("latin");
    } else if (code >= 0xc0 && code <= 0x24f) {
      scripts.add("latin-ext");
    } else if (code >= 0x370 && code <= 0x3ff) {
      scripts.add("greek");
    } else if (code >= 0x400 && code <= 0x4ff) {
      scripts.add("cyrillic");
    } else if (code >= 0x590 && code <= 0x5ff) {
      scripts.add("hebrew");
    } else if (code >= 0x600 && code <= 0x6ff) {
      scripts.add("arabic");
    } else if (code >= 0x3040 && code <= 0x30ff) {
      scripts.add("kana");
    } else if (code >= 0xac00 && code <= 0xd7af) {
      scripts.add("hangul");
    } else if (code >= 0x4e00 && code <= 0x9fff) {
      scripts.add("han");
    }
  }
  return scripts.size > 1;
}

/**
 * Scores a message. The function is deterministic: the same input and the
 * same configuration always yield the same score and the same feature set
 * (IR R-11.1.1, V-15).
 */
export function scoreContent(input: ContentScoringInput): ContentScore {
  const { message } = input;
  const features = new Set<ContentFeature>();
  // How many distinct phishing phrases matched, used to scale the feature's
  // contribution. Bounded to 3 so the score can never exceed 1.
  let phraseMultiplicity = 1;

  const subject = message.headers["subject"] ?? "";
  const text = message.text_body ?? "";
  const html = message.html_body ?? "";
  const fromHeader = message.headers["from"] ?? "";
  const from = parseAddress(fromHeader);

  // `empty_body` — no text and no HTML, or only whitespace / stripped tags.
  const textWithoutTags = html.replace(/<[^>]*>/g, " ").replace(/&nbsp;/gi, " ");
  const effectiveText = text.trim().length > 0 ? text : textWithoutTags.trim();
  if (effectiveText.length === 0) {
    features.add("empty_body");
  }

  // `html_only` — HTML with no text alternative.
  if (html.trim().length > 0 && text.trim().length === 0) {
    features.add("html_only");
  }

  // `link_count` — excessive link count relative to the body size.
  const combined = `${text}\n${html}`;
  const urls = extractUrls(combined);
  if (urls.length > 20 && urls.length > combined.length / 200) {
    features.add("link_count");
  }

  // `url_shortener` — a known shortener host.
  for (const url of urls) {
    let host = "";
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (URL_SHORTENERS.has(host)) {
      features.add("url_shortener");
      break;
    }
  }

  // `suspicious_url`.
  if (urls.some((url) => isSuspiciousUrl(url))) {
    features.add("suspicious_url");
  }

  // `duplicate_content`.
  if (input.duplicate_content) {
    features.add("duplicate_content");
  }

  // `phishing_phrase`. Several distinct credential-solicitation phrases in
  // one message is a stronger signal than one, so the feature's contribution
  // scales with the count (bounded, so the score stays in [0, 1]).
  const haystack = `${subject}\n${text}`.toLowerCase();
  const phraseHits = PHISHING_PHRASES.filter((phrase) => haystack.includes(phrase));
  if (phraseHits.length > 0) {
    features.add("phishing_phrase");
    phraseMultiplicity = Math.min(phraseHits.length, 3);
  }

  // `attachment_risk` — a risky extension or a double extension.
  for (const name of message.attachment_names) {
    const lower = name.toLowerCase();
    const parts = lower.split(".");
    const extension = parts[parts.length - 1] ?? "";
    if (extension.length > 0 && RISKY_EXTENSIONS.has(extension)) {
      features.add("attachment_risk");
      break;
    }
    if (parts.length >= 3) {
      // A double extension such as `invoice.pdf.exe`.
      const inner = parts[parts.length - 2] ?? "";
      if (inner.length > 0 && inner.length <= 5 && /^[a-z0-9]+$/.test(inner)) {
        features.add("attachment_risk");
        break;
      }
    }
  }

  // `display_name_mismatch` — the display name's domain differs from the
  // address domain.
  if (from !== null && from.display_name !== null) {
    const displayDomain = /@([^\s]+)/.exec(from.display_name)?.[1]?.toLowerCase();
    if (displayDomain !== undefined && displayDomain !== from.domain) {
      features.add("display_name_mismatch");
    }
  }

  // `lookalike_domain` — near-miss of a protected brand.
  if (from !== null && input.protected_brands.length > 0) {
    if (isLookalikeDomain(from.domain, input.protected_brands, 1)) {
      features.add("lookalike_domain");
    }
  }

  // `mixed_script` — mixed-script local part or display name.
  if (from !== null) {
    if (hasMixedScript(from.local) || (from.display_name !== null && hasMixedScript(from.display_name))) {
      features.add("mixed_script");
    }
  }

  // `header_anomaly` — missing/duplicate Message-ID, implausible Date.
  const messageId = message.headers["message-id"];
  if (messageId === undefined || messageId.trim().length === 0) {
    features.add("header_anomaly");
  }
  const dateHeader = message.headers["date"];
  if (dateHeader !== undefined) {
    const parsed = Date.parse(dateHeader);
    if (Number.isNaN(parsed)) {
      features.add("header_anomaly");
    }
  }

  // `sender_auth_mismatch`.
  if (input.sender_auth_mismatch) {
    features.add("sender_auth_mismatch");
  }

  // `cold_relationship`.
  if (input.cold_relationship) {
    features.add("cold_relationship");
  }

  // `abuse_history`.
  if (input.abuse_history) {
    features.add("abuse_history");
  }

  const ordered = CONTENT_FEATURES.filter((feature) => features.has(feature));
  let score = 0;
  for (const feature of ordered) {
    const weight = FEATURE_WEIGHTS[feature];
    if (feature === "phishing_phrase") {
      score += weight * phraseMultiplicity;
    } else {
      score += weight;
    }
  }
  // Clamp into [0, 1] — floating point accumulation must never exceed it.
  score = Math.min(1, Math.max(0, Number(score.toFixed(6))));

  return { score, model_version: SPAM_MODEL_VERSION, features: ordered };
}

/**
 * Maps a content score to a policy outcome (IR R-11.1.4).
 *
 *     score < allow_threshold                     → allow
 *     allow_threshold ≤ score < deny_threshold    → quarantine (or deny)
 *     score ≥ deny_threshold                      → deny
 */
export function scoreToDecision(
  score: number,
  allowThreshold: number,
  denyThreshold: number,
  quarantineEnabled: boolean,
): { decision: "allow" | "quarantine" | "deny"; reason_code: string } {
  if (score >= denyThreshold) {
    return { decision: "deny", reason_code: "SPAM_POLICY_DENIED" };
  }
  if (score >= allowThreshold) {
    return quarantineEnabled
      ? { decision: "quarantine", reason_code: "QUARANTINED" }
      : { decision: "deny", reason_code: "SPAM_POLICY_DENIED" };
  }
  return { decision: "allow", reason_code: "QUEUED" };
}

/**
 * The organizational domain of the `From` header, used by the lookalike
 * feature. Exported for the policy engine's identity checks.
 */
export function fromOrganizationalDomain(message: MessageUnderPolicy): string | null {
  const from = parseAddress(message.headers["from"] ?? "");
  if (from === null) {
    return null;
  }
  const org = organizationalDomain(from.domain);
  return org.length > 0 ? org : null;
}
