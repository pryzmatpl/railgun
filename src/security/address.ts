// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Email address normalization and domain alignment.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §7.2.1, §7.2.2,
// §7.2.3.
//
// Pure module — no runtime imports (IR R-4.1).

/**
 * A parsed email address.
 */
export interface ParsedAddress {
  /** The original, unmodified input. */
  readonly raw: string;
  /** Lower-cased local part. */
  readonly local: string;
  /** Lower-cased domain part. */
  readonly domain: string;
  /** Display name, when the input was `Display Name <addr>`. */
  readonly display_name: string | null;
}

/**
 * A conservative RFC 5322 address parser. It accepts the forms RailGun
 * actually accepts and rejects everything else, rather than trying to be
 * a full RFC parser.
 *
 * Returns `null` for an address that is not usable.
 */
export function parseAddress(input: string): ParsedAddress | null {
  if (typeof input !== "string") {
    return null;
  }
  const trimmed = input.trim();
  if (trimmed.length === 0 || trimmed.length > 320) {
    return null;
  }

  let displayName: string | null = null;
  let addr = trimmed;

  const angle = trimmed.match(/^(.*)<([^<>]*)>\s*$/);
  if (angle) {
    const name = (angle[1] ?? "").trim().replace(/^"(.*)"$/, "$1").trim();
    displayName = name.length > 0 ? name : null;
    addr = (angle[2] ?? "").trim();
  }

  // A bare display name with no address is not an address.
  if (addr.length === 0 || addr.includes(" ")) {
    return null;
  }

  const at = addr.lastIndexOf("@");
  if (at <= 0 || at === addr.length - 1) {
    return null;
  }

  const local = addr.slice(0, at);
  const domain = addr.slice(at + 1).toLowerCase();

  if (local.length === 0 || local.length > 64) {
    return null;
  }
  if (!isValidDomain(domain)) {
    return null;
  }
  // CR/LF anywhere is a header-injection vector (checklist A-18).
  if (/[\r\n]/.test(addr) || (displayName !== null && /[\r\n]/.test(displayName))) {
    return null;
  }
  // Quoting is not supported; a quoted local part would change normalization.
  if (local.includes('"') || local.includes(",") || local.includes(";")) {
    return null;
  }

  return { raw: trimmed, local: local.toLowerCase(), domain, display_name: displayName };
}

/**
 * Validates a DNS domain name: labels of 1–63 characters of letters, digits
 * and hyphens, separated by dots, with a valid total length.
 */
export function isValidDomain(domain: string): boolean {
  if (domain.length === 0 || domain.length > 253) {
    return false;
  }
  if (domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")) {
    return false;
  }
  const labels = domain.split(".");
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return false;
    }
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) {
      return false;
    }
  }
  return true;
}

/**
 * Extracts the domain of an address without full validation. Used where the
 * caller has already validated the address.
 */
export function domainOf(address: string): string {
  const at = address.lastIndexOf("@");
  return at < 0 ? "" : address.slice(at + 1).toLowerCase();
}

/**
 * The public-suffix-aware organizational domain.
 *
 * RailGun ships a small, curated suffix list rather than depending on the
 * `tldts`/`psl` package, so the package stays installable with zero
 * configuration (plan delta 4). The list covers the multi-label suffixes that
 * matter for alignment decisions; unknown suffixes fall back to the last two
 * labels, which is the conservative strict-alignment answer.
 */
const MULTI_LABEL_PUBLIC_SUFFIXES: readonly string[] = Object.freeze([
  "co.uk",
  "org.uk",
  "me.uk",
  "gov.uk",
  "ac.uk",
  "net.uk",
  "sch.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "id.au",
  "co.jp",
  "or.jp",
  "ne.jp",
  "ac.jp",
  "go.jp",
  "co.nz",
  "net.nz",
  "org.nz",
  "com.br",
  "net.br",
  "org.br",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "com.mx",
  "com.ar",
  "com.tr",
  "com.sg",
  "com.hk",
  "com.tw",
  "co.za",
  "co.in",
  "net.in",
  "org.in",
  "co.kr",
  "or.kr",
  "com.pl",
  "net.pl",
  "org.pl",
  "com.ua",
  "co.il",
  "com.my",
  "co.id",
  "com.vn",
  "com.ph",
  "com.sa",
  "com.eg",
  "com.ng",
  "com.pk",
  "com.co",
  "com.pe",
  "com.ve",
  "com.ec",
  "com.uy",
]);

const MULTI_LABEL_SET: ReadonlySet<string> = new Set(MULTI_LABEL_PUBLIC_SUFFIXES);

/**
 * Returns the organizational domain of `domain` — the registrable domain
 * under the shipped suffix list.
 *
 *   example.co.uk         → example.co.uk
 *   mail.example.co.uk    → example.co.uk
 *   example.com           → example.com
 *   example.unknowntld    → unknowntld  (single-label fallback)
 */
export function organizationalDomain(domain: string): string {
  const d = domain.toLowerCase().replace(/\.$/, "");
  if (d.length === 0) {
    return "";
  }
  const labels = d.split(".");
  if (labels.length <= 2) {
    return d;
  }
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SET.has(lastTwo)) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

/**
 * Alignment mode (IR §7.2.2). `strict` requires an exact domain match;
 * `relaxed` also accepts a subdomain relationship.
 */
export type AlignmentMode = "strict" | "relaxed";

/**
 * Returns true when two domains are aligned.
 *
 * - `strict`: the domains are equal after normalization.
 * - `relaxed`: the organizational domains match, or one domain is a subdomain
 *   of the other.
 */
export function domainsAligned(
  a: string,
  b: string,
  mode: AlignmentMode = "strict",
): boolean {
  const left = a.toLowerCase().replace(/\.$/, "");
  const right = b.toLowerCase().replace(/\.$/, "");
  if (left.length === 0 || right.length === 0) {
    return false;
  }
  if (left === right) {
    return true;
  }
  if (mode === "strict") {
    return false;
  }
  const orgLeft = organizationalDomain(left);
  const orgRight = organizationalDomain(right);
  if (orgLeft === orgRight) {
    return true;
  }
  return (
    left.endsWith(`.${right}`) || right.endsWith(`.${left}`)
  );
}

/**
 * Returns true when `domain` is `parent` or a subdomain of `parent`. Used
 * for the `same_domain_only` recipient scope and explicit subdomain
 * authorization (IR §8.1.2).
 */
export function isDomainWithin(domain: string, parent: string): boolean {
  const d = domain.toLowerCase().replace(/\.$/, "");
  const p = parent.toLowerCase().replace(/\.$/, "");
  if (p.length === 0) {
    return false;
  }
  return d === p || d.endsWith(`.${p}`);
}

/**
 * Computes the Levenshtein distance between two strings, bounded so a long
 * subject cannot make scoring expensive.
 */
export function levenshtein(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  if (a.length === 0) {
    return b.length;
  }
  if (b.length === 0) {
    return a.length;
  }
  const limit = 256;
  const left = a.slice(0, limit);
  const right = b.slice(0, limit);
  let previous = Array.from({ length: right.length + 1 }, (_, i) => i);
  for (let i = 1; i <= left.length; i++) {
    const current = [i];
    for (let j = 1; j <= right.length; j++) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      current[j] = Math.min(
        (current[j - 1] ?? 0) + 1,
        (previous[j] ?? 0) + 1,
        (previous[j - 1] ?? 0) + cost,
      );
    }
    previous = current;
  }
  return previous[right.length] ?? Math.max(left.length, right.length);
}

/**
 * Returns true when `candidate` is a lookalike of `protected` — a Levenshtein
 * distance of at most `maxDistance` (IR R-11.1.2, `lookalike_domain`).
 */
export function isLookalikeDomain(
  candidate: string,
  protectedDomains: readonly string[],
  maxDistance = 1,
): boolean {
  const c = candidate.toLowerCase().replace(/\.$/, "");
  for (const protectedDomain of protectedDomains) {
    const p = protectedDomain.toLowerCase().replace(/\.$/, "");
    if (c === p) {
      continue;
    }
    // Compare on the registrable domain so `paypa1.com` vs `paypal.com` is
    // caught while `paypal.com.evil.test` is not a near-miss of `paypal.com`.
    const orgC = organizationalDomain(c);
    const orgP = organizationalDomain(p);
    if (orgC === orgP) {
      continue;
    }
    if (levenshtein(orgC, orgP) <= maxDistance) {
      return true;
    }
  }
  return false;
}
