// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Defensive SPF record parsing (RFC 7208) — verification/operator use only.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §7.2.4, §7.2.5
// and verification obligation V-6.
//
// RailGun never resolves DNS recursively for arbitrary SPF mechanisms during
// normal sending; this module parses a published record and reports its
// structure so an operator can see it. Pure module — no runtime imports.

/** The qualifier of an SPF mechanism. */
export type SpfQualifier = "+" | "-" | "~" | "?";

/** One parsed SPF mechanism. */
export interface SpfMechanism {
  readonly qualifier: SpfQualifier;
  readonly name: "include" | "a" | "mx" | "ptr" | "exists" | "ip4" | "ip6" | "all";
  /** The domain or value operand, `null` for `all`. */
  readonly value: string | null;
  /** CIDR prefix length for `ip4` / `ip6`. */
  readonly cidr: number | null;
}

/** The result of parsing an SPF record. */
export interface SpfRecord {
  readonly version: string;
  readonly mechanisms: readonly SpfMechanism[];
  /** Modifier tags: `redirect=`, `exp=`. */
  readonly modifiers: Readonly<Record<string, string>>;
  /** The `all` mechanism's qualifier, `null` when the record has none. */
  readonly all_qualifier: SpfQualifier | null;
  /**
   * The number of DNS-querying mechanisms (`include`, `a`, `mx`, `ptr`,
   * `exists`, `redirect`). RFC 7208 caps this at 10.
   */
  readonly lookup_count: number;
  /** True when the record exceeds the 10-lookup limit. */
  readonly too_many_lookups: boolean;
  /** Present when the record could not be parsed. */
  readonly error?: string;
}

/** RFC 7208 §4.6.4 — the maximum number of DNS-querying mechanisms. */
export const SPF_MAX_LOOKUPS = 10;

/**
 * Parses an SPF record defensively. Never throws; a malformed record yields a
 * record with an `error` field and no mechanisms.
 */
export function parseSpfRecord(txt: string): SpfRecord {
  const empty: SpfRecord = {
    version: "",
    mechanisms: [],
    modifiers: {},
    all_qualifier: null,
    lookup_count: 0,
    too_many_lookups: false,
  };
  if (typeof txt !== "string" || txt.trim().length === 0) {
    return { ...empty, error: "empty_record" };
  }

  // A TXT record may hold several strings; take the one that starts with v=.
  const candidates = txt
    .split(/\s+/)
    .filter((part) => part.length > 0);
  const versionIndex = candidates.findIndex((part) => /^v=spf1$/i.test(part));
  if (versionIndex < 0) {
    return { ...empty, error: "missing_version" };
  }

  const mechanisms: SpfMechanism[] = [];
  const modifiers: Record<string, string> = {};
  let lookupCount = 0;
  let allQualifier: SpfQualifier | null = null;

  for (const rawTerm of candidates.slice(versionIndex + 1)) {
    const term = rawTerm.replace(/;+$/, "");
    if (term.length === 0) {
      continue;
    }
    const qualifier = (["+", "-", "~", "?"].includes(term[0] ?? "")
      ? term[0]
      : "+") as SpfQualifier;
    const body = (["+", "-", "~", "?"].includes(term[0] ?? "") ? term.slice(1) : term)
      .toLowerCase();

    if (body.includes("=")) {
      const eq = body.indexOf("=");
      modifiers[body.slice(0, eq)] = body.slice(eq + 1);
      if (body.startsWith("redirect=")) {
        lookupCount += 1;
      }
      continue;
    }

    // A mechanism is `<name>:<value>` (or `<name>` for `a`/`mx`/`ptr`), with
    // an optional `/<cidr>` suffix on `ip4`/`ip6`.
    const slash = body.indexOf("/");
    const withoutCidr = slash >= 0 ? body.slice(0, slash) : body;
    const colon = withoutCidr.indexOf(":");
    const name = colon >= 0 ? withoutCidr.slice(0, colon) : withoutCidr;
    const operand = colon >= 0 ? withoutCidr.slice(colon + 1) : null;
    const cidrText = slash >= 0 ? body.slice(slash + 1) : null;

    switch (name) {
      case "all":
        allQualifier = qualifier;
        mechanisms.push({ qualifier, name: "all", value: null, cidr: null });
        break;
      case "include":
      case "a":
      case "mx":
      case "ptr":
      case "exists": {
        lookupCount += 1;
        mechanisms.push({ qualifier, name, value: operand, cidr: null });
        break;
      }
      case "ip4":
      case "ip6": {
        const cidr = cidrText !== null ? Number.parseInt(cidrText, 10) : null;
        mechanisms.push({
          qualifier,
          name,
          value: operand,
          cidr: Number.isFinite(cidr) ? cidr : null,
        });
        break;
      }
      default:
        // Unknown term — ignored, as RFC 7208 requires.
        break;
    }
  }

  // A record consisting only of a `redirect=` modifier is valid: the
  // redirect target supplies the mechanisms.
  if (mechanisms.length === 0 && allQualifier === null && Object.keys(modifiers).length === 0) {
    return { ...empty, version: "spf1", error: "no_mechanisms" };
  }

  return {
    version: "spf1",
    mechanisms,
    modifiers,
    all_qualifier: allQualifier,
    lookup_count: lookupCount,
    too_many_lookups: lookupCount > SPF_MAX_LOOKUPS,
  };
}

/**
 * Selects the SPF record from a set of TXT strings for a domain. When several
 * `v=spf1` records exist the first is used and the conflict is reported.
 */
export function selectSpfRecord(txts: readonly string[]): {
  record: SpfRecord | null;
  conflicting: boolean;
} {
  const spfTxts = txts.filter((txt) => /(?:^|\s)v=spf1(?:\s|$)/i.test(txt));
  if (spfTxts.length === 0) {
    return { record: null, conflicting: false };
  }
  const record = parseSpfRecord(spfTxts[0] ?? "");
  const distinct = new Set(
    spfTxts.map((txt) => txt.trim().replace(/\s+/g, " ").toLowerCase()),
  );
  return { record, conflicting: distinct.size > 1 };
}

/**
 * The outcome of an SPF evaluation against a published record.
 */
export interface SpfEvaluation {
  /** `pass`, `fail`, `neutral`, `none`, `error`, `toomanylookups`. */
  readonly result: "pass" | "fail" | "neutral" | "none" | "error" | "toomanylookups";
  /** The parsed record, when one was found. */
  readonly record: SpfRecord | null;
  readonly error?: string;
}

/**
 * Evaluates a published SPF record for **presence and shape**, not for
 * authorization of a specific IP. RailGun is a *sender*: it uses SPF to
 * confirm that a sending domain publishes a sane record, and to report the
 * `all` policy to the operator.
 *
 * A record that exceeds the 10-lookup limit yields `toomanylookups` instead
 * of being evaluated further (IR §7.2.4, V-6).
 */
export function evaluateSpfRecord(txts: readonly string[]): SpfEvaluation {
  const { record, conflicting } = selectSpfRecord(txts);
  if (record === null) {
    return { result: "none", record: null };
  }
  if (record.error !== undefined) {
    return { result: "error", record, error: record.error };
  }
  if (record.too_many_lookups) {
    return { result: "toomanylookups", record };
  }
  if (record.all_qualifier === null) {
    // No `all` mechanism — the record authorizes nothing; treat as `none`.
    return { result: "neutral", record, ...(conflicting ? { error: "conflicting_records" } : {}) };
  }
  const result = record.all_qualifier === "+" ? "pass" : "fail";
  return {
    result,
    record,
    ...(conflicting ? { error: "conflicting_records" } : {}),
  };
}

/**
 * Checks whether the SPF record authorizes a third-party sender. RailGun
 * flags a record whose `include:` set does not mention the operator's own
 * sending infrastructure when the `all` mechanism is `-all`
 * (IR §8.3.5).
 */
export function spfExcludesSender(
  record: SpfRecord,
  expectedIncludes: readonly string[],
): boolean {
  if (record.all_qualifier !== "-") {
    return false;
  }
  const includes = record.mechanisms
    .filter((m) => m.name === "include")
    .map((m) => (m.value ?? "").toLowerCase());
  return !expectedIncludes.some((expected) =>
    includes.some((inc) => inc === expected.toLowerCase() || inc.endsWith(`.${expected.toLowerCase()}`)),
  );
}
