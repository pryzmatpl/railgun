// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// DMARC record parsing and posture mapping.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §7.3.2, §7.3.3,
// §7.3.4 and verification obligations V-7, V-8.
//
// RailGun reads DMARC records; it never mutates DNS (IR §7.3.6). Pure module.

import type { DmarcPosture, DnsFailurePolicy } from "../domain/identity.js";

/** The parsed DMARC record. */
export interface DmarcRecord {
  readonly version: "DMARC1";
  readonly policy: "none" | "quarantine" | "reject";
  readonly subdomain_policy: "none" | "quarantine" | "reject" | null;
  readonly adkim: "relaxed" | "strict";
  readonly aspf: "relaxed" | "strict";
  readonly rua: string | null;
  readonly ruf: string | null;
  readonly pct: number;
  readonly fo: string | null;
}

/** The outcome of a DMARC lookup. */
export interface DmarcEvaluation {
  /** The posture the sending domain is in (IR §7.3.3). */
  readonly posture: DmarcPosture;
  readonly record: DmarcRecord | null;
  /** True when several records published conflicting `p=` values. */
  readonly conflicting_policy: boolean;
  /** Present when the record could not be fetched or parsed. */
  readonly error?: string;
}

/**
 * Parses one DMARC TXT record. Returns `null` when the record is not a valid
 * `v=DMARC1` record.
 */
export function parseDmarcRecord(txt: string): DmarcRecord | null {
  if (typeof txt !== "string") {
    return null;
  }
  const tags = new Map<string, string>();
  for (const raw of txt.trim().split(/\s+/)) {
    // A tag may carry a trailing `;` when the record uses `tag=value;`
    // spacing rather than `tag=value; tag=value`.
    const part = raw.replace(/;+$/, "");
    if (part.length === 0) {
      continue;
    }
    const eq = part.indexOf("=");
    if (eq <= 0) {
      continue;
    }
    const name = part.slice(0, eq).toLowerCase();
    const value = part.slice(eq + 1);
    if (!tags.has(name)) {
      tags.set(name, value);
    }
  }

  if ((tags.get("v") ?? "").toUpperCase() !== "DMARC1") {
    return null;
  }
  const p = (tags.get("p") ?? "").toLowerCase();
  if (p !== "none" && p !== "quarantine" && p !== "reject") {
    return null;
  }
  const spRaw = (tags.get("sp") ?? "").toLowerCase();
  const sp =
    spRaw === "none" || spRaw === "quarantine" || spRaw === "reject"
      ? spRaw
      : null;
  // RFC 7489 §6.3 spells the alignment modes `s` (strict) and `r`
  // (relaxed); `relaxed`/`strict` are also accepted for tolerance.
  const adkimRaw = (tags.get("adkim") ?? "r").toLowerCase();
  const aspfRaw = (tags.get("aspf") ?? "r").toLowerCase();
  const pctRaw = tags.get("pct");

  return {
    version: "DMARC1",
    policy: p,
    subdomain_policy: sp,
    adkim: adkimRaw === "s" || adkimRaw === "strict" ? "strict" : "relaxed",
    aspf: aspfRaw === "s" || aspfRaw === "strict" ? "strict" : "relaxed",
    rua: tags.get("rua") ?? null,
    ruf: tags.get("ruf") ?? null,
    pct: pctRaw !== undefined && Number.isFinite(Number(pctRaw)) ? Number(pctRaw) : 100,
    fo: tags.get("fo") ?? null,
  };
}

/**
 * Selects the DMARC record from a set of TXT strings. The first record with a
 * valid `p=` wins; conflicting `p=` values are reported as a warning
 * (IR §7.3.2).
 */
export function selectDmarcRecord(txts: readonly string[]): {
  record: DmarcRecord | null;
  conflicting: boolean;
  error?: string;
} {
  const candidates = txts
    .map((txt) => parseDmarcRecord(txt))
    .filter((r): r is DmarcRecord => r !== null);
  if (candidates.length === 0) {
    return { record: null, conflicting: false, error: "no_valid_record" };
  }
  const policies = new Set(candidates.map((r) => r.policy));
  return {
    record: candidates[0] ?? null,
    conflicting: policies.size > 1,
  };
}

/**
 * The inputs needed to decide whether RailGun's own configuration satisfies
 * the published DMARC policy (IR §7.3.2).
 */
export interface DmarcPostureInput {
  /** The published record, or `null` when it could not be fetched/parsed. */
  readonly record: DmarcRecord | null;
  /** Whether the sending domain has been verified before (drives fail policy). */
  readonly previously_verified: boolean;
  /** The DNS failure policy configured for this domain. */
  readonly dns_failure_policy: DnsFailurePolicy;
  /**
   * Whether the DKIM `d=` domain matches the `From` domain exactly. With
   * `adkim=strict` a subdomain `d=` is not aligned.
   */
  readonly dkim_aligned: boolean;
  /** Whether the envelope sender domain aligns with the `From` domain. */
  readonly spf_aligned: boolean;
  /** The domain being evaluated. */
  readonly domain?: string;
}

/**
 * Maps a DMARC record and RailGun's configuration to a posture
 * (IR §7.3.3).
 *
 * - `aligned` — the published policy is satisfiable by RailGun's configuration.
 * - `relaxed_only` — `p=none` with no enforcement; warn only.
 * - `mismatched` — the published policy conflicts with RailGun's configuration.
 * - `unknown` — the record could not be fetched or parsed; the per-domain
 *   failure policy decides the behaviour.
 */
export function evaluateDmarcPosture(input: DmarcPostureInput): DmarcEvaluation {
  const { record } = input;
  if (record === null) {
    // Unknown posture. The fail policy is per-domain and explicit: a domain
    // that previously verified fails closed, a never-verified domain fails
    // open (IR §7.3.3).
    const posture: DmarcPosture = "unknown";
    return {
      posture,
      record: null,
      conflicting_policy: false,
      error: "record_unavailable",
    };
  }

  const conflicting = false;
  const alignmentOk = input.dkim_aligned || input.spf_aligned;

  if (!alignmentOk) {
    // Neither DKIM nor SPF aligns, so no published policy can be satisfied.
    return { posture: "mismatched", record, conflicting_policy: conflicting };
  }
  if (record.adkim === "strict" && !input.dkim_aligned) {
    // adkim=strict demands a DKIM-aligned (exact d=) signature; SPF alignment
    // alone does not satisfy it (IR §7.3.3).
    return { posture: "mismatched", record, conflicting_policy: conflicting };
  }
  if (record.aspf === "strict" && !input.spf_aligned) {
    return { posture: "mismatched", record, conflicting_policy: conflicting };
  }
  if (record.policy === "none") {
    return { posture: "relaxed_only", record, conflicting_policy: conflicting };
  }
  return { posture: "aligned", record, conflicting_policy: conflicting };
}

/**
 * Whether a posture must block sending.
 *
 * `mismatched` denies. `unknown` denies only when the domain's failure policy
 * is `fail_closed` (or when the domain previously verified). `relaxed_only`
 * never blocks (IR §7.3.3).
 */
export function postureBlocksSending(
  posture: DmarcPosture,
  previouslyVerified: boolean,
  failurePolicy: DnsFailurePolicy,
): boolean {
  if (posture === "mismatched") {
    return true;
  }
  if (posture === "unknown") {
    return failurePolicy === "fail_closed" || previouslyVerified;
  }
  return false;
}
