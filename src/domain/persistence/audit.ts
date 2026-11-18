/* RailGun hash-chained audit helpers. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { createHash } from "node:crypto";
import type { AuditVerification } from "./ports.js";
import type { AuditEventInput, AuditRecord } from "./types.js";

export const AUDIT_GENESIS_DIGEST = "0".repeat(64);

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item)}`).join(",")}}`;
}

export function auditDigest(record: Omit<AuditRecord, "digest">): string {
  return createHash("sha256").update(canonicalize(record)).digest("hex");
}

export function appendAuditRecord(event: AuditEventInput, previous: AuditRecord | undefined, timestamp: string): AuditRecord {
  const base = {
    schemaVersion: 1 as const,
    sequence: (previous?.sequence ?? 0) + 1,
    timestamp,
    actor: event.actor,
    tenantId: event.tenantId,
    action: event.action,
    subjectType: event.subjectType,
    subjectId: event.subjectId,
    outcome: event.outcome,
    reasonCode: event.reasonCode,
    correlationId: event.correlationId,
    metadata: event.metadata ?? {},
    previousDigest: previous?.digest ?? AUDIT_GENESIS_DIGEST,
  };
  return { ...base, digest: auditDigest(base) };
}

export function verifyAuditRecords(records: readonly AuditRecord[]): AuditVerification {
  let previousDigest = AUDIT_GENESIS_DIGEST;
  let expectedSequence = 1;
  for (const record of records) {
    if (record.sequence !== expectedSequence) {
      return { valid: false, headSequence: record.sequence, headDigest: record.digest, firstInvalidSequence: record.sequence, reason: "sequence_gap" };
    }
    if (record.previousDigest !== previousDigest) {
      return { valid: false, headSequence: record.sequence, headDigest: record.digest, firstInvalidSequence: record.sequence, reason: "previous_digest_mismatch" };
    }
    const { digest, ...content } = record;
    const expected = auditDigest(content);
    if (expected !== digest) {
      return { valid: false, headSequence: record.sequence, headDigest: record.digest, firstInvalidSequence: record.sequence, reason: "record_digest_mismatch" };
    }
    previousDigest = digest;
    expectedSequence++;
  }
  const last = records.at(-1);
  return { valid: true, headSequence: last?.sequence ?? 0, headDigest: last?.digest ?? AUDIT_GENESIS_DIGEST, firstInvalidSequence: null, reason: null };
}

export function canonicalAuditLine(record: AuditRecord): string {
  return canonicalize(record);
}
