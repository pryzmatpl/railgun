// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * RFC 3464 `message/delivery-status` parsing.
 *
 * Contract: `docs/design/railgun-direct-mx-delivery-engine-ir.md` §3.8
 * (R-DSN-1 … R-DSN-10).
 *
 * This parser is **distinct** from the FBL/feedback parser in
 * `src/spam/feedback.ts`: a feedback loop report carries a complaint, while a
 * delivery-status report carries a per-recipient delivery outcome. The two
 * MUST NOT be conflated.
 */

import type { DeliveryErrorCode, DeliveryOutcome } from "./types.js";

/** The action field of a delivery-status report. */
export type DsnAction = "failed" | "delayed" | "delivered" | "relayed" | "expanded";

/** The status class of a delivery-status report. */
export type DsnStatusClass = "2" | "4" | "5";

/** One per-recipient result from a delivery-status report. */
export interface DsnRecipientResult {
  /** The original recipient address, when the report named one. */
  readonly recipient: string | null;
  /** The full status field, e.g. `5.1.1`. */
  readonly status: string | null;
  /** The first digit of the status field. */
  readonly statusClass: DsnStatusClass | null;
  /** The action field, e.g. `failed`. */
  readonly action: DsnAction | null;
  /** The remote MTA identifier. */
  readonly remoteMta: string | null;
  /** The diagnostic code reported by the remote MTA. */
  readonly diagnosticCode: string | null;
  /** The human-readable diagnostic text. */
  readonly diagnostic: string | null;
  /** The date of the last delivery attempt, when reported. */
  readonly lastAttemptDate: string | null;
}

/** A parsed delivery-status report. */
export interface DsnReport {
  /** The reporting MTA. */
  readonly reportingMta: string | null;
  /** The original message identifier. */
  readonly originalMessageId: string | null;
  /** The per-recipient results, in report order. */
  readonly recipients: readonly DsnRecipientResult[];
  /** True when the report could not be parsed at all (R-DSN-8). */
  readonly parseError: string | null;
}

/** The outcome a DSN recipient result implies. */
export interface DsnOutcome {
  readonly outcome: DeliveryOutcome;
  readonly errorCode: DeliveryErrorCode | null;
  /** True when the outcome is a permanent failure that shall bounce. */
  readonly permanent: boolean;
  /** True when the outcome is a temporary failure that shall be retried. */
  readonly temporary: boolean;
}

/** The DSN actions the parser recognises. */
const ACTIONS: readonly DsnAction[] = ["failed", "delayed", "delivered", "relayed", "expanded"];

/**
 * Parse one RFC 3464 `message/delivery-status` part.
 *
 * The parser is tolerant: a missing optional field never throws, and a
 * completely malformed report produces a report whose `parseError` is set and
 * whose recipient list is empty (R-DSN-8).
 */
export function parseDeliveryStatus(raw: string): DsnReport {
  const lines = raw.split(/\r?\n/);
  const recipients: DsnRecipientResult[] = [];

  let reportingMta: string | null = null;
  let originalMessageId: string | null = null;
  let parseError: string | null = null;

  let current: MutableRecipient | null = null;
  let inRecipientBlock = false;
  let inOriginalRecipientBlock = false;
  let inFinalRecipientBlock = false;

  for (const line of lines) {
    if (line.trim() === "") {
      // A blank line ends a per-recipient block.
      if (current) {
        recipients.push(finishRecipient(current));
        current = null;
      }
      inRecipientBlock = false;
      inOriginalRecipientBlock = false;
      inFinalRecipientBlock = false;
      continue;
    }

    const separator = line.indexOf(":");
    if (separator === -1) continue;
    const field = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();

    if (field === "reporting-mta") {
      reportingMta = value || null;
      continue;
    }
    if (field === "original-message-id") {
      originalMessageId = value || null;
      continue;
    }

    if (field === "original-recipient") {
      // The original- and final-recipient headers describe the SAME
      // recipient, so a final-recipient that follows in the same block
      // updates the block instead of starting a new one. A second
      // original-recipient starts a new block.
      if (current && inOriginalRecipientBlock) {
        recipients.push(finishRecipient(current));
        current = null;
      }
      inRecipientBlock = true;
      inOriginalRecipientBlock = true;
      inFinalRecipientBlock = false;
      current ??= newRecipient();
      current.recipient = extractRecipientAddress(value);
      continue;
    }
    if (field === "final-recipient") {
      // A final-recipient never starts a block on its own: it either opens
      // one or completes the block an original-recipient opened.
      if (!current) {
        inRecipientBlock = true;
        inOriginalRecipientBlock = false;
        inFinalRecipientBlock = true;
        current = newRecipient();
      }
      current.recipient = extractRecipientAddress(value);
      continue;
    }
    if (field === "action") {
      if (!current) {
        current = newRecipient();
        inRecipientBlock = true;
      }
      current.action = normalizeAction(value);
      continue;
    }
    if (field === "status") {
      if (!current) {
        current = newRecipient();
        inRecipientBlock = true;
      }
      current.status = value || null;
      continue;
    }
    if (field === "remote-mta") {
      if (!current) {
        current = newRecipient();
        inRecipientBlock = true;
      }
      current.remoteMta = value || null;
      continue;
    }
    if (field === "diagnostic-code") {
      if (!current) {
        current = newRecipient();
        inRecipientBlock = true;
      }
      current.diagnosticCode = value || null;
      current.diagnostic = extractDiagnosticText(value);
      continue;
    }
    if (field === "last-attempt-date") {
      if (!current) {
        current = newRecipient();
        inRecipientBlock = true;
      }
      current.lastAttemptDate = value || null;
      continue;
    }
    if (field === "final-log-id" || field === "original-envelope-id") {
      continue;
    }
  }

  if (current) {
    recipients.push(finishRecipient(current));
    current = null;
  }

  if (!reportingMta && recipients.length === 0 && !parseError) {
    // A report with neither a reporting MTA nor any recipient result carries
    // no information; flag it so the handler leaves the state unchanged.
    parseError = "no_delivery_status_fields";
  }

  void inRecipientBlock;
  void inOriginalRecipientBlock;
  void inFinalRecipientBlock;

  return { reportingMta, originalMessageId, recipients, parseError };
}

/** The mutable accumulator for one per-recipient block. */
interface MutableRecipient {
  recipient: string | null;
  status: string | null;
  action: DsnAction | null;
  remoteMta: string | null;
  diagnosticCode: string | null;
  diagnostic: string | null;
  lastAttemptDate: string | null;
}

function newRecipient(): MutableRecipient {
  return {
    recipient: null,
    status: null,
    action: null,
    remoteMta: null,
    diagnosticCode: null,
    diagnostic: null,
    lastAttemptDate: null,
  };
}

function finishRecipient(current: MutableRecipient): DsnRecipientResult {
  const status = current.status;
  const statusClass = status && /^[245]\./.test(status) ? (status[0] as DsnStatusClass) : null;
  return {
    recipient: current.recipient,
    status,
    statusClass,
    action: current.action,
    remoteMta: current.remoteMta,
    diagnosticCode: current.diagnosticCode,
    diagnostic: current.diagnostic,
    lastAttemptDate: current.lastAttemptDate,
  };
}

function normalizeAction(value: string): DsnAction | null {
  const candidate = value.trim().toLowerCase();
  return (ACTIONS as readonly string[]).includes(candidate)
    ? (candidate as DsnAction)
    : null;
}

/**
 * Extract the address from a `Final-Recipient:` line.
 *
 * The value is `rfc822; user@example.com`.
 */
function extractRecipientAddress(value: string): string {
  const semicolon = value.indexOf(";");
  const address = semicolon === -1 ? value : value.slice(semicolon + 1);
  return address.trim();
}

/**
 * Extract the human-readable text from a `Diagnostic-Code:` line.
 *
 * The value is `smtp; 550 5.1.1 User unknown`, so the useful text is the part
 * after the code.
 */
function extractDiagnosticText(value: string): string | null {
  const semicolon = value.indexOf(";");
  if (semicolon === -1) return value.trim() || null;
  const rest = value.slice(semicolon + 1).trim();
  return rest || null;
}

/**
 * Derive the outcome a DSN recipient result implies (R-DSN-3, R-DSN-4).
 *
 * The action field wins over the status class when the two conflict: a
 * `failed` action is permanent even when the class says `4`, and a `delayed`
 * action is temporary even when the class says `5`.
 */
export function classifyDsnResult(result: DsnRecipientResult): DsnOutcome {
  switch (result.action) {
    case "delivered":
    case "relayed":
      return { outcome: "accepted", errorCode: null, permanent: false, temporary: false };
    case "failed":
      return {
        outcome: "bounced",
        errorCode: "mailbox_unavailable",
        permanent: true,
        temporary: false,
      };
    case "delayed":
      return {
        outcome: "deferred",
        errorCode: "temporary_failure",
        permanent: false,
        temporary: true,
      };
    default:
      break;
  }

  switch (result.statusClass) {
    case "2":
      return { outcome: "accepted", errorCode: null, permanent: false, temporary: false };
    case "4":
      return {
        outcome: "deferred",
        errorCode: "temporary_failure",
        permanent: false,
        temporary: true,
      };
    case "5":
      return {
        outcome: "bounced",
        errorCode: "mailbox_unavailable",
        permanent: true,
        temporary: false,
      };
    default:
      // An unknown or missing status is treated as temporary: it is not
      // evidence of a permanent mailbox failure.
      return {
        outcome: "deferred",
        errorCode: "temporary_failure",
        permanent: false,
        temporary: true,
      };
  }
}

/**
 * True when the DSN result confirms delivery (R-DSN-7).
 *
 * Only a `2.x.x` status or a `delivered`/`relayed` action confirms delivery.
 */
export function isDsnDeliveryConfirmed(result: DsnRecipientResult): boolean {
  return result.statusClass === "2" || result.action === "delivered" || result.action === "relayed";
}

/**
 * Parse the delivery-status part out of a full multipart report.
 *
 * The engine owns the parser; the transport that carries the report in is a
 * separate concern (IR §11 Q5). This helper accepts either a bare
 * delivery-status part or a whole report, and returns the delivery-status
 * part in the second case.
 */
export function extractDeliveryStatusPart(report: string): string {
  const boundaryMatch = /boundary="?([^"\r\n]+)"?/i.exec(report);
  if (!boundaryMatch) return report;
  const boundary = boundaryMatch[1];
  const parts = report.split(`--${boundary}`);
  const deliveryPart = parts.find((part) => /Content-Type:\s*message\/delivery-status/i.test(part));
  return deliveryPart ?? report;
}

export { extractRecipientAddress };
