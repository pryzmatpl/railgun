// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors
//
// Request-shape validation and sender-domain authorization.
//
// Contract: docs/design/fbc87052-eb7d-4179-bb6c-b24a702e1a61.md §6.1
// (gates 0, 2 and 4), §7.2.3 and §8.3.1.
//
// A malformed message is rejected as malformed (`VALIDATION_FAILED`), never
// as suppressed — the two demand different operator responses
// (IR R-6.1.2). A null reverse-path is part of the request-shape gate for
// the same reason (IR §7.2.3).

import { REASON_CODES, type PolicyDecision } from "../domain/policy.js";
import { parseAddress } from "../security/address.js";
import type { SubmissionRequest } from "../domain/policy.js";
import { authorizeSenderDomain } from "./relay.js";

/** The outcome of the shape and sender-domain gates. */
export interface RequestShapeResult {
  /** The decision, or `null` when the request is acceptable. */
  readonly decision: PolicyDecision | null;
  readonly reason_code: string | null;
  readonly rule_id: string;
  /** The normalized sending domain, when the request is acceptable. */
  readonly sender_domain: string;
}

const ACCEPTED: RequestShapeResult = {
  decision: null,
  reason_code: null,
  rule_id: "",
  sender_domain: "",
};

/**
 * Validates the request shape, the sender-domain authorization and the
 * header hygiene of a submission.
 */
export function validateRequestShape(
  request: SubmissionRequest,
  authorizedSubdomains: readonly string[],
): RequestShapeResult {
  // Gate 0 — the request must carry a request id.
  if (request.request_id.trim().length === 0) {
    return {
      decision: "reject",
      reason_code: REASON_CODES.VALIDATION_FAILED,
      rule_id: "gate.request_id.required",
      sender_domain: "",
    };
  }

  // A null reverse-path is never accepted from a client (IR §7.2.3).
  if (request.envelope.sender.length === 0 || request.envelope.sender === "<>") {
    return {
      decision: "reject",
      reason_code: REASON_CODES.VALIDATION_FAILED,
      rule_id: "gate.envelope.null_reverse_path",
      sender_domain: "",
    };
  }

  const senderDomain = request.envelope.sender.split("@")[1]?.toLowerCase() ?? "";

  // Gate 2 — sender-domain authorization.
  const senderAuth = authorizeSenderDomain(request.principal, senderDomain, {
    authorized_subdomains: authorizedSubdomains,
  });
  if (!senderAuth.allowed) {
    return {
      decision: "deny",
      reason_code: senderAuth.reason_code,
      rule_id: senderAuth.rule_id,
      sender_domain: senderDomain,
    };
  }

  // Gate 4 — header hygiene.
  const fromHeaders = request.message.headers["from"];
  if (fromHeaders === undefined || fromHeaders.trim().length === 0) {
    return {
      decision: "reject",
      reason_code: REASON_CODES.VALIDATION_FAILED,
      rule_id: "gate.headers.from_missing",
      sender_domain: senderDomain,
    };
  }
  if (fromHeaders.includes("\r") || fromHeaders.includes("\n")) {
    return {
      decision: "reject",
      reason_code: REASON_CODES.HEADER_INJECTION,
      rule_id: "gate.headers.crlf",
      sender_domain: senderDomain,
    };
  }
  if (parseAddress(fromHeaders) === null) {
    return {
      decision: "reject",
      reason_code: REASON_CODES.VALIDATION_FAILED,
      rule_id: "gate.headers.from_unparseable",
      sender_domain: senderDomain,
    };
  }

  return { ...ACCEPTED, sender_domain: senderDomain };
}
