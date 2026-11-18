/* RailGun direct-to-MX delivery engine — unit tests.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";

import {
  classifyDsnResult,
  extractDeliveryStatusPart,
  isDsnDeliveryConfirmed,
  parseDeliveryStatus,
} from "../../src/outbound/dsn.js";
import {
  buildMessageId,
  messageIdLocalPart,
  normalizeDomain,
} from "../../src/outbound/message-id.js";
import {
  classifySmtpResponse,
  extractEnhancedCode,
  permanentCodeFor,
} from "../../src/outbound/classify.js";
import {
  backoffCeiling,
  backoffDelay,
  deterministicJitter,
  effectiveMaxAttempts,
} from "../../src/outbound/backoff.js";
import {
  checkAddressPolicy,
  isNullMx,
  isTemporaryDnsError,
  orderAddresses,
  orderMxRecords,
  reverseDnsMatches,
} from "../../src/outbound/dns.js";
import { dotStuff, parseCapabilities, sanitizeResponse, takeReply } from "../../src/outbound/smtp-client.js";

describe("DSN parsing (R-DSN-1 … R-DSN-10)", () => {
  const singleRecipient = [
    "Reporting-MTA: dns; mx.example.test",
    "",
    "Final-Recipient: rfc822; user@example.test",
    "Original-Recipient: rfc822; user@example.test",
    "Action: failed",
    "Status: 5.1.1",
    "Remote-MTA: dns; mx.remote.test",
    "Diagnostic-Code: smtp; 550 5.1.1 <user@example.test>: Recipient address rejected",
    "Last-Attempt-Date: Tue, 17 Nov 2026 10:00:00 +0000",
    "",
  ].join("\r\n");

  it("parses one recipient result", () => {
    const report = parseDeliveryStatus(singleRecipient);
    expect(report.parseError).toBeNull();
    expect(report.reportingMta).toBe("dns; mx.example.test");
    expect(report.recipients).toHaveLength(1);
    const result = report.recipients[0]!;
    expect(result.recipient).toBe("user@example.test");
    expect(result.status).toBe("5.1.1");
    expect(result.statusClass).toBe("5");
    expect(result.action).toBe("failed");
    expect(result.remoteMta).toBe("dns; mx.remote.test");
    expect(result.diagnosticCode).toContain("550");
    expect(result.lastAttemptDate).toContain("17 Nov 2026");
  });

  it("parses the multi-recipient delivery-status form", () => {
    const report = parseDeliveryStatus(
      [
        "Reporting-MTA: dns; mx.example.test",
        "",
        "Original-Recipient: rfc822; first@example.test",
        "Final-Recipient: rfc822; first@example.test",
        "Action: failed",
        "Status: 5.1.1",
        "",
        "Original-Recipient: rfc822; second@example.test",
        "Final-Recipient: rfc822; second@example.test",
        "Action: delayed",
        "Status: 4.4.7",
        "",
      ].join("\r\n"),
    );
    expect(report.recipients).toHaveLength(2);
    expect(report.recipients[0]!.recipient).toBe("first@example.test");
    expect(report.recipients[1]!.recipient).toBe("second@example.test");
    expect(report.recipients[1]!.statusClass).toBe("4");
  });

  it("classifies 2.x.x as delivered", () => {
    const result = parseDeliveryStatus(
      ["Final-Recipient: rfc822; a@b.test", "Action: delivered", "Status: 2.0.0", ""].join("\r\n"),
    ).recipients[0]!;
    expect(classifyDsnResult(result).outcome).toBe("accepted");
    expect(isDsnDeliveryConfirmed(result)).toBe(true);
  });

  it("classifies 4.x.x as temporary", () => {
    const result = parseDeliveryStatus(
      ["Final-Recipient: rfc822; a@b.test", "Action: delayed", "Status: 4.4.7", ""].join("\r\n"),
    ).recipients[0]!;
    const outcome = classifyDsnResult(result);
    expect(outcome.outcome).toBe("deferred");
    expect(outcome.temporary).toBe(true);
    expect(outcome.permanent).toBe(false);
  });

  it("classifies 5.x.x as permanent", () => {
    const result = parseDeliveryStatus(
      ["Final-Recipient: rfc822; a@b.test", "Action: failed", "Status: 5.1.1", ""].join("\r\n"),
    ).recipients[0]!;
    const outcome = classifyDsnResult(result);
    expect(outcome.outcome).toBe("bounced");
    expect(outcome.permanent).toBe(true);
  });

  it("lets the action win when the class and the action conflict", () => {
    // A `failed` action on a `4.x.x` status is permanent (R-DSN-4).
    const failed = parseDeliveryStatus(
      ["Final-Recipient: rfc822; a@b.test", "Action: failed", "Status: 4.4.7", ""].join("\r\n"),
    ).recipients[0]!;
    expect(classifyDsnResult(failed).permanent).toBe(true);

    // A `delayed` action on a `5.x.x` status is temporary.
    const delayed = parseDeliveryStatus(
      ["Final-Recipient: rfc822; a@b.test", "Action: delayed", "Status: 5.1.1", ""].join("\r\n"),
    ).recipients[0]!;
    expect(classifyDsnResult(delayed).temporary).toBe(true);
  });

  it("never fabricates delivery for a 4.x.x or 5.x.x status", () => {
    for (const status of ["4.4.7", "5.1.1"]) {
      const result = parseDeliveryStatus(
        [`Final-Recipient: rfc822; a@b.test`, `Status: ${status}`, ""].join("\r\n"),
      ).recipients[0]!;
      expect(isDsnDeliveryConfirmed(result)).toBe(false);
    }
  });

  it("tolerates a malformed report without throwing", () => {
    const report = parseDeliveryStatus("not a delivery status report at all");
    expect(report.recipients).toHaveLength(0);
    expect(report.parseError).not.toBeNull();
  });

  it("extracts the delivery-status part from a multipart report", () => {
    const multipart = [
      "Content-Type: multipart/report; boundary=abc",
      "",
      "--abc",
      "Content-Type: text/plain",
      "",
      "delivery failed",
      "--abc",
      "Content-Type: message/delivery-status",
      "",
      "Reporting-MTA: dns; mx.test",
      "",
      "Final-Recipient: rfc822; a@b.test",
      "Action: failed",
      "Status: 5.1.1",
      "",
      "--abc--",
    ].join("\r\n");
    const part = extractDeliveryStatusPart(multipart);
    expect(part).toContain("Reporting-MTA");
    expect(part).not.toContain("delivery failed");
  });
});

describe("deterministic Message-ID (R-MSGID-1 … R-MSGID-5)", () => {
  it("is byte-identical for the same request", () => {
    const first = buildMessageId("tenant-1", "request-1", "example.test");
    const second = buildMessageId("tenant-1", "request-1", "example.test");
    expect(first).toBe(second);
  });

  it("differs for a different tenant or request", () => {
    const base = buildMessageId("tenant-1", "request-1", "example.test");
    expect(buildMessageId("tenant-2", "request-1", "example.test")).not.toBe(base);
    expect(buildMessageId("tenant-1", "request-2", "example.test")).not.toBe(base);
  });

  it("is stable across processes (a digest, not a random id)", () => {
    // The local part is a pure function of the canonical idempotency key.
    expect(messageIdLocalPart("tenant-1", "request-1")).toBe(
      messageIdLocalPart("tenant-1", "request-1"),
    );
    expect(messageIdLocalPart("tenant-1", "request-1")).toMatch(/^[0-9a-f]{32}$/);
  });

  it("produces a syntactically valid addr-spec", () => {
    const messageId = buildMessageId("tenant-1", "request-1", "example.test");
    expect(messageId).toMatch(/^[0-9a-f]{32}@[a-z0-9.-]+$/);
    // The local part carries no `>`, `<`, `@`, whitespace or control character.
    expect(messageId.split("@")[0]!).not.toMatch(/[<>@\s]/);
  });

  it("normalizes the domain", () => {
    expect(normalizeDomain("Example.TEST.")).toBe("example.test");
    expect(normalizeDomain("localhost")).toBe("localhost.invalid");
  });
});

describe("SMTP response classification (R-CLS-1 … R-CLS-4)", () => {
  it("classifies 2xx as success", () => {
    const result = classifySmtpResponse(250, "2.0.0 Accepted");
    expect(result.outcome).toBe("accepted");
    expect(result.errorCode).toBeNull();
  });

  it("classifies 4xx as temporary and never as a bounce", () => {
    for (const code of [421, 450, 451, 452, 454]) {
      const result = classifySmtpResponse(code, "4.3.0 Try later");
      expect(result.outcome).toBe("deferred");
      expect(result.temporary).toBe(true);
      expect(result.permanent).toBe(false);
      expect(result.errorCode).toBe("temporary_failure");
    }
  });

  it("classifies 5xx as permanent", () => {
    for (const code of [550, 551, 553, 554, 555]) {
      const result = classifySmtpResponse(code, "5.0.0 Rejected");
      expect(result.outcome).toBe("bounced");
      expect(result.permanent).toBe(true);
    }
  });

  it("refines the permanent code from the enhanced status code", () => {
    expect(permanentCodeFor(550, "5.1.1")).toBe("user_not_local");
    expect(permanentCodeFor(550, "5.7.1")).toBe("policy_refused");
    expect(permanentCodeFor(552, null)).toBe("message_too_large");
    expect(permanentCodeFor(550, null)).toBe("mailbox_unavailable");
  });

  it("extracts the enhanced status code", () => {
    expect(extractEnhancedCode("550 5.1.1 User unknown")).toBe("5.1.1");
    expect(extractEnhancedCode("no code here")).toBeNull();
  });
});

describe("bounded exponential backoff (R-RET-1 … R-RET-4)", () => {
  it("doubles the ceiling per attempt and caps it at six hours", () => {
    expect(backoffCeiling(1)).toBe(60_000);
    expect(backoffCeiling(2)).toBe(120_000);
    expect(backoffCeiling(3)).toBe(240_000);
    expect(backoffCeiling(20)).toBe(6 * 60 * 60 * 1000);
  });

  it("applies full jitter within the ceiling", () => {
    expect(backoffDelay({ attempt: 1, random: () => 0 })).toBe(0);
    expect(backoffDelay({ attempt: 1, random: () => 0.5 })).toBe(30_000);
    expect(backoffDelay({ attempt: 1, random: () => 0.999999 })).toBeLessThan(60_000);
  });

  it("is deterministic for the same message and attempt", () => {
    const first = deterministicJitter(2, "message-1");
    const second = deterministicJitter(2, "message-1");
    expect(first).toBe(second);
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(1);
  });

  it("honours the smaller of the two attempt ceilings", () => {
    expect(effectiveMaxAttempts(5)).toBe(5);
    expect(effectiveMaxAttempts(20)).toBe(8);
    expect(effectiveMaxAttempts(1)).toBe(1);
  });
});

describe("DNS ordering and policy (R-DNS-1, R-DNS-4, R-DNS-6, R-CONN-7, R-DNS-10)", () => {
  it("orders MX records by preference, then lexicographically", () => {
    const ordered = orderMxRecords([
      { exchange: "b.mx.test", preference: 10 },
      { exchange: "a.mx.test", preference: 10 },
      { exchange: "c.mx.test", preference: 5 },
    ]);
    expect(ordered.map((r) => r.exchange)).toEqual(["c.mx.test", "a.mx.test", "b.mx.test"]);
  });

  it("recognises the null MX", () => {
    expect(isNullMx([{ exchange: ".", preference: 0 }])).toBe(true);
    expect(isNullMx([{ exchange: "mx.test", preference: 0 }])).toBe(false);
    expect(isNullMx([])).toBe(false);
  });

  it("orders the address families per the policy", () => {
    const v4 = ["192.0.2.1"];
    const v6 = ["2001:db8::1"];
    expect(
      orderAddresses("mx.test", v4, v6, { ipv4First: true, ipv6Fallback: true }).map((c) => c.family),
    ).toEqual([4, 6]);
    expect(
      orderAddresses("mx.test", v4, v6, { ipv4First: false, ipv6Fallback: true }).map((c) => c.family),
    ).toEqual([6, 4]);
    expect(
      orderAddresses("mx.test", v4, v6, { ipv4First: true, ipv6Fallback: false }).map((c) => c.family),
    ).toEqual([4]);
  });

  it("refuses private and loopback addresses without the local exception", () => {
    expect(checkAddressPolicy("127.0.0.1", { allowLocal: false }).allowed).toBe(false);
    expect(checkAddressPolicy("10.0.0.5", { allowLocal: false }).allowed).toBe(false);
    expect(checkAddressPolicy("192.168.1.1", { allowLocal: false }).allowed).toBe(false);
    expect(checkAddressPolicy("169.254.1.1", { allowLocal: false }).allowed).toBe(false);
    expect(checkAddressPolicy("2001:db8::1", { allowLocal: false }).allowed).toBe(true);
    // The explicit, test-only exception.
    expect(checkAddressPolicy("127.0.0.1", { allowLocal: true }).allowed).toBe(true);
  });

  it("matches the reverse DNS names against the MX hostname", () => {
    expect(reverseDnsMatches(["mx.fake.test"], "mx.fake.test")).toBe(true);
    expect(reverseDnsMatches(["host.mx.fake.test"], "mx.fake.test")).toBe(true);
    expect(reverseDnsMatches(["other.test"], "mx.fake.test")).toBe(false);
    expect(reverseDnsMatches([], "mx.fake.test")).toBe(false);
  });

  it("separates temporary DNS failures from a missing name", () => {
    expect(isTemporaryDnsError({ code: "SERVFAIL" })).toBe(true);
    expect(isTemporaryDnsError({ code: "ETIMEOUT" })).toBe(true);
    expect(isTemporaryDnsError({ code: "ENOTFOUND" })).toBe(false);
    expect(isTemporaryDnsError({ code: "ENODATA" })).toBe(false);
  });
});

describe("the SMTP client's wire primitives (R-CLIENT-4, R-SMTP-7, R-SMTP-9)", () => {
  it("parses a multi-line reply", () => {
    const parsed = takeReply(Buffer.from("250-fake.mx.test\r\n250-SIZE 100\r\n250 8BITMIME\r\n"));
    expect(parsed).not.toBeNull();
    expect(parsed!.reply.code).toBe(250);
    expect(parsed!.reply.text).toContain("SIZE 100");
  });

  it("rejects a malformed reply", () => {
    expect(() => takeReply(Buffer.from("garbage\r\n"))).toThrow(/Malformed/);
  });

  it("parses the advertised capabilities", () => {
    const capabilities = parseCapabilities({
      code: 250,
      text: "fake.mx.test\nSIZE 10240000\n8BITMIME\nPIPELINING\nSTARTTLS\nAUTH PLAIN LOGIN",
      enhancedCode: null,
      raw: "",
    });
    expect(capabilities.starttls).toBe(true);
    expect(capabilities.pipelining).toBe(true);
    expect(capabilities.eightBitMime).toBe(true);
    expect(capabilities.maxMessageBytes).toBe(10_240_000);
    expect(capabilities.authMechanisms).toEqual(["PLAIN", "LOGIN"]);
  });

  it("dot-stuffs a body and appends the terminator", () => {
    const stuffed = dotStuff(Buffer.from("line one\n.hidden\nlast\n", "utf8")).toString("utf8");
    expect(stuffed).toBe("line one\n..hidden\nlast\n.\r\n");
  });

  it("does not modify a body without dot lines", () => {
    const body = "Subject: hi\r\n\r\nhello\r\n";
    expect(dotStuff(Buffer.from(body, "utf8")).toString("utf8")).toBe(`${body}.\r\n`);
  });

  it("sanitizes and bounds a peer response", () => {
    expect(sanitizeResponse("line one\r\nline two")).toBe("line one line two");
    expect(sanitizeResponse("x".repeat(1000)).length).toBe(256);
  });
});
