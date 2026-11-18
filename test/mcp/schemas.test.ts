// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 RailGun contributors

/**
 * `email_send` input contract: strict superset of the frozen Jaisiu schema
 * with appropriate validation (MCP-AC2, MCP-AC3).
 */

import { describe, expect, it } from "vitest";

import { RailGunError } from "../../src/mcp/errors.js";
import {
  DEFAULT_MAX_RECIPIENTS,
  normalizeSendInput,
} from "../../src/mcp/schemas.js";

/** The frozen Jaisiu payload — it must pass unchanged. */
const JaisiuPayload = {
  to: "alice@example.com",
  subject: "Hello",
  text: "Hi there",
  html: "<p>Hi there</p>",
  from: "bot@example.com",
  replyTo: "noreply@example.com",
  cc: "carol@example.com",
  bcc: "dave@example.com",
  requestId: "req-123",
};

function expectError(fn: () => unknown): RailGunError {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(RailGunError);
    return error as RailGunError;
  }
  throw new Error("Expected the call to throw.");
}

describe("email_send input — strict superset", () => {
  it("accepts the frozen Jaisiu payload unchanged", () => {
    const input = normalizeSendInput(JaisiuPayload);
    expect(input.to).toEqual(["alice@example.com"]);
    expect(input.cc).toEqual(["carol@example.com"]);
    expect(input.bcc).toEqual(["dave@example.com"]);
    expect(input.subject).toBe("Hello");
    expect(input.text).toBe("Hi there");
    expect(input.html).toBe("<p>Hi there</p>");
    expect(input.from).toBe("bot@example.com");
    expect(input.replyTo).toBe("noreply@example.com");
    expect(input.requestId).toBe("req-123");
  });

  it("accepts every Jaisiu field individually", () => {
    const cases: Record<string, unknown>[] = [
      { to: "a@example.com", subject: "s", text: "t", requestId: "r" },
      { to: "a@example.com", subject: "s", html: "<p>h</p>", requestId: "r" },
      { to: "a@example.com", subject: "s", text: "t", from: "b@example.com", requestId: "r" },
      { to: "a@example.com", subject: "s", text: "t", replyTo: "c@example.com", requestId: "r" },
      { to: "a@example.com", subject: "s", text: "t", cc: "d@example.com", requestId: "r" },
      { to: "a@example.com", subject: "s", text: "t", bcc: "e@example.com", requestId: "r" },
      { to: "a@example.com", subject: "s", text: "t", requestId: "r" },
    ];
    for (const payload of cases) {
      expect(() => normalizeSendInput(payload)).not.toThrow();
    }
  });

  it("accepts the metadata extension", () => {
    const input = normalizeSendInput({
      ...JaisiuPayload,
      metadata: { campaign: "launch", attempt: "1" },
    });
    expect(input.metadata).toEqual({ campaign: "launch", attempt: "1" });
  });

  it("accepts an array of recipients", () => {
    const input = normalizeSendInput({
      to: ["a@example.com", "b@example.com"],
      subject: "s",
      text: "t",
      requestId: "r",
    });
    expect(input.to).toEqual(["a@example.com", "b@example.com"]);
  });

  it("splits a comma-separated recipient list", () => {
    const input = normalizeSendInput({
      to: "a@example.com, b@example.com",
      subject: "s",
      text: "t",
      requestId: "r",
    });
    expect(input.to).toEqual(["a@example.com", "b@example.com"]);
  });

  it("collapses duplicate recipients case-insensitively", () => {
    const input = normalizeSendInput({
      to: ["A@example.com", "a@example.com"],
      cc: "b@example.com",
      subject: "s",
      text: "t",
      requestId: "r",
    });
    expect(input.to).toEqual(["A@example.com"]);
    expect(input.cc).toEqual(["b@example.com"]);
  });

  it("rejects unknown properties", () => {
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, unexpected: "value" }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
  });
});

describe("email_send input — validation", () => {
  it("requires to, subject and requestId", () => {
    for (const missing of ["to", "subject", "requestId"]) {
      const payload: Record<string, unknown> = {
        to: "a@example.com",
        subject: "s",
        text: "t",
        requestId: "r",
      };
      delete payload[missing];
      const error = expectError(() => normalizeSendInput(payload));
      expect(error.code).toBe("VALIDATION_FAILED");
      expect(error.field).toBe(missing);
    }
  });

  it("rejects a blank requestId", () => {
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, requestId: "   " }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
    expect(error.field).toBe("requestId");
  });

  it("rejects a message without a body", () => {
    const error = expectError(() =>
      normalizeSendInput({ to: "a@example.com", subject: "s", requestId: "r" }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
    expect(error.field).toBe("text|html");
  });

  it("rejects an empty body when present", () => {
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, text: "", html: "" }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
  });

  it("rejects CRLF injection in an address", () => {
    const error = expectError(() =>
      normalizeSendInput({
        ...JaisiuPayload,
        to: "victim@example.com\r\nBcc: attacker@example.com",
      }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
  });

  it("rejects NUL injection in an address", () => {
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, to: "victim@example.com\0" }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
  });

  it("rejects CRLF injection in the subject", () => {
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, subject: "hello\r\nBcc: attacker@example.com" }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
    expect(error.field).toBe("subject");
  });

  it("rejects a malformed address", () => {
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, to: "not-an-address" }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
  });

  it("rejects an oversized subject", () => {
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, subject: "x".repeat(1200) }),
    );
    expect(error.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("rejects an over-cap recipient count", () => {
    const to = Array.from(
      { length: DEFAULT_MAX_RECIPIENTS + 1 },
      (_, index) => `user${index}@example.com`,
    );
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, to }),
    );
    expect(error.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("rejects an over-cap metadata map", () => {
    const metadata: Record<string, string> = {};
    for (let index = 0; index < 40; index += 1) {
      metadata[`key-${index}`] = "value";
    }
    const error = expectError(() =>
      normalizeSendInput({ ...JaisiuPayload, metadata }),
    );
    expect(error.code).toBe("VALIDATION_FAILED");
  });
});
