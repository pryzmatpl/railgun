/* RailGun SMTP submission server — parser unit tests.
 * Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { describe, expect, it } from "vitest";

import {
  DataAccumulator,
  SmtpParseError,
  isNonAsciiAddress,
  parseCommand,
  parseHeaders,
  parseParams,
  parsePath,
  splitCommand,
} from "../../src/smtp/parser.js";

describe("splitCommand", () => {
  it("splits a verb and argument text", () => {
    expect(splitCommand("EHLO client.example")).toEqual({
      verb: "EHLO",
      args: "client.example",
    });
  });

  it("upper-cases the verb but preserves argument case (C-2)", () => {
    expect(splitCommand("mail from:<Sender@Example.COM>")).toEqual({
      verb: "MAIL",
      args: "from:<Sender@Example.COM>",
    });
  });

  it("handles a verb with no argument", () => {
    expect(splitCommand("QUIT")).toEqual({ verb: "QUIT", args: "" });
  });
});

describe("parseCommand", () => {
  it("parses EHLO and HELO", () => {
    expect(parseCommand("EHLO client.example")).toEqual({
      kind: "ehlo",
      domain: "client.example",
    });
    expect(parseCommand("HELO client.example")).toEqual({
      kind: "helo",
      domain: "client.example",
    });
  });

  it("parses MAIL FROM with and without a space after the colon", () => {
    expect(parseCommand("MAIL FROM:<a@example.com>")).toMatchObject({
      kind: "mail",
      path: { address: "a@example.com" },
    });
    expect(parseCommand("MAIL FROM: <a@example.com>")).toMatchObject({
      kind: "mail",
      path: { address: "a@example.com" },
    });
  });

  it("parses ESMTP parameters on MAIL FROM (C-5)", () => {
    const parsed = parseCommand("MAIL FROM:<a@example.com> SIZE=1234 BODY=8BITMIME");
    expect(parsed.kind).toBe("mail");
    if (parsed.kind !== "mail") throw new Error("unreachable");
    expect(parsed.path.params.get("SIZE")).toBe("1234");
    expect(parsed.path.params.get("BODY")).toBe("8BITMIME");
  });

  it("parses the null reverse path", () => {
    const parsed = parseCommand("MAIL FROM:<>");
    expect(parsed.kind).toBe("mail");
    if (parsed.kind !== "mail") throw new Error("unreachable");
    expect(parsed.path.address).toBeNull();
  });

  it("rejects a source route with 501 (A-4)", () => {
    expect(() => parseCommand("MAIL FROM:<@a,@b:user@example.com>")).toThrow(SmtpParseError);
    try {
      parseCommand("MAIL FROM:<@a,@b:user@example.com>");
    } catch (error) {
      expect((error as SmtpParseError).code).toBe(501);
    }
  });

  it("rejects a malformed path with 501 (A-5)", () => {
    for (const line of ["RCPT TO:<not-an-address>", "RCPT TO:<@>", "RCPT TO:<a@b@c>"]) {
      try {
        parseCommand(line);
        throw new Error(`expected ${line} to fail`);
      } catch (error) {
        expect(error).toBeInstanceOf(SmtpParseError);
        expect((error as SmtpParseError).code).toBe(501);
      }
    }
  });

  it("rejects a malformed ESMTP parameter with 555 (C-5)", () => {
    try {
      parseCommand("MAIL FROM:<a@example.com> NOTAPARAM");
      throw new Error("expected a parse failure");
    } catch (error) {
      expect(error).toBeInstanceOf(SmtpParseError);
      expect((error as SmtpParseError).code).toBe(555);
    }
  });

  it("rejects an unknown verb as unknown rather than throwing", () => {
    expect(parseCommand("FROBNICATE")).toEqual({ kind: "unknown", verb: "FROBNICATE" });
  });

  it("rejects AUTH with no mechanism", () => {
    try {
      parseCommand("AUTH");
      throw new Error("expected a parse failure");
    } catch (error) {
      expect((error as SmtpParseError).code).toBe(501);
    }
  });

  it("upper-cases the auth mechanism but keeps the initial response (C-2)", () => {
    expect(parseCommand("AUTH plain AAAA")).toEqual({
      kind: "auth",
      mechanism: "PLAIN",
      initialResponse: "AAAA",
    });
  });
});

describe("parsePath", () => {
  it("rejects a path that is not angle-bracketed", () => {
    try {
      parsePath("a@example.com", false);
      throw new Error("expected a parse failure");
    } catch (error) {
      expect((error as SmtpParseError).code).toBe(501);
    }
  });

  it("rejects the null reverse path where it is not allowed", () => {
    try {
      parsePath("", false);
      throw new Error("expected a parse failure");
    } catch (error) {
      expect((error as SmtpParseError).code).toBe(501);
    }
  });
});

describe("parseParams", () => {
  it("returns an empty map for empty input", () => {
    expect(parseParams("").size).toBe(0);
  });

  it("upper-cases parameter names", () => {
    expect(parseParams("size=10").get("SIZE")).toBe("10");
  });
});

describe("isNonAsciiAddress", () => {
  it("detects non-ASCII characters (A-6)", () => {
    expect(isNonAsciiAddress("user@example.net")).toBe(false);
    expect(isNonAsciiAddress("üser@example.net")).toBe(true);
  });
});

describe("DataAccumulator — dot-unstuffing and normalization", () => {
  it("removes exactly one leading dot (D-3)", () => {
    const acc = new DataAccumulator(1024);
    acc.push(Buffer.from("..hidden\r\n", "latin1"));
    expect(acc.bytes().toString("latin1")).toBe(".hidden\r\n");
  });

  it("stores `...` as `..`", () => {
    const acc = new DataAccumulator(1024);
    acc.push(Buffer.from("...\r\n", "latin1"));
    expect(acc.bytes().toString("latin1")).toBe("..\r\n");
  });

  it("never stores the terminator", () => {
    const acc = new DataAccumulator(1024);
    const complete = acc.push(Buffer.from("normal\r\n.\r\n", "latin1"));
    expect(complete).toBe(true);
    expect(acc.bytes().toString("latin1")).toBe("normal\r\n");
  });

  it("accepts a bare LF terminator (D-2)", () => {
    const acc = new DataAccumulator(1024);
    expect(acc.push(Buffer.from("normal\n.\n", "latin1"))).toBe(true);
    expect(acc.bytes().toString("latin1")).toBe("normal\r\n");
  });

  it("normalizes bare LF to CRLF (D-4)", () => {
    const acc = new DataAccumulator(1024);
    acc.push(Buffer.from("a\nb\r\n", "latin1"));
    expect(acc.bytes().toString("latin1")).toBe("a\r\nb\r\n");
  });

  it("handles a body split across chunks", () => {
    const acc = new DataAccumulator(1024);
    acc.push(Buffer.from("hel", "latin1"));
    acc.push(Buffer.from("lo\r\n", "latin1"));
    expect(acc.bytes().toString("latin1")).toBe("hello\r\n");
  });

  it("flags an oversize body (D-5)", () => {
    const acc = new DataAccumulator(8);
    acc.push(Buffer.from("0123456789\r\n", "latin1"));
    expect(acc.tooLarge).toBe(true);
  });

  it("does not treat `..` alone as the terminator", () => {
    const acc = new DataAccumulator(1024);
    const complete = acc.push(Buffer.from("..\r\n", "latin1"));
    expect(complete).toBe(false);
    expect(acc.bytes().toString("latin1")).toBe(".\r\n");
  });
});

describe("parseHeaders", () => {
  it("parses a header block with folded headers (M-2)", () => {
    const raw = Buffer.from(
      "From: sender@example.com\r\nSubject: a very\r\n long subject\r\n\r\nbody\r\n",
      "latin1",
    );
    const result = parseHeaders(raw);
    expect(result.malformed).toBe(false);
    expect(result.headers.map((header) => header.name)).toEqual(["from", "subject"]);
    expect(result.headers[1]!.value).toBe("a very long subject");
  });

  it("flags a malformed header line (M-4)", () => {
    const result = parseHeaders(Buffer.from("not-a-header\r\n\r\nbody\r\n", "latin1"));
    expect(result.malformed).toBe(true);
  });

  it("counts the headers", () => {
    const result = parseHeaders(
      Buffer.from("From: a@b.c\r\nTo: d@e.f\r\nSubject: x\r\n\r\nbody\r\n", "latin1"),
    );
    expect(result.headerCount).toBe(3);
  });
});
