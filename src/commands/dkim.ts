// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun dkim new` — generate a DKIM keypair and the DNS records to publish.
 *
 * Self-hosting a sending domain means three things must line up: a keypair,
 * a published public key, and a matching signer configuration. This command
 * produces all three so the operator never has to hand-roll `openssl` and
 * risk publishing a key that does not match the signer.
 *
 * The private key is written to a file with `0600` permissions and is never
 * printed. The public key is printed, because publishing it is the point.
 *
 * The command performs **no** DNS mutation. RailGun verifies DNS; it never
 * changes it. Every record is printed for the operator to publish.
 */
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

import { CliError } from "../cli/errors.js";
import { type CommandContext } from "../cli/context.js";
import { renderJson } from "../cli/output.js";

/** Options accepted by `dkim new`. */
export interface DkimNewOptions {
  /** The sending domain, e.g. `example.com`. */
  domain: string | undefined;
  /** The DKIM selector, e.g. `mail`. */
  selector: string | undefined;
  /** Where the private key is written. */
  privateKeyPath: string | undefined;
  /** Where the public key is written. */
  publicKeyPath: string | undefined;
  /** The outbound IPv4 address of the RailGun host, for the SPF record. */
  ipv4: string | undefined;
  /** The outbound IPv6 address of the RailGun host, for the SPF record. */
  ipv6: string | undefined;
  /** The hostname that publishes the MX record. */
  mailHost: string | undefined;
  /** The DMARC reporting mailbox. */
  rua: string | undefined;
  /** The DMARC policy to publish: `none`, `quarantine` or `reject`. */
  dmarcPolicy: string | undefined;
}

/** A generated keypair and the records that reference it. */
export interface DkimKeypairResult {
  readonly domain: string;
  readonly selector: string;
  readonly algorithm: "rsa-sha256";
  readonly keyBits: number;
  readonly privateKeyPath: string;
  readonly publicKeyPath: string;
  /** The DNS records the operator must publish, in publication order. */
  readonly records: readonly DnsRecord[];
}

/** One DNS record the operator must publish. */
export interface DnsRecord {
  readonly name: string;
  readonly type: "MX" | "A" | "AAAA" | "TXT";
  readonly value: string;
  readonly purpose: string;
}

const DOMAIN_PATTERN = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;
const SELECTOR_PATTERN = /^[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$/;
const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_PATTERN = /^[0-9A-Fa-f:]+$/;

/** The valid DKIM `p=` tag values. */
const DMARC_POLICIES = new Set(["none", "quarantine", "reject"]);

/**
 * Validate a domain name.
 *
 * @throws CliError when the domain is missing or malformed.
 */
function requireDomain(value: string | undefined): string {
  const domain = value?.trim().toLowerCase();
  if (!domain) {
    throw CliError.usage("A sending domain is required: railgun dkim new --domain example.com");
  }
  if (!DOMAIN_PATTERN.test(domain)) {
    throw CliError.usage(`'${domain}' is not a valid domain name`);
  }
  return domain;
}

/**
 * Validate the DKIM selector.
 *
 * @throws CliError when the selector is missing or malformed.
 */
function requireSelector(value: string | undefined): string {
  const selector = value?.trim().toLowerCase();
  if (!selector) {
    throw CliError.usage("A selector is required: railgun dkim new --selector mail");
  }
  if (!SELECTOR_PATTERN.test(selector)) {
    throw CliError.usage(`'${selector}' is not a valid DKIM selector`);
  }
  return selector;
}

/**
 * Validate an IPv4 address.
 *
 * @throws CliError when the address is malformed.
 */
function requireIpv4(value: string | undefined): string | undefined {
  const address = value?.trim();
  if (!address) return undefined;
  if (!IPV4_PATTERN.test(address)) {
    throw CliError.usage(`'${address}' is not a valid IPv4 address`);
  }
  const octets = address.split(".").map((part) => Number(part));
  if (octets.some((octet) => octet > 255)) {
    throw CliError.usage(`'${address}' is not a valid IPv4 address`);
  }
  return address;
}

/**
 * Validate an IPv6 address.
 *
 * @throws CliError when the address is malformed.
 */
function requireIpv6(value: string | undefined): string | undefined {
  const address = value?.trim();
  if (!address) return undefined;
  if (!IPV6_PATTERN.test(address)) {
    throw CliError.usage(`'${address}' is not a valid IPv6 address`);
  }
  return address;
}

/**
 * Build the SPF record from the supplied addresses.
 *
 * The SPF record must list exactly the hosts that actually send. It is
 * returned with `~all` (softfail) because `~all` is the correct rollout
 * starting point; `-all` is tightened after the alignment report confirms
 * that no legitimate sender is missing.
 */
function buildSpf(ipv4: string | undefined, ipv6: string | undefined): string | undefined {
  const mechanisms: string[] = [];
  if (ipv4) mechanisms.push(`ip4:${ipv4}`);
  if (ipv6) mechanisms.push(`ip6:${ipv6}`);
  if (mechanisms.length === 0) return undefined;
  return `v=spf1 ${mechanisms.join(" ")} ~all`;
}

/**
 * Build the DKIM public-key record for a selector.
 *
 * RFC 6376 §3.6.2 defines the `p=` tag as the base64 of the DER-encoded
 * public key, where an RSA key is the `RSAPublicKey` structure:
 *
 * ```text
 * RSAPublicKey ::= SEQUENCE {
 *   modulus        INTEGER,  -- 2048-bit modulus
 *   publicExponent INTEGER   -- normally 65537
 * }
 * ```
 *
 * That is **not** the `SubjectPublicKeyInfo` that `openssl pkey -pubout`
 * emits: the SPKI wraps the RSAPublicKey in an `AlgorithmIdentifier` and a
 * `BIT STRING`. Publishing the SPKI here produces a record that every
 * receiving verifier rejects, so the inner `RSAPublicKey` is extracted
 * explicitly rather than trimmed heuristically.
 */
function buildDkimRecord(publicKeyPem: string): string {
  const der = Buffer.from(
    publicKeyPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  const rsaPublicKey = extractRsaPublicKey(der);
  return `v=DKIM1; k=rsa; p=${rsaPublicKey.toString("base64")}`;
}

/**
 * Extract the DER `RSAPublicKey` from a DER `SubjectPublicKeyInfo`.
 *
 * The BIT STRING payload of an SPKI holding an RSA key is itself a
 * DER-encoded `RSAPublicKey`. The payload starts after the BIT STRING
 * header, whose first byte is the count of unused trailing bits (always
 * zero for a whole-octet payload).
 */
function extractRsaPublicKey(spki: Buffer): Buffer {
  let offset = 0;
  if (spki[offset++] !== 0x30) {
    throw new Error("public key is not a DER SEQUENCE");
  }
  offset = skipLength(spki, offset);

  // AlgorithmIdentifier SEQUENCE.
  if (spki[offset++] !== 0x30) {
    throw new Error("public key is missing its AlgorithmIdentifier");
  }
  const algorithmLength = readLength(spki, offset);
  offset = skipLength(spki, offset) + algorithmLength;

  // BIT STRING.
  if (spki[offset++] !== 0x03) {
    throw new Error("public key is missing its subjectPublicKey BIT STRING");
  }
  const bitStringLength = readLength(spki, offset);
  offset = skipLength(spki, offset);
  // The first content byte counts unused trailing bits.
  const payload = spki.subarray(offset + 1, offset + bitStringLength);

  if (payload[0] !== 0x30) {
    throw new Error("public key payload is not an RSAPublicKey SEQUENCE");
  }
  return payload;
}

/**
 * Read a DER length at `offset`.
 *
 * @returns The decoded length value.
 */
function readLength(der: Buffer, offset: number): number {
  const first = der[offset];
  if ((first & 0x80) === 0) {
    return first;
  }
  const count = first & 0x7f;
  let value = 0;
  for (let index = 1; index <= count; index += 1) {
    value = value * 256 + der[offset + index];
  }
  return value;
}

/**
 * Advance past a DER length field.
 *
 * @returns The offset of the first content byte.
 */
function skipLength(der: Buffer, offset: number): number {
  const first = der[offset];
  if ((first & 0x80) === 0) {
    return offset + 1;
  }
  return offset + 1 + (first & 0x7f);
}

/**
 * `railgun dkim new` — generate the keypair and print the records.
 */
export async function dkimNew(
  context: CommandContext,
  options: DkimNewOptions,
): Promise<number> {
  const domain = requireDomain(options.domain);
  const selector = requireSelector(options.selector);
  const ipv4 = requireIpv4(options.ipv4);
  const ipv6 = requireIpv6(options.ipv6);
  const policy = options.dmarcPolicy?.trim().toLowerCase() ?? "none";

  if (!DMARC_POLICIES.has(policy)) {
    throw CliError.usage(
      `--dmarc-policy must be one of none, quarantine, reject (got '${options.dmarcPolicy}')`,
    );
  }

  const mailHost = (options.mailHost?.trim() || `mail.${domain}`).toLowerCase();
  const rua = options.rua?.trim() || `dmarc@${domain}`;

  const privateKeyPath = path.resolve(
    options.privateKeyPath?.trim() || path.join("secrets", `dkim-${selector}.pem`),
  );
  const publicKeyPath = path.resolve(
    options.publicKeyPath?.trim() || path.join("secrets", `dkim-${selector}.pub.pem`),
  );

  if (existsSync(privateKeyPath)) {
    throw CliError.usage(
      `'${privateKeyPath}' already exists. Remove it or pass --private-key-path to write elsewhere.`,
    );
  }

  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  mkdirSync(path.dirname(privateKeyPath), { recursive: true });
  mkdirSync(path.dirname(publicKeyPath), { recursive: true });
  writeFileSync(privateKeyPath, privateKey, { encoding: "utf8", mode: 0o600 });
  chmodSync(privateKeyPath, 0o600);
  writeFileSync(publicKeyPath, publicKey, { encoding: "utf8", mode: 0o644 });

  const records: DnsRecord[] = [];

  if (ipv4) {
    records.push({
      name: mailHost,
      type: "A",
      value: ipv4,
      purpose: "The host that accepts inbound mail for this domain.",
    });
  }
  records.push({
    name: domain,
    type: "MX",
    value: `10 ${mailHost}.`,
    purpose: "Routes inbound mail for this domain to your host.",
  });

  const spf = buildSpf(ipv4, ipv6);
  if (spf) {
    records.push({
      name: domain,
      type: "TXT",
      value: spf,
      purpose: "SPF. Exactly one v=spf1 record per domain — a second one is a permanent error.",
    });
  }

  records.push({
    name: `${selector}._domainkey.${domain}`,
    type: "TXT",
    value: buildDkimRecord(publicKey),
    purpose: "The DKIM public key for this selector.",
  });

  records.push({
    name: `_dmarc.${domain}`,
    type: "TXT",
    value: `v=DMARC1; p=${policy}; rua=mailto:${rua}; pct=100`,
    purpose: "DMARC. Start at p=none, then tighten to quarantine and reject.",
  });

  const result: DkimKeypairResult = {
    domain,
    selector,
    algorithm: "rsa-sha256",
    keyBits: 2048,
    privateKeyPath,
    publicKeyPath,
    records,
  };

  if (context.options.json) {
    context.channel.stdout(renderJson({ ...result, privateKey: "[not printed]" }));
    return 0;
  }

  const lines: string[] = [];
  lines.push(`DKIM keypair generated for ${domain} (selector: ${selector})`);
  lines.push("");
  lines.push(`  private key  ${privateKeyPath}  (mode 0600 — keep it out of the repository)`);
  lines.push(`  public key   ${publicKeyPath}`);
  lines.push("");
  lines.push("Publish these DNS records:");
  lines.push("");
  for (const record of records) {
    lines.push(`  ${record.name}  ${record.type}`);
    lines.push(`      ${record.value}`);
    lines.push(`      ${record.purpose}`);
    lines.push("");
  }
  lines.push("Then configure RailGun:");
  lines.push("");
  lines.push(`  export RAILGUN_DKIM_ENABLED=true`);
  lines.push(`  export RAILGUN_DKIM_SELECTOR=${selector}`);
  lines.push(`  export RAILGUN_DKIM_PRIVATE_KEY_ENV=RAILGUN_DKIM_PRIVATE_KEY`);
  lines.push(`  export RAILGUN_DKIM_PRIVATE_KEY="$(cat ${privateKeyPath})"`);
  lines.push(`  export RAILGUN_SENDING_DOMAINS=${domain}`);
  lines.push("");
  lines.push("Verify with:  railgun doctor");
  lines.push("");
  lines.push("RailGun verifies DNS; it never changes it. Publish the records in your DNS provider.");

  context.channel.stdout(lines.join("\n"));
  return 0;
}
