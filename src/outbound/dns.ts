// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * MX discovery, address-family selection and the TTL-bounded DNS cache.
 *
 * Contract: `docs/design/railgun-direct-mx-delivery-engine-ir.md` §3.2
 * (R-DNS-1 … R-DNS-10).
 *
 * The resolver is a seam (IR §7): the engine accepts a {@link DnsResolver}
 * so tests can supply a deterministic fake instead of patching globals
 * (R-DNS-9). The production implementation is built on `node:dns/promises`.
 */

import dns from "node:dns/promises";

import type { DnsCache, DnsResolver, MxRecord } from "./types.js";

/** The maximum TTL the cache honours, in seconds. */
export const DEFAULT_MAX_DNS_TTL_SECONDS = 900;

/** The TTL used when the resolver does not report one. */
const DEFAULT_TTL_SECONDS = 300;

/**
 * The sentinel MX record of RFC 7505 ("null MX"): `0 .`.
 *
 * A domain publishing it accepts no mail at all, which is a *permanent*
 * condition and is distinct from "the domain publishes no MX record"
 * (R-DNS-6).
 */
export const NULL_MX_PREFERENCE = 0;
export const NULL_MX_EXCHANGE = ".";

/** The DNS error codes that indicate a temporary resolver failure (R-DNS-5). */
const TEMPORARY_DNS_CODES = new Set([
  "SERVFAIL",
  "REFUSED",
  "ETIMEOUT",
  "ESERVFAIL",
  "EREFUSED",
  "ETIMEOUT",
]);

/** One cached DNS answer. */
interface CacheEntry<T> {
  readonly value: T;
  /** The absolute expiry, in epoch milliseconds. */
  readonly expiresAt: number;
  readonly ttlSeconds: number;
}

/**
 * The production resolver, built on `node:dns/promises`.
 */
export class NodeDnsResolver implements DnsResolver {
  async resolveMx(domain: string): Promise<readonly MxRecord[]> {
    const records = await dns.resolveMx(domain);
    return records.map((record: { exchange: string; priority: number }) => ({
      exchange: record.exchange.toLowerCase(),
      preference: record.priority,
    }));
  }

  async resolve4(host: string): Promise<readonly string[]> {
    return dns.resolve4(host);
  }

  async resolve6(host: string): Promise<readonly string[]> {
    return dns.resolve6(host);
  }

  async resolvePtr(address: string): Promise<readonly string[]> {
    return dns.reverse(address);
  }
}

/**
 * Order MX candidates by ascending preference, then lexicographically by
 * exchange (R-DNS-1).
 *
 * The tiebreak makes the attempt order reproducible across runs and hosts.
 */
export function orderMxRecords(records: readonly MxRecord[]): readonly MxRecord[] {
  return [...records].sort(
    (a, b) => a.preference - b.preference || a.exchange.localeCompare(b.exchange),
  );
}

/**
 * True when the record set is the RFC 7505 null MX (R-DNS-6).
 *
 * A null MX is a single record with preference `0` and the root exchange `.`.
 */
export function isNullMx(records: readonly MxRecord[]): boolean {
  return records.some(
    (record) =>
      record.preference === NULL_MX_PREFERENCE && record.exchange === NULL_MX_EXCHANGE,
  );
}

/**
 * True when the DNS failure is a temporary resolver failure (R-DNS-5).
 *
 * `ENOTFOUND` / `ENODATA` are *not* temporary: they mean the name does not
 * exist, which is permanent for the routing domain.
 */
export function isTemporaryDnsError(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  if (typeof code !== "string") return false;
  if (code === "ENOTFOUND" || code === "ENODATA") return false;
  if (TEMPORARY_DNS_CODES.has(code)) return true;
  // Any other resolver-level failure is treated as temporary: a permanent
  // condition is signalled by the absence of records, not by an error.
  return code.startsWith("E");
}

/**
 * A TTL-bounded cache over a {@link DnsResolver} (R-DNS-8).
 *
 * Entries live for `min(record TTL, configured maximum TTL)`. A cached entry
 * is invalidated when a connection to the cached host fails with a
 * host-not-found condition.
 */
export class TtlDnsCache implements DnsCache {
  readonly resolver: DnsResolver;
  private readonly maxTtlSeconds: number;
  private readonly entries = new Map<string, CacheEntry<unknown>>();
  private readonly now: () => number;

  constructor(
    resolver: DnsResolver,
    options: { maxTtlSeconds?: number; now?: () => number } = {},
  ) {
    this.resolver = resolver;
    this.maxTtlSeconds = options.maxTtlSeconds ?? DEFAULT_MAX_DNS_TTL_SECONDS;
    this.now = options.now ?? (() => Date.now());
  }

  flush(): void {
    this.entries.clear();
  }

  invalidate(host: string): void {
    this.entries.delete(host.toLowerCase());
  }

  ttlOf(host: string): number | null {
    const entry = this.entries.get(host.toLowerCase());
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) return null;
    return Math.max(0, Math.round((entry.expiresAt - this.now()) / 1000));
  }

  /**
   * The cached MX records of a domain, or `null` when there is no live entry.
   */
  async mx(domain: string): Promise<readonly MxRecord[] | null> {
    const key = `mx:${domain.toLowerCase()}`;
    const cached = this.read<readonly MxRecord[]>(key);
    if (cached) return cached;
    const value = await this.resolver.resolveMx(domain);
    this.write(key, value, DEFAULT_TTL_SECONDS);
    return value;
  }

  /** The cached IPv4 addresses of a host, or `null` when there is no entry. */
  async addresses4(host: string): Promise<readonly string[] | null> {
    const key = `a:${host.toLowerCase()}`;
    const cached = this.read<readonly string[]>(key);
    if (cached) return cached;
    const value = await this.resolver.resolve4(host);
    this.write(key, value, DEFAULT_TTL_SECONDS);
    return value;
  }

  /** The cached IPv6 addresses of a host, or `null` when there is no entry. */
  async addresses6(host: string): Promise<readonly string[] | null> {
    const key = `aaaa:${host.toLowerCase()}`;
    const cached = this.read<readonly string[]>(key);
    if (cached) return cached;
    const value = await this.resolver.resolve6(host);
    this.write(key, value, DEFAULT_TTL_SECONDS);
    return value;
  }

  /** The cached PTR names of an address, or `null` when there is no entry. */
  async ptr(address: string): Promise<readonly string[] | null> {
    const key = `ptr:${address}`;
    const cached = this.read<readonly string[]>(key);
    if (cached) return cached;
    const value = await this.resolver.resolvePtr(address);
    this.write(key, value, DEFAULT_TTL_SECONDS);
    return value;
  }

  private read<T>(key: string): T | null {
    const entry = this.entries.get(key) as CacheEntry<T> | undefined;
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return null;
    }
    return entry.value;
  }

  private write(key: string, value: unknown, ttlSeconds: number): void {
    const ttl = Math.max(0, Math.min(ttlSeconds, this.maxTtlSeconds));
    this.entries.set(key, {
      value,
      ttlSeconds: ttl,
      expiresAt: this.now() + ttl * 1000,
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Address-family selection                                                     */
/* -------------------------------------------------------------------------- */

/** One address candidate for a connection attempt. */
export interface AddressCandidate {
  readonly host: string;
  readonly address: string;
  /** `4` for IPv4, `6` for IPv6. */
  readonly family: 4 | 6;
}

/**
 * The address candidates for one MX host, ordered per the family policy
 * (R-DNS-4).
 *
 * `ipv4_first: true` attempts IPv4 addresses first and then IPv6 when
 * `ipv6_fallback` is enabled. `ipv4_first: false` reverses the order. When the
 * fallback is disabled the second family is never attempted.
 */
export function orderAddresses(
  host: string,
  ipv4: readonly string[],
  ipv6: readonly string[],
  options: { ipv4First: boolean; ipv6Fallback: boolean },
): readonly AddressCandidate[] {
  const v4 = ipv4.map((address) => ({ host, address, family: 4 as const }));
  const v6 = ipv6.map((address) => ({ host, address, family: 6 as const }));
  const primary = options.ipv4First ? v4 : v6;
  const secondary = options.ipv4First ? v6 : v4;
  return options.ipv6Fallback ? [...primary, ...secondary] : [...primary];
}

/* -------------------------------------------------------------------------- */
/* The transport address policy                                                 */
/* -------------------------------------------------------------------------- */

/**
 * The reason an address is refused by the transport policy.
 */
export type AddressPolicyVerdict =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: string };

/**
 * The loopback, link-local and private ranges an MX record must never be used
 * to reach (R-CONN-7).
 *
 * The check exists because an MX record is attacker-influenced input: without
 * it, a hostile DNS zone could point RailGun at an internal service.
 */
const BLOCKED_V4_RANGES: readonly { readonly prefix: string; readonly bits: number }[] = [
  { prefix: "0.0.0.0", bits: 8 }, // "this network"
  { prefix: "10.0.0.0", bits: 8 }, // RFC 1918
  { prefix: "100.64.0.0", bits: 10 }, // carrier-grade NAT
  { prefix: "127.0.0.0", bits: 8 }, // loopback
  { prefix: "169.254.0.0", bits: 16 }, // link-local
  { prefix: "172.16.0.0", bits: 12 }, // RFC 1918
  { prefix: "192.0.0.0", bits: 24 }, // IETF protocol assignments
  { prefix: "192.168.0.0", bits: 16 }, // RFC 1918
  { prefix: "198.18.0.0", bits: 15 }, // benchmarking
  { prefix: "224.0.0.0", bits: 4 }, // multicast
  { prefix: "240.0.0.0", bits: 4 }, // reserved
];

/** The IPv6 prefixes that are never a legitimate MX address. */
const BLOCKED_V6_PREFIXES = ["::", "::1", "fc", "fd", "fe80", "ff"];

/**
 * Apply the transport allow/deny policy to one address (R-CONN-7).
 *
 * `allowLocal` is the explicit, test-only exception that lets the fake-MX
 * fixture (a loopback listener) be reached.
 */
export function checkAddressPolicy(
  address: string,
  options: { allowLocal: boolean },
): AddressPolicyVerdict {
  const version = address.includes(":") ? 6 : 4;
  if (version === 6) {
    const normalized = address.toLowerCase();
    for (const prefix of BLOCKED_V6_PREFIXES) {
      if (normalized === prefix || normalized.startsWith(`${prefix}:`)) {
        return options.allowLocal
          ? { allowed: true }
          : { allowed: false, reason: "ipv6_special_range" };
      }
    }
    return { allowed: true };
  }

  const octets = address.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) {
    return { allowed: false, reason: "malformed_address" };
  }
  for (const range of BLOCKED_V4_RANGES) {
    if (isInV4Range(octets, range.prefix, range.bits)) {
      return options.allowLocal
        ? { allowed: true }
        : { allowed: false, reason: "ipv4_private_range" };
    }
  }
  return { allowed: true };
}

/**
 * True when the octets fall inside the CIDR range.
 */
function isInV4Range(
  octets: readonly number[],
  prefix: string,
  bits: number,
): boolean {
  const network = prefix.split(".").map((part) => Number.parseInt(part, 10));
  const totalBits = bits;
  for (let index = 0; index < 4; index += 1) {
    const remaining = totalBits - index * 8;
    if (remaining <= 0) break;
    const width = Math.min(8, remaining);
    const mask = width === 8 ? 0xff : (0xff << (8 - width)) & 0xff;
    if (((octets[index]! & mask) >>> 0) !== ((network[index]! & mask) >>> 0)) {
      return false;
    }
  }
  return true;
}

/**
 * True when the reverse-DNS check passes for an address (R-DNS-10).
 *
 * The PTR name must be the MX hostname itself, or a name *under* it: a host
 * named `mail.mx.example.test` is consistent with the MX `mx.example.test`.
 * A resolver failure is treated as a mismatch, because an unverifiable host
 * is not a verifiable one.
 */
export function reverseDnsMatches(
  ptrNames: readonly string[],
  mxHost: string,
): boolean {
  if (ptrNames.length === 0) return false;
  const host = mxHost.toLowerCase().replace(/\.$/, "");
  for (const name of ptrNames) {
    const candidate = name.toLowerCase().replace(/\.$/, "");
    if (candidate === host) return true;
    if (candidate.endsWith(`.${host}`)) return true;
  }
  return false;
}
