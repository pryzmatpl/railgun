// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Operator-facing application services.
 *
 * The CLI is a thin projection: it owns argument parsing, presentation and
 * exit mapping, and delegates every decision to these services. The services
 * own validation, status derivation, suppression rules and audit emission, so
 * local mode and remote HTTP mode cannot drift apart.
 */
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

import type {
  AdminProjection,
  BounceProjection,
  MessageProjection,
  Page,
  RailGunStatus,
  QueueStatsProjection,
  StatsProjection,
  SuppressionProjection,
} from "../domain/types.js";

/** The scope required to read operator state. */
export const SCOPE_READ = "read";
/** The scope required to mutate operator state. */
export const SCOPE_ADMIN = "admin";

/** A stable, machine-readable service error. */
export class ServiceError extends Error {
  readonly code: string;
  readonly details: Record<string, unknown> | undefined;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ServiceError";
    this.code = code;
    this.details = details;
  }
}

interface StoredMessage {
  id: string;
  tenant: string;
  status: RailGunStatus;
  deliveryConfirmed: boolean;
  messageId: string | null;
  subject: string | null;
  from: string | null;
  recipients: {
    id: string;
    recipient: string;
    status: RailGunStatus;
    attempts: number;
    lastReason: string | null;
    lastAttemptAt: string | null;
  }[];
  attempts: number;
  createdAt: string;
  updatedAt: string;
  policyReason: string | null;
  lastResponse: string | null;
}

interface StoredBounce {
  id: string;
  messageId: string | null;
  recipient: string;
  class: "permanent" | "temporary";
  status: string | null;
  reason: string | null;
  at: string;
}

interface StoredSuppression {
  id: string;
  scope: string;
  reason: string;
  createdAt: string;
  expiresAt: string | null;
  permanent: boolean;
}

interface StoredAdmin {
  id: string;
  displayName: string;
  email: string | null;
  tenant: string;
  scopes: string[];
  /** A hash of the credential; the secret itself is never stored in plaintext. */
  credentialHash: string;
  credentialFingerprint: string;
  createdAt: string;
}

interface StoredQueueItem {
  id: string;
  messageId: string;
  destination: string;
  availableAt: string;
  attempts: number;
  leasedUntil: string | null;
}

/** The persistence surface the operator services use. */
export interface OperatorStore {
  listMessages(filter: MessageFilter): Page<MessageProjection>;
  getMessage(id: string): MessageProjection | undefined;
  retryMessage(id: string): MessageProjection;
  suppressMessage(id: string, reason: string, expiresAt: string | null): MessageProjection;
  listBounces(filter: BounceFilter): Page<BounceProjection>;
  stats(filter: StatsFilter): StatsProjection;
  listSuppressions(): SuppressionProjection[];
  addSuppression(input: {
    scope: string;
    reason: string;
    expiresAt: string | null;
  }): { projection: SuppressionProjection; created: boolean };
  queueStats(): QueueStatsProjection;
  listAdmins(): AdminProjection[];
  createAdmin(input: {
    displayName: string;
    email: string | null;
    tenant: string;
    scopes: string[];
    secret?: string;
  }): { projection: AdminProjection; secret: string | null; created: boolean };
  appendAudit(record: AuditRecord): void;
  /**
   * Flush the operator state to durable storage.
   *
   * A store that keeps its state in memory only may implement this as a
   * no-op; a file-backed store writes the snapshot so a later CLI invocation
   * observes the same state.
   */
  persist(): void;
}

export interface MessageFilter {
  tenant?: string | undefined;
  status?: RailGunStatus | undefined;
  recipient?: string | undefined;
  since?: string | undefined;
  until?: string | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}

export interface BounceFilter {
  tenant?: string | undefined;
  class?: "permanent" | "temporary" | undefined;
  since?: string | undefined;
  until?: string | undefined;
  limit?: number | undefined;
  cursor?: string | undefined;
}

export interface StatsFilter {
  tenant?: string | undefined;
  since?: string | undefined;
  until?: string | undefined;
}

export interface AuditRecord {
  action: string;
  actor: string;
  tenant: string;
  target: string | null;
  reason: string | null;
  at: string;
}

/**
 * An in-memory operator store.
 *
 * It is the default store for local operator commands when the operator has
 * not configured a durable backend, and the backing store for CLI integration
 * tests. It implements the same contract as the durable adapters, so the CLI
 * cannot behave differently between the two.
 */
export class MemoryOperatorStore implements OperatorStore {
  private readonly messages = new Map<string, StoredMessage>();
  private readonly bounces = new Map<string, StoredBounce>();
  private readonly suppressions = new Map<string, StoredSuppression>();
  private readonly admins = new Map<string, StoredAdmin>();
  private readonly queue: StoredQueueItem[] = [];
  private readonly auditPath: string | undefined;
  private readonly clock: () => Date;

  constructor(options: { auditPath?: string | undefined; clock?: (() => Date) | undefined } = {}) {
    this.auditPath = options.auditPath;
    this.clock = options.clock ?? (() => new Date());
  }

  /**
   * Replace the whole in-memory state.
   *
   * Used by {@link FileOperatorStore} to hydrate the store from disk.
   */
  hydrate(state: {
    messages: StoredMessage[];
    bounces: StoredBounce[];
    suppressions: StoredSuppression[];
    admins: StoredAdmin[];
    queue: StoredQueueItem[];
  }): void {
    this.messages.clear();
    for (const message of state.messages) {
      this.messages.set(message.id, message);
    }
    this.bounces.clear();
    for (const bounce of state.bounces) {
      this.bounces.set(bounce.id, bounce);
    }
    this.suppressions.clear();
    for (const suppression of state.suppressions) {
      this.suppressions.set(suppression.id, suppression);
    }
    this.admins.clear();
    for (const admin of state.admins) {
      this.admins.set(admin.id, admin);
    }
    this.queue.length = 0;
    this.queue.push(...state.queue);
  }

  /** Snapshot the whole in-memory state. */
  snapshot(): {
    messages: StoredMessage[];
    bounces: StoredBounce[];
    suppressions: StoredSuppression[];
    admins: StoredAdmin[];
    queue: StoredQueueItem[];
  } {
    return {
      messages: [...this.messages.values()],
      bounces: [...this.bounces.values()],
      suppressions: [...this.suppressions.values()],
      admins: [...this.admins.values()],
      queue: [...this.queue],
    };
  }

  listMessages(filter: MessageFilter): Page<MessageProjection> {
    const all = [...this.messages.values()]
      .filter((message) => matchesMessageFilter(message, filter))
      .toSorted((left, right) => {
        // Deterministic ordering: newest first, ties broken by id.
        const byTime = right.createdAt.localeCompare(left.createdAt);
        return byTime !== 0 ? byTime : left.id.localeCompare(right.id);
      });

    const start = decodeCursor(filter.cursor);
    const limit = clampLimit(filter.limit);
    const page = all.slice(start, start + limit);
    const nextOffset = start + limit;
    return {
      items: page.map((message) => projectMessage(message)),
      nextCursor: nextOffset < all.length ? encodeCursor(nextOffset) : null,
      total: all.length,
    };
  }

  getMessage(id: string): MessageProjection | undefined {
    const message = this.messages.get(id);
    return message ? projectMessage(message) : undefined;
  }

  retryMessage(id: string): MessageProjection {
    const message = this.messages.get(id);
    if (!message) {
      throw new ServiceError("NOT_FOUND", `Message not found: ${id}`, { message_id: id });
    }
    if (message.status !== "deferred" && message.status !== "bounced") {
      throw new ServiceError(
        "MESSAGE_NOT_RETRYABLE",
        `Message is not in a retryable state: ${message.status}`,
        { message_id: id, status: message.status },
      );
    }
    message.status = "queued";
    message.updatedAt = this.clock().toISOString();
    message.lastResponse = null;
    for (const recipient of message.recipients) {
      recipient.status = "queued";
      recipient.lastReason = null;
    }
    this.queue.push({
      id: randomUUID(),
      messageId: message.id,
      destination: message.recipients[0]?.recipient ?? "unknown",
      availableAt: message.updatedAt,
      attempts: 0,
      leasedUntil: null,
    });
    this.persist();
    return projectMessage(message);
  }

  suppressMessage(id: string, reason: string, expiresAt: string | null): MessageProjection {
    const message = this.messages.get(id);
    if (!message) {
      throw new ServiceError("NOT_FOUND", `Message not found: ${id}`, { message_id: id });
    }
    for (const recipient of message.recipients) {
      if (recipient.status === "delivered" || recipient.status === "accepted") {
        continue;
      }
      recipient.status = "suppressed";
      recipient.lastReason = reason;
      this.addSuppression({
        scope: recipient.recipient,
        reason,
        expiresAt,
      });
    }
    message.status = "suppressed";
    message.updatedAt = this.clock().toISOString();
    message.policyReason = reason;
    this.persist();
    return projectMessage(message);
  }

  listBounces(filter: BounceFilter): Page<BounceProjection> {
    const all = [...this.bounces.values()]
      .filter((bounce) => matchesBounceFilter(bounce, filter))
      .toSorted((left, right) => {
        const byTime = right.at.localeCompare(left.at);
        return byTime !== 0 ? byTime : left.id.localeCompare(right.id);
      });
    const start = decodeCursor(filter.cursor);
    const limit = clampLimit(filter.limit);
    const page = all.slice(start, start + limit);
    const nextOffset = start + limit;
    return {
      items: page.map((bounce) => ({ ...bounce })),
      nextCursor: nextOffset < all.length ? encodeCursor(nextOffset) : null,
      total: all.length,
    };
  }

  stats(filter: StatsFilter): StatsProjection {
    const counters: StatsProjection = {
      queued: 0,
      accepted: 0,
      delivered: 0,
      deferred: 0,
      bounced: 0,
      suppressed: 0,
      rejected: 0,
      windowStart: filter.since ?? null,
      windowEnd: filter.until ?? null,
      tenant: filter.tenant ?? null,
    };
    for (const message of this.messages.values()) {
      if (!matchesMessageFilter(message, filter)) {
        continue;
      }
      // Only the canonical counters are counted; the remaining statuses
      // (`received`, `policy_evaluated`, `failed`) have no counter of their
      // own and are reported through the delivered/bounced/deferred totals.
      switch (message.status) {
        case "queued":
        case "accepted":
        case "delivered":
        case "deferred":
        case "bounced":
        case "suppressed":
        case "rejected":
          counters[message.status] += 1;
          break;
        default:
          break;
      }
    }
    return counters;
  }

  listSuppressions(): SuppressionProjection[] {
    return [...this.suppressions.values()]
      .toSorted((left, right) => left.id.localeCompare(right.id))
      .map((entry) => ({
        id: entry.id,
        scope: entry.scope,
        reason: entry.reason,
        createdAt: entry.createdAt,
        expiresAt: entry.expiresAt,
        permanent: entry.permanent,
      }));
  }

  addSuppression(input: {
    scope: string;
    reason: string;
    expiresAt: string | null;
  }): { projection: SuppressionProjection; created: boolean } {
    const scope = input.scope.trim().toLowerCase();
    const existing = [...this.suppressions.values()].find((entry) => entry.scope === scope);
    if (existing) {
      // An identical entry is idempotent; a conflicting expiry is a conflict.
      if (existing.reason === input.reason && existing.expiresAt === input.expiresAt) {
        return {
          projection: {
            id: existing.id,
            scope: existing.scope,
            reason: existing.reason,
            createdAt: existing.createdAt,
            expiresAt: existing.expiresAt,
            permanent: existing.permanent,
          },
          created: false,
        };
      }
      if (existing.permanent && input.expiresAt !== null) {
        throw new ServiceError(
          "SUPPRESSION_CONFLICT",
          "A permanent suppression cannot be shortened by a new entry",
          { scope },
        );
      }
      existing.reason = input.reason;
      existing.expiresAt = input.expiresAt;
      existing.permanent = input.expiresAt === null;
      return {
        projection: {
          id: existing.id,
          scope: existing.scope,
          reason: existing.reason,
          createdAt: existing.createdAt,
          expiresAt: existing.expiresAt,
          permanent: existing.permanent,
        },
        created: true,
      };
    }

    const projection: SuppressionProjection = {
      id: randomUUID(),
      scope,
      reason: input.reason,
      createdAt: this.clock().toISOString(),
      expiresAt: input.expiresAt,
      permanent: input.expiresAt === null,
    };
    this.suppressions.set(projection.id, { ...projection });
    this.persist();
    return { projection, created: true };
  }

  queueStats(): QueueStatsProjection {
    const now = this.clock();
    let due = 0;
    let leased = 0;
    let scheduled = 0;
    let oldestQueuedAgeSeconds = 0;
    let oldestAvailableAt: string | null = null;
    const destinationCounts = new Map<string, number>();

    for (const item of this.queue) {
      const isLeased = item.leasedUntil !== null && item.leasedUntil > now.toISOString();
      if (isLeased) {
        leased += 1;
      } else if (item.availableAt <= now.toISOString()) {
        due += 1;
      } else {
        scheduled += 1;
      }
      if (oldestAvailableAt === null || item.availableAt < oldestAvailableAt) {
        oldestAvailableAt = item.availableAt;
      }
      destinationCounts.set(item.destination, (destinationCounts.get(item.destination) ?? 0) + 1);
    }

    if (oldestAvailableAt !== null) {
      oldestQueuedAgeSeconds = Math.max(
        0,
        Math.floor((now.getTime() - Date.parse(oldestAvailableAt)) / 1000),
      );
    }

    return {
      depth: this.queue.length,
      due,
      leased,
      scheduled,
      oldestQueuedAgeSeconds,
      // Bounded breakdown: at most ten destinations, sorted for determinism.
      destinations: [...destinationCounts.entries()]
        .toSorted((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
        .slice(0, 10)
        .map(([destination, count]) => ({ destination, count })),
    };
  }

  listAdmins(): AdminProjection[] {
    return [...this.admins.values()]
      .toSorted((left, right) => left.id.localeCompare(right.id))
      .map((admin) => ({
        id: admin.id,
        displayName: admin.displayName,
        email: admin.email,
        tenant: admin.tenant,
        scopes: [...admin.scopes],
        credentialFingerprint: admin.credentialFingerprint,
        createdAt: admin.createdAt,
      }));
  }

  createAdmin(input: {
    displayName: string;
    email: string | null;
    tenant: string;
    scopes: string[];
    secret?: string | undefined;
  }): { projection: AdminProjection; secret: string | null; created: boolean } {
    const existing = [...this.admins.values()].find((admin) => admin.tenant === input.tenant);
    if (existing) {
      // Idempotent: an administrator already exists for the tenant.
      return {
        projection: {
          id: existing.id,
          displayName: existing.displayName,
          email: existing.email,
          tenant: existing.tenant,
          scopes: [...existing.scopes],
          credentialFingerprint: existing.credentialFingerprint,
          createdAt: existing.createdAt,
        },
        secret: null,
        created: false,
      };
    }

    const secret = input.secret ?? randomBytes(24).toString("base64url");
    const admin: StoredAdmin = {
      id: randomUUID(),
      displayName: input.displayName,
      email: input.email,
      tenant: input.tenant,
      scopes: [...input.scopes],
      credentialHash: hashCredential(secret),
      credentialFingerprint: fingerprint(secret),
      createdAt: this.clock().toISOString(),
    };
    this.admins.set(admin.id, admin);
    this.persist();
    return {
      projection: {
        id: admin.id,
        displayName: admin.displayName,
        email: admin.email,
        tenant: admin.tenant,
        scopes: [...admin.scopes],
        credentialFingerprint: admin.credentialFingerprint,
        createdAt: admin.createdAt,
      },
      // The generated secret is returned once, for one-time operator display.
      secret: input.secret === undefined ? secret : null,
      created: true,
    };
  }

  /**
   * Flush the state.
   *
   * The in-memory store is not durable, so this is a no-op. The file-backed
   * store overrides it.
   */
  persist(): void {
    // Intentionally empty: the in-memory store keeps no durable copy.
  }

  appendAudit(record: AuditRecord): void {
    if (!this.auditPath) {
      return;
    }
    mkdirSync(path.dirname(this.auditPath), { recursive: true });
    const line = `${JSON.stringify({
      at: record.at,
      action: record.action,
      actor: record.actor,
      tenant: record.tenant,
      target: record.target,
      reason: record.reason,
    })}\n`;
    appendFileSync(this.auditPath, line, "utf8");
  }

  /** Test helper: seed a message directly into the store. */
  seedMessage(message: Partial<StoredMessage> & { id: string }): MessageProjection {
    const now = this.clock().toISOString();
    const stored: StoredMessage = {
      id: message.id,
      tenant: message.tenant ?? "default",
      status: message.status ?? "queued",
      deliveryConfirmed: message.deliveryConfirmed ?? false,
      messageId: message.messageId ?? `<${message.id}@railgun>`,
      subject: message.subject ?? null,
      from: message.from ?? null,
      recipients: message.recipients ?? [],
      attempts: message.attempts ?? 0,
      createdAt: message.createdAt ?? now,
      updatedAt: message.updatedAt ?? now,
      policyReason: message.policyReason ?? null,
      lastResponse: message.lastResponse ?? null,
    };
    this.messages.set(stored.id, stored);
    return projectMessage(stored);
  }

  /** Test helper: seed a bounce directly into the store. */
  seedBounce(bounce: Partial<StoredBounce> & { id: string }): BounceProjection {
    const stored: StoredBounce = {
      id: bounce.id,
      messageId: bounce.messageId ?? null,
      recipient: bounce.recipient ?? "hashed:0000",
      class: bounce.class ?? "permanent",
      status: bounce.status ?? "5.1.1",
      reason: bounce.reason ?? "Mailbox does not exist",
      at: bounce.at ?? this.clock().toISOString(),
    };
    this.bounces.set(stored.id, stored);
    return { ...stored };
  }

  /** Test helper: seed a queue item directly into the store. */
  seedQueueItem(item: Partial<StoredQueueItem> & { id: string }): void {
    this.queue.push({
      id: item.id,
      messageId: item.messageId ?? "unknown",
      destination: item.destination ?? "hashed:0000",
      availableAt: item.availableAt ?? this.clock().toISOString(),
      attempts: item.attempts ?? 0,
      leasedUntil: item.leasedUntil ?? null,
    });
  }
}

function projectMessage(message: StoredMessage): MessageProjection {
  return {
    id: message.id,
    tenant: message.tenant,
    status: message.status,
    deliveryConfirmed: message.deliveryConfirmed,
    messageId: message.messageId,
    subject: message.subject,
    from: message.from,
    recipients: message.recipients.map((recipient) => ({ ...recipient })),
    attempts: message.attempts,
    createdAt: message.createdAt,
    updatedAt: message.updatedAt,
    policyReason: message.policyReason,
    lastResponse: message.lastResponse,
  };
}

function matchesMessageFilter(message: StoredMessage, filter: MessageFilter): boolean {
  if (filter.tenant && message.tenant !== filter.tenant) {
    return false;
  }
  if (filter.status && message.status !== filter.status) {
    return false;
  }
  if (filter.recipient) {
    const needle = filter.recipient.toLowerCase();
    const hit = message.recipients.some((recipient) =>
      recipient.recipient.toLowerCase().includes(needle),
    );
    if (!hit) {
      return false;
    }
  }
  if (filter.since && message.createdAt < filter.since) {
    return false;
  }
  if (filter.until && message.createdAt > filter.until) {
    return false;
  }
  return true;
}

function matchesBounceFilter(bounce: StoredBounce, filter: BounceFilter): boolean {
  if (filter.class && bounce.class !== filter.class) {
    return false;
  }
  if (filter.since && bounce.at < filter.since) {
    return false;
  }
  if (filter.until && bounce.at > filter.until) {
    return false;
  }
  return true;
}

function clampLimit(limit: number | undefined): number {
  if (limit === undefined) {
    return 50;
  }
  return Math.min(Math.max(1, limit), 500);
}

function encodeCursor(offset: number): string {
  return Buffer.from(String(offset), "utf8").toString("base64url");
}

function decodeCursor(cursor: string | undefined): number {
  if (!cursor) {
    return 0;
  }
  const decoded = Buffer.from(cursor, "base64url").toString("utf8");
  const offset = Number.parseInt(decoded, 10);
  return Number.isFinite(offset) && offset >= 0 ? offset : 0;
}

/** Hash a credential for storage; the plaintext is never retained. */
export function hashCredential(secret: string): string {
  return createHash("sha256").update(secret).digest("hex");
}

/** A short, non-secret fingerprint of a credential for operator display. */
export function fingerprint(secret: string): string {
  return createHash("sha256").update(secret).digest("hex").slice(0, 12);
}

/** Constant-time comparison of a presented credential against a stored hash. */
export function credentialMatches(secret: string, storedHash: string): boolean {
  const presented = Buffer.from(hashCredential(secret), "utf8");
  const stored = Buffer.from(storedHash, "utf8");
  if (presented.length !== stored.length) {
    return false;
  }
  return timingSafeEqual(presented, stored);
}

/** Check that a path exists and is writable, for the doctor dependency checks. */
export function probePathWritable(target: string): { ok: boolean; detail: string } {
  try {
    const directory = path.dirname(target);
    if (!existsSync(directory)) {
      mkdirSync(directory, { recursive: true });
    }
    // The probe file is removed in a `finally` block so a failed write
    // never leaves a stray file behind in the operator's data directory.
    const probe = path.join(directory, `.railgun-probe-${process.pid}`);
    try {
      appendFileSync(probe, "ok");
      return { ok: true, detail: "writable" };
    } finally {
      try {
        unlinkSync(probe);
      } catch {
        // The probe may not have been created; that is not a failure.
      }
    }
  } catch {
    return { ok: false, detail: "not writable" };
  }
}

/** Check that a file exists and is readable, for the doctor dependency checks. */
export function probePathReadable(target: string): { ok: boolean; detail: string } {
  try {
    if (!existsSync(target)) {
      return { ok: false, detail: "not found" };
    }
    if (!statSync(target).isFile()) {
      return { ok: false, detail: "not a file" };
    }
    readFileSync(target);
    return { ok: true, detail: "readable" };
  } catch {
    return { ok: false, detail: "not readable" };
  }
}

/**
 * A file-backed operator store.
 *
 * The local operator commands run as short-lived processes, so the state they
 * observe must outlive the process: a suppression added by one invocation
 * must be visible to the next. This store keeps the operator state in a
 * single JSON document that is loaded on construction and rewritten on every
 * mutation.
 *
 * It is deliberately simple and dependency-free; the durable message and
 * outbox stores live behind the persistence ports.
 */
export class FileOperatorStore extends MemoryOperatorStore {
  private readonly statePath: string;

  constructor(options: {
    statePath: string;
    auditPath?: string | undefined;
    clock?: (() => Date) | undefined;
  }) {
    super({ auditPath: options.auditPath, clock: options.clock });
    this.statePath = options.statePath;
    this.load();
  }

  /** Read the state document from disk, if it exists. */
  private load(): void {
    let raw: string;
    try {
      raw = readFileSync(this.statePath, "utf8");
    } catch {
      // No state yet: the store starts empty.
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // A corrupt state document must not crash the CLI; the operator can
      // inspect the file and the command reports an empty store.
      return;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return;
    }
    const state = parsed as {
      messages?: StoredMessage[];
      bounces?: StoredBounce[];
      suppressions?: StoredSuppression[];
      admins?: StoredAdmin[];
      queue?: StoredQueueItem[];
    };
    this.hydrate({
      messages: state.messages ?? [],
      bounces: state.bounces ?? [],
      suppressions: state.suppressions ?? [],
      admins: state.admins ?? [],
      queue: state.queue ?? [],
    });
  }

  /** Write the state document to disk. */
  override persist(): void {
    mkdirSync(path.dirname(this.statePath), { recursive: true });
    // The write is atomic: a temporary file is renamed into place so a
    // concurrent reader never observes a half-written document.
    const temporary = `${this.statePath}.${process.pid}.tmp`;
    writeFileSync(temporary, `${JSON.stringify(this.snapshot(), null, 2)}\n`, "utf8");
    renameSync(temporary, this.statePath);
  }
}
