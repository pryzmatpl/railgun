/* RailGun NDJSON audit file adapter. Copyright (C) 2026 RailGun contributors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

import { appendFile, mkdir, open, readFile, rename, stat } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditStore, AuditVerification } from "./ports.js";
import type { AuditEventInput, AuditRecord } from "./types.js";
import { appendAuditRecord, auditDigest, canonicalAuditLine, verifyAuditRecords, AUDIT_GENESIS_DIGEST } from "./audit.js";

export interface FileAuditStoreOptions {
  readonly path: string;
  readonly fsync?: boolean;
}

export class FileAuditStore implements AuditStore {
  private tail: Promise<void> = Promise.resolve();

  constructor(private readonly options: FileAuditStoreOptions) {}

  async append(event: AuditEventInput): Promise<AuditRecord> {
    let created!: AuditRecord;
    this.tail = this.tail.then(async () => {
      const records = await this.read();
      const previous = records.at(-1);
      created = appendAuditRecord(event, previous, new Date().toISOString());
      await mkdir(dirname(this.options.path), { recursive: true });
      const handle = await open(this.options.path, "a");
      try {
        await handle.writeFile(`${canonicalAuditLine(created)}\n`, "utf8");
        if (this.options.fsync !== false) await handle.sync();
      } finally {
        await handle.close();
      }
    });
    await this.tail;
    return created;
  }

  async read(fromSequence = 1): Promise<readonly AuditRecord[]> {
    try {
      const content = await readFile(this.options.path, "utf8");
      return content.split("\n").filter(Boolean).map((line) => JSON.parse(line) as AuditRecord).filter((record) => record.sequence >= fromSequence);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  async verify(): Promise<AuditVerification> {
    try {
      const content = await readFile(this.options.path, "utf8");
      if (!content) return { valid: true, headSequence: 0, headDigest: AUDIT_GENESIS_DIGEST, firstInvalidSequence: null, reason: null };
      const lines = content.split("\n");
      const trailingNewline = lines.at(-1) === "";
      if (trailingNewline) lines.pop();
      let records: AuditRecord[];
      try {
        records = lines.map((line) => JSON.parse(line) as AuditRecord);
      } catch {
        return { valid: false, headSequence: recordsLength(lines), headDigest: "", firstInvalidSequence: recordsLength(lines), reason: "truncated_tail" };
      }
      return verifyAuditRecords(records);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { valid: true, headSequence: 0, headDigest: AUDIT_GENESIS_DIGEST, firstInvalidSequence: null, reason: null };
      throw error;
    }
  }

  async head(): Promise<{ sequence: number; digest: string }> {
    const records = await this.read();
    const last = records.at(-1);
    return last ? { sequence: last.sequence, digest: last.digest } : { sequence: 0, digest: AUDIT_GENESIS_DIGEST };
  }

  async removePrefixBefore(sequence: number): Promise<number> {
    const records = await this.read();
    const keep = records.filter((record) => record.sequence >= sequence);
    const removed = records.length - keep.length;
    if (!removed) return 0;
    const temp = `${this.options.path}.${process.pid}.tmp`;
    const body = keep.map((record) => `${canonicalAuditLine(record)}\n`).join("");
    await mkdir(dirname(this.options.path), { recursive: true });
    await open(temp, "w").then(async (handle) => { await handle.writeFile(body, "utf8"); await handle.sync(); await handle.close(); });
    await rename(temp, this.options.path);
    return removed;
  }

  async size(): Promise<number> {
    try { return (await stat(this.options.path)).size; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0; throw error; }
  }
}

function recordsLength(lines: readonly string[]): number {
  return lines.filter((line) => line.trim().length > 0).length;
}
