// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Verification support for the RailGun package.
 *
 * This module ships the two pieces the verification IR requires from inside
 * the package itself:
 *
 *   1. `scanForSecrets` — a credential-hygiene scanner that reports *counts*
 *      and file names only. It never echoes the secret it found, because a
 *      scanner that prints the match would itself leak the credential into
 *      the very log the scan is meant to protect.
 *   2. `assertNoSecretLeak` — the zero-match assertion used by the live gate
 *      and by the unit tests.
 *
 * The scanner is dependency-free on purpose: a standalone user can run it
 * after `npm install` with no workspace root and no network access.
 *
 * Contract: `docs/design/481de2b7-e002-4cdc-95e0-0adc9068e2c4.md` §4.3
 * (V-SEC-1 … V-SEC-6) and §5.3 (V-REL-9 … V-REL-11).
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

/** The sentinel that replaces a credential in every operator-facing output. */
export const REDACTION_SENTINEL = "[redacted]";

/** One file that matched a scanned secret. */
export interface SecretMatch {
  /** The path relative to the scan root; never an absolute path. */
  readonly file: string;
  /** How many times the secret occurred in the file. */
  readonly count: number;
}

/** The result of a secret scan. */
export interface SecretScanResult {
  /** The number of files that matched. */
  readonly files: number;
  /** The total number of matching occurrences. */
  readonly matches: number;
  /** The matching files, with counts but never with the secret itself. */
  readonly findings: readonly SecretMatch[];
  /** The paths that were scanned. */
  readonly scannedFiles: number;
}

/** The options accepted by {@link scanForSecrets}. */
export interface SecretScanOptions {
  /** The directory the relative paths in the result are computed against. */
  readonly root: string;
  /** The literal secret value to look for. Never logged. */
  readonly secret: string;
  /**
   * The file extensions to scan. A file without an extension is scanned too.
   * Defaults to the text-ish extensions a credential could hide in.
   */
  readonly extensions?: readonly string[];
  /** Directory names that are never descended into. */
  readonly ignoredDirectories?: readonly string[];
}

/** The default extensions the scanner inspects. */
export const DEFAULT_SCANNED_EXTENSIONS: readonly string[] = [
  ".ts",
  ".mts",
  ".cts",
  ".js",
  ".mjs",
  ".cjs",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".md",
  ".txt",
  ".log",
  ".ndjson",
  ".env",
  ".sh",
  ".html",
  ".css",
];

/** The directories the scanner never descends into by default. */
export const DEFAULT_IGNORED_DIRECTORIES: readonly string[] = [
  "node_modules",
  ".git",
  "dist",
  "coverage",
  "data",
  ".next",
  ".turbo",
];

/**
 * A file is skipped when it is larger than this. Credentials are short; a
 * multi-megabyte binary never hides one in a way a reviewer would miss.
 */
const MAX_SCANNED_FILE_BYTES = 8 * 1024 * 1024;

/** Count the occurrences of `needle` inside `haystack`, without building the value. */
function countOccurrences(haystack: string, needle: string): number {
  if (needle.length === 0) return 0;
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count += 1;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

/**
 * Replace every occurrence of a secret with the redaction sentinel.
 *
 * The live gate writes every artefact through this function, so a credential
 * can never reach stdout, a log file or an audit record.
 */
export function redactSecret(value: string, secret: string): string {
  if (secret.length === 0) return value;
  return value.split(secret).join(REDACTION_SENTINEL);
}

/** List every file below `directory`, honouring the ignore list. */
function walk(directory: string, ignored: readonly string[], out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(directory);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (ignored.includes(entry)) continue;
    const full = path.join(directory, entry);
    let stats;
    try {
      stats = statSync(full);
    } catch {
      continue;
    }
    if (stats.isDirectory()) {
      walk(full, ignored, out);
    } else if (stats.isFile()) {
      out.push(full);
    }
  }
}

/**
 * Scan a tree for a literal secret.
 *
 * The result never contains the secret: only file names and counts. That keeps
 * the scan itself safe to print in CI output and in the release evidence.
 */
export function scanForSecrets(options: SecretScanOptions): SecretScanResult {
  const extensions = options.extensions ?? DEFAULT_SCANNED_EXTENSIONS;
  const ignored = options.ignoredDirectories ?? DEFAULT_IGNORED_DIRECTORIES;
  const files: string[] = [];
  walk(options.root, ignored, files);

  const findings: SecretMatch[] = [];
  let scannedFiles = 0;
  let matches = 0;

  for (const file of files.sort()) {
    const extension = path.extname(file);
    const basename = path.basename(file);
    const isDotEnv = basename === ".env" || basename.startsWith(".env.");
    if (!isDotEnv && extension !== "" && !extensions.includes(extension)) continue;

    let stats;
    try {
      stats = statSync(file);
    } catch {
      continue;
    }
    if (stats.size > MAX_SCANNED_FILE_BYTES) continue;

    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    scannedFiles += 1;
    const count = countOccurrences(content, options.secret);
    if (count > 0) {
      matches += count;
      findings.push({ file: path.relative(options.root, file), count });
    }
  }

  return { files: findings.length, matches, findings, scannedFiles };
}

/**
 * Assert that a secret does not occur in any of the supplied files.
 *
 * Returns the scan result so the caller can record it as evidence. It throws
 * an error whose message names the offending *files* but never the secret.
 */
export function assertNoSecretLeak(
  files: readonly string[],
  secret: string,
  label = "artefact",
): SecretScanResult {
  const findings: SecretMatch[] = [];
  let matches = 0;
  let scannedFiles = 0;

  for (const file of files) {
    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    scannedFiles += 1;
    const count = countOccurrences(content, secret);
    if (count > 0) {
      matches += count;
      findings.push({ file, count });
    }
  }

  const result: SecretScanResult = { files: findings.length, matches, findings, scannedFiles };
  if (matches > 0) {
    const names = findings.map((finding) => `${finding.file} (${finding.count})`).join(", ");
    throw new Error(
      `Credential leak detected in ${label}: ${matches} match(es) in ${names}. ` +
        "The credential must be rotated before the run may continue.",
    );
  }
  return result;
}
