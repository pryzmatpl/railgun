// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * Output channels for the operator CLI.
 *
 * The contract (operator CLI IR §3.1–§3.2) is:
 *
 * - data and result summaries go to stdout;
 * - warnings, progress and diagnostics go to stderr;
 * - with `--json`, stdout carries exactly one JSON document and nothing else.
 *
 * The `McpStdio` channel exists because MCP-over-stdio reserves stdout for
 * protocol frames; there the JSON document must not be written to stdout.
 */
export interface OutputChannel {
  /** Machine-readable data. */
  stdout(text: string): void;
  /** Human-readable diagnostics, warnings and progress. */
  stderr(text: string): void;
}

export function createChannel(): OutputChannel {
  return {
    stdout(text: string): void {
      process.stdout.write(text);
    },
    stderr(text: string): void {
      process.stderr.write(text);
    },
  };
}

/**
 * A channel that discards stdout data.
 *
 * Used by `serve --stdio`, where stdout is reserved for MCP protocol frames.
 */
export function createStdioProtocolChannel(): OutputChannel {
  return {
    stdout(): void {
      // stdout is reserved for MCP protocol frames in stdio mode.
    },
    stderr(text: string): void {
      process.stderr.write(text);
    },
  };
}

/** Render one JSON document followed by a trailing newline. */
export function renderJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

/**
 * Render an aligned, deterministic table.
 *
 * Long values are truncated with an ellipsis so a table stays readable; there
 * is no ANSI colouring, which keeps piped output byte-stable.
 */
export function renderTable(
  columns: readonly string[],
  rows: readonly (readonly string[])[],
  options: { maxCellWidth?: number } = {},
): string {
  const maxCellWidth = options.maxCellWidth ?? 48;
  const truncate = (value: string): string =>
    value.length > maxCellWidth ? `${value.slice(0, Math.max(1, maxCellWidth - 1))}…` : value;

  const normalizedRows = rows.map((row) => row.map((cell) => truncate(cell)));
  const widths = columns.map((column, index) =>
    Math.max(column.length, ...normalizedRows.map((row) => (row[index] ?? "").length), 0),
  );

  const renderRow = (cells: readonly string[]): string =>
    cells
      .map((cell, index) => cell.padEnd(widths[index] ?? cell.length))
      .join("  ")
      .trimEnd();

  const lines: string[] = [];
  lines.push(renderRow(columns));
  lines.push(renderRow(widths.map((width) => "-".repeat(width))));
  for (const row of normalizedRows) {
    lines.push(renderRow(row));
  }
  return `${lines.join("\n")}\n`;
}

/** Render an aligned `key: value` block for single-record human output. */
export function renderFields(fields: readonly (readonly [string, string])[]): string {
  const width = Math.max(0, ...fields.map(([key]) => key.length));
  return `${fields
    .map(([key, value]) => `${key.padEnd(width)}  ${value}`)
    .join("\n")}\n`;
}
