// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * A small, dependency-free argument parser for the operator CLI.
 *
 * The CLI must be installable standalone with `npm install && npm run build`,
 * so the parser avoids a runtime CLI framework. It supports the exact grammar
 * fixed by the operator CLI IR §2.1:
 *
 * ```text
 * railgun serve (--stdio | --http | --smtp) [options]
 * railgun doctor [options]
 * railgun admin create-admin [options]
 * railgun messages list|show|retry|suppress [options]
 * railgun stats [options]
 * railgun bounce list [options]
 * railgun suppress add <address> --reason <code> [options]
 * railgun queue stats [options]
 * ```
 */

export interface FlagSpec {
  /** Long name without the leading dashes, e.g. `config`. */
  readonly name: string;
  /** `boolean` flags take no value; `string` flags require one. */
  readonly type: "boolean" | "string";
  /** Optional short alias, e.g. `c` for `--config`. */
  readonly short?: string;
  /** Repeatable flags accumulate into an array. */
  readonly repeatable?: boolean;
  /** Help text shown in `--help`. */
  readonly description: string;
  /** Placeholder shown in help for string flags. */
  readonly placeholder?: string;
}

export interface ParsedArgs {
  /** Positional arguments in order. */
  readonly positionals: string[];
  /** Flag values by long name. Absent flags are `undefined`. */
  readonly flags: Map<string, string | boolean | string[]>;
}

/**
 * Parse `argv` against a flag specification.
 *
 * Unknown flags and missing values are usage errors: the CLI must fail with
 * exit code 2 rather than silently ignoring operator input.
 */
export function parseArgs(argv: readonly string[], specs: readonly FlagSpec[]): ParsedArgs {
  const byName = new Map<string, FlagSpec>();
  const byShort = new Map<string, FlagSpec>();
  for (const spec of specs) {
    byName.set(spec.name, spec);
    if (spec.short) {
      byShort.set(spec.short, spec);
    }
  }

  const positionals: string[] = [];
  const flags = new Map<string, string | boolean | string[]>();

  const setFlag = (spec: FlagSpec, value: string | boolean): void => {
    if (spec.repeatable) {
      const existing = flags.get(spec.name);
      const list = Array.isArray(existing) ? existing : [];
      list.push(String(value));
      flags.set(spec.name, list);
      return;
    }
    flags.set(spec.name, value);
  };

  let index = 0;
  let onlyPositionals = false;
  while (index < argv.length) {
    const token = argv[index] ?? "";
    index += 1;

    if (onlyPositionals) {
      positionals.push(token);
      continue;
    }
    if (token === "--") {
      onlyPositionals = true;
      continue;
    }

    if (token.startsWith("--")) {
      const body = token.slice(2);
      const equals = body.indexOf("=");
      const name = equals === -1 ? body : body.slice(0, equals);
      const inlineValue = equals === -1 ? undefined : body.slice(equals + 1);
      const spec = byName.get(name);
      if (!spec) {
        throw new UsageError(`Unknown option '--${name}'`);
      }
      if (spec.type === "boolean") {
        if (inlineValue !== undefined) {
          throw new UsageError(`Option '--${name}' does not take a value`);
        }
        setFlag(spec, true);
        continue;
      }
      if (inlineValue !== undefined) {
        setFlag(spec, inlineValue);
        continue;
      }
      const next = argv[index];
      if (next === undefined || (next.startsWith("--") && next.length > 2)) {
        throw new UsageError(`Option '--${name}' requires a value`);
      }
      index += 1;
      setFlag(spec, next);
      continue;
    }

    if (token.startsWith("-") && token.length > 1 && token !== "-") {
      const short = token.slice(1);
      const spec = byShort.get(short);
      if (!spec) {
        throw new UsageError(`Unknown option '-${short}'`);
      }
      if (spec.type === "boolean") {
        setFlag(spec, true);
        continue;
      }
      const next = argv[index];
      if (next === undefined) {
        throw new UsageError(`Option '-${short}' requires a value`);
      }
      index += 1;
      setFlag(spec, next);
      continue;
    }

    positionals.push(token);
  }

  return { positionals, flags };
}

/** Thrown by {@link parseArgs} for malformed input; mapped to exit code 2. */
export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

/** Read a string flag, returning `undefined` when absent. */
export function stringFlag(parsed: ParsedArgs, name: string): string | undefined {
  const value = parsed.flags.get(name);
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "boolean") {
    throw new UsageError(`Option '--${name}' requires a value`);
  }
  if (Array.isArray(value)) {
    return value[value.length - 1];
  }
  return value;
}

/** Read a boolean flag. */
export function booleanFlag(parsed: ParsedArgs, name: string): boolean {
  return parsed.flags.get(name) === true;
}

/** Read a repeatable string flag as an array. */
export function listFlag(parsed: ParsedArgs, name: string): string[] {
  const value = parsed.flags.get(name);
  if (value === undefined) {
    return [];
  }
  if (Array.isArray(value)) {
    return value;
  }
  return [String(value)];
}

/** Read an integer flag with an inclusive range check. */
export function intFlag(
  parsed: ParsedArgs,
  name: string,
  options: { min: number; max: number; default: number },
): number {
  const raw = stringFlag(parsed, name);
  if (raw === undefined) {
    return options.default;
  }
  if (!/^-?\d+$/.test(raw)) {
    throw new UsageError(`Option '--${name}' must be an integer`);
  }
  const value = Number.parseInt(raw, 10);
  if (value < options.min || value > options.max) {
    throw new UsageError(
      `Option '--${name}' must be between ${options.min} and ${options.max}`,
    );
  }
  return value;
}

/**
 * Parse a duration such as `30s`, `5m`, `1h` or a bare second count.
 *
 * Used by the global `--timeout` option.
 */
export function durationFlag(parsed: ParsedArgs, name: string, fallbackMs: number): number {
  const raw = stringFlag(parsed, name);
  if (raw === undefined) {
    return fallbackMs;
  }
  const match = /^(\d+)(ms|s|m|h)?$/.exec(raw.trim());
  if (!match) {
    throw new UsageError(`Option '--${name}' must be a duration such as 30s, 5m or 1h`);
  }
  const amount = Number.parseInt(match[1] ?? "0", 10);
  const unit = match[2] ?? "s";
  const factor = unit === "ms" ? 1 : unit === "s" ? 1000 : unit === "m" ? 60_000 : 3_600_000;
  if (amount <= 0) {
    throw new UsageError(`Option '--${name}' must be greater than zero`);
  }
  return amount * factor;
}
