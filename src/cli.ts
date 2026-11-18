// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * The `railgun` operator command-line interface.
 *
 * This module owns argument parsing, presentation, exit-code mapping and
 * transport selection only. Every business decision lives in the package's
 * application services, so the CLI cannot drift from the HTTP and MCP
 * surfaces.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  type FlagSpec,
  UsageError,
  booleanFlag,
  intFlag,
  parseArgs,
  stringFlag,
} from "./cli/args.js";
import { GLOBAL_FLAGS, createContext, parseGlobalOptions } from "./cli/context.js";
import { CliError, EXIT, exitCodeFor, toErrorEnvelope } from "./cli/errors.js";
import { toCliError } from "./cli/service-error.js";
import { type OutputChannel, createChannel, renderJson } from "./cli/output.js";
import { createAdmin, type CreateAdminOptions } from "./commands/admin.js";
import { bounceList, type BounceListOptions } from "./commands/bounce.js";
import { doctorCommand } from "./commands/doctor.js";
import { dkimNew, type DkimNewOptions } from "./commands/dkim.js";
import {
  messagesList,
  messagesRetry,
  messagesShow,
  messagesSuppress,
  type MessageListOptions,
} from "./commands/messages.js";
import { queueStats } from "./commands/queue.js";
import { serveCommand, resolveServeMode } from "./commands/serve.js";
import { statsCommand, type StatsOptions } from "./commands/stats.js";
import { suppressAdd, type SuppressAddOptions } from "./commands/suppress.js";

/** The package version, read from the manifest at runtime. */
export function packageVersion(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const manifest = JSON.parse(
      readFileSync(path.resolve(here, "..", "package.json"), "utf8"),
    ) as { version?: string };
    return manifest.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const MESSAGE_LIST_FLAGS: readonly FlagSpec[] = [
  { name: "status", type: "string", description: "Filter by message status", placeholder: "<status>" },
  { name: "tenant", type: "string", description: "Filter by tenant", placeholder: "<tenant>" },
  { name: "recipient", type: "string", description: "Filter by recipient hash", placeholder: "<hash>" },
  { name: "since", type: "string", description: "Only messages created at or after this time", placeholder: "<time>" },
  { name: "until", type: "string", description: "Only messages created at or before this time", placeholder: "<time>" },
  { name: "limit", type: "string", description: "Maximum number of messages to return", placeholder: "<n>" },
  { name: "cursor", type: "string", description: "Pagination cursor", placeholder: "<cursor>" },
];

const BOUNCE_LIST_FLAGS: readonly FlagSpec[] = [
  {
    name: "class",
    type: "string",
    description: "Filter by bounce class (permanent or temporary)",
    placeholder: "<class>",
  },
  { name: "since", type: "string", description: "Only bounces at or after this time", placeholder: "<time>" },
  { name: "until", type: "string", description: "Only bounces at or before this time", placeholder: "<time>" },
  { name: "limit", type: "string", description: "Maximum number of bounces to return", placeholder: "<n>" },
  { name: "cursor", type: "string", description: "Pagination cursor", placeholder: "<cursor>" },
];

const STATS_FLAGS: readonly FlagSpec[] = [
  { name: "tenant", type: "string", description: "Filter by tenant", placeholder: "<tenant>" },
  { name: "since", type: "string", description: "Only activity at or after this time", placeholder: "<time>" },
  { name: "until", type: "string", description: "Only activity at or before this time", placeholder: "<time>" },
];

const SUPPRESS_ADD_FLAGS: readonly FlagSpec[] = [
  {
    name: "reason",
    type: "string",
    description: "Stable suppression reason code",
    placeholder: "<code>",
  },
  {
    name: "expires",
    type: "string",
    description: "ISO 8601 expiry; omit for a permanent suppression",
    placeholder: "<time>",
  },
];

/** Flags accepted by `railgun dkim new`. */
const DKIM_NEW_FLAGS: readonly FlagSpec[] = [
  {
    name: "domain",
    type: "string",
    description: "The sending domain, e.g. example.com",
    placeholder: "<domain>",
  },
  {
    name: "selector",
    type: "string",
    description: "The DKIM selector, e.g. mail",
    placeholder: "<selector>",
  },
  {
    name: "private-key-path",
    type: "string",
    description: "Where to write the private key (default: secrets/dkim-<selector>.pem)",
    placeholder: "<path>",
  },
  {
    name: "public-key-path",
    type: "string",
    description: "Where to write the public key (default: secrets/dkim-<selector>.pub.pem)",
    placeholder: "<path>",
  },
  {
    name: "ipv4",
    type: "string",
    description: "The outbound IPv4 address of this host, for the SPF and A records",
    placeholder: "<address>",
  },
  {
    name: "ipv6",
    type: "string",
    description: "The outbound IPv6 address of this host, for the SPF record",
    placeholder: "<address>",
  },
  {
    name: "mail-host",
    type: "string",
    description: "The hostname that publishes the MX record (default: mail.<domain>)",
    placeholder: "<host>",
  },
  {
    name: "rua",
    type: "string",
    description: "The DMARC reporting mailbox (default: dmarc@<domain>)",
    placeholder: "<address>",
  },
  {
    name: "dmarc-policy",
    type: "string",
    description: "The DMARC policy to publish: none, quarantine or reject (default: none)",
    placeholder: "<policy>",
  },
];

const ADMIN_CREATE_FLAGS: readonly FlagSpec[] = [
  { name: "name", type: "string", description: "Display name of the administrator", placeholder: "<name>" },
  { name: "email", type: "string", description: "Email address of the administrator", placeholder: "<email>" },
  { name: "tenant", type: "string", description: "Tenant the administrator belongs to", placeholder: "<tenant>" },
  {
    name: "secret-file",
    type: "string",
    description: "Read the credential from a file",
    placeholder: "<path>",
  },
  {
    name: "secret-stdin",
    type: "boolean",
    description: "Read the credential from standard input",
  },
];

const SERVE_FLAGS: readonly FlagSpec[] = [
  { name: "stdio", type: "boolean", description: "Serve the MCP transport over stdin/stdout" },
  { name: "http", type: "boolean", description: "Serve the operator and client HTTP API" },
  { name: "smtp", type: "boolean", description: "Serve the SMTP submission listener" },
  { name: "http-bind", type: "string", description: "Override the HTTP bind address", placeholder: "<host:port>" },
  { name: "smtp-bind", type: "string", description: "Override the SMTP bind address", placeholder: "<host:port>" },
];

/** The top-level help text. */
export const HELP_TEXT = `railgun — the open Mailgun alternative

Usage:
  railgun serve (--stdio | --http | --smtp) [options]
  railgun doctor [options]
  railgun admin create-admin [options]
  railgun messages list [options]
  railgun messages show <message-id> [options]
  railgun messages retry <message-id> [options]
  railgun messages suppress <message-id> --reason <code> [options]
  railgun stats [options]
  railgun bounce list [options]
  railgun suppress add <address> --reason <code> [options]
  railgun queue stats [options]
  railgun dkim new --domain <domain> --selector <selector> [options]

Global options:
${GLOBAL_FLAGS.map((flag) => `  --${flag.name.padEnd(10)} ${flag.description}`).join("\n")}

Exit codes:
  0  success
  1  operation failed
  2  usage error
  3  configuration invalid
  4  dependency or readiness failure
  5  authentication or authorization denied
`;

/**
 * Run the CLI.
 *
 * Returns the process exit code. All failures are rendered through the stable
 * error envelope; no stack trace is printed.
 */
export async function run(
  argv: readonly string[],
  channel: OutputChannel = createChannel(),
): Promise<number> {
  let context = createContext(
    {
      configPath: undefined,
      json: false,
      url: undefined,
      apiKey: undefined,
      timeoutMs: 30_000,
      help: false,
      version: false,
    },
    channel,
  );

  try {
    const { global, rest } = parseGlobalOptions(argv);
    context = createContext(global, channel);

    if (global.version) {
      channel.stdout(`railgun ${packageVersion()}\n`);
      return EXIT.SUCCESS;
    }

    // The command word is the first positional argument. Global flags may
    // appear before it, so the leading non-flag tokens are collected first.
    const commandWords = rest.filter((token) => !token.startsWith("-"));
    const command = commandWords[0];
    const subcommand = rest.filter((token) => token !== command);

    if (global.help || command === undefined || command === "help") {
      channel.stdout(HELP_TEXT);
      return command === undefined && !global.help ? EXIT.USAGE : EXIT.SUCCESS;
    }

    switch (command) {
      case "serve":
        return await runServe(context, subcommand);
      case "doctor":
        return await runDoctorCommand(context, subcommand);
      case "admin":
        return await runAdmin(context, subcommand);
      case "messages":
        return await runMessages(context, subcommand);
      case "stats":
        return await runStats(context, subcommand);
      case "bounce":
        return await runBounce(context, subcommand);
      case "suppress":
        return await runSuppress(context, subcommand);
      case "queue":
        return await runQueue(context, subcommand);
      case "dkim":
        return await runDkim(context, subcommand);
      case "version":
        channel.stdout(`railgun ${packageVersion()}\n`);
        return EXIT.SUCCESS;
      default:
        throw CliError.usage(
          `Unknown command '${command}'. Run 'railgun --help' for the command list.`,
        );
    }
  } catch (cause) {
    return renderFailure(cause, context, channel);
  }
}

/**
 * Render a failure.
 *
 * With `--json` the stable error envelope goes to stdout; otherwise a safe
 * diagnostic goes to stderr. Neither carries a stack trace or a secret.
 */
function renderFailure(
  cause: unknown,
  context: { options: { json: boolean } },
  channel: OutputChannel,
): number {
  // The service-error mapping runs first so an application-service failure
  // keeps its stable code and exit class instead of collapsing into a
  // generic internal error.
  const normalized = cause instanceof CliError ? cause : toCliError(cause);
  const exitCode = exitCodeFor(normalized);
  const envelope = toErrorEnvelope(normalized);

  if (context.options.json) {
    channel.stdout(renderJson(envelope));
    return exitCode;
  }

  const error = envelope.error;
  let text = `error: ${error.code}: ${error.message}\n`;
  if (error.details) {
    const fields = Object.entries(error.details)
      .map(([key, value]) => `  ${key}: ${JSON.stringify(value)}`)
      .join("\n");
    if (fields) {
      text += `${fields}\n`;
    }
  }
  if (error.request_id) {
    text += `  request_id: ${error.request_id}\n`;
  }
  channel.stderr(text);
  return exitCode;
}

async function runServe(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const parsed = parseFlags(argv, SERVE_FLAGS);
  const mode = resolveServeMode({
    stdio: booleanFlag(parsed, "stdio"),
    http: booleanFlag(parsed, "http"),
    smtp: booleanFlag(parsed, "smtp"),
  });
  return serveCommand(context, {
    mode,
    httpBind: stringFlag(parsed, "http-bind"),
    smtpBind: stringFlag(parsed, "smtp-bind"),
  });
}

async function runAdmin(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const { subcommand, rest } = splitSubcommand(argv);
  if (subcommand === undefined) {
    throw CliError.usage("Usage: railgun admin create-admin [options]");
  }
  if (subcommand !== "create-admin") {
    throw CliError.usage(`Unknown admin subcommand '${subcommand}'`);
  }
  const parsed = parseFlags(rest, ADMIN_CREATE_FLAGS);
  const options: CreateAdminOptions = {
    name: stringFlag(parsed, "name"),
    email: stringFlag(parsed, "email"),
    tenant: stringFlag(parsed, "tenant"),
    secretFile: stringFlag(parsed, "secret-file"),
    secretStdin: booleanFlag(parsed, "secret-stdin"),
  };
  return createAdmin(context, options);
}

async function runMessages(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const { subcommand, rest } = splitSubcommand(argv);
  switch (subcommand) {
    case undefined:
      throw CliError.usage(
        "Usage: railgun messages list|show|retry|suppress [options]",
      );
    case "list": {
      const parsed = parseFlags(rest, MESSAGE_LIST_FLAGS);
      const options: MessageListOptions = {
        status: stringFlag(parsed, "status"),
        tenant: stringFlag(parsed, "tenant"),
        recipient: stringFlag(parsed, "recipient"),
        since: stringFlag(parsed, "since"),
        until: stringFlag(parsed, "until"),
        limit: intFlag(parsed, "limit", { min: 1, max: 500, default: 50 }),
        cursor: stringFlag(parsed, "cursor"),
      };
      return messagesList(context, options);
    }
    case "show": {
      const parsed = parseFlags(rest, []);
      const id = parsed.positionals[0];
      if (!id) {
        throw CliError.usage("Usage: railgun messages show <message-id>");
      }
      return messagesShow(context, id);
    }
    case "retry": {
      const parsed = parseFlags(rest, []);
      const id = parsed.positionals[0];
      if (!id) {
        throw CliError.usage("Usage: railgun messages retry <message-id>");
      }
      return messagesRetry(context, id);
    }
    case "suppress": {
      const parsed = parseFlags(rest, SUPPRESS_ADD_FLAGS);
      const id = parsed.positionals[0];
      if (!id) {
        throw CliError.usage("Usage: railgun messages suppress <message-id> --reason <code>");
      }
      const reason = stringFlag(parsed, "reason");
      if (!reason) {
        throw CliError.usage("A suppression reason is required");
      }
      return messagesSuppress(context, id, reason, stringFlag(parsed, "expires") ?? null);
    }
    default:
      throw CliError.usage(`Unknown messages subcommand '${subcommand}'`);
  }
}

async function runStats(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const parsed = parseFlags(argv, STATS_FLAGS);
  const options: StatsOptions = {
    tenant: stringFlag(parsed, "tenant"),
    since: stringFlag(parsed, "since"),
    until: stringFlag(parsed, "until"),
  };
  return statsCommand(context, options);
}

async function runBounce(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const { subcommand, rest } = splitSubcommand(argv);
  if (subcommand !== "list") {
    throw CliError.usage("Usage: railgun bounce list [options]");
  }
  const parsed = parseFlags(rest, BOUNCE_LIST_FLAGS);
  const rawClass = stringFlag(parsed, "class");
  let bounceClass: "permanent" | "temporary" | undefined;
  if (rawClass !== undefined) {
    const normalized = rawClass.trim().toLowerCase();
    if (normalized !== "permanent" && normalized !== "temporary") {
      throw CliError.usage(
        `Unknown bounce class '${rawClass}': expected permanent or temporary`,
      );
    }
    bounceClass = normalized;
  }
  const options: BounceListOptions = {
    class: bounceClass,
    since: stringFlag(parsed, "since"),
    until: stringFlag(parsed, "until"),
    limit: intFlag(parsed, "limit", { min: 1, max: 500, default: 50 }),
    cursor: stringFlag(parsed, "cursor"),
  };
  return bounceList(context, options);
}

async function runSuppress(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const { subcommand, rest } = splitSubcommand(argv);
  if (subcommand !== "add") {
    throw CliError.usage("Usage: railgun suppress add <address> --reason <code> [options]");
  }
  const parsed = parseFlags(rest, SUPPRESS_ADD_FLAGS);
  const options: SuppressAddOptions = {
    address: parsed.positionals[0],
    reason: stringFlag(parsed, "reason"),
    expiresAt: stringFlag(parsed, "expires"),
  };
  return suppressAdd(context, options);
}

async function runQueue(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const { subcommand } = splitSubcommand(argv);
  if (subcommand !== "stats") {
    throw CliError.usage("Usage: railgun queue stats [options]");
  }
  return queueStats(context);
}

/**
 * `railgun dkim new` — generate a DKIM keypair and the records to publish.
 */
async function runDkim(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const { subcommand, rest } = splitSubcommand(argv);
  if (subcommand !== "new") {
    throw CliError.usage(
      "Usage: railgun dkim new --domain <domain> --selector <selector> [options]",
    );
  }
  const parsed = parseFlags(rest, DKIM_NEW_FLAGS);
  const options: DkimNewOptions = {
    domain: stringFlag(parsed, "domain"),
    selector: stringFlag(parsed, "selector"),
    privateKeyPath: stringFlag(parsed, "private-key-path"),
    publicKeyPath: stringFlag(parsed, "public-key-path"),
    ipv4: stringFlag(parsed, "ipv4"),
    ipv6: stringFlag(parsed, "ipv6"),
    mailHost: stringFlag(parsed, "mail-host"),
    rua: stringFlag(parsed, "rua"),
    dmarcPolicy: stringFlag(parsed, "dmarc-policy"),
  };
  return dkimNew(context, options);
}

/**
 * Split a subcommand word from the rest of the argument list.
 *
 * The subcommand word is the first positional token; global and
 * command-specific flags may appear before or after it.
 */
function splitSubcommand(argv: readonly string[]): {
  subcommand: string | undefined;
  rest: string[];
} {
  const subcommand = argv.find((token) => !token.startsWith("-"));
  return {
    subcommand,
    rest: argv.filter((token) => token !== subcommand),
  };
}

/**
 * Run `railgun doctor`.
 *
 * The doctor accepts no command-specific flags, so an unknown flag is a
 * usage error rather than a silently ignored argument.
 */
async function runDoctorCommand(
  context: ReturnType<typeof createContext>,
  argv: readonly string[],
): Promise<number> {
  const parsed = parseFlags(argv, []);
  if (parsed.positionals.length > 0) {
    throw CliError.usage(
      `Unexpected argument '${parsed.positionals[0]}': railgun doctor takes no positional arguments`,
    );
  }
  return doctorCommand(context);
}

/**
 * Parse command flags.
 *
 * The global flags are accepted alongside the command's own flags, so a
 * global option may appear anywhere on the command line. A flag that belongs
 * to neither set is a usage error: silently ignoring it would make an
 * operator believe an option took effect when it did not.
 */
function parseFlags(argv: readonly string[], specs: readonly FlagSpec[]) {
  try {
    return parseArgs(argv, [...GLOBAL_FLAGS, ...specs]);
  } catch (cause) {
    if (cause instanceof UsageError) {
      throw CliError.usage(cause.message);
    }
    throw cause;
  }
}
