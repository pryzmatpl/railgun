// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The RailGun authors

/**
 * `railgun admin create-admin` — bootstrap the first operator principal.
 *
 * The command is non-interactive: it reads the display name, email and
 * optional secret from flags, the environment or a secret file. It never
 * prompts, and it never accepts a secret as an ordinary positional value.
 *
 * A generated credential is displayed at most once, on stdout, and is never
 * written to a log, an audit record or a later projection.
 */
import { readFileSync } from "node:fs";

import { CliError } from "../cli/errors.js";
import { toCliError } from "../cli/service-error.js";
import { type CommandContext } from "../cli/context.js";
import { renderFields, renderJson } from "../cli/output.js";
import type { AdminProjection } from "../domain/types.js";
import { auditRecord, requireScope } from "../services/compose.js";

/** Options accepted by `admin create-admin`. */
export interface CreateAdminOptions {
  name: string | undefined;
  email: string | undefined;
  tenant: string | undefined;
  secretFile: string | undefined;
  secretStdin: boolean;
  /** Explicit one-time secret supplied by the caller; never taken from argv. */
  secret?: string | undefined;
}

/** The scopes granted to a bootstrapped administrator. */
const ADMIN_SCOPES = ["read", "admin", "send"];

/** `railgun admin create-admin` */
export async function createAdmin(
  context: CommandContext,
  options: CreateAdminOptions,
): Promise<number> {
  const tenant = options.tenant?.trim() || "default";
  const displayName = options.name?.trim() || `admin@${tenant}`;
  const email = options.email?.trim() || null;

  const secret = await resolveAdminSecret(context, options);

  if (context.isRemote) {
    throw CliError.usage(
      "Remote mode does not support admin creation; run the command against the local store",
    );
  }

  const services = context.services();
  requireScope(services.principal, "admin");

  let result: { projection: AdminProjection; secret: string | null; created: boolean };
  try {
    result = services.store.createAdmin({
      displayName,
      email,
      tenant,
      scopes: ADMIN_SCOPES,
      secret,
    });
  } catch (cause) {
    throw toCliError(cause);
  }

  services.store.appendAudit(
    auditRecord(services.principal, "admin.create", result.projection.id, "bootstrap"),
  );

  const payload = {
    admin: result.projection,
    created: result.created,
    // The secret is present only when the service generated one and only in
    // this response. It is never persisted or re-read.
    secret: result.secret,
  };

  context.channel.stdout(
    context.options.json ? renderJson(payload) : renderAdmin(result.projection, result.created, result.secret),
  );
  return 0;
}

/**
 * Resolve the admin credential.
 *
 * The secret may come from a secret file, from stdin, or from the
 * environment. It is never taken from a positional argument, because a
 * command-line argument is visible in the process list.
 */
async function resolveAdminSecret(
  context: CommandContext,
  options: CreateAdminOptions,
): Promise<string | undefined> {
  if (options.secretStdin) {
    // The CLI must not block when stdin is not a TTY, but an explicit
    // `--secret-stdin` is an instruction to read the pipe, so this is the one
    // case where blocking on stdin is correct.
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(Buffer.from(chunk));
    }
    const secret = Buffer.concat(chunks).toString("utf8").trim();
    if (secret.length === 0) {
      throw CliError.usage("No secret was read from stdin");
    }
    return secret;
  }

  if (options.secretFile) {
    let contents: string;
    try {
      contents = readFileSync(options.secretFile, "utf8");
    } catch {
      throw CliError.usage(`The secret file could not be read: ${options.secretFile}`);
    }
    const secret = contents.trim();
    if (secret.length === 0) {
      throw CliError.usage(`The secret file is empty: ${options.secretFile}`);
    }
    return secret;
  }

  const fromEnv = context.env["RAILGUN_ADMIN_SECRET"];
  if (fromEnv && fromEnv.length > 0) {
    return fromEnv;
  }

  return options.secret;
}

/**
 * Render the admin projection.
 *
 * Only the credential fingerprint is shown; the secret itself is shown once,
 * and only when the service generated it.
 */
function renderAdmin(
  admin: AdminProjection,
  created: boolean,
  secret: string | null,
): string {
  let output = renderFields([
    ["id", admin.id],
    ["display-name", admin.displayName],
    ["email", admin.email ?? "-"],
    ["tenant", admin.tenant],
    ["scopes", admin.scopes.join(", ")],
    ["credential-fingerprint", admin.credentialFingerprint ?? "-"],
    ["created", created ? "yes" : "already-present"],
  ]);
  if (secret) {
    output += `\ncredential (shown once): ${secret}\n`;
  }
  return output;
}
