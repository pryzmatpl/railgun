# RailGun configuration reference

RailGun is configured by three layers. Later layers override earlier ones:

1. **Shipped defaults** — a working, secure configuration. No file and no
   environment variable is required.
2. **The YAML file** — selected by `--config <path>`, by `RAILGUN_CONFIG` /
   `RAILGUN_CONFIG_FILE`, or found through the default search order:
   `./railgun.yaml` → `./config/railgun.yaml` → `./config/railgun.example.yaml`.
   A file that was **explicitly requested** and does not exist is an error; a
   missing file in the default search order falls through to the defaults
   silently.
3. **The environment overlay** — `RAILGUN_*` variables. Always the highest
   priority.

RailGun **fails closed**. An invalid configuration stops the process before
any listener binds; it never silently degrades to a default, because that
would turn a typo into a disabled control.

---

## Server

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `server.smtp_bind` | string | `0.0.0.0:2525` | `RAILGUN_SMTP_BIND` | The submission listener. Port 25 is never bound. |
| `server.http_bind` | string | `0.0.0.0:2526` | `RAILGUN_HTTP_BIND` | The HTTP API listener. |
| `server.mcp_http_bind` | string \| null | `null` | `RAILGUN_MCP_HTTP_BIND` | The MCP streamable-HTTP listener. stdio is always available. |
| `server.max_message_bytes` | number | `26214400` (25 MiB) | `RAILGUN_MAX_MESSAGE_BYTES` | A larger message yields SMTP 552. |

## Store

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `store.driver` | `sqlite` \| `postgres` \| `memory` | `sqlite` | `RAILGUN_STORE_DRIVER` | `memory` is for tests only — it is rejected when `NODE_ENV=production`. |
| `store.path` | string | `./data/railgun.db` | `RAILGUN_STORE_PATH` | The SQLite database file. |
| `store.url` | string \| null | `null` | `RAILGUN_STORE_URL` | Required when the driver is `postgres`. |

## Queue

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `queue.concurrency` | number | `8` | `RAILGUN_QUEUE_CONCURRENCY` | Outbound deliveries in flight at once. |
| `queue.lease_seconds` | number | `300` | `RAILGUN_QUEUE_LEASE_SECONDS` | How long a worker owns a message before the lease expires. |
| `queue.max_attempts` | number | `5` | `RAILGUN_QUEUE_MAX_ATTEMPTS` | Bounded retries. A 4xx deferral consumes an attempt; a 5xx bounce does not. |

## Outbound

`outbound.mode` selects the delivery path.

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `outbound.mode` | `direct` \| `relay` | `direct` | `RAILGUN_OUTBOUND_MODE` | **Direct-to-MX is the primary mode.** A relay is an explicit fallback. |
| `outbound.relay.host` | string \| null | `null` | `RAILGUN_RELAY_HOST` | Required when the mode is `relay`. |
| `outbound.relay.port` | number | `587` | `RAILGUN_RELAY_PORT` | Use 465 for implicit TLS. |
| `outbound.relay.username_env` | string \| null | `null` | `RAILGUN_RELAY_USERNAME_ENV` | The **name** of the variable holding the username — never the username itself. |
| `outbound.relay.password_env` | string \| null | `null` | `RAILGUN_RELAY_PASSWORD_ENV` | The **name** of the variable holding the password. |
| `outbound.direct.require_reverse_dns` | boolean | `true` | `RAILGUN_REQUIRE_REVERSE_DNS` | Direct mode needs a static outbound IP with published reverse DNS. |
| `outbound.direct.connection_timeout_ms` | number | `10000` | `RAILGUN_DIRECT_TIMEOUT_MS` | The TCP/TLS connect timeout. |

In `relay` mode the relay host must be present and non-empty; the validation
fails closed otherwise.

## Auth

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `auth.allow_local_submission` | boolean | `false` | `RAILGUN_ALLOW_LOCAL_SUBMISSION` | **Deny by default.** Loopback submission must be enabled explicitly. |
| `auth.local_principal` | string | `local` | `RAILGUN_LOCAL_PRINCIPAL` | The principal a local submission is attributed to. |
| `auth.setup_token_env` | string \| null | `null` | `RAILGUN_SETUP_TOKEN_ENV` | The **name** of the variable holding the first-boot admin token. |

## Audit

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `audit.enabled` | boolean | `true` | `RAILGUN_AUDIT_ENABLED` | The append-only, hash-chained NDJSON audit trail. |
| `audit.path` | string | `./data/audit.ndjson` | `RAILGUN_AUDIT_PATH` | The chain file. |
| `audit.hash_recipients` | boolean | `true` | `RAILGUN_AUDIT_HASH_RECIPIENTS` | Recipient addresses are hashed, never stored raw. |
| `audit.salt_env` | string \| null | `null` | `RAILGUN_AUDIT_SALT_ENV` | The **name** of the variable holding the rotating hash salt. |

## DKIM

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `dkim.enabled` | boolean | `false` | `RAILGUN_DKIM_ENABLED` | Outbound signing. |
| `dkim.selector` | string \| null | `null` | `RAILGUN_DKIM_SELECTOR` | The DNS selector, e.g. `mail`. |
| `dkim.private_key_env` | string \| null | `null` | `RAILGUN_DKIM_PRIVATE_KEY_ENV` | The **name** of the variable holding the private key. |

Generate the keypair and the matching DNS records with:

```bash
railgun dkim new --domain example.com --selector mail --ipv4 203.0.113.10
```

The command writes the private key with mode `0600` and never prints it. It also prints
the RFC 6376 public key to publish at `<selector>._domainkey.<domain>`.

## Domains

| Key | Type | Default | Environment variable | Notes |
|---|---|---|---|---|
| `domains.sending_domains` | string[] | `[]` | `RAILGUN_SENDING_DOMAINS` | The sender domains permitted to submit. An empty list means no restriction; the no-open-relay rule still applies. |

---

## The environment overlay

The registry is explicit. Only the variables listed above are applied; an
unknown `RAILGUN_*` variable is **ignored**, because it may belong to a
sibling consumer.

### Value parsing

| Kind | Accepted |
|---|---|
| boolean | `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off` (case-insensitive). Anything else is a validation error naming the variable and the target path. |
| integer | A decimal integer. A non-numeric value, an empty string, or a value outside the field's range is an error. |
| number | A finite decimal number. |
| enum | One of the listed values. |
| list | A comma-separated list. Empty entries are dropped. |
| JSON | A JSON document (used for structured values). |

### The `_FILE` indirection

A variable that carries a credential also accepts a `_FILE` variant:

```bash
RAILGUN_RELAY_PASSWORD_FILE=/run/secrets/relay_password
```

The `_FILE` variant **takes precedence** over the inline variable for the same
target. The file content is trimmed of a single trailing newline; surrounding
whitespace is preserved so the hazard check below still sees it.

### The quote/whitespace hazard

A credential that arrives wrapped in matching single or double quotes, or that
begins or ends with whitespace, is **rejected at startup**:

```text
Configuration error: environment variable RAILGUN_RELAY_PASSWORD contains
whitespace or surrounding quotes; use RAILGUN_RELAY_PASSWORD_FILE to point at
a secret file instead
```

The error names the **variable only** — never the value. This is a deliberate
safeguard: a shell quoting mistake produces a credential that fails SMTP
authentication with an opaque `535`, which is very hard to diagnose from the
server log.

### Secrets never enter the configuration object

A resolved configuration holds a **reference** — the variable name or the file
path, plus a presence flag — never the value. The value is read at the moment
it is needed and is never written to a log line, an error message, a
`doctor --json` document, or the audit chain. `doctor` and every other
operator-facing projection report the *name* and the *presence*.

---

## Validation rules

Validation runs once, at load. The validated object is immutable thereafter.

- Every numeric limit is positive.
- `store.driver` is one of `sqlite`, `postgres`, `memory`; `memory` is
  rejected when `NODE_ENV=production`.
- `postgres` requires a non-empty `store.url`; `sqlite` requires a non-empty
  `store.path`.
- `outbound.mode` is `direct` or `relay`; `relay` requires
  `outbound.relay.host`.
- `auth.allow_local_submission` requires a non-empty `auth.local_principal`.
- A bind address must parse as `host:port` with a port in 1–65535.
- An **unknown YAML key is an error**, not a warning. The error names the
  offending path only.

Warnings are non-fatal and are surfaced by `railgun doctor`: DKIM signing
disabled while outbound is direct, the audit salt unset, and a setup token
unset.

---

## `railgun doctor`

`railgun doctor` loads and validates the configuration exactly as the server
does, then runs a check registry. It prints one line per check and never
prints a secret.

```
$ railgun doctor
CHECK          STATUS  DETAIL
runtime        ok      node v22.14.0 (linux x64)
configuration  ok      loaded from config/railgun.yaml
store          ok      sqlite ./data/railgun.db — writable
queue          ok      concurrency=8 lease=300s max_attempts=5
outbound       ok      mode=direct mx_lookup=true require_tls=true
dkim           warn    DKIM signing is disabled — outbound mail will not be signed
```

`railgun doctor --json` emits the same checks as a machine-readable document.
The command exits non-zero when a check fails, so it can gate a deployment.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Operation failed. |
| `2` | Usage error — an unknown command or a bad argument. |
| `3` | The configuration is invalid, unreadable, or a required setting is missing. |
| `4` | A dependency or readiness check failed (including a failing `doctor` check). |
| `5` | Authentication or authorisation was denied. |

Errors are rendered as a stable envelope and never include a stack trace, a
secret, or internal topology:

```json
{
  "error": {
    "code": "CONFIG_INVALID",
    "message": "Configuration is invalid",
    "details": { "fields": ["outbound.mode"] }
  }
}
```
