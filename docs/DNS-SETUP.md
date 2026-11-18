# DNS setup for a RailGun sending domain

RailGun verifies DNS. It never mutates it. This guide lists the records an
operator must publish, how to check them, and how to roll a policy back.

## 0. Generate the keypair and the records

`railgun dkim new` produces the keypair **and** the exact records to publish,
so the published key always matches the signer:

```bash
railgun dkim new --domain example.com --selector mail --ipv4 203.0.113.10
```

It writes the private key with mode `0600` (and never prints it), writes the
public key beside it, and prints every record below with the real values
filled in. Add `--ipv6`, `--mail-host`, `--rua` and `--dmarc-policy` to cover
the remaining cases.

## 1. The records

Replace the placeholders before publishing:

| Placeholder | Meaning | Example |
|---|---|---|
| `example.com` | your sending domain | `example.com` |
| `mail` | the DKIM selector | `mail` |
| `203.0.113.10` | the host that accepts outbound mail (direct-to-MX) | `203.0.113.10` |

### MX — only needed for direct-to-MX

```dns
example.com.        MX 10 mail.example.com.
mail.example.com.   A     203.0.113.10
```

Direct-to-MX delivery requires **outbound port 25** from the RailGun host to
the recipient's MX servers. Many networks block port 25. If egress on port 25
is not available, configure the optional relay fallback instead
(`outbound.mode: relay`) and skip this record.

> **Check egress before publishing anything.** A correct MX record on a host
> that cannot reach port 25 produces mail that is accepted and silently
> deferred forever:
>
> ```bash
> # From the RailGun host:
> timeout 10 bash -c 'echo > /dev/tcp/gmail-smtp-in.l.google.com/25' && echo "25 open" || echo "25 BLOCKED"
> timeout 10 bash -c 'echo > /dev/tcp/1.1.1.1/443' && echo "443 open" || echo "443 blocked"
> ```
>
> A **timeout** (rather than a refusal) means a firewall or an upstream ISP
> is dropping the packets silently — which is the normal case on consumer and
> small-business broadband. Port 443 open while port 25 times out confirms
> the block is specific to SMTP, not a general egress failure. Residential
> ISPs block port 25 by default and only lift it for business lines; a
> datacentre or VPS with a static IP and published reverse DNS is the usual
> answer.

### SPF — one record, never two

```dns
example.com.        TXT "v=spf1 ip4:203.0.113.10 -all"
```

Start with `-all` only after SPF alignment is verified. During rollout use
`~all` and tighten it once the report shows no legitimate senders are missing.

### DKIM — the public key for the selector

RailGun signs with the private key that lives outside the repository (an
environment variable or a mounted secret file). The public key must be
published at the selector:

```dns
mail._domainkey.example.com.  TXT "v=DKIM1; k=rsa; p=<BASE64_PUBLIC_KEY>"
```

For an ed25519 key use `k=ed25519` and publish the corresponding public key.
The private key never appears in the configuration file, the audit log or any
operator projection.

### DMARC — start in monitoring mode

```dns
_dmarc.example.com.  TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com; pct=100"
```

Move to `p=quarantine` and then `p=reject` only after SPF and DKIM alignment
pass for every legitimate sending path.

## 2. Verify the records

```bash
dig +short MX example.com
dig +short A mail.example.com
dig +short TXT example.com
dig +short TXT mail._domainkey.example.com
dig +short TXT _dmarc.example.com
```

Expected results:

- `dig +short MX example.com` returns the MX host, not an empty answer.
- `dig +short TXT example.com` returns exactly one SPF record.
- `dig +short TXT mail._domainkey.example.com` returns a value starting with
  `v=DKIM1;`.
- `dig +short TXT _dmarc.example.com` returns a value starting with `v=DMARC1;`.

Use `nslookup` when `dig` is unavailable:

```bash
nslookup -type=mx example.com
nslookup -type=txt mail._domainkey.example.com
```

Propagation can take up to the TTL of the parent zone. RailGun's `doctor`
command reports the records it observes, so re-run it until the values match.

## 3. Verify from RailGun

```bash
railgun doctor
```

`doctor` reports the SPF, DKIM and DMARC observations and the DKIM selector
alignment. It never prints a private key or a credential.

## 4. Rollback and recovery

If a policy change breaks legitimate mail:

1. Reduce the DMARC policy to `p=none` and wait for the report interval to
   elapse (typically 24 hours).
2. Add the missing SPF include or DKIM selector rather than removing the
   record outright — an SPF record with two `v=spf1` entries is invalid and
   causes a permanent SPF error.
3. Keep DKIM keys rotating. Publish the new selector before switching the
   signer, and retire the old selector only after the old mail has expired.
4. If direct-to-MX delivery is blocked on port 25, switch to the relay
   fallback and update SPF with the relay's published include.

RailGun does not change DNS for you. Every change above is an operator action
in the DNS provider.
