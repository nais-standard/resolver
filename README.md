# NAIS Resolver

Reference resolver implementation for NAIS identifiers. This is the public resolver powering `resolver.nais.id`.

## What It Does

The resolver takes a domain and returns structured NAIS identity data:

1. Looks up `_agent.<domain>` DNS TXT records
2. Parses the NAIS record fields (`v`, `manifest`, `k`)
3. Fetches the `/.well-known/agent.json` card
4. Validates the card against the NAIS schema
5. Verifies the card's mandatory Ed25519 signature against the DNS `k=` key
6. Returns a normalized JSON response

## API

```
GET https://resolver.nais.id/resolve.php?domain=example.com
```

### Response

```json
{
  "ok": true,
  "cached": false,
  "domain": "example.com",
  "resolver_version": "1.0",
  "discovery": {
    "agent_txt_host": "_agent.example.com"
  },
  "dns": {
    "agent_records": ["v=nais1; manifest=https://example.com/.well-known/agent.json; k=ed25519:Bx91kQz3vR7w..."]
  },
  "resolved": {
    "manifest_url": "https://example.com/.well-known/agent.json",
    "mcp_endpoint": "https://example.com/mcp",
    "key": "ed25519:Bx91kQz3vR7w...",
    "auth": ["wallet"],
    "payments": ["x402"],
    "pay_to": ["0x742d35Cc6634C0532925a3b8D4C9B7F1A2e3d4E5"],
    "tags": ["weather", "forecast"],
    "wallet": null,
    "version": "nais1",
    "signature_verified": true
  },
  "manifest": {
    "fetched": true,
    "http_status": 200,
    "data": { ... },
    "signature": {
      "present": true,
      "verified": true,
      "kid": "ed25519:Bx91kQz3vR7w...",
      "alg": "EdDSA",
      "reason": null
    },
    "validation": {
      "valid": true,
      "errors": [],
      "warnings": []
    }
  }
}
```

Notes on the response:

- `resolved.key` is the DNS `k=` signing-key fingerprint. `resolved.pay_to` is only populated when the signature verified.
- `resolved.signature_verified` is a boolean summary of `manifest.signature.verified`.
- `manifest.signature` reports `{ present, verified, kid, alg, reason }`.
- `manifest.validation.valid` is `false` whenever the signature is missing or invalid — the signature is mandatory.

## Files

```
resolve.php    # Main resolver endpoint
.htaccess      # Apache URL rewriting
cache/         # Filesystem cache (300s TTL)
```

## Requirements

- PHP 8.1+
- `ext-sodium` (Ed25519 signature verification)
- `ext-curl` and `ext-json`
- Apache with mod_rewrite (or equivalent)
- `dns_get_record()` function enabled

## Security

- HTTPS-only manifest fetching with full TLS verification
- Mandatory Ed25519 signature verification of every card against the DNS `k=` key
- Redirect limit (max 3 hops)
- Cross-domain redirect detection
- Response size cap (1 MiB)
- Request/connection timeouts
- CORS headers

### Trust Model

Every card carries a mandatory detached EdDSA (Ed25519) JWS over its canonical JSON body (canonicalization is a subset of RFC 8785 / JCS: keys sorted, no whitespace, integers as integers). The signing-key fingerprint is published in DNS (`k=`), and the card's `kid` must match it. A web-server compromise alone therefore cannot forge a card or swap the `payTo` address — an attacker needs BOTH the DNS zone and the private signing key. x402 payments are irreversible, so `payTo` must never be used from an unverified card.

## Self-Hosting

Drop the files into any PHP-capable web server. The resolver uses filesystem caching with a 300-second TTL. Ensure the `cache/` directory is writable by the web server.

## Related

- [nais](https://github.com/nais-standard/nais) — Main website
- [spec](https://github.com/nais-standard/spec) — Protocol specification
- [clients](https://github.com/nais-standard/clients) — SDKs that wrap this resolver
