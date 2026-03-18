# NAIS Resolver

Reference resolver implementation for NAIS identifiers. This is the public resolver powering `resolver.nais.id`.

## What It Does

The resolver takes a domain and returns structured NAIS identity data:

1. Looks up `_agent.<domain>` DNS TXT records
2. Parses the NAIS record fields (`v`, `manifest`, `mcp`, `auth`, `pay`)
3. Fetches the `/.well-known/agent.json` manifest
4. Validates the manifest against the NAIS schema
5. Returns a normalized JSON response

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
  "resolver_version": "0.1",
  "discovery": {
    "agent_txt_host": "_agent.example.com"
  },
  "dns": {
    "agent_records": ["v=nais1; manifest=https://example.com/.well-known/agent.json"]
  },
  "resolved": {
    "manifest_url": "https://example.com/.well-known/agent.json",
    "mcp_endpoint": "https://example.com/mcp",
    "auth": ["wallet"],
    "payments": ["x402"],
    "version": "nais1"
  },
  "manifest": {
    "fetched": true,
    "http_status": 200,
    "data": { ... },
    "validation": {
      "valid": true,
      "errors": [],
      "warnings": []
    }
  }
}
```

## Files

```
resolve.php    # Main resolver endpoint
.htaccess      # Apache URL rewriting
cache/         # Filesystem cache (300s TTL)
```

## Requirements

- PHP 8.1+
- Apache with mod_rewrite (or equivalent)
- `dns_get_record()` function enabled

## Security

- HTTPS-only manifest fetching with full TLS verification
- Redirect limit (max 3 hops)
- Cross-domain redirect detection
- Response size cap (1 MiB)
- Request/connection timeouts
- CORS headers

## Self-Hosting

Drop the files into any PHP-capable web server. The resolver uses filesystem caching with a 300-second TTL. Ensure the `cache/` directory is writable by the web server.

## Related

- [nais](https://github.com/nais-standard/nais) — Main website
- [spec](https://github.com/nais-standard/spec) — Protocol specification
- [clients](https://github.com/nais-standard/clients) — SDKs that wrap this resolver
