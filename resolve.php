<?php
declare(strict_types=1);

/**
 * NAIS Resolver — resolve.php
 * ─────────────────────────────────────────────────────────────────────────────
 * Network Agent Identity Standard public resolver endpoint.
 *
 * Usage:
 *   GET https://resolver.nais.id/resolve?domain=weatheragent.com
 *
 * Resolution steps:
 *   1. Validate and normalize the domain parameter
 *   2. Query DNS TXT records at _agent.<domain>, _wallet.<domain>, _payments.<domain>
 *   3. Parse the NAIS TXT record (semicolon-separated key=value pairs)
 *   4. Fetch the agent manifest (from TXT manifest= field, or /.well-known/agent.json)
 *   5. Validate the manifest against the NAIS 1.0 schema
 *   6. Return a fully structured JSON response
 *   7. Cache the result on the filesystem for CACHE_TTL seconds
 *
 * Requirements: PHP 8.1+, ext-curl, ext-json
 * License: CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/
 * ─────────────────────────────────────────────────────────────────────────────
 */

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** Resolver version returned in every response. */
const RESOLVER_VERSION     = '0.1';

/** Filesystem path for cache files. Created automatically if absent. */
const CACHE_DIR            = __DIR__ . '/cache';

/** Seconds before a cached result is considered stale. */
const CACHE_TTL            = 300;

/** User-Agent header sent with outbound manifest fetches. */
const USER_AGENT           = 'NAIS-Resolver/0.1 (+https://resolver.nais.id)';

/** Maximum total time (seconds) allowed for a manifest HTTP request. */
const CURL_TIMEOUT         = 8;

/** Maximum time (seconds) allowed to establish a TCP connection. */
const CURL_CONNECT_TIMEOUT = 4;

/** Maximum manifest response body size accepted (bytes). */
const MAX_MANIFEST_SIZE    = 1_048_576; // 1 MiB

/** TXT record fields that are treated as comma-separated arrays. */
const ARRAY_FIELDS         = ['auth', 'pay', 'methods', 'chains', 'currencies', 'tags'];

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap — output headers
// ─────────────────────────────────────────────────────────────────────────────

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Accept, X-Requested-With');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow');
header('X-Resolver: NAIS-Resolver/' . RESOLVER_VERSION);

// Clients may cache the response for the same duration as the server cache
header('Cache-Control: public, max-age=' . CACHE_TTL);

// ─────────────────────────────────────────────────────────────────────────────
// Handle pre-flight CORS request
// ─────────────────────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// Method guard
// ─────────────────────────────────────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    jsonError(405, 'Method not allowed. Use GET.');
}

// ─────────────────────────────────────────────────────────────────────────────
// Input — read and normalize the domain parameter
// ─────────────────────────────────────────────────────────────────────────────

$rawInput = trim((string)($_GET['domain'] ?? ''));

if ($rawInput === '') {
    jsonError(400, 'Missing required query parameter: domain');
}

$domain = normalizeDomain($rawInput);

if ($domain === null) {
    jsonError(400, sprintf(
        'Invalid domain "%s". Provide a bare hostname such as weatheragent.com.',
        substr(htmlspecialchars($rawInput, ENT_QUOTES, 'UTF-8'), 0, 120)
    ));
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache — return early on a valid hit
// ─────────────────────────────────────────────────────────────────────────────

$cacheKey = 'resolve_' . md5($domain);
$hit      = cacheRead($cacheKey);

if ($hit !== null) {
    $hit['cached'] = true;
    echo jsonEncode($hit);
    exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS — look up TXT records for all three NAIS subdomains
// ─────────────────────────────────────────────────────────────────────────────

$agentTxtHost    = '_agent.'    . $domain;
$walletTxtHost   = '_wallet.'   . $domain;
$paymentsTxtHost = '_payments.' . $domain;

$agentRawRecords    = lookupTxt($agentTxtHost);
$walletRawRecords   = lookupTxt($walletTxtHost);
$paymentsRawRecords = lookupTxt($paymentsTxtHost);

// Parse every _agent TXT record that contains a v= field
$agentParsedRecords = [];

foreach ($agentRawRecords as $raw) {
    if (strpos($raw, 'v=') === false) {
        continue; // skip non-NAIS records (e.g. SPF, DKIM on _agent)
    }
    $agentParsedRecords[] = [
        'raw'    => $raw,
        'parsed' => parseNaisTxt($raw),
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolution — derive the canonical NAIS identity from the primary record
// ─────────────────────────────────────────────────────────────────────────────

// Use the first _agent record that has a v= field as the primary record
$primaryData = [];

foreach ($agentParsedRecords as $record) {
    if (isset($record['parsed']['v'])) {
        $primaryData = $record['parsed'];
        break;
    }
}

/*
 * Manifest URL precedence:
 *   1. manifest= field in the primary _agent TXT record
 *   2. Fallback: https://<domain>/.well-known/agent.json
 */
$manifestUrl = (!empty($primaryData['manifest']))
    ? (string)$primaryData['manifest']
    : 'https://' . $domain . '/.well-known/agent.json';

// Extract shortcut fields from the TXT record (may be null/empty if not present)
$mcpEndpoint = isset($primaryData['mcp']) ? (string)$primaryData['mcp'] : null;
$authMethods = (array)($primaryData['auth'] ?? []);
$payMethods  = (array)($primaryData['pay']  ?? []);
$naisVersion = isset($primaryData['v']) ? (string)$primaryData['v'] : null;

// Wallet: raw value of the first _wallet TXT record, if any
$walletValue = !empty($walletRawRecords) ? $walletRawRecords[0] : null;

// ─────────────────────────────────────────────────────────────────────────────
// Manifest — fetch and validate
// ─────────────────────────────────────────────────────────────────────────────

$manifestResult = fetchManifest($manifestUrl, $domain);

// If MCP was not in DNS, try to find it in the manifest data
if ($mcpEndpoint === null && $manifestResult['fetched'] && is_array($manifestResult['data'])) {
    $md          = $manifestResult['data'];
    $mcpEndpoint = $md['mcp']
        ?? $md['mcp_endpoint']
        ?? $md['service']['mcp_endpoint']
        ?? null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Response — assemble the full structured payload
// ─────────────────────────────────────────────────────────────────────────────

$response = [
    'ok'               => true,
    'cached'           => false,
    'domain'           => $domain,
    'resolver_version' => RESOLVER_VERSION,

    // Hosts that were queried
    'discovery' => [
        'agent_txt_host'    => $agentTxtHost,
        'wallet_txt_host'   => $walletTxtHost,
        'payments_txt_host' => $paymentsTxtHost,
    ],

    // Raw and parsed DNS records
    'dns' => [
        'agent_records'   => $agentParsedRecords,
        'wallet_records'  => $walletRawRecords,
        'payment_records' => $paymentsRawRecords,
    ],

    // Derived / resolved identity fields
    'resolved' => [
        'manifest_url' => $manifestUrl,
        'mcp_endpoint' => $mcpEndpoint,
        'auth'         => $authMethods,
        'payments'     => $payMethods,
        'wallet'       => $walletValue,
        'version'      => $naisVersion,
    ],

    // Manifest fetch result + schema validation
    'manifest' => $manifestResult,
];

// ─────────────────────────────────────────────────────────────────────────────
// Cache — persist the result and send the response
// ─────────────────────────────────────────────────────────────────────────────

cacheWrite($cacheKey, $response);

echo jsonEncode($response);
exit;


// ═════════════════════════════════════════════════════════════════════════════
//  H E L P E R   F U N C T I O N S
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// Domain utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normalize user-supplied input to a bare, lowercase hostname.
 *
 * Handles:
 *   - Full URLs:           https://weatheragent.com/foo  → weatheragent.com
 *   - Trailing slashes:    weatheragent.com/             → weatheragent.com
 *   - Ports:               weatheragent.com:8080         → weatheragent.com
 *   - Trailing dots (FQDN):weatheragent.com.             → weatheragent.com
 *   - Mixed case:          WeatherAgent.Com              → weatheragent.com
 *
 * Returns the normalized hostname string, or null if the result is not a
 * syntactically valid internet hostname.
 */
function normalizeDomain(string $input): ?string
{
    $input = trim($input);

    // Strip scheme (http:// or https://) so parse_url works cleanly
    if (preg_match('#^https?://#i', $input)) {
        $parsed = parse_url($input);
        $input  = $parsed['host'] ?? '';
    }

    // Drop anything that looks like a path, query, or fragment
    if (($slashPos = strpos($input, '/')) !== false) {
        $input = substr($input, 0, $slashPos);
    }

    // Drop port
    if (($colonPos = strrpos($input, ':')) !== false) {
        $input = substr($input, 0, $colonPos);
    }

    // Lowercase and strip trailing dots (fully-qualified domain name notation)
    $input = strtolower(rtrim($input, '.'));

    // Length constraints from RFC 1035
    if ($input === '' || strlen($input) > 253) {
        return null;
    }

    $labels = explode('.', $input);

    // Must have at least two labels (domain + TLD); single-label names are
    // either localhost or private and not valid public NAIS agents.
    if (count($labels) < 2) {
        return null;
    }

    // Validate each DNS label individually
    foreach ($labels as $label) {
        if ($label === '' || strlen($label) > 63) {
            return null;
        }
        // Labels must start and end with an alphanumeric character.
        // Hyphens are allowed in the middle. No underscores in user-input domains.
        if (!preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$/', $label)) {
            return null;
        }
    }

    return $input;
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Query DNS for TXT records at the given hostname.
 *
 * Returns a flat array of raw TXT string values.
 * Long records split across multiple 255-byte strings are joined automatically.
 * Returns an empty array when no records exist or on lookup failure.
 */
function lookupTxt(string $host): array
{
    // dns_get_record() returns false on hard failures; suppress the warning.
    $records = @dns_get_record($host, DNS_TXT);

    if (!is_array($records) || empty($records)) {
        return [];
    }

    $values = [];

    foreach ($records as $record) {
        if (isset($record['txt']) && $record['txt'] !== '') {
            $values[] = $record['txt'];
        } elseif (isset($record['entries']) && is_array($record['entries'])) {
            // Some PHP builds split long TXT records across 'entries' instead of 'txt'
            $joined = implode('', $record['entries']);
            if ($joined !== '') {
                $values[] = $joined;
            }
        }
    }

    return $values;
}

// ─────────────────────────────────────────────────────────────────────────────
// NAIS TXT record parser
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Parse a NAIS _agent TXT record into a structured associative array.
 *
 * Input format:
 *   "v=nais1; manifest=https://example.com/.well-known/agent.json; mcp=https://example.com/mcp; auth=wallet; pay=x402"
 *
 * Rules:
 *   - Segments are separated by semicolons
 *   - Each segment is split on the FIRST '=' character only (URLs contain '=')
 *   - Keys are lowercased; values are trimmed
 *   - Fields in ARRAY_FIELDS (auth, pay, methods, …) are split on commas → arrays
 *   - Unknown fields are preserved verbatim for forwards compatibility
 *
 * @return array<string, string|string[]>
 */
function parseNaisTxt(string $raw): array
{
    $result   = [];
    $segments = explode(';', $raw);

    foreach ($segments as $segment) {
        $segment = trim($segment);

        if ($segment === '') {
            continue;
        }

        // Find the first '=' — there must be one and it must not be the first char
        $eqPos = strpos($segment, '=');

        if ($eqPos === false || $eqPos === 0) {
            continue; // malformed segment: skip
        }

        $key   = strtolower(trim(substr($segment, 0, $eqPos)));
        $value = trim(substr($segment, $eqPos + 1));

        if ($key === '') {
            continue;
        }

        if (in_array($key, ARRAY_FIELDS, true)) {
            // Normalise to an array of non-empty trimmed strings
            $result[$key] = array_values(
                array_filter(
                    array_map('trim', explode(',', $value)),
                    static fn(string $v): bool => $v !== ''
                )
            );
        } else {
            $result[$key] = $value;
        }
    }

    return $result;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP manifest fetcher
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch a JSON manifest from an HTTPS URL and validate its structure.
 *
 * Security controls:
 *   - HTTPS only (non-HTTPS URLs are rejected before any request is made)
 *   - Full TLS certificate verification (CURLOPT_SSL_VERIFYPEER + VERIFYHOST)
 *   - Redirect limit (max 3 hops)
 *   - Cross-domain redirect detection (manifest URL may not redirect to a different host)
 *   - Response size cap (MAX_MANIFEST_SIZE bytes)
 *   - Request and connection timeouts
 *   - Low-speed abort (stalled transfers are cancelled)
 *
 * @param string $url            Full HTTPS URL to the manifest
 * @param string $expectedDomain The domain being resolved (used in validation)
 *
 * @return array{
 *   fetched: bool,
 *   http_status: int|null,
 *   error: string|null,
 *   data: array|null,
 *   validation: array|null
 * }
 */
function fetchManifest(string $url, string $expectedDomain): array
{
    // Base (empty) result structure
    $empty = [
        'fetched'     => false,
        'http_status' => null,
        'error'       => null,
        'data'        => null,
        'validation'  => null,
    ];

    // Reject anything that is not HTTPS before touching the network
    if (strpos($url, 'https://') !== 0) {
        return array_merge($empty, [
            'error' => 'Manifest URL must use HTTPS.',
        ]);
    }

    // Sanity-check the URL structure
    if (filter_var($url, FILTER_VALIDATE_URL) === false) {
        return array_merge($empty, [
            'error' => 'Manifest URL is not syntactically valid.',
        ]);
    }

    $ch = curl_init();

    curl_setopt_array($ch, [
        CURLOPT_URL             => $url,
        CURLOPT_RETURNTRANSFER  => true,

        // Follow redirects, but only a few
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 3,

        // Timeouts
        CURLOPT_TIMEOUT         => CURL_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT  => CURL_CONNECT_TIMEOUT,

        // Abort if average transfer speed falls below 20 B/s for 5 s
        CURLOPT_LOW_SPEED_LIMIT => 20,
        CURLOPT_LOW_SPEED_TIME  => 5,

        // TLS — verify peer certificate and host name
        CURLOPT_SSL_VERIFYPEER  => true,
        CURLOPT_SSL_VERIFYHOST  => 2,

        // Identity
        CURLOPT_USERAGENT       => USER_AGENT,

        // Accept gzip/deflate to save bandwidth
        CURLOPT_ENCODING        => 'gzip, deflate',

        CURLOPT_HTTPHEADER      => [
            'Accept: application/json, */*;q=0.5',
        ],
    ]);

    $body      = (string)curl_exec($ch);
    $status    = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    $finalUrl  = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    // ── cURL transport error ────────────────────────────────
    if ($curlError !== '') {
        return array_merge($empty, [
            'http_status' => $status ?: null,
            'error'       => 'Network error: ' . $curlError,
        ]);
    }

    // ── Non-2xx HTTP status ─────────────────────────────────
    if ($status < 200 || $status >= 300) {
        return array_merge($empty, [
            'http_status' => $status,
            'error'       => 'Server returned HTTP ' . $status . '.',
        ]);
    }

    // ── Response size guard ─────────────────────────────────
    if (strlen($body) > MAX_MANIFEST_SIZE) {
        return array_merge($empty, [
            'http_status' => $status,
            'error'       => 'Manifest response exceeds maximum allowed size (1 MiB). Rejected.',
        ]);
    }

    // ── Cross-domain redirect detection ────────────────────
    // If the final URL after redirects is on a different host, reject.
    // This prevents a malicious redirect from substituting a foreign manifest.
    if ($finalUrl !== '' && $finalUrl !== $url) {
        $originalHost = (string)parse_url($url,      PHP_URL_HOST);
        $finalHost    = (string)parse_url($finalUrl, PHP_URL_HOST);

        if ($originalHost !== '' && $finalHost !== '' && $originalHost !== $finalHost) {
            return array_merge($empty, [
                'http_status' => $status,
                'error'       => sprintf(
                    'Manifest URL redirected to a different domain (%s to %s). Rejected to prevent spoofing.',
                    $originalHost,
                    $finalHost
                ),
            ]);
        }
    }

    // ── JSON parsing ────────────────────────────────────────
    $data = json_decode($body, true, 32, JSON_BIGINT_AS_STRING);

    if (!is_array($data)) {
        return array_merge($empty, [
            'http_status' => $status,
            'error'       => 'Response body is not valid JSON (' . json_last_error_msg() . ').',
        ]);
    }

    return [
        'fetched'     => true,
        'http_status' => $status,
        'error'       => null,
        'data'        => $data,
        'validation'  => validateManifest($data, $expectedDomain),
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest validator
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validate a decoded agent.json manifest against the NAIS 1.0 schema.
 *
 * Produces two lists:
 *   errors   — structural problems that prevent a well-formed NAIS identity
 *   warnings — missing recommended fields that reduce interoperability
 *
 * The 'valid' flag is true when $errors is empty (warnings are non-fatal).
 *
 * @param array  $manifest        Decoded manifest data
 * @param string $expectedDomain  Normalized domain used for resolution
 *
 * @return array{valid: bool, errors: string[], warnings: string[]}
 */
function validateManifest(array $manifest, string $expectedDomain): array
{
    $errors   = [];
    $warnings = [];

    // ── nais / standard field ───────────────────────────────
    // The spec version field should be present so resolvers know which version
    // of the schema to apply.
    $hasSpecField = isset($manifest['nais']) || isset($manifest['standard']);
    if (!$hasSpecField) {
        $warnings[] = 'Missing field: nais — expected "nais": "1.0" (NAIS spec version)';
    }

    // ── name ────────────────────────────────────────────────
    if (empty($manifest['name'])) {
        $warnings[] = 'Missing or empty field: name';
    }

    // ── id / domain ─────────────────────────────────────────
    // The manifest must declare which domain it belongs to so that resolvers
    // can confirm they fetched the manifest for the right agent.
    $manifestDomain = $manifest['id'] ?? $manifest['domain'] ?? null;

    if ($manifestDomain === null) {
        $warnings[] = 'Missing field: id or domain — should equal the agent\'s domain name';
    } elseif (
        strtolower(rtrim((string)$manifestDomain, '.')) !== $expectedDomain
    ) {
        $warnings[] = sprintf(
            'Field id/domain "%s" does not match resolved domain "%s" — possible misconfiguration or spoofing',
            $manifestDomain,
            $expectedDomain
        );
    }

    // ── standard field value sanity ─────────────────────────
    if (
        isset($manifest['standard']) &&
        strpos(strtolower((string)$manifest['standard']), 'nais') !== 0
    ) {
        $warnings[] = sprintf(
            'Field standard value "%s" does not begin with "nais" — expected e.g. "nais1" or "nais/1.0"',
            substr((string)$manifest['standard'], 0, 64)
        );
    }

    // ── MCP endpoint ────────────────────────────────────────
    // Check all known locations where an MCP endpoint may be declared.
    $hasMcp = isset($manifest['mcp'])
        || isset($manifest['mcp_endpoint'])
        || (
            isset($manifest['service']) &&
            is_array($manifest['service']) &&
            isset($manifest['service']['mcp_endpoint'])
        );

    if (!$hasMcp) {
        $warnings[] = 'No MCP endpoint found — checked: mcp, mcp_endpoint, service.mcp_endpoint';
    }

    // ── capabilities ────────────────────────────────────────
    if (empty($manifest['capabilities'])) {
        $warnings[] = 'No capabilities declared — agents should list supported capabilities for discoverability';
    }

    return [
        'valid'    => empty($errors),
        'errors'   => $errors,
        'warnings' => $warnings,
    ];
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystem cache
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Attempt to read a valid (non-expired) cache entry.
 *
 * Returns the decoded array on a cache hit, or null on a miss, expiry, or
 * any read / parse error. The cache is entirely opportunistic — failures are
 * silent and result in a fresh resolution.
 */
function cacheRead(string $key): ?array
{
    $path = cacheFilePath($key);

    if (!is_file($path)) {
        return null;
    }

    // Check freshness by comparing mtime to the current time
    $mtime = @filemtime($path);

    if ($mtime === false || (time() - $mtime) > CACHE_TTL) {
        @unlink($path); // proactively remove stale entry
        return null;
    }

    $raw = @file_get_contents($path);

    if ($raw === false || $raw === '') {
        return null;
    }

    $data = json_decode($raw, true);

    return is_array($data) ? $data : null;
}

/**
 * Persist a resolution result to the cache.
 *
 * Uses LOCK_EX to prevent concurrent processes from writing a partial file.
 * Silently skips caching if the cache directory cannot be created or written to.
 */
function cacheWrite(string $key, array $data): void
{
    // Create the cache directory if it does not yet exist
    if (!is_dir(CACHE_DIR)) {
        @mkdir(CACHE_DIR, 0750, true);
    }

    // If the directory still does not exist after mkdir, skip caching
    if (!is_dir(CACHE_DIR)) {
        return;
    }

    $path    = cacheFilePath($key);
    $encoded = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    if ($encoded !== false) {
        @file_put_contents($path, $encoded, LOCK_EX);
    }
}

/**
 * Derive a safe filesystem path for a cache entry key.
 *
 * Only alphanumeric characters, underscores, and hyphens are allowed in the
 * filename; everything else is replaced with an underscore.
 */
function cacheFilePath(string $key): string
{
    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $key);
    return CACHE_DIR . DIRECTORY_SEPARATOR . $safeName . '.json';
}

// ─────────────────────────────────────────────────────────────────────────────
// Response helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Emit a JSON error payload with the given HTTP status code and terminate.
 *
 * @param int    $httpCode  HTTP status code (4xx or 5xx)
 * @param string $message   Human-readable error description
 *
 * @return never
 */
function jsonError(int $httpCode, string $message): void
{
    http_response_code($httpCode);

    echo json_encode(
        [
            'ok'               => false,
            'cached'           => false,
            'error'            => $message,
            'resolver_version' => RESOLVER_VERSION,
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );

    exit;
}

/**
 * Encode a response array to a pretty-printed, UTF-8 JSON string.
 * Slashes in URLs are intentionally left un-escaped for readability.
 */
function jsonEncode(array $data): string
{
    return (string)json_encode(
        $data,
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
    );
}
