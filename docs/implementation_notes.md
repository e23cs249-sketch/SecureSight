# SecureSight AI — Implementation Notes

## Design Decisions

### Architecture

SecureSight AI uses a flat module structure rather than a package hierarchy because all modules
are small enough to navigate easily and are always deployed together. A single `app.py` serves
as the Streamlit entry point and imports from the supporting modules.

### Risk Scoring Formula

```
Score = max(0, 100 - Σ(base_penalty(severity) × confidence_multiplier))
```

Base penalties: Critical=25, High=15, Medium=8, Low=3, Informational=0.
Confidence multipliers: High=1.0, Medium=0.8, Low=0.5.

The deduction-based model was chosen because it clearly communicates what is wrong,
and each deduction can be traced to a specific finding.

Limitations:
- The score reflects only the checks SecureSight performs, not the full security posture.
- A site with only Low findings can still score 97/100 even if it has critical vulnerabilities
  outside the tool's scope (e.g., SQL injection, authentication flaws).
- This is clearly labeled as a "configuration-based posture estimate."

### Safe Target Validation

Target validation happens at two points:
1. Before the scan starts (URL parsing + IP resolution).
2. For every redirect, before a request is made to its destination. Relative
   locations are resolved against the current URL, and redirect loops and
   redirects beyond the configured limit are rejected.

This prevents the scanner from automatically following a redirect to a
destination that its address policy rejects.

Limitations:
- DNS rebinding and time-of-check/time-of-use risks are not fully mitigated:
  the hostname is resolved for validation, but the validated address is not
  pinned to the subsequent connection. Requests and the operating system
  resolve the hostname when connecting, so DNS or routing changes may still
  lead to a different address.
- The tool uses `requests` with `verify=True` to reject invalid TLS certificates.
- Certificate metadata is retrieved using Python's default verified TLS context.
  If a normal verified request fails, the scanner classifies only structured
  certificate-verification evidence: OpenSSL's expired-certificate and hostname
  mismatch codes, and known issuer/chain validation codes. Other verifier errors
  remain general verification failures; TLS failures without a certificate
  verification reason are reported as handshake failures. Certificate inspection
  timeouts, DNS failures, and connection failures are reported separately.
- No unverified TLS connection is used to retrieve certificate data. Expiry is
  reported only from a parseable verified certificate expiry date or the
  verifier's explicit expired-certificate result. When validity cannot be
  established, the scanner does not infer that the certificate is expired.
- TLS verification failures retain the failed scan status and error in scan
  history. Any supported TLS finding is saved with the scan and is available to
  the risk summary and report generator.

### Authentication

Passwords are hashed using PBKDF2-HMAC-SHA256 with 32-byte random salt and 260,000 iterations.
This provides:
- Resistance to rainbow table attacks (unique salt per password).
- Computational cost to slow brute-force (260k PBKDF2 iterations).
- Timing-safe comparison via `hmac.compare_digest`.

Limitations of this local demonstration:
- No multi-session revocation.
- No rate limiting on login attempts.
- SQLite is not suitable for concurrent multi-user cloud deployments.
- Documented in README and Settings page.

### Demo Mode

Demo data uses synthetic `.test` TLD domains (reserved, non-routable per RFC 2606).
Demo mode is enforced at the session level — it cannot trigger real scans, access real
user records, or download real finding data from the database.

### Report Generation

All user-controlled data is passed through `html.escape()` before insertion into HTML
reports. No JavaScript is included in generated reports. The HTML template uses
`data:` URIs for nothing — all styling is inline CSS only.

### CORS Probing

The CORS probe sends a single GET request with `Origin: https://evil-securesight-probe.example.com`.
This is:
- Non-destructive (GET request, no body, no state change attempted).
- Limited to one request per scan.
- Using a clearly identifiable, non-existent origin.

The probe checks whether the server reflects arbitrary origins. It does NOT attempt to
read the response body, inject payloads, or perform any POST requests.

## Known Technical Limitations

1. TLS cipher suites and protocol versions are not inspected. Use testssl.sh or Qualys SSL Labs.
2. JavaScript-rendered content is not accessible (no headless browser).
3. Authenticated endpoints (behind login) are not tested.
4. API subpaths may have different CORS/header policies than the main page.
5. Some CDNs and proxies strip or add headers — findings may reflect CDN config, not origin.
6. PDF export is not available; browser Print → Save as PDF is recommended.

## Testing Strategy

Tests are structured to avoid any real network calls:
- URL validation tests mock `_resolve_and_validate` where needed.
- Security check tests pass pre-built header/response dicts.
- Database tests use a temporary `.db` file in a system temp directory.
- Report tests use in-memory data.

No external services are required to run the test suite.

## Security Controls Summary

| Control | Implementation |
|---------|---------------|
| Restricted IP blocking | `ipaddress` module and configured address ranges, checked before the initial and each redirected request |
| Redirect handling | Redirects are handled manually; each destination is validated before following, with loop and count limits |
| Request limits | 15s timeout, 2MB max response, 5 max redirects |
| TLS verification | `verify=True` on all requests |
| SQL injection prevention | Parameterized queries throughout |
| XSS in reports | `html.escape()` on all user data |
| Password storage | PBKDF2-HMAC-SHA256 with random salt |
| Timing-safe comparison | `hmac.compare_digest` |
| Probe scope | Single GET, no body, no state-changing methods |
