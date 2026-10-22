"""
security_checks.py — Individual security check implementations for SecureSight AI.
Each check function receives pre-fetched response data and returns a list of finding dicts.
No check performs destructive operations or sends exploit payloads.
"""

from __future__ import annotations
import re
import uuid
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Severity / confidence constants
# ---------------------------------------------------------------------------

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH     = "High"
SEVERITY_MEDIUM   = "Medium"
SEVERITY_LOW      = "Low"
SEVERITY_INFO     = "Informational"

CONF_HIGH   = "High"
CONF_MEDIUM = "Medium"
CONF_LOW    = "Low"


def _finding(
    scan_id: str,
    user_id: str,
    check_name: str,
    target: str,
    severity: str,
    confidence: str,
    title: str,
    evidence: str,
    explanation: str,
    impact: str,
    recommendation: str,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "user_id": user_id,
        "check_name": check_name,
        "target": target,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "evidence": evidence,
        "explanation": explanation,
        "impact": impact,
        "recommendation": recommendation,
        "status": "open",
        "created_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# HTTPS checks
# ---------------------------------------------------------------------------

def check_https(
    scan_id: str, user_id: str, target: str,
    final_url: str, scheme: str, ssl_info: dict | None,
    tls_error_category: str | None = None,
) -> list[dict]:
    findings = []
    check = "HTTPS Configuration"

    if scheme == "http":
        findings.append(_finding(
            scan_id, user_id, check, target,
            SEVERITY_HIGH, CONF_HIGH,
            "Site does not use HTTPS",
            f"Final URL scheme: {scheme}",
            "The site is served over plain HTTP. Traffic between the browser and server is not encrypted.",
            "Sensitive data including credentials, cookies, and form data may be intercepted by network attackers (MITM).",
            "Configure your web server to serve content over HTTPS using a valid TLS certificate. Redirect all HTTP traffic to HTTPS.",
        ))
    elif ssl_info:
        if ssl_info.get("expired"):
            findings.append(_finding(
                scan_id, user_id, check, target,
                SEVERITY_HIGH, CONF_HIGH,
                "TLS certificate has expired",
                f"Expiry date: {ssl_info.get('not_after', 'unknown')}",
                "The site's TLS certificate has passed its expiry date. Browsers will warn users and refuse the connection.",
                "Users will see security warnings. Trust in the site is compromised.",
                "Renew the TLS certificate immediately. Consider automated renewal with Let's Encrypt/Certbot.",
            ))
        elif ssl_info.get("days_until_expiry") is not None and ssl_info["days_until_expiry"] < 30:
            findings.append(_finding(
                scan_id, user_id, check, target,
                SEVERITY_MEDIUM, CONF_HIGH,
                f"TLS certificate expiring soon ({ssl_info['days_until_expiry']} days)",
                f"Expiry date: {ssl_info.get('not_after', 'unknown')}",
                "The TLS certificate will expire within 30 days.",
                "If not renewed in time, browsers will warn users and the site will appear insecure.",
                "Renew the TLS certificate before expiry. Enable automated renewal to avoid future lapses.",
            ))

        inspection_error = ssl_info.get("inspection_error")
        tls_error_category = tls_error_category or inspection_error

    if scheme == "https" and tls_error_category:
        tls_findings = {
            "certificate_expired": (
                SEVERITY_HIGH, CONF_HIGH,
                "TLS certificate has expired",
                "TLS verification reported the expired-certificate validity error (verification code 10).",
                "The certificate's validity period has ended, so clients cannot establish a trusted HTTPS connection.",
                "Users and applications that enforce certificate validation will reject the connection.",
                "Renew the TLS certificate and confirm the replacement is served by the endpoint.",
            ),
            "hostname_mismatch": (
                SEVERITY_HIGH, CONF_HIGH,
                "TLS certificate hostname mismatch",
                "TLS verification reported that the certificate does not match the target hostname (verification code 62).",
                "The certificate identity does not match the hostname requested by the scanner.",
                "Clients cannot establish that the HTTPS endpoint is the intended host.",
                "Configure the server to present a certificate valid for the requested hostname.",
            ),
            "untrusted_certificate_chain": (
                SEVERITY_HIGH, CONF_HIGH,
                "TLS certificate chain is untrusted or invalid",
                "TLS verification reported an issuer, trust, or certificate-chain validation error.",
                "The certificate chain could not be validated to a trusted issuer.",
                "Clients that enforce certificate validation may reject the connection.",
                "Install the complete valid certificate chain from a trusted certificate authority.",
            ),
            "certificate_verification_failed": (
                SEVERITY_MEDIUM, CONF_LOW,
                "TLS certificate verification failed",
                "The TLS verifier rejected the certificate, but the exact validation reason is unavailable.",
                "The scanner could not establish a trusted certificate identity; expiry was not established.",
                "The HTTPS endpoint may be rejected by clients that enforce certificate validation.",
                "Review the certificate and certificate-chain configuration using a trusted TLS client.",
            ),
            "tls_handshake_failed": (
                SEVERITY_INFO, CONF_LOW,
                "TLS handshake failed before certificate validity could be determined",
                "The TLS connection failed, but no structured certificate-verification reason was available.",
                "The scanner could not complete the TLS handshake. Certificate expiry was not established.",
                "HTTPS configuration could not be fully assessed.",
                "Review the server's TLS configuration and retry the assessment.",
            ),
            "inspection_timeout": (
                SEVERITY_INFO, CONF_LOW,
                "TLS certificate inspection timed out",
                "The verified certificate-metadata connection timed out.",
                "Certificate validity metadata could not be retrieved; expiry was not established.",
                "Certificate expiry could not be assessed during this scan.",
                "Retry the assessment when the server is responsive.",
            ),
            "inspection_dns_error": (
                SEVERITY_INFO, CONF_LOW,
                "DNS resolution failed during TLS certificate inspection",
                "The certificate-metadata connection could not resolve the target hostname.",
                "Certificate validity metadata could not be retrieved; expiry was not established.",
                "Certificate expiry could not be assessed during this scan.",
                "Review DNS resolution for the target and retry the assessment.",
            ),
            "inspection_target_rejected": (
                SEVERITY_INFO, CONF_LOW,
                "TLS certificate inspection was blocked by target validation",
                "The target's resolved addresses did not pass the scanner's restricted-address policy.",
                "Certificate validity metadata could not be retrieved; expiry was not established.",
                "Certificate expiry could not be assessed during this scan.",
                "Review the target and its DNS configuration before retrying the assessment.",
            ),
            "inspection_connection_error": (
                SEVERITY_INFO, CONF_LOW,
                "TLS certificate inspection connection failed",
                "The verified certificate-metadata connection could not be established.",
                "Certificate validity metadata could not be retrieved; expiry was not established.",
                "Certificate expiry could not be assessed during this scan.",
                "Review connectivity to the target and retry the assessment.",
            ),
            "inspection_failed": (
                SEVERITY_INFO, CONF_LOW,
                "TLS certificate inspection failed",
                "The verified certificate-metadata inspection could not be completed.",
                "Certificate validity metadata could not be retrieved; expiry was not established.",
                "Certificate expiry could not be assessed during this scan.",
                "Review the target's TLS configuration and retry the assessment.",
            ),
        }
        details = tls_findings.get(tls_error_category)
        if details:
            severity, confidence, title, evidence, explanation, impact, recommendation = details
            findings.append(_finding(
                scan_id, user_id, check, target,
                severity, confidence, title, evidence, explanation, impact,
                recommendation,
            ))

    return findings


# ---------------------------------------------------------------------------
# HTTP security header checks
# ---------------------------------------------------------------------------

HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "check_name": "HSTS Header",
        "severity_missing": SEVERITY_MEDIUM,
        "title_missing": "Missing Strict-Transport-Security (HSTS) header",
        "explanation": (
            "HSTS instructs browsers to only communicate with the server over HTTPS for a specified period. "
            "Without it, users who type the URL without 'https://' may initially connect insecurely."
        ),
        "impact": "Users may be vulnerable to protocol-downgrade attacks on their first visit.",
        "recommendation": (
            "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n"
            "Ensure your HTTPS configuration is stable before enabling preload."
        ),
        "weak_pattern": None,
    },
    {
        "header": "Content-Security-Policy",
        "check_name": "Content Security Policy",
        "severity_missing": SEVERITY_MEDIUM,
        "title_missing": "Missing Content-Security-Policy header",
        "explanation": (
            "CSP restricts the sources from which a browser can load scripts, styles, images, and other resources. "
            "It is one of the most effective defences against Cross-Site Scripting (XSS)."
        ),
        "impact": "Without CSP, injected scripts from XSS attacks have fewer browser-level restrictions.",
        "recommendation": (
            "Define a strict Content-Security-Policy appropriate for your application. "
            "Start with: Content-Security-Policy: default-src 'self'"
        ),
        "weak_pattern": r"unsafe-inline|unsafe-eval",
    },
    {
        "header": "X-Content-Type-Options",
        "check_name": "X-Content-Type-Options Header",
        "severity_missing": SEVERITY_LOW,
        "title_missing": "Missing X-Content-Type-Options header",
        "explanation": (
            "This header prevents browsers from MIME-sniffing a response away from the declared content type. "
            "MIME confusion attacks can trick browsers into executing content as scripts."
        ),
        "impact": "Some browsers may execute uploaded or linked files as scripts if MIME types are misidentified.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "weak_pattern": None,
    },
    {
        "header": "X-Frame-Options",
        "check_name": "Clickjacking Protection",
        "severity_missing": SEVERITY_MEDIUM,
        "title_missing": "Missing X-Frame-Options header (clickjacking risk)",
        "explanation": (
            "X-Frame-Options prevents the page from being embedded in an <iframe> on other domains. "
            "Without it, an attacker may create an invisible overlay to trick users into clicking UI elements."
        ),
        "impact": "The site may be vulnerable to clickjacking attacks that trick users into unintended actions.",
        "recommendation": (
            "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing on the same domain is needed). "
            "Alternatively, use Content-Security-Policy: frame-ancestors 'none'."
        ),
        "weak_pattern": None,
    },
    {
        "header": "Referrer-Policy",
        "check_name": "Referrer Policy",
        "severity_missing": SEVERITY_LOW,
        "title_missing": "Missing Referrer-Policy header",
        "explanation": (
            "Referrer-Policy controls how much referrer information is sent with requests. "
            "Without it, full URLs (including query strings with tokens or IDs) may leak to third-party sites."
        ),
        "impact": "Sensitive URL parameters may be exposed in Referer headers sent to external resources.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "weak_pattern": None,
    },
    {
        "header": "Permissions-Policy",
        "check_name": "Permissions Policy",
        "severity_missing": SEVERITY_LOW,
        "title_missing": "Missing Permissions-Policy header",
        "explanation": (
            "Permissions-Policy allows servers to control which browser features (camera, microphone, geolocation) "
            "can be used by the page and embedded iframes."
        ),
        "impact": "Browser features may be accessible to third-party embedded content without restriction.",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "weak_pattern": None,
    },
]


def check_security_headers(
    scan_id: str, user_id: str, target: str, headers: dict
) -> list[dict]:
    findings = []
    norm = {k.lower(): v for k, v in headers.items()}

    for spec in HEADER_CHECKS:
        h = spec["header"].lower()
        value = norm.get(h)

        if value is None:
            findings.append(_finding(
                scan_id, user_id, spec["check_name"], target,
                spec["severity_missing"], CONF_HIGH,
                spec["title_missing"],
                f"Header '{spec['header']}' was not present in the HTTP response.",
                spec["explanation"],
                spec["impact"],
                spec["recommendation"],
            ))
        elif spec["weak_pattern"] and re.search(spec["weak_pattern"], value, re.IGNORECASE):
            findings.append(_finding(
                scan_id, user_id, spec["check_name"], target,
                SEVERITY_MEDIUM, CONF_MEDIUM,
                f"Potentially weak {spec['header']} configuration",
                f"Header value: {value[:300]}",
                (
                    f"The {spec['header']} header is present but contains directives that may reduce its effectiveness. "
                    f"Pattern matched: {spec['weak_pattern']}"
                ),
                f"The weak directive may undermine the protection intended by {spec['header']}.",
                f"Review the {spec['header']} policy and remove unsafe directives where possible.",
            ))

    return findings


# ---------------------------------------------------------------------------
# CORS checks
# ---------------------------------------------------------------------------

def check_cors(
    scan_id: str, user_id: str, target: str,
    headers: dict, cors_probe_headers: dict | None,
) -> list[dict]:
    findings = []
    check = "CORS Configuration"
    norm = {k.lower(): v for k, v in headers.items()}
    acao = norm.get("access-control-allow-origin", "")
    acac = norm.get("access-control-allow-credentials", "").lower()

    if acao == "*":
        if acac == "true":
            findings.append(_finding(
                scan_id, user_id, check, target,
                SEVERITY_HIGH, CONF_HIGH,
                "CORS wildcard origin with credentials enabled",
                f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                (
                    "The server allows any origin ('*') and also sets Allow-Credentials: true. "
                    "Note: browsers block this combination per the CORS spec, but this configuration indicates a misconfiguration."
                ),
                "Browsers reject credentialed requests to wildcard origins, but the configuration suggests intent to allow broad access.",
                "Replace the wildcard with explicit trusted origins. Never combine wildcard origin with credentials: true.",
            ))
        else:
            findings.append(_finding(
                scan_id, user_id, check, target,
                SEVERITY_LOW, CONF_MEDIUM,
                "CORS allows all origins (wildcard)",
                f"Access-Control-Allow-Origin: {acao}",
                (
                    "The server reflects '*' in Access-Control-Allow-Origin, allowing any website to read responses to cross-origin requests. "
                    "This is appropriate for public APIs but may be too permissive for authenticated endpoints."
                ),
                "Any website can make cross-origin requests and read responses. This is low risk for genuinely public resources.",
                "Restrict Access-Control-Allow-Origin to known trusted origins unless the resource is intentionally public.",
            ))

    # Check probe result for reflected origin
    if cors_probe_headers:
        probe_norm = {k.lower(): v for k, v in cors_probe_headers.items()}
        probe_acao = probe_norm.get("access-control-allow-origin", "")
        probe_acac = probe_norm.get("access-control-allow-credentials", "").lower()
        if probe_acao and probe_acao != "*" and "evil" in probe_acao.lower():
            sev = SEVERITY_HIGH if probe_acac == "true" else SEVERITY_MEDIUM
            findings.append(_finding(
                scan_id, user_id, check, target,
                sev, CONF_MEDIUM,
                "CORS reflects arbitrary Origin header",
                f"Probe ACAO: {probe_acao}\nProbe ACAC: {probe_acac}",
                "The server reflects the submitted Origin value in Access-Control-Allow-Origin without validation.",
                "An attacker's site may be able to make credentialed cross-origin requests and read the response.",
                "Validate Origin headers against an explicit allowlist before reflecting them.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Response information (informational findings)
# ---------------------------------------------------------------------------

def check_response_info(
    scan_id: str, user_id: str, target: str,
    status_code: int, response_time_ms: float, final_url: str,
) -> list[dict]:
    findings = []

    if status_code >= 400:
        findings.append(_finding(
            scan_id, user_id, "Response Status", target,
            SEVERITY_INFO, CONF_HIGH,
            f"Server returned HTTP {status_code}",
            f"Status code: {status_code}",
            "The server returned an error status code. Security headers and configuration may not be representative.",
            "Error pages may have different security configurations than main application pages.",
            "Review the target URL and ensure it resolves to the main application page.",
        ))

    if response_time_ms > 5000:
        findings.append(_finding(
            scan_id, user_id, "Response Time", target,
            SEVERITY_INFO, CONF_LOW,
            "Slow server response time",
            f"Response time: {response_time_ms:.0f}ms",
            "The server took more than 5 seconds to respond. This may indicate performance issues.",
            "Slow responses can affect user experience and may indicate resource exhaustion.",
            "Investigate server performance, caching configuration, and resource utilisation.",
        ))

    return findings
