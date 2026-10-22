"""
scanner.py — Safe HTTP scanning engine for SecureSight AI.
Performs non-destructive web security configuration checks.
"""

from __future__ import annotations
import ipaddress
import logging
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import requests
from requests.exceptions import (
    ConnectionError as ReqConnectionError,
    SSLError as ReqSSLError,
    Timeout as ReqTimeout,
    TooManyRedirects,
)

from security_checks import (
    check_https,
    check_security_headers,
    check_cors,
    check_response_info,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCANNER_UA = "SecureSight-AI-Scanner/1.0 (Security Configuration Assessment; non-destructive)"
REQUEST_TIMEOUT = 15   # seconds
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_REDIRECTS = 5
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization"}

# Private / restricted IP ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # carrier-grade NAT
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
    ipaddress.ip_network("255.255.255.255/32"),
]


def _is_restricted_ip(ip_str: str) -> bool:
    """Return True if the IP is in a restricted / private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            not addr.is_global
            or addr.is_multicast
            or any(addr in net for net in _PRIVATE_NETWORKS)
        )
    except ValueError:
        return True  # unparseable → reject


def _resolve_and_validate(hostname: str) -> tuple[bool, str]:
    """
    Resolve hostname to IP(s) and validate none are in restricted ranges.
    Returns (is_safe, message).
    """
    # Reject raw IP addresses that look private
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_restricted_ip(hostname):
            return False, f"Target IP {hostname} is in a restricted address range."
    except ValueError:
        pass  # It's a hostname, not a bare IP

    # Reject localhost variants
    if hostname.lower() in ("localhost", "ip6-localhost", "ip6-loopback"):
        return False, "Scanning localhost is not permitted."

    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return False, f"DNS resolution failed: {exc}"

    for _fam, _type, _proto, _cname, sockaddr in results:
        ip = sockaddr[0]
        if _is_restricted_ip(ip):
            return False, (
                f"The hostname '{hostname}' resolves to {ip}, which is in a restricted address range. "
                "Scanning internal or private systems is not permitted."
            )
    return True, "ok"


def validate_target_url(url: str) -> tuple[bool, str, str, str]:
    """
    Validate that the target URL is safe to scan.
    Returns (is_valid, error_message, normalized_url, hostname).
    """
    url = url.strip()
    if not url:
        return False, "Please enter a URL.", "", ""

    # Detect unsupported schemes BEFORE prepending https://
    # e.g. ftp://, file://, javascript:, etc.
    try:
        _pre = urllib.parse.urlparse(url)
        if _pre.scheme and _pre.scheme not in ("http", "https", ""):
            return False, "Only HTTP and HTTPS URLs are supported.", "", ""
    except Exception:
        pass

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "Could not parse the URL.", "", ""

    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are supported.", "", ""

    try:
        parsed.port
    except ValueError:
        return False, "URL contains an invalid port.", "", ""

    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials are not accepted.", "", ""

    hostname = parsed.hostname
    if not hostname:
        return False, "Could not extract a hostname from the URL.", "", ""

    # Basic hostname sanity
    if len(hostname) > 253:
        return False, "Hostname is too long.", "", ""

    safe, msg = _resolve_and_validate(hostname)
    if not safe:
        return False, msg, "", ""

    # Normalize: use https if scheme is missing and https works
    normalized = urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path or "/",
        parsed.params, parsed.query, ""
    ))
    return True, "", normalized, hostname


def _url_origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlparse(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _redirect_loop_key(url: str) -> tuple[str, str, int | None, str, str, str]:
    parsed = urllib.parse.urlparse(url)
    scheme, hostname, port = _url_origin(url)
    return scheme, hostname, port, parsed.path or "/", parsed.params, parsed.query


def _clear_cross_origin_credentials(session: requests.Session) -> None:
    for header in list(session.headers):
        if header.lower() in SENSITIVE_HEADERS:
            del session.headers[header]
    session.auth = None
    session.cookies.clear()


def _exception_chain(exc: BaseException):
    pending = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        for nested in (
            getattr(current, "__cause__", None),
            getattr(current, "__context__", None),
            getattr(current, "reason", None),
            *getattr(current, "args", ()),
        ):
            if isinstance(nested, BaseException):
                pending.append(nested)


def _classify_tls_error(exc: BaseException) -> str:
    """Classify a TLS failure only when the verifier exposes structured evidence."""
    verification_error = next(
        (
            cause for cause in _exception_chain(exc)
            if isinstance(cause, ssl.SSLCertVerificationError)
        ),
        None,
    )
    if verification_error is None:
        return "tls_handshake_failed"

    verify_code = getattr(verification_error, "verify_code", None)
    if verify_code == 10:  # X509_V_ERR_CERT_HAS_EXPIRED
        return "certificate_expired"
    if verify_code == 62:  # X509_V_ERR_HOSTNAME_MISMATCH
        return "hostname_mismatch"
    if verify_code in {2, 7, 18, 19, 20, 21, 24, 25, 26, 27, 28, 32}:
        return "untrusted_certificate_chain"
    return "certificate_verification_failed"


# ---------------------------------------------------------------------------
# SSL certificate inspection
# ---------------------------------------------------------------------------

def _get_ssl_info(hostname: str, port: int = 443) -> dict:
    try:
        safe, validation_message = _resolve_and_validate(hostname)
        if not safe:
            category = (
                "inspection_dns_error"
                if validation_message.startswith("DNS resolution failed:")
                else "inspection_target_rejected"
            )
            logger.warning("TLS certificate inspection target rejected for %s", hostname)
            return {"inspection_error": category}
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10), server_hostname=hostname) as s:
            cert = s.getpeercert()
        not_after_str = cert.get("notAfter", "")
        not_before_str = cert.get("notBefore", "")
        # Parse expiry
        try:
            not_after_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (not_after_dt - datetime.now(timezone.utc)).days
            expired = days_left < 0
        except (ValueError, TypeError):
            days_left = None
            expired = False
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return {
            "not_after": not_after_str,
            "not_before": not_before_str,
            "days_until_expiry": days_left,
            "expired": expired,
            "common_name": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", ""),
            "subject_alt_names": cert.get("subjectAltName", []),
        }
    except ssl.SSLCertVerificationError as exc:
        category = _classify_tls_error(exc)
        logger.warning("TLS certificate inspection failed for %s: %s", hostname, category)
        return {"inspection_error": category}
    except socket.timeout:
        logger.warning("TLS certificate inspection timed out for %s", hostname)
        return {"inspection_error": "inspection_timeout"}
    except socket.gaierror:
        logger.warning("DNS resolution failed during TLS certificate inspection for %s", hostname)
        return {"inspection_error": "inspection_dns_error"}
    except ssl.SSLError:
        logger.warning("TLS certificate inspection failed for %s", hostname)
        return {"inspection_error": "inspection_failed"}
    except OSError:
        logger.warning("Connection failed during TLS certificate inspection for %s", hostname)
        return {"inspection_error": "inspection_connection_error"}
    except Exception:
        logger.exception("Unexpected TLS certificate inspection error for %s", hostname)
        return {"inspection_error": "inspection_failed"}


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def run_scan(
    scan_id: str,
    user_id: str,
    target_url: str,
    target_domain: str,
) -> dict:
    """
    Execute a non-destructive security configuration scan.
    Returns a result dict with findings and metadata.
    """
    result: dict[str, Any] = {
        "scan_id": scan_id,
        "target_url": target_url,
        "target_domain": target_domain,
        "status": "failed",
        "error": None,
        "findings": [],
        "ssl_info": None,
        "response_status": None,
        "response_time_ms": None,
        "final_url": None,
        "headers_observed": {},
        "checks_skipped": [],
    }

    valid, validation_error, current_url, _ = validate_target_url(target_url)
    if not valid:
        result["error"] = f"Invalid target URL: {validation_error}"
        result["checks_skipped"].append("All checks — target URL validation failed")
        return result

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    session.headers.update({"User-Agent": SCANNER_UA})

    visited_urls = {_redirect_loop_key(current_url)}
    redirect_count = 0
    previous_origin = None
    start = time.monotonic()

    # ------------------------------------------------------------------
    # Phase 1: Fetch the target URL, validating each redirect before use
    # ------------------------------------------------------------------
    try:
        while True:
            origin = _url_origin(current_url)
            if previous_origin is not None and origin != previous_origin:
                _clear_cross_origin_credentials(session)

            resp = session.get(
                current_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
                verify=True,
                headers=dict(session.headers),
            )
            resp.raw.read(MAX_RESPONSE_BYTES)

            if resp.status_code not in REDIRECT_STATUSES:
                break

            location_value = resp.headers.get("Location")
            if not isinstance(location_value, str) or not location_value.strip():
                resp.close()
                result["error"] = "Redirect response did not include a valid Location header."
                result["checks_skipped"].append("All checks — invalid redirect destination")
                return result
            location = location_value.strip()

            if redirect_count >= MAX_REDIRECTS:
                resp.close()
                result["error"] = f"Too many redirects (limit: {MAX_REDIRECTS})."
                result["checks_skipped"].append("All checks — redirect limit exceeded")
                return result

            try:
                redirect_url = urllib.parse.urljoin(current_url, location)
            except ValueError:
                redirect_url = ""
            valid, validation_error, normalized_url, _ = validate_target_url(redirect_url)
            if not valid:
                resp.close()
                result["error"] = f"Redirect destination rejected: {validation_error}"
                result["checks_skipped"].append("All checks — redirect destination rejected")
                return result

            redirect_key = _redirect_loop_key(normalized_url)
            if redirect_key in visited_urls:
                resp.close()
                result["error"] = "Redirect loop detected."
                result["checks_skipped"].append("All checks — redirect loop detected")
                return result

            visited_urls.add(redirect_key)
            redirect_count += 1
            previous_origin = origin
            current_url = normalized_url
            resp.close()

        elapsed_ms = (time.monotonic() - start) * 1000

    except ReqSSLError as exc:
        category = _classify_tls_error(exc)
        result["error"] = {
            "certificate_expired": "TLS verification failed: the certificate is expired.",
            "hostname_mismatch": "TLS verification failed: certificate hostname mismatch.",
            "untrusted_certificate_chain": "TLS verification failed: the certificate chain is untrusted or invalid.",
            "certificate_verification_failed": "TLS certificate verification failed; the exact validation reason is unavailable.",
            "tls_handshake_failed": "TLS handshake or certificate verification failed; the exact cause could not be established.",
        }[category]
        result["findings"] = check_https(
            scan_id, user_id, target_domain, current_url, "https", None,
            tls_error_category=category,
        )
        result["checks_skipped"].append("HTTP checks — TLS verification prevented the request")
        return result
    except ReqTimeout:
        result["error"] = "Connection timed out. The target did not respond within the timeout period."
        result["checks_skipped"].append("All checks — connection timed out")
        return result
    except ReqConnectionError as exc:
        if any(isinstance(cause, socket.gaierror) for cause in _exception_chain(exc)):
            result["error"] = "DNS resolution failed while connecting to the target."
            result["checks_skipped"].append("All checks — DNS resolution failed")
            return result
        result["error"] = f"Connection failed: {exc}"
        result["checks_skipped"].append("All checks — connection failed")
        return result
    except TooManyRedirects:
        result["error"] = f"Too many redirects (limit: {MAX_REDIRECTS})."
        result["checks_skipped"].append("All checks — redirect loop detected")
        return result
    except Exception as exc:
        result["error"] = f"Unexpected error during request: {exc}"
        result["checks_skipped"].append("All checks — unexpected error")
        return result

    final_url = current_url

    result["response_status"] = resp.status_code
    result["response_time_ms"] = elapsed_ms
    result["final_url"] = final_url
    result["headers_observed"] = dict(resp.headers)

    scheme = urllib.parse.urlparse(final_url).scheme.lower()

    # ------------------------------------------------------------------
    # Phase 2: SSL certificate info (HTTPS only)
    # ------------------------------------------------------------------
    ssl_info = None
    if scheme == "https":
        port = urllib.parse.urlparse(final_url).port or 443
        final_hostname = urllib.parse.urlparse(final_url).hostname or target_domain
        ssl_info = _get_ssl_info(final_hostname, port)
        result["ssl_info"] = ssl_info

    # ------------------------------------------------------------------
    # Phase 3: Run security checks
    # ------------------------------------------------------------------
    findings: list[dict] = []

    # HTTPS
    findings.extend(check_https(scan_id, user_id, target_domain, final_url, scheme, ssl_info))
    if ssl_info and ssl_info.get("inspection_error"):
        result["checks_skipped"].append(
            "TLS certificate metadata — inspection could not be completed"
        )

    # Security headers
    findings.extend(check_security_headers(scan_id, user_id, target_domain, dict(resp.headers)))

    # CORS — probe with a harmless fake origin
    cors_probe_headers: dict | None = None
    try:
        probe_resp = session.get(
            final_url,
            timeout=REQUEST_TIMEOUT,
            headers={"Origin": "https://evil-securesight-probe.example.com"},
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        probe_resp.raw.read(1024)
        cors_probe_headers = dict(probe_resp.headers)
    except Exception:
        result["checks_skipped"].append("CORS probe — could not send probe request")

    findings.extend(check_cors(scan_id, user_id, target_domain, dict(resp.headers), cors_probe_headers))

    # Response info
    findings.extend(check_response_info(scan_id, user_id, target_domain, resp.status_code, elapsed_ms, final_url))

    result["findings"] = findings
    result["status"] = "completed"
    resp.close()
    return result
