"""
tests/test_core.py — Automated tests for SecureSight AI core logic.

Tests are self-contained and use mocks for HTTP/network calls.
No real websites are contacted during testing.

Run with:
    python -m pytest tests/ -v
    python -m unittest tests/test_core.py -v
"""

import sys
import os
import json
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import streamlit

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Import modules under test
# ---------------------------------------------------------------------------
from scanner import (
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT,
    _is_restricted_ip,
    _get_ssl_info,
    _resolve_and_validate,
    run_scan,
    validate_target_url,
)
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import SSLError, Timeout
from security_checks import (
    check_security_headers,
    check_https,
    check_cors,
    SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
)
from risk_engine import (
    calculate_posture_score,
    count_by_severity,
    get_fix_first_recommendations,
    compare_scan_findings,
    get_posture_label,
)
from database import (
    init_db, create_user, authenticate_user, verify_password, hash_password,
    create_scan, complete_scan, get_scans_for_user, save_findings,
    get_findings_for_scan, update_finding_status, get_user_stats, DB_PATH,
)
from report_generator import generate_csv, generate_markdown, generate_html, _escape

import database as database_module
with (
    patch.object(database_module, "init_db"),
    patch.object(streamlit, "set_page_config"),
):
    import app as app_module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCAN_ID  = "test-scan-001"
USER_ID  = "test-user-001"
TARGET   = "example.com"


def _make_finding(sev="Medium", conf="High", status="open", check="Test Check",
                  title="Test Finding"):
    return {
        "id": f"f-{sev}-{conf}",
        "scan_id": SCAN_ID,
        "user_id": USER_ID,
        "check_name": check,
        "target": TARGET,
        "severity": sev,
        "confidence": conf,
        "title": title,
        "evidence": "test evidence",
        "explanation": "test explanation",
        "impact": "test impact",
        "recommendation": "test recommendation",
        "status": status,
        "created_at": "2024-01-01T00:00:00",
    }


# ---------------------------------------------------------------------------
# URL Validation tests
# ---------------------------------------------------------------------------

class TestURLValidation(unittest.TestCase):

    def test_valid_https_url(self):
        with patch("scanner._resolve_and_validate", return_value=(True, "ok")):
            valid, err, norm, host = validate_target_url("https://example.com")
        self.assertTrue(valid)
        self.assertEqual(err, "")
        self.assertEqual(host, "example.com")

    def test_adds_https_scheme(self):
        with patch("scanner._resolve_and_validate", return_value=(True, "ok")):
            valid, err, norm, host = validate_target_url("example.com")
        self.assertTrue(valid)
        self.assertIn("https://", norm)

    def test_rejects_empty_url(self):
        valid, err, norm, host = validate_target_url("")
        self.assertFalse(valid)
        self.assertNotEqual(err, "")

    def test_rejects_ftp_scheme(self):
        valid, err, norm, host = validate_target_url("ftp://example.com")
        self.assertFalse(valid)
        self.assertIn("HTTP", err.upper())

    def test_rejects_file_scheme(self):
        valid, err, norm, host = validate_target_url("file:///etc/passwd")
        self.assertFalse(valid)

    def test_rejects_embedded_credentials(self):
        with patch("scanner._resolve_and_validate", return_value=(True, "ok")):
            valid, err, norm, host = validate_target_url("https://user:pass@example.com")
        self.assertFalse(valid)
        self.assertIn("credential", err.lower())

    def test_rejects_localhost(self):
        valid, err, norm, host = validate_target_url("http://localhost/admin")
        self.assertFalse(valid)

    def test_rejects_loopback_ip(self):
        valid, err, norm, host = validate_target_url("http://127.0.0.1/")
        self.assertFalse(valid)

    def test_rejects_private_ip_192(self):
        valid, err, norm, host = validate_target_url("http://192.168.1.1/")
        self.assertFalse(valid)

    def test_rejects_private_ip_10(self):
        valid, err, norm, host = validate_target_url("http://10.0.0.1/")
        self.assertFalse(valid)

    def test_rejects_private_ip_172(self):
        valid, err, norm, host = validate_target_url("http://172.16.5.5/")
        self.assertFalse(valid)


# ---------------------------------------------------------------------------
# Restricted IP detection
# ---------------------------------------------------------------------------

class TestRestrictedIP(unittest.TestCase):

    def test_loopback(self):
        self.assertTrue(_is_restricted_ip("127.0.0.1"))
        self.assertTrue(_is_restricted_ip("::1"))

    def test_private_rfc1918(self):
        self.assertTrue(_is_restricted_ip("10.0.0.1"))
        self.assertTrue(_is_restricted_ip("192.168.100.200"))
        self.assertTrue(_is_restricted_ip("172.20.0.1"))

    def test_link_local(self):
        self.assertTrue(_is_restricted_ip("169.254.0.1"))

    def test_public_ip_not_restricted(self):
        self.assertFalse(_is_restricted_ip("93.184.216.34"))  # example.com
        self.assertFalse(_is_restricted_ip("8.8.8.8"))

    def test_invalid_ip_rejected(self):
        self.assertTrue(_is_restricted_ip("not-an-ip"))

    def test_reserved_and_non_global_addresses_are_restricted(self):
        self.assertTrue(_is_restricted_ip("2001:db8::1"))
        self.assertTrue(_is_restricted_ip("ff02::1"))
        self.assertTrue(_is_restricted_ip("224.0.0.1"))


class TestScannerRedirects(unittest.TestCase):

    def _response(self, status=200, url="https://example.com/", headers=None):
        response = MagicMock()
        response.status_code = status
        response.url = url
        response.headers = headers or {}
        response.raw.read.return_value = b""
        return response

    def _run_scan(self, responses, session_headers=None):
        session = MagicMock()
        session.headers = session_headers or {}
        session.get.side_effect = responses
        with (
            patch("scanner.requests.Session", return_value=session),
            patch(
                "scanner.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("93.184.216.34", 0))],
            ),
            patch("scanner._get_ssl_info", return_value=None),
        ):
            result = run_scan("scan-id", USER_ID, "https://example.com/", "example.com")
        return result, session

    def test_normal_request_disables_automatic_redirects_and_keeps_result_shape(self):
        final = self._response()
        probe = self._response()
        result, session = self._run_scan([final, probe])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["final_url"], "https://example.com/")
        self.assertEqual(result["response_status"], 200)
        self.assertTrue({
            "scan_id", "target_url", "target_domain", "status", "error",
            "findings", "ssl_info", "response_status", "response_time_ms",
            "final_url", "headers_observed", "checks_skipped",
        }.issubset(result))
        self.assertEqual(session.get.call_args_list[0].kwargs["allow_redirects"], False)
        self.assertEqual(session.get.call_args_list[0].kwargs["verify"], True)
        self.assertEqual(session.get.call_args_list[0].kwargs["timeout"], REQUEST_TIMEOUT)
        self.assertEqual(final.raw.read.call_args.args, (MAX_RESPONSE_BYTES,))

    def test_follows_permitted_absolute_redirect(self):
        first = self._response(
            302, headers={"Location": "https://other.example/path"},
        )
        final = self._response(200, "https://other.example/path")
        probe = self._response(200, "https://other.example/path")
        result, session = self._run_scan([first, final, probe])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            [call.args[0] for call in session.get.call_args_list],
            ["https://example.com/", "https://other.example/path",
             "https://other.example/path"],
        )
        self.assertEqual(first.raw.read.call_args.args, (MAX_RESPONSE_BYTES,))

    def test_follows_relative_redirect(self):
        first = self._response(302, headers={"Location": "/login"})
        final = self._response(200, "https://example.com/login")
        probe = self._response(200, "https://example.com/login")
        result, session = self._run_scan([first, final, probe])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            [call.args[0] for call in session.get.call_args_list],
            ["https://example.com/", "https://example.com/login",
             "https://example.com/login"],
        )

    def test_restricted_redirect_destinations_are_never_requested(self):
        destinations = [
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://169.254.0.1/",
            "http://[::1]/",
        ]
        for destination in destinations:
            with self.subTest(destination=destination):
                redirect = self._response(302, headers={"Location": destination})
                result, session = self._run_scan([redirect])

                self.assertEqual(result["status"], "failed")
                self.assertIn("rejected", result["error"].lower())
                self.assertEqual(session.get.call_count, 1)
                self.assertEqual(
                    session.get.call_args.args[0], "https://example.com/",
                )

    def test_unsupported_redirect_scheme_is_never_requested(self):
        redirect = self._response(302, headers={"Location": "file:///etc/passwd"})
        result, session = self._run_scan([redirect])

        self.assertEqual(result["status"], "failed")
        self.assertEqual(session.get.call_count, 1)

    def test_missing_or_malformed_redirect_destination_is_never_requested(self):
        for headers in ({}, {"Location": "https://[invalid"}):
            with self.subTest(headers=headers):
                redirect = self._response(302, headers=headers)
                result, session = self._run_scan([redirect])

                self.assertEqual(result["status"], "failed")
                self.assertEqual(session.get.call_count, 1)

    def test_rejects_invalid_port(self):
        redirect = self._response(
            302, headers={"Location": "https://other.example:99999/"},
        )
        result, session = self._run_scan([redirect])

        self.assertEqual(result["status"], "failed")
        self.assertEqual(session.get.call_count, 1)

    def test_detects_redirect_loop_before_repeating_request(self):
        redirect = self._response(
            302, headers={"Location": "https://example.com/"},
        )
        result, session = self._run_scan([redirect])

        self.assertEqual(result["status"], "failed")
        self.assertIn("loop", result["error"].lower())
        self.assertEqual(session.get.call_count, 1)

    def test_enforces_redirect_limit(self):
        responses = [
            self._response(
                302,
                url=f"https://host{index}.example/",
                headers={"Location": f"https://host{index + 1}.example/"},
            )
            for index in range(MAX_REDIRECTS + 1)
        ]
        result, session = self._run_scan(responses)

        self.assertEqual(result["status"], "failed")
        self.assertIn("Too many redirects", result["error"])
        self.assertEqual(session.get.call_count, MAX_REDIRECTS + 1)

    def test_timeout_while_following_redirect_is_reported(self):
        redirect = self._response(
            302, headers={"Location": "https://other.example/"},
        )
        result, session = self._run_scan([redirect, Timeout("timed out")])

        self.assertEqual(result["status"], "failed")
        self.assertIn("timed out", result["error"].lower())
        self.assertEqual(session.get.call_count, 2)
        self.assertEqual(session.get.call_args_list[1].kwargs["timeout"], REQUEST_TIMEOUT)

    def test_tls_verification_failure_is_reported(self):
        result, session = self._run_scan([SSLError("certificate verification failed")])

        self.assertEqual(result["status"], "failed")
        self.assertIn("TLS handshake or certificate verification failed", result["error"])
        self.assertEqual(
            result["findings"][0]["title"],
            "TLS handshake failed before certificate validity could be determined",
        )
        self.assertTrue(session.get.call_args.kwargs["verify"])
        self.assertEqual(session.get.call_count, 1)

    def test_sensitive_headers_and_cookies_are_dropped_across_origins(self):
        redirect = self._response(
            302, headers={"Location": "https://other.example/"},
        )
        final = self._response(200, "https://other.example/")
        probe = self._response(200, "https://other.example/")
        result, session = self._run_scan(
            [redirect, final, probe],
            {
                "Authorization": "sensitive",
                "Cookie": "sensitive",
                "Proxy-Authorization": "sensitive",
            },
        )

        self.assertEqual(result["status"], "completed")
        for call in session.get.call_args_list[1:]:
            headers = {key.lower(): value for key, value in call.kwargs["headers"].items()}
            self.assertNotIn("authorization", headers)
            self.assertNotIn("cookie", headers)
            self.assertNotIn("proxy-authorization", headers)
        session.cookies.clear.assert_called_once_with()
        self.assertIsNone(session.auth)


class TestTLSFailureReporting(unittest.TestCase):

    def _verification_error(self, code, message):
        outer = SSLError("certificate verification failed")
        cause = ssl.SSLCertVerificationError(message)
        cause.verify_code = code
        cause.verify_message = message
        outer.__cause__ = cause
        return outer

    def _run_tls_failure(self, error):
        session = MagicMock()
        session.get.side_effect = error
        with (
            patch("scanner.requests.Session", return_value=session),
            patch(
                "scanner.socket.getaddrinfo",
                return_value=[(2, 1, 6, "", ("93.184.216.34", 0))],
            ),
        ):
            result = run_scan("scan-id", USER_ID, "https://example.com/", "example.com")
        return result, session

    def test_valid_certificate_metadata_is_not_flagged(self):
        cert = {
            "notAfter": "Jan 01 00:00:00 2099 GMT",
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Test CA"),),),
            "subjectAltName": (("DNS", "example.com"),),
        }
        tls_socket = MagicMock()
        tls_socket.__enter__.return_value.getpeercert.return_value = cert
        context = MagicMock()
        context.wrap_socket.return_value = tls_socket
        connected_socket = MagicMock()

        with (
            patch("scanner._resolve_and_validate", return_value=(True, "ok")),
            patch("scanner.ssl.create_default_context", return_value=context) as default_context,
            patch("scanner.socket.create_connection", return_value=connected_socket),
        ):
            info = _get_ssl_info("example.com", 443)

        default_context.assert_called_once_with()
        context.wrap_socket.assert_called_once_with(
            connected_socket, server_hostname="example.com",
        )
        self.assertFalse(info["expired"])
        self.assertGreater(info["days_until_expiry"], 30)
        findings = check_https(
            SCAN_ID, USER_ID, TARGET, "https://example.com/", "https", info,
        )
        self.assertEqual(findings, [])

    def test_expired_certificate_requires_expiry_date_evidence(self):
        cert = {
            "notAfter": "Jan 01 00:00:00 2020 GMT",
            "notBefore": "Jan 01 00:00:00 2019 GMT",
            "subject": (),
            "issuer": (),
            "subjectAltName": (),
        }
        tls_socket = MagicMock()
        tls_socket.__enter__.return_value.getpeercert.return_value = cert
        context = MagicMock()
        context.wrap_socket.return_value = tls_socket
        with (
            patch("scanner._resolve_and_validate", return_value=(True, "ok")),
            patch("scanner.ssl.create_default_context", return_value=context),
            patch("scanner.socket.create_connection", return_value=MagicMock()),
        ):
            info = _get_ssl_info("example.com", 443)

        self.assertTrue(info["expired"])
        findings = check_https(
            SCAN_ID, USER_ID, TARGET, "https://example.com/", "https", info,
        )
        self.assertEqual(findings[0]["title"], "TLS certificate has expired")
        self.assertIn(info["not_after"], findings[0]["evidence"])

    def test_hostname_mismatch_is_reported_without_expiry_claim(self):
        result, session = self._run_tls_failure(
            self._verification_error(62, "hostname mismatch"),
        )

        self.assertEqual(result["status"], "failed")
        self.assertIn("hostname mismatch", result["error"].lower())
        self.assertEqual(
            [finding["title"] for finding in result["findings"]],
            ["TLS certificate hostname mismatch"],
        )
        self.assertNotIn("expired", result["findings"][0]["title"].lower())
        self.assertTrue(session.get.call_args.kwargs["verify"])
        self.assertTrue({
            "scan_id", "target_url", "target_domain", "status", "error",
            "findings", "ssl_info", "response_status", "response_time_ms",
            "final_url", "headers_observed", "checks_skipped",
        }.issubset(result))

    def test_untrusted_chain_is_reported_without_expiry_claim(self):
        result, _ = self._run_tls_failure(
            self._verification_error(20, "unable to get local issuer certificate"),
        )

        self.assertEqual(
            result["findings"][0]["title"],
            "TLS certificate chain is untrusted or invalid",
        )
        self.assertNotIn("expired", result["findings"][0]["title"].lower())

    def test_expired_verifier_code_reports_expiry(self):
        result, _ = self._run_tls_failure(
            self._verification_error(10, "certificate has expired"),
        )

        self.assertEqual(
            result["findings"][0]["title"],
            "TLS certificate has expired",
        )
        self.assertIn("verification code 10", result["findings"][0]["evidence"])

    def test_unknown_verification_error_is_not_mislabeled_as_expired(self):
        result, _ = self._run_tls_failure(
            self._verification_error(1, "unspecified certificate verification error"),
        )

        self.assertEqual(
            result["findings"][0]["title"],
            "TLS certificate verification failed",
        )
        self.assertNotIn("expired", result["findings"][0]["title"].lower())
        self.assertIn("exact validation reason is unavailable", result["error"])

    def test_unparseable_expiry_date_does_not_create_expiry_finding(self):
        cert = {"notAfter": "not a date", "notBefore": "", "subject": (), "issuer": ()}
        tls_socket = MagicMock()
        tls_socket.__enter__.return_value.getpeercert.return_value = cert
        context = MagicMock()
        context.wrap_socket.return_value = tls_socket
        with (
            patch("scanner._resolve_and_validate", return_value=(True, "ok")),
            patch("scanner.ssl.create_default_context", return_value=context),
            patch("scanner.socket.create_connection", return_value=MagicMock()),
        ):
            info = _get_ssl_info("example.com", 443)

        self.assertFalse(info["expired"])
        self.assertIsNone(info["days_until_expiry"])
        self.assertEqual(
            check_https(SCAN_ID, USER_ID, TARGET, "https://example.com/", "https", info),
            [],
        )

    def test_inspection_timeout_is_reported_and_reports_do_not_claim_expiry(self):
        with (
            patch("scanner._resolve_and_validate", return_value=(True, "ok")),
            patch("scanner.ssl.create_default_context", return_value=MagicMock()),
            patch("scanner.socket.create_connection", side_effect=socket.timeout),
        ):
            info = _get_ssl_info("example.com", 443)

        self.assertEqual(info["inspection_error"], "inspection_timeout")
        findings = check_https(
            SCAN_ID, USER_ID, TARGET, "https://example.com/", "https", info,
        )
        self.assertEqual(findings[0]["title"], "TLS certificate inspection timed out")
        self.assertIn("expiry was not established", findings[0]["explanation"])
        self.assertEqual(calculate_posture_score(findings), 100.0)

        scan = {"id": "scan-id", "target_url": "https://example.com"}
        markdown = generate_markdown(scan, findings, calculate_posture_score(findings))
        html_report = generate_html(scan, findings, calculate_posture_score(findings))
        self.assertIn("TLS certificate inspection timed out", markdown)
        self.assertIn("TLS certificate inspection timed out", html_report)
        self.assertNotIn("TLS certificate has expired", markdown)
        self.assertNotIn("TLS certificate has expired", html_report)

    def test_inspection_revalidates_target_before_connecting(self):
        with (
            patch(
                "scanner._resolve_and_validate",
                return_value=(False, "restricted target"),
            ),
            patch("scanner.socket.create_connection") as create_connection,
        ):
            info = _get_ssl_info("example.com", 443)

        self.assertEqual(info["inspection_error"], "inspection_target_rejected")
        create_connection.assert_not_called()

    def test_inspection_connection_error_is_not_reported_as_expiry(self):
        with (
            patch("scanner._resolve_and_validate", return_value=(True, "ok")),
            patch(
                "scanner.socket.create_connection",
                side_effect=ConnectionRefusedError("connection refused"),
            ),
        ):
            info = _get_ssl_info("example.com", 443)

        self.assertEqual(info["inspection_error"], "inspection_connection_error")
        findings = check_https(
            SCAN_ID, USER_ID, TARGET, "https://example.com/", "https", info,
        )
        self.assertEqual(findings[0]["title"], "TLS certificate inspection connection failed")
        self.assertNotIn("expired", findings[0]["title"].lower())

    def test_dns_connection_error_is_distinguished(self):
        error = RequestsConnectionError("connection failed")
        error.__cause__ = socket.gaierror("name resolution failed")
        result, _ = self._run_tls_failure(error)
        self.assertIn("DNS resolution failed", result["error"])
        self.assertEqual(result["findings"], [])


# ---------------------------------------------------------------------------
# Security header checks
# ---------------------------------------------------------------------------

class TestSecurityHeaders(unittest.TestCase):

    def _run(self, headers: dict) -> list:
        return check_security_headers(SCAN_ID, USER_ID, TARGET, headers)

    def test_all_missing(self):
        findings = self._run({})
        check_names = {f["check_name"] for f in findings}
        self.assertIn("HSTS Header", check_names)
        self.assertIn("Content Security Policy", check_names)
        self.assertIn("Clickjacking Protection", check_names)
        self.assertIn("X-Content-Type-Options Header", check_names)
        self.assertIn("Referrer Policy", check_names)
        self.assertIn("Permissions Policy", check_names)

    def test_no_findings_when_all_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        findings = self._run(headers)
        self.assertEqual(len(findings), 0)

    def test_weak_csp_detected(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'",
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        findings = self._run(headers)
        csp_findings = [f for f in findings if f["check_name"] == "Content Security Policy"]
        self.assertTrue(len(csp_findings) > 0)
        self.assertIn("unsafe", csp_findings[0]["evidence"].lower())

    def test_hsts_missing_severity(self):
        findings = self._run({})
        hsts = [f for f in findings if f["check_name"] == "HSTS Header"]
        self.assertEqual(len(hsts), 1)
        self.assertEqual(hsts[0]["severity"], SEVERITY_MEDIUM)

    def test_header_case_insensitive(self):
        """Headers should be matched regardless of case."""
        headers = {
            "strict-transport-security": "max-age=63072000",
            "CONTENT-SECURITY-POLICY": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        findings = self._run(headers)
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# HTTPS checks
# ---------------------------------------------------------------------------

class TestHTTPSChecks(unittest.TestCase):

    def test_http_site_flagged(self):
        findings = check_https(SCAN_ID, USER_ID, TARGET, "http://example.com", "http", None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], SEVERITY_HIGH)

    def test_https_no_ssl_issues(self):
        ssl_info = {"expired": False, "days_until_expiry": 90, "not_after": "Jan 01 00:00:00 2099 GMT"}
        findings = check_https(SCAN_ID, USER_ID, TARGET, "https://example.com", "https", ssl_info)
        self.assertEqual(len(findings), 0)

    def test_expired_cert_flagged(self):
        ssl_info = {"expired": True, "days_until_expiry": -5, "not_after": "Jan 01 00:00:00 2020 GMT"}
        findings = check_https(SCAN_ID, USER_ID, TARGET, "https://example.com", "https", ssl_info)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], SEVERITY_HIGH)

    def test_expiring_soon_medium(self):
        ssl_info = {"expired": False, "days_until_expiry": 10, "not_after": "Feb 01 00:00:00 2024 GMT"}
        findings = check_https(SCAN_ID, USER_ID, TARGET, "https://example.com", "https", ssl_info)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], SEVERITY_MEDIUM)


# ---------------------------------------------------------------------------
# CORS checks
# ---------------------------------------------------------------------------

class TestCORSChecks(unittest.TestCase):

    def test_wildcard_without_credentials(self):
        headers = {"Access-Control-Allow-Origin": "*"}
        findings = check_cors(SCAN_ID, USER_ID, TARGET, headers, None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], SEVERITY_LOW)

    def test_wildcard_with_credentials_high(self):
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        findings = check_cors(SCAN_ID, USER_ID, TARGET, headers, None)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], SEVERITY_HIGH)

    def test_no_cors_headers_no_finding(self):
        findings = check_cors(SCAN_ID, USER_ID, TARGET, {}, None)
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

class TestRiskScoring(unittest.TestCase):

    def test_no_findings_score_100(self):
        score = calculate_posture_score([])
        self.assertEqual(score, 100.0)

    def test_high_finding_reduces_score(self):
        findings = [_make_finding(sev="High", conf="High")]
        score = calculate_posture_score(findings)
        self.assertLess(score, 100.0)
        self.assertGreaterEqual(score, 0.0)

    def test_resolved_finding_not_penalized(self):
        findings = [_make_finding(sev="High", conf="High", status="resolved")]
        score = calculate_posture_score(findings)
        self.assertEqual(score, 100.0)

    def test_critical_lower_than_medium(self):
        critical_findings = [_make_finding(sev="Critical", conf="High")]
        medium_findings = [_make_finding(sev="Medium", conf="High")]
        score_c = calculate_posture_score(critical_findings)
        score_m = calculate_posture_score(medium_findings)
        self.assertLess(score_c, score_m)

    def test_score_never_below_zero(self):
        many_findings = [_make_finding(sev="Critical", conf="High") for _ in range(20)]
        for i, f in enumerate(many_findings):
            f["id"] = f"f-{i}"
        score = calculate_posture_score(many_findings)
        self.assertGreaterEqual(score, 0.0)

    def test_count_by_severity(self):
        findings = [
            _make_finding(sev="High"), _make_finding(sev="Medium"),
            _make_finding(sev="Medium"), _make_finding(sev="Low"),
        ]
        counts = count_by_severity(findings)
        self.assertEqual(counts["High"], 1)
        self.assertEqual(counts["Medium"], 2)
        self.assertEqual(counts["Low"], 1)
        self.assertEqual(counts["Critical"], 0)

    def test_posture_label_good(self):
        label, color = get_posture_label(85.0)
        self.assertEqual(label, "Good")

    def test_posture_label_critical(self):
        label, color = get_posture_label(10.0)
        self.assertEqual(label, "Critical")


# ---------------------------------------------------------------------------
# Fix-First recommendations
# ---------------------------------------------------------------------------

class TestFixFirst(unittest.TestCase):

    def test_empty_findings_no_recs(self):
        recs = get_fix_first_recommendations([])
        self.assertEqual(recs, [])

    def test_informational_excluded(self):
        findings = [_make_finding(sev="Informational")]
        recs = get_fix_first_recommendations(findings)
        self.assertEqual(recs, [])

    def test_resolved_excluded(self):
        findings = [_make_finding(sev="High", status="resolved")]
        recs = get_fix_first_recommendations(findings)
        self.assertEqual(recs, [])

    def test_high_before_low(self):
        findings = [
            _make_finding(sev="Low", conf="High", title="Low Finding"),
            _make_finding(sev="High", conf="High", title="High Finding"),
        ]
        findings[0]["id"] = "f-low"
        findings[1]["id"] = "f-high"
        recs = get_fix_first_recommendations(findings)
        self.assertEqual(recs[0]["title"], "High Finding")

    def test_top_n_respected(self):
        findings = [_make_finding(sev="Medium") for _ in range(10)]
        for i, f in enumerate(findings):
            f["id"] = f"f-{i}"
        recs = get_fix_first_recommendations(findings, top_n=3)
        self.assertLessEqual(len(recs), 3)


# ---------------------------------------------------------------------------
# Scan comparison
# ---------------------------------------------------------------------------

class TestScanComparison(unittest.TestCase):

    def test_new_finding_detected(self):
        a = [_make_finding(title="Old Finding")]
        b = [_make_finding(title="Old Finding"), _make_finding(title="New Finding")]
        b[1]["check_name"] = "New Check"
        result = compare_scan_findings(a, b)
        new_titles = [f["title"] for f in result["new_findings"]]
        self.assertIn("New Finding", new_titles)

    def test_persistent_finding(self):
        a = [_make_finding(title="Persisting")]
        b = [_make_finding(title="Persisting")]
        result = compare_scan_findings(a, b)
        self.assertEqual(len(result["persistent_findings"]), 1)

    def test_not_in_b_not_auto_resolved(self):
        a = [_make_finding(title="Old Only")]
        b = []
        result = compare_scan_findings(a, b)
        self.assertEqual(len(result["not_detected_in_b"]), 1)
        # Should NOT appear in resolved
        self.assertEqual(len(result["resolved_findings"]), 0)

    def test_empty_both(self):
        result = compare_scan_findings([], [])
        self.assertEqual(result["new_findings"], [])
        self.assertEqual(result["persistent_findings"], [])


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing(unittest.TestCase):

    def test_hash_and_verify(self):
        pw = "SecurePassword123!"
        h = hash_password(pw)
        self.assertTrue(verify_password(pw, h))

    def test_wrong_password_fails(self):
        h = hash_password("correct-password")
        self.assertFalse(verify_password("wrong-password", h))

    def test_different_hashes_same_password(self):
        """Each hash uses a unique salt — hashes should differ."""
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        self.assertNotEqual(h1, h2)

    def test_empty_password_hashes(self):
        h = hash_password("")
        self.assertTrue(verify_password("", h))
        self.assertFalse(verify_password("x", h))

    def test_malformed_hash_returns_false(self):
        self.assertFalse(verify_password("any", "not-a-valid-hash"))


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class TestDatabase(unittest.TestCase):

    def setUp(self):
        """Use a temporary database for each test."""
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        import database as db_module
        self._original_db = db_module.DB_PATH
        db_module.DB_PATH = self.tmp.name
        init_db()

    def tearDown(self):
        import database as db_module
        db_module.DB_PATH = self._original_db
        # On Windows, SQLite keeps the file open briefly; retry deletion
        import time as _time
        for _ in range(5):
            try:
                os.unlink(self.tmp.name)
                break
            except PermissionError:
                _time.sleep(0.1)

    def test_create_user(self):
        user = create_user("test@example.com", "Test User", "password123")
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], "test@example.com")

    def test_duplicate_user_returns_none(self):
        create_user("dup@example.com", "Dup", "pass123")
        result = create_user("dup@example.com", "Dup2", "pass456")
        self.assertIsNone(result)

    def test_authenticate_valid(self):
        create_user("auth@example.com", "Auth User", "mypassword")
        user = authenticate_user("auth@example.com", "mypassword")
        self.assertIsNotNone(user)
        self.assertEqual(user["display_name"], "Auth User")

    def test_authenticate_wrong_password(self):
        create_user("auth2@example.com", "Auth2", "correct")
        result = authenticate_user("auth2@example.com", "wrong")
        self.assertIsNone(result)

    def test_user_data_isolation(self):
        """User A cannot see User B's scans."""
        user_a = create_user("a@example.com", "User A", "pass")
        user_b = create_user("b@example.com", "User B", "pass")
        scan_id = create_scan(user_a["id"], "https://example.com", "example.com")
        complete_scan(scan_id, 75.0, 2)
        scans_a = get_scans_for_user(user_a["id"])
        scans_b = get_scans_for_user(user_b["id"])
        self.assertEqual(len(scans_a), 1)
        self.assertEqual(len(scans_b), 0)

    def test_findings_associated_with_user(self):
        user = create_user("f@example.com", "F User", "pass")
        uid = user["id"]
        scan_id = create_scan(uid, "https://example.com", "example.com")
        findings = [_make_finding()]
        for f in findings:
            f["scan_id"] = scan_id
            f["user_id"] = uid
        save_findings(findings)
        retrieved = get_findings_for_scan(scan_id, uid)
        self.assertEqual(len(retrieved), 1)

    def test_update_finding_status(self):
        user = create_user("s@example.com", "S User", "pass")
        uid = user["id"]
        scan_id = create_scan(uid, "https://example.com", "example.com")
        f = _make_finding()
        f["scan_id"] = scan_id
        f["user_id"] = uid
        f["id"] = "test-finding-status"
        save_findings([f])
        result = update_finding_status("test-finding-status", uid, "resolved", "Fixed it")
        self.assertTrue(result)
        retrieved = get_findings_for_scan(scan_id, uid)
        self.assertEqual(retrieved[0]["status"], "resolved")

    def test_user_stats_empty(self):
        user = create_user("stats@example.com", "Stats User", "pass")
        stats = get_user_stats(user["id"])
        self.assertEqual(stats["total_scans"], 0)
        self.assertEqual(stats["open_findings"], 0)
        self.assertIsNone(stats["latest_score"])


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

class TestDashboardHtmlEscaping(unittest.TestCase):

    SCRIPT_PAYLOAD = "<script>alert(1)</script>"
    IMAGE_PAYLOAD = '<img src=x onerror="alert(1)">'

    def _assert_rendered_as_text(self, rendered, payload):
        self.assertNotIn(payload, rendered)
        self.assertIn(app_module._html_text(payload), rendered)

    def test_account_names_and_email_are_escaped_in_sidebar_and_settings(self):
        sidebar_html = app_module._sidebar_identity_html(
            self.SCRIPT_PAYLOAD, self.IMAGE_PAYLOAD,
        )
        profile_html = app_module._account_profile_text_html({
            "display_name": self.SCRIPT_PAYLOAD,
            "email": self.IMAGE_PAYLOAD,
            "created_at": "2026-10-22",
        })

        self._assert_rendered_as_text(sidebar_html, self.SCRIPT_PAYLOAD)
        self._assert_rendered_as_text(sidebar_html, self.IMAGE_PAYLOAD)
        self._assert_rendered_as_text(profile_html, self.SCRIPT_PAYLOAD)
        self._assert_rendered_as_text(profile_html, self.IMAGE_PAYLOAD)

    def test_scan_evidence_and_finding_fields_are_escaped(self):
        finding = {
            "check_name": self.IMAGE_PAYLOAD,
            "confidence": self.SCRIPT_PAYLOAD,
            "evidence": self.IMAGE_PAYLOAD,
            "explanation": self.SCRIPT_PAYLOAD,
            "impact": self.IMAGE_PAYLOAD,
            "recommendation": self.SCRIPT_PAYLOAD,
        }

        detail_html = app_module._finding_details_html(finding)
        evidence_html = app_module._finding_evidence_html(self.IMAGE_PAYLOAD)

        self._assert_rendered_as_text(detail_html, self.SCRIPT_PAYLOAD)
        self._assert_rendered_as_text(detail_html, self.IMAGE_PAYLOAD)
        self._assert_rendered_as_text(evidence_html, self.IMAGE_PAYLOAD)

    def test_reusable_html_components_escape_labels_and_values(self):
        card_html = app_module.metric_card(self.SCRIPT_PAYLOAD, self.IMAGE_PAYLOAD)
        badge_html = app_module.severity_badge(self.IMAGE_PAYLOAD)
        expander_label = app_module.severity_expander_label(
            "High", self.SCRIPT_PAYLOAD,
        )

        self._assert_rendered_as_text(card_html, self.SCRIPT_PAYLOAD)
        self._assert_rendered_as_text(card_html, self.IMAGE_PAYLOAD)
        self._assert_rendered_as_text(badge_html, self.IMAGE_PAYLOAD)
        self._assert_rendered_as_text(expander_label, self.SCRIPT_PAYLOAD)

    def test_page_header_escapes_dynamic_text(self):
        with patch.object(app_module.st, "markdown") as markdown:
            app_module.page_header(self.SCRIPT_PAYLOAD, self.IMAGE_PAYLOAD)

        rendered = markdown.call_args.args[0]
        self._assert_rendered_as_text(rendered, self.SCRIPT_PAYLOAD)
        self._assert_rendered_as_text(rendered, self.IMAGE_PAYLOAD)


class TestDashboardTheme(unittest.TestCase):

    def test_streamlit_dropdown_styles_preserve_contrast_and_focus(self):
        with patch.object(app_module.st, "markdown") as markdown:
            app_module.inject_css()

        styles = markdown.call_args.args[0]
        self.assertIn('[data-baseweb="popover"] [role="option"]', styles)
        self.assertIn('[data-testid="stSelectboxVirtualDropdown"] [role="option"]', styles)
        self.assertIn('[data-baseweb="popover"] [role="option"]:focus-visible', styles)
        self.assertIn('[data-testid="stSelectbox"] [data-baseweb="select"]:focus-within', styles)
        self.assertIn("color: #F5FFF8 !important;", styles)
        self.assertIn("background-color: #103626 !important;", styles)
        self.assertNotIn('[data-baseweb="select"] *', styles)


class TestReportGeneration(unittest.TestCase):

    def _sample_scan(self):
        return {
            "id": "rpt-scan-001",
            "user_id": USER_ID,
            "target_url": "https://example.com",
            "target_domain": "example.com",
            "started_at": "2024-01-01T10:00:00",
            "completed_at": "2024-01-01T10:00:05",
            "status": "completed",
            "posture_score": 55.0,
        }

    def test_csv_has_headers(self):
        findings = [_make_finding()]
        csv_out = generate_csv(findings)
        self.assertIn("severity", csv_out)
        self.assertIn("title", csv_out)

    def test_csv_includes_finding(self):
        findings = [_make_finding(title="XSS Risk")]
        csv_out = generate_csv(findings)
        self.assertIn("XSS Risk", csv_out)

    def test_markdown_contains_score(self):
        findings = [_make_finding()]
        md = generate_markdown(self._sample_scan(), findings, 55.0)
        self.assertIn("55", md)
        self.assertIn("SecureSight AI", md)

    def test_html_escapes_xss(self):
        """Untrusted content must be HTML-escaped in the report."""
        self.assertEqual(_escape("<script>alert(1)</script>"),
                         "&lt;script&gt;alert(1)&lt;/script&gt;")

    def test_html_report_contains_target(self):
        findings = [_make_finding()]
        html_out = generate_html(self._sample_scan(), findings, 55.0)
        self.assertIn("example.com", html_out)
        self.assertIn("SecureSight", html_out)
        self.assertNotIn("<script>", html_out)  # No script tags in report


if __name__ == "__main__":
    unittest.main(verbosity=2)
