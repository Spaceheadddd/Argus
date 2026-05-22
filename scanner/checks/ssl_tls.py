from __future__ import annotations

import datetime
import socket
import ssl
from typing import List
from urllib.parse import urlparse

from scanner.core.models import Config, Finding, Severity
from scanner.core.requester import Requester
from scanner.utils.crawler import CrawlerData
from scanner.utils.payloads import WEAK_CIPHERS


class SSLCheck:
    NAME = "SSL/TLS"

    def __init__(self, requester: Requester, config: Config):
        self.requester = requester
        self.config = config

    def run(self, crawler_data: CrawlerData) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(crawler_data.base_url)

        if parsed.scheme != "https":
            findings.append(Finding(
                check_name=self.NAME,
                title="Site Not Using HTTPS",
                severity=Severity.CRITICAL,
                description="The target is served over plain HTTP. All traffic is unencrypted.",
                evidence=f"URL scheme: {parsed.scheme}",
                remediation="Migrate to HTTPS and redirect all HTTP traffic.",
                url=crawler_data.base_url,
                cwe="CWE-319",
                owasp="A02:2021",
            ))
            return findings

        hostname = parsed.hostname
        port = parsed.port or 443

        cert_findings = self._check_certificate(hostname, port, crawler_data.base_url)
        findings.extend(cert_findings)

        proto_findings = self._check_deprecated_protocols(hostname, port, crawler_data.base_url)
        findings.extend(proto_findings)

        return findings

    def _check_certificate(self, hostname: str, port: int, url: str) -> List[Finding]:
        findings = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher_name, proto_version, key_bits = ssock.cipher()
                    tls_version = ssock.version()

            # TLS version
            if tls_version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                findings.append(Finding(
                    check_name=self.NAME,
                    title=f"Deprecated TLS Version in Use: {tls_version}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The server negotiated {tls_version} which is deprecated and vulnerable "
                        "to known attacks (POODLE, BEAST, etc.)."
                    ),
                    evidence=f"Negotiated protocol: {tls_version}",
                    remediation="Disable TLS 1.0 and 1.1. Support TLS 1.2 minimum; prefer TLS 1.3.",
                    url=url, cwe="CWE-326", owasp="A02:2021",
                ))

            # Weak cipher
            for weak in WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    findings.append(Finding(
                        check_name=self.NAME,
                        title=f"Weak Cipher Suite in Use: {cipher_name}",
                        severity=Severity.HIGH,
                        description=f"The negotiated cipher '{cipher_name}' is considered weak.",
                        evidence=f"Cipher: {cipher_name}, Key bits: {key_bits}",
                        remediation="Configure strong cipher suites (AES-GCM, ChaCha20-Poly1305).",
                        url=url, cwe="CWE-327", owasp="A02:2021",
                    ))
                    break

            if key_bits and key_bits < 128:
                findings.append(Finding(
                    check_name=self.NAME,
                    title=f"Insufficient Key Length: {key_bits} bits",
                    severity=Severity.CRITICAL,
                    description=f"Cipher key length of {key_bits} bits is insufficient.",
                    evidence=f"Key bits: {key_bits}",
                    remediation="Use cipher suites with at least 128-bit keys.",
                    url=url, cwe="CWE-326", owasp="A02:2021",
                ))

            # Certificate expiry
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                try:
                    not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()
                    days_left = (not_after - now).days
                    if days_left < 0:
                        findings.append(Finding(
                            check_name=self.NAME,
                            title="SSL Certificate Has Expired",
                            severity=Severity.CRITICAL,
                            description=f"The certificate expired {abs(days_left)} days ago.",
                            evidence=f"Not After: {not_after_str}",
                            remediation="Renew the SSL certificate immediately.",
                            url=url, cwe="CWE-298", owasp="A02:2021",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            check_name=self.NAME,
                            title=f"SSL Certificate Expires Soon ({days_left} days)",
                            severity=Severity.HIGH,
                            description=f"Certificate expires in {days_left} days.",
                            evidence=f"Not After: {not_after_str}",
                            remediation="Renew the certificate before it expires.",
                            url=url, cwe="CWE-298", owasp="A02:2021",
                        ))
                except ValueError:
                    pass

            # Self-signed check
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            if subject == issuer:
                findings.append(Finding(
                    check_name=self.NAME,
                    title="Self-Signed Certificate Detected",
                    severity=Severity.HIGH,
                    description=(
                        "The certificate is self-signed. Browsers will show security warnings "
                        "and the certificate provides no CA-backed trust."
                    ),
                    evidence=f"Subject: {subject}, Issuer: {issuer}",
                    remediation="Obtain a certificate from a trusted CA (e.g. Let's Encrypt).",
                    url=url, cwe="CWE-295", owasp="A02:2021",
                ))

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                check_name=self.NAME,
                title="SSL Certificate Verification Failed",
                severity=Severity.CRITICAL,
                description=str(e),
                evidence=str(e),
                remediation="Fix the certificate chain and ensure it is valid for this hostname.",
                url=url, cwe="CWE-295", owasp="A02:2021",
            ))
        except Exception:
            pass

        return findings

    def _check_deprecated_protocols(self, hostname: str, port: int, url: str) -> List[Finding]:
        findings = []
        deprecated = [
            ("TLSv1", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
        ]
        for name, version_const in deprecated:
            if version_const is None:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version_const
                ctx.maximum_version = version_const
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname):
                        findings.append(Finding(
                            check_name=self.NAME,
                            title=f"Server Accepts Deprecated Protocol: {name}",
                            severity=Severity.HIGH,
                            description=(
                                f"The server accepts connections using {name}, "
                                "which is deprecated and vulnerable."
                            ),
                            evidence=f"Successfully connected using {name}",
                            remediation=f"Disable {name} in your server TLS configuration.",
                            url=url, cwe="CWE-326", owasp="A02:2021",
                        ))
            except Exception:
                pass
        return findings
