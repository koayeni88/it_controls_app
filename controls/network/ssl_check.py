"""SSL/TLS certificate verification control tests."""

import datetime
import socket
import ssl

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class SSLCertificateTest(BaseControlTest):
    def __init__(self, hosts=None):
        self.hosts = hosts or [("localhost", 443)]
        super().__init__()

    @property
    def name(self):
        return "SSL/TLS Certificate Validation"

    @property
    def category(self):
        return ControlCategory.NETWORK

    @property
    def description(self):
        return "Validates SSL/TLS certificates for expiration and security."

    def run_tests(self):
        for host, port in self.hosts:
            self._check_certificate(host, port)
        return self.result

    def _check_certificate(self, host, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    )
                    days_until_expiry = (not_after - datetime.datetime.now()).days

                    if days_until_expiry < 0:
                        self.add_finding(
                            title=f"SSL certificate expired: {host}:{port}",
                            description=f"Expired {abs(days_until_expiry)} days ago.",
                            severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                            recommendation="Renew the SSL certificate immediately.",
                            control_ref="NS-02",
                        )
                    elif days_until_expiry < 30:
                        self.add_finding(
                            title=f"SSL certificate expiring soon: {host}:{port}",
                            description=f"Expires in {days_until_expiry} days.",
                            severity=Severity.HIGH, status=ControlStatus.WARNING,
                            recommendation="Renew the SSL certificate.",
                            control_ref="NS-02",
                        )
                    else:
                        self.add_finding(
                            title=f"SSL certificate valid: {host}:{port}",
                            description=f"Valid for {days_until_expiry} more days.",
                            severity=Severity.INFO, status=ControlStatus.PASS,
                            control_ref="NS-02",
                        )
        except ssl.SSLCertVerificationError as e:
            self.add_finding(
                title=f"SSL verification failed: {host}:{port}",
                description=str(e),
                severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                recommendation="Fix the SSL certificate.",
                control_ref="NS-02",
            )
        except (ConnectionRefusedError, socket.timeout, OSError):
            self.add_finding(
                title=f"Cannot connect to {host}:{port}",
                description="Connection refused or timed out.",
                severity=Severity.INFO, status=ControlStatus.SKIPPED,
                control_ref="NS-02",
            )
