"""Port scanning control tests."""

import socket

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)

RISKY_PORTS = {
    21: ("FTP", Severity.HIGH, "FTP transmits credentials in plaintext."),
    23: ("Telnet", Severity.CRITICAL, "Telnet is unencrypted. Use SSH instead."),
    25: ("SMTP", Severity.MEDIUM, "Open SMTP relay can be exploited for spam."),
    445: ("SMB", Severity.HIGH, "SMB is a common attack vector."),
    1433: ("MSSQL", Severity.HIGH, "Database ports should not be exposed."),
    1521: ("Oracle DB", Severity.HIGH, "Database ports should not be exposed."),
    3306: ("MySQL", Severity.HIGH, "Database ports should not be exposed."),
    3389: ("RDP", Severity.CRITICAL, "RDP is a primary brute-force target."),
    5432: ("PostgreSQL", Severity.HIGH, "Database ports should not be exposed."),
    5900: ("VNC", Severity.HIGH, "VNC may lack proper encryption."),
    6379: ("Redis", Severity.CRITICAL, "Redis exposed without auth is critical."),
    27017: ("MongoDB", Severity.CRITICAL, "MongoDB exposed without auth is critical."),
}

STANDARD_PORTS = {
    22: ("SSH", Severity.INFO),
    80: ("HTTP", Severity.LOW),
    443: ("HTTPS", Severity.INFO),
    8080: ("HTTP-Alt", Severity.LOW),
    8443: ("HTTPS-Alt", Severity.INFO),
}


class PortScanTest(BaseControlTest):
    def __init__(self, target="127.0.0.1", ports=None, timeout=2):
        self.target = target
        self.ports = ports or list(RISKY_PORTS.keys()) + list(STANDARD_PORTS.keys()) + [
            53, 110, 135, 139, 143, 161, 389, 636, 993, 995, 5000, 8000, 8888, 9090
        ]
        self.timeout = timeout
        super().__init__()

    @property
    def name(self):
        return "Network Port Scan"

    @property
    def category(self):
        return ControlCategory.NETWORK

    @property
    def description(self):
        return f"Scans {self.target} for open ports and identifies risky services."

    def run_tests(self):
        open_ports = []
        for port in sorted(set(self.ports)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
                    if port in RISKY_PORTS:
                        service, severity, reason = RISKY_PORTS[port]
                        self.add_finding(
                            title=f"Risky port {port} ({service}) is open",
                            description=f"Port {port}/{service} on {self.target}: {reason}",
                            severity=severity, status=ControlStatus.FAIL,
                            recommendation=f"Close port {port} or restrict via firewall.",
                            control_ref="NS-01",
                        )
                    elif port in STANDARD_PORTS:
                        service, severity = STANDARD_PORTS[port]
                        self.add_finding(
                            title=f"Standard port {port} ({service}) is open",
                            description=f"Port {port}/{service} open on {self.target}.",
                            severity=severity, status=ControlStatus.PASS,
                            control_ref="NS-01",
                        )
                    else:
                        self.add_finding(
                            title=f"Non-standard port {port} is open",
                            description=f"Unknown service on port {port}.",
                            severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                            recommendation=f"Identify service on port {port}.",
                            control_ref="NS-01",
                        )
            except socket.error:
                pass

        risky = [p for p in open_ports if p in RISKY_PORTS]
        self.add_finding(
            title=f"Port scan summary: {len(open_ports)} open ports",
            description=f"Open: {open_ports}. Risky: {risky or 'None'}.",
            severity=Severity.INFO if not risky else Severity.HIGH,
            status=ControlStatus.PASS if not risky else ControlStatus.WARNING,
            control_ref="NS-01",
            evidence=f"Scanned {len(self.ports)} ports on {self.target}",
        )
        return self.result
