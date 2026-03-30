"""Service monitoring control tests."""

import time

import psutil

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)

RISKY_SERVICES = {
    "telnetd": "Telnet daemon (plaintext protocol)",
    "rsh": "Remote shell (insecure)",
    "rlogin": "Remote login (insecure)",
    "finger": "Finger service (information disclosure)",
    "tftpd": "Trivial FTP (insecure)",
}


class ServiceMonitorTest(BaseControlTest):
    @property
    def name(self):
        return "Service Monitoring & Hardening"

    @property
    def category(self):
        return ControlCategory.SYSTEM

    @property
    def description(self):
        return "Monitors running services, checks for risky ones, and reviews resources."

    def run_tests(self):
        self._check_risky_services()
        self._check_listening_services()
        self._check_system_resources()
        self._check_uptime()
        return self.result

    def _check_risky_services(self):
        running = {p.info["name"].lower() for p in psutil.process_iter(["name"]) if p.info["name"]}
        found = []
        for svc, desc in RISKY_SERVICES.items():
            if svc in running:
                found.append(svc)
                self.add_finding(
                    title=f"Risky service running: {svc}",
                    description=f"{desc} is running.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation=f"Disable and remove {svc}.",
                    control_ref="SC-03",
                )
        if not found:
            self.add_finding(
                title="No risky services detected",
                description="None of the known risky services are running.",
                severity=Severity.INFO, status=ControlStatus.PASS,
                control_ref="SC-03",
            )

    def _check_listening_services(self):
        try:
            listening = [c for c in psutil.net_connections(kind="inet") if c.status == "LISTEN"]
            unique_ports = {c.laddr.port for c in listening}
            if len(unique_ports) > 20:
                self.add_finding(
                    title=f"High listening services count: {len(unique_ports)}",
                    description=f"Found {len(unique_ports)} unique listening ports.",
                    severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                    recommendation="Review and disable unnecessary services.",
                    control_ref="SC-04",
                )
            else:
                self.add_finding(
                    title=f"Listening services: {len(unique_ports)} ports",
                    description=f"Ports: {sorted(unique_ports)}",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="SC-04",
                )
        except psutil.AccessDenied:
            self.add_finding(
                title="Cannot enumerate network connections",
                description="Access denied checking listening ports.",
                severity=Severity.LOW, status=ControlStatus.WARNING,
                control_ref="SC-04",
            )

    def _check_system_resources(self):
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        self.add_finding(
            title=f"CPU usage: {cpu}%",
            description=f"CPU utilization at {cpu}%.",
            severity=Severity.HIGH if cpu > 90 else Severity.INFO,
            status=ControlStatus.WARNING if cpu > 90 else ControlStatus.PASS,
            control_ref="SC-05",
        )

        self.add_finding(
            title=f"Memory usage: {mem.percent}%",
            description=f"{mem.used // (1024**3)}GB / {mem.total // (1024**3)}GB",
            severity=Severity.HIGH if mem.percent > 90 else Severity.INFO,
            status=ControlStatus.WARNING if mem.percent > 90 else ControlStatus.PASS,
            control_ref="SC-06",
        )

        if disk.percent > 90:
            sev, status = Severity.CRITICAL, ControlStatus.FAIL
        elif disk.percent > 80:
            sev, status = Severity.MEDIUM, ControlStatus.WARNING
        else:
            sev, status = Severity.INFO, ControlStatus.PASS
        self.add_finding(
            title=f"Disk usage: {disk.percent}%",
            description=f"{disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB",
            severity=sev, status=status,
            control_ref="SC-07",
        )

    def _check_uptime(self):
        uptime_days = (time.time() - psutil.boot_time()) / 86400
        if uptime_days > 90:
            self.add_finding(
                title=f"System uptime: {int(uptime_days)} days (>90)",
                description="Long uptime may mean missed kernel patches.",
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                recommendation="Schedule a maintenance reboot.",
                control_ref="SC-08",
            )
        else:
            self.add_finding(
                title=f"System uptime: {int(uptime_days)} days",
                description="Within acceptable reboot window.",
                severity=Severity.INFO, status=ControlStatus.PASS,
                control_ref="SC-08",
            )
