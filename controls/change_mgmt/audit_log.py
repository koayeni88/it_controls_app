"""Audit logging control tests."""

import os
import platform
import subprocess

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class AuditLogTest(BaseControlTest):
    @property
    def name(self):
        return "Audit Log Assessment"

    @property
    def category(self):
        return ControlCategory.CHANGE_MGMT

    @property
    def description(self):
        return "Validates audit logging is enabled and properly configured."

    def run_tests(self):
        system = platform.system()
        if system == "Darwin":
            self._check_macos_audit()
        elif system == "Linux":
            self._check_linux_audit()
        self._check_log_permissions()
        return self.result

    def _check_macos_audit(self):
        audit_control = "/etc/security/audit_control"
        if os.path.exists(audit_control):
            self.add_finding(
                title="macOS audit framework is configured",
                description=f"Audit control file exists at {audit_control}.",
                severity=Severity.INFO, status=ControlStatus.PASS,
                control_ref="CM-01",
            )
        else:
            self.add_finding(
                title="macOS audit control file missing",
                description="No audit_control file found.",
                severity=Severity.HIGH, status=ControlStatus.FAIL,
                recommendation="Configure the macOS audit framework.",
                control_ref="CM-01",
            )

        try:
            result = subprocess.run(
                ["log", "show", "--last", "1m", "--predicate",
                 "subsystem == 'com.apple.securityd'"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                self.add_finding(
                    title="Unified logging is operational",
                    description="macOS unified logging is active.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CM-02",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding(
                title="Audit check tools unavailable",
                description="Cannot verify audit config.",
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CM-01",
            )

    def _check_linux_audit(self):
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True, text=True, timeout=10
            )
            if "active" in result.stdout.strip():
                self.add_finding(
                    title="auditd service is running",
                    description="Linux audit daemon is active.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CM-01",
                )
            else:
                self.add_finding(
                    title="auditd service is not running",
                    description="Linux audit daemon inactive.",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Enable: systemctl enable --now auditd",
                    control_ref="CM-01",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding(
                title="Cannot check auditd status",
                description="systemctl/auditd not available.",
                severity=Severity.HIGH, status=ControlStatus.WARNING,
                control_ref="CM-01",
            )

    def _check_log_permissions(self):
        log_dir = "/var/log"
        if os.path.exists(log_dir):
            try:
                mode = os.stat(log_dir).st_mode & 0o777
                if mode <= 0o755:
                    self.add_finding(
                        title=f"Log directory permissions correct: {log_dir}",
                        description=f"Permissions: {oct(mode)}",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="CM-03",
                    )
                else:
                    self.add_finding(
                        title=f"Log directory too permissive: {log_dir}",
                        description=f"Mode {oct(mode)} (should be 755 or stricter).",
                        severity=Severity.HIGH, status=ControlStatus.FAIL,
                        recommendation=f"chmod 755 {log_dir}",
                        control_ref="CM-03",
                    )
            except PermissionError:
                pass
