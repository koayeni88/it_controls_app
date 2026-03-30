"""Encryption control tests."""

import os
import platform
import subprocess

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class EncryptionTest(BaseControlTest):
    @property
    def name(self):
        return "Encryption Verification"

    @property
    def category(self):
        return ControlCategory.DATA

    @property
    def description(self):
        return "Validates disk encryption and data-at-rest protection."

    def run_tests(self):
        system = platform.system()
        if system == "Darwin":
            self._check_filevault()
        elif system == "Linux":
            self._check_luks()
        self._check_sensitive_file_permissions()
        return self.result

    def _check_filevault(self):
        try:
            result = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout.strip()
            if "On" in output:
                self.add_finding(
                    title="FileVault disk encryption is enabled",
                    description=output,
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="DP-03",
                )
            elif "Off" in output:
                self.add_finding(
                    title="FileVault disk encryption is disabled",
                    description="Full-disk encryption is not enabled.",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Enable FileVault in Security & Privacy.",
                    control_ref="DP-03",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            self.add_finding(
                title="Cannot check FileVault status",
                description="fdesetup unavailable or insufficient permissions.",
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="DP-03",
            )

    def _check_luks(self):
        try:
            result = subprocess.run(
                ["lsblk", "-o", "NAME,FSTYPE,MOUNTPOINT"],
                capture_output=True, text=True, timeout=10
            )
            if "crypto_LUKS" in result.stdout:
                self.add_finding(
                    title="LUKS disk encryption detected",
                    description="LUKS-encrypted partition(s) found.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="DP-03",
                )
            else:
                self.add_finding(
                    title="No LUKS encryption detected",
                    description="No LUKS-encrypted partitions found.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Consider LUKS encryption for data at rest.",
                    control_ref="DP-03",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding(
                title="Cannot check disk encryption",
                description="lsblk not available.",
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="DP-03",
            )

    def _check_sensitive_file_permissions(self):
        sensitive_files = {
            "/etc/shadow": 0o640,
            "/etc/gshadow": 0o640,
            os.path.expanduser("~/.ssh/id_rsa"): 0o600,
            os.path.expanduser("~/.ssh/id_ed25519"): 0o600,
        }
        checked = 0
        for filepath, max_mode in sensitive_files.items():
            if os.path.exists(filepath):
                checked += 1
                try:
                    mode = os.stat(filepath).st_mode & 0o777
                    if mode <= max_mode:
                        self.add_finding(
                            title=f"Permissions correct: {filepath}",
                            description=f"Mode {oct(mode)}",
                            severity=Severity.INFO, status=ControlStatus.PASS,
                            control_ref="DP-04",
                        )
                    else:
                        self.add_finding(
                            title=f"Excessive permissions: {filepath}",
                            description=f"Mode {oct(mode)} (should be {oct(max_mode)} or stricter).",
                            severity=Severity.HIGH, status=ControlStatus.FAIL,
                            recommendation=f"chmod {oct(max_mode)[2:]} {filepath}",
                            control_ref="DP-04",
                        )
                except PermissionError:
                    pass
        if checked == 0:
            self.add_finding(
                title="No sensitive files found to check",
                description="Common sensitive files not present.",
                severity=Severity.INFO, status=ControlStatus.SKIPPED,
                control_ref="DP-04",
            )
