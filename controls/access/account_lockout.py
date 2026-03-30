"""Account lockout and session control tests."""

import os
import platform
import subprocess

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class AccountLockoutTest(BaseControlTest):
    @property
    def name(self):
        return "Account Lockout & Session Controls"

    @property
    def category(self):
        return ControlCategory.ACCESS

    @property
    def description(self):
        return "Validates account lockout thresholds and session timeout configurations."

    def run_tests(self):
        system = platform.system()
        if system == "Darwin":
            self._test_macos_lockout()
        elif system == "Linux":
            self._test_linux_lockout()
        self._check_ssh_session_timeout()
        return self.result

    def _test_macos_lockout(self):
        try:
            result = subprocess.run(
                ["pwpolicy", "getaccountpolicies"],
                capture_output=True, text=True, timeout=10
            )
            policy = result.stdout + result.stderr
            if "policyAttributeMaximumFailedAuthentications" in policy:
                self.add_finding(
                    title="Account lockout policy is configured",
                    description="Maximum failed authentication threshold detected.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="AC-10",
                )
            else:
                self.add_finding(
                    title="No account lockout policy detected",
                    description="No maximum failed authentication threshold configured.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Configure account lockout after 5 failed attempts.",
                    control_ref="AC-10",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.add_finding(
                title="Cannot check account lockout policy",
                description=str(e),
                severity=Severity.MEDIUM, status=ControlStatus.ERROR,
                control_ref="AC-10",
            )

    def _test_linux_lockout(self):
        pam_files = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                with open(pam_file, "r") as f:
                    content = f.read()
                if "pam_faillock" in content or "pam_tally2" in content:
                    self.add_finding(
                        title="Account lockout module is configured",
                        description=f"PAM lockout module found in {pam_file}.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-10",
                    )
                else:
                    self.add_finding(
                        title="No account lockout module in PAM",
                        description=f"No pam_faillock/pam_tally2 found in {pam_file}.",
                        severity=Severity.HIGH, status=ControlStatus.FAIL,
                        recommendation="Enable pam_faillock in PAM configuration.",
                        control_ref="AC-10",
                    )
                return

    def _check_ssh_session_timeout(self):
        ssh_config = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config):
            try:
                with open(ssh_config, "r") as f:
                    content = f.read()
                if "ClientAliveInterval" in content:
                    self.add_finding(
                        title="SSH session timeout is configured",
                        description="ClientAliveInterval is set.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-11",
                    )
                else:
                    self.add_finding(
                        title="SSH session timeout not configured",
                        description="ClientAliveInterval not found.",
                        severity=Severity.MEDIUM, status=ControlStatus.FAIL,
                        recommendation="Set ClientAliveInterval to 300.",
                        control_ref="AC-11",
                    )
            except PermissionError:
                self.add_finding(
                    title="Cannot read SSH config",
                    description="Insufficient permissions.",
                    severity=Severity.LOW, status=ControlStatus.WARNING,
                    control_ref="AC-11",
                )
