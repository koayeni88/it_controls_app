"""Password policy control tests."""

import os
import platform
import re
import subprocess

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class PasswordPolicyTest(BaseControlTest):
    @property
    def name(self):
        return "Password Policy Assessment"

    @property
    def category(self):
        return ControlCategory.ACCESS

    @property
    def description(self):
        return "Validates password complexity, age, history, and lockout policies."

    def run_tests(self):
        system = platform.system()
        if system == "Darwin":
            self._test_macos_password_policy()
        elif system == "Linux":
            self._test_linux_password_policy()
        else:
            self.add_finding(
                title="Unsupported OS for password policy check",
                description=f"OS '{system}' is not currently supported.",
                severity=Severity.INFO, status=ControlStatus.SKIPPED,
            )
        return self.result

    def _test_macos_password_policy(self):
        try:
            output = subprocess.run(
                ["pwpolicy", "getaccountpolicies"],
                capture_output=True, text=True, timeout=10
            )
            policy_text = output.stdout + output.stderr

            if "minLength" in policy_text or "policyAttributePassword" in policy_text:
                self.add_finding(
                    title="Password minimum length policy exists",
                    description="A password minimum length policy is configured.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="AC-01",
                    evidence=f"Policy check on {platform.node()}",
                )
            else:
                self.add_finding(
                    title="No password complexity policy detected",
                    description="No explicit password complexity policy found.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Configure password complexity via MDM or System Preferences.",
                    control_ref="AC-01",
                )

            idle_result = subprocess.run(
                ["defaults", "read", "com.apple.screensaver", "idleTime"],
                capture_output=True, text=True, timeout=10
            )
            if idle_result.returncode == 0:
                idle_time = int(idle_result.stdout.strip()) if idle_result.stdout.strip().isdigit() else 0
                if idle_time <= 900:
                    self.add_finding(
                        title="Screen lock idle timeout is appropriate",
                        description=f"Idle lock set to {idle_time} seconds.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-02", evidence=f"idleTime={idle_time}",
                    )
                else:
                    self.add_finding(
                        title="Screen lock idle timeout too long",
                        description=f"Idle lock is {idle_time}s (>900s recommended max).",
                        severity=Severity.MEDIUM, status=ControlStatus.FAIL,
                        recommendation="Set screen lock idle time to 15 minutes or less.",
                        control_ref="AC-02",
                    )
            else:
                self.add_finding(
                    title="Cannot determine screen lock settings",
                    description="Screensaver idle time setting not found.",
                    severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                    recommendation="Verify screen lock is configured via MDM.",
                    control_ref="AC-02",
                )

        except subprocess.TimeoutExpired:
            self.add_finding(
                title="Password policy check timed out",
                description="The command did not respond in time.",
                severity=Severity.MEDIUM, status=ControlStatus.ERROR,
            )
        except FileNotFoundError:
            self.add_finding(
                title="Password policy tool not available",
                description="pwpolicy command not found.",
                severity=Severity.MEDIUM, status=ControlStatus.SKIPPED,
            )

    def _test_linux_password_policy(self):
        try:
            with open("/etc/login.defs", "r") as f:
                login_defs = f.read()

            max_days_match = re.search(r"^PASS_MAX_DAYS\s+(\d+)", login_defs, re.MULTILINE)
            if max_days_match:
                max_days = int(max_days_match.group(1))
                if max_days <= 90:
                    self.add_finding(
                        title="Password maximum age is compliant",
                        description=f"PASS_MAX_DAYS is set to {max_days} days.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-03", evidence=f"PASS_MAX_DAYS={max_days}",
                    )
                else:
                    self.add_finding(
                        title="Password maximum age exceeds 90 days",
                        description=f"PASS_MAX_DAYS is {max_days} (recommended: <=90).",
                        severity=Severity.HIGH, status=ControlStatus.FAIL,
                        recommendation="Set PASS_MAX_DAYS to 90 or less.",
                        control_ref="AC-03",
                    )

            min_len_match = re.search(r"^PASS_MIN_LEN\s+(\d+)", login_defs, re.MULTILINE)
            if min_len_match:
                min_len = int(min_len_match.group(1))
                if min_len >= 12:
                    self.add_finding(
                        title="Password minimum length is compliant",
                        description=f"PASS_MIN_LEN is set to {min_len}.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-04",
                    )
                else:
                    self.add_finding(
                        title="Password minimum length is too short",
                        description=f"PASS_MIN_LEN is {min_len} (recommended: >=12).",
                        severity=Severity.HIGH, status=ControlStatus.FAIL,
                        recommendation="Set PASS_MIN_LEN to 12 or greater.",
                        control_ref="AC-04",
                    )

        except FileNotFoundError:
            self.add_finding(
                title="/etc/login.defs not found",
                description="Cannot check password policy.",
                severity=Severity.HIGH, status=ControlStatus.ERROR,
            )

        pam_paths = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]
        for pam_path in pam_paths:
            if os.path.exists(pam_path):
                with open(pam_path, "r") as f:
                    pam_content = f.read()
                if "pam_pwquality" in pam_content or "pam_cracklib" in pam_content:
                    self.add_finding(
                        title="Password complexity module is enabled",
                        description=f"PAM quality module found in {pam_path}.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-05",
                    )
                else:
                    self.add_finding(
                        title="No password complexity module in PAM",
                        description=f"pam_pwquality/pam_cracklib not found in {pam_path}.",
                        severity=Severity.HIGH, status=ControlStatus.FAIL,
                        recommendation="Enable pam_pwquality in PAM configuration.",
                        control_ref="AC-05",
                    )
                break
