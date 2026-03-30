"""Firewall configuration control tests."""

import platform
import subprocess

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class FirewallTest(BaseControlTest):
    @property
    def name(self):
        return "Firewall Configuration Check"

    @property
    def category(self):
        return ControlCategory.NETWORK

    @property
    def description(self):
        return "Validates that the host firewall is enabled and properly configured."

    def run_tests(self):
        system = platform.system()
        if system == "Darwin":
            self._check_macos_firewall()
        elif system == "Linux":
            self._check_linux_firewall()
        return self.result

    def _check_macos_firewall(self):
        try:
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=10
            )
            if "enabled" in result.stdout.lower():
                self.add_finding(
                    title="macOS Application Firewall is enabled",
                    description="The built-in firewall is active.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="NS-05", evidence=result.stdout.strip(),
                )
            else:
                self.add_finding(
                    title="macOS Application Firewall is disabled",
                    description="The built-in firewall is not active.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enable the firewall in System Preferences > Security.",
                    control_ref="NS-05",
                )

            stealth = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
                capture_output=True, text=True, timeout=10
            )
            if "enabled" in stealth.stdout.lower():
                self.add_finding(
                    title="Firewall stealth mode is enabled",
                    description="System does not respond to probing.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="NS-06",
                )
            else:
                self.add_finding(
                    title="Firewall stealth mode is disabled",
                    description="System may respond to ICMP requests.",
                    severity=Severity.LOW, status=ControlStatus.WARNING,
                    recommendation="Consider enabling stealth mode.",
                    control_ref="NS-06",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.add_finding(
                title="Cannot check macOS firewall",
                description=str(e),
                severity=Severity.MEDIUM, status=ControlStatus.ERROR,
            )

    def _check_linux_firewall(self):
        for check_cmd, name in [
            (["ufw", "status"], "UFW"),
            (["firewall-cmd", "--state"], "firewalld"),
        ]:
            try:
                result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
                if "active" in result.stdout.lower() or "running" in result.stdout.lower():
                    self.add_finding(
                        title=f"{name} firewall is active",
                        description=f"{name} is enabled.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="NS-05",
                    )
                    return
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        self.add_finding(
            title="No active firewall detected",
            description="No active firewall (ufw/firewalld) found.",
            severity=Severity.CRITICAL, status=ControlStatus.FAIL,
            recommendation="Enable and configure a host-based firewall.",
            control_ref="NS-05",
        )
