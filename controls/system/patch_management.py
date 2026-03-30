"""Patch management control tests."""

import platform
import subprocess

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class PatchManagementTest(BaseControlTest):
    @property
    def name(self):
        return "Patch Management Assessment"

    @property
    def category(self):
        return ControlCategory.SYSTEM

    @property
    def description(self):
        return "Checks for pending system updates and patch compliance."

    def run_tests(self):
        system = platform.system()
        self._check_os_version()
        if system == "Darwin":
            self._check_macos_updates()
        elif system == "Linux":
            self._check_linux_updates()
        return self.result

    def _check_os_version(self):
        system = platform.system()
        release = platform.release()
        machine = platform.machine()
        self.add_finding(
            title="System information collected",
            description=f"{system} {release} ({machine})",
            severity=Severity.INFO, status=ControlStatus.PASS,
            control_ref="SC-01",
        )

    def _check_macos_updates(self):
        try:
            result = subprocess.run(
                ["softwareupdate", "-l"],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout + result.stderr
            if "No new software available" in output:
                self.add_finding(
                    title="System is fully patched",
                    description="No pending macOS updates.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="SC-02",
                )
            else:
                updates = [l.strip() for l in output.split("\n") if l.strip().startswith("*")]
                security = [u for u in updates if "security" in u.lower()]
                if security:
                    self.add_finding(
                        title=f"{len(security)} security update(s) pending",
                        description="Critical security updates available.",
                        severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                        recommendation="Apply security updates immediately.",
                        control_ref="SC-02",
                    )
                elif updates:
                    self.add_finding(
                        title=f"{len(updates)} update(s) pending",
                        description="System updates are available.",
                        severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                        recommendation="Schedule system updates.",
                        control_ref="SC-02",
                    )
                else:
                    self.add_finding(
                        title="Update check completed",
                        description="Software update check finished.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="SC-02",
                    )
        except subprocess.TimeoutExpired:
            self.add_finding(
                title="Update check timed out",
                description="softwareupdate took too long.",
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="SC-02",
            )

    def _check_linux_updates(self):
        try:
            subprocess.run(["apt", "update"], capture_output=True, timeout=60)
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                packages = [l for l in result.stdout.strip().split("\n") if l and "Listing" not in l]
                if not packages:
                    self.add_finding(
                        title="All packages up to date",
                        description="No pending updates.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="SC-02",
                    )
                else:
                    self.add_finding(
                        title=f"{len(packages)} package update(s) pending",
                        description="Package updates available.",
                        severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                        recommendation="Run 'apt upgrade'.",
                        control_ref="SC-02",
                    )
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        self.add_finding(
            title="Package manager not detected",
            description="Could not determine package manager.",
            severity=Severity.MEDIUM, status=ControlStatus.WARNING,
            control_ref="SC-02",
        )
