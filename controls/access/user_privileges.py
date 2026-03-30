"""User privilege and access review control tests."""

import grp
import os
import platform
import pwd
import subprocess

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class UserPrivilegeTest(BaseControlTest):
    @property
    def name(self):
        return "User Privilege Review"

    @property
    def category(self):
        return ControlCategory.ACCESS

    @property
    def description(self):
        return "Reviews user accounts, administrative privileges, and least-privilege compliance."

    def run_tests(self):
        system = platform.system()
        if system in ("Darwin", "Linux"):
            self._check_admin_users()
            self._check_sudo_config()
            self._check_root_login()
        return self.result

    def _check_admin_users(self):
        system = platform.system()
        admin_users = []
        try:
            if system == "Darwin":
                result = subprocess.run(
                    ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    parts = result.stdout.strip().split()
                    admin_users = [u for u in parts if u != "GroupMembership:"]
            else:
                for group_name in ("sudo", "wheel", "admin"):
                    try:
                        group = grp.getgrnam(group_name)
                        admin_users.extend(group.gr_mem)
                    except KeyError:
                        pass

            admin_users = list(set(admin_users))
            if len(admin_users) <= 3:
                self.add_finding(
                    title="Administrative user count is acceptable",
                    description=f"Found {len(admin_users)} admin users: {', '.join(admin_users)}",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="AC-06", evidence=f"Admin users: {admin_users}",
                )
            else:
                self.add_finding(
                    title="Excessive administrative accounts detected",
                    description=f"Found {len(admin_users)} admin users (recommended: <=3).",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Review admin accounts and remove unnecessary privileges.",
                    control_ref="AC-06", evidence=f"Admin users: {admin_users}",
                )
        except Exception as e:
            self.add_finding(
                title="Could not enumerate admin users",
                description=str(e),
                severity=Severity.MEDIUM, status=ControlStatus.ERROR,
            )

    def _check_sudo_config(self):
        sudoers_path = "/etc/sudoers"
        if os.path.exists(sudoers_path):
            try:
                result = subprocess.run(
                    ["grep", "-c", "NOPASSWD", sudoers_path],
                    capture_output=True, text=True, timeout=10
                )
                nopasswd_count = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
                if nopasswd_count > 0:
                    self.add_finding(
                        title="NOPASSWD entries found in sudoers",
                        description=f"Found {nopasswd_count} NOPASSWD entries.",
                        severity=Severity.HIGH, status=ControlStatus.FAIL,
                        recommendation="Remove NOPASSWD entries and require password for sudo.",
                        control_ref="AC-08",
                    )
                else:
                    self.add_finding(
                        title="No NOPASSWD entries in sudoers",
                        description="All sudo access requires password.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-08",
                    )
            except (subprocess.TimeoutExpired, PermissionError):
                self.add_finding(
                    title="Cannot read sudoers configuration",
                    description="Insufficient permissions.",
                    severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                    control_ref="AC-08",
                )

    def _check_root_login(self):
        try:
            ssh_config_path = "/etc/ssh/sshd_config"
            if os.path.exists(ssh_config_path):
                with open(ssh_config_path, "r") as f:
                    config = f.read()
                if "PermitRootLogin no" in config or "PermitRootLogin prohibit-password" in config:
                    self.add_finding(
                        title="SSH root login is properly restricted",
                        description="PermitRootLogin is disabled or key-only.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="AC-09",
                    )
                elif "PermitRootLogin yes" in config:
                    self.add_finding(
                        title="SSH root login is enabled",
                        description="Direct SSH root login with password is allowed.",
                        severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                        recommendation="Set PermitRootLogin to 'no' in sshd_config.",
                        control_ref="AC-09",
                    )
                else:
                    self.add_finding(
                        title="SSH root login status unclear",
                        description="PermitRootLogin not explicitly set.",
                        severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                        recommendation="Explicitly set PermitRootLogin to 'no'.",
                        control_ref="AC-09",
                    )
        except PermissionError:
            self.add_finding(
                title="Cannot read SSH configuration",
                description="Insufficient permissions.",
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="AC-09",
            )
