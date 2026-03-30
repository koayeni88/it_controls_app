"""Backup verification control tests."""

import os
import platform
import subprocess
import time

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)


class BackupVerificationTest(BaseControlTest):
    def __init__(self, backup_dirs=None):
        self.backup_dirs = backup_dirs or []
        super().__init__()

    @property
    def name(self):
        return "Backup Verification"

    @property
    def category(self):
        return ControlCategory.DATA

    @property
    def description(self):
        return "Verifies backup configurations and recent backup status."

    def run_tests(self):
        system = platform.system()
        if system == "Darwin":
            self._check_time_machine()
        elif system == "Linux":
            self._check_linux_backups()
        if self.backup_dirs:
            self._check_backup_directories()
        return self.result

    def _check_time_machine(self):
        try:
            latest = subprocess.run(
                ["tmutil", "latestbackup"],
                capture_output=True, text=True, timeout=10
            )
            if latest.returncode == 0 and latest.stdout.strip():
                self.add_finding(
                    title="Time Machine: latest backup found",
                    description=f"Latest: {latest.stdout.strip()}",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="DP-01",
                )
            else:
                self.add_finding(
                    title="No Time Machine backup found",
                    description="No recent Time Machine backup detected.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Configure Time Machine backups.",
                    control_ref="DP-01",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.add_finding(
                title="Cannot check Time Machine",
                description="tmutil not available.",
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="DP-01",
            )

    def _check_linux_backups(self):
        tools = ["rsync", "borgbackup", "restic", "duplicity"]
        found = []
        for tool in tools:
            try:
                result = subprocess.run(["which", tool], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    found.append(tool)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        if found:
            self.add_finding(
                title=f"Backup tools installed: {', '.join(found)}",
                description="Backup utilities available.",
                severity=Severity.INFO, status=ControlStatus.PASS,
                control_ref="DP-01",
            )
        else:
            self.add_finding(
                title="No backup tools detected",
                description="No common backup utilities found.",
                severity=Severity.HIGH, status=ControlStatus.FAIL,
                recommendation="Install a backup solution (rsync, BorgBackup, or Restic).",
                control_ref="DP-01",
            )

    def _check_backup_directories(self):
        for backup_dir in self.backup_dirs:
            if not os.path.exists(backup_dir):
                self.add_finding(
                    title=f"Backup directory missing: {backup_dir}",
                    description="Expected backup directory does not exist.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    control_ref="DP-02",
                )
                continue
            cutoff = time.time() - (7 * 86400)
            try:
                recent = [e.name for e in os.scandir(backup_dir) if e.stat().st_mtime > cutoff]
                if recent:
                    self.add_finding(
                        title=f"Recent backups in {backup_dir}",
                        description=f"{len(recent)} files modified in last 7 days.",
                        severity=Severity.INFO, status=ControlStatus.PASS,
                        control_ref="DP-02",
                    )
                else:
                    self.add_finding(
                        title=f"No recent backups in {backup_dir}",
                        description="No files modified in last 7 days.",
                        severity=Severity.HIGH, status=ControlStatus.FAIL,
                        recommendation="Investigate backup failures.",
                        control_ref="DP-02",
                    )
            except PermissionError:
                self.add_finding(
                    title=f"Cannot access {backup_dir}",
                    description="Permission denied.",
                    severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                    control_ref="DP-02",
                )
