"""Test runner orchestrator for all IT control tests."""

import json
import os
from datetime import datetime

from controls.access.password_policy import PasswordPolicyTest
from controls.access.user_privileges import UserPrivilegeTest
from controls.access.account_lockout import AccountLockoutTest
from controls.network.port_scan import PortScanTest
from controls.network.ssl_check import SSLCertificateTest
from controls.network.firewall_check import FirewallTest
from controls.system.patch_management import PatchManagementTest
from controls.system.service_monitor import ServiceMonitorTest
from controls.data.backup_check import BackupVerificationTest
from controls.data.encryption_check import EncryptionTest
from controls.change_mgmt.audit_log import AuditLogTest
from controls.cloud.aws_controls import AWSSecurityTest
from controls.cloud.azure_controls import AzureSecurityTest
from controls.cloud.gcp_controls import GCPSecurityTest
from controls.compliance.framework_mapper import ComplianceMapper

ALL_TESTS = {
    "password_policy": PasswordPolicyTest,
    "user_privileges": UserPrivilegeTest,
    "account_lockout": AccountLockoutTest,
    "port_scan": PortScanTest,
    "ssl_certificate": SSLCertificateTest,
    "firewall": FirewallTest,
    "patch_management": PatchManagementTest,
    "service_monitor": ServiceMonitorTest,
    "backup_verification": BackupVerificationTest,
    "encryption": EncryptionTest,
    "audit_log": AuditLogTest,
    "aws_security": AWSSecurityTest,
    "azure_security": AzureSecurityTest,
    "gcp_security": GCPSecurityTest,
}

TEST_CATEGORIES = {
    "access": ["password_policy", "user_privileges", "account_lockout"],
    "network": ["port_scan", "ssl_certificate", "firewall"],
    "system": ["patch_management", "service_monitor"],
    "data": ["backup_verification", "encryption"],
    "change_mgmt": ["audit_log"],
    "cloud_aws": ["aws_security"],
    "cloud_azure": ["azure_security"],
    "cloud_gcp": ["gcp_security"],
}


class TestRunner:
    def __init__(self, config=None):
        self.config = config or {}
        self.results = []
        self.compliance_mapper = ComplianceMapper()

    def _build_test(self, test_cls):
        return test_cls()

    def run_all(self):
        self.results = []
        for name, test_cls in ALL_TESTS.items():
            test = self._build_test(test_cls)
            result = test.execute()
            self.results.append(result)
        return self.results

    def run_category(self, category):
        if category not in TEST_CATEGORIES:
            raise ValueError(f"Unknown category: {category}. Valid: {list(TEST_CATEGORIES.keys())}")
        self.results = []
        for test_name in TEST_CATEGORIES[category]:
            test_cls = ALL_TESTS[test_name]
            test = self._build_test(test_cls)
            result = test.execute()
            self.results.append(result)
        return self.results

    def run_categories(self, categories):
        """Run multiple categories, accumulating results."""
        self.results = []
        for category in categories:
            if category not in TEST_CATEGORIES:
                continue
            for test_name in TEST_CATEGORIES[category]:
                test_cls = ALL_TESTS[test_name]
                test = self._build_test(test_cls)
                result = test.execute()
                self.results.append(result)
        return self.results

    def run_single(self, test_name):
        if test_name not in ALL_TESTS:
            raise ValueError(f"Unknown test: {test_name}. Valid: {list(ALL_TESTS.keys())}")
        test_cls = ALL_TESTS[test_name]
        test = self._build_test(test_cls)
        result = test.execute()
        self.results = [result]
        return result

    def get_summary(self):
        total_pass = sum(r.pass_count for r in self.results)
        total_fail = sum(r.fail_count for r in self.results)
        total_warn = sum(r.warning_count for r in self.results)

        compliance = self.compliance_mapper.map_findings(self.results)

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_tests": len(self.results),
            "total_passed": total_pass,
            "total_failed": total_fail,
            "total_warnings": total_warn,
            "overall_status": "FAIL" if total_fail > 0 else ("WARNING" if total_warn > 0 else "PASS"),
            "compliance": compliance,
            "results": [r.to_dict() for r in self.results],
        }

    def save_results(self, output_dir="reports"):
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"it_controls_report_{ts}.json")
        summary = self.get_summary()
        with open(filepath, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        return filepath
