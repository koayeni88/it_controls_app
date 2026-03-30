"""Compliance framework mapping for control test results."""

from controls.base import ControlStatus

FRAMEWORKS = {
    "SOX": {
        "name": "Sarbanes-Oxley (SOX)",
        "controls": {
            "AC-01": {"section": "IT General Controls", "requirement": "Password complexity requirements"},
            "AC-02": {"section": "IT General Controls", "requirement": "Session timeout controls"},
            "AC-03": {"section": "IT General Controls", "requirement": "Password aging policies"},
            "AC-06": {"section": "IT General Controls", "requirement": "Administrative access management"},
            "AC-08": {"section": "IT General Controls", "requirement": "Privileged access controls"},
            "AC-09": {"section": "IT General Controls", "requirement": "Remote access controls"},
            "AC-10": {"section": "IT General Controls", "requirement": "Account lockout controls"},
            "CM-01": {"section": "Change Management", "requirement": "Audit trail maintenance"},
            "CM-02": {"section": "Change Management", "requirement": "Logging configuration"},
            "CM-03": {"section": "Change Management", "requirement": "Log integrity protection"},
            "SC-02": {"section": "IT Operations", "requirement": "Patch management"},
            "DP-01": {"section": "IT Operations", "requirement": "Data backup procedures"},
            "DP-03": {"section": "IT General Controls", "requirement": "Data encryption at rest"},
            "CLD-AWS-02": {"section": "Cloud Controls", "requirement": "AWS root account MFA"},
            "CLD-AWS-06": {"section": "Cloud Controls", "requirement": "AWS CloudTrail logging"},
            "CLD-AZ-06": {"section": "Cloud Controls", "requirement": "Azure activity log diagnostics"},
            "CLD-GCP-04": {"section": "Cloud Controls", "requirement": "GCP audit log sinks"},
        },
    },
    "PCI-DSS": {
        "name": "PCI Data Security Standard",
        "controls": {
            "NS-01": {"section": "Req 1: Firewall Config", "requirement": "Network port management"},
            "NS-02": {"section": "Req 4: Encrypt Transmission", "requirement": "SSL/TLS management"},
            "NS-05": {"section": "Req 1: Firewall Config", "requirement": "Host firewall enabled"},
            "AC-01": {"section": "Req 8: Identify & Auth", "requirement": "Password complexity"},
            "AC-10": {"section": "Req 8: Identify & Auth", "requirement": "Account lockout"},
            "DP-03": {"section": "Req 3: Protect Stored Data", "requirement": "Encryption of stored data"},
            "DP-04": {"section": "Req 3: Protect Stored Data", "requirement": "Key management"},
            "CM-01": {"section": "Req 10: Track & Monitor", "requirement": "Audit logging enabled"},
            "CLD-AWS-04": {"section": "Req 3: Protect Stored Data", "requirement": "AWS S3 public access block"},
            "CLD-AWS-05": {"section": "Req 1: Firewall Config", "requirement": "AWS security groups"},
            "CLD-AWS-07": {"section": "Req 3: Protect Stored Data", "requirement": "AWS KMS key rotation"},
            "CLD-AZ-02": {"section": "Req 1: Firewall Config", "requirement": "Azure NSG rules"},
            "CLD-AZ-03": {"section": "Req 4: Encrypt Transmission", "requirement": "Azure storage HTTPS"},
            "CLD-GCP-02": {"section": "Req 3: Protect Stored Data", "requirement": "GCS public access"},
            "CLD-GCP-03": {"section": "Req 1: Firewall Config", "requirement": "GCP firewall rules"},
            "CLD-GCP-05": {"section": "Req 3: Protect Stored Data", "requirement": "GCP KMS key rotation"},
        },
    },
    "HIPAA": {
        "name": "HIPAA Security Rule",
        "controls": {
            "AC-01": {"section": "164.312(a) Access Control", "requirement": "Unique user identification"},
            "AC-06": {"section": "164.312(a) Access Control", "requirement": "Access authorization"},
            "AC-10": {"section": "164.312(a) Access Control", "requirement": "Automatic logoff"},
            "DP-01": {"section": "164.308(a)(7) Contingency", "requirement": "Data backup plan"},
            "DP-03": {"section": "164.312(a) Access Control", "requirement": "Encryption and decryption"},
            "CM-01": {"section": "164.312(b) Audit Controls", "requirement": "Audit mechanisms"},
            "NS-02": {"section": "164.312(e) Transmission", "requirement": "Encryption in transit"},
            "CLD-AWS-07": {"section": "164.312(a) Access Control", "requirement": "AWS KMS encryption keys"},
            "CLD-AWS-08": {"section": "164.312(a) Access Control", "requirement": "AWS RDS public access"},
            "CLD-AZ-04": {"section": "164.312(a) Access Control", "requirement": "Azure Key Vault soft-delete"},
            "CLD-AZ-05": {"section": "164.312(a) Access Control", "requirement": "Azure VM disk encryption"},
            "CLD-GCP-05": {"section": "164.312(a) Access Control", "requirement": "GCP KMS key management"},
        },
    },
    "ISO-27001": {
        "name": "ISO/IEC 27001:2022",
        "controls": {
            "AC-01": {"section": "A.9.4 Access control", "requirement": "Password policy"},
            "AC-06": {"section": "A.9.2 User access", "requirement": "Privileged access management"},
            "AC-09": {"section": "A.9.4 Access control", "requirement": "Access restrictions"},
            "NS-01": {"section": "A.13.1 Network security", "requirement": "Network controls"},
            "NS-05": {"section": "A.13.1 Network security", "requirement": "Network services security"},
            "SC-02": {"section": "A.12.6 Vulnerability mgmt", "requirement": "Patch management"},
            "SC-03": {"section": "A.12.6 Vulnerability mgmt", "requirement": "Software restrictions"},
            "DP-01": {"section": "A.12.3 Backup", "requirement": "Backup procedures"},
            "DP-03": {"section": "A.10.1 Cryptographic", "requirement": "Encryption implementation"},
            "CM-01": {"section": "A.12.4 Logging", "requirement": "Event logging"},
            "CM-03": {"section": "A.12.4 Logging", "requirement": "Log protection"},
            "CLD-AWS-02": {"section": "A.9.2 User access", "requirement": "AWS root MFA"},
            "CLD-AWS-03": {"section": "A.9.4 Access control", "requirement": "AWS IAM password policy"},
            "CLD-AZ-02": {"section": "A.13.1 Network security", "requirement": "Azure NSG controls"},
            "CLD-AZ-07": {"section": "A.10.1 Cryptographic", "requirement": "Azure storage public access"},
            "CLD-GCP-03": {"section": "A.13.1 Network security", "requirement": "GCP firewall controls"},
            "CLD-GCP-07": {"section": "A.10.1 Cryptographic", "requirement": "GCP uniform bucket access"},
        },
    },
    "CSA-CCM": {
        "name": "Cloud Security Alliance CCM v4",
        "controls": {
            "CLD-AWS-02": {"section": "IAM-02", "requirement": "Root account MFA"},
            "CLD-AWS-03": {"section": "IAM-04", "requirement": "IAM password policy"},
            "CLD-AWS-04": {"section": "DSP-07", "requirement": "S3 public access block"},
            "CLD-AWS-05": {"section": "IVS-03", "requirement": "Security group restrictions"},
            "CLD-AWS-06": {"section": "LOG-03", "requirement": "CloudTrail multi-region"},
            "CLD-AWS-07": {"section": "CEK-03", "requirement": "KMS key rotation"},
            "CLD-AWS-08": {"section": "IVS-06", "requirement": "RDS public access"},
            "CLD-AZ-02": {"section": "IVS-03", "requirement": "NSG inbound rules"},
            "CLD-AZ-03": {"section": "DSP-04", "requirement": "Storage HTTPS required"},
            "CLD-AZ-04": {"section": "CEK-02", "requirement": "Key Vault soft-delete"},
            "CLD-AZ-05": {"section": "DSP-07", "requirement": "VM disk encryption"},
            "CLD-AZ-06": {"section": "LOG-03", "requirement": "Activity log diagnostics"},
            "CLD-AZ-07": {"section": "DSP-07", "requirement": "Storage public blob access"},
            "CLD-GCP-02": {"section": "DSP-07", "requirement": "GCS public access"},
            "CLD-GCP-03": {"section": "IVS-03", "requirement": "Firewall rule restrictions"},
            "CLD-GCP-04": {"section": "LOG-03", "requirement": "Log sinks configured"},
            "CLD-GCP-05": {"section": "CEK-03", "requirement": "KMS key rotation"},
            "CLD-GCP-06": {"section": "IVS-06", "requirement": "VM serial port disabled"},
            "CLD-GCP-07": {"section": "DSP-07", "requirement": "Uniform bucket-level access"},
        },
    },
}


class ComplianceMapper:
    def __init__(self, frameworks=None):
        self.frameworks = frameworks or list(FRAMEWORKS.keys())

    def map_findings(self, all_results):
        findings_by_ref = {}
        for result in all_results:
            for finding in result.findings:
                if finding.control_ref:
                    findings_by_ref.setdefault(finding.control_ref, []).append(finding)

        compliance_report = {}
        for fw_key in self.frameworks:
            if fw_key not in FRAMEWORKS:
                continue
            fw = FRAMEWORKS[fw_key]
            fr = {"name": fw["name"], "controls": {}, "total": 0, "passed": 0, "failed": 0, "warnings": 0, "not_tested": 0}

            for ctrl_ref, ctrl_info in fw["controls"].items():
                fr["total"] += 1
                if ctrl_ref in findings_by_ref:
                    findings = findings_by_ref[ctrl_ref]
                    has_fail = any(f.status == ControlStatus.FAIL for f in findings)
                    has_warn = any(f.status == ControlStatus.WARNING for f in findings)
                    has_pass = any(f.status == ControlStatus.PASS for f in findings)

                    if has_fail:
                        status = "fail"
                        fr["failed"] += 1
                    elif has_warn:
                        status = "warning"
                        fr["warnings"] += 1
                    elif has_pass:
                        status = "pass"
                        fr["passed"] += 1
                    else:
                        status = "not_tested"
                        fr["not_tested"] += 1

                    fr["controls"][ctrl_ref] = {
                        "section": ctrl_info["section"],
                        "requirement": ctrl_info["requirement"],
                        "status": status,
                        "findings": [f.to_dict() for f in findings],
                    }
                else:
                    fr["not_tested"] += 1
                    fr["controls"][ctrl_ref] = {
                        "section": ctrl_info["section"],
                        "requirement": ctrl_info["requirement"],
                        "status": "not_tested",
                        "findings": [],
                    }

            fr["compliance_pct"] = round((fr["passed"] / fr["total"]) * 100, 1) if fr["total"] > 0 else 0
            compliance_report[fw_key] = fr

        return compliance_report
