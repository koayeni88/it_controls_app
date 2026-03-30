"""GCP cloud security control tests.

Checks IAM policies, Cloud Storage bucket security, firewall rules,
Cloud Audit Logs, KMS key rotation, and Compute Engine configurations.
"""

import os

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)

_GCP_AVAILABLE = False
try:
    from google.cloud import compute_v1
    from google.cloud import storage as gcs_storage
    from google.cloud import kms_v1
    from google.cloud import logging as gcp_logging
    from google.cloud import resourcemanager_v3
    from google.api_core.exceptions import GoogleAPICallError, PermissionDenied
    _GCP_AVAILABLE = True
except ImportError:
    pass


class GCPSecurityTest(BaseControlTest):
    """Comprehensive GCP cloud security controls."""

    def __init__(self, project_id=None):
        self._project_id = project_id or os.environ.get("GCLOUD_PROJECT") or os.environ.get("GCP_PROJECT_ID")
        super().__init__()

    @property
    def name(self):
        return "GCP Cloud Security Assessment"

    @property
    def category(self):
        return ControlCategory.CLOUD_GCP

    @property
    def description(self):
        return "Validates GCP IAM, Cloud Storage, Firewall Rules, Audit Logs, KMS, and Compute controls."

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------
    def run_tests(self):
        if not _GCP_AVAILABLE:
            self.add_finding(
                title="GCP SDK not installed",
                description="Install google-cloud packages to enable GCP security checks.",
                severity=Severity.MEDIUM, status=ControlStatus.SKIPPED,
                control_ref="CLD-GCP-00",
            )
            return self.result

        if not self._project_id:
            self.add_finding(
                title="GCP project ID not configured",
                description="Set GCLOUD_PROJECT or GCP_PROJECT_ID, or pass project_id.",
                severity=Severity.HIGH, status=ControlStatus.ERROR,
                recommendation="Export GCLOUD_PROJECT=<your-project-id>",
                control_ref="CLD-GCP-01",
            )
            return self.result

        try:
            rm = resourcemanager_v3.ProjectsClient()
            project = rm.get_project(name=f"projects/{self._project_id}")
            self.add_finding(
                title="GCP credentials valid",
                description=f"Project: {project.display_name} ({self._project_id})",
                severity=Severity.INFO, status=ControlStatus.PASS,
                control_ref="CLD-GCP-01",
                evidence=f"Project: {self._project_id}",
            )
        except PermissionDenied as exc:
            self.add_finding(
                title="GCP authentication failed",
                description=str(exc),
                severity=Severity.HIGH, status=ControlStatus.ERROR,
                recommendation="Configure gcloud auth or GOOGLE_APPLICATION_CREDENTIALS.",
                control_ref="CLD-GCP-01",
            )
            return self.result
        except GoogleAPICallError as exc:
            self.add_finding(
                title="GCP connectivity error",
                description=str(exc),
                severity=Severity.HIGH, status=ControlStatus.ERROR,
                control_ref="CLD-GCP-01",
            )
            return self.result

        self._check_storage_public_access()
        self._check_firewall_rules()
        self._check_audit_logging()
        self._check_kms_rotation()
        self._check_vm_serial_port()
        self._check_storage_uniform_access()
        return self.result

    # ------------------------------------------------------------------
    # Cloud Storage public access
    # ------------------------------------------------------------------
    def _check_storage_public_access(self):
        try:
            client = gcs_storage.Client(project=self._project_id)
            buckets = list(client.list_buckets())
            public_buckets = []
            for bucket in buckets:
                iam_policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in iam_policy.bindings:
                    if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                        public_buckets.append(bucket.name)
                        break

            if public_buckets:
                self.add_finding(
                    title=f"{len(public_buckets)} GCS bucket(s) have public access",
                    description=f"Buckets: {', '.join(public_buckets[:10])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Remove allUsers and allAuthenticatedUsers from bucket IAM policies.",
                    control_ref="CLD-GCP-02",
                )
            else:
                self.add_finding(
                    title="No publicly accessible GCS buckets found",
                    description=f"Checked {len(buckets)} bucket(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-02",
                )
        except GoogleAPICallError as exc:
            self.add_finding(
                title="Cannot check GCS bucket security",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-GCP-02",
            )

    # ------------------------------------------------------------------
    # Cloud Storage uniform bucket-level access
    # ------------------------------------------------------------------
    def _check_storage_uniform_access(self):
        try:
            client = gcs_storage.Client(project=self._project_id)
            buckets = list(client.list_buckets())
            non_uniform = []
            for bucket in buckets:
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    non_uniform.append(bucket.name)

            if non_uniform:
                self.add_finding(
                    title=f"{len(non_uniform)} bucket(s) without uniform bucket-level access",
                    description=f"Buckets: {', '.join(non_uniform[:10])}",
                    severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                    recommendation="Enable uniform bucket-level access for consistent permission model.",
                    control_ref="CLD-GCP-07",
                )
            else:
                self.add_finding(
                    title="All buckets use uniform bucket-level access",
                    description=f"Checked {len(buckets)} bucket(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-07",
                )
        except GoogleAPICallError as exc:
            self.add_finding(
                title="Cannot check uniform access",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-GCP-07",
            )

    # ------------------------------------------------------------------
    # Firewall rules
    # ------------------------------------------------------------------
    def _check_firewall_rules(self):
        try:
            fw_client = compute_v1.FirewallsClient()
            firewalls = list(fw_client.list(project=self._project_id))
            wide_open = []
            for fw in firewalls:
                if fw.direction == "INGRESS" and "0.0.0.0/0" in (fw.source_ranges or []):
                    for allowed in (fw.allowed or []):
                        ports = allowed.ports or []
                        if not ports or "22" in ports or "3389" in ports:
                            wide_open.append(fw.name)
                            break

            if wide_open:
                self.add_finding(
                    title=f"{len(wide_open)} firewall rule(s) allow unrestricted ingress",
                    description=f"Rules: {', '.join(wide_open[:10])}",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Restrict firewall source ranges to specific IPs/CIDRs.",
                    control_ref="CLD-GCP-03",
                )
            else:
                self.add_finding(
                    title="No unrestricted firewall rules found",
                    description=f"Checked {len(firewalls)} rule(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-03",
                )
        except GoogleAPICallError as exc:
            self.add_finding(
                title="Cannot check GCP firewall rules",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-GCP-03",
            )

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------
    def _check_audit_logging(self):
        try:
            client = gcp_logging.Client(project=self._project_id)
            sinks = list(client.list_sinks())
            if sinks:
                self.add_finding(
                    title=f"{len(sinks)} log sink(s) configured",
                    description=f"Sinks: {', '.join(s.name for s in sinks[:5])}",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-04",
                )
            else:
                self.add_finding(
                    title="No log sinks configured",
                    description="Project has no log export sinks.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Configure log sinks to export audit logs to Cloud Storage, BigQuery, or Pub/Sub.",
                    control_ref="CLD-GCP-04",
                )
        except GoogleAPICallError as exc:
            self.add_finding(
                title="Cannot check audit logging",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-GCP-04",
            )

    # ------------------------------------------------------------------
    # KMS key rotation
    # ------------------------------------------------------------------
    def _check_kms_rotation(self):
        try:
            client = kms_v1.KeyManagementServiceClient()
            parent = f"projects/{self._project_id}/locations/-"
            key_rings = list(client.list_key_rings(request={"parent": parent}))
            no_rotation = []
            total_keys = 0
            for ring in key_rings:
                keys = list(client.list_crypto_keys(request={"parent": ring.name}))
                for key in keys:
                    if key.purpose == kms_v1.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT:
                        total_keys += 1
                        if not key.rotation_period:
                            no_rotation.append(key.name.split("/")[-1])

            if no_rotation:
                self.add_finding(
                    title=f"{len(no_rotation)} KMS key(s) without rotation",
                    description=f"Keys: {', '.join(no_rotation[:5])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enable automatic rotation (90 days) on all encryption keys.",
                    control_ref="CLD-GCP-05",
                )
            elif total_keys > 0:
                self.add_finding(
                    title="All KMS keys have rotation configured",
                    description=f"Checked {total_keys} key(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-05",
                )
            else:
                self.add_finding(
                    title="No customer-managed KMS keys found",
                    description="No KMS keys to check.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-05",
                )
        except GoogleAPICallError as exc:
            self.add_finding(
                title="Cannot check KMS key rotation",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-GCP-05",
            )

    # ------------------------------------------------------------------
    # VM serial port disabled
    # ------------------------------------------------------------------
    def _check_vm_serial_port(self):
        try:
            client = compute_v1.InstancesClient()
            agg = client.aggregated_list(project=self._project_id)
            serial_enabled = []
            total_vms = 0
            for zone, response in agg:
                for vm in (response.instances or []):
                    total_vms += 1
                    for item in (vm.metadata.items or []) if vm.metadata else []:
                        if item.key == "serial-port-enable" and item.value == "true":
                            serial_enabled.append(vm.name)

            if serial_enabled:
                self.add_finding(
                    title=f"{len(serial_enabled)} VM(s) have serial port enabled",
                    description=f"VMs: {', '.join(serial_enabled[:10])}",
                    severity=Severity.MEDIUM, status=ControlStatus.FAIL,
                    recommendation="Disable serial port access on production VMs.",
                    control_ref="CLD-GCP-06",
                )
            elif total_vms > 0:
                self.add_finding(
                    title="No VMs with serial port enabled",
                    description=f"Checked {total_vms} VM(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-06",
                )
            else:
                self.add_finding(
                    title="No Compute Engine VMs found",
                    description="No VMs to check.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-GCP-06",
                )
        except GoogleAPICallError as exc:
            self.add_finding(
                title="Cannot check VM serial ports",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-GCP-06",
            )
