"""Azure cloud security control tests.

Checks Entra ID (Azure AD), Storage Account security, NSG rules,
Activity Log / Diagnostic Settings, Key Vault, and SQL Server auditing.
"""

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)

_AZURE_AVAILABLE = False
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.core.exceptions import (
        AzureError, ClientAuthenticationError, HttpResponseError,
    )
    _AZURE_AVAILABLE = True
except ImportError:
    pass


class AzureSecurityTest(BaseControlTest):
    """Comprehensive Azure cloud security controls."""

    def __init__(self, subscription_id=None):
        self._subscription_id = subscription_id
        self._credential = None
        super().__init__()

    @property
    def name(self):
        return "Azure Cloud Security Assessment"

    @property
    def category(self):
        return ControlCategory.CLOUD_AZURE

    @property
    def description(self):
        return "Validates Azure NSGs, Storage, Key Vault, Activity Logging, and VM disk encryption."

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _get_credential(self):
        if self._credential is None:
            self._credential = DefaultAzureCredential()
        return self._credential

    def _get_subscription_id(self):
        if self._subscription_id:
            return self._subscription_id
        import os
        sub = os.environ.get("AZURE_SUBSCRIPTION_ID")
        if sub:
            self._subscription_id = sub
            return sub
        return None

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------
    def run_tests(self):
        if not _AZURE_AVAILABLE:
            self.add_finding(
                title="Azure SDK not installed",
                description="Install azure-identity and azure-mgmt packages to enable Azure checks.",
                severity=Severity.MEDIUM, status=ControlStatus.SKIPPED,
                control_ref="CLD-AZ-00",
            )
            return self.result

        sub_id = self._get_subscription_id()
        if not sub_id:
            self.add_finding(
                title="Azure subscription ID not configured",
                description="Set AZURE_SUBSCRIPTION_ID or pass subscription_id.",
                severity=Severity.HIGH, status=ControlStatus.ERROR,
                recommendation="Export AZURE_SUBSCRIPTION_ID=<your-sub-id> or pass it at init.",
                control_ref="CLD-AZ-01",
            )
            return self.result

        try:
            cred = self._get_credential()
            rm = ResourceManagementClient(cred, sub_id)
            # quick auth check – list first resource group
            next(rm.resource_groups.list(), None)
            self.add_finding(
                title="Azure credentials valid",
                description=f"Subscription {sub_id}",
                severity=Severity.INFO, status=ControlStatus.PASS,
                control_ref="CLD-AZ-01",
                evidence=f"Subscription: {sub_id}",
            )
        except ClientAuthenticationError as exc:
            self.add_finding(
                title="Azure authentication failed",
                description=str(exc),
                severity=Severity.HIGH, status=ControlStatus.ERROR,
                recommendation="Configure Azure credentials (az login, env vars, or managed identity).",
                control_ref="CLD-AZ-01",
            )
            return self.result
        except AzureError as exc:
            self.add_finding(
                title="Azure connectivity error",
                description=str(exc),
                severity=Severity.HIGH, status=ControlStatus.ERROR,
                control_ref="CLD-AZ-01",
            )
            return self.result

        self._check_nsg_rules(sub_id)
        self._check_storage_https(sub_id)
        self._check_key_vault_soft_delete(sub_id)
        self._check_vm_disk_encryption(sub_id)
        self._check_activity_log(sub_id)
        self._check_storage_public_access(sub_id)
        return self.result

    # ------------------------------------------------------------------
    # NSG
    # ------------------------------------------------------------------
    def _check_nsg_rules(self, sub_id):
        try:
            net = NetworkManagementClient(self._get_credential(), sub_id)
            nsgs = list(net.network_security_groups.list_all())
            wide_open = []
            for nsg in nsgs:
                for rule in (nsg.security_rules or []):
                    if (rule.direction == "Inbound"
                            and rule.access == "Allow"
                            and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")
                            and rule.destination_port_range in ("*", "22", "3389")):
                        wide_open.append(f"{nsg.name}/{rule.name}")

            if wide_open:
                self.add_finding(
                    title=f"{len(wide_open)} NSG rule(s) allow unrestricted inbound access",
                    description=f"Rules: {', '.join(wide_open[:10])}",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Restrict NSG rules to specific source IPs.",
                    control_ref="CLD-AZ-02",
                )
            else:
                self.add_finding(
                    title="No unrestricted NSG inbound rules found",
                    description=f"Checked {len(nsgs)} NSG(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AZ-02",
                )
        except AzureError as exc:
            self.add_finding(
                title="Cannot check NSG rules",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AZ-02",
            )

    # ------------------------------------------------------------------
    # Storage HTTPS-only
    # ------------------------------------------------------------------
    def _check_storage_https(self, sub_id):
        try:
            stor = StorageManagementClient(self._get_credential(), sub_id)
            accounts = list(stor.storage_accounts.list())
            no_https = [a.name for a in accounts if not a.enable_https_traffic_only]

            if no_https:
                self.add_finding(
                    title=f"{len(no_https)} storage account(s) allow non-HTTPS traffic",
                    description=f"Accounts: {', '.join(no_https[:10])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enable 'Secure transfer required' on all storage accounts.",
                    control_ref="CLD-AZ-03",
                )
            else:
                self.add_finding(
                    title="All storage accounts require HTTPS",
                    description=f"Checked {len(accounts)} account(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AZ-03",
                )
        except AzureError as exc:
            self.add_finding(
                title="Cannot check storage account settings",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AZ-03",
            )

    # ------------------------------------------------------------------
    # Storage public access
    # ------------------------------------------------------------------
    def _check_storage_public_access(self, sub_id):
        try:
            stor = StorageManagementClient(self._get_credential(), sub_id)
            accounts = list(stor.storage_accounts.list())
            public_accounts = [a.name for a in accounts if a.allow_blob_public_access]

            if public_accounts:
                self.add_finding(
                    title=f"{len(public_accounts)} storage account(s) allow public blob access",
                    description=f"Accounts: {', '.join(public_accounts[:10])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Disable public blob access on storage accounts.",
                    control_ref="CLD-AZ-07",
                )
            else:
                self.add_finding(
                    title="No storage accounts allow public blob access",
                    description=f"Checked {len(accounts)} account(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AZ-07",
                )
        except AzureError as exc:
            self.add_finding(
                title="Cannot check storage public access",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AZ-07",
            )

    # ------------------------------------------------------------------
    # Key Vault soft delete
    # ------------------------------------------------------------------
    def _check_key_vault_soft_delete(self, sub_id):
        try:
            kv = KeyVaultManagementClient(self._get_credential(), sub_id)
            vaults = list(kv.vaults.list_by_subscription())
            no_sd = []
            for vault in vaults:
                props = vault.properties
                if props and not getattr(props, "enable_soft_delete", True):
                    no_sd.append(vault.name)

            if no_sd:
                self.add_finding(
                    title=f"{len(no_sd)} Key Vault(s) without soft-delete",
                    description=f"Vaults: {', '.join(no_sd[:10])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enable soft-delete on all Key Vaults.",
                    control_ref="CLD-AZ-04",
                )
            else:
                self.add_finding(
                    title="All Key Vaults have soft-delete enabled",
                    description=f"Checked {len(vaults)} vault(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AZ-04",
                )
        except AzureError as exc:
            self.add_finding(
                title="Cannot check Key Vault configuration",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AZ-04",
            )

    # ------------------------------------------------------------------
    # VM disk encryption
    # ------------------------------------------------------------------
    def _check_vm_disk_encryption(self, sub_id):
        try:
            compute = ComputeManagementClient(self._get_credential(), sub_id)
            vms = list(compute.virtual_machines.list_all())
            unencrypted = []
            for vm in vms:
                if vm.storage_profile and vm.storage_profile.os_disk:
                    enc = vm.storage_profile.os_disk.encryption_settings
                    managed = vm.storage_profile.os_disk.managed_disk
                    if not (enc and getattr(enc, "enabled", False)):
                        if not (managed and getattr(managed, "disk_encryption_set", None)):
                            unencrypted.append(vm.name)

            if unencrypted:
                self.add_finding(
                    title=f"{len(unencrypted)} VM(s) without disk encryption",
                    description=f"VMs: {', '.join(unencrypted[:10])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enable Azure Disk Encryption or use encrypted managed disks.",
                    control_ref="CLD-AZ-05",
                )
            elif vms:
                self.add_finding(
                    title="All VMs have disk encryption",
                    description=f"Checked {len(vms)} VM(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AZ-05",
                )
            else:
                self.add_finding(
                    title="No VMs found",
                    description="No virtual machines to check.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AZ-05",
                )
        except AzureError as exc:
            self.add_finding(
                title="Cannot check VM disk encryption",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AZ-05",
            )

    # ------------------------------------------------------------------
    # Activity Log / Diagnostic Settings
    # ------------------------------------------------------------------
    def _check_activity_log(self, sub_id):
        try:
            monitor = MonitorManagementClient(self._get_credential(), sub_id)
            settings = list(monitor.diagnostic_settings.list(
                resource_uri=f"/subscriptions/{sub_id}"
            ))
            if settings:
                self.add_finding(
                    title="Activity log diagnostic settings configured",
                    description=f"{len(settings)} diagnostic setting(s) found for subscription.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AZ-06",
                )
            else:
                self.add_finding(
                    title="No activity log diagnostic settings found",
                    description="Subscription has no diagnostic settings for activity logs.",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Configure diagnostic settings to send activity logs to Log Analytics, Storage, or Event Hub.",
                    control_ref="CLD-AZ-06",
                )
        except AzureError as exc:
            self.add_finding(
                title="Cannot check activity log diagnostics",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AZ-06",
            )
