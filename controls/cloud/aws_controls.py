"""AWS cloud security control tests.

Checks IAM policies, S3 bucket security, security groups, CloudTrail,
KMS encryption, and RDS public access using boto3.
"""

from controls.base import (
    BaseControlTest, ControlCategory, ControlStatus, Severity
)

_BOTO3_AVAILABLE = False
try:
    import boto3
    from botocore.exceptions import (
        BotoCoreError, ClientError, NoCredentialsError, NoRegionError,
    )
    _BOTO3_AVAILABLE = True
except ImportError:
    pass


class AWSSecurityTest(BaseControlTest):
    """Comprehensive AWS cloud security controls."""

    def __init__(self, region=None, profile=None):
        self._region = region
        self._profile = profile
        self._session = None
        super().__init__()

    @property
    def name(self):
        return "AWS Cloud Security Assessment"

    @property
    def category(self):
        return ControlCategory.CLOUD_AWS

    @property
    def description(self):
        return "Validates AWS IAM, S3, Security Groups, CloudTrail, KMS, and RDS controls."

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _get_session(self):
        if self._session is None:
            kwargs = {}
            if self._region:
                kwargs["region_name"] = self._region
            if self._profile:
                kwargs["profile_name"] = self._profile
            self._session = boto3.Session(**kwargs)
        return self._session

    def _client(self, service):
        return self._get_session().client(service)

    # ------------------------------------------------------------------
    # run
    # ------------------------------------------------------------------
    def run_tests(self):
        if not _BOTO3_AVAILABLE:
            self.add_finding(
                title="boto3 SDK not installed",
                description="Install boto3 to enable AWS security checks.",
                severity=Severity.MEDIUM, status=ControlStatus.SKIPPED,
                control_ref="CLD-AWS-00",
            )
            return self.result

        try:
            sts = self._client("sts")
            identity = sts.get_caller_identity()
            self.add_finding(
                title="AWS credentials valid",
                description=f"Account {identity['Account']}, ARN {identity['Arn']}",
                severity=Severity.INFO, status=ControlStatus.PASS,
                control_ref="CLD-AWS-01",
                evidence=f"Account: {identity['Account']}",
            )
        except (NoCredentialsError, NoRegionError, BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="AWS credentials not configured",
                description=str(exc),
                severity=Severity.HIGH, status=ControlStatus.ERROR,
                recommendation="Configure AWS credentials via environment variables, ~/.aws/credentials, or IAM role.",
                control_ref="CLD-AWS-01",
            )
            return self.result

        self._check_iam_root_mfa()
        self._check_iam_password_policy()
        self._check_s3_public_access()
        self._check_security_groups()
        self._check_cloudtrail()
        self._check_kms_key_rotation()
        self._check_rds_public_access()
        return self.result

    # ------------------------------------------------------------------
    # IAM
    # ------------------------------------------------------------------
    def _check_iam_root_mfa(self):
        try:
            iam = self._client("iam")
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 1:
                self.add_finding(
                    title="Root account MFA is enabled",
                    description="The AWS root account has MFA configured.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-02",
                )
            else:
                self.add_finding(
                    title="Root account MFA is NOT enabled",
                    description="The root account does not have MFA.",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Enable MFA on the root account immediately.",
                    control_ref="CLD-AWS-02",
                )
        except (BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="Cannot check root MFA",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AWS-02",
            )

    def _check_iam_password_policy(self):
        try:
            iam = self._client("iam")
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append(f"MinLength={policy.get('MinimumPasswordLength')}")
            if not policy.get("RequireUppercaseCharacters"):
                issues.append("NoUppercase")
            if not policy.get("RequireLowercaseCharacters"):
                issues.append("NoLowercase")
            if not policy.get("RequireNumbers"):
                issues.append("NoNumbers")
            if not policy.get("RequireSymbols"):
                issues.append("NoSymbols")

            if issues:
                self.add_finding(
                    title="IAM password policy is weak",
                    description=f"Issues: {', '.join(issues)}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enforce strong password policy (>=14 chars, mixed case, numbers, symbols).",
                    control_ref="CLD-AWS-03",
                )
            else:
                self.add_finding(
                    title="IAM password policy meets requirements",
                    description="Password policy enforces complexity requirements.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-03",
                )
        except iam.exceptions.NoSuchEntityException:
            self.add_finding(
                title="No IAM password policy configured",
                description="Account has no custom password policy.",
                severity=Severity.HIGH, status=ControlStatus.FAIL,
                recommendation="Create an IAM password policy.",
                control_ref="CLD-AWS-03",
            )
        except (BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="Cannot check IAM password policy",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AWS-03",
            )

    # ------------------------------------------------------------------
    # S3
    # ------------------------------------------------------------------
    def _check_s3_public_access(self):
        try:
            s3 = self._client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            public_buckets = []
            for bucket in buckets:
                name = bucket["Name"]
                try:
                    pub = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                    if not all([
                        pub.get("BlockPublicAcls"),
                        pub.get("IgnorePublicAcls"),
                        pub.get("BlockPublicPolicy"),
                        pub.get("RestrictPublicBuckets"),
                    ]):
                        public_buckets.append(name)
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                        public_buckets.append(name)

            if public_buckets:
                self.add_finding(
                    title=f"{len(public_buckets)} S3 bucket(s) lack full public access block",
                    description=f"Buckets: {', '.join(public_buckets[:10])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enable S3 Block Public Access on all buckets.",
                    control_ref="CLD-AWS-04",
                )
            else:
                self.add_finding(
                    title="All S3 buckets have public access blocked",
                    description=f"Checked {len(buckets)} bucket(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-04",
                )
        except (BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="Cannot check S3 bucket security",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AWS-04",
            )

    # ------------------------------------------------------------------
    # Security Groups
    # ------------------------------------------------------------------
    def _check_security_groups(self):
        try:
            ec2 = self._client("ec2")
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            wide_open = []
            for sg in sgs:
                for perm in sg.get("IpPermissions", []):
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            port = perm.get("FromPort", "all")
                            if port in (22, 3389, -1, 0) or perm.get("IpProtocol") == "-1":
                                wide_open.append(f"{sg['GroupId']}:{port}")

            if wide_open:
                self.add_finding(
                    title=f"{len(wide_open)} security group rule(s) allow unrestricted access",
                    description=f"Rules: {', '.join(wide_open[:10])}",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Restrict security group rules to specific IPs/CIDRs.",
                    control_ref="CLD-AWS-05",
                )
            else:
                self.add_finding(
                    title="No unrestricted security group rules found",
                    description=f"Checked {len(sgs)} security groups.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-05",
                )
        except (BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="Cannot check security groups",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AWS-05",
            )

    # ------------------------------------------------------------------
    # CloudTrail
    # ------------------------------------------------------------------
    def _check_cloudtrail(self):
        try:
            ct = self._client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            if not trails:
                self.add_finding(
                    title="No CloudTrail trails configured",
                    description="No AWS CloudTrail is enabled.",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Enable CloudTrail with multi-region logging.",
                    control_ref="CLD-AWS-06",
                )
                return

            multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
            logging_active = False
            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging"):
                        logging_active = True
                        break
                except (BotoCoreError, ClientError):
                    pass

            if logging_active and multi_region:
                self.add_finding(
                    title="CloudTrail is active with multi-region logging",
                    description=f"{len(trails)} trail(s) configured.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-06",
                )
            elif logging_active:
                self.add_finding(
                    title="CloudTrail active but not multi-region",
                    description="Logging is on but not covering all regions.",
                    severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                    recommendation="Enable multi-region trails.",
                    control_ref="CLD-AWS-06",
                )
            else:
                self.add_finding(
                    title="CloudTrail logging is disabled",
                    description="All trails have logging turned off.",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Enable logging on CloudTrail.",
                    control_ref="CLD-AWS-06",
                )
        except (BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="Cannot check CloudTrail",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AWS-06",
            )

    # ------------------------------------------------------------------
    # KMS
    # ------------------------------------------------------------------
    def _check_kms_key_rotation(self):
        try:
            kms = self._client("kms")
            paginator = kms.get_paginator("list_keys")
            no_rotation = []
            total = 0
            for page in paginator.paginate():
                for key_meta in page["Keys"]:
                    key_id = key_meta["KeyId"]
                    try:
                        desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                        if desc.get("KeyManager") != "CUSTOMER":
                            continue
                        total += 1
                        rot = kms.get_key_rotation_status(KeyId=key_id)
                        if not rot.get("KeyRotationEnabled"):
                            no_rotation.append(key_id[:12])
                    except (BotoCoreError, ClientError):
                        pass

            if no_rotation:
                self.add_finding(
                    title=f"{len(no_rotation)} KMS keys without automatic rotation",
                    description=f"Keys: {', '.join(no_rotation[:5])}",
                    severity=Severity.HIGH, status=ControlStatus.FAIL,
                    recommendation="Enable automatic key rotation for all customer-managed KMS keys.",
                    control_ref="CLD-AWS-07",
                )
            elif total > 0:
                self.add_finding(
                    title="All customer KMS keys have rotation enabled",
                    description=f"Checked {total} key(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-07",
                )
            else:
                self.add_finding(
                    title="No customer-managed KMS keys found",
                    description="No customer KMS keys to check.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-07",
                )
        except (BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="Cannot check KMS key rotation",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AWS-07",
            )

    # ------------------------------------------------------------------
    # RDS
    # ------------------------------------------------------------------
    def _check_rds_public_access(self):
        try:
            rds = self._client("rds")
            instances = rds.describe_db_instances().get("DBInstances", [])
            public = [db["DBInstanceIdentifier"] for db in instances if db.get("PubliclyAccessible")]

            if public:
                self.add_finding(
                    title=f"{len(public)} RDS instance(s) publicly accessible",
                    description=f"Instances: {', '.join(public[:10])}",
                    severity=Severity.CRITICAL, status=ControlStatus.FAIL,
                    recommendation="Disable public accessibility on RDS instances.",
                    control_ref="CLD-AWS-08",
                )
            elif instances:
                self.add_finding(
                    title="No publicly accessible RDS instances",
                    description=f"Checked {len(instances)} instance(s).",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-08",
                )
            else:
                self.add_finding(
                    title="No RDS instances found",
                    description="No RDS databases to check.",
                    severity=Severity.INFO, status=ControlStatus.PASS,
                    control_ref="CLD-AWS-08",
                )
        except (BotoCoreError, ClientError) as exc:
            self.add_finding(
                title="Cannot check RDS instances",
                description=str(exc),
                severity=Severity.MEDIUM, status=ControlStatus.WARNING,
                control_ref="CLD-AWS-08",
            )
