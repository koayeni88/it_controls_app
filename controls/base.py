"""Base classes for IT control tests."""

import datetime
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ControlStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


class ControlCategory(Enum):
    ACCESS = "Access Control"
    NETWORK = "Network Security"
    SYSTEM = "System Configuration"
    DATA = "Data Protection"
    CHANGE_MGMT = "Change Management"
    COMPLIANCE = "Compliance"
    CLOUD_AWS = "AWS Cloud Security"
    CLOUD_AZURE = "Azure Cloud Security"
    CLOUD_GCP = "GCP Cloud Security"


@dataclass
class Finding:
    """A single finding from a control test."""
    title: str
    description: str
    severity: Severity
    status: ControlStatus
    recommendation: str = ""
    evidence: str = ""
    control_ref: str = ""
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)

    def to_dict(self):
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "control_ref": self.control_ref,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ControlTestResult:
    """Result of running a control test suite."""
    test_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    test_name: str = ""
    category: ControlCategory = ControlCategory.ACCESS
    description: str = ""
    findings: list = field(default_factory=list)
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    overall_status: ControlStatus = ControlStatus.SKIPPED

    @property
    def pass_count(self):
        return sum(1 for f in self.findings if f.status == ControlStatus.PASS)

    @property
    def fail_count(self):
        return sum(1 for f in self.findings if f.status == ControlStatus.FAIL)

    @property
    def warning_count(self):
        return sum(1 for f in self.findings if f.status == ControlStatus.WARNING)

    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0

    def compute_overall_status(self):
        if any(f.status == ControlStatus.FAIL and f.severity in (Severity.CRITICAL, Severity.HIGH)
               for f in self.findings):
            self.overall_status = ControlStatus.FAIL
        elif any(f.status == ControlStatus.FAIL for f in self.findings):
            self.overall_status = ControlStatus.WARNING
        elif any(f.status == ControlStatus.WARNING for f in self.findings):
            self.overall_status = ControlStatus.WARNING
        elif self.findings:
            self.overall_status = ControlStatus.PASS
        else:
            self.overall_status = ControlStatus.SKIPPED

    def to_dict(self):
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "category": self.category.value,
            "description": self.description,
            "overall_status": self.overall_status.value,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "warning_count": self.warning_count,
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "findings": [f.to_dict() for f in self.findings],
        }


class BaseControlTest(ABC):
    """Abstract base class for all control tests."""

    def __init__(self):
        self.result = ControlTestResult()
        self.result.test_name = self.name
        self.result.category = self.category
        self.result.description = self.description

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def category(self) -> ControlCategory:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @abstractmethod
    def run_tests(self) -> ControlTestResult:
        pass

    def execute(self) -> ControlTestResult:
        self.result = ControlTestResult()
        self.result.test_name = self.name
        self.result.category = self.category
        self.result.description = self.description
        self.result.started_at = datetime.datetime.now()
        try:
            self.run_tests()
        except Exception as e:
            self.result.findings.append(Finding(
                title=f"Test execution error: {self.name}",
                description=str(e),
                severity=Severity.HIGH,
                status=ControlStatus.ERROR,
                recommendation="Investigate the test error and verify system connectivity.",
            ))
        self.result.completed_at = datetime.datetime.now()
        self.result.compute_overall_status()
        return self.result

    def add_finding(self, title, description, severity, status,
                    recommendation="", evidence="", control_ref=""):
        self.result.findings.append(Finding(
            title=title,
            description=description,
            severity=severity,
            status=status,
            recommendation=recommendation,
            evidence=evidence,
            control_ref=control_ref,
        ))
