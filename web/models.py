"""Database models for the IT Controls web dashboard."""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class TestRun(db.Model):
    __tablename__ = "test_runs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    passed = db.Column(db.Integer, default=0)
    failed = db.Column(db.Integer, default=0)
    warnings = db.Column(db.Integer, default=0)
    raw_json = db.Column(db.Text)

    findings = db.relationship("TestFinding", backref="test_run", lazy=True, cascade="all, delete-orphan")

    @property
    def overall_status(self):
        if self.failed > 0:
            return "FAIL"
        if self.warnings > 0:
            return "WARNING"
        return "PASS"

    @property
    def total_checks(self):
        return self.passed + self.failed + self.warnings


class TestFinding(db.Model):
    __tablename__ = "test_findings"

    id = db.Column(db.Integer, primary_key=True)
    test_run_id = db.Column(db.Integer, db.ForeignKey("test_runs.id"), nullable=False)
    control_ref = db.Column(db.String(20))
    title = db.Column(db.String(200))
    status = db.Column(db.String(20))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    remediation = db.Column(db.Text)
    category = db.Column(db.String(50))


class ScheduledJob(db.Model):
    __tablename__ = "scheduled_jobs"

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(100), unique=True)
    job_type = db.Column(db.String(20))
    schedule = db.Column(db.String(100))
    mode = db.Column(db.String(20))
    category = db.Column(db.String(50), nullable=True)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
