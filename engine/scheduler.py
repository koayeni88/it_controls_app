"""Scheduler for automated control test execution."""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from engine.runner import TestRunner


class ControlScheduler:
    def __init__(self, config=None, db_session_factory=None):
        self.scheduler = BackgroundScheduler()
        self.config = config or {}
        self.db_session_factory = db_session_factory
        self.jobs = {}

    def start(self):
        if not self.scheduler.running:
            self.scheduler.start()

    def shutdown(self):
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def schedule_full_scan(self, hours=24, job_id="full_scan"):
        job = self.scheduler.add_job(
            self._run_and_save,
            trigger=IntervalTrigger(hours=hours),
            kwargs={"mode": "all"},
            id=job_id,
            replace_existing=True,
            name=f"Full scan every {hours}h",
        )
        self.jobs[job_id] = {"type": "interval", "hours": hours, "mode": "all"}
        return job

    def schedule_category(self, category, hours=12, job_id=None):
        job_id = job_id or f"category_{category}"
        job = self.scheduler.add_job(
            self._run_and_save,
            trigger=IntervalTrigger(hours=hours),
            kwargs={"mode": "category", "category": category},
            id=job_id,
            replace_existing=True,
            name=f"{category} scan every {hours}h",
        )
        self.jobs[job_id] = {"type": "interval", "hours": hours, "mode": "category", "category": category}
        return job

    def schedule_cron(self, cron_expr, mode="all", category=None, job_id=None):
        parts = cron_expr.split()
        if len(parts) != 5:
            raise ValueError("Cron expression must have 5 parts: minute hour day month day_of_week")
        trigger = CronTrigger(
            minute=parts[0], hour=parts[1], day=parts[2], month=parts[3], day_of_week=parts[4]
        )
        job_id = job_id or f"cron_{mode}_{cron_expr.replace(' ', '_')}"
        job = self.scheduler.add_job(
            self._run_and_save,
            trigger=trigger,
            kwargs={"mode": mode, "category": category},
            id=job_id,
            replace_existing=True,
            name=f"Cron: {cron_expr}",
        )
        self.jobs[job_id] = {"type": "cron", "expression": cron_expr, "mode": mode}
        return job

    def remove_job(self, job_id):
        self.scheduler.remove_job(job_id)
        self.jobs.pop(job_id, None)

    def get_jobs(self):
        return [
            {"id": job.id, "name": job.name, "next_run": str(job.next_run_time)}
            for job in self.scheduler.get_jobs()
        ]

    def _run_and_save(self, mode="all", category=None):
        runner = TestRunner(config=self.config)
        if mode == "all":
            runner.run_all()
        elif mode == "category" and category:
            runner.run_category(category)
        filepath = runner.save_results()
        if self.db_session_factory:
            self._persist_to_db(runner)
        return filepath

    def _persist_to_db(self, runner):
        try:
            from web.models import db, TestRun
            import json

            session = self.db_session_factory()
            summary = runner.get_summary()
            run = TestRun(
                passed=summary["total_passed"],
                failed=summary["total_failed"],
                warnings=summary["total_warnings"],
                raw_json=json.dumps(summary, default=str),
            )
            session.add(run)
            session.commit()
        except Exception as e:
            print(f"[Scheduler] DB persist error: {e}")
