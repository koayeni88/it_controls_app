"""Flask application factory and routes for IT Controls dashboard."""

import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from web.models import db, TestRun, TestFinding, ScheduledJob
from engine.runner import TestRunner, TEST_CATEGORIES, ALL_TESTS
from engine.scheduler import ControlScheduler


scheduler = None


def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config["SECRET_KEY"] = "change-me-in-production"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///../instance/controls.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()

    global scheduler
    scheduler = ControlScheduler(db_session_factory=lambda: db.session)

    register_routes(app)

    return app


def register_routes(app):

    @app.route("/")
    def dashboard():
        latest_runs = TestRun.query.order_by(TestRun.timestamp.desc()).limit(10).all()
        latest = latest_runs[0] if latest_runs else None
        summary = None
        compliance = {}
        if latest and latest.raw_json:
            try:
                summary = json.loads(latest.raw_json)
                compliance = summary.get("compliance", {})
            except json.JSONDecodeError:
                pass
        return render_template(
            "dashboard.html",
            latest=latest,
            runs=latest_runs,
            summary=summary,
            compliance=compliance,
            categories=list(TEST_CATEGORIES.keys()),
            tests=list(ALL_TESTS.keys()),
        )

    @app.route("/run", methods=["POST"])
    def run_tests():
        mode = request.form.get("mode", "all")
        category = request.form.get("category")
        test_name = request.form.get("test_name")

        runner = TestRunner()
        if mode == "cloud_all":
            runner.run_categories(["cloud_aws", "cloud_azure", "cloud_gcp"])
        elif mode == "category" and category:
            runner.run_category(category)
        elif mode == "single" and test_name:
            runner.run_single(test_name)
        else:
            runner.run_all()

        summary = runner.get_summary()
        run = TestRun(
            passed=summary["total_passed"],
            failed=summary["total_failed"],
            warnings=summary["total_warnings"],
            raw_json=json.dumps(summary, default=str),
        )
        db.session.add(run)
        db.session.flush()

        for result_data in summary.get("results", []):
            for finding in result_data.get("findings", []):
                tf = TestFinding(
                    test_run_id=run.id,
                    control_ref=finding.get("control_ref", ""),
                    title=finding.get("title", ""),
                    status=finding.get("status", ""),
                    severity=finding.get("severity", ""),
                    description=finding.get("description", ""),
                    remediation=finding.get("recommendation", ""),
                    category=result_data.get("category", ""),
                )
                db.session.add(tf)

        db.session.commit()
        runner.save_results()
        flash(f"Test run completed: {summary['total_passed']} passed, {summary['total_failed']} failed, {summary['total_warnings']} warnings", "success")
        return redirect(url_for("results", run_id=run.id))

    @app.route("/results/<int:run_id>")
    def results(run_id):
        run = TestRun.query.get_or_404(run_id)
        summary = None
        compliance = {}
        if run.raw_json:
            try:
                summary = json.loads(run.raw_json)
                compliance = summary.get("compliance", {})
            except json.JSONDecodeError:
                pass
        return render_template(
            "results.html",
            run=run,
            summary=summary,
            compliance=compliance,
            findings=run.findings,
        )

    @app.route("/schedule", methods=["GET", "POST"])
    def schedule():
        if request.method == "POST":
            action = request.form.get("action")
            if action == "add":
                sched_type = request.form.get("type", "interval")
                mode = request.form.get("mode", "all")
                category = request.form.get("category")
                if sched_type == "interval":
                    hours = int(request.form.get("hours", 24))
                    if mode == "category" and category:
                        scheduler.schedule_category(category, hours=hours)
                        job_id = f"category_{category}"
                    else:
                        scheduler.schedule_full_scan(hours=hours)
                        job_id = "full_scan"
                    sj = ScheduledJob(job_id=job_id, job_type="interval", schedule=f"Every {hours}h", mode=mode, category=category)
                    db.session.merge(sj)
                    db.session.commit()
                    flash(f"Scheduled {mode} scan every {hours} hours", "success")
                elif sched_type == "cron":
                    cron_expr = request.form.get("cron", "0 2 * * *")
                    scheduler.schedule_cron(cron_expr, mode=mode, category=category)
                    job_id = f"cron_{mode}_{cron_expr.replace(' ', '_')}"
                    sj = ScheduledJob(job_id=job_id, job_type="cron", schedule=cron_expr, mode=mode, category=category)
                    db.session.merge(sj)
                    db.session.commit()
                    flash(f"Scheduled cron job: {cron_expr}", "success")
            elif action == "remove":
                job_id = request.form.get("job_id")
                if job_id:
                    try:
                        scheduler.remove_job(job_id)
                    except Exception:
                        pass
                    ScheduledJob.query.filter_by(job_id=job_id).delete()
                    db.session.commit()
                    flash(f"Removed job: {job_id}", "info")
            elif action == "start":
                scheduler.start()
                flash("Scheduler started", "success")

            return redirect(url_for("schedule"))

        jobs = scheduler.get_jobs() if scheduler.scheduler.running else []
        saved_jobs = ScheduledJob.query.all()
        return render_template(
            "schedule.html",
            jobs=jobs,
            saved_jobs=saved_jobs,
            categories=list(TEST_CATEGORIES.keys()),
            scheduler_running=scheduler.scheduler.running if scheduler else False,
        )

    # --- API routes ---

    @app.route("/api/results/latest")
    def api_latest():
        latest = TestRun.query.order_by(TestRun.timestamp.desc()).first()
        if not latest or not latest.raw_json:
            return jsonify({"error": "No results found"}), 404
        return jsonify(json.loads(latest.raw_json))

    @app.route("/api/run", methods=["POST"])
    def api_run():
        data = request.get_json(silent=True) or {}
        mode = data.get("mode", "all")
        category = data.get("category")
        runner = TestRunner()
        if mode == "category" and category:
            runner.run_category(category)
        else:
            runner.run_all()
        summary = runner.get_summary()
        run = TestRun(
            passed=summary["total_passed"],
            failed=summary["total_failed"],
            warnings=summary["total_warnings"],
            raw_json=json.dumps(summary, default=str),
        )
        db.session.add(run)
        db.session.commit()
        return jsonify(summary)

    @app.route("/api/export/<int:run_id>")
    def api_export(run_id):
        run = TestRun.query.get_or_404(run_id)
        if not run.raw_json:
            return jsonify({"error": "No data"}), 404
        return jsonify(json.loads(run.raw_json))
