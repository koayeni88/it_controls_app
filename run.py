#!/usr/bin/env python3
"""Entry point for the IT Controls Testing & Automation Platform."""

import argparse
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_web(host="127.0.0.1", port=5000, debug=True):
    """Start the Flask web dashboard."""
    from web.app import create_app
    app = create_app()
    print(f"\n  IT Controls Dashboard: http://{host}:{port}\n")
    app.run(host=host, port=port, debug=debug)


def run_cli(args):
    """Run control tests from the command line."""
    from engine.runner import TestRunner, TEST_CATEGORIES, ALL_TESTS

    runner = TestRunner()

    if args.mode == "all":
        print("Running all IT control tests...\n")
        runner.run_all()
    elif args.mode == "category":
        if not args.category:
            print(f"Error: --category required. Options: {list(TEST_CATEGORIES.keys())}")
            sys.exit(1)
        print(f"Running {args.category} tests...\n")
        runner.run_category(args.category)
    elif args.mode == "single":
        if not args.test:
            print(f"Error: --test required. Options: {list(ALL_TESTS.keys())}")
            sys.exit(1)
        print(f"Running {args.test}...\n")
        runner.run_single(args.test)

    summary = runner.get_summary()

    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(f"{'='*60}")
        print(f" IT Controls Test Report")
        print(f"{'='*60}")
        print(f" Status:   {summary['overall_status']}")
        print(f" Passed:   {summary['total_passed']}")
        print(f" Failed:   {summary['total_failed']}")
        print(f" Warnings: {summary['total_warnings']}")
        print(f"{'='*60}\n")

        for result in summary["results"]:
            status_icon = {"PASS": "[PASS]", "FAIL": "[FAIL]", "WARNING": "[WARN]"}.get(result["overall_status"].upper(), "[????]")
            print(f" {status_icon} {result['test_name']} ({result['category']})")
            for finding in result["findings"]:
                f_icon = {"pass": "  +", "fail": "  X", "warning": "  !"}.get(finding["status"], "  ?")
                print(f"   {f_icon} [{finding['control_ref']}] {finding['title']}: {finding['description']}")
                if finding.get("recommendation") and finding["status"] != "pass":
                    print(f"     Remediation: {finding['recommendation']}")
            print()

        # Compliance summary
        if summary.get("compliance"):
            print(f"{'='*60}")
            print(f" Compliance Summary")
            print(f"{'='*60}")
            for fw_key, fw in summary["compliance"].items():
                print(f"  {fw['name']}: {fw['compliance_pct']}% ({fw['passed']}/{fw['total']} controls)")
            print()

    if args.save:
        filepath = runner.save_results()
        print(f"Report saved to: {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description="IT Controls Testing & Automation Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          Start the web dashboard
  python run.py cli --mode all           Run all tests via CLI
  python run.py cli --mode category --category access
  python run.py cli --mode single --test firewall --json
  python run.py cli --mode all --save    Run all and save report
        """,
    )
    subparsers = parser.add_subparsers(dest="command")

    # Web command (default)
    web_parser = subparsers.add_parser("web", help="Start web dashboard")
    web_parser.add_argument("--host", default="127.0.0.1")
    web_parser.add_argument("--port", type=int, default=5000)

    # CLI command
    cli_parser = subparsers.add_parser("cli", help="Run tests from CLI")
    cli_parser.add_argument("--mode", choices=["all", "category", "single"], default="all")
    cli_parser.add_argument("--category", help="Category to test")
    cli_parser.add_argument("--test", help="Single test to run")
    cli_parser.add_argument("--json", action="store_true", help="Output as JSON")
    cli_parser.add_argument("--save", action="store_true", help="Save report to file")

    args = parser.parse_args()

    if args.command == "cli":
        run_cli(args)
    else:
        run_web()


if __name__ == "__main__":
    main()
