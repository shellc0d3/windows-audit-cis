# File: main.py

import argparse
import sys
import os

from parser import load_all_rules
from executor import execute_subrule
from evaluator import evaluate_rule
from reporter import (
    write_enhanced_json_report,
    write_enhanced_html_report
)

def main():
    parser = argparse.ArgumentParser(description="Windows CIS Scanner Audit")
    parser.add_argument("--rules", default="./rules/windows",
                        help="Directory containing .yml rule files")
    parser.add_argument("--json", default="./output/scan.json",
                        help="Path to JSON output file")
    parser.add_argument("--html", default="./output/report.html",
                        help="Path to HTML output file")
    parser.add_argument("--host", default="MyHost", help="Hostname override")
    parser.add_argument("--os", default="Windows 11", help="OS name override")
    parser.add_argument("--benchmark", default="",
                        help="(Optional) Benchmark name to display in reports")
    args = parser.parse_args()

    # 1. Load rules from .yml files
    try:
        all_rules = load_all_rules(args.rules)
    except Exception as e:
        print(f"Error loading rules: {e}")
        sys.exit(1)

    print(f"Loaded {len(all_rules)} rules from {args.rules}")

    # 2. Execute & Evaluate
    all_results = []
    for rule in all_rules:
        exec_results = []
        for sub_rule in rule.rules:
            r_exec = execute_subrule(sub_rule)
            exec_results.append(r_exec)

        # evaluate_rule() returns a RuleResult with original fields from the rule
        r_result = evaluate_rule(rule, exec_results)
        all_results.append(r_result)

    # 3. Summaries
    passed_count = sum(1 for r in all_results if r.status == "PASS")
    failed_count = len(all_results) - passed_count
    print(f"Passed: {passed_count}, Failed: {failed_count}")

    # 4. Ensure output folders exist
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    os.makedirs(os.path.dirname(args.html), exist_ok=True)

    # 5. Generate Enhanced JSON & HTML
    write_enhanced_json_report(
        results=all_results,
        host=args.host,
        os_name=args.os,
        passed_count=passed_count,
        failed_count=failed_count,
        json_path=args.json,
        benchmark_name=args.benchmark
    )

    write_enhanced_html_report(
        results=all_results,
        host=args.host,
        os_name=args.os,
        passed_count=passed_count,
        failed_count=failed_count,
        html_path=args.html,
        benchmark_name=args.benchmark
    )

    print(f"JSON report saved to: {args.json}")
    print(f"HTML report saved to: {args.html}")

    # 6. Exit code 1 if any checks fail
    if failed_count > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
