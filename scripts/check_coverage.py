#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Check coverage thresholds and exit with non-zero if not met.
Parses coverage.xml to extract line and branch coverage percentages.

Usage:
    python scripts/check_coverage.py [--line-min 70] [--branch-min 55]

Defaults: --line-min 70 --branch-min 48 (baseline; goal is 55)
"""
from __future__ import absolute_import, division, print_function

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_coverage_xml(path):
    """Parse coverage.xml and return (line_rate, branch_rate) as floats 0-1."""
    tree = ET.parse(path)
    root = tree.getroot()
    # Coverage XML format: root has attributes line-rate, branch-rate
    line_rate = float(root.get("line-rate", 0))
    branch_rate = float(root.get("branch-rate", 0))
    return line_rate, branch_rate


def main():
    parser = argparse.ArgumentParser(description="Check coverage thresholds")
    parser.add_argument(
        "--line-min",
        type=float,
        default=70,
        help="Minimum line coverage %% (default: 70)",
    )
    parser.add_argument(
        "--branch-min",
        type=float,
        default=48,
        help="Minimum branch coverage %% (default: 48; goal 55)",
    )
    parser.add_argument(
        "--coverage-xml",
        type=Path,
        default=Path("coverage.xml"),
        help="Path to coverage.xml (default: coverage.xml)",
    )
    args = parser.parse_args()

    if not args.coverage_xml.exists():
        print(f"Error: {args.coverage_xml} not found.", file=sys.stderr)
        sys.exit(1)

    line_rate, branch_rate = parse_coverage_xml(args.coverage_xml)
    line_pct = line_rate * 100
    branch_pct = branch_rate * 100

    print(f"Line coverage:   {line_pct:.1f}% (min: {args.line_min}%)")
    print(f"Branch coverage: {branch_pct:.1f}% (min: {args.branch_min}%)")

    failed = False
    if line_pct < args.line_min:
        print(f"FAIL: Line coverage {line_pct:.1f}% is below {args.line_min}%", file=sys.stderr)
        failed = True
    if branch_pct < args.branch_min:
        print(f"FAIL: Branch coverage {branch_pct:.1f}% is below {args.branch_min}%", file=sys.stderr)
        failed = True

    if failed:
        sys.exit(1)
    print("Coverage thresholds met.")
    sys.exit(0)


if __name__ == "__main__":
    main()
