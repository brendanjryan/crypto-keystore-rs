#!/usr/bin/env python3
"""Require 95% source-branch coverage, merging Rust generic instantiations."""
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text())
branches = {}
# LLVM summaries disagree across generic instantiations: cargo-llvm-cov issue #394.
for file in report["data"][0]["files"]:
    for branch in file["branches"]:
        hits = branches.setdefault((file["filename"], *branch[:4]), [False, False])
        hits[0] |= branch[4] > 0
        hits[1] |= branch[5] > 0
count = 2 * len(branches)
covered = sum(sum(hits) for hits in branches.values())
if count == 0:
    sys.exit("No branches instrumented; run cargo llvm-cov with --branch on nightly")
print(f"Source-branch coverage: {covered}/{count} ({100 * covered / count:.2f}%)")
if 100 * covered < 95 * count:
    sys.exit("Branch coverage is below 95%")
