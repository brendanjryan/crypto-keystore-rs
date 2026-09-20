#!/usr/bin/env python3
"""Require at least 95% of instrumented production branches to be covered."""
import json
from pathlib import Path
import sys

branches = json.loads(Path(sys.argv[1]).read_text())["data"][0]["totals"]["branches"]
count, covered = branches["count"], branches["covered"]
if count == 0:
    sys.exit("No branches instrumented; run cargo llvm-cov with --branch on nightly")
print(f"Branch coverage: {covered}/{count} ({100 * covered / count:.2f}%)")
if 100 * covered < 95 * count:
    sys.exit("Branch coverage is below 95%")
