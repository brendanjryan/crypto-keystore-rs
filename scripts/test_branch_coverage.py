import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class BranchCoverageGate(unittest.TestCase):
    def test_threshold_and_generic_instantiations(self):
        cases = [("empty", [], False)]
        for covered in [18, 19, 20]:
            branches = [
                [i, 1, i, 2, int(2 * i < covered), int(2 * i + 1 < covered)]
                for i in range(10)
            ]
            cases.append((str(covered), branches, covered >= 19))
        cases += [
            ("complementary instances", [[1, 1, 1, 2, 1, 0], [1, 1, 1, 2, 0, 1]], True),
            ("duplicate misses", [[1, 1, 1, 2, 1, 0]] * 20, False),
            ("distinct sites", [[1, 1, 1, 2, 1, 0], [2, 1, 2, 2, 0, 1]], False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "coverage.json"
            for name, branches, passes in cases:
                with self.subTest(name=name):
                    report.write_text(json.dumps({"data": [{"files": [
                        {"filename": "src/lib.rs", "branches": branches}
                    ]}]}))
                    result = subprocess.run(
                        [sys.executable, str(Path(__file__).with_name("check-branch-coverage.py")), str(report)],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode == 0, passes, result.stderr)
