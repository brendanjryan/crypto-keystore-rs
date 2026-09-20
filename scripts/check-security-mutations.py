#!/usr/bin/env python3
"""Verify security regressions are caught, using a disposable source copy."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    ("constant-salt", "randomness", "rng.fill_bytes(&mut bytes);\n        bytes",
     "rng.fill_bytes(&mut bytes); if len == 32 { bytes.fill(0); }\n        bytes"),
    ("constant-nonce", "randomness", "rng.fill_bytes(&mut bytes);\n        bytes",
     "rng.fill_bytes(&mut bytes); if len == 12 { bytes.fill(0); }\n        bytes"),
    ("ignored-legacy-mac", "legacy_integrity",
     "if !bool::from(computed_mac.ct_eq(&expected_mac_bytes)) {", "if false {"),
    ("missing-authenticated-metadata", "authenticated_format",
     "&keystore.authenticated_metadata()?,", "&[],"),
    ("unbounded-json", "input_size", "if json.len() > limits.max_input_bytes {", "if false {"),
    ("relaxed-kdf-budget", "kdf_limits", "*c <= limits.max_pbkdf2_iterations",
     "*c <= limits.max_pbkdf2_iterations.saturating_add(1)"),
    ("skipped-version-check", "version_validation", "KeystoreVersion::from_u32(version)?;", ""),
]


def main():
    output = ROOT / "security-mutations.out"
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="keystore-mutations-") as temp:
        work = Path(temp) / "source"
        shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
            ".git", "target", "mutants.out", "mutants.out.old", "security-mutations.out", "artifacts", "coverage"))
        source = work / "src" / "keystore.rs"
        original = source.read_text()
        tests = sorted({test for _, test, _, _ in MUTATIONS})
        command = ["cargo", "test", "--release", "--all-features"]
        for test in tests:
            command += ["--test", test]
        with (output / "baseline.log").open("w") as log:
            subprocess.run(command, cwd=work, stdout=log, stderr=subprocess.STDOUT,
                           timeout=600, check=True)
        for name, test, before, after in MUTATIONS:
            expected_matches = 2 if name == "missing-authenticated-metadata" else 1
            if original.count(before) != expected_matches:
                raise RuntimeError(f"{name}: mutation anchor changed; update the case")
            source.write_text(original.replace(before, after))
            command = ["cargo", "test", "--release", "--all-features", "--test", test]
            with (output / f"{name}-build.log").open("w") as log:
                subprocess.run(command + ["--no-run"], cwd=work, stdout=log,
                               stderr=subprocess.STDOUT, timeout=300, check=True)
            result = subprocess.run(command, cwd=work, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=120)
            (output / f"{name}.log").write_text(result.stdout)
            caught = result.returncode == 101 and "test result: FAILED" in result.stdout
            results.append({"mutation": name, "caught": caught})
            (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            print(f"{name}: {'caught' if caught else 'NOT CAUGHT'}", flush=True)
            if not caught:
                raise RuntimeError(f"{name}: did not fail an assertion; see {output}")
    print(f"All {len(results)} security mutations caught.")


if __name__ == "__main__":
    main()
