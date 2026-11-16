#!/usr/bin/env python3
"""Prove unpack_dag.py produces correct output. Deterministic. Exit 0 = correct.

This test does NOT trust the unpack script's self-report. It reads the
produced .omp-spec.md files and checks they contain what they must,
using ground-truth data from the contracts and seam mappings.
"""
import re
import sys
import yaml
from pathlib import Path

ROOT = Path.cwd()
SUBSYSTEMS = ["crawler", "ringmaster", "hellscape", "job-hunter"]
FAILURES = []

def fail(msg):
    FAILURES.append(msg)
    print(f"[FAIL] {msg}")

def pass_(msg):
    print(f"[PASS] {msg}")

# --- Ground truth: scan all contracts for invariant definitions ---
def scan_for_rules(node):
    if isinstance(node, dict):
        if "id" in node and "rule" in node:
            yield node
        else:
            for v in node.values():
                yield from scan_for_rules(v)
    elif isinstance(node, list):
        for item in node:
            yield from scan_for_rules(item)

true_invariants = {}
for cf in (ROOT / "contracts").glob("*.yaml"):
    for doc in yaml.safe_load_all(cf.read_text(encoding="utf-8")):
        for r in scan_for_rules(doc):
            true_invariants[r["id"]] = r["rule"].strip()
print(f"Ground truth: {len(true_invariants)} invariant definitions found in contracts")

# --- Positive control: the test can detect the known-bad pattern ---
REF = re.compile(r"^- \*\*\[([A-Z0-9_-]+)\]\*\*: (.+)$")
test_bad = "- **[BO-THREAD]**: See contracts."
test_good = "- **[BO-THREAD]**: Allocate, enter, reset, and destroy..."
if not REF.match(test_bad):
    print("[FATAL] Positive control failed — regex cannot match placeholder format")
    sys.exit(2)
if not REF.match(test_good):
    print("[FATAL] Positive control failed — regex cannot match good format")
    sys.exit(2)
print("[PASS] Positive control: regex matches both placeholder and good format")

# --- For each subsystem, verify all spec invariants are dereferenced correctly ---
for subsystem in SUBSYSTEMS:
    mod_dir = ROOT / f"subsystems/{subsystem}/modules"
    if not mod_dir.exists():
        fail(f"{subsystem}: modules directory missing")
        continue
    spec_count = 0
    placeholder_count = 0
    wrong_text_count = 0
    for spec in mod_dir.glob("*/.omp-spec.md"):
        spec_count += 1
        for line in spec.read_text().splitlines():
            m = REF.match(line)
            if not m:
                continue
            inv_id, text = m.group(1), m.group(2).strip()
            if text == "See contracts.":
                placeholder_count += 1
                fail(f"{subsystem}/{spec.parent.name}: {inv_id} is placeholder")
                continue
            # Verify the text matches the contract's definition
            expected = true_invariants.get(inv_id)
            if expected and expected != text:
                wrong_text_count += 1
                fail(f"{subsystem}/{spec.parent.name}: {inv_id} text mismatch")
    if placeholder_count == 0 and wrong_text_count == 0:
        pass_(f"{subsystem}: {spec_count} specs, all invariants dereferenced correctly")

if FAILURES:
    print(f"\n{len(FAILURES)} failures — unpack output is NOT correct")
    sys.exit(1)
print("\nAll spec invariants are correctly dereferenced")
sys.exit(0)
