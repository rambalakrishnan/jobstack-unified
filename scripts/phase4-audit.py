#!/usr/bin/env python3
"""Phase 4 pre-flight audit. Deterministic. Exit 0 = green, exit 1 = blocked."""
import json, re, sys
from pathlib import Path

ROOT = Path.cwd()
results = []

def check(num, name, ok, detail=""):
    results.append((num, name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {num:02d} {name}{(' — ' + detail) if detail else ''}")

def file_contains(path, pattern):
    p = ROOT / path
    return bool(re.search(pattern, p.read_text())) if p.exists() else False

# --- Phase 3 script fixes ---
check(1, "case regex in verify_dag.py",
      file_contains("scripts/verify_dag.py", r"\(\?:C\|T\)\[0-9\]\{2,3\}"))
check(2, "case regex in unpack_dag.py",
      file_contains("scripts/unpack_dag.py", r"\(\?:C\|T\)\[0-9\]\{2,3\}"))
check(3, "coverage_mode in verify_dag.py",
      file_contains("scripts/verify_dag.py", r"coverage_mode"))
check(4, "safe_load_all in unpack_dag.py",
      file_contains("scripts/unpack_dag.py", r"safe_load_all"))
check(5, "single-quote frontmatter",
      file_contains("scripts/unpack_dag.py", r"verification_command:\s*'"))
check(6, "EXPECTED_LANG in verify_dag.py",
      file_contains("scripts/verify_dag.py", r"EXPECTED_LANG"))
check(7, "INVARIANT_PREFIXES in verify_dag.py",
      file_contains("scripts/verify_dag.py", r"INVARIANT_PREFIXES"))
check(8, "ALLOWED_VERIFICATION_TOOLS",
      file_contains("scripts/verify_dag.py", r"ALLOWED_VERIFICATION_TOOLS"))
check(9, "transform_rust_verification present",
      file_contains("scripts/unpack_dag.py", r"def transform_rust_verification"))

# --- Ringmaster filter fix (the critical one) ---
rm_specs = list((ROOT / "subsystems/ringmaster/modules").glob("*/.omp-spec.md"))
hyphenated = []
for spec in rm_specs:
    for line in spec.read_text().splitlines():
        if line.startswith("verification_command:") and " -- " in line:
            tail = line.split(" -- ", 1)[1].strip().strip('"').strip("'")
            for tok in tail.split():
                if not tok.startswith("--") and "-" in tok:
                    hyphenated.append((spec.parent.name, tok))
                    break
check(10, "ringmaster filters underscored",
      len(hyphenated) == 0,
      f"{len(hyphenated)} modules: {hyphenated[:3]}" if hyphenated else "")

# --- Phase 3 audits present ---
missing = []
for s in ["crawler", "ringmaster", "hellscape", "job-hunter"]:
    p = ROOT / f"subsystems/{s}/phase3_audit.json"
    if not p.exists() or not json.load(open(p)).get("phase3_complete"):
        missing.append(s)
check(11, "all 4 phase3_audit.json complete", not missing, str(missing))

# --- Classification count ---
c = json.load(open(ROOT / "subsystems/classification-final.json"))
non_circus = [x for x in c["classifications"] if x["subsystem"] != "circus-tent"]
check(12, "119 non-circus modules classified",
      len(non_circus) == 119, f"{len(non_circus)} found")

# --- BO-THREAD dereferenced (not "See contracts") ---
# --- Extended: no invariant anywhere should be a placeholder ---
INVARIANT_REF = re.compile(r"^- \*\*\[((?:EK|OWD|EXT|LIFE|BO|CF)-[A-Z0-9_\-]+)\]: (.+)$")
underef = []
for s in ["crawler", "ringmaster", "hellscape", "job-hunter"]:
    mod_dir = ROOT / f"subsystems/{s}/modules"
    if not mod_dir.exists():
        continue
    for spec in mod_dir.glob("*/.omp-spec.md"):
        for line in spec.read_text().splitlines():
            m = INVARIANT_REF.match(line)
            if m and m.group(2).strip() == "See contracts.":
                underef.append((s, spec.parent.name, m.group(1)))

check(13, "all invariants dereferenced across all subsystems",
      len(underef) == 0,
      f"{len(underef)} underef: {underef[:5]}" if underef else "")
if underef:
    print(f"    Undereferenced IDs: {sorted(set(u[2] for u in underef))}")

# --- Hellscape assertion duplication (NEW) ---
# Distinguish invariants (contract-prefixed) from assertions (prose or case IDs).
INVARIANT_PREFIX = re.compile(r"^- \*\*\[(EK|OWD|EXT|LIFE|BO|CF)-")
assertion_lines = {}
dup_assertions = []
for spec in (ROOT / "subsystems/hellscape/modules").glob("*/.omp-spec.md"):
    in_assertion_section = False
    for line in spec.read_text().splitlines():
        if line.strip() == "### Conformance Assertions":
            in_assertion_section = True
            continue
        if line.strip().startswith("##") or line.strip().startswith("# "):
            in_assertion_section = False
            continue
        if not in_assertion_section:
            continue
        if line.startswith("- ") and not INVARIANT_PREFIX.match(line):
            assertion_lines.setdefault(line, []).append(spec.parent.name)

for line, modules in assertion_lines.items():
    if len(modules) > 1:
        dup_assertions.append({"assertion": line[:100], "modules": modules})

check(14, "hellscape no duplicate assertions",
      len(dup_assertions) == 0,
      f"{len(dup_assertions)} duplicates" if dup_assertions else "")
if dup_assertions:
    for d in dup_assertions[:5]:
        print(f"    DUPLICATE: {d['modules']}: {d['assertion']}")
    if len(dup_assertions) > 5:
        print(f"    ... and {len(dup_assertions)-5} more")

# --- Job-hunter assertion duplication (same class of check) ---
assertion_lines_jh = {}
dup_jh = []
for spec in (ROOT / "subsystems/job-hunter/modules").glob("*/.omp-spec.md"):
    in_assertion_section = False
    for line in spec.read_text().splitlines():
        if line.strip() == "### Conformance Assertions":
            in_assertion_section = True
            continue
        if line.strip().startswith("##") or line.strip().startswith("# "):
            in_assertion_section = False
            continue
        if not in_assertion_section:
            continue
        if line.startswith("- ") and not INVARIANT_PREFIX.match(line):
            assertion_lines_jh.setdefault(line, []).append(spec.parent.name)

for line, modules in assertion_lines_jh.items():
    if len(modules) > 1:
        dup_jh.append({"assertion": line[:100], "modules": modules})

check(15, "job-hunter no duplicate assertions",
      len(dup_jh) == 0,
      f"{len(dup_jh)} duplicates" if dup_jh else "")

# --- Report ---
print()
failed = [r for r in results if not r[2]]
if failed:
    print(f"{len(failed)} of {len(results)} checks FAILED — do not proceed")
    sys.exit(1)
print(f"All {len(results)} checks pass — Phase 4 ready")
