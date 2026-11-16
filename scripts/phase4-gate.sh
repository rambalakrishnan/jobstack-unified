#!/usr/bin/env bash
set -euo pipefail
fail() { echo "[FAIL] $1"; exit 1; }

# 1. Ringmaster filter hyphens
hyphenated=$(grep -h "verification_command:" subsystems/ringmaster/modules/*/.omp-spec.md 2>/dev/null \
    | grep -cE -- '--.*rm-[0-9]' || true)
[ "$hyphenated" -eq 0 ] || fail "ringmaster hyphenated test filters: $hyphenated"

# 2. Placeholders — pilot subsystems only (circus-tent deferred); substring match, no regex, cannot lie
placeholders=$(grep -rn "See contracts" subsystems/{crawler,ringmaster,hellscape,job-hunter}/modules/*/.omp-spec.md 2>/dev/null | wc -l || true)
[ "$placeholders" -eq 0 ] || fail "undereferenced invariants: $placeholders (run: grep -rn 'See contracts' subsystems/{crawler,ringmaster,hellscape,job-hunter}/modules/*/.omp-spec.md)"

# 3. Phase 3 audits
for s in crawler ringmaster hellscape job-hunter; do
    python3 -c "import json; d=json.load(open('subsystems/$s/phase3_audit.json')); assert d['phase3_complete']" \
        || fail "phase3_audit incomplete: $s"
done

# 4. Classification count
count=$(python3 -c "import json; c=json.load(open('subsystems/classification-final.json')); print(len([x for x in c['classifications'] if x['subsystem']!='circus-tent']))")
[ "$count" -eq 119 ] || fail "classification count: $count (expected 119)"

echo "[PASS] phase4 gate: all checks green"
