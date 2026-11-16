#!/usr/bin/env python3
"""
Parse audit-classifications-all.json, split into auto-accepted and review-required.
Applies a 'round-up to the more complex tier' rule when primary and alternative classes diverge.

Usage:
    python3 scripts/filter_audit.py /tmp/triage-audit/audit-classifications-all.json subsystems/

Outputs:
    subsystems/classification-final.json  -- records, source: "audit" | "operator_override"
    subsystems/review-queue.json          -- operator work list
"""
import json
import sys
from collections import Counter
from pathlib import Path

CHEAP = {'S', 'H', 'I', 'U'}
MID = {'A'}
FRONTIER = {'B'}

# Numeric ranking for complexity comparison (higher number = more complex tier)
TIER_RANKS = {
    'cheap': 1,
    'mid': 2,
    'frontier': 3
}

def cost_tier(cls):
    if cls in CHEAP: return 'cheap'
    if cls in MID: return 'mid'
    if cls in FRONTIER: return 'frontier'
    return 'cheap' # Default fallback for any unknown class tags

def max_tier(tier1, tier2):
    """Returns the more complex tier between tier1 and tier2."""
    return tier1 if TIER_RANKS[tier1] >= TIER_RANKS[tier2] else tier2

def parse_audit(audit_path):
    path = Path(audit_path)
    if not path.exists():
        print(f"Error: Audit file not found: {audit_path}", file=sys.stderr)
        sys.exit(1)
    data = json.loads(path.read_text())
    records = data if isinstance(data, list) else data.get('classifications') or data.get('records')
    if not records:
        raise ValueError(f'No records found in {audit_path}; keys seen: {list(data.keys()) if isinstance(data, dict) else "list"}')
    return records

def needs_review(record):
    """True iff audit's class and alternative_class fall in different cost tiers."""
    primary = record['class']
    alt = record.get('alternative_class')
    if alt is None:
        return False
    return cost_tier(primary) != cost_tier(alt)

def resolve_effective_tier(record):
    """
    Computes the cost tier. If an alternative class exists and diverges, 
    rounds up to the more complex tier of the two.
    """
    primary = record['class']
    primary_t = cost_tier(primary)
    
    alt = record.get('alternative_class')
    if alt is not None:
        alt_t = cost_tier(alt)
        return max_tier(primary_t, alt_t)
    
    return primary_t

def build_review_entry(record):
    primary = record['class']
    alt = record['alternative_class']
    return {
        'module': record['module'],
        'subsystem': record['subsystem'],
        'audit_class': primary,
        'audit_tier': cost_tier(primary),
        'audit_confidence': record.get('confidence'),
        'alternative_class': alt,
        'alternative_tier': cost_tier(alt) if alt else None,
        'resolved_tier': resolve_effective_tier(record),
        'audit_reasoning': record.get('reasoning', ''),
        'operator_class': None,
        'operator_rationale': None,
    }

def build_final_entry(record):
    effective_tier = resolve_effective_tier(record)
    return {
        'module': record['module'],
        'subsystem': record['subsystem'],
        'lang': record.get('lang'),
        'class': record['class'],
        'cost_tier': effective_tier,
        'source': 'audit',
        'confidence': record.get('confidence'),
        'alternative_class': record.get('alternative_class'),
        'rationale': None,
    }

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <audit-json-path> [output-dir]", file=sys.stderr)
        sys.exit(1)

    audit_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else 'subsystems'

    records = parse_audit(audit_path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Load prior operator decisions if review-queue.json exists
    existing_rq = out / 'review-queue.json'
    prior_by_key = {}
    if existing_rq.exists():
        try:
            prior_data = json.loads(existing_rq.read_text())
            prior = prior_data.get('review_queue', []) if isinstance(prior_data, dict) else prior_data
            prior_by_key = {(r['subsystem'], r['module']): r for r in prior if isinstance(r, dict)}
        except json.JSONDecodeError:
            print(f"Warning: Could not parse existing {existing_rq}. Starting fresh.", file=sys.stderr)

    final = []
    review = []

    for record in records:
        key = (record.get('subsystem'), record.get('module'))
        final_entry = build_final_entry(record)
        
        if needs_review(record):
            review_entry = build_review_entry(record)
            if key in prior_by_key:
                p = prior_by_key[key]
                if p.get('operator_class') is not None:
                    review_entry['operator_class'] = p['operator_class']
                    review_entry['operator_rationale'] = p.get('operator_rationale')
            review.append(review_entry)

        if key in prior_by_key:
            p = prior_by_key[key]
            if p.get('operator_class') is not None:
                final_entry['class'] = p['operator_class']
                # Round up if operator class and base audit class diverge
                final_entry['cost_tier'] = max_tier(cost_tier(p['operator_class']), cost_tier(record['class']))
                final_entry['source'] = 'operator_override'
                final_entry['rationale'] = p.get('operator_rationale')

        final.append(final_entry)

    (out / 'classification-final.json').write_text(
        json.dumps({'classifications': final}, indent=2, sort_keys=True))
    (out / 'review-queue.json').write_text(
        json.dumps({'review_queue': review}, indent=2, sort_keys=True))

    print(f'Total modules: {len(final)}')
    print(f'Auto-accepted: {len(final) - len(review)}')
    print(f'Review queue:  {len(review)}')
    print()
    print(f'Final distribution: {dict(Counter(e["class"] for e in final))}')
    print(f'Final cost tiers (with Round-Up Policy): {dict(Counter(e["cost_tier"] for e in final))}')
    print()
    if review:
        print('Review queue by (audit_tier -> alternative_tier):')
        for pair, count in Counter(
            (e['audit_tier'], e['alternative_tier']) for e in review
        ).items():
            print(f'  {pair[0]:>8} -> {pair[1]:<8} : {count}')
    if existing_rq.exists():
        decided = sum(1 for r in review if r.get('operator_class') is not None)
        print(f'Operator decisions resolved: {decided}/{len(review)}')

if __name__ == '__main__':
    main()
