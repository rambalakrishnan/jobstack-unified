#!/usr/bin/env python3
"""
Pre-Phase-4 module complexity triage (name-first classifier).
Extracts signals from 150 .omp-spec.md files + 5 DAGs and classifies each
module into S, H, I, A, B, or U per pre-phase4-triage.md.

Name-first ladder: a module's name suffix is the primary responsibility
signal; extracted signals apply only when the name is generic. Class B
requires a B name suffix or 2+ agreeing boundary signals.

Usage: python3 scripts/triage_modules.py
Outputs (all under subsystems/):
  triage-report.json, triage-report.md, triage-report.warnings.json,
  triage-report.contradictions.json, triage-report.uncertain.json
On degenerate distribution: writes triage-report.DEGENERATE.json instead
and exits non-zero (§8 failure conditions).
"""
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
SUBSYSTEMS_DIR = WORKSPACE / "subsystems"

NAME_SUFFIXES = {
    'S': {
        # data shapes
        'schema', 'schemas', 'types', 'type', 'def', 'defs',
        'definition', 'definitions', 'constant', 'constants',
        'enum', 'enums', 'struct', 'record', 'model', 'models',
        'payload', 'error', 'errors',
        # record carriers and registries
        'registry', 'catalog', 'atom', 'clock', 'identity', 'digest',
        'ledger', 'manifest', 'envelope', 'document', 'state_record',
        'rules', 'store', 'stores', 'artifacts', 'journal', 'journals',
        'authority', 'capabilities', 'time', 'cursors', 'sessions',
        'retention', 'observation', 'archive', 'archives',
        'seen_ids', 'feed', 'owner', 'owners', 'reference', 'references',
        'matrix', 'handoff', 'receipt', 'receipts', 'task', 'tasks',
        'keys', 'hashes', 'declaration',
    },
    'H': {
        'test', 'tests', 'harness', 'fixture', 'fixtures',
        'golden', 'goldens', 'runner', 'benchmark', 'mock', 'stub',
    },
    'I': {
        'codec', 'protocol', 'adapter', 'serial', 'deserial', 'wire',
        'client', 'transport', 'request', 'response', 'callback',
        'handshake', 'translation', 'mapping', 'registration', 'state',
        'transition', 'dispatch', 'router', 'routing', 'binding',
        'compat', 'normalizer', 'connector', 'service', 'bridge',
        'intake', 'gateway', 'delivery', 'targets', 'browseroxide',
        'observe', 'observer', 'prepare', 'readonly', 'admission',
        'surface', 'dispatcher', 'translator',
    },
    'A': {
        'runtime', 'engine', 'handler', 'pipeline', 'state_machine',
        'transpiler', 'reducer', 'evaluator', 'detector', 'detectors',
        'classifier', 'minimizer', 'resolver', 'scheduler', 'matcher',
        'ranker', 'scorer', 'healer', 'coverage', 'replay',
        'normalization', 'preparation', 'recovery', 'reduction',
        'resolution', 'acquisition', 'hashing', 'inference_host',
        'supervisor', 'execution', 'diagnostics', 'scoring',
        'evaluation', 'transformation', 'synthesis', 'reconciler',
        'arbitration', 'ranking', 'selection', 'cursor_walk',
    },
    'B': {
        'lease', 'leases', 'lock', 'locks', 'fence', 'fences',
        'atomic', 'session_epoch', 'epoch', 'epochs', 'shard', 'shards',
        'replacement', 'replacements', 'publication', 'publications',
        'controls', 'containment', 'coordinator', 'sweeper',
        'synchronizer', 'mutex', 'owner_enforcer', 'thread_guard',
        'isolate_guard',
    },
}

CLASS_B_INVARIANT_REGEXES = [
    re.compile(r'^BO-THREAD$'),
    re.compile(r'^OWD-(REPLACE|ARCHIVE|RETENTION|LOCAL-COMMIT|PUBLISH)$'),
    re.compile(r'^EK-(LEASE|LEASE-RESTART)$'),
    re.compile(r'^LIFE-(DISPATCH|IDEMPOTENCY|CLOSE)$'),
    re.compile(r'.*(FENCE|THREAD|EPOCH).*'),
]

CLASS_B_TERMS = {
    'atomic', 'concurren', 'fence', 'epoch', 'thread', 'isolate',
    'barrier', 'contention', 'mutex', 'sweep', 'expiry',
}

ALGORITHMIC_SECTION_TERMS = {
    'crawler': {
        'coverage', 'proof', 'algebra', 'equation', 'detector', 'drift',
        'cursor', 'semantic state', 'pipeline', 'classif', 'acquisition',
        'normalization', 'replay', 'diagnostics', 'attribut',
        'reconciliation', 'minimiz', 'counterfactual', 'hashing',
        'deduplic', 'dispatcher', 'matcher', 'ranking', 'selection',
        'scoring', 'evaluation',
    },
    'circus-tent': {
        'tier', 'resolution', 'heal', 'extraction', 'reduction',
        'scheduler', 'backpressure', 'adaptive',
    },
    'ringmaster': {
        'tier', 'resolution', 'reduction', 'breaker', 'extraction',
        'observe', 'lifecycle', 'recovery', 'minimiz', 'matching',
    },
    'hellscape': {
        'assessment', 'three-way', 'diagnostic', 'replay', 'composition',
        'reducer', 'pipeline', 'attribution', 'counterfactual', 'minimiz',
    },
    'job-hunter': {
        'evaluation', 'candidate policy', 'pipeline', 'lifecycle',
        'publication', 'transformation', 'scoring', 'ranking',
        'selection', 'reconcil',
    },
}

INTEGRATION_SECTION_TERMS = {
    'crawler': {
        'transport', 'connector', 'session', 'adapter', 'declaration',
        'acquisition contract', 'intake', 'adaptation', 'bridge',
        'protocol', 'dispatch', 'routing', 'endpoint', 'wire',
    },
    'circus-tent': {
        'transport', 'connector', 'session', 'profile', 'browser',
        'route', 'adapter', 'endpoint',
    },
    'ringmaster': {
        'transport', 'connector', 'session', 'profile', 'browser',
        'binding', 'primitive', 'endpoint', 'wire',
    },
    'hellscape': {
        'application', 'connector', 'external', 'boundary', 'surface',
        'authority', 'plane', 'ingest',
    },
    'job-hunter': {
        'connector', 'protocol', 'boundary', 'topography',
        'subsystem', 'interface', 'exchange', 'transport',
    },
}

H_HEADING_TERMS = ("conformance", "test corpus", "fixture", "golden")

FORBIDDEN_TEMPLATE_LINES = {
    "No in-band nulls; all missing fields must use typed Missing envelopes.",
    "No shared database writes or cross-domain transactions.",
    "No forbidden constraints specified.",
}

LINE_ITEM_PREFIXES = ("fn ", "pub fn ", "def ", "async def ", "func ",
                      "trait ", "type ", "struct ", "enum ", "class ",
                      "interface ", "const ", "static ")

RESPONSIBILITY_BOILERPLATE = re.compile(
    r"^Module implementing \S+ at tier -?\d+$")

INVARIANT_ID_RE = re.compile(r"^- \*\*\[([A-Z0-9_\-]+)\]\*\*")
ASSERTION_BULLET_RE = re.compile(r"^- \*\*\[[^\]]+\]\*\*")

ORDER = ["S", "H", "I", "A", "B"]
PRIORITY_ORDER = ['B', 'A', 'I', 'H', 'S']


def section_text(text, heading, stop_level=None):
    """Body of a `#..###### <heading>` section, fence-aware."""
    lines = text.splitlines()
    start, level = None, 0
    for i, line in enumerate(lines):
        m = re.match(r"^(#{1,6})\s+(.*)$", line.strip())
        if m and m.group(2).strip() == heading:
            start, level = i + 1, len(m.group(1))
            break
    if start is None:
        return ""
    stop = stop_level if stop_level is not None else level
    out, in_fence = [], False
    for line in lines[start:]:
        s = line.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if not in_fence:
            m = re.match(r"^(#{1,6})\s+", s)
            if m and len(m.group(1)) <= stop:
                break
        out.append(line)
    return "\n".join(out)


def subsection_text(parent_body, subheading):
    lines = parent_body.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == subheading:
            start = i + 1
            break
    if start is None:
        return ""
    out = []
    for line in lines[start:]:
        s = line.strip()
        if re.match(r"^#{1,3}\s+", s):
            break
        out.append(line)
    return "\n".join(out)


def fenced_block(section_body):
    m = re.search(r"```[a-zA-Z+-]*\n(.*?)```", section_body, re.DOTALL)
    return m.group(1) if m else ""


def parse_frontmatter(text):
    fm = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            for line in text[4:end].splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fm[k.strip()] = v.strip().strip("'\"")
    return fm


def count_interface_items(block):
    """§3.2 paren-aware item counter. Returns (count, uncertain)."""
    text = block.strip()
    if not text or text == "[]":
        return 0, False
    lines = [ln for ln in (ln.strip() for ln in text.splitlines()) if ln]
    qual = [ln for ln in lines
            if ln.startswith(LINE_ITEM_PREFIXES)
            or re.match(r"^[A-Za-z_][\w]*\s*:", ln)]
    if lines and len(qual) == len(lines):
        return len(qual), False
    inner = text.strip()
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]
    if not inner.strip():
        return 0, False
    items, cur, stack = [], [], []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for ch in inner:
        if ch in pairs:
            stack.append(pairs[ch])
            cur.append(ch)
        elif stack and ch == stack[-1]:
            stack.pop()
            cur.append(ch)
        elif ch == "," and not stack:
            items.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    items.append("".join(cur).strip())
    items = [i for i in items if i]
    if not items:
        return 0, True
    return len(items), False


def extract_invariant_ids(invariants_body):
    ids = INVARIANT_ID_RE.findall(invariants_body)
    bullets = [ln for ln in invariants_body.splitlines()
               if ln.strip().startswith("- ")]
    return ids, len(bullets) - len(ids)


def count_assertions(assertions_body):
    return len(ASSERTION_BULLET_RE.findall(assertions_body))


def extract_forbidden(forbidden_body):
    items = []
    for line in forbidden_body.splitlines():
        s = line.strip()
        if s.startswith("- "):
            items.append(s[2:].strip())
    specific = [i for i in items if i not in FORBIDDEN_TEMPLATE_LINES]
    return specific


def extract_references(schemas_body):
    """§3.4: (fragment, heading-or-None) per #### Reference block."""
    refs = []
    lines = schemas_body.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^#### Reference: `([^`]+)`\s*$", lines[i].strip())
        if not m:
            i += 1
            continue
        frag = m.group(1)
        heading = None
        j = i + 1
        while j < len(lines):
            s = lines[j].strip()
            if not s:
                j += 1
                continue
            if s.startswith("#### Reference:"):
                break
            hm = re.match(r"^#{1,6}\s+(.*)$", s)
            if hm:
                heading = hm.group(1).strip()
                break
            break
        refs.append({"fragment": frag, "heading": heading})
        i = j if j > i else i + 1
    return refs


def name_suffix_signals(name: str) -> dict:
    tokens = name.split('_')
    signals = {'S': [], 'H': [], 'I': [], 'A': [], 'B': []}
    for tok in tokens:
        for cls, suffixes in NAME_SUFFIXES.items():
            if tok in suffixes and tok not in signals[cls]:
                signals[cls].append(tok)
    for n in (2, 3):
        if len(tokens) >= n:
            compound = '_'.join(tokens[-n:])
            for cls, suffixes in NAME_SUFFIXES.items():
                if compound in suffixes and compound not in signals[cls]:
                    signals[cls].append(compound)
    return signals


def parse_dag(dag_path):
    nodes = {}
    for line in dag_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("NODE:"):
            continue
        parts = [p.strip() for p in line[len("NODE:"):].split("|")]
        if len(parts) != 5:
            continue
        name = parts[0]
        lang = parts[2].replace("lang:", "").strip().lower()
        try:
            tier = int(parts[3].replace("tier:", "").strip())
        except ValueError:
            tier = -1
        deps_raw = parts[4].replace("deps:", "").strip().strip("[]")
        deps = [d.strip() for d in deps_raw.split(",") if d.strip()]
        nodes[name] = {"lang": lang, "tier": tier, "deps": deps}
    return nodes


def consumer_counts(nodes):
    counts = Counter()
    for data in nodes.values():
        for dep in data["deps"]:
            if dep in nodes:
                counts[dep] += 1
    return counts


def match_terms(text, terms):
    low = text.lower()
    return sorted({t for t in terms if t.lower() in low})


def advance(cls):
    return ORDER[min(ORDER.index(cls) + 1, len(ORDER) - 1)]


def build_seam_toc(seam_path):
    return [m.group(2).strip()
            for line in seam_path.read_text(encoding="utf-8").splitlines()
            for m in [re.match(r"^(#{1,6})\s+(.*)$", line.strip())]
            if m]


def classify(module):
    """Name-first classification. module holds extracted signals.

    Returns (class, signals_matched, promotions_input_flags).
    signals_matched maps class -> sorted signal list for §5 output.
    """
    name_sig = module['name_suffix_signals']

    # --- Step 1: name-first classification ---
    name_classes_present = [cls for cls in PRIORITY_ORDER if name_sig[cls]]
    name_first = name_classes_present[0] if name_classes_present else None

    # --- Step 2: collect B-signals (needed for confidence and fallback) ---
    b_invariant_ids = set()
    for inv_id in module['invariant_ids']:
        for rx in CLASS_B_INVARIANT_REGEXES:
            if rx.match(inv_id):
                b_invariant_ids.add(inv_id)
                break

    b_forbidden_hits = set()
    for item in module['forbidden_items']:
        for term in CLASS_B_TERMS:
            if term in item.lower():
                b_forbidden_hits.add(term)

    b_section_hits = set()
    for heading in module['read_section_headings']:
        for term in CLASS_B_TERMS:
            if term in heading.lower():
                b_section_hits.add(term)

    b_signal_count = (len(b_invariant_ids) + len(b_forbidden_hits)
                      + len(b_section_hits))

    section_algo_hits = module['section_signals']['algorithmic']
    section_int_hits = module['section_signals']['integration']
    iface_total = module['expose_count'] + module['consume_count']

    # Step 3: classify
    if name_first == 'B':
        cls = 'B'
    elif name_first == 'S' and b_signal_count >= 3:
        # Structural name but strong boundary agreement — trust signals
        cls = 'B'
    elif name_first in ('S', 'H', 'I', 'A'):
        cls = name_first
    else:
        # No name suffix — signal-first path
        if section_algo_hits:
            cls = 'A'
        elif section_int_hits:
            cls = 'I'
        elif b_signal_count >= 3:
            cls = 'B'
        elif module['assertion_count'] >= 5 and module['invariant_count'] >= 2:
            cls = 'A'
        elif module['invariant_count'] >= 4:
            cls = 'A'
        elif (module['expose_count'] + module['consume_count']) >= 5:
            cls = 'I'
        elif (module['assertion_count'] <= 3
              and module['invariant_count'] <= 1
              and (module['expose_count'] + module['consume_count']) <= 3):
            cls = 'S'
        else:
            cls = 'U'

    signals_matched = {}
    if name_sig['B']:
        signals_matched.setdefault('B', []).extend(
            f"name_suffix:{t}" for t in name_sig['B'])
    for inv in sorted(b_invariant_ids):
        signals_matched.setdefault('B', []).append(f"invariant:{inv}")
    for t in sorted(b_forbidden_hits):
        signals_matched.setdefault('B', []).append(f"forbidden:{t}")
    for t in sorted(b_section_hits):
        signals_matched.setdefault('B', []).append(f"section:{t}")
    if cls == 'B':
        signals_matched.setdefault('B', []).append(
            f"b_signal_count={b_signal_count}")
    if name_sig['A']:
        signals_matched.setdefault('A', []).extend(
            f"name_suffix:{t}" for t in name_sig['A'])
    for t in section_algo_hits:
        signals_matched.setdefault('A', []).append(
            f"section:algorithmic:{t}")
    if name_sig['I']:
        signals_matched.setdefault('I', []).extend(
            f"name_suffix:{t}" for t in name_sig['I'])
    for t in section_int_hits:
        signals_matched.setdefault('I', []).append(
            f"section:integration:{t}")
    if name_sig['H']:
        signals_matched.setdefault('H', []).extend(
            f"name_suffix:{t}" for t in name_sig['H'])
    if name_sig['S']:
        signals_matched.setdefault('S', []).extend(
            f"name_suffix:{t}" for t in name_sig['S'])
    signals_matched = {k: sorted(v) for k, v in signals_matched.items()}

    return cls, signals_matched, {
        'name_first': name_first,
        'b_signal_count': b_signal_count,
        'b_reasons_present': b_signal_count > 0,
    }


def main():
    spec_files = sorted(
        SUBSYSTEMS_DIR.glob("*/modules/*/.omp-spec.md"),
        key=lambda p: (p.parent.parent.parent.name, p.parent.name))

    dag_nodes, dag_consumers = {}, {}
    for dag in sorted(SUBSYSTEMS_DIR.glob("*/module-graph-0.1.0.dag")):
        sub = dag.parent.name
        nodes = parse_dag(dag)
        dag_nodes[sub] = nodes
        dag_consumers[sub] = consumer_counts(nodes)

    seam_tocs = {}
    for sub in dag_nodes:
        seam = WORKSPACE / "seam-mappings" / f"{sub}-seam-mapping.md"
        if seam.exists():
            seam_tocs[sub] = build_seam_toc(seam)

    records, uncertain, contradictions, ambiguity = [], [], [], []

    for spec in spec_files:
        subsystem = spec.parent.parent.parent.name
        module = spec.parent.name
        text = spec.read_text(encoding="utf-8")
        fm = parse_frontmatter(text)

        blind = section_text(text, "BLIND SPOT DOCUMENTATION")
        inv_body = subsection_text(blind, "### Invariants")
        assert_body = subsection_text(blind, "### Conformance Assertions")
        schemas_body = section_text(
            text, "Schemas, State Machines & Formulas (Dereferenced Verbatim)",
            stop_level=1)
        exposes_body = section_text(text, "Public Interface (EXPOSES)")
        consumes_body = section_text(text, "Consumed Dependencies (CONSUMES)")
        forbidden_body = section_text(
            text, "Boundary Execution Constraints (FORBIDDEN)")

        invariant_ids, unresolved_inv = extract_invariant_ids(inv_body)
        assertion_count = count_assertions(assert_body)
        forbidden_specific = extract_forbidden(forbidden_body)
        refs = extract_references(schemas_body)

        expose_count, expose_uncertain = count_interface_items(
            fenced_block(exposes_body))
        consume_count, consume_uncertain = count_interface_items(
            fenced_block(consumes_body))
        if expose_uncertain or consume_uncertain:
            uncertain.append({
                "module": module,
                "subsystem": subsystem,
                "reason": "interface_block_unparseable",
                "spec_path": str(spec.relative_to(WORKSPACE)),
            })

        dag = dag_nodes.get(subsystem, {}).get(module, {})
        lang = dag.get("lang", "")
        tier = dag.get("tier", -1)
        consumer_count = dag_consumers.get(subsystem, {}).get(module, 0)

        responsibility = fm.get("description", "")
        boilerplate = bool(RESPONSIBILITY_BOILERPLATE.match(responsibility))

        suffix = name_suffix_signals(module)

        headings = [r["heading"] for r in refs if r["heading"]]
        anchors = ["#" + r["fragment"].split("#", 1)[1]
                   if "#" in r["fragment"] else r["fragment"]
                   for r in refs]
        algo_terms = ALGORITHMIC_SECTION_TERMS.get(subsystem, [])
        integ_terms = INTEGRATION_SECTION_TERMS.get(subsystem, [])
        algo_hits, integ_hits = set(), set()
        for r in refs:
            if r["heading"]:
                text_src = r["heading"]
            else:
                frag_anchor = r["fragment"].split("#", 1)[-1]
                toc_title = next(
                    (t for t in seam_tocs.get(subsystem, [])
                     if frag_anchor.lower() in t.lower()),
                    frag_anchor)
                text_src = toc_title
            a = match_terms(text_src, algo_terms)
            if a:
                algo_hits.update(a)
            else:
                integ_hits.update(match_terms(text_src, integ_terms))

        uncertainty_reasons = []
        if boilerplate:
            uncertainty_reasons.append("boilerplate_responsibility")
        if unresolved_inv:
            uncertainty_reasons.append("unresolved_invariant")
        if expose_uncertain or consume_uncertain:
            uncertainty_reasons.append("interface_block_unparseable")

        module_signals = {
            'name_suffix_signals': suffix,
            'invariant_ids': invariant_ids,
            'forbidden_items': forbidden_specific,
            'read_section_headings': headings,
            'section_signals': {'algorithmic': sorted(algo_hits),
                                'integration': sorted(integ_hits)},
            'assertion_count': assertion_count,
            'invariant_count': len(invariant_ids),
            'expose_count': expose_count,
            'consume_count': consume_count,
        }
        cls, ladder_signals, flags = classify(module_signals)

        iface_total = expose_count + consume_count
        invariant_count = len(invariant_ids)

        # ---- Promotions (§4.1, centrality promotions H-only) ----
        promotions = []
        if cls in ("S", "H", "I", "A"):
            if consumer_count >= 5 and cls == "H":
                # Blast radius promotes H only: for S/I/A, high fan-out
                # confirms hub/connector/central status, not boundary work.
                cls = advance(cls)
                promotions.append("blast_radius")
            elif iface_total >= 8 and cls == "H":
                # Interface surface promotes H only: wide S/I/A interfaces
                # confirm the name, never contradict it.
                cls = advance(cls)
                promotions.append("interface_surface")
            elif invariant_count >= 3 and cls in ("I", "S"):
                cls = "A"
                promotions.append("invariant_density")

        # ---- Check-3 override (§4.2, unchanged) ----
        check3_override = False
        if assertion_count >= 8 and cls in ("S", "H", "I"):
            cls = "B" if flags['b_reasons_present'] else "A"
            check3_override = True

        # ---- Contradictions (Check 5) ----
        suffix_classes = [c for c in "SHIAB" if suffix[c]]
        if len(suffix_classes) >= 2 or (
                suffix_classes and suffix_classes != [cls]
                and cls in "SHIAB"):
            contradictions.append({
                "check": 5,
                "module": module,
                "subsystem": subsystem,
                "name_suffix_signals": {c: suffix[c] for c in "SHIAB"},
                "final_class": cls,
            })

        # ---- Priority ambiguity (Check 6) ----
        fired = [c for c in "BHIA" if c in ladder_signals]
        if flags['name_first'] == 'S' or (
                not suffix_classes and cls == 'S'):
            fired.append("S")
        fired = sorted(set(fired))
        if len(fired) >= 2:
            ambiguity.append({
                "check": 6,
                "module": module,
                "subsystem": subsystem,
                "fired_classes": fired,
                "signals": ladder_signals,
                "final_class": cls,
            })

        # ---- Confidence ----
        if cls == "U":
            confidence = "low"
        elif unresolved_inv or expose_uncertain or consume_uncertain:
            confidence = "medium"
        elif len(fired) >= 2:
            confidence = "medium"
        elif not suffix_classes:
            confidence = "medium"
        else:
            confidence = "high"

        rec = {
            "module": module,
            "subsystem": subsystem,
            "lang": lang,
            "tier": tier,
            "consumer_count": consumer_count,
            "expose_count": expose_count,
            "consume_count": consume_count,
            "assertion_count": assertion_count,
            "invariant_count": invariant_count,
            "invariant_ids": sorted(invariant_ids),
            "forbidden_count": len(forbidden_specific),
            "read_section_headings": headings,
            "read_section_anchors": anchors,
            "responsibility_text": responsibility,
            "is_boilerplate_responsibility": boilerplate,
            "name_suffix_signals": {c: suffix[c] for c in "SHIAB"},
            "section_signals": {"algorithmic": sorted(algo_hits),
                                "integration": sorted(integ_hits)},
            "class": cls,
            "promotions": promotions,
            "signals_matched": ladder_signals,
            "confidence": confidence,
            "uncertainty_reasons": sorted(set(uncertainty_reasons)),
            "check3_override": check3_override,
            "spec_path": str(spec.relative_to(WORKSPACE)),
        }
        records.append(rec)

    records.sort(key=lambda r: (r["subsystem"], r["module"]))

    # ---- §8 distribution gate (failure conditions) ----
    by_class = Counter(r["class"] for r in records)
    total = len(records)
    distribution = {c: by_class.get(c, 0) for c in "SHIABU"}
    pct = {c: round(100 * distribution[c] / total, 1) if total else 0.0
           for c in "SHIABU"}
    bound_failures = []
    if pct["S"] < 15:
        bound_failures.append(f"S {pct['S']}% < 15%")
    if pct["A"] < 10:
        bound_failures.append(f"A {pct['A']}% < 10%")
    if pct["I"] < 10:
        bound_failures.append(f"I {pct['I']}% < 10%")
    if pct["B"] > 30:
        bound_failures.append(f"B {pct['B']}% > 30%")
    if pct["U"] > 5:
        bound_failures.append(f"U {pct['U']}% > 5%")
    for c in "SHIABU":
        if pct[c] > 45:
            bound_failures.append(f"{c} {pct[c]}% > 45%")
    if bound_failures:
        degen = {
            "status": "DEGENERATE",
            "distribution": distribution,
            "pct": pct,
            "failing_bounds": bound_failures,
        }
        (SUBSYSTEMS_DIR / "triage-report.DEGENERATE.json").write_text(
            json.dumps(degen, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        print(f"[TRIAGE DEGENERATE] distribution={distribution} "
              f"failures={bound_failures}")
        sys.exit(2)

    # ---- Calibration checks ----
    warnings = []
    if total and by_class["U"] / total > 0.05:
        warnings.append({"check": 1, "message": "Class U exceeds 5%",
                         "count": by_class["U"], "total": total})
    for c in "SHIAB":
        if total and by_class[c] / total > 0.60:
            warnings.append({"check": 1,
                             "message": f"Class {c} exceeds 60%",
                             "count": by_class[c], "total": total})
    if by_class["B"] < 2:
        warnings.append({"check": 2,
                         "message": "boundary signals under-firing",
                         "count": by_class["B"]})
    if by_class["B"] > 15:
        warnings.append({"check": 2,
                         "message": "boundary signals over-triggering",
                         "count": by_class["B"]})
    for r in records:
        if r["check3_override"]:
            warnings.append({"check": 3, "module": r["module"],
                             "subsystem": r["subsystem"],
                             "assertion_count": r["assertion_count"],
                             "final_class": r["class"]})
    for r in records:
        if r["consumer_count"] >= 8 and r["class"] in ("S", "H"):
            warnings.append({"check": 4, "module": r["module"],
                             "subsystem": r["subsystem"],
                             "consumer_count": r["consumer_count"],
                             "final_class": r["class"]})

    per_subsystem = {}
    for sub in sorted({r["subsystem"] for r in records}):
        sub_recs = [r for r in records if r["subsystem"] == sub]
        sub_by = Counter(r["class"] for r in sub_recs)
        per_subsystem[sub] = {c: sub_by.get(c, 0) for c in "SHIABU"}

    report = {
        "generated_at": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"),
        "aggregate": {
            "total_modules": total,
            "distribution": distribution,
            "pct": pct,
            "per_subsystem": per_subsystem,
        },
        "modules": records,
    }

    (SUBSYSTEMS_DIR / "triage-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    (SUBSYSTEMS_DIR / "triage-report.warnings.json").write_text(
        json.dumps(warnings, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    (SUBSYSTEMS_DIR / "triage-report.contradictions.json").write_text(
        json.dumps(contradictions + ambiguity, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8")
    (SUBSYSTEMS_DIR / "triage-report.uncertain.json").write_text(
        json.dumps(uncertain, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    # ---- Markdown report ----
    conf_rank = {"low": 0, "medium": 1, "high": 2}
    weakest = sorted(
        records,
        key=lambda r: (conf_rank[r["confidence"]],
                       len(r["uncertainty_reasons"]),
                       r["subsystem"], r["module"]))[:10]

    def sample(cls):
        cands = [r for r in records if r["class"] == cls]
        if not cands:
            return None
        return sorted(cands,
                      key=lambda r: (-conf_rank[r["confidence"]],
                                     r["subsystem"], r["module"]))[0]

    def dump(r):
        suffix_str = ", ".join(
            f"{c}=[{','.join(v)}]"
            for c, v in r["name_suffix_signals"].items() if v) or "(none)"
        lines = [
            f"#### `{r['subsystem']}/{r['module']}` → {r['class']} "
            f"({r['confidence']})",
            "",
            f"- lang/tier: {r['lang']} / {r['tier']}; "
            f"consumers: {r['consumer_count']}; "
            f"expose/consume: {r['expose_count']}/{r['consume_count']}; "
            f"assertions/invariants: "
            f"{r['assertion_count']}/{r['invariant_count']}",
            f"- invariant_ids: "
            f"{', '.join(r['invariant_ids']) if r['invariant_ids'] else '(none)'}",
            f"- forbidden_count: {r['forbidden_count']}",
            f"- headings: "
            f"{'; '.join(r['read_section_headings']) if r['read_section_headings'] else '(none)'}",
            f"- suffix: {suffix_str}",
            f"- section_signals: "
            f"algo=[{', '.join(r['section_signals']['algorithmic'])}] "
            f"integ=[{', '.join(r['section_signals']['integration'])}]",
            f"- signals_matched: "
            f"{json.dumps(r['signals_matched'], sort_keys=True)}",
            f"- promotions: {r['promotions']}; "
            f"check3_override: {r['check3_override']}",
            f"- uncertainty: {r['uncertainty_reasons'] or '(none)'}",
            f"- spec: `{r['spec_path']}`",
            "",
        ]
        return "\n".join(lines)

    md = ["# Module triage report (name-first classifier)", "",
          f"Modules: {total}; generated from 150 `.omp-spec.md` files + "
          "5 DAG headers + seam-mapping heading passes.",
          "", "## Distribution", "",
          "| Class | Count | Pct |", "|---|---|---:|"]
    for c in "SHIABU":
        md.append(f"| {c} | {distribution[c]} | {pct[c]} |")
    md += ["", "## Per-subsystem", "",
           "| Subsystem | S | H | I | A | B | U |",
           "|---|---|---|---|---|---|---|"]
    for sub in sorted(per_subsystem):
        d = per_subsystem[sub]
        md.append(f"| {sub} | {d['S']} | {d['H']} | {d['I']} | "
                  f"{d['A']} | {d['B']} | {d['U']} |")
    md += ["", "## Sample module per class", ""]
    for c in "SHIABU":
        s = sample(c)
        if s:
            md.append(dump(s))
        else:
            md.append(f"#### Class {c}: (no modules)")
            md.append("")
    md += ["## Top 10 lowest-confidence modules", ""]
    for r in weakest:
        md.append(dump(r))
    md += ["## Warnings (§6 checks 1–4)", ""]
    if warnings:
        for w in warnings:
            rest = {k: v for k, v in w.items()
                    if k not in ("check", "module", "message")}
            md.append(f"- Check {w.get('check')}: "
                      f"`{w.get('module', w.get('message', ''))}` "
                      f"{json.dumps(rest, sort_keys=True)}")
    else:
        md.append("(none)")
    md += ["", "## Contradictions (checks 5–6)", ""]
    if contradictions or ambiguity:
        for c in contradictions:
            md.append(f"- Check 5 `{c['subsystem']}/{c['module']}` → "
                      f"{c['final_class']}: "
                      f"{json.dumps(c['name_suffix_signals'])}")
        for c in ambiguity:
            md.append(f"- Check 6 `{c['subsystem']}/{c['module']}` → "
                      f"{c['final_class']}: fired {c['fired_classes']}")
    else:
        md.append("(none)")
    md += ["", "## Weakest heuristic points", "",
           "The three modules where the ladder is weakest are the first "
           "three entries under “Top 10 lowest-confidence modules” above: "
           + ", ".join(f"`{r['subsystem']}/{r['module']}` "
                       f"({r['class']}, {r['confidence']})"
                       for r in weakest[:3])
           + ". Full signal dumps appear in that section.",
           ""]
    (SUBSYSTEMS_DIR / "triage-report.md").write_text("\n".join(md),
                                                     encoding="utf-8")

    print(f"modules={total} dist={distribution} "
          f"warnings={len(warnings)} contradictions={len(contradictions)} "
          f"ambiguity={len(ambiguity)} uncertain={len(uncertain)}")


if __name__ == "__main__":
    main()
    sys.exit(0)
