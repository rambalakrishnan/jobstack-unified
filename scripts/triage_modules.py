#!/usr/bin/env python3
"""
Pre-Phase-4 module complexity triage.
Extracts signals from 150 .omp-spec.md files + 5 DAGs and classifies each
module into S, H, I, A, B, or U per pre-phase4-triage.md.

Usage: python3 scripts/triage_modules.py
Outputs (all under subsystems/):
  triage-report.json, triage-report.md, triage-report.warnings.json,
  triage-report.contradictions.json, triage-report.uncertain.json
"""
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
SUBSYSTEMS_DIR = WORKSPACE / "subsystems"

NAME_SUFFIX_TOKENS = {
    "S": {"schema", "schemas", "types", "type", "def", "defs", "definition",
          "definitions", "constant", "constants", "enum", "enums", "registry",
          "catalog", "atom", "clock", "identity", "digest", "struct", "record",
          "model", "models", "payload", "error", "errors"},
    "H": {"test", "tests", "harness", "fixture", "fixtures", "golden", "goldens",
          "runner", "benchmark", "mock", "stub"},
    "I": {"codec", "protocol", "adapter", "serial", "deserial", "wire", "client",
          "transport", "request", "response", "callback", "handshake",
          "translation", "mapping", "registration", "state", "transition",
          "dispatch", "router", "routing", "binding", "compat", "normalizer",
          "connector", "service"},
    "A": {"runtime", "engine", "handler", "pipeline", "transpiler", "reducer",
          "evaluator", "detector", "classifier", "minimizer", "resolver",
          "scheduler", "matcher", "ranker", "scorer", "healer"},
    "B": {"lease", "lock", "fence", "atomic", "shard", "ownership",
          "publication", "replacement", "archive"},
}
NAME_SUFFIX_MULTIWORD = {
    "A": {"state_machine"},
    "B": {"session_epoch"},
}

ALGO_TERMS = {
    "crawler": ["coverage", "proof", "detector", "drift", "cursor",
                "semantic state", "pipeline", "lease", "classif",
                "acquisition"],
    "circus-tent": ["tier", "resolution", "heal", "extraction", "reduction",
                    "scheduler"],
    "ringmaster": ["tier", "resolution", "reduction", "breaker", "extraction",
                   "observe", "lifecycle", "recovery"],
    "hellscape": ["assessment", "three-way", "diagnostic", "replay",
                  "composition", "reducer", "pipeline"],
    "job-hunter": ["evaluation", "candidate policy", "pipeline", "lifecycle",
                   "publication", "transformation", "scoring"],
}
INTEG_TERMS = {
    "crawler": ["transport", "connector", "session", "adapter", "declaration",
                "acquisition contract"],
    "circus-tent": ["transport", "connector", "session", "profile", "browser",
                    "route"],
    "ringmaster": ["transport", "connector", "session", "profile", "browser",
                   "binding", "primitive"],
    "hellscape": ["application", "connector", "external", "boundary",
                  "surface", "authority"],
    "job-hunter": ["connector", "protocol", "boundary", "topography",
                   "subsystem", "interface"],
}

B_INVARIANT_RES = [
    re.compile(r"^OWD-(REPLACE|ARCHIVE|RETENTION|LOCAL-COMMIT|PUBLISH)$"),
    re.compile(r"^BO-THREAD$"),
    re.compile(r"^EK-(LEASE|LEASE-RESTART|ATOMICITY|JOURNAL)$"),
    re.compile(r"^LIFE-(DISPATCH|IDEMPOTENCY)$"),
]
B_INVARIANT_SUBSTR = ("THREAD", "LEASE", "FENCE", "ATOMIC", "EPOCH",
                      "OWNERSHIP", "CONCURREN", "TRANSACTION")
B_TEXT_TERMS = ("atomic", "concurren", "fence", "epoch", "lease", "thread",
                "isolate", "barrier", "transaction", "contention", "mutex",
                "lock", "sweep", "expiry", "ownership", "shard")

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
RESPONSIBILITY_ALGO_TERMS = ("proof", "algebra", "detector", "coverage",
                             "reducer", "transpiler")

INVARIANT_ID_RE = re.compile(r"^- \*\*\[([A-Z0-9_\-]+)\]\*\*")
ASSERTION_BULLET_RE = re.compile(r"^- \*\*\[[^\]]+\]\*\*")

ORDER = ["S", "H", "I", "A", "B"]


def section_text(text, heading, stop_level=None):
    """Body of a `#..###### <heading>` section, fence-aware.

    Runs to the next heading of level <= the matched heading's own level
    (or <= stop_level when given). `#`-looking lines inside fenced code
    blocks never terminate the section.
    """
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
    """Body of a `### <subheading>` within an already-extracted parent."""
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
    # Line-oriented only if EVERY non-blank line qualifies (§3.2: "each").
    if lines and len(qual) == len(lines):
        return len(qual), False
    # Comma-separated path: strip one wrapping [...] then split at depth 0.
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
    return [i for i in items if i not in FORBIDDEN_TEMPLATE_LINES]


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
            # First non-blank line is not a heading: heading absent,
            # anchor fallback (§4.5) applies.
            break
        refs.append({"fragment": frag, "heading": heading})
        i = j if j > i else i + 1
    return refs


def name_suffix_signals(module):
    tokens = set(module.split("_"))
    found = {c: sorted(tokens & toks)
             for c, toks in NAME_SUFFIX_TOKENS.items()}
    for cls, multis in NAME_SUFFIX_MULTIWORD.items():
        for mw in multis:
            if mw in module:
                found[cls] = sorted(set(found[cls]) | {mw})
    return found


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


def is_b_invariant(inv_id):
    if any(rx.match(inv_id) for rx in B_INVARIANT_RES):
        return True
    return any(s in inv_id for s in B_INVARIANT_SUBSTR)


def advance(cls):
    return ORDER[min(ORDER.index(cls) + 1, len(ORDER) - 1)]


def build_seam_toc(seam_path):
    return [m.group(2).strip()
            for line in seam_path.read_text(encoding="utf-8").splitlines()
            for m in [re.match(r"^(#{1,6})\s+(.*)$", line.strip())]
            if m]


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
        algo_terms = ALGO_TERMS.get(subsystem, [])
        integ_terms = INTEG_TERMS.get(subsystem, [])
        algo_hits, integ_hits = set(), set()
        for r in refs:
            if r["heading"]:
                text_src = r["heading"]
            else:
                # §4.5 anchor fallback: resolve against seam TOC.
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

        iface_total = expose_count + consume_count
        invariant_count = len(invariant_ids)

        # ---- Ladder ----
        matched_by_class = defaultdict(set)
        b_reasons, a_reasons, i_reasons, h_reasons = [], [], [], []

        for inv in invariant_ids:
            if is_b_invariant(inv):
                b_reasons.append(f"invariant:{inv}")
                matched_by_class["B"].add(f"invariant:{inv}")
        if suffix["B"]:
            b_reasons += [f"name_suffix:{t}" for t in suffix["B"]]
            matched_by_class["B"].update(
                f"name_suffix:{t}" for t in suffix["B"])
        for item in forbidden_specific:
            low = item.lower()
            hits = sorted({t for t in B_TEXT_TERMS if t in low})
            for t in hits:
                b_reasons.append(f"forbidden:{t}")
                matched_by_class["B"].add(f"forbidden:{t}")
        for h in headings:
            low = h.lower()
            hits = sorted({t for t in B_TEXT_TERMS if t in low})
            for t in hits:
                b_reasons.append(f"section:{t}")
                matched_by_class["B"].add(f"section:{t}")

        if suffix["A"]:
            a_reasons += [f"name_suffix:{t}" for t in suffix["A"]]
            matched_by_class["A"].update(
                f"name_suffix:{t}" for t in suffix["A"])
        if algo_hits:
            a_reasons += [f"section:algorithmic:{t}"
                          for t in sorted(algo_hits)]
            matched_by_class["A"].update(
                f"section:algorithmic:{t}" for t in sorted(algo_hits))
        if assertion_count >= 5 and invariant_count >= 2:
            a_reasons.append(
                f"density:assertions={assertion_count},"
                f"invariants={invariant_count}")
            matched_by_class["A"].add("density:assertions>=5,invariants>=2")
        if invariant_count >= 4:
            a_reasons.append(f"density:invariants={invariant_count}")
            matched_by_class["A"].add("density:invariants>=4")
        if (not boilerplate and responsibility
                and any(t in responsibility.lower()
                        for t in RESPONSIBILITY_ALGO_TERMS)):
            a_reasons.append("responsibility:algorithmic_term")
            matched_by_class["A"].add("responsibility:algorithmic_term")

        if suffix["I"]:
            i_reasons += [f"name_suffix:{t}" for t in suffix["I"]]
            matched_by_class["I"].update(
                f"name_suffix:{t}" for t in suffix["I"])
        if integ_hits:
            i_reasons += [f"section:integration:{t}"
                          for t in sorted(integ_hits)]
            matched_by_class["I"].update(
                f"section:integration:{t}" for t in sorted(integ_hits))
        if iface_total >= 5:
            i_reasons.append(f"surface:iface_total={iface_total}")
            matched_by_class["I"].add("surface:iface_total>=5")

        if suffix["H"]:
            h_reasons += [f"name_suffix:{t}" for t in suffix["H"]]
            matched_by_class["H"].update(
                f"name_suffix:{t}" for t in suffix["H"])
        for h in headings:
            low = h.lower()
            hits = sorted({t for t in H_HEADING_TERMS if t in low})
            for t in hits:
                h_reasons.append(f"section:{t}")
                matched_by_class["H"].add(f"section:{t}")

        has_s = bool(suffix["S"]) and assertion_count <= 3 \
            and invariant_count <= 1 and iface_total <= 4
        if has_s:
            matched_by_class["S"].update(
                f"name_suffix:{t}" for t in suffix["S"])
            matched_by_class["S"].add("density:s_structural")

        if b_reasons:
            cls = "B"
        elif a_reasons:
            cls = "A"
        elif i_reasons:
            cls = "I"
        elif h_reasons:
            cls = "H"
        elif has_s:
            cls = "S"
        else:
            cls = "U"
            uncertainty_reasons.append("no_ladder_signal")

        ladder_signals = {k: sorted(v)
                          for k, v in matched_by_class.items()}

        # ---- Promotions (§4.1) ----
        promotions = []
        if cls in ("S", "H", "I", "A"):
            if consumer_count >= 5:
                cls = advance(cls)
                promotions.append("blast_radius")
            elif iface_total >= 8:
                cls = advance(cls)
                promotions.append("interface_surface")
            elif invariant_count >= 3 and cls in ("I", "S"):
                cls = "A"
                promotions.append("invariant_density")

        # ---- Check-3 override (§4.2) ----
        check3_override = False
        if assertion_count >= 8 and cls in ("S", "H", "I"):
            cls = "B" if b_reasons else "A"
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
        fired = [c for c in "BHIA"
                 if (c == "B" and b_reasons) or (c == "A" and a_reasons)
                 or (c == "I" and i_reasons) or (c == "H" and h_reasons)]
        if has_s:
            fired.append("S")
        if len(fired) >= 2:
            ambiguity.append({
                "check": 6,
                "module": module,
                "subsystem": subsystem,
                "fired_classes": sorted(fired),
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
        elif cls in ("S", "H") and not (suffix["S"] or suffix["H"]):
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

    # ---- Calibration checks ----
    warnings = []
    by_class = Counter(r["class"] for r in records)
    total = len(records)

    for c in "SHIAB":
        if total and by_class[c] / total > 0.60:
            warnings.append({"check": 1,
                             "message": f"Class {c} exceeds 60%",
                             "count": by_class[c], "total": total})
    if total and by_class["U"] / total > 0.05:
        warnings.append({"check": 1, "message": "Class U exceeds 5%",
                         "count": by_class["U"], "total": total})
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

    distribution = {c: by_class.get(c, 0) for c in "SHIABU"}
    pct = {c: round(100 * distribution[c] / total, 1) if total else 0.0
           for c in "SHIABU"}
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

    md = ["# Module triage report", "",
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
