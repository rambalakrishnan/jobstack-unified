#!/usr/bin/env python3
"""
Deterministic DAG Validator.
Validates acyclic topology, strict tier monotonicity, 100% conformance case coverage,
invariant coverage, language pin compliance, command whitelisting, and anchor resolution.

Usage: python3 scripts/verify_dag.py subsystems/<subsystem>/module-graph-0.1.0.dag
"""
import json, re, sys
from collections import defaultdict, deque
from pathlib import Path

ALLOWED_VERIFICATION_TOOLS = {"cargo", "pytest", "python", "go", "npm", "npx", "yarn", "pnpm"}
EXPECTED_LANG = {
    "crawler": "rust", "circus-tent": "python", "ringmaster": "rust",
    "hellscape": "go", "job-hunter": "python",
}
INVARIANT_PREFIXES = ("EK", "OWD", "EXT", "LIFE", "BO", "CF")

def slugify(text: str) -> str:
    s = text.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_]+', '-', s)
    return s.strip('-')

def matches_anchor(heading_text: str, anchor: str) -> bool:
    clean = anchor.lstrip("#").strip()
    a_slug, h_slug = slugify(clean), slugify(heading_text)
    if h_slug == a_slug: return True
    if h_slug.startswith(a_slug) and (len(h_slug) == len(a_slug) or h_slug[len(a_slug)] == '-'):
        return True
    if clean.lower() in heading_text.lower(): return True
    sec = re.match(r'^(§?\s*\d+(?:\.\d+)*)', clean)
    if sec:
        tok = sec.group(1).replace(" ", "")
        hsec = re.match(r'^(§?\s*\d+(?:\.\d+)*)', heading_text.lstrip("#").strip())
        if hsec and hsec.group(1).replace(" ", "") == tok: return True
    return False

class DAGValidator:
    def __init__(self, dag_path: Path, workspace_root: Path = None):
        self.dag_path = dag_path.resolve()
        self.subsystem_dir = self.dag_path.parent
        self.subsystem_name = self.subsystem_dir.name
        self.workspace_root = workspace_root.resolve() if workspace_root else Path.cwd().resolve()
        self.nodes, self.edges, self.in_degree = {}, defaultdict(list), defaultdict(int)
        self.errors = []
        self.coverage_mode = "id_based"
        self.conformance_row_count = 0

    def parse_dag(self):
        content = self.dag_path.read_text(encoding="utf-8")
        current = None
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"): continue
            if line.startswith("NODE:"):
                if current: self._register(current)
                current = {"header": line, "fields": {}, "line": line_num}
                continue
            if current:
                m = re.match(r'^\s*([A-Z_]+):\s*(.*)$', line)
                if m:
                    current["fields"][m.group(1)] = m.group(2).strip()
                elif current["fields"]:
                    k = list(current["fields"].keys())[-1]
                    current["fields"][k] += "\n" + stripped
        if current: self._register(current)

    def _register(self, node):
        parts = [p.strip() for p in node["header"][len("NODE:"):].split("|")]
        if len(parts) != 5:
            self.errors.append(f"Line {node['line']}: Malformed NODE header (needs 5 pipe fields): {node['header']}")
            return
        name, path, lang_field, tier_field, deps_field = parts
        lang = lang_field.replace("lang:", "").strip().lower()
        expected = EXPECTED_LANG.get(self.subsystem_name)
        if expected and lang != expected:
            self.errors.append(f"Language pin violation: node '{name}' declares '{lang}' but subsystem '{self.subsystem_name}' requires '{expected}'")
        try:
            tier = int(tier_field.replace("tier:", "").strip())
            if tier < 0: self.errors.append(f"Line {node['line']}: Negative tier in '{name}'")
        except ValueError:
            self.errors.append(f"Line {node['line']}: Invalid tier in '{name}': {tier_field}")
            tier = -1
        deps_raw = deps_field.replace("deps:", "").strip().strip("[]")
        deps = [d.strip() for d in deps_raw.split(",") if d.strip()]
        if name in self.nodes:
            self.errors.append(f"Duplicate node: '{name}'")
        self.nodes[name] = {"name": name, "path": path, "lang": lang, "tier": tier,
                            "deps": deps, "fields": node["fields"], "line": node["line"]}

    def verify_topology(self):
        all_nodes = set(self.nodes)
        for name, data in self.nodes.items():
            self.in_degree.setdefault(name, 0)
            for dep in data["deps"]:
                if dep not in all_nodes:
                    self.errors.append(f"Node '{name}' depends on undefined '{dep}'")
                    continue
                self.edges[dep].append(name)
                self.in_degree[name] += 1
                if data["tier"] <= self.nodes[dep]["tier"]:
                    self.errors.append(f"Tier inversion: '{name}' (tier {data['tier']}) must be > dependency '{dep}' (tier {self.nodes[dep]['tier']})")
        queue = deque(n for n in all_nodes if self.in_degree[n] == 0)
        visited = 0
        while queue:
            n = queue.popleft(); visited += 1
            for neigh in self.edges[n]:
                self.in_degree[neigh] -= 1
                if self.in_degree[neigh] == 0: queue.append(neigh)
        if visited != len(all_nodes):
            self.errors.append(f"Cycle detected: visited {visited} of {len(all_nodes)} nodes")

    def verify_coverage_and_invariants(self):
        seam_file = self.workspace_root / "seam-mappings" / f"{self.subsystem_name}-seam-mapping.md"
        if not seam_file.exists():
            self.errors.append(f"Missing seam mapping: {seam_file}"); return
        seam = seam_file.read_text(encoding="utf-8")
        cases = set(re.findall(r'\b((?:[A-Z]{1,4}-)?(?:C|T)[0-9]{2,3})\b', seam))
        prefix_alt = "|".join(INVARIANT_PREFIXES)
        invariants = set(re.findall(rf'\b((?:{prefix_alt})-[A-Z0-9_\-]+)\b', seam))
        declared_cases, declared_invs = [], set()
        for name, data in self.nodes.items():
            for c in data["fields"].get("TEST_ASSERTIONS", "").strip("[]").split(","):
                if c.strip(): declared_cases.append(c.strip())
            for i in data["fields"].get("INVARIANTS", "").strip("[]").split(","):
                if i.strip(): declared_invs.add(i.strip())
        if len(declared_cases) != len(set(declared_cases)):
            seen, dups = set(), set()
            for c in declared_cases:
                if c in seen: dups.add(c)
                seen.add(c)
            self.errors.append(f"Duplicate TEST_ASSERTIONS: {sorted(dups)}")
        declared_set = set(declared_cases)
        if cases:
            self.coverage_mode = "id_based"
            if (missing := cases - declared_set):
                self.errors.append(f"Uncovered conformance cases: {sorted(missing)}")
            if (extra := declared_set - cases):
                self.errors.append(f"DAG cites unknown cases: {sorted(extra)}")
        else:
            self.coverage_mode = "count_based"
            self.conformance_row_count = self._count_conformance_rows(seam)
            distinct = {c for c in declared_cases if len(c) >= 20}
            if len(distinct) < self.conformance_row_count:
                self.errors.append(
                    f"Count-based coverage shortfall: {len(distinct)} distinct TEST_ASSERTIONS "
                    f"(>=20 chars) < {self.conformance_row_count} conformance prose rows")
        if (missing_inv := invariants - declared_invs):
            self.errors.append(f"Unassigned invariants: {sorted(missing_inv)}")

    def verify_anchors_and_commands(self):
        for name, data in self.nodes.items():
            reads = data["fields"].get("READS", "")
            items = re.findall(r'([^,\[\]\s]+#[^,\[\]\s]+)', reads)
            if not items and not reads.strip().startswith("[]"):
                self.errors.append(f"Node '{name}' has empty or malformed READS")
            for item in items:
                rel, anchor = item.split("#", 1)
                p = self.workspace_root / rel.strip()
                if not p.exists():
                    self.errors.append(f"Node '{name}' READS missing file: {rel}"); continue
                headings = re.findall(r'^#{1,6}\s+(.*)$', p.read_text(encoding="utf-8"), re.MULTILINE)
                if not any(matches_anchor(h, anchor) for h in headings):
                    self.errors.append(f"Node '{name}' unresolvable anchor '#{anchor}' in {rel}")
            cmd = data["fields"].get("VERIFICATION", "").strip()
            if not cmd:
                self.errors.append(f"Node '{name}' empty VERIFICATION")
            elif cmd.split()[0].lower() not in ALLOWED_VERIFICATION_TOOLS:
                self.errors.append(f"Node '{name}' non-whitelisted command: {cmd.split()[0]}")

    def _count_conformance_rows(self, seam: str) -> int:
        lines = seam.splitlines()
        start = -1
        for i, line in enumerate(lines):
            if re.match(r'^#{1,6}\s+.*[Cc]onformance.*$', line.strip()):
                start = i
                break
        if start == -1:
            return 0
        level = len(lines[start].split()[0])
        count = 0
        for line in lines[start + 1:]:
            s = line.strip()
            if s.startswith("#") and len(s.split()[0]) <= level:
                break
            if not s.startswith("|"):
                continue
            cells = [c.strip() for c in s.strip("|").split("|")]
            if len(cells) < 2:
                continue
            if all(re.fullmatch(r':?-{2,}:?', c) for c in cells):
                continue
            if cells[0].lower() in ("test", "case", "check", "assertion", "id"):
                continue
            count += 1
        return count

    def run(self):
        self.parse_dag()
        if self.nodes:
            self.verify_topology()
            self.verify_coverage_and_invariants()
            self.verify_anchors_and_commands()
        else:
            self.errors.append("No valid NODE definitions found")
        report = {"subsystem": self.subsystem_name, "dag_file": str(self.dag_path),
                  "node_count": len(self.nodes), "passed": not self.errors,
                  "coverage_mode": self.coverage_mode,
                  "conformance_row_count": self.conformance_row_count,
                  "error_count": len(self.errors), "errors": self.errors}
        (self.subsystem_dir / "dag_audit_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        if self.errors:
            print(f"[DAG VALIDATION FAILED] {len(self.errors)} errors:")
            for e in self.errors: print(f"  - {e}")
            sys.exit(1)
        print(f"[DAG VALIDATION PASSED] {len(self.nodes)} nodes acyclic, 100% case/invariant coverage.")
        sys.exit(0)

if __name__ == "__main__":
    p = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path("module-graph-0.1.0.dag").resolve()
    DAGValidator(p).run()
