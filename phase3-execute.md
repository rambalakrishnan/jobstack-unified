# Phase 3 Execution Plan — Block Resolution

Save this file and instruct the TUI: "Read tree/phase3-execute.md in full and execute §1 through §5."

**Critical:** Every subagent spawn in this document uses OMP's internal `task` tool, not shell commands. Wherever you see "spawn subagent," invoke `task` with the specified parameters. Do not invoke `omp --path`, `omp --task`, or any shell equivalent.

---

## §1. Prerequisites (run once)

```bash
pip install pyyaml
mkdir -p scripts subsystems/crawler subsystems/circus-tent subsystems/ringmaster subsystems/hellscape subsystems/job-hunter
```

Verify each script parses before proceeding:

```bash
python3 -c "import ast; ast.parse(open('scripts/verify_dag.py').read())" && echo OK
python3 -c "import ast; ast.parse(open('scripts/unpack_dag.py').read())" && echo OK
python3 -c "import ast; ast.parse(open('scripts/verify_specs.py').read())" && echo OK
```

If any fails, write the corresponding script from §2 before continuing.

---

## §2. Infrastructure Scripts

### `scripts/verify_dag.py`

```python
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
        cases = set(re.findall(r'\b([A-Z]{0,4}-?C[0-9]{2,3})\b', seam))
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
        if (missing := cases - declared_set):
            self.errors.append(f"Uncovered conformance cases: {sorted(missing)}")
        if (extra := declared_set - cases):
            self.errors.append(f"DAG cites unknown cases: {sorted(extra)}")
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
```

### `scripts/unpack_dag.py`

```python
#!/usr/bin/env python3
"""
Deterministic DAG Unpacker.
Expands module-graph-0.1.0.dag into per-module .omp-spec.md files.
Requires: pip install pyyaml
Usage: python3 scripts/unpack_dag.py subsystems/<subsystem>/module-graph-0.1.0.dag
"""
import re, sys
from pathlib import Path
import yaml

LSP_REGISTRY = {
    "rust": {"server": "rust-analyzer", "marker": "Cargo.toml", "lang": "Rust",
             "entry_file": "src/lib.rs", "test_file": "tests/conformance.rs"},
    "python": {"server": "pyright", "marker": "pyproject.toml", "lang": "Python",
               "entry_file": "src/__init__.py", "test_file": "tests/test_conformance.py"},
    "go": {"server": "gopls", "marker": "go.mod", "lang": "Go",
           "entry_file": "module.go", "test_file": "conformance_test.go"},
    "typescript": {"server": "tsserver", "marker": "package.json", "lang": "TypeScript",
                   "entry_file": "src/index.ts", "test_file": "tests/conformance.test.ts"},
}

OMP_TEMPLATE = """---
name: {name}
description: {responsibility}
agent: coder
effort: med
verification_command: "{verification}"
verification_expect: "0"
---

# TARGET MODULE
{name}

# WORKSPACE ROOT
./subsystems/{subsystem_name}/modules/{name}

# LSP BOUNDARIES
## Auto-Discovered Language Servers
| Language | Server | Root Marker |
|----------|--------|-------------|
| {lsp_lang} | {lsp_server} | {lsp_marker} |

## LSP-Covered Symbols (DO NOT DOCUMENT)
- Standard library modules
- Declared dependencies within workspace

# BLIND SPOT DOCUMENTATION
## Invariants & Test Assertions
### Invariants
{invariants_dereferenced}

### Conformance Assertions
{test_assertions_dereferenced}

## Schemas, State Machines & Formulas (Dereferenced Verbatim)
{inlined_blind_spots}

# IMPLEMENTATION CONTRACT
## Files to Create or Modify
| Path | Action | Description |
|------|--------|-------------|
| {entry_file} | create | Module entry point and public interface |
| {test_file} | create | Conformance test assertions implementation |

## Public Interface (EXPOSES)
```{lang_lower}
{exposes}
```

## Consumed Dependencies (CONSUMES)
```{lang_lower}
{consumes}
```

## Boundary Execution Constraints (FORBIDDEN)
{forbidden_formatted}
- No in-band nulls; all missing fields must use typed Missing envelopes.
- No shared database writes or cross-domain transactions.

# VERIFICATION CONTRACT
## Primary Command
```bash
{verification}
```
Expected result: Exit code 0.

# INTERFACE GAP REPORTING
If the declared EXPOSES or CONSUMES interface is insufficient to implement
the required TEST_ASSERTIONS, do NOT invent unapproved types or signatures.
Output this JSON block and terminate:
```json
{{
  "status": "INTERFACE_GAP",
  "gaps": [
    {{
      "missing_from_dependency": "<module_name>",
      "required_signature": "<exact signature needed>",
      "blocking_test_cases": ["<case_id>"]
    }}
  ]
}}
```

# OUTPUT CONTRACT
```json
{{
  "status": "COMPLETED" | "FAILED" | "BLOCKED",
  "summary": "Implementation summary",
  "files_changed": ["paths"],
  "verification_result": "pass" | "fail"
}}
```
"""

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

class SpecUnpacker:
    def __init__(self, workspace_root: Path = None):
        self.workspace_root = workspace_root.resolve() if workspace_root else Path.cwd().resolve()
        self.errors = []
        self.invariant_index = {}
        self.assertion_index = {}
        self._build_indexes()

    def _build_indexes(self):
        contracts_dir = self.workspace_root / "contracts"
        if contracts_dir.exists():
            for cf in contracts_dir.glob("*.yaml"):
                try:
                    data = yaml.safe_load(cf.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        rules = data.get("x-semantic-rules", []) or data.get("x-invariants", []) or []
                        for r in rules:
                            if isinstance(r, dict) and "id" in r and "rule" in r:
                                self.invariant_index[r["id"]] = f"**[{r['id']}]**: {r['rule'].strip()}"
                except Exception as e:
                    self.errors.append(f"Failed to parse {cf}: {e}")
        seam_dir = self.workspace_root / "seam-mappings"
        if seam_dir.exists():
            for sf in seam_dir.glob("*.md"):
                content = sf.read_text(encoding="utf-8")
                pat = r'(?:^|\n|\|)\s*(?:###|\*\*|\|\s*)?([A-Z]{0,4}-?C[0-9]{2,3})\b\s*[:—\-]\s*(.*?)(?=\n\s*(?:###|\*\*|\|)\s*(?:[A-Z]{0,4}-?C[0-9]{2,3})|\n\s*##|\Z)'
                for cid, desc in re.findall(pat, content, re.DOTALL):
                    self.assertion_index[cid] = f"**[{cid}]**: {' '.join(desc.strip().split())}"

    def extract_anchor(self, fp: Path, anchor: str) -> str:
        if not fp.exists():
            self.errors.append(f"File missing: {fp}")
            return f"<!-- ERROR: file missing: {fp} -->"
        lines = fp.read_text(encoding="utf-8").splitlines()
        start, level = -1, 0
        for i, line in enumerate(lines):
            if line.startswith("#") and matches_anchor(line.lstrip("#").strip(), anchor):
                start, level = i, len(line.split()[0]); break
        if start == -1:
            self.errors.append(f"Anchor '{anchor}' not in {fp}")
            return f"<!-- ERROR: anchor '{anchor}' not in {fp} -->"
        end = len(lines)
        for i in range(start + 1, len(lines)):
            if lines[i].startswith("#") and len(lines[i].split()[0]) <= level:
                end = i; break
        return "\n".join(lines[start:end]).strip()

    def resolve_reads(self, reads_raw: str) -> str:
        items = re.findall(r'([^,\[\]\s]+#[^,\[\]\s]+)', reads_raw)
        blocks = []
        for item in items:
            rel, anchor = item.split("#", 1)
            content = self.extract_anchor(self.workspace_root / rel.strip(), anchor.strip())
            blocks.append(f"#### Reference: `{item}`\n\n{content}\n")
        return "\n".join(blocks) if blocks else "No external schemas referenced."

    def deref_invariants(self, raw: str) -> str:
        ids = [i.strip() for i in raw.strip("[]").split(",") if i.strip()]
        return "\n".join(f"- {self.invariant_index.get(i, f'**[{i}]**: See contracts.')}" for i in ids) or "- None."

    def deref_assertions(self, raw: str) -> str:
        ids = [c.strip() for c in raw.strip("[]").split(",") if c.strip()]
        return "\n".join(f"- {self.assertion_index.get(c, f'**[{c}]**: See seam mapping.')}" for c in ids) or "- None."

    def unpack(self, dag_path: Path):
        subsystem_dir = dag_path.parent
        subsystem_name = subsystem_dir.name
        content = dag_path.read_text(encoding="utf-8")
        nodes, current = [], None
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"): continue
            if line.startswith("NODE:"):
                if current: nodes.append(current)
                current = {"header": line, "fields": {}, "line": line_num}
                continue
            if current:
                m = re.match(r'^\s*([A-Z_]+):\s*(.*)$', line)
                if m: current["fields"][m.group(1)] = m.group(2).strip()
                elif current["fields"]:
                    k = list(current["fields"].keys())[-1]
                    current["fields"][k] += "\n" + stripped
        if current: nodes.append(current)

        seen = set()
        for node in nodes:
            parts = [p.strip() for p in node["header"][len("NODE:"):].split("|")]
            if len(parts) != 5:
                self.errors.append(f"Line {node['line']}: Malformed header"); continue
            if parts[0] in seen:
                self.errors.append(f"Duplicate node: '{parts[0]}'")
            seen.add(parts[0])
        if self.errors:
            print(f"[UNPACK PRE-FLIGHT FAILED] {len(self.errors)} errors")
            for e in self.errors: print(f"  - {e}")
            sys.exit(1)

        created = 0
        for node in nodes:
            parts = [p.strip() for p in node["header"][len("NODE:"):].split("|")]
            name, lang = parts[0], parts[2].replace("lang:", "").strip().lower()
            tier = parts[3].replace("tier:", "").strip()
            if lang not in LSP_REGISTRY:
                self.errors.append(f"Unsupported lang '{lang}' in '{name}'"); continue
            f = node["fields"]
            forbidden_raw = f.get("FORBIDDEN", "").strip()
            forbidden_items = []
            for line in forbidden_raw.splitlines():
                item = re.sub(r'^\s*[-*+]\s*', '', line).strip()
                if item: forbidden_items.append(f"- {item}")
            if not forbidden_items and forbidden_raw:
                for part in re.split(r'[,;]\s*', forbidden_raw):
                    item = re.sub(r'^\s*[-*+]\s*', '', part).strip()
                    if item: forbidden_items.append(f"- {item}")
            forbidden_formatted = "\n".join(forbidden_items) if forbidden_items else "- No forbidden constraints specified."
            lsp = LSP_REGISTRY[lang]
            spec = OMP_TEMPLATE.format(
                name=name, responsibility=f"Module implementing {name} at tier {tier}",
                verification=f.get("VERIFICATION", "").strip(), subsystem_name=subsystem_name,
                lsp_lang=lsp["lang"], lsp_server=lsp["server"], lsp_marker=lsp["marker"],
                entry_file=lsp["entry_file"], test_file=lsp["test_file"],
                invariants_dereferenced=self.deref_invariants(f.get("INVARIANTS", "")),
                test_assertions_dereferenced=self.deref_assertions(f.get("TEST_ASSERTIONS", "")),
                inlined_blind_spots=self.resolve_reads(f.get("READS", "")),
                lang_lower=lang, exposes=f.get("EXPOSES", "").strip(),
                consumes=f.get("CONSUMES", "").strip(),
                forbidden_formatted=forbidden_formatted)
            out = subsystem_dir / "modules" / name / ".omp-spec.md"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(spec, encoding="utf-8")
            created += 1

        if self.errors:
            print(f"[UNPACK FAILED] {len(self.errors)} errors")
            for e in self.errors: print(f"  - {e}")
            sys.exit(1)
        print(f"[UNPACK SUCCESS] {created} specs for {subsystem_name}")

if __name__ == "__main__":
    p = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path("module-graph-0.1.0.dag").resolve()
    SpecUnpacker().unpack(p)
```

### `scripts/verify_specs.py`

```python
#!/usr/bin/env python3
"""
Post-unpack spec audit.
Verifies section presence, frontmatter validity, and command whitelisting.
Usage: python3 scripts/verify_specs.py subsystems/<subsystem>/module-graph-0.1.0.dag
"""
import sys
from pathlib import Path
import yaml

REQUIRED_SECTIONS = [
    "# TARGET MODULE", "# WORKSPACE ROOT", "# LSP BOUNDARIES",
    "# BLIND SPOT DOCUMENTATION", "# IMPLEMENTATION CONTRACT",
    "# VERIFICATION CONTRACT", "# INTERFACE GAP REPORTING", "# OUTPUT CONTRACT",
]
ALLOWED_COMMAND_TOOLS = {"cargo", "pytest", "python", "go", "npm", "npx", "yarn", "pnpm"}

def verify(dag_path: Path):
    subsystem_dir = dag_path.parent
    modules_dir = subsystem_dir / "modules"
    dag_content = dag_path.read_text(encoding="utf-8")
    expected = [l.split("|")[0].replace("NODE:", "").strip()
                for l in dag_content.splitlines() if l.startswith("NODE:")]
    errors = []
    if not modules_dir.exists():
        print(f"Modules dir missing: {modules_dir}"); sys.exit(1)
    for name in expected:
        spec = modules_dir / name / ".omp-spec.md"
        if not spec.exists():
            errors.append(f"Missing spec for node: {spec}"); continue
        content = spec.read_text(encoding="utf-8")
        if "<!-- ERROR:" in content:
            errors.append(f"Unresolved anchor ERROR in {name}/.omp-spec.md")
        for sec in REQUIRED_SECTIONS:
            if sec not in content:
                errors.append(f"Missing section '{sec}' in {name}/.omp-spec.md")
        if content.startswith("---"):
            end = content.find("\n---", 4)
            if end == -1:
                errors.append(f"Unterminated frontmatter in {name}/.omp-spec.md")
            else:
                try:
                    fm = yaml.safe_load(content[4:end])
                    if not isinstance(fm, dict):
                        errors.append(f"Frontmatter not a mapping in {name}/.omp-spec.md")
                    elif "verification_command" not in fm:
                        errors.append(f"Missing verification_command in {name}/.omp-spec.md")
                    else:
                        cmd = str(fm["verification_command"]).strip()
                        if not cmd:
                            errors.append(f"Empty verification_command in {name}/.omp-spec.md")
                        elif cmd.split()[0].lower() not in ALLOWED_COMMAND_TOOLS:
                            errors.append(f"Non-whitelisted command '{cmd.split()[0]}' in {name}/.omp-spec.md")
                except yaml.YAMLError as e:
                    errors.append(f"Malformed YAML in {name}/.omp-spec.md: {e}")
    if errors:
        print(f"[SPEC AUDIT FAILED] {len(errors)} issues in {subsystem_dir.name}:")
        for e in errors: print(f"  - {e}")
        sys.exit(1)
    print(f"[SPEC AUDIT PASSED] All {len(expected)} specs verified in {subsystem_dir.name}")
    sys.exit(0)

if __name__ == "__main__":
    p = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path("module-graph-0.1.0.dag").resolve()
    verify(p)
```

---

## §3. Pinned subsystem → language map

| Subsystem | Path | Language | `lang:` value |
|---|---|---|---|
| Crawler | `subsystems/crawler/` | Rust | `rust` |
| Circus-tent | `subsystems/circus-tent/` | Python | `python` |
| Ringmaster | `subsystems/ringmaster/` | Rust | `rust` |
| Hellscape | `subsystems/hellscape/` | Go | `go` |
| Job-hunter | `subsystems/job-hunter/` | Python | `python` |

Enforced by `verify_dag.py`. Any node whose `lang:` differs from its subsystem's pin is a blocking error.

---

## §4. Orchestration protocol

### Subagent invocation — using the `task` tool

Every "spawn subagent" instruction below means: **invoke the `task` tool** with these fields:

| Field | Value |
|---|---|
| `agent` | `"reviewer"` for Step 1.B; `"coder"` for Step 6 |
| `effort` | `"med"` |
| `model_role` | `"task"` |
| `name` | unique short identifier (e.g., `"argon-crawler-review"`, `"tier0-crawler-spotcheck"`) |
| `task` | the prompt text specified below |
| `working_path` | the module's directory for Step 6; workspace root for Step 1.B |
| `context` (or equivalent file-access field) | the input file paths listed below |

**Do not invoke `omp`, `omp --path`, or any shell command to spawn subagents.** Use only the `task` tool. If the `task` tool's schema requires different field names than listed above, adapt them to match — the intent is: agent=coder or reviewer, working directory as specified, prompt as specified, files accessible.

---

### Step 1 — Astra DAG generation

**Five parallel external calls via `flex_submit` from flex-mcp.** This is not a `task` tool invocation; Astra is an external model exposed through a separate MCP server.

For each subsystem, submit:

```
Engine: gpt-6-astra
Parameters:
  service_tier: "flex"
  reasoning_effort: "xhigh"
  max_output_tokens: 24000
  previous_response_id: <from seam-mappings/phase2-chain-tips.md for this subsystem, if warm>
```

Verify tip warmth first: call `flex_status({response_id: "<tip>"})`. If status is `not_found` or the tip was deleted, submit fresh with sources re-attached and no `previous_response_id`.

User message content for the submission:

```
[Layer 0 — global spine]
<full contents of contracts/00-evidence-kernel.yaml>
<full contents of contracts/01-application-attempt-lifecycle.yaml>
<full contents of contracts/02-external-connector.yaml>
<full contents of contracts/03-internal-browser-binding.yaml>
<full contents of contracts/04-owner-separated-write-domains.yaml>
<full contents of contracts/05-suggested-fix-registry.yaml>
<full contents of 1-handoff-brief.txt>

[Layer 1 — subsystem context]
<full contents of feature-inventories/{SUBSYSTEM}-feature-inventory.md>
<full contents of seam-mappings/{SUBSYSTEM}-seam-mapping.md>

[Layer 2 — directive]
Compile the internal architecture for subsystem: {SUBSYSTEM} into an acyclic DAG.
Language is pinned to: {LANG}. Any node with a different language is invalid.

Target output: subsystems/{SUBSYSTEM}/module-graph-0.1.0.dag
Format: compact pipe-delimited.

GRAMMAR:
NODE: <module_name> | modules/<module_name> | lang: {LANG} | tier: <int> | deps: [<dep1>, <dep2>]
  READS: [<file#section_anchor>, ...]
  EXPOSES: [<exact_type_or_trait_signatures>]
  CONSUMES: [<dep_name: exact_type_or_trait_signatures>]
  TEST_ASSERTIONS: [<case_id1>, <case_id2>, ...]
  INVARIANTS: [<INVARIANT_ID1>, <INVARIANT_ID2>, ...]
  FORBIDDEN:
    - <negative_constraint_1>
    - <negative_constraint_2>
  VERIFICATION: <exact_deterministic_cli_command>

RULES:
1. Target path MUST be 'modules/<module_name>'.
2. READS cites exact markdown heading text or exact slugs (e.g. #§11.5-cursor-schema, #tier-2-heal).
3. EXPOSES declares exact public structs, traits, or functions this module provides.
4. CONSUMES declares exact signatures expected from dependencies.
5. FORBIDDEN is a newline-separated list of strict boundary constraints.
6. VERIFICATION is language-idiomatic and filters on this module's TEST_ASSERTIONS:
   - Rust:   cargo test -p {module_name} -- {case_ids_lowercase}
   - Python: pytest tests/test_conformance.py -k "{case1} or {case2}"
   - Go:     go test ./... -run "Test{case1}|Test{case2}"
7. Assign integer tiers strictly: every node's tier > its dependencies' tiers.
8. Every conformance case ID from seam-mappings/{SUBSYSTEM}-seam-mapping.md appears in
   exactly one node's TEST_ASSERTIONS. No case omitted. No case duplicated.
9. Every invariant ID (EK-*, OWD-*, EXT-*, LIFE-*, BO-*, CF-*) from the seam mapping
   appears in at least one node's INVARIANTS.

Do NOT self-check or recount assertions. Emit the DAG directly.
```

Polling loop: `flex_status` every 60s up to 20 minutes. On `completed`, retrieve via `flex_get` and write bytes verbatim to `subsystems/{SUBSYSTEM}/module-graph-0.1.0.dag`. On `incomplete`, chain a continuation with `previous_response_id` set to the incomplete response and higher `max_output_tokens`. Retain the final `response_id` for Phase 4.

---

### Step 1.A — Deterministic DAG validation

For each subsystem, run:

```bash
python3 scripts/verify_dag.py subsystems/{SUBSYSTEM}/module-graph-0.1.0.dag
```

**Retry-once protocol:**

- Exit 0 → proceed to Step 1.B.
- Exit 1 → read `subsystems/{SUBSYSTEM}/dag_audit_report.json`, extract the `errors` array, resubmit to Astra with the DAG's `response_id` as `previous_response_id` and the following user message appended:

```
The previously generated DAG failed deterministic validation:

<errors array from dag_audit_report.json, one per line>

Regenerate subsystems/{SUBSYSTEM}/module-graph-0.1.0.dag correcting these exact failures. Preserve all previously-covered cases and invariants.
```

Re-run Step 1.A. If it fails a second time: **halt and escalate to operator with both audit reports.**

---

### Step 1.B — Semantic interface review

For each subsystem, invoke the `task` tool:

```
agent: "reviewer"
effort: "med"
model_role: "task"
name: "argon-review-{SUBSYSTEM}"
working_path: (workspace root)
context (files to include):
  - subsystems/{SUBSYSTEM}/module-graph-0.1.0.dag
  - subsystems/{SUBSYSTEM}/dag_audit_report.json
  - seam-mappings/{SUBSYSTEM}-seam-mapping.md
task: |
  Semantic interface review for subsystem {SUBSYSTEM} (language {LANG}).

  Inputs are in your context.

  Context note: Topology, acyclicity, tier monotonicity, language pin, 100%
  conformance case coverage, 100% invariant coverage, anchor resolution, and
  command whitelist are already verified by verify_dag.py. Do NOT recount or
  re-verify anything passing in dag_audit_report.json.

  Review exactly four things:

  1. INTERFACE SYMMETRY
     For every edge A -> B: does B's CONSUMES match A's EXPOSES?
     - Type shape mismatch (Option<T> vs T; &T vs T in Rust; Optional[T] vs T in Python)
     - Missing exposure (B consumes something no dependency exposes)
     - Phantom exposure (A exposes something no consumer needs)

  2. LANGUAGE-SPECIFIC SIGNATURE RIGOR
     - Rust: pub visibility, Result<T, E> where fallible, lifetimes when borrowed
     - Python: no leading _, Optional[T] where nullable, full annotations
     - Go: exported (capitalized) names, (T, error) returns, interface definitions

  3. READS RELEVANCE
     Over-reading (module reads sections unrelated to its responsibility) = scope creep
     Under-reading (module omits necessary context) = missing invariants
     Do NOT judge whether the module itself is needed — that was Astra's call.

  4. MODULE COUNT AND COHESION
     Fewer than ~8 modules for a 94-103 KB seam mapping suggests under-decomposition.
     More than ~20 suggests fragmentation. Flag either as a scope concern, not a blocker.

  Output exactly one of:

  APPROVED: {SUBSYSTEM} INTERFACES VERIFIED

  or

  REJECTED: {SUBSYSTEM}
  - module_X: <specific issue with A->B edge reference>
  - module_Y: <specific issue>
  ...
```

**Retry-once protocol:**

- `APPROVED` → proceed to Step 2.
- `REJECTED` → parse the discrepancy list, resubmit to Astra with the DAG's `response_id` as `previous_response_id` and the following user message:

```
The previous DAG was semantically rejected during interface review:

<REJECTED body verbatim>

Patch the DAG by correcting these specific interface issues. Do not introduce new modules or remove existing ones. Preserve all test assertions and invariant assignments.
```

Re-run Step 1.A and Step 1.B.

If `REJECTED` a second time: **halt and escalate to operator with both rejection outputs.**

---

### Step 2 — Deterministic spec unpacking

For each subsystem, run:

```bash
python3 scripts/unpack_dag.py subsystems/{SUBSYSTEM}/module-graph-0.1.0.dag
```

- Exit 0 → proceed to Step 3.
- Exit 1 → this indicates a script bug (anchor matcher divergence between `verify_dag.py` and `unpack_dag.py`, or a missing contracts/seam-mapping file). Diagnose locally, fix `unpack_dag.py` if needed, re-run. Do not modify the DAG.

---

### Step 3 — Post-unpack spec audit

For each subsystem, run:

```bash
python3 scripts/verify_specs.py subsystems/{SUBSYSTEM}/module-graph-0.1.0.dag
```

- Exit 0 → proceed to Step 6 preparation.
- Exit 1 → read the error list. Fix the indicated defect (usually: a missing anchor that `verify_dag.py` accepted but `unpack_dag.py` couldn't resolve, or a malformed frontmatter field from an unexpected DAG node value). Re-run Step 2 and Step 3.

---

### Step 6 — Dual-tier functional spot check

**Crawler pilot only. Do not fan out to siblings until crawler's `phase3_audit.json` exists with `phase3_complete: true`.**

**Identify crawler's Tier-0 module:**

```bash
grep -E "tier:\s*0\b" subsystems/crawler/module-graph-0.1.0.dag | head -n 1
```

Extract the module name from the first pipe-delimited field after `NODE: `. Call it `{TIER0_MODULE}`.

**Identify crawler's highest-tier module:**

```bash
grep -oE "tier:\s*[0-9]+" subsystems/crawler/module-graph-0.1.0.dag | sort -t: -k2 -n | tail -1
```

Extract the module name of the node with the maximum tier value. Call it `{TIER_N_MODULE}`.

**Spawn two coder subagents via the `task` tool.** These can run in parallel.

Tier-0 invocation:

```
agent: "coder"
effort: "med"
model_role: "task"
name: "tier0-crawler-spotcheck"
working_path: "./subsystems/crawler/modules/{TIER0_MODULE}"
context (files to include):
  - subsystems/crawler/modules/{TIER0_MODULE}/.omp-spec.md
  - contracts/*.yaml (all six for reference)
task: |
  Read .omp-spec.md and implement the module contract in this working directory.

  Requirements:
  - Implement every EXPOSES signature exactly as declared.
  - Consume dependencies per CONSUMES declarations.
  - Satisfy every TEST_ASSERTION listed in the spec.
  - Run the VERIFICATION command in the frontmatter until it passes.

  If CONSUMES references dependencies that are not yet implemented in this
  working tree, generate stub implementations matching those exact declared
  signatures. Stubs must compile and provide the declared interface; they do
  not need to implement real behavior.

  If a required dependency signature is missing from CONSUMES, output the
  INTERFACE_GAP JSON block defined in .omp-spec.md §"INTERFACE GAP REPORTING"
  and terminate.

  Report status via the OUTPUT CONTRACT JSON block in .omp-spec.md.
```

Tier-N invocation (identical prompt, different working path):

```
agent: "coder"
effort: "med"
model_role: "task"
name: "tierN-crawler-spotcheck"
working_path: "./subsystems/crawler/modules/{TIER_N_MODULE}"
context (files to include):
  - subsystems/crawler/modules/{TIER_N_MODULE}/.omp-spec.md
  - contracts/*.yaml (all six for reference)
task: |
  Read .omp-spec.md and implement the module contract in this working directory.

  Requirements:
  - Implement every EXPOSES signature exactly as declared.
  - Consume dependencies per CONSUMES declarations.
  - Satisfy every TEST_ASSERTION listed in the spec.
  - Run the VERIFICATION command in the frontmatter until it passes.

  If CONSUMES references dependencies that are not yet implemented in this
  working tree, generate stub implementations matching those exact declared
  signatures. Stubs must compile and provide the declared interface; they do
  not need to implement real behavior.

  If a required dependency signature is missing from CONSUMES, output the
  INTERFACE_GAP JSON block defined in .omp-spec.md §"INTERFACE GAP REPORTING"
  and terminate.

  Report status via the OUTPUT CONTRACT JSON block in .omp-spec.md.
```

**Interpretation matrix (crawler):**

| Tier-0 result | Tier-N result | Action |
|---|---|---|
| `COMPLETED` | `COMPLETED` | Write crawler `phase3_audit.json` (§5). Then fan out to siblings. |
| `COMPLETED` | `INTERFACE_GAP` | Patch DAG per protocol below. Re-run Step 1.A, Step 3, and OMP for affected modules only. |
| `INTERFACE_GAP` | any | Same as above. |
| `FAILED` / `BLOCKED` | any | Diagnose: is the failure a spec defect (charter is wrong), a script defect (unpacker emitted bad spec), or a DAG defect (interface declaration is wrong)? Fix at the correct layer. Re-run Steps 2–6 for the affected subsystem. |

**INTERFACE_GAP patch protocol:**

1. Capture the `INTERFACE_GAP` JSON block from the subagent's output.
2. Resubmit to Astra with the DAG's `response_id` as `previous_response_id` and the following user message:

```
The Tier-N spot check revealed an interface gap:

<INTERFACE_GAP JSON verbatim>

Patch the DAG by adding the missing signatures to the relevant CONSUMES
or EXPOSES declarations. Do not add new modules, remove existing ones, or
change tier assignments. Preserve all test assertions and invariant
assignments.
```

3. Re-run Step 1.A and Step 3.
4. Identify which modules' EXPOSES or CONSUMES changed in the patched DAG (diff the DAG before/after). Re-run OMP via `task` tool **only for those modules**.
5. If the gap persists after one patch cycle, halt and escalate.

**Sibling fanout — only after crawler passes:**

Once `subsystems/crawler/phase3_audit.json` exists with `phase3_complete: true`, run Step 6 identically for the four sibling subsystems in parallel: `circus-tent`, `ringmaster`, `hellscape`, `job-hunter`.

Each sibling's Tier-0 and Tier-N spot checks are independent. A sibling failure does not block other siblings.

---

## §5. Phase 3 audit completion

For each subsystem that passes Step 6, write `subsystems/{SUBSYSTEM}/phase3_audit.json`:

```json
{
  "subsystem": "{SUBSYSTEM}",
  "language": "{LANG}",
  "phase3_version": "0.1.0",
  "completed_at": "<ISO8601 UTC timestamp>",
  "dag_validated": true,
  "argon_reviewed": true,
  "argon_review_output": "APPROVED: {SUBSYSTEM} INTERFACES VERIFIED",
  "specs_verified": true,
  "tier0_module": "{TIER0_MODULE}",
  "tier0_status": "pass",
  "tier_n_module": "{TIER_N_MODULE}",
  "tier_n_status": "pass",
  "module_count": <N>,
  "conformance_case_count": <M>,
  "phase3_complete": true,
  "astra_response_id": "<DAG generation response_id>"
}
```

Replace placeholders with actual values. `module_count` is the number of `NODE:` lines in the DAG. `conformance_case_count` is the total number of unique case IDs across all nodes' `TEST_ASSERTIONS`.

Phase 3 is complete when all five `phase3_audit.json` files exist with `phase3_complete: true`.

---

## §6. Operator invariants

1. **No manual edits to `.dag` or `.omp-spec.md` files.** If a spec is wrong, the defect is in (a) Astra's DAG generation, (b) the seam mapping (log to `subsystems/{SUBSYSTEM}/seam-ambiguities.json` and proceed), or (c) a script bug (fix locally, re-run affected step).
2. **Seam mappings are frozen at `0.1.0` for Phase 3 duration.** Mid-run ambiguity goes into `seam-ambiguities.json`. Do not modify `seam-mappings/*.md` during Phase 3.
3. **Astra is invoked only via `flex_submit`** (flex-mcp). OMP subagents are invoked only via the `task` tool. No shell invocation of either.
4. **Chain `previous_response_id` when the tip is warm.** Verify with `flex_status`. If cold or deleted, submit fresh — you lose the cache discount, not correctness.
5. **No Step 6 fanout past crawler until its `phase3_audit.json` exists.** The pilot exists to catch pipeline bugs at 1× cost instead of 5×.
6. **Cache TTL:** if Phase 2 tips are warm, 12-hour TTL saves ~$1.90 across 5 chained calls. If cold, do not enable — write premium exceeds read savings.

---

## §7. Cost table

| Step | Per subsystem | 5 subsystems |
|---|---|---|
| 1 (Astra DAG gen) | $1.70–4.50 | $8.50–22.50 |
| 1.A + 2 + 3 (local scripts) | $0.00 | $0.00 |
| 1.B (Argon review via task tool) | $0.14–0.28 | $0.70–1.40 |
| 6 (coder spot checks via task tool, ×2) | $1.00–2.50 | $5.00–12.50 |
| Output tokens (~30K per Astra call, ×5) | $1.50 | $7.50 |
| **Total** | **~$3–9** | **~$15–44** |

---

## §8. Phase 4 handoff

When all five `phase3_audit.json` files exist with `phase3_complete: true`, Phase 3 is complete. Hand off `subsystems/*/modules/*/.omp-spec.md` files to Phase 4 coding agents. They assume these specs are the immutable ground truth for interface signatures and logic. The `astra_response_id` in each `phase3_audit.json` is available for Phase 4 to chain against if spec refinement is needed during implementation.

**Proceed with execution.**
