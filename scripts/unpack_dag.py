#!/usr/bin/env python3
"""
Deterministic DAG Unpacker.
Expands module-graph-0.1.0.dag into per-module .omp-spec.md files.
Requires: pip install pyyaml
Usage: python3 scripts/unpack_dag.py subsystems/<subsystem>/module-graph-0.1.0.dag
"""
import re
import sys
from pathlib import Path
import yaml

LSP_REGISTRY = {
    "rust": {
        "server": "rust-analyzer",
        "marker": "Cargo.toml",
        "lang": "Rust",
        "entry_file": "src/lib.rs",
        "test_file": "tests/conformance.rs",
        "language_setup": """1. Create `Cargo.toml` in your working directory (`[package]` name = "{package_name}", edition = "2021").
2. Add each `CONSUMES` dependency under `[dependencies]` as a path dependency:
   `<dep_name> = {{ path = "../<dep_name>" }}`
3. Implement every `EXPOSES` item in `src/lib.rs`.
4. Implement conformance tests in `tests/conformance.rs` (one `#[test]` per `TEST_ASSERTION`, matching any test filter token in `verification_command`).
5. Run your `verification_command` until exit 0.

FORBIDDEN:
- Do NOT use `../../<dep_name>` — siblings live at `../<dep_name>`.
- Do NOT edit sibling crates or shared workspace files outside your working directory.""",
    },
    "python": {
        "server": "pyright",
        "marker": "pyproject.toml",
        "lang": "Python",
        "entry_file": "src/__init__.py",
        "test_file": "tests/test_conformance.py",
        "language_setup": """1. Create an isolated virtual environment IN YOUR WORKING DIRECTORY:
   `python3 -m venv .venv`
   Every subsequent pip/python/pytest command MUST go through `.venv/bin/`.

2. Install each `CONSUMES` dependency into your `.venv`:
   `.venv/bin/pip install -e ../<dep_name>` (one call per dependency)

3. Create `pyproject.toml` with this exact package mapping (no other top-level package allowed):
   ```toml
   [build-system]
   requires = ["setuptools>=68", "wheel"]
   build-backend = "setuptools.build_meta"

   [project]
   name = "{package_name}"
   version = "0.1.0"
   requires-python = ">=3.10"

   [tool.setuptools]
   packages = ["{package_name}"]
   package-dir = {{"{package_name}" = "src"}}
   ```
   This makes `import {package_name}` resolve to your `src/` directory.
   Do NOT rely on `import src.*` — that collides across modules.

4. Install the module itself: `.venv/bin/pip install -e .`

5. Run tests via: `.venv/bin/pytest tests/test_conformance.py` (or `.venv/bin/<verification_command>`).

6. Downstream modules will import you as `import {package_name}` (or `from {package_name} import X`). Your `EXPOSES` signatures must be re-exported from `src/__init__.py`.

FORBIDDEN:
- Do NOT install into system Python or any environment outside your working directory.
- Do NOT use `src` as an importable package name.
- Do NOT share a `.venv` with sibling modules.
- Do NOT commit `.venv/` (it is gitignored).""",
    },
    "go": {
        "server": "gopls",
        "marker": "go.mod",
        "lang": "Go",
        "entry_file": "module.go",
        "test_file": "conformance_test.go",
        "language_setup": """1. Initialize `go.mod` in your working directory (`module {package_name}`).
2. For each `CONSUMES` dependency, add a `require` and local `replace` directive in `go.mod`:
   `replace <dep_name> => ../<dep_name>`
3. Implement every `EXPOSES` symbol in `module.go` (and helper files in this directory if needed).
4. Implement conformance tests in `conformance_test.go` (one `Test...(*testing.T)` function per `TEST_ASSERTION`).
5. Run your `verification_command` until exit 0.

FORBIDDEN:
- Do NOT modify sibling modules or `go.mod` files outside your working directory.""",
    },
    "typescript": {
        "server": "tsserver",
        "marker": "package.json",
        "lang": "TypeScript",
        "entry_file": "src/index.ts",
        "test_file": "tests/conformance.test.ts",
        "language_setup": "Configure `package.json` and `tsconfig.json` in your working directory.",
    },
}

OMP_TEMPLATE = """---
name: {name}
description: {responsibility}
agent: coder
effort: med
verification_command: '{verification}'
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
| {entry_file} | create | {entry_desc} |
| {test_file} | create | Conformance test assertions implementation |

## Language-Specific Setup (MANDATORY)
{language_setup}

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
      "declared_in_consumes": "<declared>",
      "actual_exposed": "<actual>",
      "blocking_test_cases": ["<case_id_or_assertion>"]
    }}
  ]
}}
```

# OUTPUT CONTRACT
```json
{{
  "status": "COMPLETED" | "FAILED" | "BLOCKED" | "RATE_LIMITED",
  "module": "{name}",
  "subsystem": "{subsystem_name}",
  "files_created": ["<paths>"],
  "verification_result": "pass" | "fail",
  "assertions_passing": 0,
  "assertions_total": 0,
  "reason": "<if FAILED or BLOCKED>",
  "evidence": "<if FAILED, BLOCKED, or RATE_LIMITED>"
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

def transform_rust_verification(cmd: str) -> str:
    # Underscore filter tokens (rm-c01 -> rm_c01) per && -separated command.
    # Only tokens after each command's own `--` are filters; flags (starting
    # with `-`) and structure are preserved so chained invocations survive.
    if " -- " not in cmd:
        return cmd
    chunks = []
    for piece in cmd.split(" && "):
        if " -- " not in piece:
            chunks.append(piece)
            continue
        prefix, tail = piece.split(" -- ", 1)
        tokens = []
        for tok in tail.split():
            if tok.startswith("-"):
                tokens.append(tok)
            else:
                tokens.append(tok.replace("-", "_"))
        chunks.append(f"{prefix} -- {' '.join(tokens)}")
    return " && ".join(chunks)

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
                    docs = list(yaml.safe_load_all(cf.read_text(encoding="utf-8")))
                except Exception as e:
                    self.errors.append(f"Failed to parse {cf}: {e}")
                    continue
                def _scan(node):
                    if isinstance(node, dict):
                        if "id" in node and "rule" in node:
                            yield node
                        else:
                            for v in node.values():
                                yield from _scan(v)
                    elif isinstance(node, list):
                        for item in node:
                            yield from _scan(item)
                for data in docs:
                    for r in _scan(data):
                        self.invariant_index[r["id"]] = f"**[{r['id']}]**: {r['rule'].strip()}"
        seam_dir = self.workspace_root / "seam-mappings"
        if seam_dir.exists():
            for sf in seam_dir.glob("*.md"):
                content = sf.read_text(encoding="utf-8")
                pat = r'(?:^|\n|\|)\s*(?:###|\*\*|\|\s*)?((?:[A-Z]{1,4}-)?(?:C|T)[0-9]{2,3})\b\s*[:—\-]\s*(.*?)(?=\n\s*(?:###|\*\*|\|)\s*(?:(?:[A-Z]{1,4}-)?(?:C|T)[0-9]{2,3})|\n\s*##|\Z)'
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
            package_name = name.replace("-", "_")
            language_setup = lsp.get(
                "language_setup", "No language-specific setup required."
            ).format(package_name=package_name)
            entry_desc = (
                f"Package source; installed as `{package_name}`"
                if lang == "python"
                else "Module entry point and public interface"
            )
            spec = OMP_TEMPLATE.format(
                name=name, responsibility=f"Module implementing {name} at tier {tier}",
                verification=(transform_rust_verification(f.get("VERIFICATION", "").strip())
                              if lang == "rust" else f.get("VERIFICATION", "").strip()),
                subsystem_name=subsystem_name,
                lsp_lang=lsp["lang"], lsp_server=lsp["server"], lsp_marker=lsp["marker"],
                entry_file=lsp["entry_file"], entry_desc=entry_desc, test_file=lsp["test_file"],
                language_setup=language_setup,
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