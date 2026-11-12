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
