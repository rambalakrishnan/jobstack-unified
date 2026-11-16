 #!/usr/bin/env python3
"""
Deterministic Phase 4 Orchestrator State Engine.

Designed to be driven by a thin OMP TUI loop that spawns `task` tool calls
with `isolated: true` and passes their JSON results back to `record`.

Subcommands:
  python3 scripts/phase4-orchestrate.py preflight
  python3 scripts/phase4-orchestrate.py tick
  python3 scripts/phase4-orchestrate.py record --results-file <path.json>
  python3 scripts/phase4-orchestrate.py status
  python3 scripts/phase4-orchestrate.py scope <subsystem> <tier>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

# --- Constants ---

PILOT_SUBSYSTEMS = ["crawler", "ringmaster", "hellscape", "job-hunter"]
COST_CEILING_USD = 300.0
POLL_INTERVAL_SECONDS = 30
PROGRESS_INTERVAL_SECONDS = 300
DEFAULT_COOLDOWN_SECONDS = 300

PRIMARY_PROVIDER = "opencode-go"
FAILOVER_PROVIDERS = {
    "muse-spark-1.3-contributor": ("meta", "muse-spark-1.3-contributor"),
    "deepseek-v4.1-flash": ("openrouter", "deepseek/deepseek-v4.1-flash-1017:floor"),
}
OPENROUTER_NO_FLOOR = ("openrouter", "deepseek/deepseek-v4.1-flash-1017")

# Fallback pricing per 1M tokens when provider does not emit cost_usd directly
PRICING_PER_M = {
    ("openrouter", "deepseek/deepseek-v4.1-flash-1017:floor"): (0.02, 0.108),
    ("openrouter", "deepseek/deepseek-v4.1-flash-1017"): (0.072, 0.108),
    ("opencode-go", "deepseek-v4.1-flash"): (0.072, 0.108),
    ("opencode-go", "muse-spark-1.3-contributor"): (0.03, 0.12),
    ("meta", "muse-spark-1.3-contributor"): (0.03, 0.12),
}

LINE_ITEM_PREFIXES = (
    "fn ", "pub fn ", "def ", "async def ", "func ", "trait ", "type ",
    "struct ", "enum ", "class ", "interface ", "const ", "static ",
)


def resolve_root() -> Path:
    cwd = Path.cwd().resolve()
    if (cwd / "subsystems").exists() and (cwd / "scripts").exists():
        return cwd
    if (cwd / "tree" / "subsystems").exists() and (cwd / "tree" / "scripts").exists():
        return cwd / "tree"
    return Path(__file__).resolve().parent.parent


ROOT = resolve_root()
STATE_FILE = ROOT / "phase4-state.json"
COMMANDS_FILE = ROOT / "phase4-commands.json"
APPROVALS_FILE = ROOT / "phase4-approvals.json"
PROGRESS_MD = ROOT / "phase4-progress.md"
PROGRESS_JSON = ROOT / "phase4-progress.json"
GAPS_DIR = ROOT / "interface-gaps"
CLASSIFICATION_FILE = ROOT / "subsystems" / "classification-final.json"
ROLLUP_FILE = ROOT / "phase4-rollup.json"


# --- Time & IO helpers ---

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return default
    return json.loads(raw)


def write_json(path: Path, data: Any) -> None:
    atomic_write(path, json.dumps(data, indent=2, sort_keys=True) + "\n")

# --- Git isolation & rollback guards ---

def git_run(args: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def git_head_sha() -> str | None:
    r = git_run(["rev-parse", "HEAD"])
    return r.stdout.strip() if r.returncode == 0 else None


def git_changed_paths_since(pre_sha: str) -> set[str]:
    paths: set[str] = set()
    for cmd in (
        ["diff", "--name-only", pre_sha, "HEAD"],
        ["diff", "--name-only"],
        ["diff", "--cached", "--name-only"],
        ["ls-files", "--others", "--exclude-standard"],
    ):
        r = git_run(cmd)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                line = line.strip()
                if line:
                    paths.add(line)
    return paths


def batch_touched_out_of_scope(pre_sha: str, allowed_prefix: str) -> list[str]:
    """Check if HEAD + working tree modified .omp-spec.md or anything outside allowed_prefix."""
    bad = []
    for p in sorted(git_changed_paths_since(pre_sha)):
        if p.startswith("interface-gaps/") or p == "phase4-rollup.json":
            continue
        if p.endswith("/.omp-spec.md") or p == ".omp-spec.md":
            bad.append(p)
        elif not p.startswith(allowed_prefix):
            bad.append(p)
    return bad


def scrub_batch_to_pre_sha(
    pre_sha: str | None,
    passing_module_dirs: set[str],
    rejected_module_dirs: set[str],
) -> list[str]:
    """
    Guarantees that no files from INTERFACE_GAP, FAILED, BLOCKED, RATE_LIMITED,
    failed-verification, or out-of-scope edits remain in HEAD or the working tree.
    """
    if not pre_sha:
        return []

    # Remove untracked .venv caches in rejected Python modules so retries start clean
    for mod_rel in rejected_module_dirs:
        venv = ROOT / mod_rel / ".venv"
        if venv.exists():
            shutil.rmtree(venv, ignore_errors=True)

    # Fast path: nothing in the batch passed -> wipe all commits & edits since pre_sha
    if not passing_module_dirs:
        head_now = git_head_sha()
        dirty = git_run(["status", "--porcelain"]).stdout.strip()
        if head_now != pre_sha or dirty:
            git_run(["reset", "--hard", pre_sha])
            git_run(["clean", "-fd"])
        return ["ALL_RESET_TO_PRE_BATCH_SHA"]

    # Mixed batch: keep ONLY valid files inside passing_module_dirs (never .omp-spec.md)
    reverted: list[str] = []
    for rel in sorted(git_changed_paths_since(pre_sha)):
        if rel.startswith("interface-gaps/") or rel == "phase4-rollup.json":
            continue
        in_passing = any(rel.startswith(p + "/") for p in passing_module_dirs)
        if in_passing and not rel.endswith("/.omp-spec.md"):
            continue

        # Restore exact pre_sha state (whether committed in HEAD or uncommitted)
        exists_at_pre = git_run(["cat-file", "-e", f"{pre_sha}:{rel}"]).returncode == 0
        if exists_at_pre:
            git_run(["checkout", pre_sha, "--", rel])
        else:
            git_run(["rm", "-rf", "--ignore-unmatch", "--", rel])
            target = ROOT / rel
            if target.exists() or target.is_symlink():
                if target.is_dir():
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
        reverted.append(rel)

    # Commit any staged rollbacks so HEAD stays clean for the next tier's branch merge
    if git_run(["diff", "--cached", "--quiet"]).returncode != 0:
        git_run(["commit", "-m", "phase4: revert partial/unverified edits from non-passing modules"])

    return reverted

# --- DAG & Spec parsing ---

def parse_dag(dag_path: Path) -> dict[str, dict[str, Any]]:
    content = dag_path.read_text(encoding="utf-8")
    raw_nodes = []
    current = None
    for line_num, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if line.startswith("NODE:"):
            if current is not None:
                raw_nodes.append(current)
            current = {"header": line, "fields": {}, "line": line_num}
            continue
        if current is not None:
            m = re.match(r"^\s*([A-Z_]+):\s*(.*)$", line)
            if m:
                current["fields"][m.group(1)] = m.group(2).strip()
            elif current["fields"]:
                k = list(current["fields"].keys())[-1]
                current["fields"][k] += "\n" + stripped
    if current is not None:
        raw_nodes.append(current)

    nodes: dict[str, dict[str, Any]] = {}
    for node in raw_nodes:
        parts = [p.strip() for p in node["header"][len("NODE:"):].split("|")]
        if len(parts) != 5:
            raise ValueError(f"{dag_path}:{node['line']}: malformed NODE header")
        name, mod_path, lang_field, tier_field, deps_field = parts
        lang = lang_field.replace("lang:", "").strip().lower()
        tier = int(tier_field.replace("tier:", "").strip())
        deps_raw = deps_field.replace("deps:", "").strip().strip("[]")
        deps = [d.strip() for d in deps_raw.split(",") if d.strip()]
        nodes[name] = {
            "name": name,
            "path": mod_path,
            "lang": lang,
            "tier": tier,
            "deps": deps,
            "fields": node["fields"],
        }
    return nodes


def parse_spec_frontmatter(spec_path: Path) -> dict[str, Any]:
    text = spec_path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    data = yaml.safe_load(text[4:end])
    return data if isinstance(data, dict) else {}


def load_classifications() -> dict[tuple[str, str], dict[str, Any]]:
    data = read_json(CLASSIFICATION_FILE)
    if not data or "classifications" not in data:
        raise FileNotFoundError(f"Missing or invalid {CLASSIFICATION_FILE}")
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in data["classifications"]:
        by_key[(entry["subsystem"], entry["module"])] = entry
    return by_key


def tier_schedule(nodes: dict[str, dict[str, Any]]) -> list[tuple[int, list[str]]]:
    groups: dict[int, list[str]] = defaultdict(list)
    for name, node in nodes.items():
        groups[node["tier"]].append(name)
    return [(t, sorted(groups[t])) for t in sorted(groups)]


# --- §10 Affected-Scope Analysis ---

def split_interface_items(block: str) -> list[str]:
    text = block.strip()
    if not text or text == "[]":
        return []
    # Strip markdown code fences if present
    text = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", text)
    text = re.sub(r"\n?```$", "", text).strip()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    qual = [
        ln for ln in lines
        if ln.startswith(LINE_ITEM_PREFIXES) or re.match(r"^[A-Za-z_][\w]*\s*:", ln)
    ]
    if lines and len(qual) == len(lines):
        return qual
    inner = text
    if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1].strip()
    if not inner:
        return []
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
            item = "".join(cur).strip()
            if item:
                items.append(item)
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        items.append(tail)
    return items


def _normalize_sig(item: str) -> str:
    return re.sub(r"\s+", " ", item.strip())


def _item_key(item: str) -> str:
    """Extract identifier prefix to distinguish signature-change from removal/addition."""
    norm = _normalize_sig(item)
    m = re.match(r"^(?:pub\s+)?(?:async\s+)?(?:fn|def|func|trait|type|struct|enum|class|interface|const|static)\s+([A-Za-z_][\w]*)", norm)
    if m:
        return m.group(1)
    m2 = re.match(r"^([A-Za-z_][\w]*)\s*[:(]", norm)
    if m2:
        return m2.group(1)
    return norm


def classify_interface_diff(old_raw: str, new_raw: str) -> str:
    old_items = [_normalize_sig(x) for x in split_interface_items(old_raw)]
    new_items = [_normalize_sig(x) for x in split_interface_items(new_raw)]
    if old_items == new_items:
        return "none"
    old_set, new_set = set(old_items), set(new_items)
    if old_set.issubset(new_set):
        return "additive"
    old_by_key = {_item_key(x): x for x in old_items}
    new_by_key = {_item_key(x): x for x in new_items}
    removed_keys = set(old_by_key) - set(new_by_key)
    if removed_keys:
        return "removal"
    return "signature-change"


def compute_prepatch_estimate(subsystem: str, tier: int, gap_report: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    blocked = set(gap_report.get("modules_blocked", []))
    deps_missing = {
        g.get("missing_from_dependency")
        for g in gap_report.get("gaps", [])
        if g.get("missing_from_dependency")
    }
    direct_reimplement = sorted(blocked | (deps_missing & set(nodes)))
    reverify = sorted(
        m for m, n in nodes.items()
        if m not in direct_reimplement and any(d in direct_reimplement for d in n["deps"])
    )
    unaffected = sorted(set(nodes) - set(direct_reimplement) - set(reverify))
    return {
        "subsystem": subsystem,
        "tier": tier,
        "kind": "pre_patch_estimate",
        "reimplement": direct_reimplement,
        "reverify": reverify,
        "unaffected": unaffected,
        "note": "Estimate only before patched DAG exists; exact §10 diff runs upon patch approval.",
    }


def compute_affected_scope(subsystem: str, tier: int, old_dag: Path, new_dag: Path) -> dict[str, Any]:
    old_nodes = parse_dag(old_dag)
    new_nodes = parse_dag(new_dag)
    all_mods = sorted(set(new_nodes))

    detail: dict[str, dict[str, str]] = {}
    reimplement: set[str] = set()
    breaking_exposes: set[str] = set()

    for m in all_mods:
        if m not in old_nodes:
            detail[m] = {"exposes_change": "added-module", "consumes_change": "added-module"}
            reimplement.add(m)
            continue
        old_f = old_nodes[m]["fields"]
        new_f = new_nodes[m]["fields"]
        exp_chg = classify_interface_diff(old_f.get("EXPOSES", ""), new_f.get("EXPOSES", ""))
        con_chg = classify_interface_diff(old_f.get("CONSUMES", ""), new_f.get("CONSUMES", ""))
        detail[m] = {"exposes_change": exp_chg, "consumes_change": con_chg}
        if exp_chg in ("additive", "signature-change", "removal"):
            reimplement.add(m)
        if exp_chg in ("signature-change", "removal"):
            breaking_exposes.add(m)
        if con_chg in ("signature-change", "removal"):
            reimplement.add(m)

    # Direct (1-hop) consumers of breaking EXPOSES changes must re-implement call sites
    for m, n in new_nodes.items():
        if any(d in breaking_exposes for d in n["deps"]):
            reimplement.add(m)

    # 1-hop consumers of RE-IMPLEMENT modules (not themselves RE-IMPLEMENT) must RE-VERIFY
    reverify: set[str] = set()
    for m, n in new_nodes.items():
        if m not in reimplement and any(d in reimplement for d in n["deps"]):
            reverify.add(m)

    unaffected = sorted(set(all_mods) - reimplement - reverify)
    est_cost = round(len(reimplement) * 2.1 + len(reverify) * 0.4, 2)

    scope = {
        "subsystem": subsystem,
        "tier": tier,
        "kind": "post_patch_scope",
        "reimplement": sorted(reimplement),
        "reverify": sorted(reverify),
        "unaffected": unaffected,
        "classification_detail": detail,
        "total_cost_estimate_usd": est_cost,
        "note": "Only RE-IMPLEMENT and RE-VERIFY modules will be re-run; UNAFFECTED modules retain existing state.",
    }
    write_json(GAPS_DIR / f"{subsystem}-t{tier}-scope.json", scope)
    return scope


# --- State initialization & health ---

def default_state() -> dict[str, Any]:
    return {
        "started_at": iso_now(),
        "started_subsystems": [],
        "halted": False,
        "halt_reason": None,
        "cumulative_spend_usd": 0.0,
        "last_progress_write_epoch": 0.0,
        "openrouter_floor_disabled": False,
        "consumed_approvals": [],
        "provider_health": {
            "opencode-go": {"status": "unknown", "cooldown_until": None, "last_429": None},
            "meta": {"status": "standby", "cooldown_until": None, "last_429": None},
            "openrouter": {"status": "standby", "cooldown_until": None, "last_429": None},
        },
        "subsystems": {
            sub: {
                "status": "NOT_STARTED",
                "current_tier": None,
                "tiers_total": 0,
                "modules": {},
                "in_progress": [],
                "issues": [],
                "rate_limit_events": [],
                "interface_gap_path": None,
                "audit_path": None,
                "halted_tier": None,
            }
            for sub in PILOT_SUBSYSTEMS
        },
    }


def load_or_init_state() -> dict[str, Any]:
    state = read_json(STATE_FILE)
    if state is None:
        GAPS_DIR.mkdir(parents=True, exist_ok=True)
        state = default_state()
        write_json(STATE_FILE, state)
    return state


def refresh_provider_health(state: dict[str, Any]) -> None:
    now = utc_now()
    for prov, info in state["provider_health"].items():
        if info.get("status") == "cooling_down":
            until = parse_iso(info.get("cooldown_until"))
            if until is None or now >= until:
                info["status"] = "active" if prov == PRIMARY_PROVIDER else "standby"
                info["cooldown_until"] = None


def mark_provider_429(state: dict[str, Any], provider: str, retry_after_s: int | None) -> None:
    wait = retry_after_s if (retry_after_s and retry_after_s > 0) else DEFAULT_COOLDOWN_SECONDS
    until = (utc_now() + timedelta(seconds=wait)).strftime("%Y-%m-%dT%H:%M:%SZ")
    info = state["provider_health"].setdefault(provider, {})
    info["status"] = "cooling_down"
    info["cooldown_until"] = until
    info["last_429"] = iso_now()


def select_model_and_provider(state: dict[str, Any], cost_tier: str) -> tuple[str, str]:
    base_model = (
        "deepseek-v4.1-flash"
        if cost_tier == "frontier"
        else "muse-spark-1.3-contributor"
    )
    return route_model(state, base_model)


def route_model(state: dict[str, Any], base_model: str) -> tuple[str, str]:
    refresh_provider_health(state)
    primary_status = state["provider_health"][PRIMARY_PROVIDER]["status"]
    if primary_status != "cooling_down":
        return base_model, PRIMARY_PROVIDER
    provider, model = FAILOVER_PROVIDERS[base_model]
    if provider == "openrouter" and state.get("openrouter_floor_disabled"):
        return OPENROUTER_NO_FLOOR[1], OPENROUTER_NO_FLOOR[0]
    return model, provider


# --- Independent Deterministic Verification (AWS Layer 4) ---

def verify_python_module_independently(mod_dir: Path, cmd: str, nodes: dict[str, dict[str, Any]], mod_name: str) -> tuple[bool, str]:
    venv_dir = mod_dir / ".venv"
    py_bin = venv_dir / "bin" / "python"
    pip_bin = venv_dir / "bin" / "pip"
    if not py_bin.exists():
        r = subprocess.run(["python3", "-m", "venv", str(venv_dir)], cwd=mod_dir, capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"venv creation failed: {r.stderr[-800:]}"
        for dep in nodes[mod_name]["deps"]:
            dep_dir = mod_dir.parent / dep
            r_dep = subprocess.run([str(pip_bin), "install", "-e", str(dep_dir)], cwd=mod_dir, capture_output=True, text=True)
            if r_dep.returncode != 0:
                return False, f"pip install -e ../{dep} failed: {r_dep.stderr[-800:]}"
        r_self = subprocess.run([str(pip_bin), "install", "-e", "."], cwd=mod_dir, capture_output=True, text=True)
        if r_self.returncode != 0:
            return False, f"pip install -e . failed: {r_self.stderr[-800:]}"

    env = os.environ.copy()
    env["PATH"] = f"{venv_dir / 'bin'}:{env.get('PATH', '')}"
    r = subprocess.run(cmd, shell=True, cwd=mod_dir, env=env, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return False, (r.stdout + "\n" + r.stderr)[-2000:]
    return True, r.stdout[-500:]


def verify_module_independently(subsystem: str, mod_name: str, nodes: dict[str, dict[str, Any]]) -> tuple[bool, str]:
    mod_dir = ROOT / "subsystems" / subsystem / "modules" / mod_name
    spec_path = mod_dir / ".omp-spec.md"
    if not spec_path.exists():
        return False, f"Missing spec: {spec_path}"
    fm = parse_spec_frontmatter(spec_path)
    cmd = str(fm.get("verification_command", "")).strip()
    if not cmd:
        return False, "Missing verification_command in .omp-spec.md"

    lang = nodes[mod_name]["lang"]
    try:
        if lang == "python":
            return verify_python_module_independently(mod_dir, cmd, nodes, mod_name)
        r = subprocess.run(cmd, shell=True, cwd=mod_dir, capture_output=True, text=True, timeout=300)
        if r.returncode != 0:
            return False, (r.stdout + "\n" + r.stderr)[-2000:]
        return True, r.stdout[-500:]
    except subprocess.TimeoutExpired:
        return False, f"Verification timed out after 300s: {cmd}"


# --- Prompt builders ---

def build_coder_prompt(subsystem: str, mod_name: str, model: str, provider: str, node: dict[str, Any], prior_error: str | None = None) -> str:
    mod_dir = ROOT / "subsystems" / subsystem / "modules" / mod_name
    fm = parse_spec_frontmatter(mod_dir / ".omp-spec.md")
    ver_cmd = fm.get("verification_command", "(see .omp-spec.md)")
    deps = node["deps"]
    deps_block = "\n".join(f"  - `{d}` at `../{d}`" for d in deps) if deps else "  - (none)"
    retry_block = ""
    if prior_error:
        retry_block = f"""

## PRIOR ATTEMPT FAILURE (fix this root cause)
```
{prior_error[-1500:]}
```
"""

    return f"""Role: coder
Model: {model}
Provider: {provider}
Working directory: subsystems/{subsystem}/modules/{mod_name}

You are implementing module `{mod_name}` of subsystem `{subsystem}` (lang: {node['lang']}, tier: {node['tier']}).
Read `.omp-spec.md` in your working directory in full before writing code.

## Resolved Context
- Consumed sibling dependencies:
{deps_block}
- Required `verification_command`: `{ver_cmd}`
- Shared contracts (read-only): `../../../contracts/` (from module dir, or `./contracts/` at repo root)
{retry_block}
## Mandatory Rules (override conflicting boilerplate in README.md or .omp-spec.md)
1. **Do NOT run `git add`, `git commit`, or `git push`.** You run NON-ISOLATED in the shared checkout (degraded mode: OMP worktree isolation is broken). The dispatcher commits verified work; the orchestrator scrubs the rest via CLI git.
2. **Do NOT modify files outside `subsystems/{subsystem}/modules/{mod_name}/`**, and do NOT modify `.omp-spec.md`.
3. **Check dependencies BEFORE editing:** Inspect your `CONSUMES` siblings (`../<dep>`) first. If a required upstream signature/type is missing or incompatible, stop editing and report `INTERFACE_GAP` immediately; the orchestrator scrubs leftover files automatically.
4. **CRITICAL — SHARED CHECKOUT, NEVER WIPE:**
   You run NON-ISOLATED alongside sibling coders. If you are returning **`INTERFACE_GAP`**, **`FAILED`**, **`BLOCKED`**, or **`RATE_LIMITED`**, simply STOP EDITING and emit your JSON. NEVER run `git checkout`, `git clean`, `git reset`, or delete files outside your module dir — the orchestrator reverts unverified work via CLI git after `record`.
5. Follow the `## Language-Specific Setup (MANDATORY)` section of `.omp-spec.md` verbatim.
   - Python: use `.venv/` inside your working directory and `[tool.setuptools] packages = ["{mod_name.replace('-', '_')}"]`, `package-dir = {{"{mod_name.replace('-', '_')}" = "src"}}`. Never use `src` as an importable package name.
   - Rust: use `path = "../<dep>"` in `Cargo.toml`. Match test function names to any filter token in `{ver_cmd}`.
   - Go: use `replace <dep> => ../<dep>` in `go.mod`.
6. Implement one test function per conformance assertion in `### Conformance Assertions`.
   - If assertions have IDs (e.g. `C01`, `RM-C01`), match the IDs/tokens in `{ver_cmd}`.
   - If assertions are prose (e.g. `hellscape` / `job-hunter`), write descriptive test function names covering every bullet.
7. Run `{ver_cmd}` (capped at 8 fix-and-verify iterations). Before claiming `COMPLETED`, ensure every test exercises real module behavior.
8. Ignore `.omp-spec.md`'s older `# OUTPUT CONTRACT` JSON layout. Your **final message MUST be ONLY a valid JSON object** matching one of these exact schemas:

COMPLETED:
{{
  "status": "COMPLETED",
  "module": "{mod_name}",
  "subsystem": "{subsystem}",
  "files_created": ["<paths>"],
  "verification_result": "pass",
  "assertions_passing": <int>,
  "assertions_total": <int>,
  "usage": {{"input_tokens": <int_or_null>, "output_tokens": <int_or_null>, "cost_usd": <float_or_null>}}
}}

INTERFACE_GAP (stop editing; orchestrator scrubs automatically):
{{
  "status": "INTERFACE_GAP",
  "gaps": [{{
    "missing_from_dependency": "<dep>",
    "required_signature": "<sig>",
    "declared_in_consumes": "<declared>",
    "actual_exposed": "<actual>",
    "blocking_test_cases": ["<case_or_assertion>"]
  }}],
  "usage": {{"input_tokens": null, "output_tokens": null, "cost_usd": null}}
}}

FAILED (stop editing; orchestrator scrubs automatically):
{{
  "status": "FAILED",
  "reason": "<specific>",
  "evidence": "<concise error output>",
  "usage": {{"input_tokens": null, "output_tokens": null, "cost_usd": null}}
}}

BLOCKED (stop editing; orchestrator scrubs automatically):
{{
  "status": "BLOCKED",
  "reason": "<specific>",
  "evidence": "<concise error output>"
}}

RATE_LIMITED (stop editing; orchestrator scrubs automatically):
{{
  "status": "RATE_LIMITED",
  "provider": "<{provider} or pypi>",
  "model": "{model}",
  "retry_after_seconds": <int_or_null>,
  "evidence": "<429 message>"
}}"""


def build_reverify_prompt(subsystem: str, mod_name: str, model: str, provider: str, node: dict[str, Any]) -> str:
    mod_dir = ROOT / "subsystems" / subsystem / "modules" / mod_name
    fm = parse_spec_frontmatter(mod_dir / ".omp-spec.md")
    ver_cmd = fm.get("verification_command", "(see .omp-spec.md)")
    return f"""Role: coder
Model: {model}
Provider: {provider}
Working directory: subsystems/{subsystem}/modules/{mod_name}

Module `{mod_name}` already exists at `subsystems/{subsystem}/modules/{mod_name}`.
An upstream dependency in `{subsystem}` was patched.

## Your job
1. Re-run `{ver_cmd}` (for Python, rebuild `.venv` deps via `.venv/bin/pip install -e ../<dep>` first if needed, then `.venv/bin/pytest`).
2. Do NOT modify implementation code unless verification fails due to upstream API compatibility; if an upstream signature is still missing, report `INTERFACE_GAP`.
3. Do NOT run `git add`, `git commit`, or `git push`.
4. **CRITICAL — SHARED CHECKOUT, NEVER WIPE:** If returning `INTERFACE_GAP`, `FAILED`, `BLOCKED`, or `RATE_LIMITED`, stop editing and yield; NEVER run git checkout/clean/reset. The orchestrator reverts unverified work via CLI git after `record`.
5. Return ONLY valid JSON matching the §5 schema (`COMPLETED`, `INTERFACE_GAP`, `FAILED`, `BLOCKED`, or `RATE_LIMITED`)."""


# --- Progress rendering (§7) ---

def render_progress(state: dict[str, Any], force: bool = False) -> None:
    now_epoch = time.time()
    if not force and (now_epoch - state.get("last_progress_write_epoch", 0.0)) < PROGRESS_INTERVAL_SECONDS:
        return
    state["last_progress_write_epoch"] = now_epoch

    started_dt = parse_iso(state.get("started_at")) or utc_now()
    elapsed_s = max(0, int((utc_now() - started_dt).total_seconds()))
    h, rem = divmod(elapsed_s, 3600)
    m, _ = divmod(rem, 60)

    total_done = 0
    total_mods = 0
    for sub in PILOT_SUBSYSTEMS:
        sub_st = state["subsystems"][sub]
        mods = sub_st.get("modules", {})
        if mods:
            total_mods += len(mods)
            total_done += sum(1 for v in mods.values() if v.get("status") in ("COMPLETED", "OPERATOR_SKIPPED"))
        else:
            dag_p = ROOT / "subsystems" / sub / "module-graph-0.1.0.dag"
            if dag_p.exists():
                total_mods += len(parse_dag(dag_p))
    if total_mods == 0:
        total_mods = 119

    spend = round(float(state.get("cumulative_spend_usd", 0.0)), 2)
    avg = round(spend / total_done, 2) if total_done else 0.0

    lines = [
        f"# Phase 4 Progress — {iso_now()}",
        "",
        f"**Elapsed:** {h}h {m:02d}m",
        f"**Modules complete:** {total_done}/{total_mods}",
        f"**Estimated spend:** ${spend:.2f} (~${avg:.2f}/module avg; ceiling ${COST_CEILING_USD:.0f})",
        "",
        "## Provider Health",
        "",
        "| Provider | Status | Cooldown until | Last 429 |",
        "|---|---|---|---|",
    ]
    for prov in ("opencode-go", "meta", "openrouter"):
        p = state["provider_health"].get(prov, {})
        lines.append(
            f"| {prov} | {p.get('status', 'unknown')} | {p.get('cooldown_until') or '—'} | {p.get('last_429') or '—'} |"
        )
    lines.append("")

    blocking_issues = []
    non_blocking_issues = []

    for sub in PILOT_SUBSYSTEMS:
        sub_st = state["subsystems"][sub]
        mods = sub_st.get("modules", {})
        sub_total = len(mods) if mods else (
            len(parse_dag(ROOT / "subsystems" / sub / "module-graph-0.1.0.dag"))
            if (ROOT / "subsystems" / sub / "module-graph-0.1.0.dag").exists() else 0
        )
        sub_done = sum(1 for v in mods.values() if v.get("status") in ("COMPLETED", "OPERATOR_SKIPPED"))
        lines.append(f"## Subsystem: {sub} — {sub_st['status']} ({sub_total} modules)")
        lines.append("")
        if sub_st["status"] == "NOT_STARTED":
            lines.append(f'- Awaiting command: add `"{sub}"` to `phase4-commands.json`')
        else:
            lines.append(f"- Current tier: {sub_st.get('current_tier')} of {sub_st.get('tiers_total')}")
            lines.append(f"- Modules done: {sub_done}/{sub_total}")
            if sub_st.get("in_progress"):
                lines.append("- In progress:")
                for item in sub_st["in_progress"]:
                    lines.append(f"  - `{item['module']}` @ {item['model']} · {item['provider']}")
            blocked = [m for m, v in mods.items() if v.get("status") in ("BLOCKED", "INTERFACE_GAP")]
            lines.append(f"- Blocked: {', '.join(blocked) if blocked else 'none'}")
            if sub_st.get("interface_gap_path"):
                lines.append(f"- Gap report: `{sub_st['interface_gap_path']}`")
                blocking_issues.append(f"{sub}: INTERFACE_GAP at tier {sub_st.get('halted_tier')} — see `{sub_st['interface_gap_path']}`")
            for iss in sub_st.get("issues", []):
                non_blocking_issues.append(f"{sub}: {iss}")
        lines.append("")

    lines += ["## Blocking Issues", ""]
    lines.extend([f"- {b}" for b in blocking_issues] if blocking_issues else ["- none"])
    lines += ["", "## Non-blocking Issues", ""]
    lines.extend([f"- {n}" for n in non_blocking_issues] if non_blocking_issues else ["- none"])
    lines.append("")

    atomic_write(PROGRESS_MD, "\n".join(lines))
    write_json(PROGRESS_JSON, {
        "timestamp": iso_now(),
        "elapsed_seconds": elapsed_s,
        "modules_complete": total_done,
        "modules_total": total_mods,
        "cumulative_spend_usd": spend,
        "providers": state["provider_health"],
        "subsystems": state["subsystems"],
    })


# --- Audit & Rollup (§11) ---

def write_subsystem_audit(state: dict[str, Any], sub: str, integration_passed: bool, integration_detail: str) -> Path:
    sub_st = state["subsystems"][sub]
    mods = sub_st["modules"]
    completed = sum(1 for v in mods.values() if v.get("status") == "COMPLETED")
    skipped = sum(1 for v in mods.values() if v.get("status") == "OPERATOR_SKIPPED")
    failed = sum(1 for v in mods.values() if v.get("status") == "FAILED")
    blocked = sum(1 for v in mods.values() if v.get("status") == "BLOCKED")
    phase4_complete = (
        sub_st["status"] == "COMPLETE"
        and integration_passed
        and failed == 0
        and blocked == 0
        and (completed + skipped) == len(mods)
    )
    audit = {
        "schema_version": "phase4-audit/0.1.0",
        "subsystem": sub,
        "generated_at": iso_now(),
        "phase4_complete": phase4_complete,
        "modules_total": len(mods),
        "modules_completed": completed,
        "modules_operator_skipped": skipped,
        "modules_failed": failed,
        "modules_blocked": blocked,
        "integration_test": {"passed": integration_passed, "detail": integration_detail[:1000]},
        "rate_limit_events": sub_st.get("rate_limit_events", []),
        "modules": {
            m: {
                "status": v.get("status"),
                "tier": v.get("tier"),
                "model": v.get("model"),
                "provider": v.get("provider"),
                "retries": v.get("retries", 0),
                "verified_independently": v.get("verified_independently", False),
            }
            for m, v in sorted(mods.items())
        },
    }
    audit_path = ROOT / "subsystems" / sub / "phase4_audit.json"
    write_json(audit_path, audit)
    sub_st["audit_path"] = f"subsystems/{sub}/phase4_audit.json"
    return audit_path


def write_rollup(state: dict[str, Any]) -> None:
    audits = {}
    all_pass = True
    for sub in PILOT_SUBSYSTEMS:
        p = ROOT / "subsystems" / sub / "phase4_audit.json"
        if p.exists():
            a = read_json(p)
            audits[sub] = {"phase4_complete": a.get("phase4_complete", False), "modules_completed": a.get("modules_completed", 0)}
            if not a.get("phase4_complete"):
                all_pass = False
        else:
            audits[sub] = {"phase4_complete": False, "status": state["subsystems"][sub]["status"]}
            all_pass = False
    rollup = {
        "generated_at": iso_now(),
        "phase4_80pct_gate": "pass" if all_pass else "fail",
        "cumulative_spend_usd": round(float(state.get("cumulative_spend_usd", 0.0)), 2),
        "subsystems": audits,
    }
    write_json(ROLLUP_FILE, rollup)


# --- Subcommands ---

def cmd_preflight() -> int:
    checks = [
        ("phase4-gate.sh", ["bash", "scripts/phase4-gate.sh"]),
        ("phase4-audit.py", [sys.executable, "scripts/phase4-audit.py"]),
        ("verify_unpack_correctness.py", [sys.executable, "scripts/verify_unpack_correctness.py"]),
        ("verify_unpack_internals.py", [sys.executable, "scripts/verify_unpack_internals.py"]),
    ]
    for label, cmd in checks:
        print(f"=== Running {label} ===")
        r = subprocess.run(cmd, cwd=ROOT)
        if r.returncode != 0:
            print(f"[PREFLIGHT FAILED] {label} exited {r.returncode}", file=sys.stderr)
            return r.returncode

    print("=== Checking classification-final.json & DAGs ===")
    clf = load_classifications()
    for sub in PILOT_SUBSYSTEMS:
        dag_p = ROOT / "subsystems" / sub / "module-graph-0.1.0.dag"
        nodes = parse_dag(dag_p)
        missing = [m for m in nodes if (sub, m) not in clf]
        if missing:
            print(f"[PREFLIGHT FAILED] Unclassified modules in {sub}: {missing}", file=sys.stderr)
            return 1
    print("[PREFLIGHT PASSED] All deterministic checks green.")
    return 0


def init_subsystem_modules(state: dict[str, Any], sub: str, clf: dict[tuple[str, str], dict[str, Any]]) -> bool:
    dag_p = ROOT / "subsystems" / sub / "module-graph-0.1.0.dag"
    nodes = parse_dag(dag_p)
    sched = tier_schedule(nodes)
    sub_st = state["subsystems"][sub]
    sub_st["status"] = "RUNNING"
    sub_st["tiers_total"] = len(sched)
    sub_st["current_tier"] = sched[0][0] if sched else None
    sub_st["modules"] = {}
    for m, n in nodes.items():
        if (sub, m) not in clf:
            sub_st["status"] = "HALT"
            sub_st["issues"].append(f"unclassified module: {m}")
            return False
        c = clf[(sub, m)]
        sub_st["modules"][m] = {
            "status": "PENDING",
            "mode": "implement",
            "tier": n["tier"],
            "cost_tier": c["cost_tier"],
            "confidence": c.get("confidence", "medium"),
            "retries": 0,
            "model": None,
            "provider": None,
            "prior_error": None,
            "verified_independently": False,
        }
    return True


def handle_approvals(state: dict[str, Any]) -> None:
    approvals_data = read_json(APPROVALS_FILE, {"approve": []}) or {"approve": []}
    consumed = set(state.setdefault("consumed_approvals", []))
    for app in approvals_data.get("approve", []):
        sub = app.get("subsystem")
        tier = app.get("tier")
        action = app.get("action")
        sig = json.dumps(app, sort_keys=True)
        if sig in consumed or sub not in state["subsystems"]:
            continue
        sub_st = state["subsystems"][sub]
        if sub_st["status"] != "AWAITING_OPERATOR_APPROVAL":
            continue

        consumed.add(sig)
        if action == "halt":
            sub_st["status"] = "HALT"
            sub_st["issues"].append(f"Operator halted at tier {tier}")
            write_subsystem_audit(state, sub, False, "Operator halted on INTERFACE_GAP")
        elif action == "skip":
            target_mod = app.get("module")
            for m, mv in sub_st["modules"].items():
                if target_mod and m == target_mod or (not target_mod and mv["status"] == "INTERFACE_GAP"):
                    mv["status"] = "OPERATOR_SKIPPED"
            sub_st["status"] = "RUNNING"
            sub_st["interface_gap_path"] = None
            sub_st["issues"].append(f"Operator skipped module(s) at tier {tier}")
        elif action == "patch":
            dag_p = ROOT / "subsystems" / sub / "module-graph-0.1.0.dag"
            for script in ("verify_dag.py", "unpack_dag.py", "verify_specs.py"):
                r = subprocess.run([sys.executable, f"scripts/{script}", str(dag_p)], cwd=ROOT, capture_output=True, text=True)
                if r.returncode != 0:
                    sub_st["status"] = "HALT"
                    sub_st["issues"].append(f"Patch validation failed in {script}: {r.stderr or r.stdout}")
                    write_subsystem_audit(state, sub, False, f"Patch failed {script}")
                    break
            else:
                halted_tier = sub_st.get("halted_tier", tier)
                old_dag = GAPS_DIR / f"{sub}-t{halted_tier}-old.dag"
                scope = compute_affected_scope(sub, halted_tier, old_dag, dag_p)
                nodes = parse_dag(dag_p)
                clf = load_classifications()
                for m in scope["reimplement"]:
                    if m not in sub_st["modules"]:
                        c = clf[(sub, m)]
                        sub_st["modules"][m] = {
                            "tier": nodes[m]["tier"], "cost_tier": c["cost_tier"],
                            "confidence": c.get("confidence", "medium"), "retries": 0,
                        }
                    sub_st["modules"][m].update({"status": "PENDING", "mode": "implement", "tier": nodes[m]["tier"], "retries": 0, "prior_error": None})
                for m in scope["reverify"]:
                    sub_st["modules"][m].update({"status": "PENDING", "mode": "reverify", "tier": nodes[m]["tier"], "retries": 0, "prior_error": None})
                for m, mv in sub_st["modules"].items():
                    if m in scope["unaffected"] and mv.get("status") == "INTERFACE_GAP":
                        mv["status"] = "PENDING"
                sub_st["status"] = "RUNNING"
                sub_st["interface_gap_path"] = None
                sub_st["halted_tier"] = None
                sub_st["issues"].append(f"Patch approved at tier {tier}: {len(scope['reimplement'])} reimplement, {len(scope['reverify'])} reverify")

    state["consumed_approvals"] = sorted(consumed)


def run_subsystem_integration(sub: str) -> tuple[bool, str]:
    tests_dir = ROOT / "subsystems" / sub / "tests"
    if tests_dir.exists():
        for cand in sorted(tests_dir.glob("integration.*")):
            if cand.suffix == ".py":
                r = subprocess.run([sys.executable, str(cand)], cwd=ROOT, capture_output=True, text=True, timeout=300)
                return r.returncode == 0, (r.stdout + r.stderr)[-1000:]
            if cand.suffix == ".sh":
                r = subprocess.run(["bash", str(cand)], cwd=ROOT, capture_output=True, text=True, timeout=300)
                return r.returncode == 0, (r.stdout + r.stderr)[-1000:]
    return True, "All tier verifications passed independently (no subsystem tests/integration.* script present)."


def cmd_tick() -> int:
    state = load_or_init_state()
    refresh_provider_health(state)

    cmds = read_json(COMMANDS_FILE, {"start": []}) or {"start": []}
    if cmds.get("halt"):
        state["halted"] = True
        state["halt_reason"] = "Operator halt command"
        write_rollup(state)
        render_progress(state, force=True)
        write_json(STATE_FILE, state)
        print(json.dumps({"action": "HALT", "reason": "Operator halt command"}, indent=2))
        return 0

    if float(state.get("cumulative_spend_usd", 0.0)) >= COST_CEILING_USD:
        state["halted"] = True
        state["halt_reason"] = f"Cost ceiling ${COST_CEILING_USD} reached"
        write_rollup(state)
        render_progress(state, force=True)
        write_json(STATE_FILE, state)
        print(json.dumps({"action": "HALT", "reason": state["halt_reason"]}, indent=2))
        return 0

    clf = load_classifications()
    for sub in cmds.get("start", []):
        if sub in PILOT_SUBSYSTEMS and sub not in state["started_subsystems"]:
            state["started_subsystems"].append(sub)
            init_subsystem_modules(state, sub, clf)

    handle_approvals(state)

    tasks_to_spawn = []
    any_running = False
    for sub in PILOT_SUBSYSTEMS:
        sub_st = state["subsystems"][sub]
        if sub_st["status"] != "RUNNING":
            continue
        any_running = True
        dag_p = ROOT / "subsystems" / sub / "module-graph-0.1.0.dag"
        nodes = parse_dag(dag_p)
        sched = tier_schedule(nodes)

        active_tier = None
        pending_mods = []
        for t, mod_names in sched:
            t_pending = [
                m for m in mod_names
                if sub_st["modules"][m]["status"] in ("PENDING", "RETRY_PENDING")
            ]
            if t_pending:
                active_tier = t
                pending_mods = t_pending
                break
            if any(sub_st["modules"][m]["status"] in ("BLOCKED", "INTERFACE_GAP") for m in mod_names):
                active_tier = t
                break

        if active_tier is None:
            ok, detail = run_subsystem_integration(sub)
            sub_st["status"] = "COMPLETE" if ok else "HALT"
            if not ok:
                sub_st["issues"].append(f"Integration test failed: {detail}")
            write_subsystem_audit(state, sub, ok, detail)
            continue

        sub_st["current_tier"] = active_tier
        sub_st["in_progress"] = []
        for m in pending_mods:
            mv = sub_st["modules"][m]
            if mv["status"] == "RETRY_PENDING" and mv.get("escalate"):
                model, provider = route_model(state, "deepseek-v4.1-flash")
            else:
                model, provider = select_model_and_provider(state, mv["cost_tier"])
            mv["model"] = model
            mv["provider"] = provider
            mv["status"] = "IN_PROGRESS"
            sub_st["in_progress"].append({"module": m, "model": model, "provider": provider})
            prompt = (
                build_reverify_prompt(sub, m, model, provider, nodes[m])
                if mv.get("mode") == "reverify"
                else build_coder_prompt(sub, m, model, provider, nodes[m], mv.get("prior_error"))
            )
            tasks_to_spawn.append({
                "subsystem": sub,
                "module": m,
                "tier": active_tier,
                "role": "coder",
                "model": model,
                "provider": provider,
                "isolated": False,  # DEGRADED MODE: OMP worktree git-open broken; CLI scrubber owns safety
                "cwd": f"subsystems/{sub}/modules/{m}",
                "prompt": prompt,
            })

    terminal_states = {"COMPLETE", "HALT", "OPERATOR_SKIPPED"}
    all_terminal = all(state["subsystems"][s]["status"] in terminal_states for s in PILOT_SUBSYSTEMS)
    render_progress(state, force=bool(tasks_to_spawn or all_terminal))

    if all_terminal:
        write_json(STATE_FILE, state)
        write_rollup(state)
        print(json.dumps({"action": "DONE", "rollup_path": str(ROLLUP_FILE.relative_to(ROOT))}, indent=2))
        return 0

    if tasks_to_spawn:
        dirty_lines = [
            ln for ln in git_run(["status", "--porcelain"]).stdout.splitlines()
            if ln.strip() and "interface-gaps/" not in ln and "phase4-rollup.json" not in ln
        ]
        if dirty_lines:
            # This tick already marked tasks_to_spawn IN_PROGRESS above, but the
            # batch is discarded unspawned. Restore prior pending states or the
            # affected tiers strand forever (never re-emitted, never recorded).
            for t in tasks_to_spawn:
                mv = state["subsystems"][t["subsystem"]]["modules"][t["module"]]
                if mv.get("status") == "IN_PROGRESS":
                    if mv.get("retries", 0) > 0 or mv.get("prior_error"):
                        mv["status"] = "RETRY_PENDING"
                    else:
                        mv["status"] = "PENDING"
            for sub in PILOT_SUBSYSTEMS:
                state["subsystems"][sub]["in_progress"] = []
            state["halted"] = True
            state["halt_reason"] = f"Dirty git working tree before batch spawn: {dirty_lines[:5]}"
            render_progress(state, force=True)
            write_json(STATE_FILE, state)
            print(json.dumps({"action": "HALT", "reason": state["halt_reason"]}, indent=2))
            return 1

        state["active_batch"] = {
            "pre_batch_sha": git_head_sha(),
            "tasks": [
                {"subsystem": t["subsystem"], "module": t["module"], "cwd": t["cwd"]}
                for t in tasks_to_spawn
            ],
        }
        write_json(STATE_FILE, state)
        print(json.dumps({"action": "SPAWN_TASKS", "tasks": tasks_to_spawn}, indent=2))
    else:
        write_json(STATE_FILE, state)
        print(json.dumps({"action": "WAIT", "seconds": POLL_INTERVAL_SECONDS, "any_running": any_running}, indent=2))
    return 0


def record_cost(state: dict[str, Any], result: dict[str, Any], provider: str, model: str) -> None:
    usage = result.get("usage") or {}
    if isinstance(usage.get("cost_usd"), (int, float)):
        state["cumulative_spend_usd"] = float(state.get("cumulative_spend_usd", 0.0)) + float(usage["cost_usd"])
        return
    in_tok = usage.get("input_tokens") or 0
    out_tok = usage.get("output_tokens") or 0
    if in_tok or out_tok:
        pin, pout = PRICING_PER_M.get((provider, model), (0.05, 0.12))
        cost = (in_tok * pin + out_tok * pout) / 1_000_000.0
        state["cumulative_spend_usd"] = float(state.get("cumulative_spend_usd", 0.0)) + cost


def cmd_record(results_file: Path) -> int:
    state = load_or_init_state()
    results = read_json(results_file)
    if not isinstance(results, list):
        raise ValueError("results-file must contain a JSON array of task outcomes")

    active_batch = state.pop("active_batch", None) or {}
    pre_batch_sha = active_batch.get("pre_batch_sha")
    passing_module_dirs: set[str] = set()
    rejected_module_dirs: set[str] = set()

    by_sub: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in results:
        by_sub[item["subsystem"]].append(item)

    tampered_specs = set()
    if pre_batch_sha:
        for rel in git_changed_paths_since(pre_batch_sha):
            if rel.endswith("/.omp-spec.md"):
                tampered_specs.add(rel)

    for sub, items in by_sub.items():
        sub_st = state["subsystems"][sub]
        sub_st["in_progress"] = []
        nodes = parse_dag(ROOT / "subsystems" / sub / "module-graph-0.1.0.dag")
        gaps_collected = []
        blocked_mods = []
        hit_429_llm = False

        for item in items:
            mod = item["module"]
            mod_rel = f"subsystems/{sub}/modules/{mod}"
            mv = sub_st["modules"][mod]
            status = item.get("status")
            record_cost(state, item, mv.get("provider") or "", mv.get("model") or "")

            if status == "COMPLETED":
                if f"{mod_rel}/.omp-spec.md" in tampered_specs:
                    status = "FAILED"
                    item["reason"] = "Module modified read-only .omp-spec.md"
                    item["evidence"] = f"{mod_rel}/.omp-spec.md changed"
                else:
                    ok, detail = verify_module_independently(sub, mod, nodes)
                    if ok:
                        mv["status"] = "COMPLETED"
                        mv["verified_independently"] = True
                        passing_module_dirs.add(mod_rel)
                        if mv.get("provider") == PRIMARY_PROVIDER:
                            state["provider_health"][PRIMARY_PROVIDER]["status"] = "active"
                    else:
                        status = "FAILED"
                        item["reason"] = "Independent verification failed"
                        item["evidence"] = detail

            if status != "COMPLETED":
                rejected_module_dirs.add(mod_rel)

            if status == "RATE_LIMITED":
                rl_prov = item.get("provider") or mv.get("provider")
                if rl_prov == "pypi":
                    if mv["retries"] < 2:
                        mv["retries"] += 1
                        mv["status"] = "RETRY_PENDING"
                        mv["prior_error"] = item.get("evidence")
                    else:
                        mv["status"] = "BLOCKED"
                        sub_st["status"] = "HALT"
                        sub_st["issues"].append(f"{mod}: PyPI rate limited repeatedly")
                elif rl_prov == PRIMARY_PROVIDER:
                    hit_429_llm = True
                    mark_provider_429(state, PRIMARY_PROVIDER, item.get("retry_after_seconds"))
                    sub_st["rate_limit_events"].append({"provider": rl_prov, "timestamp": iso_now()})
                    mv["status"] = "RETRY_PENDING"
                    mv["escalate"] = False
                elif rl_prov == "openrouter" and ":floor" in (mv.get("model") or "") and "unknown" in (item.get("evidence", "").lower()):
                    state["openrouter_floor_disabled"] = True
                    mv["status"] = "RETRY_PENDING"
                else:
                    mv["status"] = "BLOCKED"
                    sub_st["status"] = "HALT"
                    sub_st["issues"].append(f"Both primary and failover provider ({rl_prov}) rate-limited on {mod}")
                    write_subsystem_audit(state, sub, False, "Both providers rate-limited")

            elif status == "INTERFACE_GAP":
                mv["status"] = "INTERFACE_GAP"
                blocked_mods.append(mod)
                gaps_collected.extend(item.get("gaps", []))

            elif status == "FAILED":
                if mv.get("provider") == "openrouter" and ":floor" in (mv.get("model") or "") and not state.get("openrouter_floor_disabled"):
                    state["openrouter_floor_disabled"] = True
                    mv["status"] = "RETRY_PENDING"
                    sub_st["issues"].append(f"{mod}: OpenRouter :floor rejected; falling back without :floor")
                elif mv["retries"] < 1:
                    mv["retries"] += 1
                    mv["status"] = "RETRY_PENDING"
                    mv["escalate"] = mv.get("confidence") != "high"
                    mv["prior_error"] = f"{item.get('reason', '')}\n{item.get('evidence', '')}"
                    sub_st["issues"].append(
                        f"`{mod}` failed tier {mv['tier']} ({mv.get('confidence')} conf) -> scheduling retry"
                    )
                else:
                    mv["status"] = "BLOCKED"
                    sub_st["status"] = "HALT"
                    sub_st["issues"].append(f"{mod}: failed twice -> BLOCKED")
                    write_subsystem_audit(state, sub, False, f"Module {mod} failed twice")

            elif status == "BLOCKED":
                mv["status"] = "BLOCKED"
                sub_st["status"] = "HALT"
                sub_st["issues"].append(f"{mod}: BLOCKED ({item.get('reason')})")
                write_subsystem_audit(state, sub, False, f"Module {mod} BLOCKED: {item.get('reason')}")

        if gaps_collected and sub_st["status"] != "HALT":
            t = sub_st["current_tier"]
            gap_path = GAPS_DIR / f"{sub}-t{t}.json"
            gap_payload = {
                "subsystem": sub,
                "tier": t,
                "modules_blocked": sorted(set(blocked_mods)),
                "gaps": gaps_collected,
            }
            write_json(gap_path, gap_payload)
            old_dag_copy = GAPS_DIR / f"{sub}-t{t}-old.dag"
            if not old_dag_copy.exists():
                shutil.copy2(ROOT / "subsystems" / sub / "module-graph-0.1.0.dag", old_dag_copy)
            est = compute_prepatch_estimate(sub, t, gap_payload, nodes)
            write_json(GAPS_DIR / f"{sub}-t{t}-estimate.json", est)
            sub_st["status"] = "AWAITING_OPERATOR_APPROVAL"
            sub_st["halted_tier"] = t
            sub_st["interface_gap_path"] = str(gap_path.relative_to(ROOT))

        if hit_429_llm:
            sub_st["issues"].append("opencode-go 429 cooldown triggered; retrying on failover")

    for t in active_batch.get("tasks", []):
        mod_rel = f"subsystems/{t['subsystem']}/modules/{t['module']}"
        if mod_rel not in passing_module_dirs:
            rejected_module_dirs.add(mod_rel)

    reverted_paths = scrub_batch_to_pre_sha(pre_batch_sha, passing_module_dirs, rejected_module_dirs)

    render_progress(state, force=True)
    write_json(STATE_FILE, state)
    print(json.dumps({
        "recorded": len(results),
        "verified_passed": len(passing_module_dirs),
        "reverted_paths": reverted_paths,
        "cumulative_spend_usd": round(float(state["cumulative_spend_usd"]), 2),
    }))
    return 0

def cmd_status() -> int:
    state = load_or_init_state()
    render_progress(state, force=True)
    write_json(STATE_FILE, state)
    print(PROGRESS_MD.read_text(encoding="utf-8"))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 4 deterministic orchestrator")
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    subparsers.add_parser("preflight")
    subparsers.add_parser("tick")
    rec_p = subparsers.add_parser("record")
    rec_p.add_argument("--results-file", required=True, type=Path)
    subparsers.add_parser("status")
    sc_p = subparsers.add_parser("scope")
    sc_p.add_argument("subsystem")
    sc_p.add_argument("tier", type=int)
    sc_p.add_argument("--old-dag", type=Path)
    sc_p.add_argument("--new-dag", type=Path)

    args = parser.parse_args()
    if args.cmd == "preflight":
        return cmd_preflight()
    if args.cmd == "tick":
        return cmd_tick()
    if args.cmd == "record":
        return cmd_record(args.results_file)
    if args.cmd == "status":
        return cmd_status()
    if args.cmd == "scope":
        old_p = args.old_dag or (GAPS_DIR / f"{args.subsystem}-t{args.tier}-old.dag")
        new_p = args.new_dag or (ROOT / "subsystems" / args.subsystem / "module-graph-0.1.0.dag")
        print(json.dumps(compute_affected_scope(args.subsystem, args.tier, old_p, new_p), indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
