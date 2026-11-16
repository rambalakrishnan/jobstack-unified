# File: `phase4-execute.md` (workspace root: `/home/whipsthellamasass/workspace/unification/tree`)

Instruct the TUI: "Read `phase4-execute.md` in full and execute §1 through §14."

**Scope:** 119 modules across 4 subsystems (`crawler`: 33, `ringmaster`: 24, `hellscape`: 29, `job-hunter`: 33). `circus-tent` (31 modules) is deferred pending codebase reconciliation.

**Model and provider strings:**

| Role | Primary | Failover |
|---|---|---|
| Orchestrator driver | `deepseek-v4.1-flash` @ `opencode-go` | `deepseek/deepseek-v4.1-flash-1017:floor` @ `openrouter` (fallback: drop `:floor`) |
| Coder cheap/mid | `muse-spark-1.3-contributor` @ `opencode-go` | `muse-spark-1.3-contributor` @ `meta` |
| Coder frontier | `deepseek-v4.1-flash` @ `opencode-go` | `deepseek/deepseek-v4.1-flash-1017:floor` @ `openrouter` (fallback: drop `:floor`) |

**Mandatory isolation flag on EVERY `task` spawn:**
`task.isolation.enabled` alone does NOT isolate subagents. Every `task` tool call spawning a module coder MUST explicitly pass `"isolated": true` so OMP creates a BtrFS copy-on-write worktree and merges changes back per branch strategy.

**DEGRADED MODE (active 2026-11-16):** OMP's worktree git-open layer is broken (`git open ... does not appear to be a git repository` on CLI-valid repos, including fresh clones). Coders spawn with `"isolated": false` in the shared checkout under module-dir discipline; `scrub_batch_to_pre_sha` reverts unverified work at `record` via CLI git; the dispatcher commits passing module dirs between every `record` and the next `tick` (the tick guard HALTs on dirt). Revert to `"isolated": true` and delete this note once OMP isolation works.

**No automatic Astra invocation.** Any `INTERFACE_GAP` halts that subsystem only, snapshots the pre-patch DAG, writes a gap report + pre-patch estimate, and enters `AWAITING_OPERATOR_APPROVAL`. Independent subsystems continue.

---

## §1. Prerequisites — must all pass

### 1.1–1.3 — Deterministic preflight (via orchestrator)

Run:
```bash
python3 scripts/phase4-orchestrate.py preflight
```
This runs `scripts/phase4-gate.sh`, `scripts/phase4-audit.py` (all 15 checks), `scripts/verify_unpack_correctness.py`, `scripts/verify_unpack_internals.py`, and verifies all 119 pilot modules exist in `subsystems/classification-final.json`. Halt if non-zero.

### 1.4 — Provider availability

Confirm in OMP's provider registry / model list that `opencode-go`, `meta`, and `openrouter` are active and that `deepseek-v4.1-flash`, `muse-spark-1.3-contributor`, and `deepseek/deepseek-v4.1-flash-1017:floor` resolve cleanly (do not guess shell env var names—inspect OMP's configured providers directly). Halt if any of the three providers is missing.

---

## §2. Role topology

`scripts/phase4-orchestrate.py` owns all deterministic state: command/approval polling, tier scheduling, provider failover health, `$300` spend tracking, §10 DAG diffing, independent post-coder verification, progress dashboards, and `phase4_audit.json` / `phase4-rollup.json`.

The OMP TUI agent acts strictly as the **thin `task` dispatcher**:
1. Calls `python3 scripts/phase4-orchestrate.py tick`.
2. Spawns all returned `tasks` in parallel using OMP's `task` tool with `"isolated": false` (degraded mode; see note above).
3. Writes the subagents' JSON responses to `.phase4-batch-results.json` (matching `{subsystem, module, ...coder_json}`) and calls `python3 scripts/phase4-orchestrate.py record --results-file .phase4-batch-results.json`.
4. Sleeps 30 seconds on `WAIT`, or exits on `DONE` / `HALT`.

---

## §3. Orchestrator Driver — full prompt

```
Role: orchestrator
Model: deepseek-v4.1-flash
Provider: opencode-go
Working directory: . (/home/whipsthellamasass/workspace/unification/tree)

You are the thin Phase 4 dispatcher. `scripts/phase4-orchestrate.py` holds all
orchestration logic, DAG scheduling, provider failover state, and dashboards.

## Startup
1. Run `python3 scripts/phase4-orchestrate.py preflight`. Halt if non-zero.
2. Confirm OMP providers (`opencode-go`, `meta`, `openrouter`) are configured.

## Main loop
Repeat until `tick` returns `"action": "DONE"` or `"action": "HALT"`:

1. Run: `python3 scripts/phase4-orchestrate.py tick`
2. Parse the JSON output:
   - If `action == "DONE"` or `action == "HALT"`: summarize `phase4-rollup.json` and exit.
   - If `action == "WAIT"`: sleep `seconds` (30s), then continue loop.
   - If `action == "SPAWN_TASKS"`:
     Spawn all entries in `tasks` IN PARALLEL via the OMP `task` tool,
     passing EVERY field literally and ALWAYS setting `"isolated": false`:
       - model: task.model
       - provider: task.provider
       - cwd / working_directory: task.cwd
     - isolated: false  <-- DEGRADED (shared checkout; scrubber owns safety)
       - prompt: task.prompt
     Wait for all spawned tasks in this batch to return.
     If a subagent fails to emit valid JSON (e.g. HTTP 429 or crash), wrap it as
     `{"subsystem": task.subsystem, "module": task.module, "status": "RATE_LIMITED" | "FAILED", "evidence": "<raw error>"}`.
     Write the JSON array of `{subsystem, module, ...parsed_json}` to `/tmp/phase4-batch-results.json`.
     Run: `python3 scripts/phase4-orchestrate.py record --results-file /tmp/phase4-batch-results.json`
     Immediately continue loop (do not sleep before the next `tick`).

## What you must NOT do
- Do NOT invoke Astra.
- Do NOT implement modules yourself or edit `.omp-spec.md` / `.dag` files.
- Do NOT set `"isolated": true` (broken git layer); spawn non-isolated per degraded mode.
- Do NOT maintain separate progress/health state in memory — trust `phase4-orchestrate.py`.
```

---

## §4. Patch resumption (operator-approved)

When a subsystem enters `AWAITING_OPERATOR_APPROVAL`:
1. `phase4-orchestrate.py` has already written `interface-gaps/{subsystem}-t{tier}.json`, snapshotted `interface-gaps/{subsystem}-t{tier}-old.dag`, and written a pre-patch estimate `interface-gaps/{subsystem}-t{tier}-estimate.json`.
2. Out-of-band, the **operator** decides whether to skip, halt, or manually run Astra to patch `subsystems/{subsystem}/module-graph-0.1.0.dag`.
3. The operator writes an approval entry to `phase4-approvals.json`:
   `{"approve": [{"subsystem": "ringmaster", "tier": 4, "action": "patch"}]}`
4. On the next `tick`, `phase4-orchestrate.py`:
   - Re-runs `verify_dag.py`, `unpack_dag.py`, and `verify_specs.py` with `subsystems/{subsystem}/module-graph-0.1.0.dag`.
   - Computes the exact §10 post-patch diff (`interface-gaps/{subsystem}-t{tier}-scope.json`).
   - Schedules `RE-IMPLEMENT` and `RE-VERIFY` modules and leaves `UNAFFECTED` completed modules untouched.

---

## §5. Module coder — reference specification

(`scripts/phase4-orchestrate.py` injects the concrete prompt per module with resolved `CONSUMES` paths and `verification_command`.)

### Files to create (per language)

- **Rust** (`crawler`, `ringmaster`):
  - `Cargo.toml` — with `<dep_name> = { path = "../<dep_name>" }` for each `CONSUMES` entry
  - `src/lib.rs` — public interface implementation
  - `tests/conformance.rs` — one `#[test]` per `TEST_ASSERTION`, matching any test filter token in `verification_command`
- **Python** (`job-hunter`):
  - `pyproject.toml` — with `[tool.setuptools]` `packages = ["<package_name>"]` and `package-dir = {"<package_name>" = "src"}`, where `<package_name>` is your module name with hyphens replaced by underscores (e.g. `contract_codec` for `contract-codec`)
  - `src/__init__.py` — package source; installed as `<package_name>`
  - `tests/test_conformance.py` — one test function per `TEST_ASSERTION` (see naming rule below)
  - `.venv/` — created via `python3 -m venv .venv` (gitignored); all `pip`/`pytest`/imports go through `.venv/bin/`
- **Go** (`hellscape`):
  - `go.mod` — with `replace <dep_name> => ../<dep_name>` for each `CONSUMES` entry
  - `module.go` — public interface implementation
  - `conformance_test.go` — one `Test...(*testing.T)` function per `TEST_ASSERTION`

### Test naming rule (ID-based vs. prose-based subsystems)

- **ID-based (`crawler`, `ringmaster`):** Name each test function after its case ID (`#[test] fn c01()`, `#[test] fn rm_c01()`) matching the exact case/casing in `.omp-spec.md` `verification_command`.
- **Prose-based (`hellscape`, `job-hunter`):** `### Conformance Assertions` contains prose sentences without case IDs. Name each test descriptively (`def test_<snake_case>():`, `func Test<CamelCase>(t *testing.T)`), ensuring names match any `-k` / `-run` filter in `verification_command`.

### Python module isolation (MANDATORY)

1. `python3 -m venv .venv`
2. For each `CONSUMES` dependency: `.venv/bin/pip install -e ../<dep_name>`
3. Create `pyproject.toml` with `packages = ["<package_name>"]` and `package-dir = {"<package_name>" = "src"}`
4. `.venv/bin/pip install -e .`
5. `.venv/bin/pytest tests/test_conformance.py` (or `.venv/bin/<verification_command>`)

Do NOT: install into system Python, reuse a sibling `.venv`, use `src` as an importable package name, or commit `.venv/`.

### Git & Scope Discipline (overrides `README.md` for Phase 4)

- Do NOT run `git add`, `git commit`, or `git push`. The dispatcher commits verified module dirs between `record` and the next `tick`; the orchestrator scrubs unverified work automatically.
- Do NOT modify files outside `subsystems/{SUBSYSTEM}/modules/{MODULE_NAME}/` or edit `.omp-spec.md`.

### Failure protocol (`RATE_LIMITED` / `pypi` addition)

- If `pip install` hits an HTTP 429 from PyPI, return `RATE_LIMITED` with `provider: "pypi"` (retried separately without cooling down LLM `opencode-go`).
- Ignore `.omp-spec.md`'s older `# OUTPUT CONTRACT` if different; emit ONLY the JSON schemas enforced by `phase4-orchestrate.py` (including optional `"usage": {"input_tokens", "output_tokens", "cost_usd"}`).

---

## §6. Failure protocols summary (updated)

| Condition | Orchestrator behavior |
|---|---|
| 429 from `opencode-go` coder | Mark `opencode-go` `cooling_down`; re-queue failed coder on failover (`meta` / `openrouter`) |
| 429 from `pypi` during `pip install` | Retry module locally (up to 2×); do NOT cool down LLM providers |
| `INTERFACE_GAP` | Snapshot `old.dag` → write `interface-gaps/{sub}-t{tier}.json` + pre-patch estimate → `AWAITING_OPERATOR_APPROVAL` |
| `FAILED` (`confidence == "high"`) | Retry once on same model (respecting `provider_health`) |
| `FAILED` (`confidence` in `"medium"`, `"low"`, or `null`) | Retry once escalated to `deepseek-v4.1-flash` |
| `FAILED` twice (or fails independent verification twice) | Mark `BLOCKED`, `HALT` subsystem |
| `BLOCKED` | `HALT` subsystem immediately |

---

## §7. Progress chart — `phase4-progress.md`

**Written every 5 minutes by `phase4-orchestrate.py`.** Atomic write: write to `.progress.md.tmp`, then `mv` over. Operator `cat`s it as a dashboard.

Format (Markdown, human-readable via `cat`):

```markdown
# Phase 4 Progress — {ISO8601 UTC}

**Elapsed:** 1h 23m
**Modules complete:** 47/119
**Estimated spend:** $89 (~$1.90/module avg)

## Provider Health

| Provider | Status | Cooldown until | Last 429 |
|---|---|---|---|
| opencode-go | active | — | 14:03 (recovered 14:08) |
| meta | standby | — | — |
| openrouter | standby | — | — |

## Subsystem: crawler — RUNNING (33 modules)

- Current tier: 3 of 8
- Modules done: 15/33
- In progress:
  - `crawler_publication` @ deepseek-v4.1-flash · opencode-go
  - `crawler_store` @ muse-spark-1.3-contributor · opencode-go
- Blocked: none
- Issues: none

## Subsystem: ringmaster — AWAITING_OPERATOR_APPROVAL (24 modules)

- Halted at: tier 4 (INTERFACE_GAP)
- Blocked modules: rm_controls, rm_delivery, rm_supervisor
- Gap report: interface-gaps/ringmaster-t4.json
- Affected scope (if patched): 3 to re-implement, 2 to re-verify, 19 unaffected
- **Operator action required**

## Subsystem: hellscape — NOT_STARTED (29 modules)

- Awaiting command: add "hellscape" to phase4-commands.json

## Subsystem: job-hunter — RUNNING (33 modules)

- Current tier: 2 of 7
- Modules done: 8/33
- In progress:
  - `connector_dispatch` @ muse-spark-1.3-contributor · opencode-go
- Blocked: none
- Issues: none

## Blocking Issues

- ringmaster: INTERFACE_GAP at tier 4 — see interface-gaps/ringmaster-t4.json

## Non-blocking Issues

- crawler: `crawler_leases` retried once at tier 2 (high-confidence FAILED → same-model retry succeeded)
- job-hunter: two providers exercised (opencode-go → meta failover at 14:08 for one retry, recovered)
```

**Also writes `phase4-progress.json`** with the same content, machine-readable.

---

## §8. Provider health states (unified)

`phase4-state.json` `provider_health.<provider>.status` uses strictly `{unknown, active, standby, cooling_down}` with `cooldown_until: "<ISO8601>" | null`. Checking `status == "cooling_down"` is exact across all components. If `openrouter` rejects `:floor`, `openrouter_floor_disabled` flips `true` and drops `:floor` automatically.

---

## §9. Staged subsystem start

Operator triggers each subsystem independently.

**Command file:** `phase4-commands.json`
```json
{"start": ["crawler"]}
```
Operator edits this file to add subsystems or halt:
```json
{"start": ["crawler", "hellscape", "job-hunter"], "halt": false}
```
**Approval file:** `phase4-approvals.json`
```json
{
  "approve": [
    {"subsystem": "ringmaster", "tier": 4, "action": "patch"}
  ]
}
```

---

## §10. Affected-scope analysis (two-phase: pre-patch estimate vs. post-patch diff)

1. **On `INTERFACE_GAP` (before approval):** `phase4-orchestrate.py` snapshots `interface-gaps/{subsystem}-t{tier}-old.dag` and writes `interface-gaps/{subsystem}-t{tier}-estimate.json` (blocked modules + missing dependencies + 1-hop consumers) for the progress dashboard.
2. **On `"action": "patch"` (after operator runs Astra and updates `.dag`):** `phase4-orchestrate.py` validates/unpacks the new `.dag`, then diffs `old.dag` vs. new `module-graph-0.1.0.dag`:
   - `RE-IMPLEMENT`: modules with any `EXPOSES` change (`additive`, `signature-change`, `removal`), modules with `CONSUMES` `signature-change`/`removal`, and direct 1-hop consumers of `EXPOSES` `signature-change`/`removal`. (Additive `CONSUMES` alone does NOT force `RE-IMPLEMENT`.)
   - `RE-VERIFY`: direct 1-hop consumers of `RE-IMPLEMENT` modules that are not themselves in `RE-IMPLEMENT`.
   - `UNAFFECTED`: all other modules (skip).
   Writes `interface-gaps/{subsystem}-t{tier}-scope.json`.

---

## §11. `phase4_audit.json` schema & completion gates

Every subsystem writes `subsystems/{subsystem}/phase4_audit.json`:

```json
{
  "schema_version": "phase4-audit/0.1.0",
  "subsystem": "<name>",
  "generated_at": "<ISO8601>",
  "phase4_complete": true,
  "modules_total": 33,
  "modules_completed": 33,
  "modules_operator_skipped": 0,
  "modules_failed": 0,
  "modules_blocked": 0,
  "integration_test": {"passed": true, "detail": "<summary>"},
  "rate_limit_events": [{"provider": "<p>", "timestamp": "<t>"}],
  "modules": {
    "<module>": {
      "status": "COMPLETED",
      "tier": 0,
      "model": "<model>",
      "provider": "<provider>",
      "retries": 0,
      "verified_independently": true
    }
  }
}
```

- **Per-subsystem**: all modules COMPLETED with passing verification + integration test passes + `phase4_audit.json` written with `phase4_complete: true`.
- **80% pilot**: all 4 subsystems `phase4_complete: true`.
- **Circus-tent**: not required.
- **Post-Phase-4**: operator authorizes Phase 5 separately. Do NOT auto-proceed.

---

## §12. Operator invariants

1. **No manual edits to `.omp-spec.md` or `.dag`** except by operator via Astra patch (which the operator initiates by approving).
2. **Model routing by `cost_tier`, not `class`.**
3. **Escalation on failure only.**
4. **Tier sequencing inviolable.**
5. **Subsystem independence.**
6. **No retry on BLOCKED.**
7. **Cost ceiling $300.**
8. **Circus-tent is not a fallback.**
9. **No automatic Astra.** `INTERFACE_GAP` = operator gate.
10. **Provider failover is state-driven.** Orchestrator maintains authoritative state; coordinators read before spawn.
11. **Progress chart every 5 minutes.** Snapshot, not log. `cat phase4-progress.md` is the dashboard.
12. **Degraded non-isolated mode (active).** Coders share the checkout; module-dir discipline + scrubber replace worktree isolation; dispatcher commits per batch.

---

## §13. Cost estimate (updated for failover pricing)

| Scenario | Est. cost |
|---|---|
| No failover (all opencode-go, no 429s) | $195–285 |
| Moderate failover (20% of calls hit 429, use openrouter `:floor`) | $180–260 (floor cheaper on deepseek) |
| Heavy failover (50% hit 429, fall back without `:floor`) | $210–300 |

Ceiling $300 is the hard limit.

---

## §14. What comes after

When `phase4_80pct_gate: pass`:
1. Phase 5 integration — separate spec, separate authorization.
2. Circus-tent reconciliation — separate step.
3. Portfolio-level audit — roll-up.

None auto-trigger from Phase 4 completion.
