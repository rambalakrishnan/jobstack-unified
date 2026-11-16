# jobstack-unified

Monorepo de-novo rewrite of hellscape, circus-tent, and job-hunter; initial
development of crawler and ringmaster — all against unified contracts
(`contracts/00–05`). To be split into multiple repos after a TBD milestone.

## Layout

| Path | Contents |
|---|---|
| `contracts/` | Frozen interface contracts 00–05 (+ verification notes) |
| `full-featured-blueprints/` | Source blueprints + handoff brief (inputs, read-only) |
| `feature-inventories/` | Phase 1 lossless "do-not-delete" inventories (5) |
| `seam-mappings/` | Phase 2 boundary seam mappings (5, ~95–103 KB each) |
| `subsystems/*/` | Phase 3 module DAGs, unpacked `.omp-spec.md` files, `phase3_audit.json` |
| `scripts/` | `verify_dag.py`, `unpack_dag.py`, `verify_specs.py` (deterministic, $0.00) |
| `conformance/`, `decisions/`, `prd/` | Review packet, decision register, product PRDs |
| `phase3-execute.md` | Executable Phase 3 plan (authoritative procedure) |

## Phase 3 status: complete (5/5 subsystems)

Each `subsystems/<name>/` holds `module-graph-0.1.0.dag`,
`modules/*/.omp-spec.md` (150 total), and `phase3_audit.json` with
`phase3_complete: true`. See `phase3-execute.md` §5 for the audit schema.

## Agent commit protocol (binding on all agents, all depths)

Every agent — including subagents at any depth — MUST commit AND push its
file changes with a descriptive message before yielding:

```bash
git add -A && git commit -m "<subsystem/scope>: <what changed>" && git push
```

- Commit when a unit of work completes (module implemented, spec unpacked,
  audit written), not once per session.
- Never `git push --force`, never amend another agent's commit.
- Never commit build output (`target/`, `__pycache__/`, `*.pyc`) — covered
  by `.gitignore`. Never commit secrets.

## Agent commit protocol (binding on all agents, all depths)

Every agent — including subagents at any depth — MUST commit AND push its
file changes with a descriptive message before yielding:

```bash
git add -A && git commit -m "<subsystem/scope>: <what changed>" && git push
```

- Phase 4 exception (BtrFS isolated: true subagents): Module coders
spawned by Phase 4 with isolated: true MUST NOT run git add, git commit,
or git push. OMP's isolation backend (Apply Isolated Changes: true,
Isolation Merge Strategy: branch) commits and integrates each isolated
checkout automatically. The Phase 4 orchestrator pushes cleanly at tier
boundaries.
- Commit when a unit of work completes (module implemented, spec unpacked,
audit written), not once per session.
- Never git push --force, never amend another agent's commit.
- Never commit build output (target/, __pycache__/, *.pyc, .venv/,
*.egg-info/) — covered by .gitignore. Never commit secrets.
