# m0-qualification

Local, evidence-producing qualification harness for **driver + browser binary +
configuration** stacks used in authenticated job-application workflows.

It answers one operator question: is a given stack trustworthy for a declared
scope — and it answers with mechanics, not adjectives. The harness measures;
the operator decides.

Evidence discipline (the harness never manufactures evidence):

- A Python method returning `None` is not evidence of success.
- A protocol acknowledgement is not a semantic success.
- A harness timeout is not a native driver timeout.
- An HTTP 200 is not authentication.
- A skipped required step is not a pass.
- A missing dependency is not a driver failure.
- Forced termination is not cooperative cancellation.
- Human assistance is not unattended completion.
- Loopback fixtures are not Workday or USA Jobs.

## Repository layout

```text
m0qual/            harness package (events, config, privacy, processes,
                   worker, runner, CLI, journeys, manual, reporting, adapters)
adapters/          nodriver / patchright / camoufox / pydoll (worker-only SDK imports)
suites/            T3 actions, T4 supervision/offline, T5 persistence, T6 fingerprint
schemas/           machine-readable contracts (event core, journey, fixture case,
                   fpcheck-1 collector export) — code-enforced, never decorative
configs/           local.json campaign + local-mock journey example
fixtures/          dual-origin loopback server + oracle, site pages, cases.json,
                   deterministic PDF generator
docs/              METHOD.md SAFETY.md MANUAL.md API_MATRIX.md ENV_MATRIX.md
tests/unit         harness self-tests (no browsers, no network, no SDK imports)
tests/integration  OPT-IN real-browser loopback suite (--integration)
output/<run_id>/   evidence: manifest.json, events.jsonl, report.md, artifacts/
private/           operator profiles/journeys/data — never enters VCS
```

## Setup and execution (exact commands)

Dependencies: Python 3.11+ venv with `pytest`, `httpx`,
`nodriver>=0.50`, `patchright>=1.60`, `camoufox>=0.5.7` (pydoll has no PyPI
distribution from the build host — its adapter reports BLOCKED honestly).
Browser binaries are operator-provided and never downloaded by the harness.

```bash
cd ~/workspace/m0-qualification

# 1. environment + SDK inspection report
.venv/bin/python -m m0qual doctor

# 2. dry-run plan (imports NO driver SDK, starts NO browser, loads NO credentials)
.venv/bin/python -m m0qual plan --campaign configs/local.json

# 3. local qualification battery (loopback fixtures only; no live targets)
.venv/bin/python -m m0qual run --campaign configs/local.json --stack thorium-nodriver
.venv/bin/python -m m0qual run --campaign configs/local.json --test T3 --stack thorium-patchright

# 4. harness self-tests (no browsers) and opt-in integration (real browsers, loopback)
.venv/bin/python -m pytest tests/unit -q
.venv/bin/python -m pytest tests/integration -q --integration

# 5. compare two runs mechanically
.venv/bin/python -m m0qual compare --runs RUN_ID RUN_ID

# 6. live workflows (operator-authorized only)
.venv/bin/python -m m0qual manual prepare --journey configs/journey-local-mock.json
.venv/bin/python -m m0qual run --test T1 --journey configs/journey-local-mock.json --confirm-live
```

Live runs additionally require `--allow-live-writes` when and only when the
journey contains write steps, and ALWAYS require an operator-validated journey
file. The final submission control is a physical operator action in every
mode; no flag exists that automates it.

## Exit codes

```text
0   requested qualification completed and required gates passed,
    or a successful non-executing command (plan/help/doctor)
1   valid measurement established a required-gate failure
2   blocked prerequisite, safety refusal, or configuration/dependency issue
3   harness/internal/data-integrity error
4   incomplete or inconclusive required evidence
130 interrupted
```

Every normal termination prints a sanitized one-line summary: run id (if any),
artifact location, actual status, blocking category.

## Qualification statuses

`QUALIFIED_FOR_DECLARED_SCOPE` / `NOT_QUALIFIED_FOR_DECLARED_SCOPE` /
`INCOMPLETE_EVIDENCE` / `INCOMPARABLE_CONTROLS` / `HARNESS_ERROR`. "Qualified"
names the exact tested scope: campaign, stacks, binary/driver versions,
required gates, and assistance allowed. Nothing generalizes beyond it.

## Current verification status

See `docs/ENV_MATRIX.md` (host), `docs/API_MATRIX.md` (SDKs), `MANIFEST.json`
(component-by-component status) and the latest `output/<run_id>/report.md`
(run evidence). Live portal execution is operator work: the harness ships
guards and journeys, it does not ship selector sets or claims about portals it
has not touched.

## Operator workflow (headless host)

Browsers run under Xvfb and are viewed through noVNC. Reserved display
numbers: `:99` (the operator's own `~/workspace/launch-thorium.sh`),
`:140`–`:149` (`scripts/viewer-open.sh`), `:177`–`:217` (campaign-allocated,
recorded in each run's events), `:240` fallback. Attach a web viewer to any
display with `scripts/viewer-attach.sh :<N>`; find the newest campaign's
display with `scripts/current-display.sh`. Step-by-step rote-operation and
outcome-recording instructions live in `docs/OPERATOR_GUIDE.md`.