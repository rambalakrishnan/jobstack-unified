# m0-qualification Feature Inventory

## 1. CORE EVIDENCE DISCIPLINE & NEGATIVE AXIOMS

### System Mission & Operator Boundary
- **System Purpose**: Local, evidence-producing qualification harness for **driver + browser binary + configuration** stacks used in authenticated job-application workflows.
- **Core Question Answered**: Is a given stack trustworthy for a declared scope — answered with mechanics, not adjectives.
- **Division of Responsibility**: The harness measures; the operator decides.
- **Cardinal Rule**: The harness never manufactures evidence.

### Negative Axioms (Verbatim & Exhaustive)
1. **None is not success**: A Python method returning `None` is not evidence of success.
2. **Protocol acknowledgement is not semantic success**: A protocol acknowledgement is not a semantic success.
3. **Harness timeout is not native driver timeout**: A harness timeout is not a native driver timeout.
4. **HTTP 200 is not authentication**: An HTTP 200 is not authentication.
5. **Skipped required step is not a pass**: A skipped required step is not a pass.
6. **Missing dependency is not a driver failure**: A missing dependency is not a driver failure.
7. **Forced termination is not cancellation**: Forced termination is not cooperative cancellation.
8. **Human assistance is not unattended completion**: Human assistance is not unattended completion.
9. **Loopback fixtures are not Workday**: Loopback fixtures are not Workday or USA Jobs.

### Live Portal Execution & Final Submission Boundaries
- **Portal Claims & Selector Sets**: Live portal execution is operator work; the harness ships guards and journeys, it does not ship selector sets or claims about portals it has not touched.
- **Physical Operator Final Submission Control**: The final submission control is a physical operator action in every mode; no flag exists that automates it.
- **Browser Binary Provisioning**: Browser binaries are operator-provided and never downloaded by the harness.

---

## 2. HARNESS PACKAGE & SUITE TOPOLOGY

### Repository Directory & Package Layout

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

### Core Harness Package (`m0qual/`) Submodules
- `events`
- `config`
- `privacy`
- `processes`
- `worker`
- `runner`
- `CLI`
- `journeys`
- `manual`
- `reporting`
- `adapters`

### Driver Adapters (`adapters/`) & Dependencies
- **Isolation Rule**: Worker-only SDK imports (dry-run planning and unit tests import NO driver SDKs).
- **Runtime Environment**: Python 3.11+ venv with `pytest`, `httpx`.
- **Supported Driver Adapters**:
  - `nodriver`: Requires `nodriver>=0.50`. Evaluated in stacks such as `thorium-nodriver`.
  - `patchright`: Requires `patchright>=1.60`. Evaluated in stacks such as `thorium-patchright`.
  - `camoufox`: Requires `camoufox>=0.5.7`.
  - `pydoll`: Has no PyPI distribution from the build host — its adapter reports `BLOCKED` honestly.

### Test Suites (`suites/` & Live Workflows)
- **`T1`**: Live / journey workflow execution test (invoked via `--test T1 --journey <path> --confirm-live`).
- **`T3` (`suites/`)**: Actions qualification suite (e.g., invoked via `--test T3`).
- **`T4` (`suites/`)**: Supervision / offline qualification suite.
- **`T5` (`suites/`)**: Persistence qualification suite.
- **`T6` (`suites/`)**: Fingerprint qualification suite.

### Schemas, Fixtures, Documentation & Output Artifacts
- **`schemas/`**: Code-enforced, never decorative machine-readable contracts:
  - `event core`
  - `journey`
  - `fixture case`
  - `fpcheck-1 collector export`
- **`configs/`**:
  - `configs/local.json` (campaign configuration)
  - `configs/journey-local-mock.json` (local-mock journey example)
- **`fixtures/`**:
  - Dual-origin loopback server + oracle
  - Site pages
  - `cases.json`
  - Deterministic PDF generator
- **`docs/` & Root Verification Manifests**:
  - `docs/METHOD.md`
  - `docs/SAFETY.md`
  - `docs/MANUAL.md`
  - `docs/API_MATRIX.md` (SDKs verification status)
  - `docs/ENV_MATRIX.md` (host verification status)
  - `docs/OPERATOR_GUIDE.md` (step-by-step rote-operation and outcome-recording instructions)
  - `MANIFEST.json` (component-by-component status)
- **`tests/`**:
  - `tests/unit`: Harness self-tests (no browsers, no network, no SDK imports).
  - `tests/integration`: OPT-IN real-browser loopback suite (enabled via `--integration`).
- **`output/<run_id>/`**:
  - `manifest.json`
  - `events.jsonl`
  - `report.md` (run evidence)
  - `artifacts/`
- **`private/`**:
  - Operator profiles, journeys, and data — never enters VCS.

---

## 3. CLI COMMAND INTERFACE & EXECUTION PIPELINE

### Working Directory
```bash
cd ~/workspace/m0-qualification
```

### Exact Command Invocations

1. **Environment + SDK Inspection Report (`doctor`)**:
   ```bash
   .venv/bin/python -m m0qual doctor
   ```

2. **Dry-Run Plan (`plan`)**:
   - Constraints: Imports NO driver SDK, starts NO browser, loads NO credentials.
   ```bash
   .venv/bin/python -m m0qual plan --campaign configs/local.json
   ```

3. **Local Qualification Battery (`run` — loopback fixtures only; no live targets)**:
   - Full campaign for a specific stack:
     ```bash
     .venv/bin/python -m m0qual run --campaign configs/local.json --stack thorium-nodriver
     ```
   - Specific test suite (`T3`) for a specific stack:
     ```bash
     .venv/bin/python -m m0qual run --campaign configs/local.json --test T3 --stack thorium-patchright
     ```

4. **Harness Self-Tests & Opt-In Integration Tests (`pytest`)**:
   - Unit tests (no browsers, no network, no SDK imports):
     ```bash
     .venv/bin/python -m pytest tests/unit -q
     ```
   - Opt-in integration tests (real browsers, loopback):
     ```bash
     .venv/bin/python -m pytest tests/integration -q --integration
     ```

5. **Mechanical Run Comparison (`compare`)**:
   ```bash
   .venv/bin/python -m m0qual compare --runs RUN_ID RUN_ID
   ```

6. **Live Workflows (`manual prepare` & `run` — operator-authorized only)**:
   - Manual preparation step:
     ```bash
     .venv/bin/python -m m0qual manual prepare --journey configs/journey-local-mock.json
     ```
   - Live test execution step:
     ```bash
     .venv/bin/python -m m0qual run --test T1 --journey configs/journey-local-mock.json --confirm-live
     ```

### Live Run Safety Flags & Execution Guards
- `--confirm-live`: Required to authorize live workflow runs (`m0qual run --test T1 --journey <journey_file> --confirm-live`).
- `--allow-live-writes`: Required on live runs when and only when the journey contains write steps.
- **Journey File Requirement**: Live runs ALWAYS require an operator-validated journey file.
- **Unautomated Final Submission**: The final submission control is a physical operator action in every mode; no flag exists that automates it.

---

## 4. EXIT CODES & STATUS TAXONOMY

### Exit Codes

```text
0   requested qualification completed and required gates passed,
    or a successful non-executing command (plan/help/doctor)
1   valid measurement established a required-gate failure
2   blocked prerequisite, safety refusal, or configuration/dependency issue
3   harness/internal/data-integrity error
4   incomplete or inconclusive required evidence
130 interrupted
```

| Exit Code | Mechanical Meaning |
| :--- | :--- |
| `0` | Requested qualification completed and required gates passed, or a successful non-executing command (`plan`/`help`/`doctor`). |
| `1` | Valid measurement established a required-gate failure. |
| `2` | Blocked prerequisite, safety refusal, or configuration/dependency issue. |
| `3` | Harness/internal/data-integrity error. |
| `4` | Incomplete or inconclusive required evidence. |
| `130` | Interrupted. |

### Normal Termination Summary Output Contract
Every normal termination prints a sanitized one-line summary containing:
1. `run id` (if any)
2. `artifact location`
3. `actual status`
4. `blocking category`

### Qualification Status Definitions
- `QUALIFIED_FOR_DECLARED_SCOPE`
- `NOT_QUALIFIED_FOR_DECLARED_SCOPE`
- `INCOMPLETE_EVIDENCE`
- `INCOMPARABLE_CONTROLS`
- `HARNESS_ERROR`

**Scope Boundary Rule**: "Qualified" (`QUALIFIED_FOR_DECLARED_SCOPE`) names the exact tested scope:
1. Campaign
2. Stacks
3. Binary/driver versions
4. Required gates
5. Assistance allowed

Nothing generalizes beyond the exact tested scope.

---

## 5. HEADLESS OPERATOR DISPLAY ARCHITECTURE

### Display Server & Viewer Stack
- Browsers run under **Xvfb** and are viewed through **noVNC**.

### Reserved Xvfb Display Number Allocations
| Display Range / Number | Allocation & Responsibility |
| :--- | :--- |
| `:99` | Reserved for the operator's own `~/workspace/launch-thorium.sh`. |
| `:140`–`:149` | Allocated for `scripts/viewer-open.sh`. |
| `:177`–`:217` | Campaign-allocated displays; recorded in each run's events (`events.jsonl`). |
| `:240` | Fallback display. |

### Operator Display Scripts & Commands
- **`~/workspace/launch-thorium.sh`**: Operator's standalone browser launcher using display `:99`.
- **`scripts/viewer-open.sh`**: Opens viewer displays in the reserved `:140`–`:149` range.
- **`scripts/viewer-attach.sh :<N>`**: Attaches a web viewer (noVNC) to any display `:<N>`.
- **`scripts/current-display.sh`**: Finds the newest campaign's display.
- **`docs/OPERATOR_GUIDE.md`**: Contains step-by-step rote-operation and outcome-recording instructions.
