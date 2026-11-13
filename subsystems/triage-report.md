# Module triage report (name-first classifier)

Modules: 150; generated from 150 `.omp-spec.md` files + 5 DAG headers + seam-mapping heading passes.

## Distribution

| Class | Count | Pct |
|---|---|---:|
| S | 42 | 28.0 |
| H | 1 | 0.7 |
| I | 50 | 33.3 |
| A | 44 | 29.3 |
| B | 13 | 8.7 |
| U | 0 | 0.0 |

## Per-subsystem

| Subsystem | S | H | I | A | B | U |
|---|---|---|---|---|---|---|
| circus-tent | 10 | 0 | 8 | 11 | 2 | 0 |
| crawler | 12 | 0 | 6 | 11 | 4 | 0 |
| hellscape | 9 | 1 | 10 | 8 | 1 | 0 |
| job-hunter | 6 | 0 | 17 | 6 | 4 | 0 |
| ringmaster | 5 | 0 | 9 | 8 | 2 | 0 |

## Sample module per class

#### `circus-tent/clock_discipline` → S (medium)

- lang/tier: python / 1; consumers: 13; expose/consume: 2/1; assertions/invariants: 1/1
- invariant_ids: EK-TIME
- forbidden_count: 4
- headings: 3.3 Clocks and time points; 3.4 Measurements
- suffix: S=[clock]
- section_signals: algo=[] integ=[]
- signals_matched: {"S": ["name_suffix:clock"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/clock_discipline/.omp-spec.md`

#### `hellscape/fixture_policy` → H (medium)

- lang/tier: go / 1; consumers: 3; expose/consume: 1/2; assertions/invariants: 1/1
- invariant_ids: EK-ATTEMPT-SCOPE
- forbidden_count: 5
- headings: 5.2 Manifest field mapping; 12.1 M1 cooperative profile; 12.2 Feature-pack contract; 12.5 Compiler rejection rules; 12.6 Curriculum and recommendations
- suffix: H=[fixture]
- section_signals: algo=[] integ=[]
- signals_matched: {"H": ["name_suffix:fixture"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/hellscape/modules/fixture_policy/.omp-spec.md`

#### `circus-tent/access_policy` → I (medium)

- lang/tier: python / 1; consumers: 17; expose/consume: 6/1; assertions/invariants: 1/1
- invariant_ids: EK-PROVENANCE
- forbidden_count: 5
- headings: 5.4 Task envelope; 5.5 Assistance and runtime access; 16.1 Configuration; 16.2 Sensitive data reconciliation; 18.4 Eight binding inventory benchmarks
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/access_policy/.omp-spec.md`

#### `circus-tent/admission_scheduler` → A (medium)

- lang/tier: python / 4; consumers: 3; expose/consume: 4/3; assertions/invariants: 1/1
- invariant_ids: EK-LEASE
- forbidden_count: 6
- headings: 5.8 Budgets and concerns; 11.1 Routing and concurrency; 11.2 Backpressure and target backoff; 18.4 Eight binding inventory benchmarks
- suffix: I=[admission], A=[scheduler]
- section_signals: algo=[backpressure] integ=[]
- signals_matched: {"A": ["name_suffix:scheduler", "section:algorithmic:backpressure"], "B": ["invariant:EK-LEASE", "section:concurren"], "I": ["name_suffix:admission"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/admission_scheduler/.omp-spec.md`

#### `circus-tent/local_controls` → B (medium)

- lang/tier: python / 6; consumers: 1; expose/consume: 2/10; assertions/invariants: 1/1
- invariant_ids: EK-CLAIMS
- forbidden_count: 6
- headings: 14.3 Observation policy and states; 14.4 Close snapshot; 15.1 Separate controls; 15.2 Control observations
- suffix: B=[controls]
- section_signals: algo=[] integ=[]
- signals_matched: {"B": ["b_signal_count=0", "name_suffix:controls"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/local_controls/.omp-spec.md`

#### Class U: (no modules)

## Top 10 lowest-confidence modules

#### `circus-tent/access_policy` → I (medium)

- lang/tier: python / 1; consumers: 17; expose/consume: 6/1; assertions/invariants: 1/1
- invariant_ids: EK-PROVENANCE
- forbidden_count: 5
- headings: 5.4 Task envelope; 5.5 Assistance and runtime access; 16.1 Configuration; 16.2 Sensitive data reconciliation; 18.4 Eight binding inventory benchmarks
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/access_policy/.omp-spec.md`

#### `circus-tent/admission_scheduler` → A (medium)

- lang/tier: python / 4; consumers: 3; expose/consume: 4/3; assertions/invariants: 1/1
- invariant_ids: EK-LEASE
- forbidden_count: 6
- headings: 5.8 Budgets and concerns; 11.1 Routing and concurrency; 11.2 Backpressure and target backoff; 18.4 Eight binding inventory benchmarks
- suffix: I=[admission], A=[scheduler]
- section_signals: algo=[backpressure] integ=[]
- signals_matched: {"A": ["name_suffix:scheduler", "section:algorithmic:backpressure"], "B": ["invariant:EK-LEASE", "section:concurren"], "I": ["name_suffix:admission"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/admission_scheduler/.omp-spec.md`

#### `circus-tent/attempt_lifecycle` → I (medium)

- lang/tier: python / 5; consumers: 4; expose/consume: 4/5; assertions/invariants: 1/1
- invariant_ids: EK-ATTEMPT-SCOPE
- forbidden_count: 6
- headings: 6.4 Dispatch transitions and fields; 14.1 Commission; 14.3 Observation policy and states; 14.4 Close snapshot; 14.5 Origin facts; 14.6 Reports and snapshots
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/attempt_lifecycle/.omp-spec.md`

#### `circus-tent/camoufox_binding` → I (medium)

- lang/tier: python / 5; consumers: 7; expose/consume: 1/12; assertions/invariants: 1/1
- invariant_ids: CF-ROUTE
- forbidden_count: 7
- headings: 7.1 Route and descriptor; 8.1 Transcript and failures; 8.2 Primitive matrix; 8.3 Nested structures; Appendix A — Normative contract-identifier cross-reference
- suffix: I=[binding]
- section_signals: algo=[] integ=[route]
- signals_matched: {"B": ["forbidden:expiry"], "I": ["name_suffix:binding", "section:integration:route"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/camoufox_binding/.omp-spec.md`

#### `circus-tent/challenge_recovery` → A (medium)

- lang/tier: python / 6; consumers: 1; expose/consume: 1/7; assertions/invariants: 1/1
- invariant_ids: CF-ROUTE
- forbidden_count: 5
- headings: 10.4 Challenges; 19.1 Required immutable implementation artifacts; 19.2 Explicit unresolved cuts
- suffix: A=[recovery]
- section_signals: algo=[] integ=[]
- signals_matched: {"A": ["name_suffix:recovery"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/challenge_recovery/.omp-spec.md`

#### `circus-tent/circus_tent_service` → I (medium)

- lang/tier: python / 9; consumers: 0; expose/consume: 0/22; assertions/invariants: 1/1
- invariant_ids: EK-MANUAL
- forbidden_count: 8
- headings: 1.4 Architectural cut; 5.1 Carrier; 5.2 Nine verbs; 11.5 Shutdown; 15.4 Errors; 16.3 Callbacks; 16.4 Telemetry; 19.3 Completion criteria
- suffix: I=[service]
- section_signals: algo=[] integ=[]
- signals_matched: {"I": ["name_suffix:service"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/circus_tent_service/.omp-spec.md`

#### `circus-tent/clock_discipline` → S (medium)

- lang/tier: python / 1; consumers: 13; expose/consume: 2/1; assertions/invariants: 1/1
- invariant_ids: EK-TIME
- forbidden_count: 4
- headings: 3.3 Clocks and time points; 3.4 Measurements
- suffix: S=[clock]
- section_signals: algo=[] integ=[]
- signals_matched: {"S": ["name_suffix:clock"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/clock_discipline/.omp-spec.md`

#### `circus-tent/connector_execution` → A (medium)

- lang/tier: python / 7; consumers: 1; expose/consume: 2/13; assertions/invariants: 1/1
- invariant_ids: EK-ATOMICITY
- forbidden_count: 6
- headings: 6.1 Start records; 6.2 Atomic local admission; 6.3 Idempotency layers; 6.4 Dispatch transitions and fields; 6.6 Checkpoint mapping
- suffix: I=[connector], A=[execution]
- section_signals: algo=[] integ=[]
- signals_matched: {"A": ["name_suffix:execution"], "B": ["section:atomic"], "I": ["name_suffix:connector"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/connector_execution/.omp-spec.md`

#### `circus-tent/contract_codec` → I (medium)

- lang/tier: python / 0; consumers: 17; expose/consume: 3/0; assertions/invariants: 1/1
- invariant_ids: EK-NULL
- forbidden_count: 3
- headings: 3.1 Scalar and structural validation; 3.2 Missingness; 3.5 References and artifacts
- suffix: I=[codec]
- section_signals: algo=[] integ=[]
- signals_matched: {"I": ["name_suffix:codec"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/contract_codec/.omp-spec.md`

#### `circus-tent/deterministic_extraction` → A (medium)

- lang/tier: python / 7; consumers: 2; expose/consume: 2/6; assertions/invariants: 1/1
- invariant_ids: EXT-READ-ONLY
- forbidden_count: 6
- headings: 10.1 Stabilization and reduction; 10.2 Extraction; 18.4 Eight binding inventory benchmarks
- suffix: (none)
- section_signals: algo=[extraction, reduction] integ=[]
- signals_matched: {"A": ["section:algorithmic:extraction", "section:algorithmic:reduction"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/deterministic_extraction/.omp-spec.md`

## Warnings (§6 checks 1–4)

- Check 4: `clock_discipline` {"consumer_count": 13, "final_class": "S", "subsystem": "circus-tent"}
- Check 4: `evidence_artifacts` {"consumer_count": 25, "final_class": "S", "subsystem": "circus-tent"}
- Check 4: `evidence_journal` {"consumer_count": 25, "final_class": "S", "subsystem": "circus-tent"}
- Check 4: `crawler_artifacts` {"consumer_count": 11, "final_class": "S", "subsystem": "crawler"}
- Check 4: `crawler_authority` {"consumer_count": 22, "final_class": "S", "subsystem": "crawler"}
- Check 4: `crawler_schema` {"consumer_count": 32, "final_class": "S", "subsystem": "crawler"}
- Check 4: `crawler_store` {"consumer_count": 17, "final_class": "S", "subsystem": "crawler"}
- Check 4: `crawler_time` {"consumer_count": 15, "final_class": "S", "subsystem": "crawler"}
- Check 4: `authority` {"consumer_count": 8, "final_class": "S", "subsystem": "hellscape"}
- Check 4: `clock_rules` {"consumer_count": 9, "final_class": "S", "subsystem": "hellscape"}
- Check 4: `journal_rules` {"consumer_count": 10, "final_class": "S", "subsystem": "hellscape"}
- Check 4: `owner_store` {"consumer_count": 15, "final_class": "S", "subsystem": "hellscape"}
- Check 4: `access_policy` {"consumer_count": 19, "final_class": "S", "subsystem": "job-hunter"}
- Check 4: `artifact_store` {"consumer_count": 30, "final_class": "S", "subsystem": "job-hunter"}
- Check 4: `evidence_journal` {"consumer_count": 29, "final_class": "S", "subsystem": "job-hunter"}
- Check 4: `rm_authority` {"consumer_count": 21, "final_class": "S", "subsystem": "ringmaster"}
- Check 4: `rm_time` {"consumer_count": 14, "final_class": "S", "subsystem": "ringmaster"}

## Contradictions (checks 5–6)

- Check 5 `circus-tent/admission_scheduler` → A: {"S": [], "H": [], "I": ["admission"], "A": ["scheduler"], "B": []}
- Check 5 `circus-tent/connector_execution` → A: {"S": [], "H": [], "I": ["connector"], "A": ["execution"], "B": []}
- Check 5 `circus-tent/owner_publications` → B: {"S": ["owner"], "H": [], "I": [], "A": [], "B": ["publications"]}
- Check 5 `circus-tent/task_preparation` → A: {"S": ["task"], "H": [], "I": [], "A": ["preparation"], "B": []}
- Check 5 `crawler/crawler_archives` → B: {"S": ["archives"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `hellscape/fixture_reducer` → A: {"S": [], "H": ["fixture"], "I": [], "A": ["reducer"], "B": []}
- Check 5 `hellscape/reference_connector` → I: {"S": ["reference"], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `job-hunter/archive_retention` → B: {"S": ["archive", "retention"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `job-hunter/connector_artifacts` → I: {"S": ["artifacts"], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `job-hunter/connector_controls` → B: {"S": [], "H": [], "I": ["connector"], "A": [], "B": ["controls"]}
- Check 5 `job-hunter/connector_observation` → I: {"S": ["observation"], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `job-hunter/lease_authority` → B: {"S": ["authority"], "H": [], "I": [], "A": [], "B": ["lease"]}
- Check 5 `job-hunter/model_gateway` → I: {"S": ["model"], "H": [], "I": ["gateway"], "A": [], "B": []}
- Check 6 `circus-tent/admission_scheduler` → A: fired ['A', 'B', 'I']
- Check 6 `circus-tent/camoufox_binding` → I: fired ['B', 'I']
- Check 6 `circus-tent/connector_execution` → A: fired ['A', 'B', 'I']
- Check 6 `circus-tent/learning_store` → S: fired ['A', 'S']
- Check 6 `circus-tent/model_conduit` → S: fired ['A', 'S']
- Check 6 `circus-tent/native_ledger` → S: fired ['B', 'S']
- Check 6 `circus-tent/page_observation` → S: fired ['A', 'B', 'S']
- Check 6 `circus-tent/profile_supervisor` → A: fired ['A', 'B', 'I']
- Check 6 `circus-tent/resource_registry` → S: fired ['B', 'S']
- Check 6 `circus-tent/subject_catalog` → S: fired ['I', 'S']
- Check 6 `circus-tent/workflow_engine` → A: fired ['A', 'B']
- Check 6 `crawler/crawler_acquisition` → A: fired ['A', 'I']
- Check 6 `crawler/crawler_archives` → B: fired ['B', 'I', 'S']
- Check 6 `crawler/crawler_artifacts` → S: fired ['B', 'S']
- Check 6 `crawler/crawler_browser` → I: fired ['B', 'I']
- Check 6 `crawler/crawler_classifier` → A: fired ['A', 'B']
- Check 6 `crawler/crawler_controls` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_dispatch` → I: fired ['B', 'I']
- Check 6 `crawler/crawler_inference_host` → A: fired ['A', 'I']
- Check 6 `crawler/crawler_pipeline` → A: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_recovery` → A: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_retention` → S: fired ['B', 'S']
- Check 6 `crawler/crawler_seen_ids` → S: fired ['B', 'S']
- Check 6 `crawler/crawler_sessions` → S: fired ['B', 'I', 'S']
- Check 6 `crawler/crawler_store` → S: fired ['B', 'S']
- Check 6 `hellscape/analysis_owner` → S: fired ['A', 'S']
- Check 6 `hellscape/application_owner` → S: fired ['I', 'S']
- Check 6 `hellscape/fixture_reducer` → A: fired ['A', 'H']
- Check 6 `hellscape/journal_rules` → S: fired ['A', 'I', 'S']
- Check 6 `hellscape/lifecycle_rules` → S: fired ['A', 'I', 'S']
- Check 6 `hellscape/owner_store` → S: fired ['B', 'S']
- Check 6 `hellscape/session_runtime` → A: fired ['A', 'B']
- Check 6 `job-hunter/archive_retention` → B: fired ['B', 'S']
- Check 6 `job-hunter/connector_controls` → B: fired ['B', 'I']
- Check 6 `job-hunter/connector_dispatch` → I: fired ['B', 'I']
- Check 6 `job-hunter/crawler_intake` → I: fired ['A', 'I']
- Check 6 `job-hunter/origin_receipts` → S: fired ['A', 'S']
- Check 6 `job-hunter/owner_revisions` → S: fired ['A', 'B', 'S']
- Check 6 `job-hunter/read_publications` → B: fired ['A', 'B']
- Check 6 `ringmaster/rm_authority` → S: fired ['I', 'S']
- Check 6 `ringmaster/rm_browseroxide` → I: fired ['B', 'I']
- Check 6 `ringmaster/rm_catalog` → S: fired ['I', 'S']
- Check 6 `ringmaster/rm_controls` → B: fired ['A', 'B']
- Check 6 `ringmaster/rm_delivery` → I: fired ['A', 'I']
- Check 6 `ringmaster/rm_evidence` → A: fired ['A', 'B']
- Check 6 `ringmaster/rm_execution` → A: fired ['A', 'B']
- Check 6 `ringmaster/rm_leases` → B: fired ['A', 'B']
- Check 6 `ringmaster/rm_models` → S: fired ['A', 'S']
- Check 6 `ringmaster/rm_normalization` → A: fired ['A', 'I']
- Check 6 `ringmaster/rm_observe` → I: fired ['A', 'I']
- Check 6 `ringmaster/rm_reduction` → A: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_supervisor` → A: fired ['A', 'B']
- Check 6 `ringmaster/rm_targets` → I: fired ['A', 'I']

## Weakest heuristic points

The three modules where the ladder is weakest are the first three entries under “Top 10 lowest-confidence modules” above: `circus-tent/access_policy` (I, medium), `circus-tent/admission_scheduler` (A, medium), `circus-tent/attempt_lifecycle` (I, medium). Full signal dumps appear in that section.
