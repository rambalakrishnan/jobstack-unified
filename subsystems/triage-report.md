# Module triage report

Modules: 150; generated from 150 `.omp-spec.md` files + 5 DAG headers + seam-mapping heading passes.

## Distribution

| Class | Count | Pct |
|---|---|---:|
| S | 0 | 0.0 |
| H | 1 | 0.7 |
| I | 17 | 11.3 |
| A | 36 | 24.0 |
| B | 91 | 60.7 |
| U | 5 | 3.3 |

## Per-subsystem

| Subsystem | S | H | I | A | B | U |
|---|---|---|---|---|---|---|
| circus-tent | 0 | 0 | 3 | 8 | 19 | 1 |
| crawler | 0 | 0 | 0 | 8 | 25 | 0 |
| hellscape | 0 | 1 | 4 | 7 | 15 | 2 |
| job-hunter | 0 | 0 | 10 | 4 | 17 | 2 |
| ringmaster | 0 | 0 | 0 | 9 | 15 | 0 |

## Sample module per class

#### Class S: (no modules)

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

#### `circus-tent/file_upload` → I (medium)

- lang/tier: python / 6; consumers: 1; expose/consume: 1/4; assertions/invariants: 1/1
- invariant_ids: CF-INPUT
- forbidden_count: 6
- headings: 8.3 Nested structures; 10.3 Upload custody
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {"I": ["surface:iface_total>=5"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/file_upload/.omp-spec.md`

#### `circus-tent/access_policy` → A (medium)

- lang/tier: python / 1; consumers: 17; expose/consume: 6/1; assertions/invariants: 1/1
- invariant_ids: EK-PROVENANCE
- forbidden_count: 5
- headings: 5.4 Task envelope; 5.5 Assistance and runtime access; 16.1 Configuration; 16.2 Sensitive data reconciliation; 18.4 Eight binding inventory benchmarks
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {"I": ["surface:iface_total>=5"]}
- promotions: ['blast_radius']; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/access_policy/.omp-spec.md`

#### `circus-tent/admission_scheduler` → B (medium)

- lang/tier: python / 4; consumers: 3; expose/consume: 4/3; assertions/invariants: 1/1
- invariant_ids: EK-LEASE
- forbidden_count: 6
- headings: 5.8 Budgets and concerns; 11.1 Routing and concurrency; 11.2 Backpressure and target backoff; 18.4 Eight binding inventory benchmarks
- suffix: A=[scheduler]
- section_signals: algo=[] integ=[]
- signals_matched: {"A": ["name_suffix:scheduler"], "B": ["forbidden:shard", "invariant:EK-LEASE", "section:concurren"], "I": ["surface:iface_total>=5"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/admission_scheduler/.omp-spec.md`

#### `circus-tent/target_resolution` → U (low)

- lang/tier: python / 6; consumers: 2; expose/consume: 2/2; assertions/invariants: 1/1
- invariant_ids: CF-STATE
- forbidden_count: 5
- headings: 8.3 Nested structures; 9.5 Selector strategy gap
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'no_ladder_signal', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/target_resolution/.omp-spec.md`

## Top 10 lowest-confidence modules

#### `circus-tent/target_resolution` → U (low)

- lang/tier: python / 6; consumers: 2; expose/consume: 2/2; assertions/invariants: 1/1
- invariant_ids: CF-STATE
- forbidden_count: 5
- headings: 8.3 Nested structures; 9.5 Selector strategy gap
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'no_ladder_signal', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/target_resolution/.omp-spec.md`

#### `hellscape/authority` → U (low)

- lang/tier: go / 0; consumers: 8; expose/consume: 2/0; assertions/invariants: 1/1
- invariant_ids: EK-PROVENANCE
- forbidden_count: 4
- headings: (none)
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'no_ladder_signal', 'unresolved_invariant']
- spec: `subsystems/hellscape/modules/authority/.omp-spec.md`

#### `hellscape/cooperative_assets` → U (low)

- lang/tier: go / 1; consumers: 1; expose/consume: 1/1; assertions/invariants: 1/1
- invariant_ids: EK-ARTIFACTS
- forbidden_count: 5
- headings: 6.2 Endpoint map; 12.1 M1 cooperative profile; 1.5 Baseline Cooperative Frontend Behavior (§9.2)
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'no_ladder_signal', 'unresolved_invariant']
- spec: `subsystems/hellscape/modules/cooperative_assets/.omp-spec.md`

#### `job-hunter/access_policy` → U (low)

- lang/tier: python / 0; consumers: 19; expose/consume: 1/0; assertions/invariants: 1/1
- invariant_ids: EK-PROVENANCE
- forbidden_count: 4
- headings: 2.3 Write grants; 16.9 `vault`; 18. Privacy, evidence scope, and practice isolation
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'no_ladder_signal', 'unresolved_invariant']
- spec: `subsystems/job-hunter/modules/access_policy/.omp-spec.md`

#### `job-hunter/artifact_store` → U (low)

- lang/tier: python / 1; consumers: 30; expose/consume: 2/2; assertions/invariants: 1/1
- invariant_ids: EK-ARTIFACTS
- forbidden_count: 4
- headings: 3.4 References and hashes; 15.4 Archive and retention; 18. Privacy, evidence scope, and practice isolation
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'no_ladder_signal', 'unresolved_invariant']
- spec: `subsystems/job-hunter/modules/artifact_store/.omp-spec.md`

#### `circus-tent/access_policy` → A (medium)

- lang/tier: python / 1; consumers: 17; expose/consume: 6/1; assertions/invariants: 1/1
- invariant_ids: EK-PROVENANCE
- forbidden_count: 5
- headings: 5.4 Task envelope; 5.5 Assistance and runtime access; 16.1 Configuration; 16.2 Sensitive data reconciliation; 18.4 Eight binding inventory benchmarks
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {"I": ["surface:iface_total>=5"]}
- promotions: ['blast_radius']; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/access_policy/.omp-spec.md`

#### `circus-tent/admission_scheduler` → B (medium)

- lang/tier: python / 4; consumers: 3; expose/consume: 4/3; assertions/invariants: 1/1
- invariant_ids: EK-LEASE
- forbidden_count: 6
- headings: 5.8 Budgets and concerns; 11.1 Routing and concurrency; 11.2 Backpressure and target backoff; 18.4 Eight binding inventory benchmarks
- suffix: A=[scheduler]
- section_signals: algo=[] integ=[]
- signals_matched: {"A": ["name_suffix:scheduler"], "B": ["forbidden:shard", "invariant:EK-LEASE", "section:concurren"], "I": ["surface:iface_total>=5"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/admission_scheduler/.omp-spec.md`

#### `circus-tent/attempt_lifecycle` → A (medium)

- lang/tier: python / 5; consumers: 4; expose/consume: 4/5; assertions/invariants: 1/1
- invariant_ids: EK-ATTEMPT-SCOPE
- forbidden_count: 6
- headings: 6.4 Dispatch transitions and fields; 14.1 Commission; 14.3 Observation policy and states; 14.4 Close snapshot; 14.5 Origin facts; 14.6 Reports and snapshots
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {"I": ["surface:iface_total>=5"]}
- promotions: ['interface_surface']; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/attempt_lifecycle/.omp-spec.md`

#### `circus-tent/camoufox_binding` → B (medium)

- lang/tier: python / 5; consumers: 7; expose/consume: 1/12; assertions/invariants: 1/1
- invariant_ids: CF-ROUTE
- forbidden_count: 7
- headings: 7.1 Route and descriptor; 8.1 Transcript and failures; 8.2 Primitive matrix; 8.3 Nested structures; Appendix A — Normative contract-identifier cross-reference
- suffix: I=[binding]
- section_signals: algo=[] integ=[route]
- signals_matched: {"B": ["forbidden:expiry", "forbidden:lock"], "I": ["name_suffix:binding", "section:integration:route", "surface:iface_total>=5"]}
- promotions: []; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/camoufox_binding/.omp-spec.md`

#### `circus-tent/challenge_recovery` → A (medium)

- lang/tier: python / 6; consumers: 1; expose/consume: 1/7; assertions/invariants: 1/1
- invariant_ids: CF-ROUTE
- forbidden_count: 5
- headings: 10.4 Challenges; 19.1 Required immutable implementation artifacts; 19.2 Explicit unresolved cuts
- suffix: (none)
- section_signals: algo=[] integ=[]
- signals_matched: {"I": ["surface:iface_total>=5"]}
- promotions: ['interface_surface']; check3_override: False
- uncertainty: ['boilerplate_responsibility', 'unresolved_invariant']
- spec: `subsystems/circus-tent/modules/challenge_recovery/.omp-spec.md`

## Warnings (§6 checks 1–4)

- Check 1: `Class B exceeds 60%` {"count": 91, "total": 150}
- Check 2: `boundary signals over-triggering` {"count": 91}

## Contradictions (checks 5–6)

- Check 5 `circus-tent/admission_scheduler` → B: {"S": [], "H": [], "I": [], "A": ["scheduler"], "B": []}
- Check 5 `circus-tent/camoufox_binding` → B: {"S": [], "H": [], "I": ["binding"], "A": [], "B": []}
- Check 5 `circus-tent/circus_tent_service` → B: {"S": [], "H": [], "I": ["service"], "A": [], "B": []}
- Check 5 `circus-tent/clock_discipline` → B: {"S": ["clock"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `circus-tent/connector_execution` → B: {"S": [], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `circus-tent/contract_codec` → A: {"S": [], "H": [], "I": ["codec"], "A": [], "B": []}
- Check 5 `circus-tent/model_conduit` → B: {"S": ["model"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `circus-tent/native_transport` → B: {"S": [], "H": [], "I": ["transport"], "A": [], "B": []}
- Check 5 `circus-tent/resource_registry` → B: {"S": ["registry"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `circus-tent/subject_catalog` → I: {"S": ["catalog"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `circus-tent/workflow_engine` → B: {"S": [], "H": [], "I": [], "A": ["engine"], "B": []}
- Check 5 `crawler/crawler_classifier` → B: {"S": [], "H": [], "I": [], "A": ["classifier"], "B": []}
- Check 5 `crawler/crawler_dispatch` → B: {"S": [], "H": [], "I": ["dispatch"], "A": [], "B": []}
- Check 5 `crawler/crawler_fetch_identity` → A: {"S": ["identity"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `crawler/crawler_pipeline` → B: {"S": [], "H": [], "I": [], "A": ["pipeline"], "B": []}
- Check 5 `crawler/crawler_runtime` → B: {"S": [], "H": [], "I": [], "A": ["runtime"], "B": []}
- Check 5 `crawler/crawler_schema` → A: {"S": ["schema"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `hellscape/clock_rules` → B: {"S": ["clock"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `hellscape/connector_queries` → A: {"S": [], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `hellscape/evidence_codec` → A: {"S": [], "H": [], "I": ["codec"], "A": [], "B": []}
- Check 5 `hellscape/fixture_reducer` → B: {"S": [], "H": ["fixture"], "I": [], "A": ["reducer"], "B": []}
- Check 5 `hellscape/hellscape_engine` → B: {"S": [], "H": [], "I": [], "A": ["engine"], "B": []}
- Check 5 `hellscape/reference_connector` → B: {"S": [], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `hellscape/session_runtime` → B: {"S": [], "H": [], "I": [], "A": ["runtime"], "B": []}
- Check 5 `job-hunter/connector_controls` → B: {"S": [], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `job-hunter/connector_dispatch` → B: {"S": [], "H": [], "I": ["connector", "dispatch"], "A": [], "B": []}
- Check 5 `job-hunter/connector_observation` → A: {"S": [], "H": [], "I": ["connector"], "A": [], "B": []}
- Check 5 `job-hunter/connector_transport` → B: {"S": [], "H": [], "I": ["connector", "transport"], "A": [], "B": []}
- Check 5 `job-hunter/contract_codec` → A: {"S": [], "H": [], "I": ["codec"], "A": [], "B": []}
- Check 5 `job-hunter/model_gateway` → B: {"S": ["model"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `job-hunter/workflow_runtime` → B: {"S": [], "H": [], "I": [], "A": ["runtime"], "B": []}
- Check 5 `ringmaster/rm_catalog` → A: {"S": ["catalog"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `ringmaster/rm_models` → B: {"S": ["models"], "H": [], "I": [], "A": [], "B": []}
- Check 5 `ringmaster/rm_service` → A: {"S": [], "H": [], "I": ["service"], "A": [], "B": []}
- Check 5 `ringmaster/rm_wire` → A: {"S": [], "H": [], "I": ["wire"], "A": [], "B": []}
- Check 6 `circus-tent/admission_scheduler` → B: fired ['A', 'B', 'I']
- Check 6 `circus-tent/camoufox_binding` → B: fired ['B', 'I']
- Check 6 `circus-tent/circus_tent_service` → B: fired ['B', 'I']
- Check 6 `circus-tent/clock_discipline` → B: fired ['B', 'S']
- Check 6 `circus-tent/connector_execution` → B: fired ['B', 'I']
- Check 6 `circus-tent/deterministic_extraction` → B: fired ['A', 'B', 'I']
- Check 6 `circus-tent/evidence_journal` → B: fired ['B', 'I']
- Check 6 `circus-tent/learning_store` → A: fired ['A', 'I']
- Check 6 `circus-tent/local_controls` → B: fired ['B', 'I']
- Check 6 `circus-tent/model_conduit` → B: fired ['A', 'B', 'I']
- Check 6 `circus-tent/native_ledger` → B: fired ['B', 'I']
- Check 6 `circus-tent/native_transport` → B: fired ['B', 'I']
- Check 6 `circus-tent/observation_reader` → B: fired ['B', 'I']
- Check 6 `circus-tent/owner_publications` → B: fired ['B', 'I']
- Check 6 `circus-tent/page_observation` → B: fired ['A', 'B', 'I']
- Check 6 `circus-tent/profile_supervisor` → B: fired ['B', 'I']
- Check 6 `circus-tent/resource_registry` → B: fired ['B', 'I']
- Check 6 `circus-tent/task_preparation` → B: fired ['B', 'I']
- Check 6 `circus-tent/text_healing` → A: fired ['A', 'I']
- Check 6 `circus-tent/visual_recovery` → B: fired ['A', 'I']
- Check 6 `circus-tent/workflow_engine` → B: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_archives` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_artifacts` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_authority` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_browser` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_capabilities` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_classifier` → B: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_controls` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_coverage` → B: fired ['A', 'I']
- Check 6 `crawler/crawler_cursors` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_detectors` → B: fired ['A', 'I']
- Check 6 `crawler/crawler_dispatch` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_feed` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_leases` → B: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_normalization` → B: fired ['A', 'I']
- Check 6 `crawler/crawler_pipeline` → B: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_prepare` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_publication` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_recovery` → B: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_replay` → B: fired ['A', 'I']
- Check 6 `crawler/crawler_retention` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_runtime` → B: fired ['A', 'B', 'I']
- Check 6 `crawler/crawler_seen_ids` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_sessions` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_store` → B: fired ['B', 'I']
- Check 6 `crawler/crawler_time` → B: fired ['A', 'B', 'I']
- Check 6 `hellscape/admission` → B: fired ['B', 'I']
- Check 6 `hellscape/analysis_owner` → B: fired ['A', 'B', 'I']
- Check 6 `hellscape/application_owner` → B: fired ['B', 'I']
- Check 6 `hellscape/clock_rules` → B: fired ['B', 'S']
- Check 6 `hellscape/control_http` → B: fired ['B', 'I']
- Check 6 `hellscape/diagnostic_reducer` → A: fired ['A', 'I']
- Check 6 `hellscape/evidence_import` → B: fired ['A', 'B', 'I']
- Check 6 `hellscape/fixture_reducer` → B: fired ['A', 'B', 'H', 'I']
- Check 6 `hellscape/hellscape_engine` → B: fired ['A', 'B', 'I']
- Check 6 `hellscape/journal_rules` → B: fired ['A', 'B', 'I']
- Check 6 `hellscape/lifecycle_rules` → B: fired ['A', 'I']
- Check 6 `hellscape/manual_acceptance` → A: fired ['A', 'I']
- Check 6 `hellscape/owner_store` → B: fired ['B', 'I']
- Check 6 `hellscape/publication` → B: fired ['B', 'I']
- Check 6 `hellscape/reference_connector` → B: fired ['B', 'I']
- Check 6 `hellscape/replay` → B: fired ['A', 'B', 'I']
- Check 6 `hellscape/session_runtime` → B: fired ['A', 'B', 'I']
- Check 6 `job-hunter/archive_retention` → B: fired ['B', 'I']
- Check 6 `job-hunter/attempt_commissioning` → B: fired ['B', 'I']
- Check 6 `job-hunter/connector_controls` → B: fired ['B', 'I']
- Check 6 `job-hunter/connector_dispatch` → B: fired ['B', 'I']
- Check 6 `job-hunter/connector_transport` → B: fired ['B', 'I']
- Check 6 `job-hunter/crawler_intake` → B: fired ['A', 'B', 'I']
- Check 6 `job-hunter/evidence_journal` → B: fired ['B', 'I']
- Check 6 `job-hunter/job_evaluation` → B: fired ['A', 'I']
- Check 6 `job-hunter/lease_authority` → B: fired ['B', 'I']
- Check 6 `job-hunter/model_gateway` → B: fired ['B', 'I']
- Check 6 `job-hunter/offline_replay` → I: fired ['H', 'I']
- Check 6 `job-hunter/origin_receipts` → B: fired ['B', 'I']
- Check 6 `job-hunter/owner_revisions` → B: fired ['A', 'B', 'I']
- Check 6 `job-hunter/product_domain` → B: fired ['B', 'I']
- Check 6 `job-hunter/provider_effects` → B: fired ['B', 'I']
- Check 6 `job-hunter/query_policy` → B: fired ['A', 'I']
- Check 6 `job-hunter/read_publications` → B: fired ['A', 'B', 'I']
- Check 6 `job-hunter/workflow_runtime` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_browseroxide` → B: fired ['B', 'I']
- Check 6 `ringmaster/rm_controls` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_delivery` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_evidence` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_execution` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_leases` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_lifecycle` → B: fired ['B', 'I']
- Check 6 `ringmaster/rm_models` → B: fired ['A', 'I']
- Check 6 `ringmaster/rm_observe` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_preparation` → B: fired ['B', 'I']
- Check 6 `ringmaster/rm_recovery` → B: fired ['A', 'I']
- Check 6 `ringmaster/rm_reduction` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_supervisor` → B: fired ['A', 'B', 'I']
- Check 6 `ringmaster/rm_targets` → B: fired ['A', 'I']
- Check 6 `ringmaster/rm_time` → B: fired ['B', 'I']

## Weakest heuristic points

The three modules where the ladder is weakest are the first three entries under “Top 10 lowest-confidence modules” above: `circus-tent/target_resolution` (U, low), `hellscape/authority` (U, low), `hellscape/cooperative_assets` (U, low). Full signal dumps appear in that section.
