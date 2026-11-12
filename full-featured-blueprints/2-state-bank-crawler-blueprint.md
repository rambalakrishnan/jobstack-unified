# PHASE 1 PROMPT — Engine & Data Plane Architecture

## §0 Assumption Table

The supplied target reconnaissance and `browser_oxide` inventory are contractual inputs, not independently revalidated target behavior. Assumptions below concern deployment conditions only. An assumption does not override a Floor.

| ID | Scope | Field | Assumed Value | Architectural Rationale | Confidence | Cited In |
|---|---|---|---|---|---|---|
| A1 | Reference host | Hardware and resource isolation | [ASSUMED: A1 — 64-bit Linux, 16 physical CPU cores, 32 GiB RAM, working memory-controller isolation; reference sizing environment.] | Allows separate crawler, inference, storage, and coordination resource domains without making memory targets hard process limits. | Medium | §2, §6, §12 decisions 1 and 6 |
| A2 | Persistence | Storage service domains | [ASSUMED: A2 — ingest, downstream-agent persistence, and asynchronous snapshot exchange have independently reserved I/O service; ingest durable-commit median is at most 5 ms at the reference load.] | The non-blocking crawler-write Floor requires more than different table names on one contested write path. | Medium | §2, §11, §12 decisions 5 and 8 |
| A3 | Network benchmark | Pagination request time | [ASSUMED: A3 — reference median pagination network time is 200 ms; this is a sizing baseline, not a target-board measurement.] | Produces an illustrative 20 ms orchestration-overhead budget. Actual acceptance uses measured target-specific network time. | Low | §2, §12 decision 5 |
| A4 | Recovery environment | Process recovery bound | [ASSUMED: A4 — a failed local process is detected within 3 s and replacement execution is available within 10 s.] | Permits crash recovery within the default 300 s lease without waiting for lease expiry. | Medium | §5, §11, §12 decision 5 |
| A5 | Timekeeping | Clock behavior | [ASSUMED: A5 — authoritative storage time and worker wall clocks differ by at most 100 ms; monotonic clocks are available for elapsed-time measurements.] | Supports lease deadlines, navigation ceilings, and conservative session-expiration scheduling. | Medium | §2, §9, §11 |
| A6 | Storage sizing | Typical entity sizes | [ASSUMED: A6 — reference listing payload is 2 KiB and reference detail payload is 16 KiB, excluding retained response evidence and agent artifacts.] | Sizes initial queue-byte reservations. These values never become parser limits or claims about board content. | Low | §2, §12 decisions 5 and 8 |
| A7 | Downstream workload | Agent-write sizing load | [ASSUMED: A7 — reference downstream load is 5 mutations/s, with 256 KiB typical and 5 MiB p99 payloads.] | Exercises separation of frequent small crawler writes from infrequent large downstream writes. | Low | §11, §12 decision 8, §15 |
| A8 | Inference benchmark | CPU test envelope | [ASSUMED: A8 — reference inference benchmarking uses the A1 CPU host and inputs of at most 512 model tokens per item.] | Makes the requested batch-latency envelope testable without claiming that arbitrary full descriptions fit it. | Low | §6, §12 decision 6, §15 |
| A9 | Fault model | Durability boundary | [ASSUMED: A9 — process crashes and host reboots preserve acknowledged local durable storage; permanent media loss is outside the single-host recovery guarantee.] | Distinguishes crash durability from geographically replicated disaster recovery. | High | §2, §11, §12 decision 5 |

## §1 Executive Summary

### Architectural responsibilities

The data plane owns five execution boundaries:

| Boundary | Responsibility | Required result |
|---|---|---|
| Wire acquisition | Request construction, target-consistent identity, socket reuse, response acquisition, cookie processing, render classification | An acquisition result containing response evidence, transport history, session generation, and a six-value render verdict |
| Browser execution | Creation, ownership, navigation, reset, and destruction of thread-bound `Page` instances | No `Page`, isolate-local handle, DOM reference, or solver instance crosses its owning OS-thread boundary |
| Session execution | Bootstrap, handoff ingestion, live cookie continuity, request serialization where required, expiration handling | Each request belongs to exactly one current session generation or to a sessionless slot |
| Pipeline execution | Extract, optional classification, enrichment, finalization, bounded admission, leased claims | Durable entities are the source of work; stage handoffs are transactional |
| Persistence | Entity writes, cursor advancement, coverage evidence, audit events, idempotency, local recovery | A committed cursor never points beyond durably materialized observations and generated entities |

The pipeline is:

**Extract → [Snippet Classify] → [Enrich, including Phase B Fetcher] → [Description Classify] → [Finalize].**

Brackets denote surface-dependent participation, not optional implementation quality.

The data plane uses two independent classifications:

- **Render classification:** `engine_classify(html)` and `Page::challenge_verdict()` describe acquisition/rendering outcomes.
- **Content classification:** LiteRT-executed SLM output describes posting relevance.

Neither classifier substitutes for the other. A render `Pass` does not imply content `PASS`; content inference must not run on an unaccepted render.

Durable entity tables form an operational outbox. Logical queue views select declared `pipeline_state` values. Lease ownership is orthogonal to those values. A queue reference is never the sole durable copy of work.

### Scope exclusion

[DEFERRED-TO-PHASE-2: D1 — policy posture, legal admission, scheduling, crawl_allotment enforcement, integration-surface selection, agent lifecycles, human workflows, dashboards, and build sequencing.]

The data plane nevertheless enforces structural limits on its own capabilities: an extraction extension cannot invoke a state-mutating application workflow, and the Phase 1 write-action extension is non-executing.

### Resource objective

The objective is to **minimize per-worker peak RSS per unit of throughput**, subject to:

1. The network-relative performance Floor.
2. Complete Phase 1 functionality.
3. Inclusion of structured diagnostics, queryable state, self-healing recovery, deterministic replay hooks, and supported warmth reuse.

Memory targets are design pressure, not hard ceilings. A justified, declared overshoot within the prescribed bound is compliant.

### Contract completeness

This document separates:

- A fully specified architectural contract.
- Deployment assumptions requiring validation.
- Target capabilities that the supplied reconnaissance does not establish.

In particular, it does not disguise positional pagination as a non-offset cursor, manufacture an independent coverage count, or represent the placeholder Oregon solver as operational. Those activation blockers are enumerated in §16.

## §2 Non-Functional Requirements & Process Budgets

### 2.1 Memory targets

Memory values below use decimal MB and GB. Measurements include process-private allocations, resident mapped model pages, buffers, and resident runtime allocations attributable to the process.

| Process class | Target | Accounting requirement |
|---|---:|---|
| Cold crawler worker, `warm_pool_size=0` | Peak RSS ≤ 200 MB | 130 MB V8 envelope + 50 MB orchestration + 20 MB headroom |
| Warm crawler worker, `warm_pool_size=N≥1` | Peak RSS ≤ `(N+1)×130+70` MB | Includes N retained isolates and one active/cold-allocation allowance; additional bootstrap processes are separately counted |
| Orchestrator core | RSS ≤ 200 MB | Includes command routing, bounded instrumentation buffering, and run-local coordination; excludes separately accounted workers |
| SLM, nominal operating range | 600 MB–2.5 GB | Includes weights, tokenizer, runtime, activations, input/output buffers, and allocator retention |
| SLM, 0.5B class | RSS ≤ 1 GB target | Not a hard memory cap |
| SLM, 1.5B class | RSS ≤ 3 GB class target | Usage above the nominal 2.5 GB envelope still requires an overshoot declaration |
| Embedded storage service | RSS ≤ 100 MB aggregate | Aggregate across its files, caches, journals, and projection readers; not 100 MB per file |
| Remote/delegated storage service | Host-sized | Client buffers remain charged to their actual calling process |

For example, the warm-worker targets are 330 MB at `N=1` and 460 MB at `N=2`.

The 50 MB cold-worker orchestration allowance is a sizing allocation, not a requirement to preallocate memory:

| Allocation | Reference allowance |
|---|---:|
| Streaming response and encoding buffers | 16 MB |
| Command and entity-reference buffers | 8 MB |
| Exact-lookup acceleration and deduplication cache | 8 MB |
| Structured diagnostic and instrumentation buffers | 4 MB |
| Session, request, runtime, and miscellaneous state | 14 MB |

Large durable evidence and agent artifacts must not be retained as unbounded in-memory object graphs.

### 2.2 The sole hard memory Floor

**SLM execution must never cause crawler-worker OOM.**

Containment must cover:

- Model allocations and mappings.
- Runtime allocator growth.
- Inference panic or process failure.
- Input/output transport buffers.
- Host-level memory pressure attributable to the inference domain.

A different PID alone is insufficient unless deployment admission also prevents inference pressure from exhausting the shared host. The containment mechanism is specified in decision 1.

An SLM-induced crawler-isolate termination invalidates the affected crawl run. The data plane emits a durable run-invalidating diagnostic, stops claiming further work for that run, and prevents its partitions from being represented as successfully completed. This is a failed isolation acceptance test, not a recoverable within-run inference error.

### 2.3 Target overshoot contract

For each accounted process role:

\[
allowed\_overshoot\_mb
=
\left\lfloor target\_mb \times
memory\_target\_overshoot\_max\_pct / 100 \right\rfloor
\]

The adapter declaration must identify:

- The affected role and its baseline target.
- `memory_target_overshoot_mb`.
- `memory_target_overshoot_justification` when overshoot is nonzero.
- The concrete operator-labor reduction or throughput gain enabled.

The default maximum is 25%. A cold worker may therefore declare up to 50 MB above its 200 MB target. This does **not** turn 250 MB into an OOM kill threshold.

[DEFERRED-TO-PHASE-2: D2 — adjudicating whether a memory-overshoot justification qualifies and approving any scope change beyond the declared percentage bound.]

Unexplained overshoot is a target violation. Declared, qualifying overshoot within the bound is not.

### 2.4 Storage-budget compatibility

The alternatives are defined only in decision 8.

| Decision 8 alternative | Embedded-storage allocation | Remote allocation | Compatibility condition |
|---|---|---|---|
| Alternative A | Aggregate ≤ 100 MB target across ingest-owned storage components | Agent and exchange services separately host-sized | No multiplication of the embedded allowance by file count |
| Alternative B | Only local clients/caches are charged locally | Independent persistence domains host-sized | Remote latency must still satisfy the acquisition-path overhead Floor |
| Alternative C | Aggregate local journal/projection RSS ≤ 100 MB target | Any external projection service separately sized | Replay buffers and projection lag must remain bounded |

### 2.5 Throughput Floor

For pagination requests only, per target and phase-slot:

\[
median(T_{orchestration}) \le 0.10 \times median(T_{network})
\]

`T_orchestration` includes request-path storage lookup, exact deduplication checks, transactional materialization, cursor advancement, and waits introduced by those operations.

It excludes:

- Actual network acquisition.
- Bootstrap-only operations.
- SLM inference performed by downstream stages.
- Explicit queue-admission waiting.
- Blocking duration inside `signals_emit`.

Excluded durations must be reported separately; they must not disappear from end-to-end measurements.

Under A3, the illustrative orchestration budget is 20 ms. Acceptance uses the measured median, not A3.

### 2.6 Signals sink

The contract is a synchronous call:

`signals_emit({metric_name, labels:{target,phase,stage,worker_id}, value, timestamp})`

Required metrics:

| Metric | Unit and interpretation |
|---|---|
| `stage_rows_in` | Rows accepted by a stage, including separately labeled cache/bypass paths |
| `stage_rows_out` | Rows durably advanced or terminated |
| `stage_latency_ms` | Claim-to-durable-stage-result elapsed time |
| `queue_depth` | Existing eligible entity rows, not notification count |
| `phase_request_overhead_ms` | Acquisition-path orchestration time |
| `signals_emit_latency_ms` | Wall-clock duration of the synchronous sink call |

Instrumentation must not hold a session mutex, database transaction, row lease-completion lock, or V8 ownership lock while calling the sink.

If median sink latency exceeds `signals_sink_degradation_threshold_ms`, default 100 ms, over a five-minute window:

1. Emit or durably record a sink-degradation diagnostic.
2. Report throughput as degraded rather than claiming normal end-to-end conformance.
3. Continue measuring internal overhead with sink duration excluded.
4. Preserve all data-integrity, lease, memory-isolation, and target-isolation Floors.

A stuck sink must not recursively emit its own latency. A completed call’s latency is reported by a later instrumentation operation.

### 2.7 Resilience acceptance conditions

- A process crash must not lose acknowledged entities, cursor commits, classifier results, or audit transitions.
- Completed partitions are recovered from durable evidence and are not re-fetched merely because a process restarted.
- Incomplete walks may replay; their observations remain idempotent.
- A silent session rejection is detected before its body is accepted as posting content.
- One target’s challenge failure, model queue pressure, or handoff wait cannot block sibling targets.
- Within A4 and A9, pending work becomes claimable again within its configured `lease_ttl`.

## §3 Two-Transport Execution Model

### 3.1 Ten-slot transport matrix

The matrix is semantic: all ten slots exist even when a classification surface does not activate Phase B.

| Slot | Axis 1 requirement | `bootstrap_mode` | `pagination_mode` | Initial request/session preparation | Initial activation |
|---|---|---|---|---|---|
| MN-A | None | `none` | `HttpClient` | Browser-consistent profile identity | Active |
| MN-B | None | `none` | `HttpClient` | Public detail/apply-redirect acquisition only | Active |
| IL-A | None | `none` | `HttpClient` | Synthetic 32-hex `_session_id`; structured JSON representation | Active |
| IL-B | None | `none` | `HttpClient` | Public `/jobs/{id}` only; no apply action | Dormant under full-description allocation |
| WI-A | None | `none` | `HttpClient` | Response-derived WebForms state | Active |
| WI-B | Headed human login | `none` | `HttpClient` | Validated external Handoff | Active after handoff |
| MI-A | None | `none` | `HttpClient` | Query POST and subsequent result walk are acquisition operations | Active |
| MI-B | Headless challenge clear | `Page` | `HttpClient` | Cold Page cookie harvest followed by HTTP verification | Active |
| OR-A | Headless challenge clear | `Page` | `HttpClient` | Cold challenge clearance; live rotating jar | Structurally configured; activation blocked as specified in §4 |
| OR-B | Headless challenge clear | `Page` | `HttpClient` | Independently established live rotating jar | Structurally configured; activation blocked as specified in §4 |

An endpoint override may select transport behavior only within its parent slot’s declared capabilities. It cannot override:

- Target-wide `nav_timeout_ms`.
- Session serialization.
- Profile consistency.
- Solver exclusivity.
- A non-mutating acquisition capability.
- Coverage or ordering Floors.

### 3.2 Transport non-monotonicity

**`Page` is not an operational superset of `HttpClient`.**

The supplied MI behavior is the defining counterexample: browser navigation can stall on a truncated document while the cookies obtained by that navigation enable a complete approximately 154 KB HTTP response.

Therefore:

- Transport escalation is evidence-driven, not a monotonic quality ladder.
- Successful bootstrap does not require the bootstrap browser to have rendered the final job document.
- A cold browser may establish a session whose production acquisition transport remains `HttpClient`.
- A content result from one transport cannot be inferred from the apparent success of another.

### 3.3 Acquisition result contract

Every acquisition produces an immutable result envelope before entity materialization:

| Field | Meaning |
|---|---|
| `request_identity` | Canonical URL, method, body hash, representation headers |
| `target`, `phase`, `endpoint_id` | Slot and endpoint ownership |
| `worker_identity` | Executing worker |
| `session_epoch`, `shard_id` | Nullable only for sessionless execution |
| `transport_attempts` | Ordered attempt records |
| `render_verdict` | Final six-value verdict |
| `render_history` | Verdict, transport, classifier basis, content hash, timestamp per attempt |
| `response_headers`, `response_hash`, `response_bytes` | Evidence; secret header values are not copied into ordinary diagnostics |
| `accepted_content` | Present only when the acquisition is accepted |
| `deadline_at` | Navigation ceiling applied to the acquisition |

The elapsed acquisition, including its hybrid escalation chain, cannot exceed the target navigation ceiling. A remaining-deadline check precedes each escalation.

### 3.4 Hybrid pattern

| Step | Input verdict or condition | Required behavior |
|---|---|---|
| HTTP pass | `Pass` | Process the response immediately |
| HTTP pass | `ThinShell` or `RenderIncomplete`, and all required rendering inputs are already present | Dispatch the fetched HTML to `Page::from_html`; perform no network request in this step |
| HTTP pass | `ThinShell` or `RenderIncomplete`, but required subresources are absent | Skip `from_html`; escalate directly to fresh cold navigation |
| HTTP pass | `EdgeBlock`, `SensorFail`, or `ChallengeIncomplete` | Escalate to fresh cold navigation |
| `from_html` pass | `Pass` | Yield rendered DOM bytes and retain both verdicts |
| `from_html` pass | Any non-`Pass` | Escalate to fresh cold navigation |
| Cold navigation | `Pass` | Accept browser content if that endpoint’s content contract is satisfied |
| Cold navigation used for harvest | Session established but browser content incomplete | Verify through the slot’s `HttpClient`; the HTTP result determines content acceptance |
| Final attempt/deadline | Non-`Pass` | Execute the render-failure routing contract |

A cold escalation must use the slot’s configured solver fleet or other mechanism. It is not permission to try undeclared solvers.

### 3.5 Structured responses

IL’s structured representation does not pass raw JSON to an HTML-only classifier.

The endpoint normalizer must:

1. Validate media type, top-level structure, posting IDs, and the configured required structured fields.
2. Reject HTML challenge bodies masquerading as successful JSON responses.
3. Produce deterministic escaped HTML evidence from the validated structured content for `engine_classify`.
4. Record `render_basis='validated_structured_payload'`, the raw payload hash, and normalization version.
5. Preserve the raw structured fields for extraction.

The normalizer must not manufacture missing description text or override a non-`Pass` engine verdict. Empty valid result sets remain subject to the zero-observation coverage rule.

### 3.6 Session continuity

Bootstrap and pagination must use the same logical live HTTP session and pool.

Permitted engine bindings are:

- `HttpClient::shared(profile)` where the process-wide sharing domain is intentionally the required session domain.
- A retained client passed through `navigate_with_init(client)` and subsequently used for HTTP acquisition.

An ordinary `HttpClient::clone()` must not be mistaken for a shared-pool handle: the supplied engine contract gives ordinary clones independent pools.

A rotating session must serialize request completion and cookie application. Concurrent `Set-Cookie` responses can otherwise race; RFC 6265 explicitly identifies this behavior. ([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc6265.html))

### 3.7 Acquisition failure contract

| Detection | Scope | Response | Recovery | Learning |
|---|---|---|---|---|
| Non-`Pass` final verdict or navigation deadline, recorded in `render_history` by `nav_timeout_ms` | Current acquisition and its known posting, if any | Stop escalation; do not classify or extract failed content | Bounded pre-terminal retries; then §11 failed-render materialization. Unknown-ID listing pages affect the partition, not fabricated posting rows | Attempt sequence, byte lengths, hashes, deadline, final verdict, session epoch, and failure route in `audit_log` |
| Valid render but required extraction fields absent, detected before materialization | Current known posting or page extraction | Reject the successful-content write | Retry within the row/partition budget; otherwise `incomplete_extraction` | Missing-field names and extractor version; never substitute an SLM verdict |
| Decoded response exceeds `max_response_bytes`, detected while streaming | Current request | Abort body acceptance and close/drain the connection safely | Retry only after an explicitly valid representation/limit change; otherwise terminal extension reason | Actual bytes, configured bound, endpoint, and response hash prefix |

## §4 ChallengeSolver Fleet

### 4.1 Ten-slot fleet mapping

An empty fleet with no `other_mechanism` means no automated challenge capability is configured.

| Slot | `solver_names` | `other_mechanism` | `unsolvable_policy` |
|---|---|---|---|
| MN-A | `[]` | null | `abort` |
| MN-B | `[]` | null | `abort` |
| IL-A | `[]` | null | `abort` |
| IL-B | `[]` | null | `abort` |
| WI-A | `[]` | null | `abort` |
| WI-B | `[]` | `{type:'headed_sidecar', description:'external authenticated Handoff'}` | `escalate_to_human` |
| MI-A | `[]` | null | `abort` |
| MI-B | `[]` | `{type:'harvest', description:'cold Page clearance-cookie harvest, then HTTP verification'}` | `retry` |
| OR-A | `['f5_volt_adc']` | null | `abort` |
| OR-B | `['f5_volt_adc']` | null | `abort` |

The IL cookie preparation is request preparation, not a solver fleet and not a bootstrap navigation.

[INCOMPLETE: §4.OR-solver — `f5_volt_adc` is supplied only as a registered placeholder; Oregon cold bootstrap cannot be certified operational until a conforming implementation passes the challenge and continuity contracts.]

A placeholder must fail availability validation. It must not produce a successful bootstrap signal.

### 4.2 Exclusivity and capability validation

For every phase-slot:

\[
(nonempty(solver\_names) \Rightarrow other\_mechanism=null)
\]

and

\[
(other\_mechanism\ne null \Rightarrow solver\_names=[])
\]

Validation must also confirm:

- Every named solver is registered and operational, not merely named.
- Solver lifetime remains within the Page’s owning thread.
- The endpoint/profile combination is within the solver’s supported capability declaration.
- A challenge-clear bootstrap is not configured with `per_crawl_run` topology.
- The navigation deadline remains enforceable during solver execution.

### 4.3 Solver lifecycle contract

| Hook | Required ordering and effect |
|---|---|
| `observe_response` | Receives response evidence before a final content decision |
| `prepare_request` | Applies only declared request preparation; cannot replace session ownership |
| `detect` | Identifies applicability without mutating posting state |
| `relax_response_csp` | Runs before CSP attachment for that response; relaxation is response-scoped |
| `solve` | Runs on the Page thread and observes the navigation deadline |
| `solved_signal` | Terminates the challenge loop early once the solver’s clearance condition is met |

A solved signal means challenge resolution, not automatically render `Pass` or content `PASS`.

### 4.4 Unsupported automated surfaces

- Kasada: unsupported.
- reCAPTCHA Enterprise: not an automated solver; WI-B uses an external headed sidecar.
- Interactive DataDome: unsupported.

These surfaces cannot silently fall back to a generic automation attempt.

### 4.5 Unsolvable behavior

| Policy | Detection | Scope | Response | Recovery | Learning |
|---|---|---|---|---|---|
| `retry` | `SolveOutcome::Unsolvable` or bootstrap deadline | Current slot/shard generation | Retire the failed cold Page; consume one bootstrap retry | Fresh cold generation, at most `bootstrap_retry_limit`; exhaustion becomes slot-local abort | Solver/version, outcome, elapsed time, retry ordinal, redacted evidence |
| `abort` | Same, or unavailable declared solver | Current slot and dependent partitions/work | Stop new acquisitions for that slot; preserve durable work | Resume only with an operational compatible configuration or new admitted run | Durable `solver_unsolvable` or `solver_unavailable` diagnostic and affected references |
| `escalate_to_human` | Same, or authenticated-session lapse requiring login | Current authenticated shard | Release active work safely; enter the §11 handoff-wait state | A new valid Handoff reactivates acquisition; no worker waits while holding a row lease | Handoff request reason, last authenticated URL, expiry evidence, affected rows |

No policy aborts unrelated targets.

## §5 Async Pipeline Architecture

### 5.1 Function blocks

All operational state names referenced here are defined in §11.

| Block | Input | Processing responsibility | Durable output and atomic boundary |
|---|---|---|---|
| Extract | Accepted Phase A response and current cursor | Parse stubs/full descriptions; compute page evidence; perform declared deduplication; validate IDs and source URLs | Listing creation/update, observation evidence, coverage deltas, cursor advancement, and audit entries commit together |
| Snippet Classify | Claimed eligible `listing` rows | Obtain/reuse SLM verdict; apply effective shadow declaration | Classifier provenance plus listing transition to enrichment or terminal veto |
| Enrich dispatcher | Claimed eligible `listing` rows | Construct canonical Phase B request; create or reuse work | `work_item` materialization and listing delegation commit together |
| Phase B Fetcher, internal to Enrich | Claimed eligible `work_item` | Check `seen_ids` when configured; acquire detail; validate render and content | Detail write, work completion/failure, lineage, and audit commit together |
| Description Classify | Full-description listing, or accepted `job_detail` | Infer/reuse genuine description verdict | Full-description listing advances to Finalize; detail advances to ready/vetoed |
| Finalize | Claimed full-description listing | Apply the four-field synthesis mapping and fetch-key protocol | Final `job_detail`, listing completion, audit, and eligible `seen_ids` update commit together |

The dispatcher and Phase B Fetcher are separate execution boundaries but one logical **Enrich stage** for stage-count accounting.

### 5.2 Surface variants

| Classification surface | Active logical stages | Count | Initial listing state | Terminal posting entity |
|---|---|---:|---|---|
| `phase_a_full_description` | Extract → Description Classify → Finalize | 3 | `pending_description_classify` | `job_detail`; listing becomes `finalized` |
| `phase_a_snippet_phase_b_description` | Extract → Snippet Classify → Enrich → Description Classify | 4 | `pending_snippet_classify` | Snippet veto: `listing`; otherwise `job_detail` |
| `phase_b_description_only` | Extract → Enrich → Description Classify | 3 | `pending_enrich` | `job_detail` |
| `none` | Extract → Enrich | 2 | `pending_enrich` | `job_detail` |

Finalize is a no-op for the last three surfaces. It does not perform an extra hidden stage or write.

Under `none`, all eligible Phase A rows advance to enrichment. A content verdict is never fabricated.

### 5.3 Queue-view and materialization Floors

A queue view is a predicate over an existing entity:

- Eligible snippet work: listing state filter.
- Eligible enrichment dispatch: listing state filter.
- Eligible full-description classification: listing state filter.
- Eligible finalization: listing state filter.
- Eligible detail fetching: work-item state filter.
- Eligible detail classification: job-detail state filter.

There are no shadow work tables carrying independent copies of these rows.

A notification, broker record, or disk reference may accelerate discovery, but:

1. It references a committed entity.
2. Its loss cannot lose work.
3. Its duplication cannot duplicate a stage effect.
4. Queue depth is calculated from entities, not notifications.

Persistence is specified by decision 5.

### 5.4 Stage transaction contract

A stage completion must atomically:

1. Validate the lease token, entity revision, input revision, and session generation where applicable.
2. Apply the authorized operational transition.
3. Create any downstream entity.
4. Write classifier provenance or the explicit bypass transition.
5. Append state-transition audit records.
6. Update `seen_ids` only when the detail enters an eligible successful terminal state.
7. Release the lease.

A downstream entity must not be visible without its corresponding upstream delegation/completion.

No stage may hold a database transaction open during network navigation, model inference, a sink call, or human handoff waiting.

### 5.5 Thread confinement and asynchronous boundaries

- A V8 navigation, render-from-HTML operation, solver loop, or reset runs synchronously on its owning OS thread.
- Queue acquisition, durable I/O submission, and inter-process delivery may yield outside that synchronous engine operation.
- Messages crossing threads contain owned bytes, immutable request/profile descriptions, IDs, and permitted `Send` HTTP-client handles.
- Messages must not contain a `Page`, solver, DOM handle, V8 handle, or closure capturing one.

### 5.6 Routing rules

| Condition | Required route |
|---|---|
| Applied snippet `VETO` | `listing.pipeline_state='vetoed'`; retain the listing |
| Applied snippet `PASS` | Listing advances to `pending_enrich` |
| Description `VETO` on fetched detail | `job_detail.pipeline_state='vetoed'` |
| Description result on full-description listing | Listing advances to `pending_finalize`; Finalize materializes ready/vetoed detail |
| Final non-`Pass` detail render | Case B detail in `render_failed`; work item fails |
| Valid render with incomplete required extraction | No invalid successful detail; `incomplete_extraction` handling |
| No SLM surface | Ready detail with `content_verdict=null`, effective pass-through, and initial `DISCOVERED` semantics |
| SLM bypass | Advance without a classifier-result row; record `content_verdict=null`, `verdict_applied='PASS'`, and `bypass_reason='slm_bypass_on_failure'` |

**Bypass semantic clarification:** a bypass alone produces `DISCOVERED`. If an earlier applicable stage produced a genuine applied `PASS`, a later bypass preserves the genuine-verdict-derived `SHORTLISTED` candidate, as required by P.§1.B. It does not erase that provenance. Existing Phase 2-owned `CLAIMED` or `APPLIED` state is not downgraded by crawler reclassification.

### 5.7 Failure modes

| Failure | Detection | Scope | Immediate response | Recovery | Learning |
|---|---|---|---|---|---|
| SLM crash | Process exit or inference heartbeat loss within A4; otherwise batch deadline | In-flight classifier batch and classifier process | Fence late responses; release ownership through failure/bypass completion; do not terminate crawlers | Restart model execution; reuse durable inputs/results; retry or bypass according to §6 | Exit category, model digest, batch IDs, row references, retry counts, memory event, elapsed time |
| Extract worker crash | Supervisor loss detection within 3 s; otherwise lease/partition-owner expiry | Uncommitted response packet and current walk | Fence worker epoch; retain last committed cursor and observations | Replace worker within A4; replay only uncommitted/incomplete traversal; never re-fetch proven partitions | Last committed page signature, worker epoch, session generation, replay boundary |
| Phase B worker crash | Process exit/heartbeat loss; orphaned work lease | Claimed work items | Fence completion attempts; preserve completed detail transactions | Reclaim within lease TTL; recheck `seen_ids` and existing fetch key before fetching | Work key, request hash, last known acquisition stage, whether a transaction committed |
| Queue saturation | Admission counter reaches row or byte capacity, before request/claim admission | Saturated stage and its upstream producers | Stop admitting additional output-producing requests; finish already reserved writes | Joint queue/session protocol in decision 2; resume below the declared low-water mark | Queue depth, capacity type, pause duration, session deadlines, rejected admission count |
| Session lapse | Redirect/body predicate, challenge verdict, or missing authenticated-content predicate, before content acceptance and within navigation deadline | One session generation and its in-flight request | Stop using the generation; do not classify rejection content | Cold re-bootstrap or fresh headed Handoff; restart affected non-resumable walk | `session_lapse`, URL/response hashes, last successful request, cookie-generation number, affected cursor |
| Absolute lifetime expiration | Deadline calculation before dispatch, or `now ≥ session_expires_at` | One session generation | Refuse new requests; retire or replace generation | Proactive replacement before ceiling; if missed, cold recovery and walk restart where required | `session_lifetime_exceeded`, estimated birth time, ceiling, buffer, actual replacement latency |
| Durable storage unavailable | Commit failure or durable-write deadline | Current target’s affected transactions | Do not acknowledge materialization or advance cursor | Retry bounded storage recovery; pause acquisition while preserving reserved evidence | Storage error class, transaction ID, uncommitted packet references, capacity and latency |
| Final render failure | Final acquisition verdict is non-`Pass` | Known detail row, or partition if no posting IDs are trustworthy | Apply failed-render routing | Terminal for that acquisition generation; later recovery obeys fetch-key and reset rules | Full multi-stage render history and final failure reason |

## §6 SLM Classifier Stage

### 6.1 Model and performance envelope

| Dimension | Contract |
|---|---|
| Runtime | LiteRT; no inference inside crawler-worker address space |
| Parameter class | 0.5B–1.5B |
| Quantization | `int8` or `int4` |
| Nominal RSS | 600 MB–2.5 GB, with §2 model-class targets |
| Reference batch size | 25 items |
| Reference CPU latency target | 100–200 ms per batch of 25 within A8’s input envelope |
| Default inference timeout | 2,000 ms per batch |
| Long-input behavior | Never silently truncate required input; batch/token admission must respect the model manifest |
| Performance status | Acceptance target, not a supplied benchmark result |

The model manifest pins model version, artifact digest, tokenizer digest, prompt/preprocessing digest, quantization, parameter count, and maximum accepted token length.

A description outside the admitted model envelope is an inference failure unless the manifest explicitly defines a deterministic complete-input decomposition. The data plane does not invent such decomposition or discard the tail.

### 6.2 Input contract

`{target, job_id, title, employer, snippet_or_description, source_url, posted_date}`

Additional execution metadata is separate from model input:

- Stage: `snippet` or `description`.
- Model version and manifest digest.
- Entity revision and lease token.
- Effective shadow declaration revision.
- Batch ID.

Canonicalization:

1. Normalize text to Unicode NFC.
2. Normalize line endings to `\n`.
3. Trim outer whitespace; preserve internal semantic text.
4. Use an empty string for an absent optional field.
5. Serialize `posted_date` as an ISO calendar date or empty string.
6. Construct:

   `title \n employer \n snippet_or_description \n source_url \n posted_date`

7. Hash the canonical text, stage, and model version using the common canonical hash framing.

No cookie, authorization header, profile fingerprint, or worker identity enters `input_hash`.

### 6.3 Output contract

`{target, job_id, stage, verdict, verdict_applied, confidence, reason, model_version, classified_at, latency_ms, input_hash}`

Validation rules:

- `verdict ∈ {PASS,VETO}`.
- `verdict_applied ∈ {PASS,VETO}`.
- Confidence is finite and within `[0,1]`.
- `reason` is a bounded nonempty string.
- Target, job, stage, model, and hash must match the claimed input.
- Each successfully classified input has exactly one accepted output.
- Duplicate or mismatched outputs are rejected; they cannot advance another row.
- A malformed output is an inference failure, not an implicit `PASS`.

### 6.4 Batch execution and lease behavior

A batch is a collection of individually fenced row claims. Partial success is permitted: valid outputs may commit while failed or timed-out items are released.

Before dispatch:

\[
inference\_timeout + batch\_collection\_bound + commit\_margin
<
remaining\_lease\_duration
\]

A late model response cannot commit after lease release, expiry, input revision change, or model revision mismatch.

On timeout:

- Release ownership immediately.
- Record `last_failure_reason='inference_error'`.
- Increment the entity’s retry counter once.
- With bypass disabled, return unclassified rows to their unchanged pending state, or synchronously execute exhausted-retry termination.
- With bypass enabled, execute the separately audited bypass-completion route instead of scheduling another inference attempt.

The bypass route is a stage completion, not an exhausted-retry resurrection. It clears the lease and records the failure occurrence, but creates no classifier-result row.

### 6.5 Shadow and bypass matrix

| Surface | Snippet behavior | Description behavior | Bypass semantic candidate when no earlier genuine applied PASS exists |
|---|---|---|---|
| `phase_a_full_description` | Not applicable; shadow declaration must be `off` | Genuine verdict determines Finalize result | `DISCOVERED` |
| `phase_a_snippet_phase_b_description` | `off`: apply veto; `on`: record raw veto but apply pass; `dynamic_auto`: use effective Phase 2 declaration revision | Description verdict is not made shadow by snippet mode | `DISCOVERED`; preserve earlier genuine applied snippet PASS when present |
| `phase_b_description_only` | Not applicable; shadow declaration must be `off` | Genuine verdict determines ready/vetoed | `DISCOVERED` |
| `none` | No inference | No inference | Always initially `DISCOVERED`; bypass setting has no execution effect |

A raw snippet `VETO` overridden by shadow mode does not itself shortlist a posting. A later genuine description `PASS` can.

For `dynamic_auto`, the data plane accepts a versioned effective `on`/`off` declaration. A claimed batch retains the revision under which it was admitted. If no effective revision exists, the safe structural default is shadow `on`; the diagnostic records the missing revision.

[DEFERRED-TO-PHASE-2: D3 — relevance criteria, model promotion, evaluation interpretation, dynamic shadow activation thresholds, and human approval of those decisions.]

### 6.6 Result reuse

`classifier_result` is persistent by default.

A matching `(target, job_id, stage, model_version, input_hash)` permits reuse of the genuine model result. Reuse does not require another inference call.

If effective shadow application changes:

- The genuine result remains unchanged.
- The latest `verdict_applied` and application revision are updated transactionally.
- The previous application is retained in audit history.
- The stage entity records the effective decision actually used for its transition.

A TTL may evict classifier-result rows only when explicitly declared. It does not remove historical transition provenance already committed to `audit_log`.

## §7 Truncation Models & Coverage Verification

### 7.1 Detector allocation and proof baselines

| Target | Truncation/order interaction | Partition basis supplied | Intended total source | Proof baseline |
|---|---|---|---|---|
| MN | 10,000-row query cap; cosmetic 500 label | Published `loc` city facets | `facet_count` | Equality against the selected city’s exact count; cosmetic header excluded |
| IL | 10,000-match ceiling and tail clamping | County and `work_type` facets | `facet_count` | Equality |
| WI | 500 accessible rows; saturation label; backend count drift | `onet × wd` | `header_count`, `header_label_is_floor=true` | Floor proof using jobs, not openings, plus no saturation |
| MI | No supplied row cap; session-randomized order | Session-local complete walks | Candidate `payload_field_union` after normalized aggregate extraction is verified | Lower-bound union with `session_min_count=2` |
| OR | 1,000-row cap; no-op `start`; oldest IDs retained | `loc` code sets | `unreported` until independent evidence is supplied | No positive proof permitted from row count alone |

`payload_field_union` refers to a normalized extraction-envelope field. It does not imply that MI returns JSON.

[INCOMPLETE: §7.proof-sources — the supplied material does not identify a verifiable independent MI aggregate extractor or an independent OR total/floor source; MI’s lower-bound allocation and OR partition completion remain uncertified until those evidence sources are supplied.]

### 7.2 Observation accounting

Coverage evidence is recorded independently of whether an observed posting is already in `seen_ids`.

For a partition:

- `observed_total` counts rows in accepted, distinct observation packets.
- A replay of the same committed packet does not increment it.
- A new walk or session may observe the same job again and contributes a new observation.
- `distinct_observed_total` counts the exact union of job IDs.
- `observed_ids_set_hash` hashes the sorted exact ID set.
- `duplicate_rate` uses the P.§1.B repeated-distinct-ID definition.

Proof evaluation uses an identified **proof cohort**: a set of non-replayed page observations, compatible count evidence, and traversal obligations. Diagnostic probes and abandoned parent walks are not silently added to a child’s equality total.

### 7.3 The five detectors

| Detector | Detection and latency | Scope | Immediate response | Recovery | Learning |
|---|---|---|---|---|---|
| Row cap | Accepted observed count reaches declared cap, or a cap-boundary response terminates before the independent count; evaluated at each page commit | Current partition | Stop treating ordinary termination as completeness | Sub-partition; re-evaluate children | Cap, count source, boundary page, partition predicate, observed IDs hash |
| Saturation marker | Configured marker matches response, e.g. WI jobs label containing `+`; evaluated before page acceptance for proof | Current partition/count cohort | Set `saturation_marker_present=true`; invalidate positive floor proof | Split using verified axes; unsaturated child evidence may qualify | Exact matched label, normalized unit, response hash, backend evidence |
| No-op pagination parameter | Distinct requested coordinates produce the same page-1 ID set/content signature with no legitimate continuation progress; threshold two corroborating observations | Current endpoint/partition walk | Stop the loop; do not advance the cursor on fabricated progress | Use partition-only enumeration or a verified alternative cursor | Parameter delta, response signatures, first-page signature |
| Tail clamping | Beyond-range requests repeat the terminal item/page, with unchanged terminal ID signature; threshold two corroborating observations | Current walk | Terminate repetition without claiming coverage | Split the query below the cap | Last advancing coordinate, repeated IDs, reported count, clamp evidence |
| Ascending overflow | Ascending-ID order plus cap/saturation evidence, or configured banner; post-hoc newest-date regression adds corroboration | Current partition and comparable prior ledger | Mark potential loss of newest postings; prohibit ordinary completion | Split on verified axes; otherwise `ascending_overflow_unrecoverable` | Min/max IDs, max posted date, prior comparison key, banners and cap evidence |

Previously established no-op behavior does not justify repeatedly issuing prohibited positional requests. Such detector tests may be executed against retained fixtures.

### 7.4 Proof selection

Proof type is selected as follows:

1. `reported_total_source='payload_field_union'` → lower-bound proof.
2. Otherwise, `header_label_is_floor=true` → floor proof.
3. Otherwise, a verified independent exact source → equality proof.
4. Missing, inconsistent, or unverified count evidence → no positive proof.

The required equations are:

**Equality**

\[
\sum observed = reported\_total
\]

**Floor**

\[
\sum observed \ge floor\_value
\quad\land\quad
saturation\_marker\_present=false
\]

**Lower bound**

\[
|\bigcup_{\text{sessions}} job\_ids|
\ge
\max(session\_reported\_aggregate)
\quad\land\quad
session\_count \ge session\_min\_count
\]

Additional validity guards apply to every proof:

- Count units are postings, not openings or page count.
- Count evidence refers to the same partition predicate.
- No unresolved cap, clamp, no-op, or overflow detector remains.
- Required traversal termination evidence exists.
- Replayed observations are excluded.
- A count coincidence caused by duplicates does not satisfy equality: the exact-ID accounting must also show that repeated rows did not substitute for unseen advertised rows.
- Required session walks must meet their declared eligibility criteria; merely creating two cookies does not satisfy `session_count`.

**If `observed_total=0`, `pagination_coverage_proven=false`, even when the advertised total is zero.**

### 7.5 Bisection protocol

Partition planning must establish a verifiable covering domain. It may not assume facet values are disjoint unless the target evidence establishes that fact.

Selection order:

1. Eligible declared `partition_keys`.
2. If that list is empty or exhausted: `primary_partition_key`.
3. Then verified `date_partition_keys`.
4. Then verified `secondary_partition_keys`.

Only server-supported predicates may be used.

For each saturated round:

1. Persist the detector and parent predicate.
2. Produce child predicates whose union covers the parent.
3. Record overlap explicitly if the children are not disjoint.
4. Evaluate child counts and acquisition evidence.
5. Exclude exploratory parent observations from child proof arithmetic.
6. Repeat for still-saturated children.

After three saturated rounds, remaining affected leaves are marked incomplete. The crawl proceeds to other partitions.

If no valid split axis exists:

- Use `ascending_overflow_unrecoverable` when ascending overflow is established.
- Otherwise use `no_bisection_axis_available`.

A parent is complete only when its covering children have valid proofs and no uncovered predicate domain remains. Overlapping children are combined by exact job-ID union, not blind addition.

### 7.6 Coverage failure behavior

| Detection | Scope | Response | Recovery | Learning |
|---|---|---|---|---|
| Missing or contradictory total evidence at proof evaluation | Current partition | Keep proof false; record `coverage_evidence_missing` | Continue other partitions; re-evaluate only after compatible evidence is available | Source values, extraction version, count units, predicate hash |
| Three saturated rounds exhausted | Affected leaf and ancestor completion result | Mark incomplete; stop splitting that leaf | A later compatible declaration may reopen only that incomplete work | Split tree, detector history, remaining overflow |
| Zero observations | Current partition | Record `empty_unproven`; render coverage is null | Do not manufacture completion; retry only under the declared traversal/retry contract | Advertised count, request/response evidence, whether the response was validly empty |

### 7.7 Pagination versus render coverage

\[
render\_coverage =
\begin{cases}
Pass\_rendered\_rows / observed\_total,& observed\_total>0\\
null,& observed\_total=0
\end{cases}
\]

Render coverage is a health indicator. It does not gate partition completion and cannot compensate for unproven pagination.

A partition can have perfect render coverage and incomplete pagination. It can also have proven pagination while some observed rows ultimately fail rendering.

## §8 Ordering & Cursor Semantics

### 8.1 Cursor acceptance Floor

Offset pagination is permitted only when:

`ordering_model='Deterministic' AND coverage_scope='per_run'`.

A numeric `page=N`, `start=N`, or equivalent positional postback does not become a non-offset cursor merely because the adapter stores the last value or follows a “Next” link.

A permissible continuation cursor must be a verified response-bound continuation capability, not an arithmetic substitute for a page offset.

### 8.2 Ordering contracts

| Ordering model | Permitted cursor invariant | Restart invariant | Initial reconciliation/over-fetch rule |
|---|---|---|---|
| Deterministic | Offset allowed only under the stated scope; otherwise verified continuation/keyset | Resume from last committed coordinate only when ordering fingerprint remains compatible | Factor 1.0 when proof and traversal evidence remain consistent |
| Churn-shifted | Verified keyset/continuation or exhaustive single-response partitions; no positional walk | Resume only from a still-valid continuation; otherwise restart incomplete walk | Low/medium/high factors 1.1/1.5/2.0; exact-ID union and reconciliation required |
| Session-randomized | Cursor bound to session epoch, partition predicate, and previous response; no cross-session offset reuse | New session starts a new walk from its beginning | At least two eligible session walks for union proof; initial factor 2.0 |
| Multi-backend-inconsistent | Response-bound continuation with backend evidence; count cohorts cannot be mixed blindly | Backend discontinuity invalidates the active proof cohort; restart/reconcile | Factors 1.1/1.5/2.0 and bounded repeated walks |
| Ascending-by-ID with overflow | Verified keyset if available; otherwise partition-only complete responses | Restart incomplete leaf; never infer unseen newest IDs from the oldest returned IDs | Factor 1.0 for single-response leaves; splitting, not repeated no-op requests |

Over-fetch factors are traversal-planning multipliers, not proofs of completeness and not a substitute for Phase 2’s `crawl_allotment`.

### 8.3 Initial-target cursor certification

| Target | Supplied interface | Certification under the immutable offset Floor |
|---|---|---|
| MN | Numeric `page` parameter | Not certified for a churn-shifted walk |
| IL | Deterministic page enumeration | Permitted with `coverage_scope='per_run'`, subject to clamp detection |
| WI | `Page$N` stateless postback chains | Numeric positional semantics are not certified as a non-offset continuation |
| MI | Session-local serial postbacks | Session affinity is established, but a genuinely non-offset continuation capability is not established by the supplied description |
| OR | `start` is a no-op | Use partition-only acquisition; do not attempt an offset walk |

[INCOMPLETE: §8.nonoffset-cursors — the supplied MN, WI, and MI interfaces do not establish cursor capabilities satisfying the explicit non-offset Floor for their declared ordering models; initial-response acquisition and partition planning may operate, but complete multi-page walks cannot be certified without verified non-offset continuation support or a versioned change to the Phase 1 Floor.]

This is an activation boundary, not permission to silently change the ordering declaration to `Deterministic`.

### 8.4 Drift severity

For each partition/run:

\[
effective\_baseline=\max(baseline\_dup\_rate,0.001)
\]

| Band | Definition |
|---|---|
| `low` | `duplicate_rate <= effective_baseline × 1.5` |
| `medium` | `effective_baseline × 1.5 < duplicate_rate <= effective_baseline × 3.0` |
| `high` | `duplicate_rate > effective_baseline × 3.0` |

A job observed multiple times contributes one unit to the numerator, regardless of repetition count. With no distinct IDs, the rate is `0.0`.

A missing historical baseline uses declared initialization `0.0`, giving an effective baseline of `0.001`; this is a conservative detector setting, not an empirical duplicate-rate estimate.

### 8.5 Drift response

| Detection | Scope | Response | Recovery | Learning |
|---|---|---|---|---|
| Medium band at page commit, or page hash changes at an expected stable boundary | Current walk/proof cohort | Increase planned reconciliation to the medium factor; retain exact observations | Reconcile using permitted cursors; stop once proof is valid or bounded attempts exhaust | Structured `drift_events` with rate, baseline, page hashes, cursor, session/backend identity |
| High band, session permutation evidence, or ordering contradiction | Current partition and its current cursor interpretation | Stop trusting the cursor for proof; do not silently change adapter axes | Restart a compatible walk or mark incomplete after `reconciliation_pass_limit` | `ordering_drift`, old/new evidence, IDs overlap, failed assumption |
| Backend aggregate changes without compatible cohort evidence | Current WI-style count cohort | Separate count evidence; do not average totals | Complete a coherent cohort or retain incomplete status | Backend signature, both counts, units, response sequence |
| Newest-date regression against comparable prior ledger | Same partition-definition hash across runs | Flag ascending-overflow suspicion; prevent unexamined completion | Reconcile using cap/banner evidence and valid splitting | Current/prior `max_date_posted`, missing-date count, min/max IDs |

Date regression alone is not proof of truncation: legitimate removal of newer jobs can produce it. It is a required corroboration trigger.

### 8.6 Duplicate-aware ingestion

| `dedupe_location` | Wire/ingest behavior | Storage behavior |
|---|---|---|
| `phase_a` | Exact `seen_ids` check before listing creation; hit short-circuits downstream work | INSERT-OR-SKIP for the listing; observation and coverage evidence still commits |
| `phase_b` | Phase A UPSERT occurs; Phase B checks `seen_ids` before detail acquisition | Hit completes the work by reference to existing successful detail without fetching |
| `storage` | Full pipeline executes; no early successful-detail short circuit | Atomic fetch-key protocol resolves the write |

An approximate membership structure may avoid unnecessary exact lookups on definite misses. A possible hit must be confirmed against the exact store. False positives must never drop work.

Repeated observations must not cause repeated root-row writes merely to prove coverage. Exact occurrence accounting belongs to cursor/coverage evidence.

### 8.7 UPSERT reset policy

| Condition | `preserve-policy` | `reset-policy` |
|---|---|---|
| Same-run duplicate | Preserve operational state, retry count, and active lease | Same; never reset within a run |
| New-run observation of successful terminal row | Preserve terminal state | May initialize a new pipeline generation after fencing the prior generation |
| New-run observation of failed row | Preserve failure unless an explicit retry transition is admitted | Reset to the surface’s initial state and reset retry count |
| Active lease or active prior generation | Do not overwrite | Reject/defer reset; no concurrent generation under the same root key |
| Existing agent-owned fields | Preserve | Preserve |
| Existing detail with identical fetch key | Content write remains a no-op | Content write remains a no-op; reset is not a fetch-key invalidation |

Reset policy is not authority to erase audit history, clear a live lease, or bypass the fetch-key rule.

### 8.8 `seen_ids` invariant

`seen_ids` contains exact keys for details currently completed in `ready` or `vetoed`.

It excludes:

- Snippet-only vetoes with no completed detail.
- `render_failed`.
- `failed`.
- Pending classification.
- Merely observed listing IDs.

A detail transition out of an eligible successful terminal state removes or invalidates its `seen_ids` entry in the same transaction. Successful re-completion reinstates it.

## §9 Session Sharding & `!Send` Thread Confinement

### 9.1 Ten-slot session topology

Session requirements below are execution allocations derived from the supplied behavior. They do not assert additional server internals.

| Slot | Axis 2 allocation | `shard_topology` | `shard_id` | Initial bootstrap cost class | Absolute lifetime |
|---|---|---|---|---|---|
| MN-A | Stateless-per-request | `none` | null | `none` | null |
| MN-B | Stateless-per-request | `none` | null | `none` | null |
| IL-A | Stateless-per-request | `none` | null | `none` | null |
| IL-B | Stateless-per-request | `none` | null | `none` | null |
| WI-A | Stateless-per-request | `none` | null | `none` | null |
| WI-B | Session-stateful authenticated execution | `per_worker` | `worker_<N>` | `external_handoff` | null |
| MI-A | Session-stateful | `per_crawl_run` | `shared` | `none` | null |
| MI-B | Session-stateful clearance-affine execution | `per_worker` | `worker_<N>` | `per_worker` | null |
| OR-A | Stateful-rotating | `per_shard` | `shard_<I>` | `per_shard` | null |
| OR-B | Stateful-rotating | `per_shard` | `shard_<I>` | `per_shard` | null |

Initial OR shard count is a deployment declaration of two per slot, not a claim about target capacity. OR-A and OR-B do not share a frozen cookie snapshot.

### 9.2 Sessionless invariant

For `shard_topology='none'`:

- `shard_id` is null.
- Zero `session_state` rows are written.
- An in-process HTTP cookie jar and connection pool may still exist.
- “No durable session shard” does not mean “create a new socket for every request.”

### 9.3 Shared-session execution

For `per_crawl_run`:

- Shared state resides in the live `HttpClient` session.
- Workers share the intended client handle, not independent-pool clones.
- Each worker’s `Page`, if needed, remains isolated and bound to its OS thread.
- Browser operations join the live client through the engine’s initialization binding.
- Session-stateful request steps are serialized even when multiple workers exist.

V8 permits at most one thread to enter an isolate at a time; the supplied `browser_oxide::Page` contract is stricter and forbids moving the Page between threads at all. ([v8.github.io](https://v8.github.io/api/head/classv8_1_1Isolate.html))

### 9.4 Rotating-session invariants

For OR-style rotating sessions:

1. At most one request affecting a jar is in flight.
2. Every response’s cookie changes are applied before the next request is prepared.
3. Redirects and solver-generated requests are included.
4. Request sequence and cookie-generation sequence are monotonically increasing.
5. A session generation cannot have two simultaneous owners.
6. A persisted snapshot is recovery evidence, not proof that replay remains valid.
7. After owner crash, a rotating session is re-established cold rather than trusting an unacknowledged snapshot.

The engine’s process-wide `SharedSession` must not accidentally merge independent shard cookies. The isolation mechanism is specified in decision 2.

### 9.5 Absolute lifetime scheduling

When a verified lifetime `L` is declared:

\[
session\_expires\_at = verified\_session\_birth + L
\]

\[
replacement\_deadline =
session\_expires\_at - session\_rebootstrap\_buffer
\]

The buffer must cover:

- Maximum in-flight acquisition drain.
- Cold bootstrap and verification bound.
- Publication/fencing bound.
- Clock uncertainty and a declared safety margin.

A request is not admitted when its worst-case completion would cross the applicable replacement/expiration boundary.

A handoff receipt timestamp is not silently treated as original login time. If a future headed-login slot declares an absolute lifetime but lacks a trustworthy birth time, the lifetime contract is not satisfied by the current three-field Handoff alone.

All initial targets declare `session_absolute_lifetime_seconds=null`; they rely on response inspection and conservative retirement, not invented lifetime estimates.

### 9.6 Bootstrap and warmth

- All bootstrap Page instances are cold.
- PagePool serves browser pagination only.
- Handoff receipt counts as bootstrap completion for preconnect and cost attribution.
- MI-A’s query submission is not reclassified as a bootstrap merely because it establishes server-side search state.
- Unknown idle lifetimes do not justify invented keepalive requests.

### 9.7 Re-bootstrap failure behavior

| Detection | Scope | Response | Recovery | Learning |
|---|---|---|---|---|
| Replacement cannot finish before deadline | One shard generation | Stop new data requests; retire safely before the hard ceiling | Re-establish cold when capacity permits; restart session-bound walk | Deadline miss, drain/bootstrap durations, queue occupancy |
| Cold replacement fails | Replacement generation and waiting work | Keep old generation only if still valid; otherwise quiesce | Bounded retry or handoff path under slot policy | Solver outcome, generation IDs, remaining lifetime |
| Stale owner attempts publication | One obsolete worker/session generation | Reject the response and cursor commit | Current owner proceeds; obsolete worker is fenced | Owner epoch, request sequence, rejected commit reference |
| Snapshot replay is rejected | One recovered shard | Treat as lapse; no content acceptance | Cold bootstrap; restart non-resumable walk | Snapshot age, last committed cookie generation, rejection evidence |

## §10 Warm Pool & Concurrency

### 10.1 Isolate warmth

PagePool scope is:

`(process, profile, target)`

It is used only by endpoints whose effective `pagination_mode='Page'`.

Within that scope, a retained Page must remain compatible with its session generation and cookie ownership. A reset does not authorize cross-session reuse.

Lifecycle:

| Operation | Precondition | Required postcondition |
|---|---|---|
| Allocate | Worker has memory admission and owning OS thread | Page registered to exactly one thread and pool scope |
| Acquire | Page is idle and compatible with current session generation | Exclusive use; pool generation token issued |
| Execute | Owner thread holds exclusive Page access | Navigation obeys target ceiling |
| `reset_for_reuse` | Navigation finished; no outstanding Page work | DOM registry cleared; all old DOM handles invalidated; cookie jar preserved |
| Release | Reset succeeded and compatibility remains valid | Page becomes available in the same scope |
| Destroy | Reset failed, generation retired, or memory admission withdrawn | Page destroyed on owning thread; no later handle use |

### 10.2 Connection warmth

Preconnect scope is:

`(process, profile, target, phase-slot)`

It applies only to `pagination_mode='HttpClient'`.

Firing points:

- Bootstrapped slot: immediately after successful bootstrap verification.
- Non-bootstrapped slot: first request admission.
- Headed-login slot: valid Handoff receipt.
- Replacement generation: after successful replacement bootstrap.

Preconnect targets only declared acquisition origins. It must not navigate an apply/contact-reveal endpoint.

An existing compatible connection satisfies the warmth intent; repeated events must not create unbounded redundant sockets.

### 10.3 Ten-slot warmth matrix

| Slot | `warm_pool_size` | `preconnect` | Trigger |
|---|---:|---|---|
| MN-A | 0 | true | First request |
| MN-B | 0 | true | First request |
| IL-A | 0 | true | First request |
| IL-B | 0 | true | First request if activated |
| WI-A | 0 | true | First request |
| WI-B | 0 | true | Handoff receipt |
| MI-A | 0 | true | First request |
| MI-B | 0 | true | Bootstrap completion |
| OR-A | 0 | true | Bootstrap completion |
| OR-B | 0 | true | Bootstrap completion |

All five initial targets use HTTP pagination; retaining V8 isolates for their pagination would add memory without serving the declared transport.

### 10.4 Warmth failure modes

| Detection | Scope | Response | Recovery | Learning |
|---|---|---|---|---|
| Reset fails or stale DOM registry entry survives, within `page_pool_reset_timeout_ms` | One retained Page | Quarantine; do not return it to pool | Destroy on owner thread and allocate cold on next permitted admission | `warm_reset_failed`, reset phase, page generation, retained-handle diagnostic |
| Cookie jar changed unexpectedly during reset | One Page/session association | Reject reuse and fence association | Rebind only through valid session initialization or re-bootstrap | Before/after jar-generation hashes, reset version |
| Preconnect fails before request deadline | One origin/pool | Record failed warming; do not mark session failed solely for this reason | Ordinary acquisition may establish a fresh connection within its remaining deadline | DNS/TLS/connect category and added connection latency |
| Pool memory exceeds declared target/overshoot allowance | One process/pool | Stop retaining additional idle Pages | Drain idle Pages; preserve active operation correctness | RSS, pool occupancy, target declaration, reclamation result |

## §11 Storage as Operational Outbox — Schema-of-Record

### 11.0 Common conventions and ownership

#### Logical typing

Schemas are abstract and vendor-neutral.

- `id`: opaque, collision-resistant identifier.
- `timestamp`: UTC instant.
- `duration_ms`: nonnegative integer.
- `hash`: canonical digest with algorithm/version identifier.
- `json`: structurally validated JSON.
- `bytes_ref`: reference to durable bytes owned by the entity’s persistence domain.
- Nullable fields are explicitly identified.

All **posting-owned** entities root at `(target, job_id)`. Partition and session entities necessarily use their own natural scope keys; they must not fabricate a dummy posting ID. Their observation collections carry posting-root references.

`run_id` is an opaque externally supplied run identifier, not a twelfth Phase 1 entity.

#### Common claimable-row fields

`listing`, `work_item`, and `job_detail` include:

| Field | Type/constraint |
|---|---|
| `target`, `job_id` | Non-null root key |
| `active_run_id` | Run owning current pipeline generation |
| `entity_revision` | Monotonically increasing integer |
| `input_revision` | Revision of the input being processed |
| `retry_count` | Nonnegative; cumulative across stages of that row |
| `max_retries_effective` | Positive value captured for the generation |
| `lease_id` | Nullable opaque fencing token |
| `lease_owner` | Nullable worker identity |
| `leased_at`, `lease_expires_at` | Both null or both non-null with a lease |
| `last_failure_reason` | Nullable base/declared extension reason |
| `created_at`, `updated_at` | Timestamps |

Lease fields are all null when unleased. Claim does not alter operational state.

#### State vocabulary ownership

The following subsections define every operational state referenced elsewhere. Queue-state predicates use these exact values.

### 11.1 `listing`

**Primary key:** `(target, job_id)`.

| Field group | Fields |
|---|---|
| Discovery | `first_seen_run_id`, `last_seen_run_id`, `first_seen_at`, `last_seen_at` |
| Source | `partition_id`, `listing_page_url`, `source_url`, `source_response_hash`, `source_page_hash`, `extractor_version` |
| Content | `title`, nullable `employer`, nullable `snippet`, nullable `full_description`, nullable `posted_date`, `extracted_fields_json` |
| Surface | `classification_surface`, `pipeline_state` |
| Classification | nullable `content_verdict`, nullable `verdict_applied`, nullable `classifier_result_ref`, nullable `classification_policy_revision`, nullable `bypass_reason` |
| Lineage | nullable `delegated_work_item_ref`, nullable `finalized_detail_ref` |
| Operational | Common claimable fields |

`pipeline_state` domain:

`pending_snippet_classify`, `pending_enrich`, `pending_description_classify`, `pending_finalize`, `enqueued`, `finalized`, `deduped`, `vetoed`, `render_failed`, `failed`.

**Four claimable tuples**

| Entity | State field | Pending value | Claiming stage |
|---|---|---|---|
| listing | `pipeline_state` | `pending_snippet_classify` | Snippet Classify |
| listing | `pipeline_state` | `pending_enrich` | Enrich dispatcher |
| listing | `pipeline_state` | `pending_description_classify` | Full-description Description Classify |
| listing | `pipeline_state` | `pending_finalize` | Finalize |

**Initial-state mapping:** exactly as §5.2.

**Source URL invariants**

- Full-description surface: `source_url` is the actual listing response URL from which the full posting content was extracted.
- Other surfaces: `source_url` is the canonical detail acquisition URL derived from the listing.
- `listing_page_url` always identifies the enumeration response.
- Neither URL contains an invented session token.
- Missing required URL evidence causes `incomplete_extraction`; it does not produce a blank-URL ready row.

**Foreign keys**

- `classifier_result_ref` → classifier-result composite key when non-null.
- `delegated_work_item_ref` → work-item root.
- `finalized_detail_ref` → detail root.
- Partition provenance is a scoped reference to the corresponding coverage ledger.

**Indices**

- `(target, pipeline_state, lease_expires_at, created_at)`.
- `(active_run_id, target, pipeline_state)`.
- `(target, partition_id, last_seen_run_id)`.
- `(lease_owner, lease_expires_at)` for active leases.

### 11.2 `classifier_result`

**Primary key:** `(target, job_id, stage, model_version, input_hash)`.

| Field | Constraint |
|---|---|
| `stage` | `snippet` or `description` |
| `verdict` | Genuine `PASS` or `VETO` |
| `verdict_applied` | Latest applied effective verdict |
| `confidence` | Finite `[0,1]` |
| `reason` | Bounded nonempty string |
| `classified_at` | Original inference completion timestamp |
| `latency_ms` | Original inference latency |
| `model_artifact_digest`, `tokenizer_digest`, `prompt_digest` | Pinned provenance |
| `canonicalization_version` | Input canonicalization revision |
| `application_revision`, `policy_revision`, `last_applied_at` | Effective-application provenance |
| `created_at`, nullable `expires_at` | `expires_at` only when TTL declared |

The genuine model output is immutable for a key. A conflicting genuine output for the same key is rejected and audited; a later inference must not silently replace it.

**Foreign key:** posting root must exist in `listing` or `job_detail`; insertion occurs with the owning stage transaction.

**Indices**

- `(target, job_id, stage, classified_at)`.
- `(model_version, stage, classified_at)`.
- `(expires_at)` when TTL is enabled.

No row is written for bypass.

### 11.3 `work_item`

**Primary key:** `(target, job_id)`.

| Field group | Fields |
|---|---|
| State | `pipeline_state ∈ {pending,done,failed}` |
| Request | `endpoint_id`, `request_url`, `request_method`, `request_body_hash`, `request_body_ref`, `header_identity_set`, `computed_fetch_key` |
| Provenance | `listing_revision`, `classification_surface`, `partition_id`, nullable `snippet_classifier_result_ref` |
| Execution | nullable `assigned_shard_id`, nullable `session_epoch`, nullable `request_sequence` |
| Completion | nullable `job_detail_ref`, nullable `completed_at`, nullable `completion_kind` |
| Operational | Common claimable fields |

`completion_kind` is data, not a pipeline state: fetched, existing-success reuse, or idempotent-existing-detail.

Idempotent creation uses the root key and request/input revision:

- Same active request generation: no duplicate work.
- Different request while the row is actively leased: no overwrite; caller must retry/defer.
- New generation after fencing: permitted under the declared reset rules.

**Claimable tuple:** `(work_item, pipeline_state, pending, Phase B Fetcher)`.

**Foreign keys:** listing root is required; successful detail reference is optional until completion.

**Indices**

- `(target, pipeline_state, lease_expires_at, created_at)`.
- `(target, computed_fetch_key)`.
- `(active_run_id, target, pipeline_state)`.
- `(lease_owner, lease_expires_at)`.

### 11.4 `job_detail`

**Primary key:** `(target, job_id)`.

| Field group | Fields |
|---|---|
| Identity/source | `source_url`, `fetch_key`, `fetch_phase_token`, `request_params_json`, `source_response_hash`, `extractor_version` |
| Core content | nullable `title`, `employer`, `snippet`, `description`, `posted_date` |
| Extended content | `content_fields_json`, validated against `detail_content_fields` |
| Render | `render_verdict`, `render_basis`, `render_history`, `rendered_at` |
| Pipeline | `pipeline_state ∈ {pending_classification,ready,vetoed,render_failed,failed}` |
| Semantics | `semantic_state ∈ {DISCOVERED,SHORTLISTED,CLAIMED,APPLIED,CLOSED}` |
| Classification | nullable `content_verdict`, nullable `verdict_applied`, nullable snippet/description result references, nullable `final_genuine_result_ref`, nullable `bypass_reason` |
| Downstream-owned | nullable `priority_hint`, nullable `artifacts_json` |
| Versioning | `crawler_revision`, `published_agent_revision`, `semantic_candidate`, `semantic_evidence_json` |
| Operational | Common claimable fields |

Phase 1 initializes `priority_hint` and `artifacts_json` to null. It never clears downstream values during a crawler refresh.

#### Case A: successful render and required content

- `render_verdict='Pass'`.
- Every required declared content field exists, is non-null, and has the declared type.
- Pipeline state is `pending_classification`, `ready`, or `vetoed`, or a later operational failure after valid materialization.
- `source_url`, root key, fetch key, and provenance are present.

#### Case B: failed render

- `render_verdict != 'Pass'`.
- `pipeline_state='render_failed'`.
- `title`, `employer`, `snippet`, `description`, `posted_date`, and all declared content values are null.
- Root key, requested source URL, fetch key, render history, and failure evidence remain present.
- No classifier result or `seen_ids` success is created.

A `Pass` render with missing required content is not Case B. It is `incomplete_extraction`, and no invalid successful detail is inserted.

#### Finalize mapping

| Listing field | Detail field |
|---|---|
| `title` | `title` |
| `employer` | `employer` |
| `snippet` | `snippet` |
| `full_description` | `description` |

Structural provenance fields—root key, source URL, hashes, timestamps—are populated by the Finalize contract, not by arbitrary content mappings.

A required declared **content** field outside these four mappings causes `incomplete_extraction`. Finalize cannot invent compensation, requirements, or contact data.

#### Content type vocabulary

`detail_content_fields` is a map:

`field_name → {type, required, nullable, extraction_binding}`

`type` is exactly one of:

`string`, `text`, `integer`, `float`, `boolean`, `date`, `url`.

No undeclared type name, nested arbitrary object type, or vendor-specific type is accepted.

**Claimable tuple:** `(job_detail, pipeline_state, pending_classification, Description Classify)`.

**Foreign keys**

- Listing root.
- Optional classifier-result composite references.
- Work-item root for Phase B-generated detail.
- No work-item dependency for `A_full`.

**Indices**

- `(target, pipeline_state, lease_expires_at, created_at)`.
- `(target, semantic_state, updated_at)`.
- `(target, fetch_key)` for diagnosis; the primary lookup remains the root key.
- `(target, posted_date)`.
- `(active_run_id, target, pipeline_state)`.

### 11.5 `coverage_ledger`

**Primary key:** `(target, run_id, partition_id)`.

| Field group | Fields |
|---|---|
| Partition definition | `partition_predicate_json`, `partition_definition_hash`, nullable `parent_partition_id`, `child_partition_ids`, `split_round` |
| Status | `status ∈ {open,bisected,proven,incomplete,empty_unproven}` |
| Count evidence | `reported_total_source`, `reported_total_unit`, nullable `reported_total`, nullable `floor_value`, `header_label_is_floor`, `session_reported_aggregates` |
| Observations | `observed_total`, `distinct_observed_total`, `repeated_distinct_id_total`, `observed_ids_set_hash`, `duplicate_rate` |
| Render health | `render_pass_total`, nullable `render_coverage` |
| Proof | `proof_type`, `proof_cohort_refs`, `session_count`, `session_min_count`, `saturation_marker_present`, `pagination_coverage_proven`, `proof_evidence_json` |
| Time/ID bounds | nullable `min_job_id`, `max_job_id`, `max_date_posted`, `missing_posted_date_total` |
| Failure | nullable `failure_reason`, `detector_events`, `last_evaluated_at` |
| Cost evidence | Request counts, request/response bytes, bootstrap elapsed time, acquisition elapsed time |
| Versioning | `entity_revision`, `created_at`, `updated_at` |

**Foreign keys**

- Parent partition within the same target/run.
- Proof-cohort references to cursor-state walks.
- Child references must be reciprocal.

**Indices**

- `(run_id, target, status)`.
- `(target, partition_definition_hash, updated_at)`.
- `(target, failure_reason, updated_at)`.
- `(target, pagination_coverage_proven, updated_at)`.

### 11.6 `cursor_state`

**Primary key:** `(target, run_id, partition_id, walk_id)`.

| Field group | Fields |
|---|---|
| Ownership | `worker_identity`, `owner_epoch`, `phase='A'` |
| Session binding | nullable `shard_id`, nullable `session_epoch`, nullable `session_state_ref` |
| Cursor | `cursor_kind`, `cursor_payload_json`, `previous_response_hash`, `next_request_identity`, `cursor_revision` |
| Ordering | `ordering_model`, `coverage_scope`, `ordering_fingerprint`, nullable `backend_signature` |
| Walk state | `status ∈ {open,paused,complete,invalidated,failed}` |
| Evidence | `page_observations`, `exact_id_occurrences`, `page_hashes`, `drift_events` |
| Replay | nullable retained request/response byte references, profile/engine/extractor versions |
| Accounting | `observed_total`, `distinct_total`, `last_committed_request_sequence`, `created_at`, `updated_at` |

`page_observations` is a durable child collection within the cursor entity, keyed by an observation identity derived from walk, request sequence, and response hash. Physical normalization is permitted; it does not create another work queue.

Each observation records:

- Request identity and response hash.
- Page hash after volatile-selector removal.
- Ordered observed IDs and render-verdict counts.
- Reported count evidence.
- Session/backend identity.
- Whether it belongs to the active proof cohort.

`drift_events` entries contain:

`{detected_at, kind, severity, duplicate_rate, baseline, previous_page_hash, current_page_hash, cursor_revision, session_epoch, backend_signature, action, audit_event_ref}`.

**Foreign keys:** coverage ledger; optional session-state generation.

**Indices**

- `(target, run_id, partition_id, status)`.
- `(worker_identity, owner_epoch, status)`.
- Child exact-ID index `(target, run_id, partition_id, job_id)`.
- Unique observation identity.

### 11.7 `session_state`

**Primary key:** `(target, run_id, phase, shard_id, session_epoch)`.

`shard_id` is non-null here. Sessionless slots never create a row.

| Field group | Fields |
|---|---|
| Topology | `shard_topology`, `worker_identity`, `owner_epoch` |
| Lifecycle | `status ∈ {establishing,active,quiescent,expired,needs_handoff,failed,retired}` |
| Bootstrap | `bootstrap_kind ∈ {none,form_postback,challenge_clear,headed_login_handoff}`, `bootstrap_started_at`, nullable `bootstrap_completed_at`, `bootstrap_attempt` |
| State | Encrypted `cookie_jar_snapshot`, `cookie_generation`, `last_committed_request_sequence`, `profile_ref`, `client_generation` |
| Authentication | nullable `last_authenticated_url`, nullable `handoff_timestamp`, authenticated-state evidence |
| Timing | nullable `verified_session_birth`, nullable `session_absolute_lifetime_seconds`, nullable `session_expires_at`, nullable `replacement_deadline`, `last_success_at` |
| Diagnostics | nullable `last_failure_reason`, redacted solver/harvest evidence |
| Versioning | `entity_revision`, `created_at`, `updated_at` |

`bootstrap_kind` is derived from Axis 1, not inferred from transport:

- None → `none`.
- Stateless form postback → `form_postback`.
- Headless challenge clear → `challenge_clear`.
- Headed human login → `headed_login_handoff`.

**Constraints**

- At most one active generation per `(target,run_id,phase,shard_id)`.
- Cookie snapshot publication follows cookie application and request sequence advancement.
- Passwords, MFA answers, and human login credentials are never stored.
- Snapshots are sensitive session material; ordinary audit payloads contain references/hashes, not plaintext cookies.

**Indices**

- `(target, run_id, phase, shard_id, status)`.
- `(replacement_deadline, status)`.
- `(worker_identity, owner_epoch)`.
- `(target, last_failure_reason, updated_at)`.

### 11.8 `audit_log`

**Primary key:** `(target, owner_domain, event_id)`.

| Field | Constraint |
|---|---|
| `transaction_id`, `transaction_sequence` | Identifies atomic group and event order |
| `run_id`, `phase`, `partition_id`, `shard_id` | Nullable when not applicable |
| `worker_identity` | Phase 1 worker identity; nullable for non-worker writers |
| `entity_type`, `entity_id` | Polymorphic entity reference |
| `action_type` | `write` or `transition` |
| `payload_kind` | Archive, diagnostic, declaration validation, replay evidence, or other declared write kind |
| `payload_json` | Non-null only for `write` |
| `transition_json` | Non-null only for `transition` |
| `created_at`, `schema_version` | Non-null |
| `source_revision`, `result_revision` | Revision provenance where applicable |

**Exclusive payload constraint**

- `action_type='write'` → `payload_json` non-null and `transition_json` null.
- `action_type='transition'` → `transition_json` non-null and `payload_json` null.

A transition payload includes:

`{trigger, field_changes, lease_id, input_revision, session_epoch, reason, bypass_reason, policy_revision}`

with inapplicable fields null/absent.

Full-detail archive writes store the **entire existing logical detail row as JSON**, including null fields and published downstream-owned values, at the archived version vector. A hash or locator alone is not the logical payload.

**Indices**

- `(entity_type, entity_id, created_at)`.
- `(run_id, target, created_at)`.
- `(worker_identity, created_at)`.
- `(action_type, payload_kind, created_at)`.
- Unique `(transaction_id, transaction_sequence)`.

Audit records are append-only.

### 11.9 `state_mutation_record`

**Primary key:** `(target, job_id, mutation_id)`.

| Field | Meaning |
|---|---|
| `action_name`, `action_version` | External mutation identity |
| `idempotency_key` | Mutation deduplication identity |
| `request_evidence_json`, `response_evidence_json` | Redacted execution evidence |
| `status` | `requested`, `confirmed`, `rejected`, or `indeterminate` |
| `requested_at`, nullable `confirmed_at` | Timing |
| `audit_event_ref` | Associated audit provenance |

**Foreign key:** job-detail root.

**Indices**

- Unique `(target, idempotency_key)`.
- `(target, job_id, requested_at)`.
- `(target, status, requested_at)`.

**Phase 1 invariant: zero rows written.** These fields reserve a data contract, not an executable mutation workflow.

### 11.10 `dead_letter`

**Primary key:** `(target, entity_type, entity_id, failure_reason)`.

| Field | Meaning |
|---|---|
| `run_id`, `stage`, `partition_id` | Failure context |
| `retry_count` | Number of occurrences of this specific terminal failure reason for this entity |
| `first_failed_at`, `last_failed_at` | Timing |
| `last_entity_revision`, nullable `last_lease_id` | Fencing provenance |
| `diagnostic_json` | Structured failure detail |
| `audit_event_refs` | Evidence pointers |
| `resolution_status` | `open` or `superseded`; no Phase 1 human workflow implied |

The counter is independent of `listing.retry_count`, `work_item.retry_count`, and `job_detail.retry_count`.

**Foreign key:** polymorphic entity reference, retained even when a later allowed retention process removes the source row.

**Indices**

- `(target, failure_reason, last_failed_at)`.
- `(run_id, stage, last_failed_at)`.
- `(entity_type, entity_id)`.
- `(resolution_status, last_failed_at)`.

Base `failure_reason` vocabulary is exactly the preamble vocabulary. Extensions must be declared.

### 11.11 `seen_ids`

**Primary key:** `(target, job_id)`.

| Field | Meaning |
|---|---|
| `completed_fetch_key` | Detail request identity successfully completed |
| `completed_pipeline_state` | `ready` or `vetoed` only |
| `completed_detail_revision` | Fenced successful detail revision |
| `first_completed_at`, `last_completed_at` | Timing |
| `completed_run_id` | Completion provenance |

**Foreign key:** job-detail root, with matching successful terminal revision.

**Indices**

- Primary exact membership index.
- `(target, last_completed_at)`.
- `(target, completed_run_id)`.

No approximate structure replaces this exact entity.

### 11.12 Polymorphic reference format

References use canonical escaped components:

| Entity | `entity_id` format |
|---|---|
| listing | `listing/<target>/<job_id>` |
| work_item | `work_item/<target>/<job_id>` |
| job_detail | `job_detail/<target>/<job_id>` |
| classifier_result | `classifier_result/<target>/<job_id>/<stage>/<model_version>/<input_hash>` |
| coverage_ledger | `coverage_ledger/<target>/<run_id>/<partition_id>` |
| cursor_state | `cursor_state/<target>/<run_id>/<partition_id>/<walk_id>` |
| session_state | `session_state/<target>/<run_id>/<phase>/<shard_id>/<session_epoch>` |
| state_mutation_record | `state_mutation_record/<target>/<job_id>/<mutation_id>` |
| seen_ids | `seen_ids/<target>/<job_id>` |

Components are length-framed or escaped without ambiguity. Raw slash concatenation of unescaped identifiers is prohibited.

Soft references are validated transactionally when the referenced entity is expected to exist. Diagnostic references to rejected configuration or unavailable workers are explicitly typed as diagnostic subjects, not falsely declared entity foreign keys.

### 11.13 Operational state-transition matrix

| Entity | From | Trigger/guard | To |
|---|---|---|---|
| listing | Absent | Valid new extraction | Surface-specific initial state |
| listing | `pending_snippet_classify` | Effective PASS or bypass completion | `pending_enrich` |
| listing | `pending_snippet_classify` | Applied VETO | `vetoed` |
| listing | `pending_enrich` | Work UPSERT committed | `enqueued` |
| listing | Any eligible initial state | Exact successful-detail short circuit where applicable | `deduped` |
| listing | `pending_description_classify` | Genuine result or bypass completion | `pending_finalize` |
| listing | `pending_finalize` | Valid detail synthesis committed | `finalized` |
| listing | Eligible pending state | Exhausted operational/extraction failure | `failed` |
| listing | Known-row extraction generation | Final non-Pass render | `render_failed` |
| work_item | Absent | Dispatcher materialization | `pending` |
| work_item | `pending` | Detail committed or exact existing success reused | `done` |
| work_item | `pending` | Terminal fetch/render/extraction failure | `failed` |
| job_detail | Absent/new fetch revision | Case A and SLM required | `pending_classification` |
| job_detail | Absent/new fetch revision | Case A and no SLM, or Finalize effective PASS | `ready` |
| job_detail | Absent/new fetch revision | Finalize effective VETO | `vetoed` |
| job_detail | Absent/new fetch revision | Case B | `render_failed` |
| job_detail | `pending_classification` | Applied PASS or bypass completion | `ready` |
| job_detail | `pending_classification` | Applied VETO | `vetoed` |
| job_detail | `pending_classification` | Exhausted non-bypassed classifier failure | `failed` |
| Any claimable entity | Pending | Claim or successful lease renewal | Same state |
| Any claimable entity | Pending | Non-exhausted early release/expiry | Same state |
| Any claimable entity | Prior-run non-active state | Authorized `reset-policy` generation change | Declared initial state |

Transitions not listed are rejected unless a versioned schema extension explicitly declares them.

### 11.14 Semantic state matrix

`semantic_candidate` is derived from the final applicable genuine verdict:

- Genuine applied PASS → `SHORTLISTED`.
- Genuine VETO, no genuine verdict, or bypass-only path → `DISCOVERED`.
- Explicit authoritative closure evidence → `CLOSED`.

A content veto is not evidence that the posting is closed.

| From \ To | DISCOVERED | SHORTLISTED | CLAIMED | APPLIED | CLOSED |
|---|---|---|---|---|---|
| DISCOVERED | P1, idempotent/current candidate | P1, genuine applied PASS | P2, accepted ready-row claim | Forbidden direct transition | P1, authoritative closure |
| SHORTLISTED | P1, newer genuine non-shortlisting result and no active P2 ownership | P1, idempotent/current candidate | P2, accepted ready-row claim | Forbidden direct transition | P1, authoritative closure |
| CLAIMED | P2 release to current DISCOVERED candidate | P2 release to current SHORTLISTED candidate | P2, idempotent ownership update | P2, confirmed application transition | P1, authoritative closure |
| APPLIED | Forbidden | Forbidden | Forbidden | P2, idempotent update | P1, authoritative closure |
| CLOSED | Forbidden automatic reopen | Forbidden automatic reopen | Forbidden | Forbidden | P1, idempotent closure |

Guards:

- Phase 1 never writes `CLAIMED` or `APPLIED`.
- Missing from one crawl is not authoritative closure.
- Phase 1 reclassification cannot overwrite active downstream ownership.
- Closure dominates a stale downstream claim projection.
- A Phase 2 command based on a stale crawler revision may be durably recorded by its owner but is not guaranteed to become the effective merged semantic state.
- Reopening a closed posting requires a future explicitly versioned transition contract.

### 11.15 Generic lease primitive

#### Atomic claim

Inputs:

`entity_type, pending_value, target_scope, limit, worker_identity, lease_ttl, expected_schema_version`

Atomic postconditions for each selected row:

1. State equals the requested pending value.
2. No unexpired lease exists.
3. A unique `lease_id` and owner are written.
4. `leased_at` and `lease_expires_at` are set from authoritative time.
5. `last_failure_reason` is cleared.
6. Entity revision advances.
7. Operational state is unchanged.
8. Claim audit is appended.

#### Completion fencing

A completion is accepted only if:

- Lease ID matches.
- Lease is unexpired.
- Input/entity revision is compatible.
- Worker/session ownership epoch is current.
- The requested transition is permitted.

A stale completion has no side effect.

#### Expiry sweeper

For each expired lease, atomically:

1. Clear lease ownership fields.
2. Increment `retry_count` once.
3. Preserve the pending state if retries remain.
4. If exhausted, apply the entity’s terminal failure route.
5. Append/update `dead_letter` using:

   `failure_reason = last_failure_reason ?? 'retry_exhausted'`.

6. Append audit transitions.

#### Early release

A failed worker operation atomically:

- Clears the lease.
- Increments `retry_count`.
- Sets `last_failure_reason`.
- Leaves the row pending if retries remain.
- Otherwise synchronously applies terminal failure and dead-letter recording.

The explicit classifier bypass-completion route in §6 advances the stage instead of requesting a retry; it is not a later reset of a dead-lettered row.

#### Crash recovery bound

The expiry sweeper is not the only recovery trigger. Confirmed worker death fences the owner and makes its work recoverable under the same atomic accounting rules. Under A4, this occurs well before the default lease TTL.

Lease overrides must exceed the configured detection/restart/reclamation bound. A deployment cannot declare a 2 s lease while claiming a 10 s process-replacement guarantee.

#### Retry accounting

Counters accumulate across stages of the same row. They reset across runs only under `reset-policy`.

Moving from listing to work item creates a different entity with its own counter; it does not reset the listing’s history.

### 11.16 Fetch-key construction and atomic update

Canonical request parameters are:

`(URL, method, body_hash, header_identity_set)`.

Canonicalization:

- Uppercase method.
- Normalize scheme/host case and default port.
- Remove URL fragment.
- Preserve query ordering unless the endpoint explicitly proves it irrelevant.
- Hash the actual request body bytes.
- Normalize header names and deterministic multi-value framing.

Representation headers remain included. Identity/session-ephemeral headers are excluded, including Cookie, Authorization, Referer, Date, profile identity headers, and valid adapter exclusions. An adapter may not exclude a known representation-determining header merely to increase cache hits.

Keys:

- Normal detail: `hash(target, 'B', job_id, request_params)`.
- Full-description synthesis: `hash(target, 'A_full', job_id, listing.source_url)`.

Atomic protocol:

| Lookup result at `(target,job_id)` | Required action |
|---|---|
| Absent | Insert complete validated row with computed fetch key |
| Present, same fetch key | No-op for the content write; existing row remains authoritative |
| Present, different fetch key | Archive the entire old logical row in `audit_log.payload_json` with `action_type='write'`; then update crawler-owned content and fetch key atomically |

The archive and replacement are one committed effect. A failure cannot leave an updated row without its archive.

Independent lease, classification, and semantic transitions remain governed by their own state contracts; “same fetch key” does not authorize rewriting response content.

**Consequence:** the prescribed key does not encode response content or crawl date. Same-request content changes are not automatic refreshes. A failed-render row also cannot be replaced by a same-key content rewrite. This limitation is explicit in §15; no hidden run nonce is added.

### 11.17 Write ownership and non-blocking requirements

The logical `job_detail` entity has two ownership components:

| Component | Owned fields |
|---|---|
| Crawler-owned | Acquisition content, fetch key, render evidence, pipeline state, classifier provenance, crawler semantic candidate, crawler revision |
| Downstream-owned | Priority hint, artifacts, downstream semantic ownership state, downstream revision |

Required behavior, implemented by decision 8:

- No crawler transaction acquires an agent-owned write lock.
- No crawler commit waits for an agent transaction, agent acknowledgment, or large agent-payload serialization.
- Agent writes cannot hold an ingest journal, checkpoint, or storage writer.
- Effective reads identify their crawler/agent version vector.
- Only fully published, locally durable downstream snapshots participate in the logical row.
- Full-row archiving captures the entire previously published logical row at a named version vector.
- Publication lag is explicit; global cross-owner linearizability is not promised.
- Crawler refresh preserves published downstream-owned fields.

## §12 Key Technical Design Decisions & Core Tensions

### Decision 1 — SLM isolation mechanism

**Floor.** Inference activity must never cause crawler-worker OOM.

**Problem statement.** Model weights are only part of inference memory. Activations, tokenizer buffers, allocator fragmentation, and request bursts can exceed the nominal model envelope. Process separation without host admission leaves a global-OOM failure path.

**Floor-compliant alternatives**

1. Separate local inference process in an independently bounded memory domain, with host admission reserving crawler and operating-system memory.
2. Inference service on a dedicated host with bounded client buffers and request admission.
3. Inference in a fixed-memory virtual machine whose failure cannot reclaim crawler memory.

A thread in the crawler address space is not a viable alternative. The cgroup memory controller is a resource-domain mechanism, not a way to make shared-address-space inference allocations harmless to the rest of that process. The kernel documentation distinguishes threaded controllers from domain resource accounting and defines memory-limit OOM behavior within the affected domain. ([docs.kernel.org](https://docs.kernel.org/admin-guide/cgroup-v2.html))

**Chosen mechanism and justification.** Use a separate local inference process, its own memory-control domain, bounded IPC buffers, and explicit host admission. The host must reserve crawler, storage, coordination, and OS capacity before enabling model execution. The inference domain may be killed or restarted without entering the crawler domain.

The model-class targets remain targets. A separately configured inference containment limit protects other domains; it is not a redefinition of the §2 RSS targets.

**Flip condition.** Move inference to a dedicated host if host admission cannot prove isolation, if model-load plus inference pressure repeatedly consumes more than 80% of its reserved domain, or if two simultaneous model versions cannot coexist without reducing required crawler admission.

**Failure and containment.**

- **Detection:** inference memory events, process exit, or failed allocation within the batch deadline.
- **Scope:** inference process and its in-flight batches.
- **Response:** fence replies and execute retry/bypass completion.
- **Recovery:** restart and reload; repeated failures use `slm_oom` or `model_missing`.
- **Learning:** record model digest, peak resident memory, containment events, and affected batch IDs.

### Decision 2 — Back-pressure × re-bootstrap joint deadlock

**Floor.** A full work queue must not prevent session retirement/replacement, and a live rotating session must never be handed across threads as a frozen cookie snapshot or a moved Page.

**Problem statement.** A producer blocked on downstream capacity can hold the only thread capable of applying rotating cookies or refreshing clearance. If replacement itself needs the same bounded queue or exhausted worker pool, neither side can progress.

**Floor-compliant alternatives**

1. Independent control execution with reserved response-materialization credits and generation-fenced session replacement.
2. Immediate session retirement whenever downstream capacity disappears, followed by cold reconstruction after capacity returns.
3. Separate session-keeper execution that continues only verified non-mutating keepalive operations while data producers pause.

Alternative 3 is viable only where a safe keepalive and idle-lifetime contract are actually known; they are not supplied for the initial targets.

**Chosen mechanism and justification.** Use a **reserved control lane plus credit-before-wire admission**:

1. Before a request, reserve enough durable capacity for its maximum admitted response packet and generated references.
2. No admitted response has to wait for new queue capacity merely to become durable.
3. Data admission pauses at capacity; already reserved responses finish.
4. A control lane has independent command capacity, CPU admission, and cold-bootstrap memory admission.
5. Bootstrap never claims a listing/work/detail lease.
6. A known deadline triggers replacement through that lane even while data queues are full.
7. The old owner drains its single in-flight request, applies cookie changes, commits its cursor boundary, and is fenced.
8. The replacement publishes a `Send` live-client handle plus session epoch. No Page or solver crosses threads.
9. If saturation persists beyond `queue_saturation_grace_ms`, the shard may deliberately become quiescent. It is safer to retire than to keep refreshing an unusable session indefinitely.
10. New admission resumes below the low-water mark and establishes a new generation if needed.

Because `SharedSession` is process-wide in the supplied engine, independent session domains use separate engine processes unless explicit engine-level namespacing is verified. A `per_crawl_run` session may have several OS workers inside its single session domain; independent rotating shards do not share that process-global cookie store.

**Flip condition.** Prefer immediate retirement over proactive replacement when more than 50% of replacements occur during pauses longer than the useful remaining session lifetime. Adopt a keeper only after a safe keepalive is verified and its request cost is lower than observed cold-recovery cost.

**Failure and containment.**

- **Detection:** reserved control admission unavailable before replacement deadline, or a response exceeds its declared reservation.
- **Scope:** affected shard/partition only.
- **Response:** stop new data dispatch; retire the session; reject oversized response acceptance.
- **Recovery:** drain persisted work and cold-restart the incomplete walk.
- **Learning:** queue occupancy, deadline slack, reserved/actual bytes, generation handoff timing, and avoided/actual expiry.

### Decision 3 — State-machine enforcement

**Floor.** Invalid transitions, stale lease completions, and unaudited state changes cannot commit.

**Problem statement.** Pure application conventions are easy to bypass; storage-specific procedures reduce portability; event-only models can make current-state claims expensive.

**Floor-compliant alternatives**

1. A single typed transition gateway backed by atomic conditional storage operations and declarative constraints.
2. Storage-resident transition procedures with equivalent guards and audit creation.
3. Append-only state events with a transactionally maintained claimable projection.

**Chosen mechanism and justification.** Use a typed transition gateway with versioned transition specifications and storage-enforced atomic predicates. Only the gateway’s persistence identity may modify operational state. The storage layer enforces lease-token equality, row revision, payload exclusivity, and key constraints.

This keeps the schema portable while making correctness independent of caller discipline.

**Flip condition.** Move more enforcement into storage-resident procedures if independent trusted writers exceed three implementations or conformance tests find any state mutation bypassing the gateway. Move toward event projections only if replay/query requirements outweigh the extra projection-lag complexity.

**Failure and containment.**

- **Detection:** rejected guard, unknown state, stale revision, or unauthorized write at commit.
- **Scope:** one transaction.
- **Response:** reject all effects.
- **Recovery:** reread current state and retry only if the intended transition remains valid.
- **Learning:** rejected transition, expected/actual revision, lease and owner epoch, caller identity.

### Decision 4 — SLM shadow-mode support

**Floor.** Raw verdict, applied verdict, and the declaration revision used by a transition must be recoverable independently.

**Problem statement.** Changing a shadow setting while batches are in flight can produce irreproducible routing. Encoding evaluation thresholds in the data plane would duplicate Phase 2 policy.

**Floor-compliant alternatives**

1. Immutable per-run shadow declarations.
2. Versioned effective shadow updates applied at claim boundaries.
3. Separate immutable application-decision records layered over cached genuine classifier results.

**Chosen mechanism and justification.** Use versioned effective updates at claim boundaries. The data plane supports `off`, `on`, and externally resolved `dynamic_auto`; it does not calculate activation thresholds.

Initial snippet surfaces use `on`. A claimed batch records its effective revision. Later updates affect only later claims. Genuine result reuse may receive a new applied-verdict revision with audit history.

**Flip condition.** Restrict to immutable per-run declarations if effective-update propagation exceeds 5 s or revision ambiguity appears in any accepted transition. Introduce a separate application-history projection only if audit-backed queries cannot meet the required provenance query latency.

**Failure and containment.**

- **Detection:** missing, stale, or conflicting effective revision at claim.
- **Scope:** target’s snippet claims.
- **Response:** retain the last valid effective revision; absent any valid revision, use shadow `on`.
- **Recovery:** apply a newer valid revision at a later claim boundary.
- **Learning:** rejected revision and the exact effective mode used.

### Decision 5 — Queue persistence and durability

**Floor.** Entity materialization is durable; queue capacity is bounded; process-crash recovery occurs within lease TTL without losing acknowledged work.

**Problem statement.** A separate broker can improve dispatch but introduces entity/broker atomicity and duplicate-delivery problems. A table-only queue can concentrate writes and require careful indexing.

**Floor-compliant alternatives**

1. Transactional entity tables with indexed queue views and optional non-authoritative wakeups.
2. Durable broker references emitted only after entity materialization, with an entity-backed outbox and reconciliation.
3. Transactional embedded journals maintaining entity projections and queue indices in the same commit.

**Chosen mechanism and justification.** Use transactional entity tables as the authoritative queue, with indexed pending-state scans and optional wakeups. A page transaction includes generated rows, observation records, cursor movement, and audit effects.

Durable acknowledgment requires a durable journal commit. Microbatching may combine independent small transactions for at most 1 ms; it must not extend a transaction across network or inference execution.

The durability boundary assumes functioning durable storage under A9. Write-ahead logging alone does not eliminate the need to configure durable synchronization and checkpoint behavior correctly. ([sqlite.org](https://sqlite.org/wal.html))

Capacity is enforced by both:

- `queue_max_capacity` per queue view.
- `queue_max_bytes` plus reserved response staging capacity.

Notifications are disposable.

**Flip condition.** Add a durable reference broker if indexed claim discovery consumes over 25% of the orchestration budget for 30 minutes at the validated storage capacity. The entity-first materialization Floor remains unchanged.

**Failure and containment.**

- **Detection:** storage commit failure, lost notification, or orphaned owner.
- **Scope:** affected target transactions.
- **Response:** no acknowledgment or cursor advance without commit.
- **Recovery:** journal recovery, entity rescan, owner fencing, and lease reclamation within A4.
- **Learning:** recovery duration, replay count, lost-wakeup reconciliation count, and uncommitted transaction IDs.

### Decision 6 — SLM batch sizing [PROVISIONAL]

**Floor.** Batch collection cannot violate lease deadlines, inference deadlines, complete-input handling, or crawler isolation.

**Problem statement.** Fixed 25-item batches waste latency at low arrival rates and can exceed memory/latency envelopes when descriptions are long. Aggressive adaptation can make latency unpredictable.

**Floor-compliant alternatives**

1. Fixed-size immediate batches, with smaller batches when fewer rows exist.
2. Deadline-bounded collection with item and token ceilings.
3. Arrival/service-rate adaptation with a strict maximum dwell time and token budget.

**Chosen mechanism and justification.** Use deadline-bounded collection with:

- Maximum 25 items.
- Maximum 20 ms collection dwell.
- Model-manifest token budget.
- Immediate dispatch when either ceiling is reached.
- Reduction of the item ceiling when measured p95 inference exceeds 1,000 ms.
- Gradual return toward 25 when p95 is below 150 ms and queued work supports it.

No adaptation truncates input or extends the 2,000 ms inference timeout.

The decision is provisional because the requested 100–200 ms CPU envelope and complete long-description processing have not been jointly benchmarked.

**Flip condition.** Use a fixed validated batch profile if adaptation oscillates by more than 2× over five consecutive windows. Move inference hardware/domain if full-input p95 remains above 1,000 ms at batch size one.

**Failure and containment.**

- **Detection:** timeout, token admission failure, or memory event.
- **Scope:** current batch/model process.
- **Response:** release/fence affected rows; reduce future admission, not input fidelity.
- **Recovery:** retry under a smaller valid batch or execute declared bypass.
- **Learning:** token counts, batch cardinality, dwell, latency distribution, memory peak, and timeout rate.

### Decision 7 — Coverage strictness and partition failure

**Floor.** A single partition shortfall never aborts the entire crawl, and incomplete evidence never becomes a positive coverage proof.

**Problem statement.** Failing the whole run maximizes visible strictness but wastes valid partitions. Silently accepting shortfalls hides systematic losses, especially OR’s missing newest jobs.

**Floor-compliant alternatives**

1. Immediately quarantine each failing partition while continuing siblings.
2. Perform bounded split/reconciliation attempts, then mark only the unresolved leaves incomplete.
3. Produce separate verified and unverified output cohorts while preserving partition-level proof status.

**Chosen mechanism and justification.** Use bounded split/reconciliation followed by explicit incomplete leaves. The ledger retains the entire split tree, proof cohort, and failure reason. Verified outputs remain available, but no whole-run completeness claim can ignore incomplete descendants.

**Flip condition.** Prefer direct fine-grained planning over reactive splitting when more than 25% of initial partitions require two or more split rounds. Prefer immediate quarantine when the failure is a missing capability rather than a potentially recoverable shortfall.

**Failure and containment.**

- **Detection:** detector trigger, proof mismatch, or third saturated round.
- **Scope:** affected leaf and ancestor completion status.
- **Response:** stop that leaf’s invalid completion path.
- **Recovery:** continue siblings; later replay only unresolved work.
- **Learning:** split effectiveness, proof deficits, uncovered predicates, and per-leaf cost.

### Decision 8 — Write-path separation

**Floor.** Crawler writes never block on downstream-agent writes or large downstream payload serialization.

**Problem statement.** Separate tables in one serialized writer do not satisfy the Floor. For example, SQLite’s WAL permits reader/writer concurrency but still has a single writer; using it for two tables alone would not isolate crawler writes from agent writes. ([sqlite.org](https://www.sqlite.org/isolation.html))

**Floor-compliant alternatives**

1. Separate owner-specific persistence files/services with independently reserved I/O and asynchronous publication of immutable snapshots.
2. Separate remote persistence domains with non-blocking versioned read composition.
3. Owner-specific append journals with independently materialized projections and deterministic field ownership.

**Chosen mechanism and justification.** Use separate owner-specific persistence domains and immutable snapshot publication:

- Crawler transactions write only the ingest domain.
- Agent transactions write only the downstream domain.
- Large downstream artifacts are fully persisted before publication.
- Asynchronous exchange publishes a locally durable, immutable snapshot with a revision.
- The effective logical detail row is the crawler revision plus its latest published downstream revision.
- Snapshot import has its own reserved I/O service and bounded buffers; it cannot hold the ingest writer.
- Publication is a bounded metadata operation, not large JSON serialization under an ingest lock.
- A full-row archive is a complete logical JSON value assembled from the old crawler snapshot and the already durable published downstream snapshot. Its physical representation may use immutable extents, but reading `payload_json` must yield the entire archived row.
- Referenced immutable extents cannot be reclaimed while an audit archive depends on them.

Agent durability acknowledgment and publication into the effective detail view are distinct. Global synchronous linearizability across owners is deliberately not promised.

**Flip condition.** Move an owner to a remote domain if independent I/O reservations cannot be demonstrated. Change the snapshot-exchange implementation if publication lag exceeds 5 s under A7 for 30 minutes or archive serialization enters the crawler critical path.

**Failure and containment.**

- **Detection:** exchange lag, unavailable downstream domain, or incomplete snapshot checksum.
- **Scope:** downstream-field freshness, not crawler ingest.
- **Response:** retain the last complete published revision; reject partial publication.
- **Recovery:** resume asynchronous transfer and publish a complete newer revision.
- **Learning:** revision lag, bytes outstanding, checksum failures, and archived version vectors.

### Decision 9 — Adapter division of labor

**Floor.** Adapters cannot override core state, lease, thread, proof, or mutation boundaries.

**Problem statement.** Declaration-only adapters cannot express all target pagination behavior; implementation-heavy adapters duplicate fragile invariants.

**Floor-compliant alternatives**

1. Declarative templates with narrowly typed exceptional callbacks.
2. Custom implementations for all four extensions behind strict conformance tests.
3. Per-extension selection of declaration depth with common validated result types.

**Chosen mechanism and justification.** Choose per-extension depth:

- Partition Planning: declaration-first facet/range descriptions; custom planning only for verified target-specific partition logic.
- Pagination Loop: target implementation where stateful postback/continuation behavior diverges; all commits remain core-owned.
- Endpoint Transport Choice: declaration-only unless a response-evidence-driven choice is necessary; no arbitrary engine ownership.
- Write-Action Handler: fixed non-executing Phase 1 stub.

Custom code returns typed plans, requests, parsed evidence, or capability errors. It does not directly write entity tables.

**Flip condition.** Promote a custom path into a shared declarative primitive after three adapters use materially identical semantics. Require a custom extension when a declarative workaround would hide session order or proof evidence.

**Failure and containment.**

- **Detection:** invalid extension result at validation boundary.
- **Scope:** current target/partition.
- **Response:** reject the result before wire dispatch or commit.
- **Recovery:** use a valid declared path or mark the capability incomplete.
- **Learning:** adapter version, violated contract, input fixture hash, and rejected output.

### Decision 10 — SLM loading lifecycle

**Floor.** Model loading is decoupled from crawler isolation and cannot leave claimed rows waiting indefinitely for an unavailable model.

**Problem statement.** Eager loading consumes memory for unused stages; lazy loading can make the first leased batch exceed its deadline.

**Floor-compliant alternatives**

1. Eager loading of models required by the admitted target surfaces before classifier claims.
2. Lazy initialization before any row claim, with explicit readiness gating.
3. A shared model service with version-pinned readiness and bounded residency.

**Chosen mechanism and justification.** Eagerly load only the model versions required by admitted active classification stages. Loading occurs in the inference domain before classifier claims, with artifact verification and a bounded readiness deadline.

Crawler extraction may proceed only while bounded downstream admission remains available. It must not create an unbounded backlog waiting for model readiness.

**Flip condition.** Switch to pre-claim lazy loading when more than 75% of admitted model versions remain unused across ten representative runs. Use a shared service when duplicate resident weights dominate host memory and isolation remains provable.

**Failure and containment.**

- **Detection:** missing artifact, digest mismatch, load timeout, or allocation failure before readiness.
- **Scope:** affected model version/stages.
- **Response:** do not claim inference work; expose `model_missing` or `slm_oom`.
- **Recovery:** valid artifact/restart, or explicit bypass completion for eligible rows.
- **Learning:** artifact identity, load stage, memory peak, deadline, and readiness transition.

## §13 Adapter Contract — Declaration and Extension Specification

### §13.A Declaration inventory

Every field below carries a condition. A condition applies to every field in its row. A missing required field, invalid enum, contradictory mapping, or unavailable required capability produces a declaration-validation audit record and an `INCOMPLETE` activation result.

Distributed sections define meaning; this inventory defines completeness.

#### Identity and seven axes

| Fields | Condition | Type/default/validation |
|---|---|---|
| `adapter_id`, `adapter_version`, `target` | [always] | Versioned identity; target in MN/IL/WI/MI/OR |
| `phase_slots` | [always] | Exactly A and B |
| `bootstrap_requirement` | [always; per slot] | Axis 1 enum |
| `session_requirement` | [always; per slot] | Axis 2 enum |
| `truncation_model` | [always; Phase A] | Axis 3 enum |
| `ordering_model` | [always; Phase A] | Axis 4 enum |
| `state_mutation_surface` | [always; per target] | Axis 5 enum |
| `estimated_requests_per_partition`, `estimated_request_bytes`, `estimated_response_bytes` | [always; per slot] | Nonnegative estimates or explicit null/unmeasured |
| `phase_a_sufficient`, `phase_b_value` | [always] | Boolean; `high`, `low`, or `none`; enforce preamble contradictions |
| `classification_surface` | [always] | Exact four-value vocabulary |

Axis 6 has no Phase 1 declaration.

#### Transport, endpoints, solver, and navigation

| Fields | Condition | Type/default/validation |
|---|---|---|
| `bootstrap_mode`, `pagination_mode` | [always; per slot] | Mapping Floors in §3 |
| `endpoints` | [always; per slot] | Endpoint ID, URL pattern, method, representation, extraction binding, non-mutating operation capability |
| `endpoint_transport_overrides` | [if an override is declared] | Cannot override target ceiling or slot continuity Floors |
| `profile_ref` | [always; per slot] | Pinned StealthProfile identity |
| `response_schema_ref`, `render_readiness_predicates`, `session_lapse_predicates` | [always; per endpoint] | Versioned typed validators; empty lists permitted only where not applicable |
| `nav_timeout_ms` | [always; per target] | One positive target-wide value |
| `nav_max_iter` | [if a Page can execute] | Positive bounded iteration declaration |
| `bootstrap_timeout_ms` | [if bootstrap or replacement executes] | Positive; each navigation remains within `nav_timeout_ms` |
| `bootstrap_retry_limit` | [always] | Default 2; finite |
| `solver_names` | [always; per slot] | Registered operational names or empty list |
| `other_mechanism` | [always; per slot] | Null or `{type:harvest|headed_sidecar, description}` |
| `unsolvable_policy` | [always; per slot] | `retry`, `abort`, `escalate_to_human` |
| `max_response_bytes`, `io_buffer_bytes` | [always] | Deployment defaults: 64 MiB decoded response limit and 1 MiB streaming buffer; not target behavior claims |
| `max_rows_per_response` | [always; per endpoint] | Verified bound or conservative admission bound used for reservation |

#### Session and worker topology

| Fields | Condition | Type/default/validation |
|---|---|---|
| `shard_topology` | [always; per slot] | Four-value topology enum |
| `shard_count` | [if `per_shard`] | Positive; initial OR allocation 2 |
| `worker_count` | [always; per slot] | Positive admission setting; stateful per-session concurrency remains one |
| `max_inflight_per_session` | [always] | Must be 1 for rotating and session-stateful execution |
| `initial_bootstrap_cost_class` | [always; per slot] | Derived mapping, not freely chosen |
| `session_absolute_lifetime_seconds` | [always] | Positive verified value or null; initially null for all slots |
| `session_rebootstrap_buffer_seconds` | [if absolute lifetime is non-null] | Must cover drain/bootstrap/publication/clock bounds |
| `session_idle_timeout_seconds` | [always] | Verified value or null; initially null |
| `keepalive_request` | [if a verified non-mutating keepalive exists] | Otherwise absent; initial targets declare none |
| `handoff_max_age_seconds` | [if headed handoff] | Deployment validity bound; default 300 s; not an asserted server lifetime |
| `engine_session_domain` | [if decision 2] | Identifies isolated process/session-sharing domain |
| `control_reserve_slots` | [if decision 2] | At least one admitted control execution slot per active target |
| `queue_saturation_grace_ms` | [if decision 2] | Default 5,000 ms before deliberate quiescence is considered |
| `queue_resume_low_watermark` | [if decision 2] | Default 0.8 of both row and byte capacity |
| `worker_loss_detection_ms`, `process_restart_bound_ms` | [always] | Reference 3,000 and 10,000; lease validation uses actual deployment bounds |

#### Warmth and pools

| Fields | Condition | Type/default/validation |
|---|---|---|
| `warm_pool_size` | [always; per slot] | Initially 0; positive only for Page pagination |
| `preconnect` | [always; per slot] | Initially true for all ten HTTP pagination slots |
| `preconnect_origins` | [if preconnect] | Derived from declared acquisition endpoints |
| `max_connections_per_slot` | [always] | Bounded deployment value; stateful request gate remains independent of HTTP/2 capability |
| `connection_idle_timeout_seconds` | [always] | Client pool-retention setting; not server validity |
| `page_pool_reset_timeout_ms` | [if `warm_pool_size>0`] | Default 500 ms; failure destroys the Page |

#### Coverage, detectors, and partition planning

| Fields | Condition | Type/default/validation |
|---|---|---|
| `partition_keys`, `primary_partition_key`, `date_partition_keys`, `secondary_partition_keys` | [always] | Verified predicates; explicit empty/null where unavailable |
| `partition_domain_extractor_ref` | [if target publishes facets/domain values] | Versioned extraction binding |
| `bisection_round_limit` | [always] | 3 under this contract |
| `reported_total_source` | [always] | `facet_count`, `header_count`, `payload_field`, `payload_field_union`, or `unreported` |
| `reported_total_extractor_ref` | [if source is not `unreported`] | Must be verified before positive proof |
| `reported_total_unit` | [always] | `postings` |
| `header_label_is_floor` | [always] | Boolean |
| `session_min_count` | [if `payload_field_union`] | Initial MI allocation 2 |
| `row_cap` | [always] | Positive verified cap or null |
| `page_size` | [always] | Verified value or response-derived declaration |
| `saturation_marker_patterns` | [always] | Pattern list; may be empty |
| `tail_repeat_threshold`, `noop_probe_count` | [always] | Default 2 each; probes cannot violate cursor restrictions |
| `ascending_overflow_banner_patterns` | [if ascending-overflow ordering] | Verified patterns or empty; cap/date checks still apply |
| `posted_date_extractor_ref` | [if posted-date evidence is available] | Used for `max_date_posted` |
| `coverage_capability_status` | [always] | Verified or unverified; unverified cannot produce positive proof |

#### Ordering, deduplication, and hash declarations

| Fields | Condition | Type/default/validation |
|---|---|---|
| `cursor_kind`, `cursor_capability_status` | [always] | Verified offset, continuation, keyset, or exhaustive single-response capability |
| `coverage_scope` | [always] | `per_run` or session-union scope |
| `baseline_dup_rate` | [always] | Prior calibrated value or explicit initialization 0.0 |
| `over_fetch_factors` | [always] | Low/medium/high values; initial 1.1/1.5/2.0 where relevant |
| `reconciliation_pass_limit` | [always] | Default 3 |
| `dedupe_location` | [always] | `phase_a`, `phase_b`, or `storage`; initial allocation `phase_a` |
| `upsert_reset_policy` | [always] | `preserve-policy` initially; `reset-policy` explicit |
| `fetch_key_excluded_headers` | [always] | Additional exclusions; default empty |
| `fetch_key_representation_headers` | [always] | Declared representation-determining headers |
| `page_hash_volatile_selectors` | [always] | Explicit selector list; default empty, never guessed |
| `replay_capture_mode` | [always] | `failures` initially or `all`; complete captured fixtures are immutable |

#### SLM declarations

| Fields | Condition | Type/default/validation |
|---|---|---|
| `snippet_shadow_mode` | [always] | `on` for initial snippet surfaces; `off` otherwise |
| `slm_bypass_on_failure` | [always] | Initially false |
| `model_version`, `model_artifact_ref`, `model_artifact_digest`, `tokenizer_digest`, `prompt_digest` | [if surface is not `none`; per active classifier stage] | Pinned deployment manifest |
| `model_parameters`, `quantization`, `max_input_tokens`, `batch_token_budget` | [if SLM active] | Must fit §6 envelope and manifest |
| `slm_batch_size` | [if SLM active] | Maximum 25 initially |
| `inference_timeout_ms` | [if SLM active] | Default 2,000 |
| `batch_flush_ms` | [if decision 6] | Default 20 |
| `classifier_result_ttl` | [always] | Null by default; duration only when eviction requested |
| `model_load_timeout_ms` | [if decision 10] | Default 30,000 |
| `slm_isolation_reservation_mb` | [if decision 1] | Deployment resource admission, distinct from RSS target |
| `effective_shadow_revision` | [if `dynamic_auto`] | Versioned Phase 2 input, not a locally computed threshold |

#### Queue, lease, and retry declarations

| Fields | Condition | Type/default/validation |
|---|---|---|
| `lease_ttl` | [always; per entity type] | Default 300 s |
| `lease_ttl_overrides` | [always] | Explicit map; empty by default |
| `max_retries`, `max_retries_overrides` | [always] | Default 3 and empty override map |
| `sweeper_interval_ms` | [always] | Default 1,000 |
| `queue_max_capacity` | [always; per queue view] | Default 10,000 eligible rows; deployment may change |
| `queue_max_bytes` | [always; per queue view] | Explicit bounded value sized from actual payloads |
| `staging_disk_budget_bytes` | [always; per target] | Covers reserved response packets and recovery evidence |
| `transaction_microbatch_max_ms` | [if decision 5] | At most 1 ms initially |
| `projection_lag_target_ms` | [if decision 8] | 5,000 ms reference target |
| `projection_publish_max_bytes` | [if decision 8] | Bounded metadata publication; default 4 KiB, excluding already durable immutable payload extents |

#### Memory, content, failures, and telemetry

| Fields | Condition | Type/default/validation |
|---|---|---|
| `memory_targets` | [always] | Role-indexed allocation records |
| `memory_target_overshoot_max_pct` | [always; per allocation] | Default 25 |
| `memory_target_overshoot_mb` | [always; per allocation] | Integer; 0 if no overshoot |
| `memory_target_overshoot_justification` | [if overshoot > 0] | Names concrete labor reduction or throughput gain |
| `detail_content_fields` | [always] | Strict seven-type vocabulary; required/nullable/extraction bindings |
| `failure_reason_extensions` | [always] | Explicit strings; no undeclared persisted reason |
| `signals_sink_degradation_threshold_ms` | [always] | Default 100 |
| `telemetry_buffer_records` | [always] | Bounded; reference 1,024 per target emitter |
| `diagnostic_buffer_bytes` | [always] | Bounded; reference 4 MiB per crawler worker |

The common declared extension set includes:

`solver_unavailable`, `solver_unsolvable`, `warm_reset_failed`, `storage_unavailable`, `coverage_evidence_missing`, `cursor_capability_unverified`, `ordering_drift`, `response_limit_exceeded`, `invalid_configuration`.

No declaration or schema slot named `crawl_allotment` is reserved.

### Initial target allocations

| Target | Classification surface | `phase_a_sufficient` | `phase_b_value` | `nav_timeout_ms` | Initial snippet shadow |
|---|---|---:|---|---:|---|
| MN | `phase_a_snippet_phase_b_description` | false | high | 30,000 | on |
| IL | `phase_a_full_description` | true | low | 30,000 | off |
| WI | `phase_b_description_only` | false | high | 45,000 | off |
| MI | `phase_a_snippet_phase_b_description` | false | high | 60,000 | on |
| OR | `phase_b_description_only` | false | high | 90,000 | off |

IL’s `phase_b_value='low'` avoids the preamble’s prohibited `phase_a_sufficient=true / phase_b_value='none'` combination. Its selected surface still performs no Phase B work.

Snippet inputs may contain an empty snippet when the listing supplies only title/employer. This is not an assertion that MN or MI exposes any unprovided text field.

### §13.B Four extension boundaries

| Extension | Abstract interface | Minimum declarations | Permitted implementation depth | Forbidden responsibilities |
|---|---|---|---|---|
| Partition Planning | `plan(partition, count_evidence) → child predicates + coverage relation + evidence` | Axis 3/4, partition keys, domain extractor, count source, split limit | Declarative facets/ranges; custom verified plan logic | No arbitrary endpoint probing, invented predicates, or coverage override |
| Pagination Loop | `advance(previous response, cursor, session epoch) → next request or termination evidence` | Cursor kind, ordering model, scope, request schema, page/cap detectors | Template for deterministic requests; custom response-state logic | No direct cursor commit, no offset use outside Floor, no session-generation substitution |
| Endpoint Transport Choice | `choose(endpoint, acquisition evidence) → declared transport action` | Transport modes, overrides, solver/other mechanism, profile, ceiling | Declaration-first; typed evidence-driven callback if necessary | No new transport vocabulary, no moving Page, no timeout extension |
| Write-Action Handler | `handle(action request) → non-executing unsupported result` | Axis 5 and declared action names | Phase 1 fixed stub | No external mutation, no self-referral, no `state_mutation_record` insertion |

Each extension returns owned data and typed evidence. Core persistence performs the actual transitions.

### §13.C Reused primitives

Adapters inherit, without reimplementation:

- Target-wide navigation deadline propagation.
- Profile-consistent request construction.
- Hybrid render classification and acquisition history.
- Cold Page ownership and solver lifecycle.
- Session fencing and rotating-cookie serialization.
- Preconnect and PagePool lifecycle contracts.
- Canonical input, page, observation-set, and fetch-key hashing.
- Exact `seen_ids` lookup.
- Entity-first queue materialization.
- Lease claim, completion, early-release, expiry, and retry accounting.
- Classifier result reuse and bypass auditing.
- Coverage equations and detector event recording.
- Full-row archival on fetch-key replacement.
- Structured diagnostics and offline replay from retained evidence.
- Non-mutating extension validation.

### §13.D Worked Oregon trace

This trace specifies data-plane behavior on admitted execution or retained test fixtures. It does not grant live access. The supplied reconnaissance identifies a strict prohibition; admission remains within D1’s Phase 2 scope.

#### Axis allocation

| Axis | Oregon allocation |
|---|---|
| 1 | Headless challenge clear in A and B |
| 2 | Stateful-rotating in A and B |
| 3 | No-op pagination parameter interacting with a hard 1,000-row cap |
| 4 | Ascending-by-ID with overflow |
| 5 | Mixed / writes-on-apply capability exists externally; Phase 1 uses only non-mutating acquisition |
| 7 | Phase A insufficient; Phase B high value; approximately 244 KB challenge evidence is supplied, other byte estimates remain unmeasured |
| 8 | `phase_b_description_only` |

Axis 6 is not declared here.

#### End-to-end execution

1. **Validate declarations.**  
   The adapter declares `Page` bootstrap, `HttpClient` pagination, `per_shard`, two shards per slot, no warm isolates, and preconnect enabled. The placeholder solver currently blocks operational activation.

2. **Plan partitions.**  
   The planner uses verified `loc` code sets from the supplied 54-code domain. It may split code lists but cannot invent a date or ID-range filter. A leaf still exceeding the cap after valid splits is incomplete.

3. **Establish an A session.**  
   A cold Page executes the conforming solver once available. The client used during clearance becomes the live pagination client. Every response applies the new `OClmoOot` value before the next request. No static snapshot is handed to a different live client.

4. **Complete bootstrap and preconnect.**  
   Successful clearance and HTTP verification publish the new session generation. Preconnect fires for declared acquisition origins.

5. **Acquire a leaf.**  
   The worker does not loop through `start=1001`. It records the accepted ID set, cap evidence, page hash, and posted-date bounds. Because an independent OR total/floor source is not supplied, the ledger does not claim a positive proof merely because fewer than 1,000 rows were returned.

6. **Perform duplicate-aware Extract.**  
   `seen_ids` hits are counted in observation evidence but do not create new listing work. A new posting becomes a listing in `pending_enrich`.

7. **Delegate enrichment.**  
   The dispatcher creates a `work_item` in `pending` and changes the listing to `enqueued` in the same transaction.

8. **Establish/use a B session.**  
   OR-B has its own live rotating session generation. It is not initialized by replaying OR-A’s frozen jar.

9. **Fetch detail.**  
   The fetcher issues only the declared detail acquisition. It extracts available structured compensation and requirements. Hidden employer-contact data is nullable unless a non-mutating source actually provides it.

10. **Do not reveal contact through self-referral.**  
    The “Obtain Contact Information” action and `self-refer-step1-validate.cfm` POST are outside the extraction capability. The `usemyssn=No` checkbox does not make that POST read-only. The write-action stub returns a non-executing result. `state_mutation_record` remains empty.

11. **Materialize detail.**  
    A valid render and required content produce `pending_classification`. The fetch key uses token `'B'`; rotating cookies are excluded, so cookie rotation does not create new detail identities.

12. **Classify.**  
    Genuine description PASS produces `ready` and `SHORTLISTED`; genuine VETO produces `vetoed` and an unclaimed `DISCOVERED` candidate. Both successful terminal detail states update `seen_ids`. A configured bypass produces ready/`DISCOVERED` with no classifier-result row.

13. **Handle duplicate writes.**  
    Same fetch key is a no-op. A different key archives the entire prior published detail row before replacement.

14. **Handle saturation or expiration.**  
    Decision 2 allows durable response completion, independent control execution, and deliberate quiescence. A new generation restarts only incomplete acquisition work; proven partitions are not re-fetched.

### Source-of-truth resolution

- §§2–10 own semantic behavior.
- §11 owns entities and states.
- §12 owns chosen mechanisms.
- §13.A owns declaration inventory completeness.
- An adapter cannot resolve a contradiction by changing one of these meanings locally.

## §14 Future Control Plane Requirements

| Commitment | Phase 1 guarantee | Phase 2 obligation/boundary |
|---|---|---|
| 1. Non-blocking concurrent agent writes | Owner-separated writes and explicit published revision vectors | Accept asynchronous publication; do not demand a distributed synchronous transaction on crawler commits |
| 2. Complete classifier provenance | Model version/digests, confidence, reason, input hash, genuine/applied verdict, application revision | Interpret quality and decide promotion/policy |
| 3. Orthogonal lease claiming | Claims preserve pipeline state; completion is fenced | Use the generic primitive rather than inventing “in-progress” pipeline states |
| 4. Extensible state schema | Versioned transition vocabulary and unknown-value rejection | Add states only through compatible contract versioning; do not repurpose existing values |
| 5. Transactional audit | Every state change and full-row replacement archive commits with its effect | Preserve audit immutability and ownership |
| 6. Multi-stage render reporting | HTTP, from-HTML, cold navigation, and verification history retained | Do not collapse render and content verdicts |
| 7. Shard-isolated sessions | Scoped encrypted snapshots, owner epochs, live-session continuity | Do not redistribute rotating snapshots as reusable sessions |
| 8. Unblocked crawler path | No agent lock, acknowledgment, or payload serialization on ingest critical path | Preserve persistence and resource-domain separation |
| 9. Structured triage and quality-of-life support | Queryable dead letters, audit, coverage, cursor, and session state; self-healing retries; retained failure fixtures; deterministic offline replay; supported warmth | Define human triage workflows and dashboards without requiring raw-log reconstruction |
| 10. Decoupled SLM lifecycle | Model readiness, failure, and replacement are independent of crawler processes | Manage model selection and lifecycle without embedding inference in crawler workers |

Minimum triage query capabilities:

- Pending rows whose leases expired or whose owners disappeared.
- Dead letters grouped by target, stage, reason, and last failure time.
- Partitions with false coverage proof and their exact blocking evidence.
- Session generations in handoff wait, failure, or missed replacement.
- Bypassed rows and the genuine-verdict history used for semantic state.
- Rejected stale commits and their owner epochs.
- Fetch-key replacements with the complete archived prior row.
- Replayable failure evidence by adapter, engine, profile, and model version.

These are logical query contracts, not a choice of API, CLI, dashboard, or integration protocol.

## §15 Architectural Risks & Open Questions

### 15.1 Architectural risk register

| Risk | Detection | Scope | Response | Recovery/triage path | Learning |
|---|---|---|---|---|---|
| Session lifetime is shorter than declared | Rejection before calculated ceiling; repeated lapse timing | Affected slot/shards | Stop trusting the ceiling; use reactive retirement and conservative replacement | Re-establish verified lifetime evidence; retain null where unknown | Observed lifetime distribution and bootstrap cost |
| Ordering stability collapses | High drift, permutation evidence, incompatible page hashes | Current partition and cursor capability | Invalidate proof cohort; no silent axis rewrite | Verify a permitted cursor or leave partition incomplete | Ordering evidence and failed declaration version |
| SLM precision shifts | Phase 2 evaluation references disagree with accumulated genuine/applied outcomes | Affected model/stage/target | Preserve provenance and support shadow revision changes | Phase 2 determines model/policy action; data plane continues deterministic routing | Model/input hashes, verdict distributions, bypass and shadow history |
| Hardware assumptions drift | RSS, durable-commit, or inference latency exceeds reference envelopes | Host resource domains | Reduce admission/retention without dropping acknowledged work | Recalibrate deployment declarations and isolation proof | Measured versus assumed envelopes |
| Shared-session leakage | Cookie/profile generation appears in an unrelated shard | Session domains | Fence affected domains; invalidate their session-dependent cursors | Correct isolation binding; cold re-bootstrap | Domain IDs, cookie hashes, engine binding evidence |
| Fetch-key freshness limitation | Same request key returns changed content or repairs a prior failed render | Existing detail root | Honor no-op rule; do not hide a different key in metadata | Requires an explicitly versioned freshness/key contract if refresh is desired | Response hash difference, old/new render evidence, unchanged fetch key |
| Snapshot publication lag | Published agent revision trails durable agent revision | Downstream-field freshness | Continue crawler writes against last complete published snapshot | Resume exchange; investigate reserved I/O admission | Lag and payload-size distribution |

### 15.2 Cost risks

No empirical veto rates are supplied. Applied savings are particularly uncertain while snippets are shadowed.

| Target | Snippet veto projection | Description veto projection | Capacity-planning basis |
|---|---|---|---|
| MN | Unmeasured; initially not applied | Unmeasured | Assume no filtering benefit |
| IL | Not applicable | Unmeasured | All extracted full descriptions classified/finalized |
| WI | Not applicable | Unmeasured | All eligible listings require detail acquisition |
| MI | Unmeasured; initially not applied | Unmeasured | Assume no filtering benefit |
| OR | Not applicable | Unmeasured | All eligible listings require detail acquisition if execution is admitted |

[INCOMPLETE: §15.veto-projections — no relevance evaluation data is supplied, so per-target veto-rate classes cannot be responsibly projected; all classes remain unmeasured and capacity planning assumes zero applied filtering benefit.]

Other cost risks:

- **Byte-transfer bloat:** detect bytes per accepted row and bootstrap-to-pagination byte ratio at each commit; scope the affected endpoint; preserve fidelity, stop redundant/no-op walks, and record response-size distributions.
- **Network variance:** detect per-slot median/p95 network time over active windows; scope the slot; recompute the relative overhead budget from actual measurements; retain absolute latency alongside ratios.
- **Repeated bootstrap:** detect bootstrap count per successful request; scope the shard; apply the decision 2 flip criteria rather than repeatedly refreshing a saturated pipeline.
- **Large audit archives:** detect immutable-byte retention growth; scope the owning persistence domain; keep bounded buffers and durable archive semantics; retention decisions remain outside Phase 1.

### 15.3 Open questions requiring evidence

| Question | Required evidence | Contract until resolved |
|---|---|---|
| What ingest write rate satisfies the overhead Floor on deployment hardware? | Durable-commit and claim benchmarks with actual payload/index sizes | A2 remains an assumption; acceptance is not claimed from reference numbers |
| Should inference remain co-located? | Model memory/latency under simultaneous crawler load and verified containment | Decision 1’s isolated local deployment is conditional on resource admission |
| Can MN/WI/MI expose genuinely permitted continuations? | Captured request/response semantics, not renamed page offsets | §8 activation blockers remain |
| What exact MI aggregate and OR total/floor evidence is available? | Independent count extraction fixtures and units | No positive proof from guessed totals |
| Is the OR solver operational? | Cold clearance, live cookie rotation, deadline, and restart tests | Placeholder remains unavailable |
| Can future browser-paginated sessions survive long-lived pool reuse? | Reset, cookie affinity, DOM invalidation, and memory-retention tests | Warmth never substitutes for bootstrap validity |
| Should same-request content refresh be supported? | A separately approved versioned identity/freshness contract | Existing fetch-key no-op semantics remain immutable |
| Have engine memory envelopes changed? | Reproducible peak-RSS profiles for cold and retained Pages | Recalibrate targets explicitly; do not silently raise them |

## §16 Technical Integrity Self-Check

This is a structural contract audit, not a claim that deployment benchmarks or live target tests have already passed.

### 16.1 Verification checklist

| Check | Verification | Result |
|---|---|---|
| T01 | Scope and section ownership remain separated from Phase 2 policy/workflows | Pass |
| T02 | Memory objective, target character, and declared overshoot mechanism are explicit | Pass |
| T03 | SLM-to-crawler OOM propagation is prohibited and containment is specified | Pass, conditional on A1 deployment proof |
| T04 | Storage allocations map to decision 8 alternatives without multiplying budgets | Pass |
| T05 | Network-relative overhead and synchronous sink degradation are defined | Pass |
| T06 | Exactly ten semantic transport slots are allocated | Pass |
| T07 | Hybrid paths, no-network `from_html`, direct subresource escalation, and JSON handling are defined | Pass |
| T08 | Every required solver is operational rather than merely named | **Blocked: §4.OR-solver** |
| T09 | Four surface variants have stage counts 3/4/3/2 | Pass |
| T10 | Entity-first materialization and no shadow queues are required | Pass |
| T11 | Claims preserve operational state and all claimable tuples are declared | Pass |
| T12 | Raw/applied verdict, shadow, bypass, and genuine-verdict semantic precedence are explicit | Pass |
| T13 | SLM input/output, model provenance, deadlines, batch bounds, and envelopes are defined | Pass; performance unbenchmarked |
| T14 | All five truncation detectors include five-part failure behavior | Pass |
| T15 | Equality/floor/lower-bound formulas, count units, and zero-observation rule are explicit | Pass |
| T16 | Independent proof sources are established for all five targets | **Blocked: §7.proof-sources** |
| T17 | Three-round splitting, no-axis failure, and sibling continuation are defined | Pass |
| T18 | Initial non-deterministic target walks have certified non-offset cursors | **Blocked: §8.nonoffset-cursors** |
| T19 | Duplicate-rate formula, drift bands, over-fetch limits, and date corroboration are explicit | Pass |
| T20 | All dedupe locations, exact lookup, reset/preserve behavior, and successful-only seen IDs are defined | Pass |
| T21 | Ten shard allocations and zero session rows for topology none are defined | Pass |
| T22 | Page/solver thread confinement and permitted cross-thread data are explicit | Pass |
| T23 | Rotating-cookie serialization, shared-client semantics, and process-global store isolation are addressed | Pass |
| T24 | Lifetime replacement and bounded-queue deadlock have a joint mechanism | Pass |
| T25 | Warmth scopes, cold bootstrap, reset lifecycle, and ten warmth slots are defined | Pass |
| T26 | Exactly eleven logical entities have keys, foreign references, and indices | Pass |
| T27 | Detail Case A/Case B, strict content types, and four-field Finalize mapping are defined | Pass |
| T28 | Operational transitions and complete five-state semantic matrix are defined | Pass |
| T29 | Claim, expiry, early release, fencing, and cross-stage retry accounting are defined | Pass |
| T30 | Crawler/agent write ownership and complete archived logical rows are reconciled without agent blocking | Pass, conditional on A2 |
| T31 | Ten decisions include floors, alternatives, choice, flip conditions, and five-part failure containment | Pass |
| T32 | Declaration inventory includes conditions, overrides, memory fields, and no crawl-allotment slot | Pass |
| T33 | All four adapter extensions have typed boundaries and prohibited responsibilities | Pass |
| T34 | Oregon trace preserves rotating sessions and never executes self-referral | Pass |
| T35 | Quality-of-life capabilities and ten Phase 2 commitments are specified | Pass |
| T36 | Empirical per-target veto-rate class projections exist | **Blocked: §15.veto-projections** |

### 16.2 Mathematical and concurrency verification

The following invariants are explicit and testable:

- A claim does not change pipeline state.
- A lease release or expiry increments its entity retry counter at most once.
- A stale lease/session owner cannot commit.
- A cursor commit cannot outlive its materialized observation packet.
- A duplicated notification cannot create a duplicated entity effect.
- A `seen_ids` hit cannot suppress coverage evidence.
- A failed render cannot produce successful content fields.
- A bypass cannot produce a fabricated classifier result.
- A same-key content write cannot silently refresh a detail.
- A different-key replacement cannot commit without a complete old-row archive.
- An active rotating jar has one request owner and one cookie-application sequence.
- A Page remains on its allocating OS thread.
- Queue saturation cannot consume the independent control execution path.
- An unresolved partition cannot become proven because another partition succeeded.
- Render coverage never substitutes for pagination coverage.
- Zero observations never yield a positive pagination proof.
- Crawler writes do not wait for downstream ownership or payload serialization.

### 16.3 Self-check summary

**INCOMPLETE markers: 4**

1. §4.OR-solver — operational implementation of the placeholder solver.
2. §7.proof-sources — independent MI aggregate and OR total/floor evidence.
3. §8.nonoffset-cursors — compatible continuation capability for MN/WI/MI.
4. §15.veto-projections — missing empirical relevance evaluation.

**ASSUMED markers: 9**

A1 hardware/isolation; A2 storage service; A3 reference network time; A4 process recovery; A5 clocks; A6 entity sizes; A7 agent-write load; A8 inference benchmark input envelope; A9 durability fault model.

**DEFERRED markers: 3**

- D1: policy, admission, scheduling, integrations, agents/humans, dashboards, sequencing.
- D2: memory-overshoot adjudication and beyond-bound scope changes.
- D3: relevance/model policy and dynamic shadow thresholds.

**PROVISIONAL decisions: 1**

- Decision 6: CPU batching envelope pending complete-input performance evidence.

**Audit score: 32 of 36 structural checks passed; 4 activation/evidence checks blocked.**

This score does not certify live crawling readiness for all five targets. It explicitly prevents Phase 2 from treating unresolved target capabilities as completed implementation facts.

**Highest-risk areas**

1. Non-offset cursor Floor versus the supplied positional interfaces.
2. Oregon solver availability and independent completeness evidence.
3. Real CPU inference latency for long descriptions.
4. Session birth/lifetime uncertainty.
5. Same-request freshness limitations imposed by the prescribed fetch key.
6. Deployment proof that agent persistence and inference pressure cannot enter crawler critical paths.

## EXPORT DECLARATION

The following contracts are exported to Phase 2. Phase 2 may configure and govern them but may not silently weaken their Floors. Changes to a Floor require a versioned Phase 1 contract revision.

| # | Exported contract | Status | Exported value and provenance |
|---|---|---|---|
| 1 | Per-target classification surfaces | **complete** | MN and MI: `phase_a_snippet_phase_b_description`; IL: `phase_a_full_description`; WI and OR: `phase_b_description_only`. `none` remains fully specified. Provenance: §§5, 6, 13.A |
| 2 | Per-target veto-rate class projections | **incomplete** | All applicable rates are unmeasured; initial snippet shadowing applies no snippet veto savings. Capacity assumes zero filtering benefit. Provenance: §15.veto-projections |
| 3 | Storage outbox schema | **complete** | Eleven logical entities; posting roots, scoped partition/session keys, foreign references, indices, state matrices, leases, audit exclusivity, complete-row archives, and successful-only `seen_ids`. Provenance: §11; deployment separation conditions in decision 8 |
| 4 | Coverage baselines and detector mappings | **incomplete** | MN/IL equality and WI floor baselines are specified; MI union proof requires verified aggregate extraction; OR lacks independent total/floor evidence. All five detectors and proof equations are complete. Non-offset activation blockers remain. Provenance: §§7–8 |
| 5 | Transport constraints and hybrid acquisition | **complete** | Ten-slot matrix; all initial pagination uses `HttpClient`; MI-B and OR use cold Page bootstrap; WI-B uses external Handoff; exact hybrid and continuity rules. Solver availability is separately blocked for OR. Provenance: §§3–4 |
| 6 | Adapter declaration inventory | **complete** | Conditional, exhaustive inventory; four extension boundaries; memory overshoot fields; no Phase 1 crawl-allotment slot. Provenance: §13 |
| 7 | Session topology and lifecycle parameters | **assumed** | Ten-slot topology is specified; all initial absolute lifetimes are null; reactive detection and verified-lifetime replacement rules are complete. Deployment isolation/recovery relies on A1, A4, A5, and A9. Provenance: §§9, 11.7, decision 2 |
| 8 | SLM class and performance envelopes | **provisional** | LiteRT, 0.5B–1.5B, int8/int4, stated RSS targets, 25-item reference batches, 100–200 ms reference CPU target, 2,000 ms inference deadline, complete-input requirement. Benchmark acceptance remains outstanding under A8. Provenance: §§2, 6, decision 6 |
| 9 | Re-bootstrap and back-pressure coordination | **assumed** | Credit-before-wire admission, independent control execution, generation-fenced live-client publication, deliberate quiescence, and cold recovery are specified. Correct deployment requires reserved resources and the A4/A9 recovery environment. Provenance: §§5, 9, decision 2 |

**Export integrity rule:** an `incomplete` target capability cannot be converted into `complete` by Phase 2 scheduling, policy approval, a memory exception, or a renamed cursor. Evidence or a versioned architectural change is required.