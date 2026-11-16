//! `crawler_inference_host`: bounded, contained SLM inference seam.
//!
//! This module is the crawler-side host of the separately bounded inference
//! domain (seam map §18.1 / §21.3, conformance **C17**). It does not run a
//! model: it gates readiness, admits bounded memory for a batch, fences
//! correlated results, and contains inference-domain memory failures so they
//! can never terminate the crawler process or be represented as a successful
//! completion.
//!
//! Contract points enforced here:
//!
//! * **EXT-BOUNDS** — item count (≤25), collection dwell (≤20 ms), manifest
//!   token budget, finite inference timeout, and the pre-dispatch inequality
//!   `timeout + collection bound + commit margin < remaining lease` on one
//!   registered monotonic clock. Over-budget input is rejected, never
//!   truncated.
//! * **EK-CLAIMS** — a ready run is required before inference; outputs must
//!   correlate exactly (run, target, stage, model, job, input hash). Partial
//!   item success is allowed; malformed, duplicate, or mismatched outputs are
//!   inference errors and never implicit PASS.
//! * **Isolation** — inference is admitted only when the manifest declares a
//!   separate engine domain, independently bounded host memory, bounded IPC,
//!   and reserves protecting the crawler, storage, and OS domains. A memory
//!   failure is recorded as a containment event, invalidates the run, stops
//!   claims, and prevents any later successful completion representation. It
//!   is not an ordinary retry.
//!
//! Every record produced here is validated through `crawler_schema` under the
//! structural `"audit_log"` envelope: no bare nulls, only typed `Missing`
//! envelopes.

use crawler_admission::Admission;
use crawler_capabilities::check_capability;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_time::{compare_deadline, ClockAuthority};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard};

/// Structural envelope schema id (the gate is structural only).
const OUTPUT_SCHEMA: &str = "audit_log";

/// Engine domains that are genuinely separate from the crawler process.
const SEPARATE_DOMAINS: &[&str] = &["separate_process", "separate_domain"];

/// Closed classifier stages (§18.1).
const STAGES: &[&str] = &["snippet", "description"];

/// Binary verdicts; anything else is an inference error, never a PASS.
const VERDICTS: &[&str] = &["PASS", "VETO"];

/// Fault codes an engine uses to report memory exhaustion in its own domain.
const MEMORY_FAILURE_CODES: &[&str] = &[
    "inference_memory_exceeded",
    "memory_limit_exceeded",
    "host_memory_exhausted",
    "out_of_memory",
];

/// Hard item ceiling from §18.1.
const ABSOLUTE_MAX_ITEMS: u64 = 25;

/// Hard collection dwell ceiling from §18.1.
const ABSOLUTE_COLLECTION_DWELL_MS: u64 = 20;

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn missing(reason: &str, detail: impl Into<String>) -> Value {
    json!({
        "value": Value::Null,
        "reason": reason,
        "detail": detail.into(),
    })
}

fn is_missing(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("value").is_some_and(Value::is_null)
                && map.get("reason").is_some_and(Value::is_string)
        }
        _ => false,
    }
}

fn object_of<'a>(
    record: &'a CheckedRecord,
    code: &'static str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record)
        .as_object()
        .ok_or_else(|| fault(code, format!("{what} must be an object")))
}

fn required_text(
    map: &Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<String, Fault> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| fault(code, format!("{what} requires a nonempty string {key:?}")))
}

fn required_object<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    match map.get(key) {
        Some(Value::Object(nested)) => Ok(nested),
        Some(value) if is_missing(value) => Err(fault(
            code,
            format!("{what} requires an established {key:?} object, found Missing"),
        )),
        _ => Err(fault(
            code,
            format!("{what} requires an object {key:?}"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<u64, Fault> {
    map.get(key).and_then(Value::as_u64).ok_or_else(|| {
        fault(
            code,
            format!("{what} requires a nonnegative integer {key:?}"),
        )
    })
}

fn optional_u64(
    map: &Map<String, Value>,
    key: &str,
    code: &'static str,
    what: &str,
) -> Result<Option<u64>, Fault> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| {
            fault(
                code,
                format!("{what} requires a nonnegative integer {key:?} when established"),
            )
        }),
        Some(value) if is_missing(value) => Ok(None),
        Some(_) => Err(fault(
            code,
            format!("{what} requires a nonnegative integer or Missing envelope for {key:?}"),
        )),
    }
}

fn offset_of(value: &Value) -> Option<f64> {
    value
        .get("monotonic_offset_ms")
        .and_then(Value::as_f64)
        .filter(|offset| offset.is_finite() && *offset >= 0.0)
}

fn offset_timepoint(now: &CheckedRecord, delta_ms: u64) -> Result<CheckedRecord, Fault> {
    let mut value = record_value(now).clone();
    let map = value.as_object_mut().ok_or_else(|| {
        fault(
            "invalid_clock",
            "registered clock must report a TimePoint object",
        )
    })?;
    let start = map
        .get("monotonic_offset_ms")
        .and_then(Value::as_f64)
        .filter(|offset| offset.is_finite() && *offset >= 0.0)
        .ok_or_else(|| {
            fault(
                "invalid_clock",
                "registered clock TimePoint has no finite monotonic_offset_ms",
            )
        })?;
    map.insert(
        "monotonic_offset_ms".to_string(),
        json!(start + delta_ms as f64),
    );
    validate(OUTPUT_SCHEMA, value)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Deployment declaration of the host-side isolation and batch bounds.
///
/// These are ceilings, not measurements. A manifest may declare tighter
/// bounds; it may never raise one. Reference latency/memory targets are never
/// output as measured acceptance evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct HostConfig {
    /// Default inference timeout when the manifest leaves it Missing (§18.1).
    pub inference_timeout_ms: u64,
    /// Local ceiling for an explicit inference timeout.
    pub max_inference_timeout_ms: u64,
    /// Maximum accepted batch items (never above 25).
    pub max_items: u64,
    /// Maximum accepted collection dwell (never above 20 ms).
    pub collection_dwell_ms: u64,
    /// Commit margin added to the pre-dispatch lease inequality.
    pub commit_margin_ms: u64,
    /// Manifest batch token budget ceiling.
    pub max_batch_tokens: u64,
    /// Nominal class-target host memory ceiling (§21.3: 1 GB / 3 GB classes).
    pub max_host_memory_bytes: u64,
    /// Bounded IPC buffer ceiling.
    pub max_ipc_buffer_bytes: u64,
    /// Crawler-domain reserve the manifest must declare before inference.
    pub required_crawler_reserve_bytes: u64,
    /// Storage-domain reserve the manifest must declare before inference.
    pub required_storage_reserve_bytes: u64,
    /// OS-domain reserve the manifest must declare before inference.
    pub required_os_reserve_bytes: u64,
    /// Bounded accepted classifier reason length.
    pub max_reason_chars: usize,
    /// Retained containment evidence records.
    pub containment_evidence_bound: usize,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            inference_timeout_ms: 2_000,
            max_inference_timeout_ms: 30_000,
            max_items: ABSOLUTE_MAX_ITEMS,
            collection_dwell_ms: ABSOLUTE_COLLECTION_DWELL_MS,
            commit_margin_ms: 250,
            max_batch_tokens: 8_192,
            max_host_memory_bytes: 3_221_225_472,
            max_ipc_buffer_bytes: 1_048_576,
            required_crawler_reserve_bytes: 209_715_200,
            required_storage_reserve_bytes: 104_857_600,
            required_os_reserve_bytes: 268_435_456,
            max_reason_chars: 512,
            containment_evidence_bound: 64,
        }
    }
}

impl HostConfig {
    /// Reject a declaration that cannot express finite, bounded isolation.
    pub fn validate(&self) -> Result<(), Fault> {
        for (name, value) in [
            ("inference_timeout_ms", self.inference_timeout_ms),
            ("max_inference_timeout_ms", self.max_inference_timeout_ms),
            ("max_items", self.max_items),
            ("collection_dwell_ms", self.collection_dwell_ms),
            ("commit_margin_ms", self.commit_margin_ms),
            ("max_batch_tokens", self.max_batch_tokens),
            ("max_host_memory_bytes", self.max_host_memory_bytes),
            ("max_ipc_buffer_bytes", self.max_ipc_buffer_bytes),
            (
                "required_crawler_reserve_bytes",
                self.required_crawler_reserve_bytes,
            ),
            (
                "required_storage_reserve_bytes",
                self.required_storage_reserve_bytes,
            ),
            ("required_os_reserve_bytes", self.required_os_reserve_bytes),
        ] {
            if value == 0 {
                return Err(fault(
                    "invalid_configuration",
                    format!("host bound {name} must be positive"),
                ));
            }
        }
        if self.max_items > ABSOLUTE_MAX_ITEMS {
            return Err(fault(
                "invalid_configuration",
                "max_items cannot exceed the 25-item batch limit",
            ));
        }
        if self.collection_dwell_ms > ABSOLUTE_COLLECTION_DWELL_MS {
            return Err(fault(
                "invalid_configuration",
                "collection_dwell_ms cannot exceed the 20 ms collection bound",
            ));
        }
        if self.max_reason_chars == 0 || self.containment_evidence_bound == 0 {
            return Err(fault(
                "invalid_configuration",
                "reason bound and containment evidence bound must retain at least one unit",
            ));
        }
        if self.inference_timeout_ms > self.max_inference_timeout_ms {
            return Err(fault(
                "invalid_configuration",
                "default inference timeout exceeds the declared ceiling",
            ));
        }
        if self.max_ipc_buffer_bytes > self.max_host_memory_bytes {
            return Err(fault(
                "invalid_configuration",
                "bounded IPC cannot exceed the bounded host memory domain",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public seams
// ---------------------------------------------------------------------------

/// Host-side inference seam consumed by the classifier (§18.1, seam S05).
///
/// The engine runs in a separately bounded domain; the model cannot issue
/// leases, mutate rows, or terminate the crawler. Every method returns a
/// validated record or a [`Fault`]; none panics on input.
pub trait InferenceHost: Send + Sync {
    /// Validate the pinned manifest and open the claim/readiness gate.
    fn ensure_ready(&self, manifest: &CheckedRecord) -> Result<CheckedRecord, Fault>;
    /// Admit, dispatch, correlate, and settle one bounded inference batch.
    fn infer(&self, batch: &CheckedRecord) -> Result<CheckedRecord, Fault>;
    /// Retained containment evidence for this host instance.
    fn containment_events(&self) -> Result<CheckedRecord, Fault>;
}

/// Execution boundary of the separately bounded inference domain.
///
/// Implementations are expected to speak to a separate process/domain over
/// bounded IPC. Returning a memory fault or panicking inside this boundary is
/// contained by the host and can never take the crawler down.
pub trait InferenceEngine: Send + Sync {
    /// Execute one already-admitted dispatch record.
    fn execute(&self, request: &CheckedRecord) -> Result<CheckedRecord, Fault>;
}

// ---------------------------------------------------------------------------
// Host state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct EffectiveLimits {
    max_items: u64,
    collection_dwell_ms: u64,
    inference_timeout_ms: u64,
    batch_token_budget: u64,
    commit_margin_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct IsolationBounds {
    engine_domain: String,
    host_memory_bytes: u64,
    ipc_buffer_bytes: u64,
    crawler_reserve_bytes: u64,
    storage_reserve_bytes: u64,
    os_reserve_bytes: u64,
    control_lane_slots: u64,
}

#[derive(Debug, Clone)]
struct RunState {
    manifest_revision: String,
    model_id: String,
    model_version: String,
    limits: EffectiveLimits,
    isolation: IsolationBounds,
    readiness_sequence: u64,
    ready: bool,
}

#[derive(Debug, Clone)]
struct Invalidation {
    kind: String,
    detail: String,
}

#[derive(Debug, Default)]
struct HostState {
    runs: HashMap<String, RunState>,
    invalidated: HashMap<String, Invalidation>,
    events: VecDeque<Value>,
    total_events: u64,
}

// ---------------------------------------------------------------------------
// Bounded inference host
// ---------------------------------------------------------------------------

/// Host that admits bounded inference, fences correlated outputs, and contains
/// inference-domain memory failures.
pub struct BoundedInferenceHost {
    clock: Arc<dyn ClockAuthority>,
    admission: Arc<dyn Admission>,
    engine: Arc<dyn InferenceEngine>,
    config: HostConfig,
    state: Mutex<HostState>,
}

impl BoundedInferenceHost {
    /// Build a host around a registered local clock, owner-local admission,
    /// and the separately bounded engine boundary.
    pub fn new(
        clock: Arc<dyn ClockAuthority>,
        admission: Arc<dyn Admission>,
        engine: Arc<dyn InferenceEngine>,
        config: HostConfig,
    ) -> Result<Self, Fault> {
        config.validate()?;
        Ok(Self {
            clock,
            admission,
            engine,
            config,
            state: Mutex::new(HostState::default()),
        })
    }

    /// The deployment declaration this host enforces.
    pub fn config(&self) -> &HostConfig {
        &self.config
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, HostState>, Fault> {
        self.state.lock().map_err(|_| {
            fault(
                "internal_error",
                "inference host state lock poisoned by an earlier panic",
            )
        })
    }

    fn invalidated_fault(run_id: &str, invalidation: &Invalidation) -> Fault {
        fault(
            "run_invalidated",
            format!(
                "run {run_id:?} is invalidated by {} and cannot be represented as a successful completion: {}",
                invalidation.kind, invalidation.detail
            ),
        )
    }

    /// Record a containment event and invalidate exactly one run.
    ///
    /// Evidence recording is best-effort with respect to the primary fault:
    /// the containment result (a returned `Fault`, never a process abort) is
    /// authoritative even if the evidence ledger is unavailable.
    fn contain(
        &self,
        run_id: &str,
        kind: &str,
        detail: String,
        memory: Option<Value>,
        isolation: Option<&IsolationBounds>,
    ) -> Fault {
        let observed_at = match self.clock.now() {
            Ok(now) => record_value(&now).clone(),
            Err(_) => missing(
                "not_observed",
                "registered clock unavailable while recording the containment event",
            ),
        };
        let Ok(mut state) = self.state.lock() else {
            return fault(kind, detail);
        };
        state.total_events += 1;
        let sequence = state.total_events;
        let model = state
            .runs
            .get(run_id)
            .map(|run| {
                json!({
                    "id": run.model_id.clone(),
                    "version": run.model_version.clone(),
                })
            })
            .unwrap_or_else(|| {
                missing(
                    "not_observed",
                    "the run never reached a readiness admission",
                )
            });
        let engine_domain = isolation
            .map(|bounds| Value::String(bounds.engine_domain.clone()))
            .unwrap_or_else(|| {
                missing(
                    "not_observed",
                    "no admitted isolation declaration exists for this run",
                )
            });
        let separate_domain = isolation
            .is_some_and(|bounds| SEPARATE_DOMAINS.contains(&bounds.engine_domain.as_str()));
        state.invalidated.insert(
            run_id.to_string(),
            Invalidation {
                kind: kind.to_string(),
                detail: detail.clone(),
            },
        );
        if let Some(run) = state.runs.get_mut(run_id) {
            run.ready = false;
        }
        let event = json!({
            "event_id": format!("containment-{sequence}"),
            "event_kind": kind,
            "run_id": run_id,
            "model": model,
            "engine_domain": engine_domain,
            "detail": detail,
            "crawler_terminated": false,
            "contained_outside_crawler": separate_domain,
            "run_invalidated": true,
            "claims": "stopped",
            "claim_gate": "closed",
            "successful_completion_prevented": true,
            "memory": memory.unwrap_or_else(|| {
                missing(
                    "not_observed",
                    "the inference domain reported no memory evidence for this failure",
                )
            }),
            "observed_at": observed_at,
        });
        if let Ok(event) = validate(OUTPUT_SCHEMA, event) {
            while state.events.len() >= self.config.containment_evidence_bound {
                state.events.pop_front();
            }
            state.events.push_back(record_value(&event).clone());
        }
        fault(kind, detail)
    }

    /// Read the manifest's isolation declaration, enforcing independent host
    /// memory, bounded IPC, and crawler/storage/OS reserves.
    ///
    /// A malformed declaration is a manifest error. A declaration that
    /// actively undercuts isolation (in-process engine, zero/unbounded host
    /// memory, oversized IPC, or missing domain reserves) is an induced
    /// isolation violation: the run is invalidated immediately.
    fn read_isolation(
        &self,
        map: &Map<String, Value>,
        run_id: &str,
    ) -> Result<IsolationBounds, Fault> {
        let isolation = required_object(map, "isolation", "invalid_isolation", "manifest")?;
        let engine_domain = required_text(
            isolation,
            "engine_domain",
            "invalid_isolation",
            "manifest isolation",
        )?;
        let host_memory_bytes = required_u64(
            isolation,
            "host_memory_bytes",
            "invalid_isolation",
            "manifest isolation",
        )?;
        let ipc_buffer_bytes = required_u64(
            isolation,
            "ipc_buffer_bytes",
            "invalid_isolation",
            "manifest isolation",
        )?;
        let crawler_reserve_bytes = required_u64(
            isolation,
            "crawler_reserve_bytes",
            "invalid_isolation",
            "manifest isolation",
        )?;
        let storage_reserve_bytes = required_u64(
            isolation,
            "storage_reserve_bytes",
            "invalid_isolation",
            "manifest isolation",
        )?;
        let os_reserve_bytes = required_u64(
            isolation,
            "os_reserve_bytes",
            "invalid_isolation",
            "manifest isolation",
        )?;
        let control_lane_slots = required_u64(
            isolation,
            "control_lane_slots",
            "invalid_isolation",
            "manifest isolation",
        )?;

        let mut violations = Vec::new();
        if !SEPARATE_DOMAINS.contains(&engine_domain.as_str()) {
            violations.push(format!(
                "engine_domain {engine_domain:?} does not place inference in a separate bounded process/domain"
            ));
        }
        if host_memory_bytes == 0 {
            violations.push("host_memory_bytes must bound the inference domain".to_string());
        }
        if host_memory_bytes > self.config.max_host_memory_bytes {
            violations.push(format!(
                "host_memory_bytes {host_memory_bytes} exceeds the declared ceiling of {}",
                self.config.max_host_memory_bytes
            ));
        }
        if ipc_buffer_bytes == 0 {
            violations.push("ipc_buffer_bytes must bound the IPC channel".to_string());
        }
        if ipc_buffer_bytes > self.config.max_ipc_buffer_bytes {
            violations.push(format!(
                "ipc_buffer_bytes {ipc_buffer_bytes} exceeds the bounded IPC ceiling of {}",
                self.config.max_ipc_buffer_bytes
            ));
        }
        if ipc_buffer_bytes > host_memory_bytes {
            violations.push(
                "the bounded IPC channel cannot exceed the bounded host memory domain".to_string(),
            );
        }
        if crawler_reserve_bytes < self.config.required_crawler_reserve_bytes {
            violations.push(format!(
                "crawler_reserve_bytes {crawler_reserve_bytes} is below the required crawler reserve of {}",
                self.config.required_crawler_reserve_bytes
            ));
        }
        if storage_reserve_bytes < self.config.required_storage_reserve_bytes {
            violations.push(format!(
                "storage_reserve_bytes {storage_reserve_bytes} is below the required storage reserve of {}",
                self.config.required_storage_reserve_bytes
            ));
        }
        if os_reserve_bytes < self.config.required_os_reserve_bytes {
            violations.push(format!(
                "os_reserve_bytes {os_reserve_bytes} is below the required OS reserve of {}",
                self.config.required_os_reserve_bytes
            ));
        }
        if control_lane_slots == 0 {
            violations.push(
                "control_lane_slots must reserve at least one independent control command"
                    .to_string(),
            );
        }

        let bounds = IsolationBounds {
            engine_domain,
            host_memory_bytes,
            ipc_buffer_bytes,
            crawler_reserve_bytes,
            storage_reserve_bytes,
            os_reserve_bytes,
            control_lane_slots,
        };
        if violations.is_empty() {
            return Ok(bounds);
        }
        Err(self.contain(
            run_id,
            "isolation_violation",
            violations.join("; "),
            None,
            Some(&bounds),
        ))
    }

    fn acquire_run(
        &self,
        run_id: &str,
        manifest_revision: &str,
        model_version: &str,
    ) -> Result<(EffectiveLimits, IsolationBounds, String, u64), Fault> {
        let state = self.lock_state()?;
        if let Some(invalidation) = state.invalidated.get(run_id) {
            return Err(Self::invalidated_fault(run_id, invalidation));
        }
        let run = state.runs.get(run_id).ok_or_else(|| {
            fault(
                "run_not_ready",
                format!("run {run_id:?} has no readiness admission; classifier rows cannot be claimed before readiness"),
            )
        })?;
        if !run.ready {
            return Err(fault(
                "run_not_ready",
                format!("run {run_id:?} is not ready for inference"),
            ));
        }
        if run.manifest_revision != manifest_revision {
            return Err(fault(
                "manifest_revision_mismatch",
                format!(
                    "batch targets manifest revision {manifest_revision:?} but run {run_id:?} is ready under {:?}",
                    run.manifest_revision
                ),
            ));
        }
        if run.model_version != model_version {
            return Err(fault(
                "model_mismatch",
                format!(
                    "batch targets model {model_version:?} but run {run_id:?} is pinned to {:?}",
                    run.model_version
                ),
            ));
        }
        Ok((
            run.limits.clone(),
            run.isolation.clone(),
            run.model_id.clone(),
            run.readiness_sequence,
        ))
    }

}

impl InferenceHost for BoundedInferenceHost {
    fn ensure_ready(&self, manifest: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let map = object_of(manifest, "invalid_manifest", "manifest")?;
        let run_id = required_text(map, "run_id", "invalid_manifest", "manifest")?;
        let manifest_revision = required_text(
            map,
            "manifest_revision",
            "invalid_manifest",
            "manifest",
        )?;
        {
            let state = self.lock_state()?;
            if let Some(invalidation) = state.invalidated.get(&run_id) {
                return Err(Self::invalidated_fault(&run_id, invalidation));
            }
        }

        let model = required_object(map, "model", "invalid_manifest", "manifest")?;
        let model_id = required_text(model, "id", "invalid_manifest", "manifest model")?;
        let model_version =
            required_text(model, "version", "invalid_manifest", "manifest model")?;
        let artifact_digest =
            required_text(model, "artifact_digest", "invalid_manifest", "manifest model")?;
        let tokenizer_digest =
            required_text(model, "tokenizer_digest", "invalid_manifest", "manifest model")?;
        let prompt_digest =
            required_text(model, "prompt_digest", "invalid_manifest", "manifest model")?;

        let limits = required_object(map, "limits", "invalid_limits", "manifest")?;
        let max_items = required_u64(limits, "max_items", "invalid_limits", "manifest limits")?;
        if max_items == 0
            || max_items > ABSOLUTE_MAX_ITEMS
            || max_items > self.config.max_items
        {
            return Err(fault(
                "invalid_limits",
                format!(
                    "manifest max_items {max_items} must be within 1..={}",
                    self.config.max_items.min(ABSOLUTE_MAX_ITEMS)
                ),
            ));
        }
        let collection_dwell_ms = required_u64(
            limits,
            "collection_dwell_ms",
            "invalid_limits",
            "manifest limits",
        )?;
        if collection_dwell_ms > ABSOLUTE_COLLECTION_DWELL_MS
            || collection_dwell_ms > self.config.collection_dwell_ms
        {
            return Err(fault(
                "invalid_limits",
                format!(
                    "manifest collection_dwell_ms {collection_dwell_ms} exceeds the {} ms collection bound",
                    self.config
                        .collection_dwell_ms
                        .min(ABSOLUTE_COLLECTION_DWELL_MS)
                ),
            ));
        }
        let inference_timeout_ms =
            optional_u64(limits, "inference_timeout_ms", "invalid_limits", "manifest limits")?
                .unwrap_or(self.config.inference_timeout_ms);
        if inference_timeout_ms == 0 || inference_timeout_ms > self.config.max_inference_timeout_ms {
            return Err(fault(
                "invalid_limits",
                format!(
                    "manifest inference_timeout_ms {inference_timeout_ms} must be within 1..={}",
                    self.config.max_inference_timeout_ms
                ),
            ));
        }
        let batch_token_budget = required_u64(
            limits,
            "batch_token_budget",
            "invalid_limits",
            "manifest limits",
        )?;
        if batch_token_budget == 0 || batch_token_budget > self.config.max_batch_tokens {
            return Err(fault(
                "invalid_limits",
                format!(
                    "manifest batch_token_budget {batch_token_budget} must be within 1..={}",
                    self.config.max_batch_tokens
                ),
            ));
        }

        let isolation = self.read_isolation(map, &run_id)?;

        let capability = required_object(map, "capability", "invalid_capability", "manifest")?;
        let capability_id = required_text(
            capability,
            "capability_id",
            "invalid_capability",
            "manifest capability",
        )?;
        let descriptor_value = capability
            .get("descriptor")
            .filter(|value| !is_missing(value))
            .cloned()
            .ok_or_else(|| {
                fault(
                    "invalid_capability",
                    "manifest capability requires an established descriptor object",
                )
            })?;
        let scope_value = capability
            .get("scope")
            .filter(|value| !is_missing(value))
            .cloned()
            .ok_or_else(|| {
                fault(
                    "invalid_capability",
                    "manifest capability requires an established scope object",
                )
            })?;
        let descriptor = validate(OUTPUT_SCHEMA, descriptor_value)
            .map_err(|error| fault("invalid_capability", format!("descriptor: {}", error.detail)))?;
        let scope = validate(OUTPUT_SCHEMA, scope_value)
            .map_err(|error| fault("invalid_capability", format!("scope: {}", error.detail)))?;
        let finding = check_capability(&descriptor, &capability_id, &scope)?;
        let availability = record_value(&finding)
            .get("availability")
            .and_then(Value::as_str)
            .unwrap_or("");
        if availability == "absent" {
            return Err(fault(
                "capability_absent",
                format!(
                    "capability {capability_id:?} is explicitly absent for this exact subject scope; readiness cannot be granted"
                ),
            ));
        }

        let control_scope = validate(
            OUTPUT_SCHEMA,
            json!({
                "scope_id": format!("{run_id}:readiness"),
                "target": "inference-host",
                "command": "ensure_ready",
            }),
        )?;
        let control_credit = self.admission.reserve_control(&control_scope)?;
        let control_reservation = record_value(&control_credit.reservation).clone();
        let ready_at = self.clock.now()?;

        let readiness_sequence = {
            let mut state = self.lock_state()?;
            if let Some(invalidation) = state.invalidated.get(&run_id) {
                return Err(Self::invalidated_fault(&run_id, invalidation));
            }
            let sequence = state
                .runs
                .get(&run_id)
                .map(|run| run.readiness_sequence + 1)
                .unwrap_or(1);
            state.runs.insert(
                run_id.clone(),
                RunState {
                    manifest_revision: manifest_revision.clone(),
                    model_id: model_id.clone(),
                    model_version: model_version.clone(),
                    limits: EffectiveLimits {
                        max_items,
                        collection_dwell_ms,
                        inference_timeout_ms,
                        batch_token_budget,
                        commit_margin_ms: self.config.commit_margin_ms,
                    },
                    isolation: isolation.clone(),
                    readiness_sequence: sequence,
                    ready: true,
                },
            );
            sequence
        };

        let readiness = validate(
            OUTPUT_SCHEMA,
            json!({
                "kind": "inference_readiness",
                "run_id": run_id,
                "manifest_revision": manifest_revision,
                "status": "ready",
                "claim_gate": "open",
                "readiness_sequence": readiness_sequence,
                "model": {
                    "id": model_id,
                    "version": model_version,
                    "artifact_digest": artifact_digest,
                    "tokenizer_digest": tokenizer_digest,
                    "prompt_digest": prompt_digest,
                },
                "limits": {
                    "max_items": max_items,
                    "collection_dwell_ms": collection_dwell_ms,
                    "inference_timeout_ms": inference_timeout_ms,
                    "batch_token_budget": batch_token_budget,
                    "commit_margin_ms": self.config.commit_margin_ms,
                },
                "isolation": {
                    "engine_domain": isolation.engine_domain,
                    "host_memory_bytes": isolation.host_memory_bytes,
                    "ipc_buffer_bytes": isolation.ipc_buffer_bytes,
                    "crawler_reserve_bytes": isolation.crawler_reserve_bytes,
                    "storage_reserve_bytes": isolation.storage_reserve_bytes,
                    "os_reserve_bytes": isolation.os_reserve_bytes,
                    "control_lane_slots": isolation.control_lane_slots,
                    "required_crawler_reserve_bytes": self.config.required_crawler_reserve_bytes,
                    "required_storage_reserve_bytes": self.config.required_storage_reserve_bytes,
                    "required_os_reserve_bytes": self.config.required_os_reserve_bytes,
                },
                "capability": record_value(&finding),
                "admission_control": control_reservation,
                "crawler_terminated": false,
                "ready_at": record_value(&ready_at),
            }),
        )?;
        drop(control_credit);
        Ok(readiness)
    }

    fn infer(&self, batch: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let map = object_of(batch, "invalid_batch", "batch")?;
        let run_id = required_text(map, "run_id", "invalid_batch", "batch")?;
        {
            let state = self.lock_state()?;
            if let Some(invalidation) = state.invalidated.get(&run_id) {
                return Err(Self::invalidated_fault(&run_id, invalidation));
            }
        }
        let manifest_revision = required_text(
            map,
            "manifest_revision",
            "invalid_batch",
            "batch",
        )?;
        let model_version = required_text(map, "model_version", "invalid_batch", "batch")?;
        let batch_id = required_text(map, "batch_id", "invalid_batch", "batch")?;
        let target = required_text(map, "target", "invalid_batch", "batch")?;
        let stage = required_text(map, "stage", "invalid_batch", "batch")?;
        if !STAGES.contains(&stage.as_str()) {
            return Err(fault(
                "invalid_batch",
                format!("batch stage {stage:?} must be snippet or description"),
            ));
        }

        let (limits, isolation, model_id, _) =
            self.acquire_run(&run_id, &manifest_revision, &model_version)?;

        let items = map
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| fault("invalid_batch", "batch requires an items array"))?;
        if items.is_empty() {
            return Err(fault("invalid_batch", "batch items cannot be empty"));
        }
        if items.len() as u64 > limits.max_items
            || items.len() as u64 > ABSOLUTE_MAX_ITEMS
        {
            return Err(fault(
                "batch_too_large",
                format!(
                    "batch carries {} items; the admitted limit is {}",
                    items.len(),
                    limits.max_items.min(ABSOLUTE_MAX_ITEMS)
                ),
            ));
        }
        let mut seen_jobs = HashSet::new();
        let mut input_hashes: HashMap<String, String> = HashMap::new();
        let mut token_total: u64 = 0;
        for (index, item) in items.iter().enumerate() {
            let item_map = item.as_object().ok_or_else(|| {
                fault(
                    "invalid_batch",
                    format!("batch items[{index}] must be an object"),
                )
            })?;
            let job_id = required_text(item_map, "job_id", "invalid_batch", "batch item")?;
            let input_hash =
                required_text(item_map, "input_hash", "invalid_batch", "batch item")?;
            if !seen_jobs.insert(job_id.clone()) {
                return Err(fault(
                    "invalid_batch",
                    format!("batch repeats job_id {job_id:?}; one item per job is required"),
                ));
            }
            input_hashes.insert(job_id, input_hash);
            let token_count =
                optional_u64(item_map, "token_count", "invalid_batch", "batch item")?;
            let Some(token_count) = token_count else {
                return Err(fault(
                    "unverifiable_token_budget",
                    format!(
                        "batch items[{index}] carries no token_count; long input is not silently truncated and an unmeasured item cannot be admitted"
                    ),
                ));
            };
            token_total = token_total.saturating_add(token_count);
        }
        if let Some(declared) =
            optional_u64(map, "token_estimate", "invalid_batch", "batch")?
        {
            if declared != token_total {
                return Err(fault(
                    "token_estimate_mismatch",
                    format!(
                        "batch declares token_estimate {declared} but item token counts sum to {token_total}"
                    ),
                ));
            }
        }
        if token_total > limits.batch_token_budget {
            return Err(fault(
                "batch_token_budget_exceeded",
                format!(
                    "batch needs {token_total} tokens; the manifest budget is {}",
                    limits.batch_token_budget
                ),
            ));
        }
        let collection_dwell_ms = required_u64(
            map,
            "collection_dwell_ms",
            "invalid_batch",
            "batch",
        )?;
        if collection_dwell_ms > ABSOLUTE_COLLECTION_DWELL_MS
            || collection_dwell_ms > limits.collection_dwell_ms
        {
            return Err(fault(
                "collection_dwell_exceeded",
                format!(
                    "batch collection dwell {collection_dwell_ms} ms exceeds the admitted {} ms bound",
                    limits.collection_dwell_ms
                ),
            ));
        }

        let lease_value = map
            .get("lease_expires_at")
            .filter(|value| !is_missing(value))
            .cloned()
            .ok_or_else(|| {
                fault(
                    "unverifiable_lease_bound",
                    "batch requires an established lease_expires_at TimePoint before dispatch",
                )
            })?;
        let lease_expires_at = validate(OUTPUT_SCHEMA, lease_value).map_err(|error| {
            fault(
                "unverifiable_lease_bound",
                format!("lease_expires_at must be a TimePoint: {}", error.detail),
            )
        })?;
        let now = self.clock.now()?;
        let required_ms = limits
            .inference_timeout_ms
            .saturating_add(limits.collection_dwell_ms)
            .saturating_add(limits.commit_margin_ms);
        let dispatch_deadline = offset_timepoint(&now, required_ms)?;
        if compare_deadline(&dispatch_deadline, &lease_expires_at)? != Ordering::Less {
            return Err(fault(
                "lease_insufficient",
                "inference timeout + collection bound + commit margin does not fit inside the remaining lease",
            ));
        }

        let observation_bytes = isolation.ipc_buffer_bytes;
        let reservation_request = validate(
            OUTPUT_SCHEMA,
            json!({
                "request_id": format!("{batch_id}:inference"),
                "target": target,
                "max_packet_rows": items.len() as u64,
                "max_packet_bytes": isolation.ipc_buffer_bytes,
                "observation_bytes": observation_bytes,
            }),
        )?;
        let credit = self.admission.reserve_response(&reservation_request)?;
        let admitted = record_value(&credit.reservation).clone();

        let dispatch = validate(
            OUTPUT_SCHEMA,
            json!({
                "kind": "inference_dispatch",
                "batch_id": batch_id,
                "run_id": run_id,
                "manifest_revision": manifest_revision,
                "target": target,
                "stage": stage,
                "model": {"id": model_id, "version": model_version},
                "items": Value::Array(items.clone()),
                "collection_dwell_ms": collection_dwell_ms,
                "token_estimate": token_total,
                "batch_token_budget": limits.batch_token_budget,
                "timeout_ms": limits.inference_timeout_ms,
                "dispatch_deadline": record_value(&dispatch_deadline),
                "isolation": {
                    "engine_domain": isolation.engine_domain,
                    "host_memory_bytes": isolation.host_memory_bytes,
                    "ipc_buffer_bytes": isolation.ipc_buffer_bytes,
                    "crawler_reserve_bytes": isolation.crawler_reserve_bytes,
                    "storage_reserve_bytes": isolation.storage_reserve_bytes,
                    "os_reserve_bytes": isolation.os_reserve_bytes,
                },
            }),
        )?;

        let engine_outcome =
            catch_unwind(AssertUnwindSafe(|| self.engine.execute(&dispatch)));
        let outcome = match engine_outcome {
            Ok(result) => result,
            Err(_) => {
                return Err(self.contain(
                    &run_id,
                    "inference_engine_panic",
                    "the separately bounded inference engine panicked; the crawler domain survived the boundary"
                        .to_string(),
                    None,
                    Some(&isolation),
                ));
            }
        };
        let outcome = match outcome {
            Ok(record) => record,
            Err(error) => {
                if MEMORY_FAILURE_CODES.contains(&error.code.as_str()) {
                    return Err(self.contain(
                        &run_id,
                        "inference_memory_failure",
                        format!(
                            "inference domain exhausted its bounded memory ({}): {}",
                            error.code, error.detail
                        ),
                        None,
                        Some(&isolation),
                    ));
                }
                return Err(error);
            }
        };

        let outcome_map = object_of(&outcome, "inference_output_invalid", "engine result")?;
        let completed_at = self.clock.now()?;
        if compare_deadline(&completed_at, &dispatch_deadline)? == Ordering::Greater {
            return Err(fault(
                "late_response",
                "inference response arrived after its admitted dispatch deadline and is fenced",
            ));
        }

        let memory = outcome_map
            .get("memory")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                fault(
                    "inference_output_invalid",
                    "engine result requires a memory object with peak_bytes and limit_bytes",
                )
            })?;
        let peak_bytes = memory.get("peak_bytes").and_then(Value::as_u64).ok_or_else(|| {
            fault(
                "inference_output_invalid",
                "engine result memory requires a nonnegative peak_bytes",
            )
        })?;
        let limit_bytes = memory
            .get("limit_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                fault(
                    "inference_output_invalid",
                    "engine result memory requires a nonnegative limit_bytes",
                )
            })?;
        let memory_evidence = json!({
            "peak_bytes": peak_bytes,
            "limit_bytes": limit_bytes,
            "host_bound_bytes": isolation.host_memory_bytes,
        });
        if limit_bytes != isolation.host_memory_bytes {
            return Err(self.contain(
                &run_id,
                "isolation_violation",
                format!(
                    "engine executed under a memory limit of {limit_bytes} bytes instead of the admitted host bound of {} bytes",
                    isolation.host_memory_bytes
                ),
                Some(memory_evidence),
                Some(&isolation),
            ));
        }
        if peak_bytes > limit_bytes {
            return Err(self.contain(
                &run_id,
                "inference_memory_failure",
                format!(
                    "engine peak memory {peak_bytes} bytes crossed its admitted limit of {limit_bytes} bytes"
                ),
                Some(memory_evidence),
                Some(&isolation),
            ));
        }

        let fenced = {
            let state = self.lock_state()?;
            if let Some(invalidation) = state.invalidated.get(&run_id) {
                Some(invalidation.kind.clone())
            } else {
                match state.runs.get(&run_id) {
                    Some(run)
                        if run.ready
                            && run.manifest_revision == manifest_revision
                            && run.model_version == model_version =>
                    {
                        None
                    }
                    _ => Some("revision or readiness changed".to_string()),
                }
            }
        };
        if let Some(reason) = fenced {
            return Err(fault(
                "fenced_response",
                format!(
                    "inference response is fenced: the run was released, invalidated, or its revision changed ({reason})"
                ),
            ));
        }

        let outcome_run = required_text(
            outcome_map,
            "run_id",
            "inference_output_mismatch",
            "engine result",
        )?;
        let outcome_revision = required_text(
            outcome_map,
            "manifest_revision",
            "inference_output_mismatch",
            "engine result",
        )?;
        let outcome_target = required_text(
            outcome_map,
            "target",
            "inference_output_mismatch",
            "engine result",
        )?;
        let outcome_stage = required_text(
            outcome_map,
            "stage",
            "inference_output_mismatch",
            "engine result",
        )?;
        let outcome_model = required_text(
            outcome_map,
            "model_version",
            "inference_output_mismatch",
            "engine result",
        )?;
        if outcome_run != run_id
            || outcome_revision != manifest_revision
            || outcome_target != target
            || outcome_stage != stage
            || outcome_model != model_version
        {
            return Err(fault(
                "inference_output_mismatch",
                "engine result does not correlate to the dispatched run, revision, target, stage, and model",
            ));
        }

        let outputs = outcome_map
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                fault(
                    "inference_output_invalid",
                    "engine result requires an items array",
                )
            })?;
        let mut seen_output = HashSet::new();
        let mut normalized = Vec::with_capacity(outputs.len());
        for (index, output) in outputs.iter().enumerate() {
            let output_map = output.as_object().ok_or_else(|| {
                fault(
                    "inference_output_invalid",
                    format!("engine result items[{index}] must be an object"),
                )
            })?;
            let job_id = required_text(
                output_map,
                "job_id",
                "inference_output_invalid",
                "engine output item",
            )?;
            let input_hash = required_text(
                output_map,
                "input_hash",
                "inference_output_invalid",
                "engine output item",
            )?;
            if !seen_output.insert(job_id.clone()) {
                return Err(fault(
                    "inference_output_duplicate",
                    format!("engine returned job_id {job_id:?} more than once"),
                ));
            }
            match input_hashes.get(&job_id) {
                Some(expected) if expected == &input_hash => {}
                Some(_) => {
                    return Err(fault(
                        "inference_output_mismatch",
                        format!("engine returned a different input hash for job_id {job_id:?}"),
                    ));
                }
                None => {
                    return Err(fault(
                        "inference_output_mismatch",
                        format!("engine returned an output for job_id {job_id:?} that was not dispatched"),
                    ));
                }
            }
            let verdict = required_text(
                output_map,
                "verdict",
                "inference_output_invalid",
                "engine output item",
            )?;
            let verdict_applied = required_text(
                output_map,
                "verdict_applied",
                "inference_output_invalid",
                "engine output item",
            )?;
            if !VERDICTS.contains(&verdict.as_str())
                || !VERDICTS.contains(&verdict_applied.as_str())
            {
                return Err(fault(
                    "inference_output_invalid",
                    format!(
                        "engine output for job_id {job_id:?} must use PASS or VETO; a malformed verdict is never implicit PASS"
                    ),
                ));
            }
            let confidence = output_map
                .get("confidence")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
                .ok_or_else(|| {
                    fault(
                        "inference_output_invalid",
                        format!(
                            "engine output for job_id {job_id:?} requires a finite confidence in [0,1]"
                        ),
                    )
                })?;
            let reason = required_text(
                output_map,
                "reason",
                "inference_output_invalid",
                "engine output item",
            )?;
            if reason.chars().count() > self.config.max_reason_chars {
                return Err(fault(
                    "inference_output_invalid",
                    format!(
                        "engine output reason for job_id {job_id:?} exceeds the {} character bound",
                        self.config.max_reason_chars
                    ),
                ));
            }
            normalized.push(json!({
                "job_id": job_id,
                "input_hash": input_hash,
                "stage": stage,
                "model_version": model_version,
                "verdict": verdict,
                "verdict_applied": verdict_applied,
                "confidence": confidence,
                "reason": reason,
            }));
        }
        let submitted = items.len() as u64;
        let accepted = normalized.len() as u64;
        let partial = accepted < submitted;
        let observed_latency = match (
            offset_of(record_value(&now)),
            offset_of(record_value(&completed_at)),
        ) {
            (Some(start), Some(end)) if end >= start => Some(end - start),
            _ => None,
        };
        let latency_evidence = match observed_latency {
            Some(value) => json!(value),
            None => missing(
                "not_observed",
                "monotonic latency is unavailable for this dispatch",
            ),
        };
        let results = validate(
            OUTPUT_SCHEMA,
            json!({
                "kind": "inference_results",
                "batch_id": batch_id,
                "run_id": run_id,
                "manifest_revision": manifest_revision,
                "target": target,
                "stage": stage,
                "model": {"id": model_id, "version": model_version},
                "items": normalized,
                "submitted_count": submitted,
                "accepted_count": accepted,
                "partial": partial,
                "memory": memory_evidence,
                "isolation": {
                    "engine_domain": isolation.engine_domain,
                    "host_memory_bytes": isolation.host_memory_bytes,
                    "crawler_reserve_bytes": isolation.crawler_reserve_bytes,
                    "storage_reserve_bytes": isolation.storage_reserve_bytes,
                    "os_reserve_bytes": isolation.os_reserve_bytes,
                },
                "crawler_terminated": false,
                "started_at": record_value(&now),
                "completed_at": record_value(&completed_at),
                "observed_latency_ms": latency_evidence,
                "latency_basis": "registered_monotonic_clock",
                "admission": admitted,
            }),
        )?;
        let decoded_bytes = serde_json::to_vec(record_value(&results))
            .map_err(|_| {
                fault(
                    "internal_error",
                    "accepted inference result could not be measured for admission",
                )
            })?
            .len() as u64;
        let settlement = validate(
            OUTPUT_SCHEMA,
            json!({
                "kind": "inference_result_receipt",
                "run_id": run_id,
                "batch_id": batch_id,
                "submitted_count": submitted,
                "accepted_count": accepted,
                "decoded_bytes": decoded_bytes,
                "memory": memory_evidence,
                "completed_at": record_value(&completed_at),
            }),
        )?;
        self.admission.settle_response(credit, &settlement)?;
        Ok(results)
    }

    fn containment_events(&self) -> Result<CheckedRecord, Fault> {
        let state = self.lock_state()?;
        let latest = state.events.back().cloned().unwrap_or_else(|| {
            missing(
                "not_observed",
                "no containment event has been recorded by this host",
            )
        });
        validate(
            OUTPUT_SCHEMA,
            json!({
                "kind": "inference_containment_events",
                "crawler_terminated": false,
                "total_events": state.total_events,
                "retained_events": state.events.len() as u64,
                "retention_bound": self.config.containment_evidence_bound,
                "events": Value::Array(state.events.iter().cloned().collect()),
                "latest": latest,
            }),
        )
    }
}
