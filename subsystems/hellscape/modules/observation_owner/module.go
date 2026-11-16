// Package observation_owner implements the Hellscape observation-owner surface.
//
// The observation owner holds the observation journal: it admits telemetry
// producer deliveries through an ingestion authority, tracks per-producer
// sequence completeness (gaps, overflow, flush, closure), journals manual
// operator notes with manual provenance, and publishes closed observation
// axis revisions with frozen close-time knowledge.
//
// Boundaries honored by this module:
//
//   - One owner durability boundary: every mutation touches only the store
//     passed to NewTelemetryHandler / InitializeObservation /
//     RecordManualNote / CloseObservationWindow. No commit acquires a
//     peer-owned write lock or spans two databases.
//   - EK-PROVENANCE: untrusted callers submit EventSubmission (producer
//     sequence, event kind/version, occurrence time, payload) only. The
//     authority assigns event ID, journal sequence, provenance, owner
//     domain, role, assertion kind, receipt time, evidence scope, manifest
//     hash, and chain hashes. Caller-supplied authority fields are rejected.
//   - EK-OBSERVATION: (producer_id, producer_sequence) deliveries deduplicate
//     identical repeats without duplicating effects. Conflicting content
//     under that key is an integrity incident, not last-write-wins. Gaps,
//     overflow, loss, flush receipts, and producer closure are tracked. A
//     closed HTTP connection is never producer completeness or execution
//     termination.
//   - EK-MANUAL: manual notes retain manual provenance and disclosed
//     assistance. An operator note alone cannot set an authoritative
//     business predicate (submission, identity, commitment).
//   - OWD-SESSION: observation never sets accepted data, identity
//     verification, or commitment. Telemetry event kinds that assert
//     application authority are rejected.
//   - LIFE-CLOSE / LIFE-LATE-EVIDENCE: closure freezes knowledge and pins.
//     Late evidence appends at the current journal head and creates a new
//     observation revision without rewriting close-time knowledge.
//   - No in-band nulls: absent values are typed Missing envelopes. Empty
//     arrays mean established empty collections.
package observation_owner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"authority"
	"clock_rules"
	"evidence_codec"
	"evidence_import"
	"lifecycle_rules"
	"owner_store"
)

// ---------------------------------------------------------------------------
// Shared types.
// ---------------------------------------------------------------------------

type (
	// OwnerStore is the owner-local durable boundary (one SQLite database
	// plus one content-addressed artifact root).
	OwnerStore = owner_store.OwnerStore
	// Manifest is the admitted observation journal manifest.
	Manifest = owner_store.Manifest
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = owner_store.EvidenceRef
	// EventSubmission is the untrusted ingress shape (no authority fields).
	EventSubmission = owner_store.EventSubmission
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = owner_store.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = owner_store.JournalPrefix
	// ArtifactReference is an immutable byte identity plus metadata.
	ArtifactReference = owner_store.ArtifactReference
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = owner_store.TimePoint
	// ClockDescriptor registers one clock lifetime.
	ClockDescriptor = owner_store.ClockDescriptor
	// Measurement is the EK Measurement record carried in payloads.
	Measurement = owner_store.Measurement
	// Missing is a typed EK Missing envelope.
	Missing = owner_store.MissingEnvelope
	// AttemptReference identifies one attempt and kind.
	AttemptReference = lifecycle_rules.AttemptReference
	// AttemptCommission freezes the attempt identity and owner bindings.
	AttemptCommission = lifecycle_rules.AttemptCommission
	// AxisRevision is one complete immutable axis publication.
	AxisRevision = lifecycle_rules.AxisRevision
)

// EntityRegistration is the immutable, authenticated registration of a
// Hellscape session entity. Identity and owners ride as JSON-compatible
// objects; this module checks only the fields that gate observation
// admission. Producer/run identity derives from authenticated registration,
// never from request payload principals.
type EntityRegistration struct {
	RecordType     string         `json:"record_type"`
	SchemaVersion  string         `json:"schema_version"`
	RegistrationID string         `json:"registration_id"`
	Entity         map[string]any `json:"entity"`
	Identity       map[string]any `json:"identity"`
	Owners         map[string]any `json:"owners"`
	EvidencePrefix JournalPrefix  `json:"evidence_prefix"`
	EvidenceRefs   []EvidenceRef  `json:"evidence_refs"`
}

// Sentinel errors.
var (
	ErrInvalid           = errors.New("observation_owner: invalid input")
	ErrUnauthorized      = errors.New("observation_owner: unauthorized")
	ErrUnknownAttempt    = errors.New("observation_owner: unknown attempt")
	ErrIntegrityIncident = errors.New("observation_owner: integrity incident")
)

// Compile-time CONSUMES linkage. These references fail compilation if the
// declared upstream signatures disappear.
var (
	_ = evidence_import.ImportSourcePrefix
	_ = owner_store.CommitOwner
	_ = owner_store.LoadPrefix
	_ = lifecycle_rules.ValidateAxisTransition
	_ = clock_rules.ValidateMeasurement
	_ = authority.Authenticate
	_ = authority.Authorize
)

// Owner-local journal event kinds emitted or accepted by this module.
const (
	eventInit           = "observation_opened"
	eventClose          = "observation_closed"
	eventFlush          = "producer_flush"
	eventClosure        = "producer_closure"
	eventTransportClose = "transport_close"
	eventIncident       = "integrity_incident"
	eventManual         = "manual_note"
	eventOverflow       = "producer_overflow"
)

// Observation owner domain used for Authorize. The store's own domain
// authorizes the underlying owner_store operations via the same context.
const ownerDomain = "observation"

// maxRequestBytes bounds one admitted HTTP request body.
const maxRequestBytes = 4 << 20

// allowedSubmissionKeys is the closed EventSubmission shape accepted from
// untrusted ingress (seam 7.1). Any other top-level key is rejected; server
// authority fields are never trusted.
var allowedSubmissionKeys = map[string]bool{
	"producer_sequence":    true,
	"event_kind":           true,
	"event_schema_version": true,
	"occurred_at":          true,
	"payload":              true,
}

// serverFieldKeys are authority-assigned envelope fields that must never
// appear in untrusted submissions. They are a subset of the rejected
// unknown keys, reported distinctly for diagnostics.
var serverFieldKeys = map[string]bool{
	"event_id": true, "event_hash": true, "previous_event_hash": true,
	"chain_hash": true, "chain_hashes": true, "provenance": true,
	"owner_domain": true, "role": true, "assertion_kind": true,
	"receipt_time": true, "recorded_at": true, "manifest_hash": true,
	"evidence_scope": true, "journal_sequence": true, "sequence": true,
	"journal_id": true, "run_id": true, "producer_id": true,
	"record_type": true, "schema_version": true, "causal_refs": true,
}

// forbiddenTelemetryKinds are event kinds the observation/telemetry surface
// must never emit: application-authoritative effects (submission, identity,
// workflow, upload, validation, seal, origin facts) and server-lifecycle
// kinds forged by clients (manifest, open/close, flush/closure, incident).
var forbiddenTelemetryKinds = map[string]bool{
	"submission_committed": true, "identity_verified": true,
	"application_committed": true, "workflow_transition": true,
	"upload_stored": true, "validation_accepted": true,
	"validation_rejected": true, "validation_superseded": true,
	"request_completed": true, "request_rejected": true,
	"fixture_seal": true, "origin_fact": true,
	"commitment_asserted": true, "commitment": true,
	"application_truth": true,
	"manifest_admitted": true, "observation_opened": true,
	"observation_closed": true, "integrity_incident": true,
	"producer_flush": true, "producer_closure": true,
	"transport_close": true, "connection_close": true,
}

// forbiddenBusinessKeys are top-level payload data keys that assert an
// authoritative business predicate. Manual notes and telemetry data must
// never set them.
var forbiddenBusinessKeys = map[string]bool{
	"committed": true, "not_committed": true, "verified": true,
	"submission_committed": true, "identity_verified": true,
	"commitment": true, "application_truth": true,
	"business_predicate": true, "accepted_data": true,
	"identity_verification": true,
}

var validNullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

var validOrigins = map[string]bool{
	"engine_measured": true, "browser_measured": true,
	"subject_reported": true, "manual_reference": true,
}

// ---------------------------------------------------------------------------
// Runtime registry.
// ---------------------------------------------------------------------------

// observationRuntime is the owner-local live state for one observation
// journal: the admitted manifest, window coordinates, journal head, and the
// cumulative observation publication history. Producer completeness is always
// derived from the retained journal, never cached as truth.
type observationRuntime struct {
	manifest       Manifest
	registration   EntityRegistration
	journalID      string
	attemptID      string
	windowID       string
	ownerDomain    string
	producerID     string
	openedAt       TimePoint
	activeDeadline TimePoint
	head           JournalPrefix
	history        []AxisRevision
}

var (
	registryMu        sync.Mutex
	registryByJournal = map[string]*observationRuntime{}
	registryByAttempt = map[string]*observationRuntime{}
)

func registryKey(store *OwnerStore, id string) string {
	return fmt.Sprintf("%p/%s", store, id)
}

func lookupByJournal(store *OwnerStore, journalID string) (*observationRuntime, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	rt, ok := registryByJournal[registryKey(store, journalID)]
	return rt, ok
}

func lookupByAttempt(store *OwnerStore, attemptID string) (*observationRuntime, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	rt, ok := registryByAttempt[registryKey(store, attemptID)]
	return rt, ok
}

func registerRuntime(store *OwnerStore, rt *observationRuntime) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registryByJournal[registryKey(store, rt.journalID)] = rt
	registryByAttempt[registryKey(store, rt.attemptID)] = rt
}

func updateHead(store *OwnerStore, rt *observationRuntime, head JournalPrefix) {
	registryMu.Lock()
	defer registryMu.Unlock()
	rt.head = head
}

func appendHistory(store *OwnerStore, rt *observationRuntime, rev AxisRevision) {
	registryMu.Lock()
	defer registryMu.Unlock()
	rt.history = append(rt.history, rev)
}

// ---------------------------------------------------------------------------
// Small JSON helpers.
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"reason":"encode_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(raw)
}

func writeError(w http.ResponseWriter, code int, reason, detail string) {
	writeJSON(w, code, map[string]any{"reason": reason, "detail": detail})
}

func artifactRefMap(ref ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

func validDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hexPart := s[len(prefix):]
	if len(hexPart) != 64 {
		return false
	}
	for i := range hexPart {
		c := hexPart[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func nestedString(obj map[string]any, path ...string) string {
	var cur any = obj
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

// asMissing detects a Missing envelope in struct or generic-map form.
func asMissing(v any) (Missing, bool) {
	switch t := v.(type) {
	case Missing:
		if t.Value != nil {
			return Missing{}, false
		}
		if !validNullReasons[t.Reason] {
			return Missing{}, false
		}
		return t, true
	case *Missing:
		if t == nil {
			return Missing{}, false
		}
		return asMissing(*t)
	case map[string]any:
		raw, ok := t["value"]
		if !ok || raw != nil {
			return Missing{}, false
		}
		r, _ := t["reason"].(string)
		if !validNullReasons[r] {
			return Missing{}, false
		}
		detail := ""
		if d, ok := t["detail"].(string); ok {
			detail = d
		} else if d, ok := t["Detail"].(string); ok {
			detail = d
		}
		return Missing{Value: nil, Reason: r, Detail: detail}, true
	default:
		return Missing{}, false
	}
}

// producerSeqInt extracts an integer producer sequence. Missing and
// non-integer values report ok=false.
func producerSeqInt(v any) (int64, bool) {
	if v == nil {
		return 0, false
	}
	if _, ok := asMissing(v); ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		if n < 0 {
			return 0, false
		}
		return int64(n), true
	case int32:
		if n < 0 {
			return 0, false
		}
		return int64(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return n, true
	case uint:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > uint64(1<<63-1) {
			return 0, false
		}
		return int64(n), true
	case float64:
		if n != float64(int64(n)) || n < 0 {
			return 0, false
		}
		return int64(n), true
	case float32:
		f := float64(n)
		if f != float64(int64(f)) || f < 0 {
			return 0, false
		}
		return int64(f), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 0 {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

// asTimePoint coerces a TimePoint in struct or generic-map form.
func asTimePoint(v any) (TimePoint, bool) {
	switch t := v.(type) {
	case TimePoint:
		return t, true
	case *TimePoint:
		if t == nil {
			return TimePoint{}, false
		}
		return *t, true
	case map[string]any:
		raw, err := json.Marshal(t)
		if err != nil {
			return TimePoint{}, false
		}
		var tp TimePoint
		if err := json.Unmarshal(raw, &tp); err != nil {
			return TimePoint{}, false
		}
		if strings.TrimSpace(tp.ClockID) == "" || strings.TrimSpace(tp.BootID) == "" {
			return TimePoint{}, false
		}
		return tp, true
	default:
		return TimePoint{}, false
	}
}

// ---------------------------------------------------------------------------
// Producer completeness.
// ---------------------------------------------------------------------------

// SequenceRange is an inclusive producer sequence interval.
type SequenceRange struct {
	First int64 `json:"first"`
	Last  int64 `json:"last"`
}

// ProducerCompleteness records per-producer journal completeness over the
// retained prefix: producer ID, state, observed/missing ranges, evidenced
// final sequence, and support references. Complete requires an evidenced
// final sequence and no unresolved gap.
type ProducerCompleteness struct {
	ProducerID     string         `json:"producer_id"`
	State          string         `json:"state"`
	ObservedRanges []SequenceRange `json:"observed_ranges"`
	MissingRanges  []SequenceRange `json:"missing_ranges"`
	FinalSequence  any            `json:"final_sequence"`
	EvidenceRefs   []EvidenceRef  `json:"evidence_refs"`
}

// rangesForObserved builds merged observed ranges and missing gaps over
// 1..max(observed) for the given sequences.
func rangesForObserved(seqs []int64) (observed, missing []SequenceRange) {
	observed = []SequenceRange{}
	missing = []SequenceRange{}
	if len(seqs) == 0 {
		return observed, missing
	}
	sorted := append([]int64(nil), seqs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	// Deduplicate (journal uniqueness guarantees this, but be safe).
	dedup := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			dedup = append(dedup, s)
		}
	}
	sorted = dedup
	// Observed merged ranges.
	start, prev := sorted[0], sorted[0]
	for _, s := range sorted[1:] {
		if s == prev+1 {
			prev = s
			continue
		}
		observed = append(observed, SequenceRange{First: start, Last: prev})
		start, prev = s, s
	}
	observed = append(observed, SequenceRange{First: start, Last: prev})
	// Missing gaps over 1..max.
	max := sorted[len(sorted)-1]
	present := map[int64]bool{}
	for _, s := range sorted {
		present[s] = true
	}
	var gapStart int64 = -1
	for s := int64(1); s <= max; s++ {
		if !present[s] {
			if gapStart == -1 {
				gapStart = s
			}
			continue
		}
		if gapStart != -1 {
			missing = append(missing, SequenceRange{First: gapStart, Last: s - 1})
			gapStart = -1
		}
	}
	if gapStart != -1 {
		missing = append(missing, SequenceRange{First: gapStart, Last: max})
	}
	return observed, missing
}

// missingRangesForFinal builds missing ranges over 1..final given observed.
func missingRangesForFinal(seqs []int64, final int64) []SequenceRange {
	out := []SequenceRange{}
	if final < 1 {
		return out
	}
	present := map[int64]bool{}
	for _, s := range seqs {
		present[s] = true
	}
	var gapStart int64 = -1
	for s := int64(1); s <= final; s++ {
		if !present[s] {
			if gapStart == -1 {
				gapStart = s
			}
			continue
		}
		if gapStart != -1 {
			out = append(out, SequenceRange{First: gapStart, Last: s - 1})
			gapStart = -1
		}
	}
	if gapStart != -1 {
		out = append(out, SequenceRange{First: gapStart, Last: final})
	}
	return out
}

// finalSequenceFromData extracts an evidenced final sequence from flush or
// closure payload data. Missing/absent reports found=false.
func finalSequenceFromData(data map[string]any) (int64, bool) {
	if data == nil {
		return 0, false
	}
	v, ok := data["final_sequence"]
	if !ok || v == nil {
		return 0, false
	}
	if _, isMissing := asMissing(v); isMissing {
		return 0, false
	}
	// Nested map Missing (e.g. after JSON round trip) is handled above.
	if seq, ok := producerSeqInt(v); ok {
		return seq, true
	}
	return 0, false
}

// assessFromEnvelopes derives producer completeness from retained journal
// events. Integer producer sequences are telemetry deliveries; Missing
// sequences carry ingestion-authority lifecycle (flush, closure, overflow,
// transport close, incidents).
func assessFromEnvelopes(producerID string, envelopes []JournalEnvelope) ProducerCompleteness {
	var seqs []int64
	var support []EvidenceRef
	var finalVal int64
	finalFound := false
	overflowFound := false
	for i := range envelopes {
		env := &envelopes[i]
		if seq, ok := producerSeqInt(env.ProducerSequence); ok {
			seqs = append(seqs, seq)
			support = append(support, EvidenceRef{
				JournalID: env.JournalID, Sequence: env.Sequence,
				EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
			})
			continue
		}
		switch env.EventKind {
		case eventFlush, eventClosure:
			if fv, ok := finalSequenceFromData(env.Payload.Data); ok {
				finalVal, finalFound = fv, true
				support = append(support, EvidenceRef{
					JournalID: env.JournalID, Sequence: env.Sequence,
					EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
				})
			} else {
				// Flush observed without terminal: support the flush, but
				// completeness stays unresolved.
				support = append(support, EvidenceRef{
					JournalID: env.JournalID, Sequence: env.Sequence,
					EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
				})
			}
		case eventOverflow:
			overflowFound = true
			support = append(support, EvidenceRef{
				JournalID: env.JournalID, Sequence: env.Sequence,
				EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
			})
		case eventTransportClose, "connection_close":
			support = append(support, EvidenceRef{
				JournalID: env.JournalID, Sequence: env.Sequence,
				EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
			})
		}
	}
	observed, missing := rangesForObserved(seqs)
	if support == nil {
		support = []EvidenceRef{}
	}
	var finalAny any = owner_store.NewMissing("not_observed")
	state := "unknown"
	switch {
	case overflowFound:
		// Overflow records loss; never claim completeness.
		state = "incomplete"
		if finalFound {
			finalAny = finalVal
			// Recompute missing against the evidenced final so the tail
			// beyond the observed max is visible.
			if finalVal > 0 {
				missing = missingRangesForFinal(seqs, finalVal)
			}
		}
	case finalFound:
		finalAny = finalVal
		switch {
		case finalVal == 0:
			if len(seqs) == 0 {
				state = "complete"
				observed = []SequenceRange{}
				missing = []SequenceRange{}
			} else {
				state = "incomplete"
			}
		case finalVal > 0:
			missing = missingRangesForFinal(seqs, finalVal)
			if len(missing) == 0 {
				// No unresolved gap and evidenced final: complete. Also
				// require the observed max to equal the final (no events
				// beyond the terminal sequence).
				maxObs := int64(0)
				for _, s := range seqs {
					if s > maxObs {
						maxObs = s
					}
				}
				if maxObs == finalVal {
					state = "complete"
				} else {
					state = "incomplete"
				}
			} else {
				state = "incomplete"
			}
		default:
			state = "incomplete"
		}
	default:
		if len(seqs) == 0 {
			state = "unknown"
		} else {
			state = "incomplete"
		}
	}
	if observed == nil {
		observed = []SequenceRange{}
	}
	if missing == nil {
		missing = []SequenceRange{}
	}
	return ProducerCompleteness{
		ProducerID: producerID, State: state,
		ObservedRanges: observed, MissingRanges: missing,
		FinalSequence: finalAny, EvidenceRefs: support,
	}
}

// AssessProducerCompleteness derives the current producer completeness for
// one observation journal from the retained prefix.
func AssessProducerCompleteness(ctx context.Context, store *OwnerStore, journalID string) (ProducerCompleteness, error) {
	var zero ProducerCompleteness
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if strings.TrimSpace(journalID) == "" {
		return zero, fmt.Errorf("%w: journal_id is required", ErrInvalid)
	}
	rt, ok := lookupByJournal(store, journalID)
	if !ok {
		return zero, fmt.Errorf("%w: journal %q", ErrUnknownAttempt, journalID)
	}
	if err := authority.Authorize(ctx, ownerDomain, "read", journalID); err != nil {
		return zero, fmt.Errorf("%w: assess: %v", ErrUnauthorized, err)
	}
	evidence, err := owner_store.LoadPrefix(ctx, store, rt.head)
	if err != nil {
		return zero, fmt.Errorf("observation_owner: load prefix: %w", err)
	}
	return assessFromEnvelopes(rt.producerID, evidence), nil
}

// ---------------------------------------------------------------------------
// Measurement validation (clock_rules CONSUMES).
// ---------------------------------------------------------------------------

func toClockRulesClock(cd ClockDescriptor) clock_rules.ClockDescriptor {
	return clock_rules.ClockDescriptor{
		ClockID: cd.ClockID, BootID: cd.BootID, Origin: cd.Origin,
		SourceID: cd.SourceID, Basis: cd.Basis, Unit: cd.Unit,
	}
}

func toClockRulesMissing(m Missing) clock_rules.Missing {
	return clock_rules.Missing{Reason: m.Reason, Detail: m.Detail}
}

func convertUTCAnnotation(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is an in-band null: use a typed Missing envelope", field)
	}
	if s, ok := v.(string); ok {
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			return nil, fmt.Errorf("%s is not a valid date-time %q", field, s)
		}
		return s, nil
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	return nil, fmt.Errorf("%s must be a date-time annotation or Missing, got %T", field, v)
}

func convertEndpoint(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is an in-band null: use TimePoint or Missing", field)
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	tp, ok := asTimePoint(v)
	if !ok {
		return nil, fmt.Errorf("%s must be a TimePoint or Missing, got %T", field, v)
	}
	utc, err := convertUTCAnnotation(tp.UTCAnnotation, field+".utc_annotation")
	if err != nil {
		return nil, err
	}
	return clock_rules.TimePoint{
		ClockID: tp.ClockID, BootID: tp.BootID, Origin: tp.Origin,
		MonotonicOffsetMs: tp.MonotonicOffsetMs, UTCAnnotation: utc,
	}, nil
}

func convertNumberOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is an in-band null: use a number or Missing", field)
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	switch v.(type) {
	case float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, json.Number:
		return v, nil
	default:
		return nil, fmt.Errorf("%s must be numeric or Missing, got %T", field, v)
	}
}

func convertStringOrMissing(v any, field string) (any, error) {
	if v == nil {
		return nil, fmt.Errorf("%s is an in-band null: use a string or Missing", field)
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	if m, ok := asMissing(v); ok {
		return toClockRulesMissing(m), nil
	}
	return nil, fmt.Errorf("%s must be a string or Missing, got %T", field, v)
}

func convertEstimate(e owner_store.Measurement, field string) (clock_rules.Estimate, error) {
	// owner_store.Measurement embeds journal Estimate with Kind/Value/Bounds.
	raw, err := json.Marshal(e.Estimate)
	if err != nil {
		return clock_rules.Estimate{}, err
	}
	var je struct {
		Kind       string `json:"kind"`
		Value      any    `json:"value"`
		LowerBound any    `json:"lower_bound"`
		UpperBound any    `json:"upper_bound"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&je); err != nil {
		return clock_rules.Estimate{}, err
	}
	// Normalize absent bounds (JSON null from omitempty decoding): a nil
	// interface after decoding means absent for exact/unavailable.
	switch je.Kind {
	case "exact":
		if je.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("%s exact estimate needs a numeric value", field)
		}
		if je.LowerBound != nil || je.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("%s exact estimate must not carry bounds", field)
		}
		if _, ok := asMissing(je.Value); ok {
			return clock_rules.Estimate{}, fmt.Errorf("%s exact estimate value must be numeric", field)
		}
		val, err := convertNumberOrMissing(je.Value, field+".value")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		return clock_rules.Estimate{Kind: je.Kind, Value: val}, nil
	case "bounded":
		if je.Value != nil {
			return clock_rules.Estimate{}, fmt.Errorf("%s bounded estimate must not carry a value", field)
		}
		var lo, hi any
		if je.LowerBound != nil {
			lo, err = convertNumberOrMissing(je.LowerBound, field+".lower_bound")
			if err != nil {
				return clock_rules.Estimate{}, err
			}
		}
		if je.UpperBound != nil {
			hi, err = convertNumberOrMissing(je.UpperBound, field+".upper_bound")
			if err != nil {
				return clock_rules.Estimate{}, err
			}
		}
		return clock_rules.Estimate{Kind: je.Kind, LowerBound: lo, UpperBound: hi}, nil
	case "unavailable":
		if je.Value == nil {
			return clock_rules.Estimate{}, fmt.Errorf("%s unavailable estimate needs a Missing value", field)
		}
		if je.LowerBound != nil || je.UpperBound != nil {
			return clock_rules.Estimate{}, fmt.Errorf("%s unavailable estimate must not carry bounds", field)
		}
		if _, ok := asMissing(je.Value); !ok {
			return clock_rules.Estimate{}, fmt.Errorf("%s unavailable estimate value must be Missing", field)
		}
		val, err := convertNumberOrMissing(je.Value, field+".value")
		if err != nil {
			return clock_rules.Estimate{}, err
		}
		return clock_rules.Estimate{Kind: je.Kind, Value: val}, nil
	default:
		return clock_rules.Estimate{}, fmt.Errorf("%s has invalid estimate kind %q", field, je.Kind)
	}
}

func toClockRulesMeasurement(m Measurement, field string) (clock_rules.Measurement, error) {
	start, err := convertEndpoint(m.Start, field+".start")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	end, err := convertEndpoint(m.End, field+".end")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	res, err := convertNumberOrMissing(m.Resolution, field+".resolution")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	cg, err := convertStringOrMissing(m.ComparabilityGroup, field+".comparability_group")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	est, err := convertEstimate(m, field+".estimate")
	if err != nil {
		return clock_rules.Measurement{}, err
	}
	return clock_rules.Measurement{
		MeasurementID: m.MeasurementID, Name: m.Name,
		Scope: clock_rules.Scope{Kind: m.Scope.Kind, ID: m.Scope.ID},
		Quantity: m.Quantity, Unit: m.Unit, Origin: m.Origin,
		ClockID: m.ClockID, BootID: m.BootID, Method: m.Method,
		Start: start, End: end, Estimate: est, Resolution: res,
		Censoring: m.Censoring, ComparabilityGroup: cg,
		AggregateSource: m.AggregateSource,
	}, nil
}

// validateMeasurements enforces clock_rules timing semantics for every
// measurement carried in a telemetry or manual payload.
func validateMeasurements(measurements []Measurement, clocks []ClockDescriptor, field string) error {
	if len(measurements) == 0 {
		return nil
	}
	converted := make([]clock_rules.ClockDescriptor, 0, len(clocks))
	for _, cd := range clocks {
		converted = append(converted, toClockRulesClock(cd))
	}
	for i, m := range measurements {
		cm, err := toClockRulesMeasurement(m, fmt.Sprintf("%s[%d].measurement", field, i))
		if err != nil {
			return err
		}
		if err := clock_rules.ValidateMeasurement(cm, converted); err != nil {
			return fmt.Errorf("%s[%d]: %v", field, i, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// InitializeObservation.
// ---------------------------------------------------------------------------

// InitializeObservation admits one observation journal for the commissioned
// attempt: it installs the canonical manifest, commits the admission and
// observation-opened framing events with Missing producer sequences (leaving
// the integer producer namespace free for telemetry), and registers the
// observation window. It returns the opened-event evidence reference.
func InitializeObservation(ctx context.Context, store *OwnerStore, manifest Manifest, registration EntityRegistration) (EvidenceRef, error) {
	var zero EvidenceRef
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	resource := registration.RegistrationID
	if strings.TrimSpace(resource) == "" {
		resource = manifest.RunID
	}
	if err := authority.Authorize(ctx, ownerDomain, "write", resource); err != nil {
		return zero, fmt.Errorf("%w: initialize: %v", ErrUnauthorized, err)
	}
	if manifest.RecordType != "manifest" {
		return zero, fmt.Errorf("%w: manifest record_type must be manifest, got %q", ErrInvalid, manifest.RecordType)
	}
	if manifest.SchemaVersion != "0.1.0" && manifest.SchemaVersion != "1.0" && manifest.SchemaVersion != "1.0.0" {
		return zero, fmt.Errorf("%w: manifest schema_version %q is unknown", ErrInvalid, manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.ManifestID) == "" ||
		strings.TrimSpace(manifest.RunID) == "" ||
		strings.TrimSpace(manifest.JournalID) == "" ||
		strings.TrimSpace(manifest.OwnerDomain) == "" {
		return zero, fmt.Errorf("%w: manifest must name manifest_id, run_id, journal_id, and owner_domain", ErrInvalid)
	}
	if len(manifest.Clocks) == 0 {
		return zero, fmt.Errorf("%w: manifest must register at least one clock", ErrInvalid)
	}
	for i, cd := range manifest.Clocks {
		if strings.TrimSpace(cd.ClockID) == "" || strings.TrimSpace(cd.BootID) == "" {
			return zero, fmt.Errorf("%w: manifest.clocks[%d] must name clock_id and boot_id", ErrInvalid, i)
		}
		if !validOrigins[cd.Origin] {
			return zero, fmt.Errorf("%w: manifest.clocks[%d] origin %q is invalid", ErrInvalid, i, cd.Origin)
		}
		if strings.TrimSpace(cd.SourceID) == "" || strings.TrimSpace(cd.Basis) == "" || strings.TrimSpace(cd.Unit) == "" {
			return zero, fmt.Errorf("%w: manifest.clocks[%d] must name source_id, basis, and unit", ErrInvalid, i)
		}
	}
	if registration.RecordType != "write_domain_entity" {
		return zero, fmt.Errorf("%w: registration record_type must be write_domain_entity, got %q", ErrInvalid, registration.RecordType)
	}
	if strings.TrimSpace(registration.RegistrationID) == "" {
		return zero, fmt.Errorf("%w: registration_id is required", ErrInvalid)
	}
	entityType := nestedString(registration.Entity, "entity_type")
	if entityType != "hellscape_session" && entityType != "observation_attempt" && entityType != "application_attempt" {
		return zero, fmt.Errorf("%w: registration entity_type %q is not a Hellscape session", ErrInvalid, entityType)
	}
	if runID := nestedString(registration.Identity, "run_id"); runID != "" && runID != manifest.RunID {
		return zero, fmt.Errorf("%w: registration run_id %q does not match manifest %q", ErrInvalid, runID, manifest.RunID)
	}
	if journalID := nestedString(registration.Identity, "journal_id"); journalID != "" && journalID != manifest.JournalID {
		return zero, fmt.Errorf("%w: registration journal_id %q does not match manifest %q", ErrInvalid, journalID, manifest.JournalID)
	}

	attemptID := manifest.RunID
	journalID := manifest.JournalID
	if _, exists := lookupByJournal(store, journalID); exists {
		return zero, fmt.Errorf("%w: journal %q is already initialized", ErrInvalid, journalID)
	}
	if _, exists := lookupByAttempt(store, attemptID); exists {
		return zero, fmt.Errorf("%w: attempt %q is already initialized", ErrInvalid, attemptID)
	}

	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot encode journal manifest: %v", ErrInvalid, err)
	}
	canonicalManifest, err := evidence_codec.CanonicalJSON(rawManifest, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize journal manifest: %v", ErrInvalid, err)
	}
	manifestRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalManifest), "application/json", "public")
	if err != nil {
		return zero, fmt.Errorf("observation_owner: install journal manifest: %w", err)
	}

	clock := manifest.Clocks[0]
	windowID := "window-" + attemptID
	producerID := journalID
	openedAt := TimePoint{
		ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
		MonotonicOffsetMs: 0, UTCAnnotation: owner_store.NewMissing("not_applicable"),
	}

	admission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt: TimePoint{
			ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
			MonotonicOffsetMs: 0, UTCAnnotation: owner_store.NewMissing("not_applicable"),
		},
		Payload: owner_store.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(manifestRef)},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{manifestRef},
		},
	}
	initEvent := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventInit,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"attempt_id":  attemptID,
				"window_id":   windowID,
				"producer_id": producerID,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, []EventSubmission{admission, initEvent}, nil)
	if err != nil {
		return zero, fmt.Errorf("observation_owner: commit initialization: %w", err)
	}
	if len(envelopes) != 2 {
		return zero, fmt.Errorf("%w: initialization committed %d events, want 2", ErrInvalid, len(envelopes))
	}
	initEnv := envelopes[1]
	head := JournalPrefix{JournalID: journalID, LastSequence: initEnv.Sequence, HeadHash: initEnv.EventHash}
	initRef := EvidenceRef{JournalID: initEnv.JournalID, Sequence: initEnv.Sequence, EventID: initEnv.EventID, EventHash: initEnv.EventHash, Pointer: ""}

	registerRuntime(store, &observationRuntime{
		manifest:     manifest,
		registration: registration,
		journalID:    journalID,
		attemptID:    attemptID,
		windowID:     windowID,
		ownerDomain:  manifest.OwnerDomain,
		producerID:   producerID,
		openedAt:     openedAt,
		activeDeadline: TimePoint{
			ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
			MonotonicOffsetMs: 60000, UTCAnnotation: owner_store.NewMissing("not_applicable"),
		},
		head:    head,
		history: []AxisRevision{},
	})
	return initRef, nil
}

// ---------------------------------------------------------------------------
// RecordManualNote.
// ---------------------------------------------------------------------------

// RecordManualNote journals one human operator note with manual provenance.
// Notes retain manual provenance and disclosed assistance, and an operator
// note alone can never set an authoritative business predicate: event kinds
// or payload keys that assert submission, identity, or commitment are
// rejected. Manual framing uses a Missing producer sequence so operator
// notes never collide with the integer telemetry namespace.
func RecordManualNote(ctx context.Context, store *OwnerStore, attempt AttemptReference, note EventSubmission) (EvidenceRef, error) {
	var zero EvidenceRef
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if strings.TrimSpace(attempt.AttemptID) == "" {
		return zero, fmt.Errorf("%w: attempt_id is required", ErrInvalid)
	}
	if err := authority.Authorize(ctx, ownerDomain, "write", attempt.AttemptID); err != nil {
		return zero, fmt.Errorf("%w: manual note: %v", ErrUnauthorized, err)
	}
	rt, ok := lookupByAttempt(store, attempt.AttemptID)
	if !ok {
		return zero, fmt.Errorf("%w: attempt %q", ErrUnknownAttempt, attempt.AttemptID)
	}
	if strings.TrimSpace(note.EventKind) == "" {
		return zero, fmt.Errorf("%w: event_kind is required", ErrInvalid)
	}
	if strings.TrimSpace(note.EventSchemaVersion) == "" {
		return zero, fmt.Errorf("%w: event_schema_version is required", ErrInvalid)
	}
	if note.ProducerSequence == nil {
		return zero, fmt.Errorf("%w: producer_sequence is an in-band null: use an integer or typed Missing", ErrInvalid)
	}
	if note.OccurredAt == nil {
		return zero, fmt.Errorf("%w: occurred_at is an in-band null: use a TimePoint or typed Missing", ErrInvalid)
	}
	if forbiddenTelemetryKinds[note.EventKind] {
		return zero, fmt.Errorf("%w: manual note event_kind %q asserts authoritative or server-lifecycle semantics", ErrInvalid, note.EventKind)
	}
	data := note.Payload.Data
	if data == nil {
		data = map[string]any{}
	}
	for key := range data {
		if forbiddenBusinessKeys[key] {
			return zero, fmt.Errorf("%w: manual note data key %q asserts an authoritative business predicate", ErrInvalid, key)
		}
	}
	if err := validateMeasurements(note.Payload.Measurements, rt.manifest.Clocks, "manual_note.measurements"); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Retain manual provenance and disclosed assistance. The envelope
	// provenance is server-assigned; the manual origin rides in payload
	// data so human actions are never mistaken for automation subjects.
	manualData := make(map[string]any, len(data)+3)
	for k, v := range data {
		manualData[k] = v
	}
	manualData["provenance"] = "manual"
	if _, hasAssistance := manualData["assistance"]; !hasAssistance {
		manualData["assistance"] = "operator:disclosed"
	}
	manualData["recorded_by"] = "manual_recorder"

	submission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          note.EventKind,
		EventSchemaVersion: note.EventSchemaVersion,
		OccurredAt:         note.OccurredAt,
		Payload: owner_store.Payload{
			Data:         manualData,
			Measurements: note.Payload.Measurements,
			EvidenceRefs: note.Payload.EvidenceRefs,
			ArtifactRefs: note.Payload.ArtifactRefs,
		},
	}
	if submission.Payload.Measurements == nil {
		submission.Payload.Measurements = []Measurement{}
	}
	if submission.Payload.EvidenceRefs == nil {
		submission.Payload.EvidenceRefs = []EvidenceRef{}
	}
	if submission.Payload.ArtifactRefs == nil {
		submission.Payload.ArtifactRefs = []ArtifactReference{}
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, rt.journalID, []EventSubmission{submission}, nil)
	if err != nil {
		return zero, fmt.Errorf("observation_owner: commit manual note: %w", err)
	}
	if len(envelopes) != 1 {
		return zero, fmt.Errorf("%w: manual note committed %d events, want 1", ErrInvalid, len(envelopes))
	}
	env := envelopes[0]
	updateHead(store, rt, JournalPrefix{JournalID: env.JournalID, LastSequence: env.Sequence, HeadHash: env.EventHash})
	return EvidenceRef{JournalID: env.JournalID, Sequence: env.Sequence, EventID: env.EventID, EventHash: env.EventHash, Pointer: ""}, nil
}

// ---------------------------------------------------------------------------
// CloseObservationWindow.
// ---------------------------------------------------------------------------

// CloseObservationWindow publishes the closed observation axis revision over
// the retained prefix. The first close commits the observation-closed
// lifecycle event, freezes close-time knowledge (boundary reference,
// version pins, execution/application knowledge, limitations), and validates
// through lifecycle_rules. Later closes after late evidence append no new
// closure event; they publish a new revision with identical frozen closure
// fields and appended late-evidence references (closed-to-closed).
func CloseObservationWindow(ctx context.Context, store *OwnerStore, commission AttemptCommission, boundary EvidenceRef) (AxisRevision, error) {
	var zero AxisRevision
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if strings.TrimSpace(commission.Attempt.AttemptID) == "" {
		return zero, fmt.Errorf("%w: commission attempt_id is required", ErrInvalid)
	}
	if err := authority.Authorize(ctx, ownerDomain, "write", commission.Attempt.AttemptID); err != nil {
		return zero, fmt.Errorf("%w: close: %v", ErrUnauthorized, err)
	}
	journalID := commission.JournalID
	if strings.TrimSpace(journalID) == "" {
		return zero, fmt.Errorf("%w: commission journal_id is required", ErrInvalid)
	}
	if boundary.JournalID != journalID {
		return zero, fmt.Errorf("%w: boundary journal %q does not match commission journal %q", ErrInvalid, boundary.JournalID, journalID)
	}
	rt, ok := lookupByJournal(store, journalID)
	if !ok {
		// Fall back to attempt lookup (same runtime, alternate key).
		rt, ok = lookupByAttempt(store, commission.Attempt.AttemptID)
		if !ok {
			return zero, fmt.Errorf("%w: journal %q", ErrUnknownAttempt, journalID)
		}
		if rt.journalID != journalID {
			return zero, fmt.Errorf("%w: commission journal %q does not match attempt journal %q", ErrInvalid, journalID, rt.journalID)
		}
	}

	evidence, err := owner_store.LoadPrefix(ctx, store, rt.head)
	if err != nil {
		return zero, fmt.Errorf("observation_owner: load close evidence: %w", err)
	}
	boundaryFound := false
	for _, env := range evidence {
		if env.JournalID == boundary.JournalID && env.Sequence == boundary.Sequence &&
			env.EventID == boundary.EventID && env.EventHash == boundary.EventHash {
			boundaryFound = true
			break
		}
	}
	if !boundaryFound {
		return zero, fmt.Errorf("%w: boundary reference does not resolve against the retained prefix", ErrInvalid)
	}

	registryMu.Lock()
	historyLen := len(rt.history)
	var prevHistory []AxisRevision
	if historyLen > 0 {
		prevHistory = append([]AxisRevision(nil), rt.history...)
	}
	registryMu.Unlock()

	if historyLen == 0 {
		return closeFirstRevision(ctx, store, rt, commission, boundary, evidence)
	}
	return closeLateRevision(ctx, store, rt, commission, prevHistory, evidence)
}

func closeFirstRevision(ctx context.Context, store *OwnerStore, rt *observationRuntime, commission AttemptCommission, boundary EvidenceRef, evidence []JournalEnvelope) (AxisRevision, error) {
	var zero AxisRevision
	completeness := assessFromEnvelopes(rt.producerID, evidence)
	clock := rt.manifest.Clocks[0]
	closedAt := TimePoint{
		ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
		MonotonicOffsetMs: 61000, UTCAnnotation: owner_store.NewMissing("not_applicable"),
	}
	closureID := "closure-" + rt.attemptID
	limitations := []string{
		fmt.Sprintf("producer %s completeness at close: %s (observed %d ranges, missing %d ranges, terminal evidenced: %v)",
			rt.producerID, completeness.State, len(completeness.ObservedRanges), len(completeness.MissingRanges), completenessStateHasTerminal(completeness)),
		"close-time knowledge derives only from boundary-available evidence",
	}
	closeData := map[string]any{
		"closure_id":   closureID,
		"window_id":    rt.windowID,
		"attempt_id":   rt.attemptID,
		"close_reason": "normal_completion",
		"completeness": map[string]any{
			"state":          completeness.State,
			"observed_ranges": completeness.ObservedRanges,
			"missing_ranges":  completeness.MissingRanges,
		},
	}
	submission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventClose,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         closedAt,
		Payload: owner_store.Payload{
			Data:         closeData,
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{boundary},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, rt.journalID, []EventSubmission{submission}, nil)
	if err != nil {
		return zero, fmt.Errorf("observation_owner: commit close event: %w", err)
	}
	if len(envelopes) != 1 {
		return zero, fmt.Errorf("%w: close committed %d events, want 1", ErrInvalid, len(envelopes))
	}
	closeEnv := envelopes[0]
	newHead := JournalPrefix{JournalID: closeEnv.JournalID, LastSequence: closeEnv.Sequence, HeadHash: closeEnv.EventHash}
	updateHead(store, rt, newHead)
	fullEvidence, err := owner_store.LoadPrefix(ctx, store, newHead)
	if err != nil {
		return zero, fmt.Errorf("observation_owner: reload close evidence: %w", err)
	}
	closeRef := EvidenceRef{JournalID: closeEnv.JournalID, Sequence: closeEnv.Sequence, EventID: closeEnv.EventID, EventHash: closeEnv.EventHash, Pointer: ""}

	snapshot := lifecycle_rules.CloseSnapshot{
		ClosureID:   closureID,
		BoundaryRef: lifecycleEvidenceRef(boundary),
		KnownVersions: lifecycle_rules.CloseInputPins{
			Dispatch:    lifecycle_rules.DomainPin{Revision: 0, RecordDigest: lifecycle_rules.NewMissing("not_applicable")},
			Execution:   lifecycle_rules.DomainPin{Revision: 0, RecordDigest: lifecycle_rules.NewMissing("not_applicable")},
			Application: lifecycle_rules.DomainPin{Revision: 0, RecordDigest: lifecycle_rules.NewMissing("not_applicable")},
			Report:      lifecycle_rules.DomainPin{Revision: 0, RecordDigest: lifecycle_rules.NewMissing("not_applicable")},
		},
		ExecutionKnowledge:      "unknown",
		ExecutionEvidenceRefs:   []lifecycle_rules.EvidenceRef{},
		ApplicationKnowledge:    "unknown",
		ApplicationEvidenceRefs: []lifecycle_rules.EvidenceRef{},
		Limitations:             limitations,
	}
	value := lifecycle_rules.ObservationValue{
		State:               lifecycle_rules.ObsClosed,
		WindowID:            rt.windowID,
		OpenedAt:            rt.openedAt,
		ActiveDeadline:      rt.activeDeadline,
		DrainStartedAt:      lifecycle_rules.NewMissing("not_applicable"),
		DrainDeadline:       lifecycle_rules.NewMissing("not_applicable"),
		ClosedAt:            closedAt,
		CloseReason:         "normal_completion",
		AtClose:             snapshot,
		ControlObservations: []lifecycle_rules.ControlObservation{},
		LateEvidenceRefs:    []lifecycle_rules.EvidenceRef{},
		Measurements:        []lifecycle_rules.MeasurementEvidence{},
	}
	next, err := buildObservationRevision(commission, rt, nil, value, newHead, []EvidenceRef{closeRef})
	if err != nil {
		return zero, err
	}
	lifecycleEvidence := toLifecycleEvidence(fullEvidence)
	if err := lifecycle_rules.ValidateAxisTransition(commission, nil, next, lifecycleEvidence); err != nil {
		return zero, fmt.Errorf("observation_owner: close publication rejected: %w", err)
	}
	appendHistory(store, rt, next)
	return next, nil
}

func closeLateRevision(ctx context.Context, store *OwnerStore, rt *observationRuntime, commission AttemptCommission, history []AxisRevision, evidence []JournalEnvelope) (AxisRevision, error) {
	var zero AxisRevision
	prev := history[len(history)-1]
	prevVal, err := parseObservationValue(prev.Value)
	if err != nil {
		return zero, fmt.Errorf("%w: prior observation value is unreadable: %v", ErrInvalid, err)
	}
	// Late evidence: every retained event beyond the previous revision
	// prefix. Late appends never rewrite frozen closure fields.
	prevLast := prev.EvidencePrefix.LastSequence
	var newLate []lifecycle_rules.EvidenceRef
	for _, env := range evidence {
		if env.Sequence > prevLast {
			newLate = append(newLate, lifecycle_rules.EvidenceRef{
				JournalID: env.JournalID, Sequence: env.Sequence,
				EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
			})
		}
	}
	lateRefs := append([]lifecycle_rules.EvidenceRef(nil), prevVal.LateEvidenceRefs...)
	lateRefs = append(lateRefs, newLate...)

	value := lifecycle_rules.ObservationValue{
		State:               prevVal.State,
		WindowID:            prevVal.WindowID,
		OpenedAt:            prevVal.OpenedAt,
		ActiveDeadline:      prevVal.ActiveDeadline,
		DrainStartedAt:      prevVal.DrainStartedAt,
		DrainDeadline:       prevVal.DrainDeadline,
		ClosedAt:            prevVal.ClosedAt,
		CloseReason:         prevVal.CloseReason,
		AtClose:             prevVal.AtClose,
		ControlObservations: append([]lifecycle_rules.ControlObservation(nil), prevVal.ControlObservations...),
		LateEvidenceRefs:    lateRefs,
		Measurements:        append([]lifecycle_rules.MeasurementEvidence(nil), prevVal.Measurements...),
	}
	if value.ControlObservations == nil {
		value.ControlObservations = []lifecycle_rules.ControlObservation{}
	}
	if value.LateEvidenceRefs == nil {
		value.LateEvidenceRefs = []lifecycle_rules.EvidenceRef{}
	}
	if value.Measurements == nil {
		value.Measurements = []lifecycle_rules.MeasurementEvidence{}
	}
	// Support: the original close event plus all late evidence. The
	// original close ref is the first evidence ref of the first revision.
	support := append([]EvidenceRef(nil), evidenceRefFromLifecycle(prev.EvidenceRefs[0]) /* close event */)
	for _, r := range newLate {
		support = append(support, evidenceRefFromLifecycle(r))
	}
	// If for any reason the history head carries more support, preserve it.
	if len(prev.EvidenceRefs) > 1 {
		seen := map[string]bool{}
		for _, r := range support {
			seen[evidenceRefKey(r)] = true
		}
		for _, r := range prev.EvidenceRefs[1:] {
			converted := evidenceRefFromLifecycle(r)
			if !seen[evidenceRefKey(converted)] {
				support = append(support, converted)
				seen[evidenceRefKey(converted)] = true
			}
		}
	}
	registryMu.Lock()
	head := rt.head
	registryMu.Unlock()
	next, err := buildObservationRevision(commission, rt, history, value, head, support)
	if err != nil {
		return zero, err
	}
	lifecycleEvidence := toLifecycleEvidence(evidence)
	if err := lifecycle_rules.ValidateAxisTransition(commission, history, next, lifecycleEvidence); err != nil {
		return zero, fmt.Errorf("observation_owner: late publication rejected: %w", err)
	}
	appendHistory(store, rt, next)
	return next, nil
}

func completenessStateHasTerminal(c ProducerCompleteness) bool {
	if _, ok := producerSeqInt(c.FinalSequence); ok {
		return true
	}
	return false
}

func lifecycleEvidenceRef(r EvidenceRef) lifecycle_rules.EvidenceRef {
	return lifecycle_rules.EvidenceRef{
		JournalID: r.JournalID, Sequence: r.Sequence,
		EventID: r.EventID, EventHash: r.EventHash, Pointer: r.Pointer,
	}
}

func evidenceRefFromLifecycle(r lifecycle_rules.EvidenceRef) EvidenceRef {
	return EvidenceRef{
		JournalID: r.JournalID, Sequence: r.Sequence,
		EventID: r.EventID, EventHash: r.EventHash, Pointer: r.Pointer,
	}
}

func evidenceRefKey(r EvidenceRef) string {
	return r.JournalID + "\x00" + fmt.Sprintf("%d", r.Sequence) + "\x00" + r.EventID + "\x00" + r.EventHash
}

func toLifecycleEvidence(in []JournalEnvelope) []lifecycle_rules.JournalEnvelope {
	out := make([]lifecycle_rules.JournalEnvelope, len(in))
	for i := range in {
		raw, err := json.Marshal(in[i])
		if err != nil {
			continue
		}
		var converted lifecycle_rules.JournalEnvelope
		if err := json.Unmarshal(raw, &converted); err != nil {
			continue
		}
		out[i] = converted
	}
	return out
}

func parseObservationValue(v any) (lifecycle_rules.ObservationValue, error) {
	var out lifecycle_rules.ObservationValue
	raw, err := json.Marshal(v)
	if err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var mid any
	if err := dec.Decode(&mid); err != nil {
		return out, err
	}
	remarshaled, err := json.Marshal(mid)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(remarshaled, &out); err != nil {
		return out, err
	}
	return out, nil
}

func buildObservationRevision(commission AttemptCommission, rt *observationRuntime, history []AxisRevision, value lifecycle_rules.ObservationValue, prefix JournalPrefix, support []EvidenceRef) (AxisRevision, error) {
	var zero AxisRevision
	rawCommission, err := json.Marshal(commission)
	if err != nil {
		return zero, fmt.Errorf("observation_owner: encode commission: %w", err)
	}
	canonicalCommission, err := evidence_codec.CanonicalJSON(rawCommission, "application/json")
	if err != nil {
		return zero, fmt.Errorf("observation_owner: canonicalize commission: %w", err)
	}
	commissionDigest := string(evidence_codec.HashBytes(canonicalCommission))
	ownerDomain, _ := commission.Owners.Observation.OwnerDomain, true
	writerID, ok := commission.Owners.Observation.WriterID.(string)
	if !ok || strings.TrimSpace(writerID) == "" {
		// The lifecycle gate reports the precise binding error; produce a
		// revision that fails closed with the same signal.
		return zero, fmt.Errorf("%w: commission owners.observation writer_id must be an identifier", ErrInvalid)
	}
	lifecyclePrefix := lifecycle_rules.JournalPrefix{
		JournalID: prefix.JournalID, LastSequence: prefix.LastSequence, HeadHash: prefix.HeadHash,
	}
	lifecycleSupport := make([]lifecycle_rules.EvidenceRef, 0, len(support))
	for _, r := range support {
		lifecycleSupport = append(lifecycleSupport, lifecycleEvidenceRef(r))
	}
	revision := int64(len(history) + 1)
	next := AxisRevision{
		RecordType:       lifecycle_rules.RecordAxis,
		SchemaVersion:    lifecycle_rules.SchemaLifecycle,
		Attempt:          AttemptReference{AttemptID: commission.Attempt.AttemptID, Kind: commission.Attempt.Kind},
		CommissionDigest: commissionDigest,
		Axis:             lifecycle_rules.AxisObservation,
		OwnerDomain:      ownerDomain,
		WriterID:         writerID,
		Revision:         revision,
		PreviousRevision: revision - 1,
		EvidencePrefix:   lifecyclePrefix,
		EvidenceRefs:     lifecycleSupport,
		Value:            value,
	}
	_ = rt
	return next, nil
}

// ---------------------------------------------------------------------------
// Telemetry HTTP handler.
// ---------------------------------------------------------------------------

type telemetryHandler struct {
	store *OwnerStore
}

// NewTelemetryHandler serves the observation-owner telemetry surface for one
// owner store. The handler authorizes every operation against the principal
// in the request context (upstream middleware authenticates the channel).
//
// Routes (all require ?journal_id=):
//
//	POST /telemetry          single EventSubmission ingress
//	POST /telemetry/batch    batched EventSubmission ingress (atomic)
//	POST /flush              record a producer flush receipt
//	POST /connection/close   record transport closure (never completeness)
//	GET  /completeness       current producer completeness assessment
func NewTelemetryHandler(store *OwnerStore) http.Handler {
	return &telemetryHandler{store: store}
}

func (h *telemetryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/telemetry" && r.Method == http.MethodPost:
		h.serveTelemetry(w, r, false)
	case r.URL.Path == "/telemetry/batch" && r.Method == http.MethodPost:
		h.serveTelemetry(w, r, true)
	case r.URL.Path == "/flush" && r.Method == http.MethodPost:
		h.serveFlush(w, r)
	case (r.URL.Path == "/connection/close" || r.URL.Path == "/connection_close") && r.Method == http.MethodPost:
		h.serveConnectionClose(w, r)
	case r.URL.Path == "/completeness" && r.Method == http.MethodGet:
		h.serveCompleteness(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "unknown observation route")
	}
}

func (h *telemetryHandler) journalFor(w http.ResponseWriter, r *http.Request, operation string) (*observationRuntime, bool) {
	if h.store == nil {
		writeError(w, http.StatusInternalServerError, "no_store", "telemetry handler has no store")
		return nil, false
	}
	journalID := r.URL.Query().Get("journal_id")
	if strings.TrimSpace(journalID) == "" {
		writeError(w, http.StatusBadRequest, "missing_journal", "query journal_id is required")
		return nil, false
	}
	if err := authority.Authorize(r.Context(), ownerDomain, operation, journalID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return nil, false
	}
	rt, ok := lookupByJournal(h.store, journalID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_journal", "journal "+journalID+" is not initialized")
		return nil, false
	}
	return rt, true
}

func readBoundedBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, errors.New("empty body")
	}
	defer r.Body.Close()
	reader := io.LimitReader(r.Body, limit+1)
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("request body exceeds bound")
	}
	return raw, nil
}

// rejectUnknownSubmissionKeys enforces the closed EventSubmission shape.
// Server authority fields are reported distinctly and always rejected.
func rejectUnknownSubmissionKeys(m map[string]any) (serverField string, unknownField string) {
	for key := range m {
		if allowedSubmissionKeys[key] {
			continue
		}
		if serverFieldKeys[key] {
			return key, ""
		}
		return "", key
	}
	return "", ""
}

func validateSubmissionShape(sub EventSubmission) error {
	if sub.ProducerSequence == nil {
		return errors.New("producer_sequence is an in-band null: use an integer or typed Missing")
	}
	if _, ok := asMissing(sub.ProducerSequence); !ok {
		if _, ok := producerSeqInt(sub.ProducerSequence); !ok {
			return errors.New("producer_sequence must be a nonnegative integer or typed Missing")
		}
	}
	if strings.TrimSpace(sub.EventKind) == "" {
		return errors.New("event_kind is required")
	}
	if strings.TrimSpace(sub.EventSchemaVersion) == "" {
		return errors.New("event_schema_version is required")
	}
	if sub.OccurredAt == nil {
		return errors.New("occurred_at is an in-band null: use a TimePoint or typed Missing")
	}
	return nil
}

func (h *telemetryHandler) serveTelemetry(w http.ResponseWriter, r *http.Request, batch bool) {
	rt, ok := h.journalFor(w, r, "write")
	if !ok {
		return
	}
	raw, err := readBoundedBody(r, maxRequestBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	var subs []EventSubmission
	if batch {
		var rawItems []map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rawItems); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", "batch body must be a JSON array of EventSubmission")
			return
		}
		if len(rawItems) == 0 {
			writeError(w, http.StatusBadRequest, "empty_batch", "at least one submission is required")
			return
		}
		for i, item := range rawItems {
			if serverField, unknownField := rejectUnknownSubmissionKeys(item); serverField != "" || unknownField != "" {
				if serverField != "" {
					writeError(w, http.StatusBadRequest, "server_field_rejected",
						fmt.Sprintf("batch[%d] carries caller-supplied authority field %q", i, serverField))
				} else {
					writeError(w, http.StatusBadRequest, "unknown_field",
						fmt.Sprintf("batch[%d] carries unknown field %q", i, unknownField))
				}
				return
			}
		}
		dec2 := json.NewDecoder(bytes.NewReader(raw))
		dec2.UseNumber()
		if err := dec2.Decode(&subs); err != nil {
			writeError(w, http.StatusBadRequest, "bad_submission", err.Error())
			return
		}
	} else {
		var rawMap map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rawMap); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", "body must be a JSON EventSubmission object")
			return
		}
		if serverField, unknownField := rejectUnknownSubmissionKeys(rawMap); serverField != "" || unknownField != "" {
			if serverField != "" {
				writeError(w, http.StatusBadRequest, "server_field_rejected",
					fmt.Sprintf("caller-supplied authority field %q is rejected", serverField))
			} else {
				writeError(w, http.StatusBadRequest, "unknown_field",
					fmt.Sprintf("unknown field %q is rejected", unknownField))
			}
			return
		}
		dec2 := json.NewDecoder(bytes.NewReader(raw))
		dec2.UseNumber()
		var single EventSubmission
		if err := dec2.Decode(&single); err != nil {
			writeError(w, http.StatusBadRequest, "bad_submission", err.Error())
			return
		}
		subs = []EventSubmission{single}
	}
	for i, sub := range subs {
		if err := validateSubmissionShape(sub); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_submission", fmt.Sprintf("events[%d]: %v", i, err))
			return
		}
		if forbiddenTelemetryKinds[sub.EventKind] {
			writeError(w, http.StatusForbidden, "unauthorized_event",
				fmt.Sprintf("telemetry cannot emit %q: application authority or server lifecycle", sub.EventKind))
			return
		}
		if sub.Payload.Data != nil {
			for key := range sub.Payload.Data {
				if forbiddenBusinessKeys[key] {
					writeError(w, http.StatusForbidden, "unauthorized_event",
						fmt.Sprintf("telemetry data key %q asserts an authoritative business predicate", key))
					return
				}
			}
		}
		if err := validateMeasurements(sub.Payload.Measurements, rt.manifest.Clocks, fmt.Sprintf("events[%d].measurements", i)); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_measurement", err.Error())
			return
		}
	}

	// Telemetry batching commits atomically; no trailing debounce drops
	// any delivery.
	registryMu.Lock()
	headBefore := rt.head
	registryMu.Unlock()
	envelopes, err := owner_store.CommitOwner(r.Context(), h.store, rt.journalID, subs, nil)
	if err != nil {
		if errors.Is(err, owner_store.ErrIntegrityConflict) {
			// Same sequence/different content (or duplicate within the
			// batch): record the integrity incident and retain the
			// conflict. The original delivery is preserved.
			seq, _ := conflictingSequence(subs)
			incidentRef, incidentErr := h.recordIncident(r.Context(), rt, seq, subs, err.Error())
			if incidentErr != nil {
				writeError(w, http.StatusConflict, "integrity_conflict",
					fmt.Sprintf("conflicting producer sequence %d; incident journaling failed: %v", seq, incidentErr))
				return
			}
			writeJSON(w, http.StatusConflict, map[string]any{
				"reason":            "integrity_conflict",
				"producer_sequence": seq,
				"incident_ref":      incidentRef,
				"detail":            err.Error(),
			})
			return
		}
		if errors.Is(err, owner_store.ErrUnauthorized) {
			writeError(w, http.StatusForbidden, "unauthorized", err.Error())
			return
		}
		if errors.Is(err, owner_store.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid_submission", err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "commit_failed", err.Error())
		return
	}
	deduped := len(envelopes) > 0 && envelopes[0].Sequence <= headBefore.LastSequence
	if !deduped && len(envelopes) > 0 {
		last := envelopes[len(envelopes)-1]
		updateHead(h.store, rt, JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash})
	}
	if batch {
		receipts := make([]any, 0, len(envelopes))
		for _, env := range envelopes {
			receipts = append(receipts, map[string]any{
				"event_id": env.EventID, "journal_sequence": env.Sequence,
				"event_hash": env.EventHash, "producer_sequence": env.ProducerSequence,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"receipts": receipts, "duplicate": deduped})
		return
	}
	env := envelopes[0]
	writeJSON(w, http.StatusOK, map[string]any{
		"event_id": env.EventID, "journal_sequence": env.Sequence,
		"event_hash": env.EventHash, "producer_sequence": env.ProducerSequence,
		"duplicate": deduped,
	})
}

// conflictingSequence extracts the first integer producer sequence from the
// attempted submissions for incident reporting.
func conflictingSequence(subs []EventSubmission) (int64, bool) {
	for _, sub := range subs {
		if seq, ok := producerSeqInt(sub.ProducerSequence); ok {
			return seq, true
		}
		// json.Number / float64 forms are handled by producerSeqInt; fall
		// back to a direct map probe for exotic decodings.
		if m, ok := sub.ProducerSequence.(map[string]any); ok {
			_ = m
		}
	}
	// Scan for duplicates within the batch even when the first extraction
	// missed (e.g. duplicate Missing is not a conflict; return 0).
	seen := map[int64]int{}
	for _, sub := range subs {
		if seq, ok := producerSeqInt(sub.ProducerSequence); ok {
			seen[seq]++
			if seen[seq] > 1 {
				return seq, true
			}
		}
	}
	if len(subs) > 0 {
		if seq, ok := producerSeqInt(subs[0].ProducerSequence); ok {
			return seq, true
		}
	}
	return 0, false
}

// recordIncident journals an integrity incident for a conflicting producer
// sequence, retaining the conflicting attempt alongside the original.
func (h *telemetryHandler) recordIncident(ctx context.Context, rt *observationRuntime, seq int64, attempted []EventSubmission, cause string) (EvidenceRef, error) {
	var zero EvidenceRef
	evidence, err := owner_store.LoadPrefix(ctx, h.store, rt.head)
	if err != nil {
		return zero, err
	}
	var originalRef EvidenceRef
	var originalFound bool
	for _, env := range evidence {
		if s, ok := producerSeqInt(env.ProducerSequence); ok && s == seq {
			originalRef = EvidenceRef{JournalID: env.JournalID, Sequence: env.Sequence, EventID: env.EventID, EventHash: env.EventHash, Pointer: ""}
			originalFound = true
			break
		}
	}
	var attemptedData []any
	for _, sub := range attempted {
		attemptedRaw, _ := json.Marshal(sub)
		canonical, _ := evidence_codec.CanonicalJSON(attemptedRaw, "application/json")
		var digest string
		if canonical != nil {
			digest = string(evidence_codec.HashBytes(canonical))
		}
		attemptedData = append(attemptedData, map[string]any{
			"event_kind":       sub.EventKind,
			"producer_sequence": sub.ProducerSequence,
			"data":             sub.Payload.Data,
			"content_digest":   digest,
		})
	}
	data := map[string]any{
		"code":              "integrity_conflict",
		"detail":            fmt.Sprintf("conflicting content under producer_sequence %d is retained, not last-write-wins: %s", seq, cause),
		"producer_id":       rt.producerID,
		"producer_sequence": seq,
		"attempted":         attemptedData,
	}
	if originalFound {
		data["original_ref"] = map[string]any{
			"journal_id": originalRef.JournalID, "sequence": originalRef.Sequence,
			"event_id": originalRef.EventID, "event_hash": originalRef.EventHash,
		}
	}
	refs := []EvidenceRef{}
	if originalFound {
		refs = append(refs, originalRef)
	}
	submission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventIncident,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         data,
			Measurements: []Measurement{},
			EvidenceRefs: refs,
			ArtifactRefs: []ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, h.store, rt.journalID, []EventSubmission{submission}, nil)
	if err != nil {
		return zero, err
	}
	env := envelopes[0]
	updateHead(h.store, rt, JournalPrefix{JournalID: env.JournalID, LastSequence: env.Sequence, HeadHash: env.EventHash})
	return EvidenceRef{JournalID: env.JournalID, Sequence: env.Sequence, EventID: env.EventID, EventHash: env.EventHash, Pointer: ""}, nil
}

func (h *telemetryHandler) serveFlush(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.journalFor(w, r, "write")
	if !ok {
		return
	}
	raw, err := readBoundedBody(r, maxRequestBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	var rawMap map[string]any
	if len(bytes.TrimSpace(raw)) == 0 {
		rawMap = map[string]any{}
	} else {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rawMap); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		if rawMap == nil {
			rawMap = map[string]any{}
		}
	}
	// Reject bare nulls and unknown fields. Flush accepts only an
	// optional final_sequence.
	for key, val := range rawMap {
		if key != "final_sequence" {
			writeError(w, http.StatusBadRequest, "unknown_field", fmt.Sprintf("unknown flush field %q", key))
			return
		}
		if val == nil {
			writeError(w, http.StatusBadRequest, "inband_null", "final_sequence is an in-band null: use an integer or typed Missing")
			return
		}
	}
	var finalAny any = owner_store.NewMissing("not_observed")
	finalProvided := false
	var finalVal int64
	if v, present := rawMap["final_sequence"]; present {
		if _, isMissing := asMissing(v); isMissing {
			finalAny = v
		} else if seq, ok := producerSeqInt(v); ok {
			finalVal, finalProvided = seq, true
			finalAny = seq
		} else {
			writeError(w, http.StatusBadRequest, "invalid_final", "final_sequence must be a nonnegative integer or typed Missing")
			return
		}
	}
	_ = finalProvided
	_ = finalVal
	evidence, err := owner_store.LoadPrefix(r.Context(), h.store, rt.head)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load_failed", err.Error())
		return
	}
	before := assessFromEnvelopes(rt.producerID, evidence)
	data := map[string]any{
		"producer_id":    rt.producerID,
		"flush_observed": true,
		"final_sequence": finalAny,
		"observed_ranges": before.ObservedRanges,
		"missing_ranges":  before.MissingRanges,
	}
	submission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventFlush,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         data,
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(r.Context(), h.store, rt.journalID, []EventSubmission{submission}, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "commit_failed", err.Error())
		return
	}
	last := envelopes[0]
	updateHead(h.store, rt, JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash})
	afterEvidence, err := owner_store.LoadPrefix(r.Context(), h.store, rt.head)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load_failed", err.Error())
		return
	}
	after := assessFromEnvelopes(rt.producerID, afterEvidence)
	writeJSON(w, http.StatusOK, map[string]any{"flush_observed": true, "completeness": after})
}

func (h *telemetryHandler) serveConnectionClose(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.journalFor(w, r, "write")
	if !ok {
		return
	}
	raw, err := readBoundedBody(r, maxRequestBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	reason := "connection_closed"
	if len(bytes.TrimSpace(raw)) != 0 {
		var rawMap map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rawMap); err != nil {
			writeError(w, http.StatusBadRequest, "bad_json", err.Error())
			return
		}
		for key, val := range rawMap {
			if key != "reason" {
				writeError(w, http.StatusBadRequest, "unknown_field", fmt.Sprintf("unknown connection-close field %q", key))
				return
			}
			if val == nil {
				writeError(w, http.StatusBadRequest, "inband_null", "reason is an in-band null")
				return
			}
			s, isStr := val.(string)
			if !isStr || strings.TrimSpace(s) == "" {
				writeError(w, http.StatusBadRequest, "invalid_reason", "reason must be a nonempty string")
				return
			}
			reason = s
		}
	}
	// A closed transport connection is recorded as lifecycle observation.
	// It never evidences a terminal producer sequence, native termination,
	// or completeness.
	data := map[string]any{
		"producer_id": rt.producerID,
		"reason":      reason,
	}
	submission := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventTransportClose,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data:         data,
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(r.Context(), h.store, rt.journalID, []EventSubmission{submission}, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "commit_failed", err.Error())
		return
	}
	last := envelopes[0]
	updateHead(h.store, rt, JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash})
	evidence, err := owner_store.LoadPrefix(r.Context(), h.store, rt.head)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load_failed", err.Error())
		return
	}
	completeness := assessFromEnvelopes(rt.producerID, evidence)
	writeJSON(w, http.StatusOK, map[string]any{"connection_closed": true, "completeness": completeness})
}

func (h *telemetryHandler) serveCompleteness(w http.ResponseWriter, r *http.Request) {
	rt, ok := h.journalFor(w, r, "read")
	if !ok {
		return
	}
	evidence, err := owner_store.LoadPrefix(r.Context(), h.store, rt.head)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, assessFromEnvelopes(rt.producerID, evidence))
}
