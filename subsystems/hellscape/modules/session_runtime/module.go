// Package session_runtime implements the tier-8 Hellscape session runtime.
//
// The runtime owns the local execution loop around one durably admitted
// session: it accepts bounded work, journals a native dispatch intent before
// any side-effecting connector call, records the correlated outcome, and
// records dispatch uncertainty (never a resend) when delivery is ambiguous.
// It also owns the closure protocol (seam 9.9) and the restart rules
// (seam 14.2):
//
//   - At end/deadline it stops issuing workflow commands, records native
//     cancel availability and any request separately, records transport
//     closure separately, drains only within the commissioned bound, requests
//     fixture-origin sealing, closes locally even when the origin seal is
//     unavailable, freezes knowledge and pins, accepts authorized late
//     evidence at the current journal head, and publishes a new diagnostic
//     revision without reopening observation.
//   - On restart it registers a new boot clock, fences unfinished observation
//     epochs and unfinished sessions as infrastructure-interrupted, and
//     recovers ambiguous dispatch as uncertain. It never replays a
//     side-effecting native request and never derives downtime from UTC or by
//     subtracting offsets across boots.
//   - Persistence failure stops new work where durability cannot be trusted.
//     An unpersisted tail is never called complete, and a failure to append
//     never fabricates an event reference.
//
// Owner separation is preserved throughout: runtime bookkeeping lives in the
// runtime-owned journal of the primary (diagnostic) store, application
// mutation authority is sealed only through the application owner,
// observation closure only through the observation owner, evidence import only
// through the shared importer, and publication only through the publisher. No
// owner transaction is held while a peer owner, connector, or artifact
// transfer runs, and no two owners share a transaction.
package session_runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"admission"
	"analysis_owner"
	"application_owner"
	"clock_rules"
	"connector_transport"
	"evidence_codec"
	"evidence_import"
	"journal_rules"
	"lifecycle_rules"
	"observation_owner"
	"owner_store"
	"publication"
)

// ---------------------------------------------------------------------------
// Evidence-kernel aliases.
//
// The aliases keep every CONSUMES call translation-free: owner stores,
// journals, references, lifecycle commissions, and diagnostic documents all
// resolve to the same shared kernels the dependency modules use.
// ---------------------------------------------------------------------------

type (
	// OwnerStore is one owner-local durable boundary (one SQLite database
	// plus one content-addressed artifact root).
	OwnerStore = owner_store.OwnerStore
	// Manifest is the admitted journal manifest.
	Manifest = journal_rules.Manifest
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = journal_rules.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = journal_rules.JournalPrefix
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = journal_rules.EvidenceRef
	// ArtifactReference is an immutable byte identity plus resolver metadata.
	ArtifactReference = journal_rules.ArtifactReference
	// EventSubmission is the ingress shape for owner-local commits.
	EventSubmission = owner_store.EventSubmission
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = journal_rules.TimePoint
	// ClockDescriptor registers one clock lifetime.
	ClockDescriptor = journal_rules.ClockDescriptor
	// MissingEnvelope is the typed EK Missing value.
	MissingEnvelope = journal_rules.MissingEnvelope
	// Measurement is the EK measurement record carried in payloads.
	Measurement = journal_rules.Measurement
	// AttemptCommission freezes the attempt identity, owner bindings, and
	// commissioned local bounds.
	AttemptCommission = lifecycle_rules.AttemptCommission
	// AttemptReference identifies one attempt and kind.
	AttemptReference = lifecycle_rules.AttemptReference
	// AxisRevision is one complete immutable axis publication.
	AxisRevision = lifecycle_rules.AxisRevision
	// VersionPin pins an immutable versioned import-policy artifact.
	VersionPin = evidence_import.VersionPin
	// AnalysisPin pins one diagnostic classifier or requirement registry in
	// the analysis owner's own versioned pin shape.
	AnalysisPin = analysis_owner.VersionPin
	// DiagnosticDocument is the deterministic analysis output.
	DiagnosticDocument = analysis_owner.DiagnosticDocument
	// AnalysisRequest pins one diagnostic revision's inputs.
	AnalysisRequest = analysis_owner.AnalysisRequest
)

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears.
var (
	_ = admission.AdvanceAdmission
	_ = analysis_owner.AnalyzeSession
	_ = publication.InstallPublication
	_ = observation_owner.CloseObservationWindow
	_ = application_owner.SealApplication
	_ = connector_transport.CallConnector
	_ = evidence_import.ImportSourcePrefix
	_ = owner_store.CommitOwner
	_ = owner_store.CollectUnreachable
	_ = clock_rules.ComputeDeadline
)

// ---------------------------------------------------------------------------
// Constants.
// ---------------------------------------------------------------------------

const (
	// runtimeJournalID is the deterministic runtime-owned journal in the
	// primary store. It is never a session journal: session evidence stays
	// owner-owned and is only cited by coordinate.
	runtimeJournalID = "session-runtime"
	runtimeRunID     = "session-runtime"
	runtimeClockID   = "session-runtime-clock"
	runtimeSourceID  = "session-runtime"

	eventSchemaVersion   = "1.0.0"
	journalSchemaVersion = "0.1.0"
	mediaTypeJSON        = "application/json"
	accessPublic         = "public"
	accessRestricted     = "restricted"

	// publicationViewID names the read view the runtime publishes into.
	publicationViewID = "session-runtime-view"
	// publicationEntityType is the owner-separated entity the runtime
	// registers for its session diagnostic revisions.
	publicationEntityType = "hellscape_session"

	defaultQueueCapacity  = 8
	defaultControlReserve = 2
	defaultCallLimitMs    = 30_000.0
	defaultActiveLimitMs  = 60_000.0
	defaultDrainLimitMs   = 10_000.0
	defaultCancelWaitMs   = 5_000.0
	defaultCleanupWaitMs  = 5_000.0
	defaultLeaseTTL       = 15 * time.Minute
	defaultMaxRetries     = 3
)

// Runtime journal event kinds (all server-authored, owner-local facts).
const (
	eventRuntimeRecoveryProbe  = "runtime_recovery_probe"
	eventClockRegistered       = "clock_registered"
	eventRuntimeBoot           = "runtime_boot"
	eventSessionOpened         = "session_opened"
	eventWorkAccepted          = "work_accepted"
	eventWorkRejected          = "work_rejected"
	eventCloseRequested        = "close_requested"
	eventControlRecorded       = "control_recorded"
	eventTransportClosed       = "transport_closed"
	eventDrainRecorded         = "drain_recorded"
	eventOriginSealRecorded    = "origin_seal_recorded"
	eventObservationClosed     = "observation_close_recorded"
	eventKnowledgeFrozen       = "knowledge_frozen"
	eventDispatchIntent        = "dispatch_intent"
	eventDispatchRecorded      = "dispatch_recorded"
	eventDispatchRejected      = "dispatch_rejected"
	eventDispatchUncertain     = "dispatch_uncertain"
	eventObservationFenced     = "observation_epoch_fenced"
	eventSessionInterrupted    = "session_interrupted"
	eventDiagnosticRecorded    = "diagnostic_recorded"
	eventPublicationRecorded   = "publication_recorded"
	eventFinalizationRecorded  = "finalization_recorded"
	eventLateEvidenceRecorded  = "late_evidence_recorded"
	eventLateEvidenceFinalized = "late_evidence_finalized"
)

// Session-journal and observation-journal event kinds the runtime appends on
// behalf of the primary diagnostic owner or the observation owner.
const (
	eventSessionRegistered  = "session_registered"
	eventAnalysisRequested  = "analysis_requested"
	eventPublicationPinned  = "diagnostic_publication_pinned"
	eventLateEvidence       = "late_evidence"
	eventLateEvidenceImport = "late_evidence_imported"
)

// Session phases.
const (
	phaseOpen        = "open"
	phaseClosing     = "closing"
	phaseClosed      = "closed"
	phaseFinalized   = "finalized"
	phaseInterrupted = "interrupted"
)

// Drain states.
const (
	drainComplete    = "complete"
	drainIncomplete  = "incomplete"
	drainUnavailable = "unavailable"
)

// CloseReason is one commissioned local close reason (seam 9.3). It is
// recorded verbatim; it never claims native termination.
type CloseReason string

// Close reasons accepted by the runtime.
const (
	CloseNormalCompletion           CloseReason = "normal_completion"
	CloseOperatorStop               CloseReason = "operator_stop"
	CloseLocalDeadline              CloseReason = "local_deadline"
	CloseTranslationFailure         CloseReason = "translation_failure"
	CloseLaunchFailure              CloseReason = "launch_failure"
	CloseSubjectTerminal            CloseReason = "subject_terminal"
	CloseConnectionLost             CloseReason = "connection_lost"
	CloseInfrastructureInterruption CloseReason = "infrastructure_interruption"
)

var validCloseReasons = map[CloseReason]bool{
	CloseNormalCompletion:           true,
	CloseOperatorStop:               true,
	CloseLocalDeadline:              true,
	CloseTranslationFailure:         true,
	CloseLaunchFailure:              true,
	CloseSubjectTerminal:            true,
	CloseConnectionLost:             true,
	CloseInfrastructureInterruption: true,
}

// Valid reports whether the reason is one of the commissioned close reasons.
func (c CloseReason) Valid() bool { return validCloseReasons[c] }

// WorkKind classifies one bounded queue item.
type WorkKind string

// Queue item kinds. Workflow items may be rejected to preserve control
// progress; control and close items draw on the reserved capacity.
const (
	WorkflowWork WorkKind = "workflow"
	ControlWork  WorkKind = "control"
	CloseWork    WorkKind = "close"
)

// WorkItem is one bounded unit of session work. Workflow items carry a
// connector operation and payload; control items carry exactly one control
// operation; close items carry the local close reason.
type WorkItem struct {
	SessionID string
	Kind      WorkKind
	Operation string
	RequestID string
	Payload   json.RawMessage
	Reason    CloseReason
}

// QueueLimits bounds the accepted work queue and reserves progress for
// close/control handling.
type QueueLimits struct {
	Capacity       int
	ControlReserve int
}

// Options configures one Runtime. Zero values select the commissioned
// defaults.
type Options struct {
	// ConnectorEndpoint is the deployment-configured connector endpoint the
	// runtime may post to. It is never a caller-supplied destination.
	ConnectorEndpoint string
	// Limits bounds the work queue.
	Limits QueueLimits
	// CallLimitMs bounds one local connector call.
	CallLimitMs float64
	// DiagnosticID overrides the diagnostic identity prefix.
	DiagnosticID string
}

// SessionSpec is the durable registration input for one session. The
// commission is the same lifecycle object the observation and application
// owners consume; nothing is translated at the boundary.
type SessionSpec struct {
	Commission        AttemptCommission
	ConnectorEndpoint string
	Configuration     []byte
	DiagnosticID      string
}

// SessionBounds are the commissioned local bounds in milliseconds. They are
// configuration, never elapsed measurements.
type SessionBounds struct {
	ActiveLimitMs           float64
	DrainLimitMs            float64
	NativeCancelWaitLimitMs float64
	CleanupWaitLimitMs      float64
}

// SessionSnapshot is a read-only projection of one session's durable runtime
// state. It is a convenience for the engine; it is never a write command.
type SessionSnapshot struct {
	SessionID               string
	AttemptID               string
	JournalID               string
	Mode                    string
	Phase                   string
	BootID                  string
	DispatchCount           int64
	PendingDispatch         string
	LastDispatchState       string
	CloseReason             CloseReason
	DrainState              string
	ObservationState        string
	ObservationRevision     int64
	ObservationCompleteness string
	ApplicationState        string
	ApplicationRevision     int64
	DiagnosticRevision      int64
	DiagnosticDigest        string
	PublishedRevision       int64
	Finalized               bool
}

// Sentinel errors.
var (
	// ErrInvalid marks malformed caller input or an unreadable stored record.
	ErrInvalid = errors.New("session_runtime: invalid input")
	// ErrNotAdmitted marks a journal that is not a durably admitted session.
	ErrNotAdmitted = errors.New("session_runtime: journal is not a durably admitted session")
	// ErrQueueFull marks a rejected work item. Rejection is recorded before
	// it is reported; rejected work is never silently lost.
	ErrQueueFull = errors.New("session_runtime: work queue is full")
	// ErrQueueClosed marks a queue closed for shutdown.
	ErrQueueClosed = errors.New("session_runtime: work queue is closed")
	// ErrRecoveryConflict marks a runtime journal that belongs to a
	// different admitted manifest.
	ErrRecoveryConflict = errors.New("session_runtime: runtime journal conflict")
	// ErrStorageUnavailable marks a durability boundary that cannot append.
	ErrStorageUnavailable = errors.New("session_runtime: durable storage unavailable")
	// ErrSessionClosed marks work attempted for a closed session.
	ErrSessionClosed = errors.New("session_runtime: session is already closed")
)

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

// newBootID returns a fresh opaque boot identity. Boot identity is never
// derived from UTC and is never compared with a previous boot's offsets.
func newBootID() (string, error) {
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("session_runtime: generate boot id: %w", err)
	}
	return "boot-" + hex.EncodeToString(buf[:]), nil
}

// artifactRefMap renders one artifact reference as retained payload data.
func artifactRefMap(ref ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       ref.Digest,
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

// refInto merges one evidence reference into payload data as flat scalars.
// Cross-journal references must never ride as embedded EvidenceRef objects:
// journal validation requires every embedded coordinate to name the same
// journal as the event carrying it. An absent reference contributes nothing
// (empty digest-shaped strings are rejected by the structural gate).
func refInto(out map[string]any, prefix string, ref EvidenceRef) {
	if strings.TrimSpace(ref.JournalID) == "" {
		return
	}
	out[prefix+"_journal"] = ref.JournalID
	out[prefix+"_sequence"] = ref.Sequence
	out[prefix+"_event_id"] = ref.EventID
	out[prefix+"_event_hash"] = ref.EventHash
	out[prefix+"_pointer"] = ref.Pointer
}

// refFrom rebuilds an EvidenceRef previously flattened by refInto. Absent
// coordinates stay zero rather than fabricated.
func refFrom(data map[string]any, prefix string) EvidenceRef {
	return EvidenceRef{
		JournalID: asString(data[prefix+"_journal"]),
		Sequence:  asInt64(data[prefix+"_sequence"]),
		EventID:   asString(data[prefix+"_event_id"]),
		EventHash: asString(data[prefix+"_event_hash"]),
		Pointer:   asString(data[prefix+"_pointer"]),
	}
}

// prefixInto flattens a journal prefix as scalars. An absent prefix
// contributes nothing.
func prefixInto(out map[string]any, prefix string, p JournalPrefix) {
	if strings.TrimSpace(p.JournalID) == "" {
		return
	}
	out[prefix+"_journal"] = p.JournalID
	out[prefix+"_last_sequence"] = p.LastSequence
	out[prefix+"_head_hash"] = p.HeadHash
}

// putDigest adds a digest-shaped field only when the value exists. The
// shared structural gate rejects empty digest strings and accepts no
// fabricated coordinate.
func putDigest(out map[string]any, key, value string) {
	if strings.TrimSpace(value) != "" {
		out[key] = value
	}
}

// prefixFrom rebuilds a journal prefix flattened by prefixInto.
func prefixFrom(data map[string]any, prefix string) JournalPrefix {
	return JournalPrefix{
		JournalID:    asString(data[prefix+"_journal"]),
		LastSequence: asInt64(data[prefix+"_last_sequence"]),
		HeadHash:     asString(data[prefix+"_head_hash"]),
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n
		}
	}
	return 0
}

func asFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int64:
		return float64(t)
	case int:
		return float64(t)
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return f
		}
	}
	return 0
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// jsonString renders one JSON value compactly for a scalar payload field.
func jsonString(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}

// mustJSONString is jsonString with an empty fallback; it is only used for
// already-validated local structures.
func mustJSONString(v any) string { return jsonString(v) }

// canonicalDigest returns the canonical digest of one value.
func canonicalDigest(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

// canonicalBytes returns canonical JSON bytes for one value.
func canonicalBytes(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return evidence_codec.CanonicalJSON(raw, mediaTypeJSON)
}

// digestRevision digests one axis revision as published.
func digestRevision(rev AxisRevision) string {
	d, err := canonicalDigest(rev)
	if err != nil {
		return ""
	}
	return d
}

// boundsFromCommission converts the commissioned lifecycle bounds.
func boundsFromCommission(commission AttemptCommission) SessionBounds {
	policy := commission.ObservationPolicy
	return SessionBounds{
		ActiveLimitMs:           policy.ActiveLimit.Value,
		DrainLimitMs:            policy.DrainLimit.Value,
		NativeCancelWaitLimitMs: policy.NativeCancelWaitLimit.Value,
		CleanupWaitLimitMs:      policy.CleanupWaitLimit.Value,
	}
}

// normalizedBounds fills unset bounds with the commissioned defaults.
func normalizedBounds(b SessionBounds) SessionBounds {
	if b.ActiveLimitMs <= 0 {
		b.ActiveLimitMs = defaultActiveLimitMs
	}
	if b.DrainLimitMs <= 0 {
		b.DrainLimitMs = defaultDrainLimitMs
	}
	if b.NativeCancelWaitLimitMs <= 0 {
		b.NativeCancelWaitLimitMs = defaultCancelWaitMs
	}
	if b.CleanupWaitLimitMs <= 0 {
		b.CleanupWaitLimitMs = defaultCleanupWaitMs
	}
	return b
}

func durationFromMs(ms float64) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms * float64(time.Millisecond))
}

// ---------------------------------------------------------------------------
// Bounded work queue.
//
// Capacity is split into a general region and a control reserve. Workflow
// work may only fill the general region; control and close work may also use
// the reserve, and the server drains control/close before workflow. A queue
// that is full is reported to the caller and journalled as a rejection.
// ---------------------------------------------------------------------------

type queuedWork struct {
	item       WorkItem
	acceptedAt time.Time
	// deadlineMs is the active-budget deadline coordinate on the runtime
	// clock. Comparisons only happen while the boot identity still matches;
	// offsets from a previous boot are never subtracted.
	deadlineMs   float64
	deadlineBoot string
}

type workQueue struct {
	mu       sync.Mutex
	items    []*queuedWork
	capacity int
	reserve  int
	signal   chan struct{}
}

func newWorkQueue(limits QueueLimits) *workQueue {
	capacity := limits.Capacity
	if capacity <= 0 {
		capacity = defaultQueueCapacity
	}
	reserve := limits.ControlReserve
	if reserve < 0 {
		reserve = 0
	}
	if reserve > capacity-1 {
		reserve = capacity - 1
	}
	if reserve < 0 {
		reserve = 0
	}
	return &workQueue{capacity: capacity, reserve: reserve, signal: make(chan struct{}, 1)}
}

// tryEnqueue accepts one item or reports that the queue cannot hold it.
func (q *workQueue) tryEnqueue(item WorkItem, acceptedAt time.Time, deadlineMs float64, bootID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.capacity {
		return ErrQueueFull
	}
	if item.Kind == WorkflowWork && len(q.items) >= q.capacity-q.reserve {
		return ErrQueueFull
	}
	q.items = append(q.items, &queuedWork{
		item: item, acceptedAt: acceptedAt,
		deadlineMs: deadlineMs, deadlineBoot: bootID,
	})
	select {
	case q.signal <- struct{}{}:
	default:
	}
	return nil
}

// next removes and returns the highest-priority queued item: close first,
// then control, then workflow (FIFO within each class).
func (q *workQueue) next() (*queuedWork, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, false
	}
	best := -1
	bestRank := 3
	for i, item := range q.items {
		rank := 2
		switch item.item.Kind {
		case CloseWork:
			rank = 0
		case ControlWork:
			rank = 1
		}
		if rank < bestRank {
			best, bestRank = i, rank
		}
	}
	if best < 0 {
		best = 0
	}
	item := q.items[best]
	q.items = append(q.items[:best], q.items[best+1:]...)
	return item, true
}

// removeWhere drops matching items and returns them. Callers record a
// durable rejection for every dropped item so no accepted work disappears
// silently.
func (q *workQueue) removeWhere(match func(queuedWork) bool) []queuedWork {
	q.mu.Lock()
	defer q.mu.Unlock()
	var dropped []queuedWork
	kept := q.items[:0]
	for _, item := range q.items {
		if match(*item) {
			dropped = append(dropped, *item)
			continue
		}
		kept = append(kept, item)
	}
	q.items = kept
	return dropped
}

// depth reports the current queued depth.
func (q *workQueue) depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// take blocks for the next item, waking on enqueue or context cancellation.
func (q *workQueue) take(ctx context.Context) (*queuedWork, error) {
	for {
		if item, ok := q.next(); ok {
			return item, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-q.signal:
		}
	}
}

// ---------------------------------------------------------------------------
// Durable session state.
//
// The durable truth is the runtime-owned journal: every accepted work item,
// dispatch intent, outcome, control, close step, freeze, diagnostic
// revision, publication, and interruption is an appended event. The in-memory
// sessionState is a replay cache rebuilt from those events; it is never
// authoritative on its own.
// ---------------------------------------------------------------------------

type sessionState struct {
	id        string
	attemptID string
	journalID string
	mode      string
	bootID    string
	phase     string

	commission   AttemptCommission
	config       []byte
	diagnosticID string
	bounds       SessionBounds
	endpoint     string

	journalManifest    journal_rules.Manifest
	obsJournalManifest journal_rules.Manifest
	appRef             EvidenceRef
	obsRef             EvidenceRef
	obsPrefix          JournalPrefix

	leaseEpoch int64
	leaseBoot  string

	dispatchCount     int64
	pendingCommand    string
	pendingRequest    string
	lastDispatchState string
	lastDispatchRef   EvidenceRef

	closeRequested          bool
	closeReason             CloseReason
	controlCancelState      string
	transportClosed         bool
	drainState              string
	observationCompleteness string
	observationState        string
	observationRevision     int64
	observationDigest       string
	closureSnapshotDigest   string
	applicationState        string
	applicationRevision     int64
	knowledgeFrozen         bool

	diagnosticRevision int64
	documentRef        ArtifactReference
	documentDigest     string
	lastAnalysisRef    EvidenceRef
	lastAnalysisPrefix JournalPrefix
	publishedRevision  int64
	latePending        bool
}

func (s *sessionState) terminal() bool {
	return s.phase == phaseFinalized || s.phase == phaseInterrupted
}

// Runtime is one boot of the session runtime over the three owner stores.
// Each boot recovers the durable runtime journal and registers a fresh local
// monotonic clock; session state is always replayed from that journal.
type Runtime struct {
	mu sync.Mutex

	primary     *OwnerStore
	application *OwnerStore
	observation *OwnerStore

	journalID string
	domain    string
	clock     ClockDescriptor
	bootID    string
	startedAt time.Time
	booted    bool

	head     JournalPrefix
	events   []JournalEnvelope
	sessions map[string]*sessionState
	order    []string

	queue            *workQueue
	endpoint         string
	limits           QueueLimits
	callLimitMs      float64
	diagnosticPrefix string

	recovered bool
}

// NewRuntime opens the runtime over the owner stores. The primary store is
// the diagnostic owner boundary; the application and observation stores
// remain independently owned. Each call boots the runtime: an existing
// runtime journal is recovered by appending one probe event that reveals the
// current head, then the whole retained prefix is verified against the
// deterministic runtime manifest. A fresh engine process therefore recovers
// durable session state without adopting a foreign journal.
func NewRuntime(ctx context.Context, primary, application, observation *OwnerStore, opts Options) (*Runtime, error) {
	if primary == nil || application == nil || observation == nil {
		return nil, fmt.Errorf("%w: primary, application, and observation stores are required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	limits := opts.Limits
	if limits.Capacity <= 0 {
		limits.Capacity = defaultQueueCapacity
	}
	callLimit := opts.CallLimitMs
	if callLimit <= 0 {
		callLimit = defaultCallLimitMs
	}
	r := &Runtime{
		primary: primary, application: application, observation: observation,
		journalID:        runtimeJournalID,
		sessions:         map[string]*sessionState{},
		queue:            newWorkQueue(limits),
		endpoint:         strings.TrimSpace(opts.ConnectorEndpoint),
		limits:           limits,
		callLimitMs:      callLimit,
		diagnosticPrefix: strings.TrimSpace(opts.DiagnosticID),
	}
	if err := r.openJournal(ctx, opts); err != nil {
		return nil, err
	}
	return r, nil
}

// runtimeFor boots a runtime for one closure request.
func runtimeFor(ctx context.Context, primary, application, observation *OwnerStore) (*Runtime, error) {
	return NewRuntime(ctx, primary, application, observation, Options{})
}

// openJournal admits or recovers the runtime-owned journal and registers the
// boot clock. The journal ID and manifest are deterministic, so a fresh
// process can prove an existing journal is this runtime's journal rather than
// adopting a foreign one.
func (r *Runtime) openJournal(ctx context.Context, opts Options) error {
	// Learn the store's authenticated owner domain from one installed
	// artifact; owner domains are never caller-declared at this boundary.
	probe := map[string]any{"probe": runtimeJournalID, "schema_version": journalSchemaVersion}
	probeBytes, err := canonicalBytes(probe)
	if err != nil {
		return fmt.Errorf("session_runtime: canonicalize domain probe: %w", err)
	}
	probeRef, err := owner_store.InstallArtifact(ctx, r.primary, bytesReader(probeBytes), mediaTypeJSON, accessPublic)
	if err != nil {
		return fmt.Errorf("%w: install domain probe: %v", ErrStorageUnavailable, err)
	}
	domain := strings.TrimSpace(probeRef.OwnerDomain)
	if domain == "" {
		return fmt.Errorf("%w: primary store names no owner domain", ErrInvalid)
	}
	r.domain = domain

	baseClock := ClockDescriptor{
		ClockID: runtimeClockID, BootID: "boot-" + runtimeJournalID,
		Origin: "engine_measured", SourceID: runtimeSourceID,
		Basis: "monotonic_offset", Unit: "ms",
	}
	manifest := journal_rules.Manifest{
		RecordType: "manifest", SchemaVersion: journalSchemaVersion,
		ManifestID: "manifest-" + runtimeJournalID, RunID: runtimeRunID,
		JournalID: runtimeJournalID, OwnerDomain: domain,
		Clocks: []ClockDescriptor{baseClock},
	}
	manifestBytes, err := canonicalBytes(manifest)
	if err != nil {
		return fmt.Errorf("session_runtime: canonicalize runtime manifest: %w", err)
	}
	manifestRef, err := owner_store.InstallArtifact(ctx, r.primary, bytesReader(manifestBytes), mediaTypeJSON, accessPublic)
	if err != nil {
		return fmt.Errorf("%w: install runtime manifest: %v", ErrStorageUnavailable, err)
	}

	nonce, err := newBootID()
	if err != nil {
		return err
	}
	probeEnv, probeErr := r.appendRaw(ctx, eventRuntimeRecoveryProbe, map[string]any{
		"recovered_by": runtimeSourceID,
		"probe_nonce":  nonce,
	})
	switch {
	case probeErr == nil:
		// Existing journal: the unique probe envelope reveals the current
		// head. Verify the retained manifest is exactly the runtime manifest
		// (never adopt a foreign journal under our ID).
		head := JournalPrefix{JournalID: probeEnv.JournalID, LastSequence: probeEnv.Sequence, HeadHash: probeEnv.EventHash}
		events, loadErr := owner_store.LoadPrefix(ctx, r.primary, head)
		if loadErr != nil {
			return fmt.Errorf("%w: load existing runtime journal: %v", ErrRecoveryConflict, loadErr)
		}
		if len(events) == 0 || events[0].EventKind != "manifest_admitted" {
			return fmt.Errorf("%w: runtime journal does not begin with an admitted manifest", ErrRecoveryConflict)
		}
		retained, ok := events[0].Payload.Data["manifest"].(map[string]any)
		if !ok {
			return fmt.Errorf("%w: runtime journal manifest pin is unreadable", ErrRecoveryConflict)
		}
		if asString(retained["digest"]) != manifestRef.Digest {
			return fmt.Errorf("%w: runtime journal pins a different manifest (%q, want %q)",
				ErrRecoveryConflict, asString(retained["digest"]), manifestRef.Digest)
		}
		r.events = events
		r.head = head
		r.booted = true
		r.applyHistory()
		// Continue with boot-clock registration below.
	case strings.Contains(probeErr.Error(), "journal begins with manifest_admitted") ||
		errors.Is(probeErr, owner_store.ErrJournalUnknown):
		// Fresh journal: admit the deterministic manifest. The admission
		// carries a unique winning event only when the journal is empty.
		admission := EventSubmission{
			ProducerSequence:   owner_store.NewMissing("not_applicable"),
			EventKind:          "manifest_admitted",
			EventSchemaVersion: journalSchemaVersion,
			OccurredAt:         owner_store.NewMissing("not_applicable"),
			Payload: owner_store.Payload{
				Data:         map[string]any{"manifest": artifactRefMap(manifestRef)},
				Measurements: []Measurement{},
				EvidenceRefs: []EvidenceRef{},
				ArtifactRefs: []ArtifactReference{manifestRef},
			},
		}
		envelopes, admitErr := owner_store.CommitOwner(ctx, r.primary, r.journalID, []EventSubmission{admission}, nil)
		if admitErr != nil {
			return fmt.Errorf("%w: admit runtime journal: %v", ErrStorageUnavailable, admitErr)
		}
		if len(envelopes) == 0 {
			return fmt.Errorf("%w: runtime journal admission returned no envelope", ErrStorageUnavailable)
		}
		r.events = append(r.events, envelopes...)
		last := envelopes[len(envelopes)-1]
		r.head = JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
	default:
		return fmt.Errorf("%w: probe runtime journal: %v", ErrStorageUnavailable, probeErr)
	}

	bootID, err := newBootID()
	if err != nil {
		return err
	}
	r.bootID = bootID
	r.clock = ClockDescriptor{
		ClockID: runtimeClockID, BootID: bootID,
		Origin: "engine_measured", SourceID: runtimeSourceID,
		Basis: "monotonic_offset", Unit: "ms",
	}
	r.startedAt = time.Now()

	// Register the boot clock. The registration event itself cannot yet use
	// the clock it registers for occurred_at (only recorded_at carries the
	// atomic exception), so occurrence stays a typed Missing; every later
	// event uses the new clock coordinate.
	clockData := map[string]any{
		"clock_id": runtimeClockID, "boot_id": bootID, "origin": "engine_measured",
		"source_id": runtimeSourceID, "basis": "monotonic_offset", "unit": "ms",
	}
	sub := EventSubmission{
		ProducerSequence: owner_store.NewMissing("not_applicable"),
		EventKind:        eventClockRegistered, EventSchemaVersion: eventSchemaVersion,
		OccurredAt: owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: clockData, Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}
	clockEnvs, err := owner_store.CommitOwner(ctx, r.primary, r.journalID, []EventSubmission{sub}, nil)
	if err != nil {
		return fmt.Errorf("%w: register boot clock: %v", ErrStorageUnavailable, err)
	}
	r.appendEnvelopes(clockEnvs, true)

	priorBoot := ""
	for _, env := range r.events {
		if env.EventKind == eventClockRegistered {
			priorBoot = asString(env.Payload.Data["boot_id"])
		}
	}
	bootData := map[string]any{
		"boot_id": bootID, "clock_id": runtimeClockID,
		"recovered": r.booted,
	}
	if priorBoot != "" && priorBoot != bootID {
		bootData["previous_boot"] = priorBoot
	} else {
		bootData["previous_boot"] = owner_store.NewMissing("not_applicable")
	}
	if _, err := r.commitRuntime(ctx, eventRuntimeBoot, bootData, nil); err != nil {
		return err
	}
	r.booted = true
	return nil
}

// appendRaw commits one runtime-journal event without touching session state.
func (r *Runtime) appendRaw(ctx context.Context, kind string, data map[string]any) (JournalEnvelope, error) {
	return r.commitRuntime(ctx, kind, data, nil)
}

// commitRuntime appends one runtime-owned event and applies it to state.
func (r *Runtime) commitRuntime(ctx context.Context, kind string, data map[string]any, evidence []EvidenceRef) (JournalEnvelope, error) {
	if data == nil {
		data = map[string]any{}
	}
	if evidence == nil {
		evidence = []EvidenceRef{}
	}
	var occurred any = owner_store.NewMissing("not_observed")
	if r.booted {
		occurred = r.nowPoint()
	}
	sub := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          kind,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         occurred,
		Payload: owner_store.Payload{
			Data: data, Measurements: []Measurement{},
			EvidenceRefs: evidence, ArtifactRefs: []ArtifactReference{},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, r.primary, r.journalID, []EventSubmission{sub}, nil)
	if err != nil {
		return JournalEnvelope{}, wrapStorage(err)
	}
	if len(envelopes) == 0 {
		return JournalEnvelope{}, fmt.Errorf("%w: commit returned no envelope for %q", ErrStorageUnavailable, kind)
	}
	r.appendEnvelopes(envelopes, true)
	return envelopes[len(envelopes)-1], nil
}

// commitRuntimeArtifact appends one runtime event carrying installed bytes.
func (r *Runtime) commitRuntimeArtifact(ctx context.Context, kind string, data map[string]any, ref ArtifactReference) (JournalEnvelope, error) {
	if data == nil {
		data = map[string]any{}
	}
	sub := EventSubmission{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          kind,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         r.nowPoint(),
		Payload: owner_store.Payload{
			Data: data, Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{ref},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, r.primary, r.journalID, []EventSubmission{sub}, nil)
	if err != nil {
		return JournalEnvelope{}, wrapStorage(err)
	}
	if len(envelopes) == 0 {
		return JournalEnvelope{}, fmt.Errorf("%w: commit returned no envelope for %q", ErrStorageUnavailable, kind)
	}
	r.appendEnvelopes(envelopes, true)
	return envelopes[len(envelopes)-1], nil
}

// appendEnvelopes appends committed envelopes, advancing head and applying
// state under the runtime lock.
func (r *Runtime) appendEnvelopes(envelopes []JournalEnvelope, apply bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range envelopes {
		r.events = append(r.events, envelopes[i])
		if apply {
			r.applyEventLocked(&envelopes[i])
		}
	}
	if len(envelopes) > 0 {
		last := envelopes[len(envelopes)-1]
		r.head = JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
	}
}

// applyHistory replays all retained runtime events into session state.
func (r *Runtime) applyHistory() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.events {
		r.applyEventLocked(&r.events[i])
	}
}

// applyEventLocked folds one runtime event into the session cache.
func (r *Runtime) applyEventLocked(env *JournalEnvelope) {
	if env.EventKind == eventClockRegistered && env.Sequence == r.head.LastSequence {
		// The current boot clock is the last registration in history.
		r.clock = ClockDescriptor{
			ClockID:  asString(env.Payload.Data["clock_id"]),
			BootID:   asString(env.Payload.Data["boot_id"]),
			Origin:   asString(env.Payload.Data["origin"]),
			SourceID: asString(env.Payload.Data["source_id"]),
			Basis:    asString(env.Payload.Data["basis"]),
			Unit:     asString(env.Payload.Data["unit"]),
		}
	}
	sessionID := asString(env.Payload.Data["session_id"])
	if sessionID == "" {
		return
	}
	st, ok := r.sessions[sessionID]
	if !ok {
		st = &sessionState{id: sessionID, phase: phaseOpen}
		r.sessions[sessionID] = st
		r.order = append(r.order, sessionID)
	}
	data := env.Payload.Data
	switch env.EventKind {
	case eventSessionOpened:
		st.attemptID = asString(data["attempt_id"])
		st.journalID = asString(data["journal_id"])
		st.mode = asString(data["mode"])
		st.bootID = asString(data["boot_id"])
		st.diagnosticID = asString(data["diagnostic_id"])
		st.config = []byte(asString(data["configuration"]))
		st.endpoint = asString(data["connector_endpoint"])
		st.bounds = SessionBounds{
			ActiveLimitMs:           asFloat(data["active_limit_ms"]),
			DrainLimitMs:            asFloat(data["drain_limit_ms"]),
			NativeCancelWaitLimitMs: asFloat(data["native_cancel_wait_limit_ms"]),
			CleanupWaitLimitMs:      asFloat(data["cleanup_wait_limit_ms"]),
		}
		st.appRef = refFrom(data, "application_init")
		st.obsRef = refFrom(data, "observation_init")
		st.obsPrefix = prefixFrom(data, "observation_prefix")
		st.leaseEpoch = asInt64(data["lease_epoch"])
		st.leaseBoot = asString(data["lease_boot"])
		if raw := asString(data["journal_manifest"]); raw != "" {
			var m journal_rules.Manifest
			if json.Unmarshal([]byte(raw), &m) == nil {
				st.journalManifest = m
			}
		}
		if raw := asString(data["observation_manifest"]); raw != "" {
			var m journal_rules.Manifest
			if json.Unmarshal([]byte(raw), &m) == nil {
				st.obsJournalManifest = m
			}
		}
		if raw := asString(data["commission"]); raw != "" {
			var c lifecycle_rules.AttemptCommission
			if json.Unmarshal([]byte(raw), &c) == nil {
				st.commission = c
			}
		}
	case eventWorkAccepted:
		// Acceptance is a durable fact; the item itself lives in the queue.
	case eventWorkRejected:
		// Rejection is a durable fact and is never silently dropped.
	case eventCloseRequested:
		st.closeRequested = true
		st.closeReason = CloseReason(asString(data["reason"]))
		st.phase = phaseClosing
	case eventControlRecorded:
		if asString(data["operation"]) == connector_transport.OpRequestNativeCancel {
			st.controlCancelState = asString(data["disposition"])
		}
	case eventTransportClosed:
		st.transportClosed = true
	case eventDrainRecorded:
		st.drainState = asString(data["state"])
		st.observationCompleteness = asString(data["producer_completeness"])
	case eventOriginSealRecorded:
		st.applicationState = asString(data["state"])
		st.applicationRevision = asInt64(data["revision"])
	case eventObservationClosed:
		st.observationState = asString(data["state"])
		st.observationRevision = asInt64(data["revision"])
		st.observationDigest = asString(data["digest"])
		st.closureSnapshotDigest = asString(data["closure_snapshot_digest"])
		if p := prefixFrom(data, "closed_prefix"); p.JournalID != "" {
			st.obsPrefix = p
		}
	case eventKnowledgeFrozen:
		st.knowledgeFrozen = true
		if v := asString(data["observation_completeness"]); v != "" {
			st.observationCompleteness = v
		}
	case eventDispatchIntent:
		st.dispatchCount++
		st.pendingCommand = asString(data["command_id"])
		st.pendingRequest = asString(data["request_id"])
		st.lastDispatchState = "dispatching"
		st.lastDispatchRef = EvidenceRef{
			JournalID: env.JournalID, Sequence: env.Sequence,
			EventID: env.EventID, EventHash: env.EventHash, Pointer: "",
		}
	case eventDispatchRecorded:
		st.pendingCommand = ""
		st.pendingRequest = ""
		st.lastDispatchState = asString(data["outcome"])
	case eventDispatchRejected:
		st.pendingCommand = ""
		st.pendingRequest = ""
		st.lastDispatchState = "rejected"
	case eventDispatchUncertain:
		st.pendingCommand = ""
		st.pendingRequest = ""
		st.lastDispatchState = "uncertain"
	case eventObservationFenced:
		st.observationCompleteness = "unknown"
		st.bootID = r.bootID
	case eventSessionInterrupted:
		st.phase = phaseInterrupted
	case eventDiagnosticRecorded:
		st.diagnosticRevision = asInt64(data["analysis_revision"])
		st.documentDigest = asString(data["document_digest"])
		st.documentRef = ArtifactReference{
			Digest:      asString(data["document_digest"]),
			SizeBytes:   asInt64(data["document_size_bytes"]),
			MediaType:   asString(data["document_media_type"]),
			OwnerDomain: asString(data["document_owner_domain"]),
			Access:      asString(data["document_access"]),
		}
		st.lastAnalysisRef = refFrom(data, "analysis_request")
		st.lastAnalysisPrefix = prefixFrom(data, "input_prefix")
	case eventPublicationRecorded:
		if asString(data["state"]) == "published" {
			st.publishedRevision = asInt64(data["revision"])
		}
	case eventFinalizationRecorded, eventLateEvidenceFinalized:
		st.phase = phaseFinalized
		st.latePending = false
	case eventLateEvidenceRecorded:
		st.latePending = true
	}
}

// nowPoint returns the current coordinate on this boot's registered local
// monotonic clock. UTC is an annotation only and never a duration basis.
func (r *Runtime) nowPoint() TimePoint {
	offset := float64(time.Since(r.startedAt).Microseconds()) / 1000.0
	if offset < 0 {
		offset = 0
	}
	return TimePoint{
		ClockID: runtimeClockID, BootID: r.bootID, Origin: "engine_measured",
		MonotonicOffsetMs: offset, UTCAnnotation: owner_store.NewMissing("not_applicable"),
	}
}

// wrapStorage classifies owner-store failures. A closed or failed store is
// reported as unavailable durability, never as a rejected domain operation.
func wrapStorage(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, owner_store.ErrClosed) || errors.Is(err, owner_store.ErrStorageUnavailable) {
		return fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}
	return err
}

// bytesReader adapts canonical bytes for artifact installation.
func bytesReader(raw []byte) *bytes.Reader { return bytes.NewReader(raw) }

// ---------------------------------------------------------------------------
// Session registration.
// ---------------------------------------------------------------------------

// OpenSession registers one commissioned session with the runtime. It appends
// a durable registration marker to the session journal, reloads that journal
// prefix to learn the admitted manifest and any owner initialization receipts,
// claims a fenced session lease, and records the complete runtime binding.
//
// Repeated OpenSession calls for the same immutable commission return the
// existing binding: a second logical execution is never launched.
func (r *Runtime) OpenSession(ctx context.Context, spec SessionSpec) error {
	commission := spec.Commission
	sessionID := strings.TrimSpace(commission.Attempt.AttemptID)
	if sessionID == "" {
		return fmt.Errorf("%w: commission attempt_id is required", ErrInvalid)
	}
	journalID := strings.TrimSpace(commission.JournalID)
	if journalID == "" {
		return fmt.Errorf("%w: commission journal_id is required", ErrInvalid)
	}
	mode := strings.TrimSpace(commission.Execution.Mode)
	if mode == "" {
		mode = "manual"
	}
	if mode != "manual" && mode != "subject" {
		return fmt.Errorf("%w: execution mode %q is not manual or subject", ErrInvalid, mode)
	}

	r.mu.Lock()
	existing, ok := r.sessions[sessionID]
	r.mu.Unlock()
	if ok {
		if existing.journalID != journalID {
			return fmt.Errorf("%w: session %q already binds journal %q", ErrInvalid, sessionID, existing.journalID)
		}
		return nil
	}

	// Durable registration marker in the session (diagnostic) journal. This
	// also reveals the journal head, which is how the runtime learns an
	// admitted session's retained manifest and owner receipts without
	// scanning a peer database.
	registered, err := owner_store.CommitOwner(ctx, r.primary, journalID, []EventSubmission{{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventSessionRegistered,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id": sessionID, "attempt_id": sessionID,
				"journal_id": journalID, "mode": mode,
				"registered_by": runtimeSourceID,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}}, nil)
	if err != nil {
		if strings.Contains(err.Error(), "a journal begins with manifest_admitted") ||
			errors.Is(err, owner_store.ErrJournalUnknown) {
			return fmt.Errorf("%w: %s", ErrNotAdmitted, journalID)
		}
		return fmt.Errorf("session_runtime: register session %q: %w", sessionID, wrapStorage(err))
	}
	if len(registered) == 0 {
		return fmt.Errorf("%w: registration returned no envelope", ErrStorageUnavailable)
	}
	head := JournalPrefix{
		JournalID:    registered[len(registered)-1].JournalID,
		LastSequence: registered[len(registered)-1].Sequence,
		HeadHash:     registered[len(registered)-1].EventHash,
	}
	sessionEvents, err := owner_store.LoadPrefix(ctx, r.primary, head)
	if err != nil {
		return fmt.Errorf("session_runtime: load session journal %q: %w", journalID, err)
	}
	if len(sessionEvents) == 0 || sessionEvents[0].EventKind != "manifest_admitted" {
		return fmt.Errorf("%w: %s", ErrNotAdmitted, journalID)
	}
	journalManifest, err := r.readJournalManifest(ctx, sessionEvents[0])
	if err != nil {
		return fmt.Errorf("session_runtime: read admitted manifest %q: %w", journalID, err)
	}

	appRef, obsRef := receiptsFromSessionJournal(sessionEvents)
	obsManifest, obsPrefix := r.observationBinding(ctx, obsRef)

	lease, leaseErr := r.primary.ClaimLease(ctx, "session:"+sessionID, 0, defaultMaxRetries, defaultLeaseTTL)
	if leaseErr != nil && !errors.Is(leaseErr, owner_store.ErrLeaseHeld) {
		return fmt.Errorf("session_runtime: claim session lease: %w", leaseErr)
	}
	if errors.Is(leaseErr, owner_store.ErrLeaseHeld) {
		return fmt.Errorf("session_runtime: session %q is leased by another writer: %w", sessionID, leaseErr)
	}

	config := append([]byte(nil), spec.Configuration...)
	if len(config) == 0 {
		config = application_owner.DefaultFixtureConfiguration()
	}
	canonicalConfig, err := evidence_codec.CanonicalJSON(config, mediaTypeJSON)
	if err != nil {
		return fmt.Errorf("%w: effective configuration is not canonical JSON: %v", ErrInvalid, err)
	}
	diagnosticID := strings.TrimSpace(spec.DiagnosticID)
	if diagnosticID == "" {
		if r.diagnosticPrefix != "" {
			diagnosticID = r.diagnosticPrefix + sessionID
		} else {
			diagnosticID = "diagnostic-" + sessionID
		}
	}
	bounds := normalizedBounds(boundsFromCommission(commission))
	endpoint := strings.TrimSpace(spec.ConnectorEndpoint)
	if endpoint == "" {
		endpoint = r.endpoint
	}

	data := map[string]any{
		"session_id": sessionID, "attempt_id": sessionID,
		"journal_id": journalID, "mode": mode,
		"boot_id": r.bootID, "diagnostic_id": diagnosticID,
		"configuration":               string(canonicalConfig),
		"connector_endpoint":          endpoint,
		"active_limit_ms":             bounds.ActiveLimitMs,
		"drain_limit_ms":              bounds.DrainLimitMs,
		"native_cancel_wait_limit_ms": bounds.NativeCancelWaitLimitMs,
		"cleanup_wait_limit_ms":       bounds.CleanupWaitLimitMs,
		"lease_epoch":                 lease.AuthorityEpoch, "lease_boot": lease.BootID,
		"journal_manifest":     mustJSONString(journalManifest),
		"observation_manifest": mustJSONString(obsManifest),
		"commission":           mustJSONString(commission),
	}
	refInto(data, "application_init", appRef)
	refInto(data, "observation_init", obsRef)
	prefixInto(data, "observation_prefix", obsPrefix)
	if _, err := r.commitRuntime(ctx, eventSessionOpened, data, nil); err != nil {
		return err
	}
	return nil
}

// observationBinding loads the observation journal prefix named by an
// initialization receipt and returns its admitted manifest plus that prefix.
// Absent receipts stay absent; nothing is fabricated.
func (r *Runtime) observationBinding(ctx context.Context, obsRef EvidenceRef) (journal_rules.Manifest, JournalPrefix) {
	if obsRef.JournalID == "" || obsRef.Sequence < 1 {
		return journal_rules.Manifest{}, JournalPrefix{}
	}
	prefix := JournalPrefix{JournalID: obsRef.JournalID, LastSequence: obsRef.Sequence, HeadHash: obsRef.EventHash}
	events, err := owner_store.LoadPrefix(ctx, r.observation, prefix)
	if err != nil || len(events) == 0 || events[0].EventKind != "manifest_admitted" {
		return journal_rules.Manifest{}, JournalPrefix{}
	}
	manifest, err := r.readJournalManifestArtifact(ctx, r.observation, events[0])
	if err != nil {
		return journal_rules.Manifest{}, JournalPrefix{}
	}
	return manifest, prefix
}

// receiptsFromSessionJournal recovers the application and observation
// initialization references from primary-local receipt events. Receipts ride
// as flat scalars because a primary event may only cite its own journal.
func receiptsFromSessionJournal(events []JournalEnvelope) (appRef, obsRef EvidenceRef) {
	for i := range events {
		env := &events[i]
		data := env.Payload.Data
		var prefix string
		switch env.EventKind {
		case "application_init_receipt":
			prefix = "app_receipt"
		case "observation_init_receipt":
			prefix = "obs_receipt"
		default:
			continue
		}
		if asString(data["receipt_kind"]) == "" {
			continue
		}
		ref := EvidenceRef{
			JournalID: asString(data["receipt_journal"]),
			Sequence:  asInt64(data["receipt_sequence"]),
			EventID:   asString(data["receipt_event"]),
			EventHash: asString(data["receipt_hash"]),
			Pointer:   "",
		}
		if ref.JournalID == "" || ref.Sequence < 1 {
			continue
		}
		if prefix == "app_receipt" {
			appRef = ref
		} else {
			obsRef = ref
		}
	}
	return appRef, obsRef
}

// readJournalManifest reads the admitted manifest pinned by one
// manifest_admitted event.
func (r *Runtime) readJournalManifest(ctx context.Context, env JournalEnvelope) (journal_rules.Manifest, error) {
	return r.readJournalManifestArtifact(ctx, r.primary, env)
}

// readJournalManifestArtifact reads a pinned manifest artifact from one store.
func (r *Runtime) readJournalManifestArtifact(ctx context.Context, store *OwnerStore, env JournalEnvelope) (journal_rules.Manifest, error) {
	var manifest journal_rules.Manifest
	raw, ok := env.Payload.Data["manifest"]
	if !ok {
		return manifest, fmt.Errorf("manifest admission pins no manifest artifact")
	}
	refBytes, err := json.Marshal(raw)
	if err != nil {
		return manifest, err
	}
	var ref ArtifactReference
	if err := json.Unmarshal(refBytes, &ref); err != nil {
		return manifest, err
	}
	if ref.Digest == "" {
		return manifest, fmt.Errorf("manifest artifact reference is empty")
	}
	content, err := owner_store.ReadArtifact(ctx, store, ref)
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

// Snapshot returns a read-only projection of one session's durable state.
func (r *Runtime) Snapshot(sessionID string) (SessionSnapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.sessions[sessionID]
	if !ok {
		return SessionSnapshot{}, false
	}
	return SessionSnapshot{
		SessionID: st.id, AttemptID: st.attemptID, JournalID: st.journalID,
		Mode: st.mode, Phase: st.phase, BootID: st.bootID,
		DispatchCount: st.dispatchCount, PendingDispatch: st.pendingCommand,
		LastDispatchState: st.lastDispatchState,
		CloseReason:       st.closeReason, DrainState: st.drainState,
		ObservationState:        st.observationState,
		ObservationRevision:     st.observationRevision,
		ObservationCompleteness: st.observationCompleteness,
		ApplicationState:        st.applicationState,
		ApplicationRevision:     st.applicationRevision,
		DiagnosticRevision:      st.diagnosticRevision,
		DiagnosticDigest:        st.documentDigest,
		PublishedRevision:       st.publishedRevision,
		Finalized:               st.phase == phaseFinalized,
	}, true
}

// Events returns a copy of the retained runtime journal events.
func (r *Runtime) Events() []JournalEnvelope {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]JournalEnvelope, len(r.events))
	copy(out, r.events)
	return out
}

// AdvanceAdmission drives the owner-initialization steps of admission
// (seam 5.1 steps 8-10) for one already-admitted session through the
// admission owner. It never holds a primary transaction while a peer owner
// writes.
func (r *Runtime) AdvanceAdmission(ctx context.Context, sessionID string) error {
	if err := admission.AdvanceAdmission(ctx, r.primary, r.application, r.observation, sessionID); err != nil {
		return fmt.Errorf("session_runtime: advance admission %q: %w", sessionID, err)
	}
	return nil
}

// stateCopy returns a read-only copy of one durable session state.
func (r *Runtime) stateCopy(sessionID string) (sessionState, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.sessions[sessionID]
	if !ok {
		return sessionState{}, false
	}
	return *st, true
}

// ---------------------------------------------------------------------------
// Work acceptance.
// ---------------------------------------------------------------------------

// Accept records and enqueues one bounded work item. Acceptance is durable
// before the item can be served: a rejected item is journalled as rejected
// and reported, never silently discarded, and an accepted workflow item
// consumes its active observation budget from the accepted instant.
func (r *Runtime) Accept(ctx context.Context, item WorkItem) error {
	st, ok := r.stateCopy(item.SessionID)
	if !ok {
		return fmt.Errorf("%w: unknown session %q", ErrInvalid, item.SessionID)
	}
	if item.Kind == "" {
		item.Kind = WorkflowWork
	}
	if st.phase != phaseOpen || st.closeRequested {
		if _, err := r.commitRuntime(ctx, eventWorkRejected, map[string]any{
			"session_id": st.id, "kind": string(item.Kind), "operation": item.Operation,
			"reason": "session_not_open", "phase": st.phase,
		}, nil); err != nil {
			return err
		}
		return ErrSessionClosed
	}

	limit := clock_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: st.bounds.ActiveLimitMs}
	start := r.nowPoint()
	deadline, err := clock_rules.ComputeDeadline(clock_rules.TimePoint{
		ClockID: start.ClockID, BootID: start.BootID, Origin: start.Origin,
		MonotonicOffsetMs: start.MonotonicOffsetMs,
		UTCAnnotation:     clock_rules.Missing{Reason: "not_applicable"},
	}, limit)
	if err != nil {
		return fmt.Errorf("session_runtime: compute active budget: %w", err)
	}
	acceptedAt := time.Now()
	if err := r.queue.tryEnqueue(item, acceptedAt, deadline.MonotonicOffsetMs, r.bootID); err != nil {
		if _, rerr := r.commitRuntime(ctx, eventWorkRejected, map[string]any{
			"session_id": st.id, "kind": string(item.Kind), "operation": item.Operation,
			"reason":      "queue_full",
			"queue_depth": r.queue.depth(), "queue_capacity": r.limits.Capacity,
			"control_reserve": r.limits.ControlReserve,
		}, nil); rerr != nil {
			return fmt.Errorf("%w (durable rejection record failed: %v)", err, rerr)
		}
		return err
	}
	if _, err := r.commitRuntime(ctx, eventWorkAccepted, map[string]any{
		"session_id": st.id, "kind": string(item.Kind), "operation": item.Operation,
		"request_id":         item.RequestID,
		"active_budget_ms":   st.bounds.ActiveLimitMs,
		"deadline_offset_ms": deadline.MonotonicOffsetMs,
		"deadline_boot":      r.bootID,
		"queue_depth":        r.queue.depth(),
	}, nil); err != nil {
		// Durability failed after the local queue took the item: drop it so
		// an unpersisted acceptance is never served.
		r.queue.removeWhere(func(q queuedWork) bool {
			return q.item.SessionID == item.SessionID && q.item.Kind == item.Kind &&
				q.item.Operation == item.Operation && q.item.RequestID == item.RequestID
		})
		return err
	}
	return nil
}

// ServeSessionWork runs bounded session work across the owner stores until
// ctx ends. Restart recovery runs before the first item, and the loop never
// performs a cross-owner transaction or issues browser/crawler traffic. With
// no queued work it waits for cancellation and returns nil.
func ServeSessionWork(ctx context.Context, primary *OwnerStore, application *OwnerStore, observation *OwnerStore) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runtime, err := NewRuntime(ctx, primary, application, observation, Options{})
	if err != nil {
		return err
	}
	if err := runtime.Recover(ctx); err != nil {
		return err
	}
	return runtime.Serve(ctx)
}

// Serve drains accepted work until the context ends. Control and close work
// is always taken before workflow work, so queue pressure cannot starve
// closure.
func (r *Runtime) Serve(ctx context.Context) error {
	for {
		queued, err := r.queue.take(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return err
		}
		if err := r.processItem(ctx, queued); err != nil {
			if errors.Is(err, ErrStorageUnavailable) {
				return err
			}
			// Domain-level failures stay recorded per item; the loop keeps
			// serving other sessions.
		}
	}
}

// Step serves at most one queued item, reporting whether one was available.
// It lets an engine drive the loop deterministically without a background
// goroutine.
func (r *Runtime) Step(ctx context.Context) (bool, error) {
	queued, err := r.queue.take(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, nil
		}
		return false, err
	}
	return true, r.processItem(ctx, queued)
}

// processItem executes one accepted item.
func (r *Runtime) processItem(ctx context.Context, queued *queuedWork) error {
	st, ok := r.stateCopy(queued.item.SessionID)
	if !ok {
		return fmt.Errorf("%w: queued item names unknown session %q", ErrInvalid, queued.item.SessionID)
	}
	switch queued.item.Kind {
	case CloseWork:
		reason := queued.item.Reason
		if !reason.Valid() {
			reason = CloseOperatorStop
		}
		_, err := r.finalize(ctx, st.commission, reason)
		return err
	case ControlWork:
		return r.performControl(ctx, st, queued.item)
	default:
		return r.processWorkflow(ctx, st, queued)
	}
}

// processWorkflow performs one bounded native delivery. A workflow command is
// never issued after the close boundary, after the commissioned active budget
// deadline, or after restart fencing.
func (r *Runtime) processWorkflow(ctx context.Context, st sessionState, queued *queuedWork) error {
	if st.phase != phaseOpen || st.closeRequested {
		_, err := r.commitRuntime(ctx, eventWorkRejected, map[string]any{
			"session_id": st.id, "operation": queued.item.Operation,
			"reason": "no_delivery_after_close", "phase": st.phase,
		}, nil)
		return err
	}
	if queued.deadlineBoot != r.bootID {
		_, err := r.commitRuntime(ctx, eventWorkRejected, map[string]any{
			"session_id": st.id, "operation": queued.item.Operation,
			"reason":        "active_budget_boot_changed",
			"accepted_boot": queued.deadlineBoot, "serving_boot": r.bootID,
		}, nil)
		return err
	}
	now := r.nowPoint()
	if now.MonotonicOffsetMs > queued.deadlineMs {
		_, err := r.commitRuntime(ctx, eventWorkRejected, map[string]any{
			"session_id": st.id, "operation": queued.item.Operation,
			"reason":             "active_budget_exhausted",
			"deadline_offset_ms": queued.deadlineMs,
			"observed_offset_ms": now.MonotonicOffsetMs,
		}, nil)
		return err
	}
	return r.deliverWorkflow(ctx, st, queued.item, queued.deadlineMs)
}

// PrepareDispatch journals one native dispatch intent without delivering it.
// It is the crash seam: a later boot that finds the intent with no outcome
// must record dispatch uncertainty and must not resend.
func (r *Runtime) PrepareDispatch(ctx context.Context, sessionID string, operation string) (string, string, error) {
	st, ok := r.stateCopy(sessionID)
	if !ok {
		return "", "", fmt.Errorf("%w: unknown session %q", ErrInvalid, sessionID)
	}
	if operation == "" {
		operation = connector_transport.OpStart
	}
	commandID := fmt.Sprintf("cmd-%s-%d", st.id, st.dispatchCount+1)
	requestID := commandID + "-request"
	payload := json.RawMessage(`{"command_id":"` + commandID + `"}`)
	request := connector_transport.ConnectorRequest{
		RecordType:    connector_transport.RecordTypeRequest,
		SchemaVersion: connector_transport.SchemaVersion,
		RequestID:     requestID, ConnectorID: st.id,
		Operation: operation,
		CallLimit: connector_transport.DurationLimit{Kind: "exact", Unit: "ms", Value: r.callLimitMs},
		Payload:   payload,
	}
	digest, err := canonicalDigest(request)
	if err != nil {
		return "", "", fmt.Errorf("session_runtime: digest dispatch request: %w", err)
	}
	if _, err := r.commitRuntime(ctx, eventDispatchIntent, map[string]any{
		"session_id": st.id, "command_id": commandID, "request_id": requestID,
		"operation": operation, "request_digest": digest,
		"delivery_started": false,
	}, nil); err != nil {
		return "", "", err
	}
	return commandID, requestID, nil
}

// deliverWorkflow journals the intent, performs exactly one connector call,
// and records the correlated outcome. Ambiguous delivery is recorded as
// uncertain with no resend and no native termination claim.
func (r *Runtime) deliverWorkflow(ctx context.Context, st sessionState, item WorkItem, deadlineMs float64) error {
	operation := item.Operation
	if operation == "" {
		operation = connector_transport.OpStart
	}
	commandID := fmt.Sprintf("cmd-%s-%d", st.id, st.dispatchCount+1)
	requestID := item.RequestID
	if requestID == "" {
		requestID = commandID + "-request"
	}
	payload := item.Payload
	if len(bytes.TrimSpace(payload)) == 0 {
		payload = json.RawMessage(`{"command_id":"` + commandID + `"}`)
	}
	now := r.nowPoint()
	remaining := deadlineMs - now.MonotonicOffsetMs
	callLimit := r.callLimitMs
	if remaining < callLimit {
		callLimit = remaining
	}
	if callLimit <= 0 {
		_, err := r.commitRuntime(ctx, eventWorkRejected, map[string]any{
			"session_id": st.id, "operation": operation,
			"reason":             "active_budget_exhausted",
			"deadline_offset_ms": deadlineMs, "observed_offset_ms": now.MonotonicOffsetMs,
		}, nil)
		return err
	}
	request := connector_transport.ConnectorRequest{
		RecordType:    connector_transport.RecordTypeRequest,
		SchemaVersion: connector_transport.SchemaVersion,
		RequestID:     requestID, ConnectorID: st.id, Operation: operation,
		CallLimit: connector_transport.DurationLimit{Kind: "exact", Unit: "ms", Value: callLimit},
		Payload:   payload,
	}
	requestDigest, err := canonicalDigest(request)
	if err != nil {
		return fmt.Errorf("session_runtime: digest dispatch request: %w", err)
	}
	intent, err := r.commitRuntime(ctx, eventDispatchIntent, map[string]any{
		"session_id": st.id, "command_id": commandID, "request_id": requestID,
		"operation": operation, "request_digest": requestDigest,
		"delivery_started": true,
	}, nil)
	if err != nil {
		// No durable intent means no delivery: an unpersisted dispatch may
		// never produce native side effects.
		return err
	}
	intentRef := EvidenceRef{
		JournalID: intent.JournalID, Sequence: intent.Sequence,
		EventID: intent.EventID, EventHash: intent.EventHash, Pointer: "",
	}

	callCtx, cancel := context.WithTimeout(ctx, durationFromMs(callLimit))
	defer cancel()
	if st.endpoint == "" {
		return r.recordDispatchUncertain(ctx, st, commandID, requestID, "endpoint_unavailable", "no deployment connector endpoint is configured", "not_dispatched", intentRef)
	}
	response, callErr := connector_transport.CallConnector(callCtx, st.endpoint, request)
	if callErr != nil {
		var connectorErr *connector_transport.ConnectorError
		if errors.As(callErr, &connectorErr) {
			delivery := connectorErr.OperationDelivery
			if delivery == "may_have_dispatched" || delivery == "dispatched" {
				return r.recordDispatchUncertain(ctx, st, commandID, requestID, connectorErr.Code, connectorErr.Detail, delivery, intentRef)
			}
			if _, err := r.commitRuntime(ctx, eventDispatchRejected, map[string]any{
				"session_id": st.id, "command_id": commandID, "request_id": requestID,
				"operation": operation, "code": connectorErr.Code,
				"detail": connectorErr.Detail, "delivery": delivery,
				"subject_failure_claimed": false,
			}, []EvidenceRef{intentRef}); err != nil {
				return err
			}
			return nil
		}
		return r.recordDispatchUncertain(ctx, st, commandID, requestID, "DELIVERY_UNCERTAIN", callErr.Error(), "may_have_dispatched", intentRef)
	}
	responseDigest, err := canonicalDigest(response)
	if err != nil {
		return fmt.Errorf("session_runtime: digest connector response: %w", err)
	}
	_, err = r.commitRuntime(ctx, eventDispatchRecorded, map[string]any{
		"session_id": st.id, "command_id": commandID, "request_id": requestID,
		"operation": operation, "outcome": "accepted",
		"response_digest": responseDigest,
		"delivery":        "dispatched",
	}, []EvidenceRef{intentRef})
	return err
}

// recordDispatchUncertain records ambiguous delivery. It never asserts we
// may resend and never claims a native stop.
func (r *Runtime) recordDispatchUncertain(ctx context.Context, st sessionState, commandID, requestID, code, detail, delivery string, intentRef EvidenceRef) error {
	if delivery == "" {
		delivery = "may_have_dispatched"
	}
	_, err := r.commitRuntime(ctx, eventDispatchUncertain, map[string]any{
		"session_id": st.id, "command_id": commandID, "request_id": requestID,
		"code": code, "detail": detail, "delivery": delivery,
		"native_state": "unknown", "resend": "forbidden",
		"termination_claimed": false,
	}, []EvidenceRef{intentRef})
	return err
}

// performControl records one control operation separately. A request is not
// an acknowledgement and an acknowledgement is not an observed effect.
func (r *Runtime) performControl(ctx context.Context, st sessionState, item WorkItem) error {
	operation := item.Operation
	if operation == "" {
		operation = connector_transport.OpRequestNativeCancel
	}
	switch operation {
	case connector_transport.OpRequestNativeCancel, connector_transport.OpCloseObservationConnection,
		connector_transport.OpReleaseNativeContext, connector_transport.OpContain:
	default:
		return fmt.Errorf("%w: %q is not a control operation", ErrInvalid, operation)
	}
	commandID := fmt.Sprintf("ctrl-%s-%d", st.id, r.queue.depth())
	availability := "available"
	disposition := "not_attempted"
	if st.mode == "manual" {
		availability = "not_applicable"
		disposition = "not_applicable"
	}
	requestDigest := ""
	responseDigest := ""
	var extraDetail any = owner_store.NewMissing("not_applicable")
	if availability == "available" {
		if st.endpoint == "" {
			availability = "unavailable"
			disposition = "unavailable"
			extraDetail = "no deployment connector endpoint is configured"
		} else {
			request := connector_transport.ConnectorRequest{
				RecordType:    connector_transport.RecordTypeRequest,
				SchemaVersion: connector_transport.SchemaVersion,
				RequestID:     commandID + "-request", ConnectorID: st.id, Operation: operation,
				CallLimit: connector_transport.DurationLimit{Kind: "exact", Unit: "ms", Value: st.bounds.NativeCancelWaitLimitMs},
				Payload:   json.RawMessage(`{"command_id":"` + commandID + `"}`),
			}
			if digest, err := canonicalDigest(request); err == nil {
				requestDigest = digest
			}
			callCtx, cancel := context.WithTimeout(ctx, durationFromMs(st.bounds.NativeCancelWaitLimitMs))
			response, err := connector_transport.CallConnector(callCtx, st.endpoint, request)
			cancel()
			if err != nil {
				var connectorErr *connector_transport.ConnectorError
				if errors.As(err, &connectorErr) {
					extraDetail = connectorErr.Detail
					switch connectorErr.Code {
					case "UNSUPPORTED_MAPPING", "UNSUPPORTED_VERSION":
						disposition = "unsupported"
					case "FORBIDDEN":
						disposition = "rejected"
					case "DELIVERY_UNCERTAIN":
						disposition = "uncertain"
					default:
						disposition = "unavailable"
					}
				} else {
					disposition = "unavailable"
					extraDetail = err.Error()
				}
			} else {
				disposition = "requested"
				if operation == connector_transport.OpCloseObservationConnection {
					disposition = "closed_requested"
				}
				if digest, derr := canonicalDigest(response); derr == nil {
					responseDigest = digest
				}
			}
		}
	}
	controlData := map[string]any{
		"session_id": st.id, "command_id": commandID, "operation": operation,
		"availability": availability, "disposition": disposition,
		"detail":                    extraDetail,
		"native_termination":        owner_store.NewMissing("not_observed"),
		"acknowledgement_is_effect": false,
	}
	putDigest(controlData, "request_digest", requestDigest)
	putDigest(controlData, "response_digest", responseDigest)
	_, err := r.commitRuntime(ctx, eventControlRecorded, controlData, nil)
	return err
}

// ---------------------------------------------------------------------------
// Restart recovery (seam 14.2).
// ---------------------------------------------------------------------------

// Recover applies the restart rules to every non-terminal session: unfinished
// dispatch becomes uncertain (never resent), unfinished observation epochs are
// durably fenced without assuming the native side stopped, and unfinished
// sessions are marked infrastructure-interrupted. Recovery never calls the
// connector and never compares offsets across boots.
func (r *Runtime) Recover(ctx context.Context) error {
	r.mu.Lock()
	if r.recovered {
		r.mu.Unlock()
		return nil
	}
	ids := append([]string(nil), r.order...)
	r.mu.Unlock()

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, id := range ids {
		st, ok := r.stateCopy(id)
		if !ok || st.terminal() {
			continue
		}
		if st.pendingCommand != "" {
			_, err := r.commitRuntime(ctx, eventDispatchUncertain, map[string]any{
				"session_id": st.id, "command_id": st.pendingCommand,
				"request_id":   st.pendingRequest,
				"code":         "DELIVERY_UNCERTAIN",
				"detail":       "runtime restart found a dispatch intent with no recorded outcome",
				"delivery":     "may_have_dispatched",
				"native_state": "unknown", "resend": "forbidden",
				"termination_claimed": false,
				"recovered_boot":      r.bootID,
			}, []EvidenceRef{st.lastDispatchRef})
			record(err)
		}
		if st.bootID == "" || st.bootID == r.bootID {
			continue
		}
		// A session accepted under an earlier boot: fence the stale epoch.
		lease, leaseErr := r.primary.ClaimLease(ctx, "session:"+st.id, 0, defaultMaxRetries, defaultLeaseTTL)
		fence := map[string]any{
			"session_id":                 st.id,
			"reason":                     "authority_restart",
			"previous_boot":              st.bootID,
			"serving_boot":               r.bootID,
			"previous_lease_epoch":       st.leaseEpoch,
			"native_stop":                owner_store.NewMissing("not_observed"),
			"native_termination_claimed": false,
			"observation_completeness":   "unknown",
		}
		if leaseErr == nil {
			fence["new_lease_epoch"] = lease.AuthorityEpoch
			fence["new_lease_boot"] = lease.BootID
			fence["previous_lease_fenced"] = lease.AuthorityEpoch > st.leaseEpoch
		} else {
			fence["lease_error"] = leaseErr.Error()
		}
		record(func() error {
			_, err := r.commitRuntime(ctx, eventObservationFenced, fence, nil)
			return err
		}())
		record(func() error {
			_, err := r.commitRuntime(ctx, eventSessionInterrupted, map[string]any{
				"session_id":         st.id,
				"reason":             string(CloseInfrastructureInterruption),
				"detail":             "unfinished session fenced by restart; native execution state is unobserved",
				"diagnostic_pending": st.diagnosticRevision == 0,
				"native_state":       "unknown",
			}, nil)
			return err
		}())
	}
	r.mu.Lock()
	r.recovered = true
	r.mu.Unlock()
	return firstErr
}

// ---------------------------------------------------------------------------
// FinalizeSession (closure protocol, seam 9.9).
// ---------------------------------------------------------------------------

// FinalizeSession performs the local closure protocol for one commissioned
// session and returns the diagnostic document derived after closure. It never
// holds one owner's transaction while another owner runs, and every wait is
// bounded by the commissioned local limits.
func FinalizeSession(ctx context.Context, primary *OwnerStore, application *OwnerStore, observation *OwnerStore, commission AttemptCommission, reason CloseReason) (DiagnosticDocument, error) {
	var zero DiagnosticDocument
	if ctx == nil {
		ctx = context.Background()
	}
	runtime, err := runtimeFor(ctx, primary, application, observation)
	if err != nil {
		return zero, err
	}
	return runtime.finalize(ctx, commission, reason)
}

// Finalize runs the closure protocol on this runtime instance, reusing its
// boot clock and in-memory queue. The durable close steps are idempotent, so a
// repeated call after late evidence derives only the new revision.
func (r *Runtime) Finalize(ctx context.Context, commission AttemptCommission, reason CloseReason) (DiagnosticDocument, error) {
	return r.finalize(ctx, commission, reason)
}

// finalize runs the closure protocol steps in order. Steps already recorded
// durably are not repeated: a repeated Finalize returns the retained
// diagnostic document, and a close that received late evidence derives a new
// diagnostic revision without reopening observation.
func (r *Runtime) finalize(ctx context.Context, commission AttemptCommission, reason CloseReason) (DiagnosticDocument, error) {
	var zero DiagnosticDocument
	if !reason.Valid() {
		return zero, fmt.Errorf("%w: close reason %q is not a commissioned reason", ErrInvalid, reason)
	}
	sessionID := strings.TrimSpace(commission.Attempt.AttemptID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(commission.RunID)
	}
	if sessionID == "" {
		return zero, fmt.Errorf("%w: commission names no attempt", ErrInvalid)
	}
	st, ok := r.stateCopy(sessionID)
	if !ok {
		if err := r.OpenSession(ctx, SessionSpec{Commission: commission, ConnectorEndpoint: r.endpoint}); err != nil {
			return zero, err
		}
		st, ok = r.stateCopy(sessionID)
		if !ok {
			return zero, fmt.Errorf("%w: session %q is not durably registered", ErrNotAdmitted, sessionID)
		}
	}
	if st.phase == phaseFinalized && !st.latePending {
		if doc, err := r.loadDocument(ctx, st); err == nil {
			return doc, nil
		}
	}

	// Step 1: stop issuing workflow commands. Queued workflow work for this
	// session is rejected durably so it is not silently lost.
	if !st.closeRequested {
		if _, err := r.commitRuntime(ctx, eventCloseRequested, map[string]any{
			"session_id": st.id, "reason": string(reason),
			"stop_workflow_commands": true,
			"end_observation":        true,
		}, nil); err != nil {
			return zero, err
		}
		// Only workflow work is stopped at the close boundary. Control
		// requests remain independently servable after close.
		dropped := r.queue.removeWhere(func(q queuedWork) bool {
			return q.item.SessionID == st.id && q.item.Kind == WorkflowWork
		})
		for _, q := range dropped {
			if _, err := r.commitRuntime(ctx, eventWorkRejected, map[string]any{
				"session_id": st.id, "kind": string(q.item.Kind),
				"operation": q.item.Operation, "reason": "close_requested",
			}, nil); err != nil {
				return zero, err
			}
		}
		st, _ = r.stateCopy(sessionID)
	}

	// Step 2: record cancel availability and any request separately.
	if st.controlCancelState == "" {
		if err := r.recordNativeCancel(ctx, st, commission); err != nil {
			return zero, err
		}
		st, _ = r.stateCopy(sessionID)
	}

	// Step 3: record transport closure separately.
	if !st.transportClosed {
		if _, err := r.commitRuntime(ctx, eventTransportClosed, map[string]any{
			"session_id": st.id, "end_observation": true,
			"transport_selected":  "native_observation",
			"remote_confirmation": owner_store.NewMissing("not_observed"),
			"native_termination":  owner_store.NewMissing("not_observed"),
			"reason":              string(reason),
		}, nil); err != nil {
			return zero, err
		}
		st, _ = r.stateCopy(sessionID)
	}

	// Step 4: drain only within the commissioned bound. An unavailable
	// observation tail is recorded as incomplete/unknown, never complete.
	if st.drainState == "" {
		if err := r.drainObservation(ctx, st); err != nil {
			return zero, err
		}
		st, _ = r.stateCopy(sessionID)
	}

	// Step 5: request fixture-origin sealing. Failure is recorded and does
	// not block local closure.
	if st.applicationState == "" {
		if err := r.sealOrigin(ctx, st, commission); err != nil {
			return zero, err
		}
		st, _ = r.stateCopy(sessionID)
	}

	// Step 6: close locally within the bound even if remote work continues.
	if st.observationState == "" {
		if err := r.closeObservation(ctx, st, commission); err != nil {
			return zero, err
		}
		st, _ = r.stateCopy(sessionID)
	}

	// Step 7: freeze knowledge and pins.
	if !st.knowledgeFrozen {
		if err := r.freezeKnowledge(ctx, st, reason); err != nil {
			return zero, err
		}
		st, _ = r.stateCopy(sessionID)
	}

	// Steps 8-9: accept authorized late evidence at the current head and
	// publish a new diagnostic revision without reopening observation.
	doc, err := r.deriveDiagnostic(ctx, st, commission)
	if err != nil {
		// Diagnostic failure is an interruption, never a fabricated report.
		if _, recErr := r.commitRuntime(ctx, eventSessionInterrupted, map[string]any{
			"session_id": st.id, "reason": string(CloseInfrastructureInterruption),
			"detail":             "diagnostic derivation unavailable: " + err.Error(),
			"diagnostic_pending": true,
			"native_state":       "unknown",
		}, nil); recErr != nil {
			return zero, recErr
		}
		return zero, fmt.Errorf("session_runtime: finalize %q: %w", st.id, err)
	}
	st, _ = r.stateCopy(sessionID)
	if err := r.publishDiagnostic(ctx, st, doc); err != nil {
		// Publication failure is recorded; the source remains committed and
		// the read view remains older. It is not a fabricated diagnostic.
		if _, recErr := r.commitRuntime(ctx, eventPublicationRecorded, map[string]any{
			"session_id":         st.id,
			"state":              "unavailable",
			"revision":           st.publishedRevision + 1,
			"analysis_revision":  st.diagnosticRevision,
			"detail":             err.Error(),
			"source_committed":   true,
			"read_view_advanced": false,
		}, nil); recErr != nil {
			return zero, recErr
		}
	}

	terminalKind := eventFinalizationRecorded
	if st.latePending {
		terminalKind = eventLateEvidenceFinalized
	}
	if _, err := r.commitRuntime(ctx, terminalKind, map[string]any{
		"session_id": st.id, "reason": string(reason),
		"outcome":                  "finalized",
		"analysis_revision":        st.diagnosticRevision + 1,
		"diagnostic_digest":        st.documentDigest,
		"observation_state":        st.observationState,
		"observation_revision":     st.observationRevision,
		"observation_completeness": st.observationCompleteness,
		"application_state":        st.applicationState,
		"application_revision":     st.applicationRevision,
		"published_revision":       st.publishedRevision,
		"late_evidence":            st.latePending,
		"observation_reopened":     false,
	}, nil); err != nil {
		return zero, err
	}
	return doc, nil
}

// recordNativeCancel records cancel availability and any request as separate
// control evidence. A request never implies acknowledgement or termination.
func (r *Runtime) recordNativeCancel(ctx context.Context, st sessionState, commission AttemptCommission) error {
	availability := "available"
	if commission.Execution.Mode == "manual" || st.mode == "manual" {
		availability = "not_applicable"
	}
	disposition := "not_attempted"
	requestDigest := ""
	responseDigest := ""
	detail := "no native cancellation requested: close is a local observation-owner operation"
	if availability == "available" {
		if st.endpoint == "" {
			availability = "unavailable"
			disposition = "unavailable"
			detail = "no deployment connector endpoint is configured"
		} else {
			commandID := "cancel-" + st.id
			request := connector_transport.ConnectorRequest{
				RecordType:    connector_transport.RecordTypeRequest,
				SchemaVersion: connector_transport.SchemaVersion,
				RequestID:     commandID + "-request", ConnectorID: st.id,
				Operation: connector_transport.OpRequestNativeCancel,
				CallLimit: connector_transport.DurationLimit{Kind: "exact", Unit: "ms", Value: st.bounds.NativeCancelWaitLimitMs},
				Payload:   json.RawMessage(`{"command_id":"` + commandID + `"}`),
			}
			if digest, err := canonicalDigest(request); err == nil {
				requestDigest = digest
			}
			callCtx, cancel := context.WithTimeout(ctx, durationFromMs(st.bounds.NativeCancelWaitLimitMs))
			response, err := connector_transport.CallConnector(callCtx, st.endpoint, request)
			cancel()
			if err != nil {
				var connectorErr *connector_transport.ConnectorError
				if errors.As(err, &connectorErr) {
					detail = connectorErr.Detail
					switch connectorErr.Code {
					case "UNSUPPORTED_MAPPING", "UNSUPPORTED_VERSION":
						disposition = "unsupported"
					case "FORBIDDEN":
						disposition = "rejected"
					case "DELIVERY_UNCERTAIN":
						disposition = "uncertain"
					default:
						disposition = "unavailable"
					}
				} else {
					disposition = "unavailable"
					detail = err.Error()
				}
			} else {
				disposition = "requested"
				if digest, derr := canonicalDigest(response); derr == nil {
					responseDigest = digest
				}
			}
		}
	}
	controlData := map[string]any{
		"session_id":   st.id,
		"operation":    connector_transport.OpRequestNativeCancel,
		"availability": availability, "disposition": disposition,
		"detail":                    detail,
		"native_termination":        owner_store.NewMissing("not_observed"),
		"acknowledgement_is_effect": false,
	}
	putDigest(controlData, "request_digest", requestDigest)
	putDigest(controlData, "response_digest", responseDigest)
	_, err := r.commitRuntime(ctx, eventControlRecorded, controlData, nil)
	return err
}

// drainObservation loads the retained observation prefix within the
// commissioned drain limit and imports it as diagnostic-source evidence. When
// the observation store or its prefix is unavailable the tail is recorded as
// incomplete/unknown and is never called complete.
func (r *Runtime) drainObservation(ctx context.Context, st sessionState) error {
	bound := durationFromMs(st.bounds.DrainLimitMs)
	dctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	state := drainUnavailable
	completeness := "unknown"
	detail := ""
	drained := 0
	imported := 0
	switch {
	case st.obsRef.JournalID == "":
		detail = "observation initialization evidence is not available locally"
	case st.obsJournalManifest.JournalID == "":
		detail = "observation journal manifest is not available locally"
	default:
		prefix := st.obsPrefix
		if prefix.JournalID == "" || prefix.LastSequence < 1 {
			prefix = JournalPrefix{JournalID: st.obsRef.JournalID, LastSequence: st.obsRef.Sequence, HeadHash: st.obsRef.EventHash}
		}
		events, err := owner_store.LoadPrefix(dctx, r.observation, prefix)
		if err != nil {
			detail = err.Error()
			break
		}
		drained = len(events)
		state = drainComplete
		if completenessResult, err := observation_owner.AssessProducerCompleteness(dctx, r.observation, st.obsRef.JournalID); err == nil {
			completeness = completenessResult.State
		}
		policy, err := r.installImportPolicy(dctx, st.obsJournalManifest.OwnerDomain)
		if err != nil {
			state = drainIncomplete
			detail = "install import policy: " + err.Error()
			break
		}
		refs, err := evidence_import.ImportSourcePrefix(dctx, r.primary, st.obsJournalManifest, prefix, events, policy)
		if err != nil {
			state = drainIncomplete
			detail = "import observation prefix: " + err.Error()
			break
		}
		imported = len(refs)
	}
	data := map[string]any{
		"session_id":            st.id,
		"state":                 state,
		"producer_completeness": completeness,
		"drained_events":        drained,
		"imported_events":       imported,
		"bound_ms":              st.bounds.DrainLimitMs,
	}
	if detail != "" {
		data["detail"] = detail
	} else {
		data["detail"] = owner_store.NewMissing("not_applicable")
	}
	if state == drainUnavailable {
		data["producer_completeness"] = "unknown"
	}
	_, err := r.commitRuntime(ctx, eventDrainRecorded, data, nil)
	return err
}

// installImportPolicy installs one import-policy artifact authorizing exactly
// the observation owner domain.
func (r *Runtime) installImportPolicy(ctx context.Context, sourceOwner string) (VersionPin, error) {
	owner := strings.TrimSpace(sourceOwner)
	if owner == "" {
		return VersionPin{}, fmt.Errorf("%w: source owner domain is required", ErrInvalid)
	}
	doc := map[string]any{
		"policy_id":          "session-runtime-source-" + owner,
		"version":            "session-runtime/1",
		"authorized_sources": []any{owner},
		"verification_kind":  "pinned_contract_presence",
	}
	raw, err := canonicalBytes(doc)
	if err != nil {
		return VersionPin{}, err
	}
	ref, err := owner_store.InstallArtifact(ctx, r.primary, bytes.NewReader(raw), mediaTypeJSON, accessPublic)
	if err != nil {
		return VersionPin{}, err
	}
	return VersionPin{ID: "session-runtime-source-" + owner, Version: "session-runtime/1", ArtifactDigest: ref.Digest}, nil
}

// sealOrigin requests fixture-origin sealing through the application owner
// within the commissioned cleanup bound. Unavailability is recorded and local
// closure continues; no final absence is manufactured.
func (r *Runtime) sealOrigin(ctx context.Context, st sessionState, commission AttemptCommission) error {
	state := "unavailable"
	detail := ""
	revision := int64(0)
	digest := ""
	if st.appRef.JournalID == "" || st.appRef.Sequence < 1 {
		detail = "application initialization evidence is not available locally"
	} else if commission.Attempt.Kind != "" && commission.Attempt.Kind != "practice" {
		state = "unsupported"
		detail = "fixture sealing admits only practice attempts"
	} else {
		bound := durationFromMs(st.bounds.CleanupWaitLimitMs)
		sctx, cancel := context.WithTimeout(ctx, bound)
		attempt := AttemptReference{AttemptID: st.attemptID, Kind: "practice"}
		rev, err := application_owner.SealApplication(sctx, r.application, attempt, st.appRef)
		cancel()
		switch {
		case err == nil:
			state = "sealed"
			revision = rev.Revision
			digest = digestRevision(rev)
		case errors.Is(err, application_owner.ErrSealed):
			state = "sealed"
			detail = "application mutation authority was already sealed"
		default:
			detail = err.Error()
		}
	}
	data := map[string]any{
		"session_id": st.id, "state": state,
		"revision":              revision,
		"bound_ms":              st.bounds.CleanupWaitLimitMs,
		"final_absence_claimed": false,
		"application_knowledge": "unknown",
	}
	putDigest(data, "digest", digest)
	if detail != "" {
		data["detail"] = detail
	} else {
		data["detail"] = owner_store.NewMissing("not_applicable")
	}
	_, err := r.commitRuntime(ctx, eventOriginSealRecorded, data, nil)
	return err
}

// closeObservation closes the observation window through the observation
// owner within the commissioned cleanup bound. The close is local: remote
// work may continue, and no cancellation is implied.
func (r *Runtime) closeObservation(ctx context.Context, st sessionState, commission AttemptCommission) error {
	state := "unavailable"
	detail := ""
	revision := int64(0)
	digest := ""
	closureSnapshot := ""
	closedPrefix := JournalPrefix{}
	if st.obsRef.JournalID == "" || st.obsRef.Sequence < 1 {
		detail = "observation initialization evidence is not available locally"
	} else if commission.Attempt.AttemptID == "" || commission.JournalID == "" {
		detail = "commission does not identify the observation journal"
	} else {
		bound := durationFromMs(st.bounds.CleanupWaitLimitMs)
		cctx, cancel := context.WithTimeout(ctx, bound)
		rev, err := observation_owner.CloseObservationWindow(cctx, r.observation, commission, st.obsRef)
		cancel()
		if err != nil {
			detail = err.Error()
		} else {
			state = "closed"
			revision = rev.Revision
			digest = digestRevision(rev)
			closedPrefix = rev.EvidencePrefix
			if valueDigest, derr := canonicalDigest(rev.Value); derr == nil {
				closureSnapshot = valueDigest
			}
		}
	}
	data := map[string]any{
		"session_id": st.id, "state": state,
		"revision":              revision,
		"bound_ms":              st.bounds.CleanupWaitLimitMs,
		"remote_work_continues": state == "closed",
		"observation_reopened":  false,
	}
	putDigest(data, "digest", digest)
	putDigest(data, "closure_snapshot_digest", closureSnapshot)
	prefixInto(data, "closed_prefix", closedPrefix)
	if detail != "" {
		data["detail"] = detail
	} else {
		data["detail"] = owner_store.NewMissing("not_applicable")
	}
	_, err := r.commitRuntime(ctx, eventObservationClosed, data, nil)
	return err
}

// freezeKnowledge freezes the close-time knowledge and pins. Completeness is
// only reported as complete when the drain succeeded and the producer
// completeness assessment evidenced it; otherwise it stays unknown/incomplete.
func (r *Runtime) freezeKnowledge(ctx context.Context, st sessionState, reason CloseReason) error {
	completeness := st.observationCompleteness
	if completeness == "" || st.drainState != drainComplete {
		completeness = "unknown"
	}
	dispatchState := st.lastDispatchState
	if dispatchState == "" {
		dispatchState = "not_started"
	}
	nativeStop := any(owner_store.NewMissing("not_observed"))
	if st.mode == "manual" {
		nativeStop = owner_store.NewMissing("not_applicable")
	}
	limitations := []any{
		"close-time knowledge derives only from boundary-available evidence",
		"observation completeness is bounded by the drained prefix",
		"native stop and application commitment remain independent facts",
	}
	freezeData := map[string]any{
		"session_id": st.id, "reason": string(reason),
		"dispatch_state":           dispatchState,
		"observation_state":        st.observationState,
		"observation_revision":     st.observationRevision,
		"observation_completeness": completeness,
		"application_state":        st.applicationState,
		"application_revision":     st.applicationRevision,
		"report_state":             "not_published",
		"native_stop":              nativeStop,
		"limitations":              limitations,
	}
	putDigest(freezeData, "closure_snapshot_digest", st.closureSnapshotDigest)
	_, err := r.commitRuntime(ctx, eventKnowledgeFrozen, freezeData, nil)
	return err
}

func stringOrMissing(s string) any {
	if strings.TrimSpace(s) == "" {
		return owner_store.NewMissing("not_observed")
	}
	return s
}

// ---------------------------------------------------------------------------
// Diagnostic derivation and publication.
// ---------------------------------------------------------------------------

// installPin installs one deterministic pinned descriptor and returns its
// version pin. The bytes are content-addressed, so repeated calls replay.
func (r *Runtime) installPin(ctx context.Context, sessionID, kind string) (AnalysisPin, error) {
	doc := map[string]any{
		"pin_id": kind, "version": "1.0",
		"session_id": sessionID, "kind": kind,
	}
	raw, err := canonicalBytes(doc)
	if err != nil {
		return AnalysisPin{}, err
	}
	ref, err := owner_store.InstallArtifact(ctx, r.primary, bytes.NewReader(raw), mediaTypeJSON, accessPublic)
	if err != nil {
		return AnalysisPin{}, err
	}
	return AnalysisPin{ID: kind, Version: "1.0", ArtifactDigest: ref.Digest}, nil
}

func pinMap(pin AnalysisPin) map[string]any {
	return map[string]any{
		"id": pin.ID, "version": pin.Version, "artifact_digest": pin.ArtifactDigest,
	}
}

// subjectVersionFromCommission reads the commissioned subject version without
// assuming one particular in-memory shape.
func subjectVersionFromCommission(commission AttemptCommission) string {
	switch subject := commission.Execution.Subject.(type) {
	case lifecycle_rules.SubjectIdentity:
		return subject.SubjectVersion
	case *lifecycle_rules.SubjectIdentity:
		if subject != nil {
			return subject.SubjectVersion
		}
	case map[string]any:
		return asString(subject["subject_version"])
	}
	return ""
}

// diagnosticManifest builds the analysis manifest for one session. The
// journal-identity fields and clocks come from the admitted session journal
// manifest; the policy fields come from the commission. No field is invented
// as an in-band null.
func (r *Runtime) diagnosticManifest(st sessionState, commission AttemptCommission) (analysis_owner.Manifest, error) {
	jm := st.journalManifest
	if strings.TrimSpace(jm.JournalID) == "" {
		return analysis_owner.Manifest{}, fmt.Errorf("%w: session journal manifest is not retained", ErrInvalid)
	}
	m := analysis_owner.Manifest{
		RecordType: jm.RecordType, SchemaVersion: jm.SchemaVersion,
		ManifestID: jm.ManifestID, RunID: jm.RunID,
		JournalID: jm.JournalID, OwnerDomain: jm.OwnerDomain,
		Clocks:           jm.Clocks,
		CommissionerID:   commission.CommissionedBy,
		Activity:         "application_attempt",
		TaskSemanticHash: commission.TaskSemanticHash,
		Environment:      map[string]any{"deployment": "laboratory"},
		Seed:             "seed-" + st.id,
		BuildPins:        map[string]string{"fixture": "1.0.0"},
		Profile:          "M1",
	}
	m.Attempt = analysis_owner.AttemptContext{
		Kind: "practice", Context: "laboratory_fixture", Scope: "held_in",
		Assistance: "none",
	}
	m.Task = map[string]any{"task_id": "task-" + st.id}
	m.Execution = map[string]any{"mode": st.mode}
	if st.mode == "subject" {
		version := subjectVersionFromCommission(commission)
		m.Attempt.SubjectVersion = version
		m.Subject = analysis_owner.SubjectDescriptor{Name: "subject", Version: version}
	}
	return m, nil
}

// deriveDiagnostic appends the analysis request pin at the current session
// journal head and derives the diagnostic through the analysis owner. It
// never fabricates a document: a derivation failure is returned and recorded
// as an interruption by the caller.
func (r *Runtime) deriveDiagnostic(ctx context.Context, st sessionState, commission AttemptCommission) (DiagnosticDocument, error) {
	var zero DiagnosticDocument
	revision := st.diagnosticRevision + 1
	if revision < 1 {
		revision = 1
	}
	classifier, err := r.installPin(ctx, st.id, "classifier")
	if err != nil {
		return zero, fmt.Errorf("install classifier pin: %w", err)
	}
	registry, err := r.installPin(ctx, st.id, "requirement-registry")
	if err != nil {
		return zero, fmt.Errorf("install requirement registry pin: %w", err)
	}
	request := analysis_owner.AnalysisRequest{
		DiagnosticID:        st.diagnosticID,
		AnalysisRevision:    revision,
		Classifier:          classifier,
		RequirementRegistry: registry,
		FixRegistry:         owner_store.NewMissing("not_enabled"),
		Configuration:       append([]byte(nil), st.config...),
		ManualMode:          st.mode == "manual",
	}
	if st.mode == "subject" {
		request.Subject = analysis_owner.SubjectIdentity{
			SubjectID: "subject-" + st.id, SubjectVersion: subjectVersionFromCommission(commission),
			ConfiguredMode: "subject", InterfaceSurface: "laboratory",
		}
	}
	requestData := map[string]any{
		"session_id": st.id, "diagnostic_id": st.diagnosticID,
		"analysis_revision":    revision,
		"classifier":           pinMap(classifier),
		"requirement_registry": pinMap(registry),
		"fix_registry":         owner_store.NewMissing("not_enabled"),
	}
	putDigest(requestData, "closure_snapshot_digest", st.closureSnapshotDigest)
	requestEnvelopes, err := analysis_owner.AppendSourceEvents(ctx, r.primary, st.journalID, []EventSubmission{{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventAnalysisRequested,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: requestData, Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}})
	if err != nil {
		return zero, fmt.Errorf("append analysis request: %w", err)
	}
	if len(requestEnvelopes) == 0 {
		return zero, fmt.Errorf("%w: analysis request returned no envelope", ErrStorageUnavailable)
	}
	requestEnv := requestEnvelopes[len(requestEnvelopes)-1]
	requestRef := EvidenceRef{
		JournalID: requestEnv.JournalID, Sequence: requestEnv.Sequence,
		EventID: requestEnv.EventID, EventHash: requestEnv.EventHash, Pointer: "",
	}

	manifest, err := r.diagnosticManifest(st, commission)
	if err != nil {
		return zero, err
	}
	doc, err := analysis_owner.AnalyzeSession(ctx, r.primary, manifest, request)
	if err != nil {
		return zero, err
	}
	docBytes, err := canonicalBytes(doc)
	if err != nil {
		return zero, fmt.Errorf("canonicalize diagnostic: %w", err)
	}
	docRef, err := owner_store.InstallArtifact(ctx, r.primary, bytes.NewReader(docBytes), mediaTypeJSON, accessRestricted)
	if err != nil {
		return zero, fmt.Errorf("install diagnostic bytes: %w", err)
	}
	data := map[string]any{
		"session_id": st.id, "diagnostic_id": st.diagnosticID,
		"analysis_revision":     revision,
		"document_digest":       docRef.Digest,
		"document_size_bytes":   docRef.SizeBytes,
		"document_media_type":   docRef.MediaType,
		"document_owner_domain": docRef.OwnerDomain,
		"document_access":       docRef.Access,
	}
	putDigest(data, "closure_snapshot_digest", st.closureSnapshotDigest)
	refInto(data, "analysis_request", requestRef)
	prefixInto(data, "input_prefix", doc.InputPrefix)
	if _, err := r.commitRuntime(ctx, eventDiagnosticRecorded, data, nil); err != nil {
		return zero, err
	}
	return doc, nil
}

// publicationRegistration builds the immutable owner-separated registration
// for the session entity. Every declared domain has a distinct owner domain
// and one bound writer.
func (r *Runtime) publicationRegistration(st sessionState) publication.EntityRegistration {
	applicationOwner := "application-owner"
	observationOwner := "observation-owner"
	diagnosticOwner := r.domain
	if diagnosticOwner == applicationOwner || diagnosticOwner == observationOwner ||
		diagnosticOwner == "application-owner-session" || diagnosticOwner == "observation-owner-session" {
		diagnosticOwner = "diagnostic-owner-session-runtime"
	}
	pin := func(seed string) map[string]any {
		return map[string]any{
			"id": "publication-policy-" + seed, "version": "1.0",
			"artifact_digest": string(evidence_codec.HashBytes([]byte("session-runtime/publication-policy/" + seed))),
		}
	}
	owners := map[string]any{
		"application": map[string]any{
			"role": "origin", "source_id": st.id, "writer_id": "application-writer",
			"owner_domain": applicationOwner, "publication_policy": pin("application"),
		},
		"observation": map[string]any{
			"role": "observer", "source_id": "observation-1", "writer_id": "observation-writer",
			"owner_domain": observationOwner, "publication_policy": pin("observation"),
		},
		"diagnostic": map[string]any{
			"role": "analyzer", "source_id": runtimeSourceID, "writer_id": "diagnostic-writer",
			"owner_domain": diagnosticOwner, "publication_policy": pin("diagnostic"),
		},
	}
	return publication.EntityRegistration{
		RecordType:     "write_domain_entity",
		SchemaVersion:  "owner-separated-write-domains/0.1.0",
		RegistrationID: "registration-" + st.id,
		Entity:         map[string]any{"entity_type": publicationEntityType, "session_id": st.id},
		Identity:       map[string]any{"run_id": st.attemptID, "journal_id": st.journalID},
		Owners:         owners,
		EvidencePrefix: st.lastAnalysisPrefix,
		EvidenceRefs:   []publication.EvidenceRef{st.lastAnalysisRef},
	}
}

func evidenceRefMap(ref publication.EvidenceRef) map[string]any {
	return map[string]any{
		"journal_id": ref.JournalID, "sequence": ref.Sequence,
		"event_id": ref.EventID, "event_hash": ref.EventHash, "pointer": ref.Pointer,
	}
}

func prefixMap(prefix publication.JournalPrefix) map[string]any {
	return map[string]any{
		"journal_id": prefix.JournalID, "last_sequence": prefix.LastSequence,
		"head_hash": prefix.HeadHash,
	}
}

// publishDiagnostic appends the document pin to the session journal and
// publishes the complete owned revision through the publication owner. The
// caller records a typed publication failure when this returns an error; the
// source diagnostic commit is never rolled back and no report is fabricated.
func (r *Runtime) publishDiagnostic(ctx context.Context, st sessionState, doc DiagnosticDocument) error {
	if st.lastAnalysisPrefix.JournalID == "" || st.lastAnalysisRef.JournalID == "" {
		return fmt.Errorf("%w: diagnostic input pins are not retained", ErrInvalid)
	}
	if st.journalManifest.JournalID == "" {
		return fmt.Errorf("%w: session journal manifest is not retained", ErrInvalid)
	}
	revision := st.publishedRevision + 1
	if revision < 1 {
		revision = 1
	}
	docBytes, err := canonicalBytes(doc)
	if err != nil {
		return fmt.Errorf("canonicalize diagnostic payload: %w", err)
	}
	registration := r.publicationRegistration(st)
	registrationBytes, err := canonicalBytes(registration)
	if err != nil {
		return fmt.Errorf("canonicalize registration: %w", err)
	}
	registrationDigest := string(evidence_codec.HashBytes(registrationBytes))

	var value any
	if err := json.Unmarshal(docBytes, &value); err != nil {
		return fmt.Errorf("decode diagnostic payload: %w", err)
	}
	diagnosticOwner := asString(registration.Owners["diagnostic"].(map[string]any)["owner_domain"])
	document := map[string]any{
		"record_type":         "owned_domain_revision",
		"schema_version":      "owner-separated-write-domains/0.1.0",
		"entity":              registration.Entity,
		"domain":              "diagnostic",
		"owner_domain":        diagnosticOwner,
		"writer_id":           "diagnostic-writer",
		"revision":            revision,
		"previous_revision":   st.publishedRevision,
		"evidence_prefix":     prefixMap(st.lastAnalysisPrefix),
		"evidence_refs":       []any{evidenceRefMap(st.lastAnalysisRef)},
		"value":               value,
		"registration_digest": registrationDigest,
	}
	documentBytes, err := canonicalBytes(document)
	if err != nil {
		return fmt.Errorf("canonicalize publication document: %w", err)
	}
	documentDigest := string(evidence_codec.HashBytes(documentBytes))

	// The publisher requires a source event above the document's input prefix
	// that pins the exact published-document digest: register after the
	// complete document bytes exist.
	pinEnvelopes, err := owner_store.CommitOwner(ctx, r.primary, st.journalID, []EventSubmission{{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventPublicationPinned,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id": st.id, "diagnostic_id": st.diagnosticID,
				"analysis_revision": st.diagnosticRevision,
				"document_digest":   documentDigest,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("pin document digest: %w", err)
	}
	if len(pinEnvelopes) == 0 {
		return fmt.Errorf("%w: publication pin returned no envelope", ErrStorageUnavailable)
	}
	pinEnv := pinEnvelopes[len(pinEnvelopes)-1]
	sourceHead := JournalPrefix{
		JournalID: pinEnv.JournalID, LastSequence: pinEnv.Sequence, HeadHash: pinEnv.EventHash,
	}
	source, err := owner_store.LoadPrefix(ctx, r.primary, sourceHead)
	if err != nil {
		return fmt.Errorf("load publication source prefix: %w", err)
	}
	receipt, err := publication.InstallPublication(ctx, r.primary, registration, documentBytes, st.journalManifest, source, publicationViewID)
	if err != nil {
		return err
	}
	data := map[string]any{
		"session_id": st.id, "state": "published",
		"revision":                    receipt.Revision,
		"analysis_revision":           st.diagnosticRevision,
		"receipt_id":                  receipt.ReceiptID,
		"document_digest":             receipt.Document.Digest,
		"document_size_bytes":         receipt.Document.SizeBytes,
		"document_media_type":         receipt.Document.MediaType,
		"document_owner_domain":       receipt.Document.OwnerDomain,
		"document_access":             receipt.Document.Access,
		"supersedes_revision":         receipt.Supersedes.Revision,
		"source_prefix_last_sequence": receipt.SourcePrefix.LastSequence,
		"read_view_advanced":          true,
	}
	refInto(data, "publication", receipt.PublicationRef)
	_, err = r.commitRuntime(ctx, eventPublicationRecorded, data, nil)
	return err
}

// loadDocument reads the retained diagnostic document for one session.
func (r *Runtime) loadDocument(ctx context.Context, st sessionState) (DiagnosticDocument, error) {
	var doc DiagnosticDocument
	if st.documentRef.Digest == "" {
		return doc, fmt.Errorf("%w: no retained diagnostic document", ErrInvalid)
	}
	raw, err := owner_store.ReadArtifact(ctx, r.primary, st.documentRef)
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, err
	}
	return doc, nil
}

// ---------------------------------------------------------------------------
// Late evidence (seam 14.1 / LIFE-LATE-EVIDENCE).
// ---------------------------------------------------------------------------

// RecordLateEvidence appends authorized evidence after observation closure at
// the current observation journal head, imports a citation into the diagnostic
// source journal, and records the late-evidence fact. It never resumes
// workflow commands and never reopens observation: the next Finalize derives a
// new diagnostic revision over new input pins while preserving the prior
// closure snapshot, seals, and publications.
func (r *Runtime) RecordLateEvidence(ctx context.Context, sessionID, kind, detail string) (EvidenceRef, error) {
	var zero EvidenceRef
	st, ok := r.stateCopy(sessionID)
	if !ok {
		return zero, fmt.Errorf("%w: unknown session %q", ErrInvalid, sessionID)
	}
	if !st.closeRequested {
		return zero, fmt.Errorf("%w: late evidence applies only after the close request", ErrInvalid)
	}
	if st.obsRef.JournalID == "" {
		return zero, fmt.Errorf("%w: observation journal is not available locally", ErrInvalid)
	}
	if strings.TrimSpace(kind) == "" {
		kind = "late_callback"
	}
	lateEnvelopes, err := owner_store.CommitOwner(ctx, r.observation, st.obsRef.JournalID, []EventSubmission{{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventLateEvidence,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id": st.id, "attempt_id": st.attemptID,
				"kind": kind, "detail": detail,
				"received_after_close": true,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}}, nil)
	if err != nil {
		return zero, fmt.Errorf("session_runtime: append late evidence: %w", err)
	}
	if len(lateEnvelopes) == 0 {
		return zero, fmt.Errorf("%w: late evidence commit returned no envelope", ErrStorageUnavailable)
	}
	lateEnv := lateEnvelopes[len(lateEnvelopes)-1]
	lateRef := EvidenceRef{
		JournalID: lateEnv.JournalID, Sequence: lateEnv.Sequence,
		EventID: lateEnv.EventID, EventHash: lateEnv.EventHash, Pointer: "",
	}
	markerData := map[string]any{
		"session_id": st.id, "kind": kind, "detail": detail,
		"imported_after_close": true,
	}
	refInto(markerData, "late_evidence", lateRef)
	markerEnvelopes, err := owner_store.CommitOwner(ctx, r.primary, st.journalID, []EventSubmission{{
		ProducerSequence:   owner_store.NewMissing("not_applicable"),
		EventKind:          eventLateEvidenceImport,
		EventSchemaVersion: eventSchemaVersion,
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: markerData, Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{}, ArtifactRefs: []ArtifactReference{},
		},
	}}, nil)
	if err != nil {
		return zero, fmt.Errorf("session_runtime: import late evidence citation: %w", err)
	}
	if len(markerEnvelopes) == 0 {
		return zero, fmt.Errorf("%w: late citation returned no envelope", ErrStorageUnavailable)
	}
	markerEnv := markerEnvelopes[len(markerEnvelopes)-1]
	markerRef := EvidenceRef{
		JournalID: markerEnv.JournalID, Sequence: markerEnv.Sequence,
		EventID: markerEnv.EventID, EventHash: markerEnv.EventHash, Pointer: "",
	}
	data := map[string]any{
		"session_id": st.id, "kind": kind, "detail": detail,
		"observation_journal":       st.obsRef.JournalID,
		"observation_reopened":      false,
		"workflow_commands_resumed": false,
	}
	refInto(data, "late_evidence", lateRef)
	refInto(data, "import_marker", markerRef)
	if _, err := r.commitRuntime(ctx, eventLateEvidenceRecorded, data, nil); err != nil {
		return zero, err
	}
	return lateRef, nil
}
