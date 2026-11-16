// Package application_owner implements the Hellscape application-owner surface.
//
// The application owner holds the fixture application journal: it admits one
// laboratory fixture attempt per owner-local journal, applies the
// fixture_reducer to admitted commands, and commits the admitted command,
// idempotency record, reducer effect, business events, and replayable
// response atomically through owner_store.CommitOwner before acknowledging
// anything to the caller (EK-ATOMICITY, OWD-LOCAL-COMMIT).
//
// Boundaries honored by this module:
//
//   - One owner durability boundary: every mutation touches only the store
//     passed to NewApplicationHandler / InitializeApplication /
//     SealApplication. No commit acquires a peer-owned write lock, waits for
//     a peer transaction, or serializes a large peer payload.
//   - Fixture only: production attempts and real identity verification are
//     rejected; the fixture API admits practice / laboratory_fixture /
//     held_in attempts exclusively.
//   - Upload bytes are hash-verified and durably installed before the
//     owner-local commit that acknowledges them.
//   - Identity verification binds the pinned identity epoch and the opaque
//     attempt identity; token possession alone verifies nothing.
//   - Commitment, receipt retrieval, and receipt rendering are three
//     separate facts. Missing rendering telemetry never erases a commitment.
//   - Sealing fences new mutations and accounts for already admitted
//     transactions; it is not cancellation or rollback.
//   - No in-band nulls: absent values are typed Missing envelopes.
package application_owner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"authority"
	"evidence_codec"
	"fixture_reducer"
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
	// Manifest is the admitted laboratory fixture manifest projection.
	Manifest = fixture_reducer.Manifest
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = lifecycle_rules.EvidenceRef
	// AttemptReference identifies one attempt and kind.
	AttemptReference = lifecycle_rules.AttemptReference
	// AxisRevision is one complete immutable axis publication.
	AxisRevision = lifecycle_rules.AxisRevision
	// ArtifactReference is an immutable byte identity plus metadata.
	ArtifactReference = lifecycle_rules.ArtifactReference
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = lifecycle_rules.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = lifecycle_rules.JournalPrefix
)

// EntityRegistration is the immutable, authenticated registration of a
// Hellscape session (or application attempt) entity. Identity and owners
// ride as JSON-compatible objects so registrations produced against the
// owner-separated write-domains contract validate structurally; this module
// checks only the fields that gate fixture admission.
type EntityRegistration struct {
	RecordType     string         `json:"record_type"`
	SchemaVersion  string         `json:"schema_version"`
	RegistrationID string         `json:"registration_id"`
	Entity         map[string]any `json:"entity"`
	Identity       map[string]any `json:"identity"`
	Owners         map[string]any `json:"owners"`
	EvidencePrefix JournalPrefix  `json:"evidence_prefix"`
	EvidenceRefs   []EvidenceRef  `json:"evidence_refs"`
	// Configuration carries the effective fixture configuration pinned at
	// initialization. When absent, DefaultFixtureConfiguration is used.
	Configuration json.RawMessage `json:"configuration,omitempty"`
}

// Sentinel errors.
var (
	ErrInvalid        = errors.New("application_owner: invalid input")
	ErrUnauthorized   = errors.New("application_owner: unauthorized")
	ErrUnknownAttempt = errors.New("application_owner: unknown attempt")
	ErrConflict       = errors.New("application_owner: operation key conflict")
	ErrSealed         = errors.New("application_owner: mutation authority is sealed")
	ErrNotCommitted   = errors.New("application_owner: no committed submission")
)

// Owner-local journal event kinds emitted by this module. Reducer business
// events keep the fixture_reducer vocabulary; the two below frame the
// owner-local journal.
const (
	eventInit = "application_initialized"
	eventSeal = "fixture_seal"
)

// Application owner domain used for Authorize. The store's own domain
// authorizes the underlying owner_store operations via the same context.
const ownerDomain = "application"

// maxRequestBytes bounds one admitted HTTP request body (32 MiB comfortably
// covers the default 5 MiB upload bound plus base64 overhead).
const maxRequestBytes = 32 << 20

// ---------------------------------------------------------------------------
// Missing envelopes and small JSON helpers.
// ---------------------------------------------------------------------------

// missing builds a typed Missing envelope: {"value":null,"reason":...}.
// It is the only place a JSON null may appear in module output.
func missing(reason string) map[string]any {
	return map[string]any{"value": nil, "reason": reason}
}

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

func hashDigest(content []byte) string {
	return string(evidence_codec.HashBytes(content))
}

// ---------------------------------------------------------------------------
// Default fixture configuration.
// ---------------------------------------------------------------------------

// DefaultFixtureConfiguration returns the pinned M1 effective fixture
// configuration used when a registration carries none. It admits the
// cooperative-form feature, completion tasks with a human path, the pinned
// identity epoch, the synthetic job set, and a 5 MiB upload bound.
func DefaultFixtureConfiguration() []byte {
	return []byte(`{"artificial_delay_ms":100.0,"budgets":{"artificial_delay_ms":100.0,"required_ms":5000.0,"task_ms":60000.0},"features":[{"name":"cooperative-form","recipe":"primitive:cooperative-form/1.0"}],"human_path":true,"identity_epoch":"epoch-1","known_jobs":["job-1","job-2"],"profile":"M1","review_dependencies":["contact","history"],"task":{"available_browser_capabilities":["dom"],"hidden_controls":[],"human_path":true,"kind":"completion","permanently_rejected_verifiers":[],"recovery_paths":["retry"],"required_browser_capabilities":[],"required_controls":["contact-name"],"required_ms":5000.0,"required_verifiers":["v1"],"requires_recovery":false},"upload_max_bytes":5242880}`)
}

// ---------------------------------------------------------------------------
// Reducer state snapshots (JSON-compatible read mirrors).
// ---------------------------------------------------------------------------

type stateSection struct {
	Section              string          `json:"section"`
	ValueRevision        int             `json:"value_revision"`
	ValidationGeneration int             `json:"validation_generation"`
	DataDigest           string          `json:"data_digest"`
	Data                 json.RawMessage `json:"data"`
	Support              string          `json:"support"`
}

type stateReview struct {
	ValueRevision        int    `json:"value_revision"`
	ValidationGeneration int    `json:"validation_generation"`
	ContactValueRevision int    `json:"contact_value_revision"`
	ContactGeneration    int    `json:"contact_generation"`
	HistoryValueRevision int    `json:"history_value_revision"`
	HistoryGeneration    int    `json:"history_generation"`
	Support              string `json:"support"`
}

type stateUpload struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	Digest      string `json:"digest"`
	Support     string `json:"support"`
}

type stateIdentity struct {
	Epoch     string `json:"epoch"`
	Receipt   string `json:"receipt"`
	AttemptID string `json:"attempt_id"`
	Verified  bool   `json:"verified"`
	Support   string `json:"support"`
}

type stateCommitment struct {
	ApplicationID string `json:"application_id"`
	OperationKey  string `json:"operation_key"`
	RequestDigest string `json:"request_digest"`
	Receipt       string `json:"receipt"`
	CommittedAt   string `json:"committed_at"`
	CommitRef     string `json:"commit_ref"`
}

type stateJournalEntry struct {
	Sequence       int    `json:"sequence"`
	OperationKey   string `json:"operation_key"`
	OperationKind  string `json:"operation_kind"`
	Digest         string `json:"digest"`
	Outcome        string `json:"outcome"`
	Reason         string `json:"reason"`
	RevisionBefore int    `json:"revision_before"`
	RevisionAfter  int    `json:"revision_after"`
	WorkflowBefore string `json:"workflow_before"`
	WorkflowAfter  string `json:"workflow_after"`
	Detail         string `json:"detail"`
}

// fixtureSnapshot mirrors the reducer state for owner-local reads. Unknown
// fields are ignored on decode; the reducer remains the sole writer.
type fixtureSnapshot struct {
	ManifestID         string              `json:"manifest_id"`
	AttemptID          string              `json:"attempt_id"`
	WorkflowState      string              `json:"workflow_state"`
	StateRevision      int                 `json:"state_revision"`
	MutationAuthority  string              `json:"mutation_authority"`
	AuthoritySealRef   string              `json:"authority_seal_ref"`
	IdentityEpoch      string              `json:"identity_epoch"`
	KnownJobs          []string            `json:"known_jobs"`
	ReviewDependencies []string            `json:"review_dependencies"`
	UploadMaxBytes     int64               `json:"upload_max_bytes"`
	UploadAllowedTypes []string            `json:"upload_allowed_types"`
	SelectedJob        string              `json:"selected_job"`
	Contact            *stateSection       `json:"contact"`
	History            *stateSection       `json:"history"`
	Upload             *stateUpload        `json:"upload"`
	Identity           *stateIdentity      `json:"identity"`
	Review             *stateReview        `json:"review"`
	Submission         *stateCommitment    `json:"submission"`
	Journal            []stateJournalEntry `json:"journal"`
}

func decodeSnapshot(state []byte) (fixtureSnapshot, error) {
	var snap fixtureSnapshot
	if err := json.Unmarshal(state, &snap); err != nil {
		return snap, fmt.Errorf("application_owner: cannot decode reducer state: %w", err)
	}
	if snap.KnownJobs == nil {
		snap.KnownJobs = []string{}
	}
	if snap.ReviewDependencies == nil {
		snap.ReviewDependencies = []string{}
	}
	if snap.UploadAllowedTypes == nil {
		snap.UploadAllowedTypes = []string{}
	}
	if snap.Journal == nil {
		snap.Journal = []stateJournalEntry{}
	}
	return snap, nil
}

type reducerResponse struct {
	Status            string           `json:"status"`
	OperationKey      string           `json:"operation_key"`
	OperationKind     string           `json:"operation_kind"`
	RequestDigest     string           `json:"request_digest"`
	StateRevision     int              `json:"state_revision"`
	WorkflowState     string           `json:"workflow_state"`
	Reason            string           `json:"reason"`
	ReasonDetail      string           `json:"reason_detail"`
	Commitment        *stateCommitment `json:"commitment"`
	InvalidatedReview bool             `json:"invalidated_review"`
}

func decodeReducerResponse(raw []byte) (reducerResponse, error) {
	var resp reducerResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return resp, fmt.Errorf("application_owner: cannot decode reducer response: %w", err)
	}
	return resp, nil
}

// ---------------------------------------------------------------------------
// Attempt runtime registry.
//
// The durable truth is the owner-local journal: every admitted operation is
// committed through owner_store.CommitOwner before acknowledgement. This
// registry caches the live reducer snapshot, pinned configuration, and
// journal head per (store, attempt) so requests need no peer access and no
// journal scan. Entries are created only by InitializeApplication.
// ---------------------------------------------------------------------------

type attemptRuntime struct {
	mu           sync.Mutex
	manifest     Manifest
	config       []byte
	journalID    string
	ownerDomain  string
	state        []byte
	head         JournalPrefix
	producerSeq  int64
	manifestHash string
	admissionRef EvidenceRef
	initRef      EvidenceRef
	sealed       bool
	publications []AxisRevision
}

var (
	registryMu sync.Mutex
	registry   = map[*OwnerStore]map[string]*attemptRuntime{}
)

func lookupRuntime(store *OwnerStore, attemptID string) (*attemptRuntime, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	byAttempt, ok := registry[store]
	if !ok {
		return nil, false
	}
	rt, ok := byAttempt[attemptID]
	return rt, ok
}

func registerRuntime(store *OwnerStore, attemptID string, rt *attemptRuntime) {
	registryMu.Lock()
	defer registryMu.Unlock()
	byAttempt, ok := registry[store]
	if !ok {
		byAttempt = map[string]*attemptRuntime{}
		registry[store] = byAttempt
	}
	byAttempt[attemptID] = rt
}

// ---------------------------------------------------------------------------
// InitializeApplication.
// ---------------------------------------------------------------------------

// InitializeApplication admits one fixture attempt into the application
// owner: it validates the fixture manifest and session registration through
// the fixture gate, pins the effective configuration, and atomically commits
// the journal admission plus the initial reducer snapshot. It returns an
// evidence reference to the application_initialized event.
//
// Production attempts are rejected: the fixture API admits practice
// laboratory fixtures exclusively.
func InitializeApplication(ctx context.Context, store *OwnerStore, manifest Manifest, registration EntityRegistration) (EvidenceRef, error) {
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
	if strings.TrimSpace(manifest.ManifestID) == "" ||
		strings.TrimSpace(manifest.RunID) == "" ||
		strings.TrimSpace(manifest.JournalID) == "" ||
		strings.TrimSpace(manifest.OwnerDomain) == "" {
		return zero, fmt.Errorf("%w: manifest must name manifest_id, run_id, journal_id, and owner_domain", ErrInvalid)
	}
	if strings.TrimSpace(manifest.Attempt.Kind) != "" && manifest.Attempt.Kind != "practice" {
		return zero, fmt.Errorf("%w: fixture API admits only practice attempts, got kind %q", ErrInvalid, manifest.Attempt.Kind)
	}
	if registration.RecordType != "write_domain_entity" {
		return zero, fmt.Errorf("%w: registration record_type must be write_domain_entity, got %q", ErrInvalid, registration.RecordType)
	}
	if strings.TrimSpace(registration.RegistrationID) == "" {
		return zero, fmt.Errorf("%w: registration_id is required", ErrInvalid)
	}
	entityType := ""
	if registration.Entity != nil {
		entityType, _ = registration.Entity["entity_type"].(string)
	}
	if entityType != "hellscape_session" && entityType != "application_attempt" {
		return zero, fmt.Errorf("%w: registration entity_type %q is not a Hellscape session", ErrInvalid, entityType)
	}
	if kind := nestedString(registration.Identity, "attempt", "kind"); kind == "production" {
		return zero, fmt.Errorf("%w: production attempts are not admitted through the fixture API", ErrInvalid)
	}

	attemptID := manifest.RunID
	journalID := manifest.JournalID
	if _, exists := lookupRuntime(store, attemptID); exists {
		return zero, fmt.Errorf("%w: attempt %q is already initialized", ErrInvalid, attemptID)
	}

	config := registration.Configuration
	if len(bytes.TrimSpace(config)) == 0 {
		config = DefaultFixtureConfiguration()
	}
	if _, err := evidence_codec.CanonicalJSON(config, "application/json"); err != nil {
		return zero, fmt.Errorf("%w: effective configuration is not valid JSON: %v", ErrInvalid, err)
	}
	initial, err := fixture_reducer.InitialFixtureState(manifest, config)
	if err != nil {
		return zero, fmt.Errorf("%w: fixture gate rejects manifest/configuration: %v", ErrInvalid, err)
	}

	// Owner-local journal manifest for this attempt journal.
	clockID := "clock-" + journalID
	bootID := "boot-" + journalID
	ownerManifest := owner_store.Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         manifest.RunID,
		JournalID:     journalID,
		OwnerDomain:   manifest.OwnerDomain,
		Clocks: []owner_store.ClockDescriptor{{
			ClockID: clockID, BootID: bootID,
			Origin: "engine_measured", SourceID: "application-owner",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
	rawManifest, err := json.Marshal(ownerManifest)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot encode journal manifest: %v", ErrInvalid, err)
	}
	canonicalManifest, err := evidence_codec.CanonicalJSON(rawManifest, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize journal manifest: %v", ErrInvalid, err)
	}
	manifestRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalManifest), "application/json", "public")
	if err != nil {
		return zero, fmt.Errorf("application_owner: install journal manifest: %w", err)
	}
	canonicalState, err := evidence_codec.CanonicalJSON(initial, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize initial state: %v", ErrInvalid, err)
	}
	stateRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalState), "application/json", "restricted")
	if err != nil {
		return zero, fmt.Errorf("application_owner: install initial state: %w", err)
	}
	canonicalConfig, err := evidence_codec.CanonicalJSON(config, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize configuration: %v", ErrInvalid, err)
	}
	configRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalConfig), "application/json", "restricted")
	if err != nil {
		return zero, fmt.Errorf("application_owner: install configuration: %w", err)
	}

	admission := owner_store.EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt: owner_store.TimePoint{
			ClockID: clockID, BootID: bootID, Origin: "engine_measured",
			MonotonicOffsetMs: 0, UTCAnnotation: owner_store.NewMissing("not_applicable"),
		},
		Payload: owner_store.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(manifestRef)},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: []owner_store.ArtifactReference{manifestRef},
		},
	}
	initEvent := owner_store.EventSubmission{
		ProducerSequence:   int64(2),
		EventKind:          eventInit,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"attempt_id":           attemptID,
				"manifest_id":          manifest.ManifestID,
				"registration_id":      registration.RegistrationID,
				"state_digest":         stateRef.Digest,
				"configuration_digest": configRef.Digest,
				"workflow_state":       "LISTING",
				"state_revision":       int64(0),
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: []owner_store.ArtifactReference{stateRef, configRef},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, journalID, []owner_store.EventSubmission{admission, initEvent}, nil)
	if err != nil {
		return zero, fmt.Errorf("application_owner: commit initialization: %w", err)
	}
	if len(envelopes) != 2 {
		return zero, fmt.Errorf("%w: initialization committed %d events, want 2", ErrInvalid, len(envelopes))
	}
	admEnv, initEnv := envelopes[0], envelopes[1]
	head := JournalPrefix{JournalID: journalID, LastSequence: initEnv.Sequence, HeadHash: initEnv.EventHash}
	admRef := EvidenceRef{JournalID: admEnv.JournalID, Sequence: admEnv.Sequence, EventID: admEnv.EventID, EventHash: admEnv.EventHash, Pointer: ""}
	initRef := EvidenceRef{JournalID: initEnv.JournalID, Sequence: initEnv.Sequence, EventID: initEnv.EventID, EventHash: initEnv.EventHash, Pointer: ""}

	registerRuntime(store, attemptID, &attemptRuntime{
		manifest:     manifest,
		config:       append([]byte(nil), config...),
		journalID:    journalID,
		ownerDomain:  manifest.OwnerDomain,
		state:        append([]byte(nil), canonicalState...),
		head:         head,
		producerSeq:  2,
		manifestHash: manifestRef.Digest,
		admissionRef: admRef,
		initRef:      initRef,
	})
	return initRef, nil
}

// ---------------------------------------------------------------------------
// HTTP handler.
// ---------------------------------------------------------------------------

type applicationHandler struct {
	store *OwnerStore
}

// NewApplicationHandler serves the application-owner fixture surface for one
// owner store. The handler authenticates nothing itself: upstream middleware
// authenticates the channel and the handler authorizes the attempt operation
// against the principal in the request context. Callers in tests attach an
// authenticated context directly.
func NewApplicationHandler(store *OwnerStore) http.Handler {
	return &applicationHandler{store: store}
}

func (h *applicationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "no_store", "application owner has no store")
		return
	}
	path := r.URL.Path
	method := r.Method
	switch {
	case path == "/api/jobs" && method == http.MethodGet:
		h.serveJobs(w, r)
	case strings.HasPrefix(path, "/api/jobs/") && method == http.MethodGet:
		h.serveJobDetail(w, r)
	case path == "/api/job-selection" && method == http.MethodPost:
		h.serveJobSelection(w, r)
	case path == "/api/draft" && method == http.MethodGet:
		h.serveDraft(w, r)
	case path == "/api/contact" && method == http.MethodPut:
		h.serveContact(w, r)
	case path == "/api/history/enter" && method == http.MethodPost:
		h.serveHistoryEnter(w, r)
	case path == "/api/history" && method == http.MethodPut:
		h.serveHistory(w, r)
	case path == "/api/upload" && method == http.MethodPost:
		h.serveUpload(w, r)
	case path == "/api/identity/verify" && method == http.MethodPost:
		h.serveIdentityVerify(w, r)
	case path == "/api/review/validate" && method == http.MethodPost:
		h.serveReviewValidate(w, r)
	case path == "/api/submit" && method == http.MethodPost:
		h.serveSubmit(w, r)
	case path == "/api/confirmation" && method == http.MethodGet:
		h.serveConfirmation(w, r)
	default:
		writeError(w, http.StatusNotFound, "unknown_endpoint", "no application endpoint at "+path)
	}
}

// authorizeAttempt authorizes a read or write against the opaque attempt
// binding. Session cookies, session query parameters, and any other global
// session material carry no authority and never select the attempt: only the
// exact attempt_id does.
func (h *applicationHandler) authorizeAttempt(r *http.Request, operation, attemptID string) error {
	if strings.TrimSpace(attemptID) == "" {
		return fmt.Errorf("%w: attempt_id is required", ErrInvalid)
	}
	if err := authority.Authorize(r.Context(), ownerDomain, operation, attemptID); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

func (h *applicationHandler) runtimeFor(w http.ResponseWriter, attemptID string) (*attemptRuntime, bool) {
	rt, ok := lookupRuntime(h.store, attemptID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown_attempt", "attempt "+attemptID+" is not initialized")
		return nil, false
	}
	return rt, true
}

// queryAttempt extracts the opaque attempt binding for reads. A session_id
// query parameter, when present, is ignored: it never redirects the binding.
func queryAttempt(r *http.Request) (string, error) {
	attemptID := strings.TrimSpace(r.URL.Query().Get("attempt_id"))
	if attemptID == "" {
		return "", fmt.Errorf("%w: query attempt_id is required", ErrInvalid)
	}
	return attemptID, nil
}

func decodeRequestBody(r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxRequestBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("%w: cannot read body: %v", ErrInvalid, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("%w: request body is required", ErrInvalid)
	}
	// Endpoint structs intentionally tolerate unknown session material:
	// only attempt_id binds the attempt, everything else is ignored.
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: malformed JSON body: %v", ErrInvalid, err)
	}
	return nil
}

// mutationEnvelope carries the shared mutation identity. Session material is
// accepted and ignored: only attempt_id binds the attempt.
type mutationEnvelope struct {
	AttemptID        string `json:"attempt_id"`
	OperationKey     string `json:"operation_key"`
	ExpectedRevision int    `json:"expected_revision"`
}

func (m mutationEnvelope) validate() error {
	if strings.TrimSpace(m.AttemptID) == "" {
		return fmt.Errorf("%w: attempt_id is required", ErrInvalid)
	}
	if strings.TrimSpace(m.OperationKey) == "" {
		return fmt.Errorf("%w: operation_key is required", ErrInvalid)
	}
	if m.ExpectedRevision < 0 {
		return fmt.Errorf("%w: expected_revision must not be negative", ErrInvalid)
	}
	return nil
}

// checkQueryBinding rejects an ambiguous binding: when the query also names
// an attempt it must equal the body attempt. A differing session_id never
// redirects; it is ignored.
func checkQueryBinding(r *http.Request, attemptID string) error {
	if q := strings.TrimSpace(r.URL.Query().Get("attempt_id")); q != "" && q != attemptID {
		return fmt.Errorf("%w: query attempt_id %q does not match body attempt_id %q", ErrInvalid, q, attemptID)
	}
	return nil
}

// commitMutation runs one application transaction: reduce the admitted
// command, durably install the resulting state and response artifacts, and
// atomically commit the business event plus idempotency receipt through the
// owner-local journal. The caller is acknowledged only after durability.
//
// Identical replays return the stored response with no new commit. Hard
// reducer failures (key conflicts, shape violations) commit nothing.
func (h *applicationHandler) commitMutation(ctx context.Context, rt *attemptRuntime, cmd fixture_reducer.EventSubmission, extra []owner_store.ArtifactReference) (out []byte, httpCode int, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	nextState, events, response, err := fixture_reducer.ReduceFixture(rt.manifest, rt.config, rt.state, cmd)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "already bound"):
			return nil, http.StatusConflict, fmt.Errorf("%w: %v", ErrConflict, err)
		case strings.Contains(msg, "attempt binding mismatch"):
			return nil, http.StatusBadRequest, fmt.Errorf("%w: %v", ErrInvalid, err)
		default:
			return nil, http.StatusBadRequest, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	}
	if len(events) == 0 {
		// Identical replay: the exact stored response, no new effect.
		// Replays are acknowledged without a commit because the original
		// commit is already durable.
		return response, http.StatusOK, nil
	}
	resp, err := decodeReducerResponse(response)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	canonicalState, err := evidence_codec.CanonicalJSON(nextState, "application/json")
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("application_owner: canonicalize state: %w", err)
	}
	canonicalResponse, err := evidence_codec.CanonicalJSON(response, "application/json")
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("application_owner: canonicalize response: %w", err)
	}
	stateRef, err := owner_store.InstallArtifact(ctx, h.store, bytes.NewReader(canonicalState), "application/json", "restricted")
	if err != nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("application_owner: install state: %w", err)
	}
	responseRef, err := owner_store.InstallArtifact(ctx, h.store, bytes.NewReader(canonicalResponse), "application/json", "restricted")
	if err != nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("application_owner: install response: %w", err)
	}
	refs := []owner_store.ArtifactReference{stateRef, responseRef}
	refs = append(refs, extra...)

	rt.producerSeq++
	submission := owner_store.EventSubmission{
		ProducerSequence:   rt.producerSeq,
		EventKind:          events[0].EventKind,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"attempt_id":      cmd.AttemptID,
				"operation_key":   cmd.OperationKey,
				"operation_kind":  cmd.OperationKind,
				"state_revision":  int64(resp.StateRevision),
				"workflow_state":  resp.WorkflowState,
				"status":          resp.Status,
				"request_digest":  resp.RequestDigest,
				"state_digest":    stateRef.Digest,
				"response_digest": responseRef.Digest,
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: refs,
		},
	}
	// Rejection reasons ride as data, never as bare nulls.
	if resp.Status == fixture_reducer.OutcomeRejected {
		submission.Payload.Data["reason"] = resp.Reason
		submission.Payload.Data["reason_detail"] = resp.ReasonDetail
	}
	envelopes, err := owner_store.CommitOwner(ctx, h.store, rt.journalID, []owner_store.EventSubmission{submission}, nil)
	if err != nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("application_owner: commit mutation: %w", err)
	}
	last := envelopes[len(envelopes)-1]
	rt.state = append([]byte(nil), canonicalState...)
	rt.head = JournalPrefix{JournalID: rt.journalID, LastSequence: last.Sequence, HeadHash: last.EventHash}

	code := http.StatusOK
	if resp.Status == fixture_reducer.OutcomeRejected {
		code = http.StatusUnprocessableEntity
	}
	return canonicalResponse, code, nil
}

// ---------------------------------------------------------------------------
// Read endpoints.
// ---------------------------------------------------------------------------

func (h *applicationHandler) serveJobs(w http.ResponseWriter, r *http.Request) {
	attemptID, err := queryAttempt(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_attempt", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "read", attemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, attemptID)
	if !ok {
		return
	}
	rt.mu.Lock()
	snap, err := decodeSnapshot(rt.state)
	rt.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state_error", err.Error())
		return
	}
	jobs := make([]map[string]any, 0, len(snap.KnownJobs))
	for _, id := range snap.KnownJobs {
		jobs = append(jobs, map[string]any{"job_id": id})
	}
	writeJSON(w, http.StatusOK, map[string]any{"attempt_id": attemptID, "jobs": jobs})
}

func (h *applicationHandler) serveJobDetail(w http.ResponseWriter, r *http.Request) {
	attemptID, err := queryAttempt(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_attempt", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "read", attemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, attemptID)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	if strings.TrimSpace(id) == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "invalid_job", "job id is required")
		return
	}
	rt.mu.Lock()
	snap, err := decodeSnapshot(rt.state)
	rt.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state_error", err.Error())
		return
	}
	for _, known := range snap.KnownJobs {
		if known == id {
			writeJSON(w, http.StatusOK, map[string]any{"attempt_id": attemptID, "job_id": id, "known": true})
			return
		}
	}
	// Unknown job is not selection.
	writeError(w, http.StatusNotFound, "unknown_job", "job "+id+" is not a known synthetic job")
}

func (h *applicationHandler) serveDraft(w http.ResponseWriter, r *http.Request) {
	attemptID, err := queryAttempt(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_attempt", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "read", attemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, attemptID)
	if !ok {
		return
	}
	rt.mu.Lock()
	snap, err := decodeSnapshot(rt.state)
	rt.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, buildDraft(attemptID, snap))
}

func buildDraft(attemptID string, snap fixtureSnapshot) map[string]any {
	var selected any = missing("not_observed")
	if strings.TrimSpace(snap.SelectedJob) != "" {
		selected = snap.SelectedJob
	}
	contact := sectionOrMissing(snap.Contact)
	history := sectionOrMissing(snap.History)
	var review any = missing("not_observed")
	if snap.Review != nil {
		review = map[string]any{
			"value_revision":         snap.Review.ValueRevision,
			"validation_generation":  snap.Review.ValidationGeneration,
			"contact_value_revision": snap.Review.ContactValueRevision,
			"contact_generation":     snap.Review.ContactGeneration,
			"history_value_revision": snap.Review.HistoryValueRevision,
			"history_generation":     snap.Review.HistoryGeneration,
			"support":                snap.Review.Support,
		}
	}
	var upload any = missing("not_observed")
	if snap.Upload != nil {
		upload = map[string]any{
			"filename":     snap.Upload.Filename,
			"content_type": snap.Upload.ContentType,
			"size_bytes":   snap.Upload.SizeBytes,
			"digest":       snap.Upload.Digest,
			"support":      snap.Upload.Support,
		}
	}
	var identity any = missing("not_observed")
	if snap.Identity != nil {
		// The receipt token itself is not rendered; verification is
		// reported as the bound epoch plus the verified flag.
		identity = map[string]any{
			"epoch":    snap.Identity.Epoch,
			"verified": snap.Identity.Verified,
			"support":  snap.Identity.Support,
		}
	}
	var submission any = missing("not_observed")
	if snap.Submission != nil {
		submission = commitmentMap(snap.Submission)
	}
	var sealRef any = missing("not_applicable")
	if strings.TrimSpace(snap.AuthoritySealRef) != "" {
		sealRef = snap.AuthoritySealRef
	}
	return map[string]any{
		"attempt_id":         attemptID,
		"state_revision":     snap.StateRevision,
		"workflow_state":     snap.WorkflowState,
		"selected_job":       selected,
		"accepted_sections":  map[string]any{"contact": contact, "history": history, "review": review},
		"upload":             upload,
		"identity_receipt":   identity,
		"submission":         submission,
		"mutation_authority": snap.MutationAuthority,
		"authority_seal_ref": sealRef,
	}
}

func sectionOrMissing(s *stateSection) any {
	if s == nil {
		return missing("not_observed")
	}
	var data any = missing("not_observed")
	if len(bytes.TrimSpace(s.Data)) > 0 {
		var v any
		if err := json.Unmarshal(s.Data, &v); err == nil {
			data = v
		}
	}
	return map[string]any{
		"section":               s.Section,
		"value_revision":        s.ValueRevision,
		"validation_generation": s.ValidationGeneration,
		"data_digest":           s.DataDigest,
		"data":                  data,
		"support":               s.Support,
	}
}

func commitmentMap(c *stateCommitment) map[string]any {
	return map[string]any{
		"application_id": c.ApplicationID,
		"operation_key":  c.OperationKey,
		"request_digest": c.RequestDigest,
		"receipt":        c.Receipt,
		"committed_at":   c.CommittedAt,
		"commit_ref":     c.CommitRef,
	}
}

// serveConfirmation returns the existing committed receipt. Commitment,
// receipt retrieval, and receipt rendering are three separate facts: this
// endpoint asserts nothing about rendering, and missing rendering telemetry
// cannot erase the commitment.
func (h *applicationHandler) serveConfirmation(w http.ResponseWriter, r *http.Request) {
	attemptID, err := queryAttempt(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_attempt", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "read", attemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, attemptID)
	if !ok {
		return
	}
	rt.mu.Lock()
	snap, err := decodeSnapshot(rt.state)
	rt.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "state_error", err.Error())
		return
	}
	if snap.Submission == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"attempt_id": attemptID,
			"status":     "not_committed",
		})
		return
	}
	out := commitmentMap(snap.Submission)
	out["attempt_id"] = attemptID
	out["state_revision"] = snap.StateRevision
	out["workflow_state"] = snap.WorkflowState
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Mutation endpoints.
// ---------------------------------------------------------------------------

func (h *applicationHandler) serveJobSelection(w http.ResponseWriter, r *http.Request) {
	var body struct {
		mutationEnvelope
		JobID string `json:"job_id"`
	}
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	payload, err := json.Marshal(map[string]any{"job_id": body.JobID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode_error", err.Error())
		return
	}
	cmd := fixture_reducer.EventSubmission{
		OperationKey:     body.OperationKey,
		OperationKind:    fixture_reducer.OpJobSelection,
		AttemptID:        body.AttemptID,
		ExpectedRevision: body.ExpectedRevision,
		Payload:          payload,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, nil)
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

func (h *applicationHandler) serveContact(w http.ResponseWriter, r *http.Request) {
	var body struct {
		mutationEnvelope
		SectionValueRevision int             `json:"section_value_revision"`
		ValidationGeneration int             `json:"validation_generation"`
		Data                 json.RawMessage `json:"data"`
	}
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	rev, gen := body.SectionValueRevision, body.ValidationGeneration
	cmd := fixture_reducer.EventSubmission{
		OperationKey:                   body.OperationKey,
		OperationKind:                  fixture_reducer.OpContact,
		AttemptID:                      body.AttemptID,
		ExpectedRevision:               body.ExpectedRevision,
		Section:                        "contact",
		SectionValueRevision:           &rev,
		SectionValueRevisionApplicable: true,
		ValidationGeneration:           &gen,
		ValidationGenerationApplicable: true,
		Payload:                        body.Data,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, nil)
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

func (h *applicationHandler) serveHistoryEnter(w http.ResponseWriter, r *http.Request) {
	var body mutationEnvelope
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	cmd := fixture_reducer.EventSubmission{
		OperationKey:     body.OperationKey,
		OperationKind:    fixture_reducer.OpHistoryEnter,
		AttemptID:        body.AttemptID,
		ExpectedRevision: body.ExpectedRevision,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, nil)
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

func (h *applicationHandler) serveHistory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		mutationEnvelope
		SectionValueRevision int             `json:"section_value_revision"`
		ValidationGeneration int             `json:"validation_generation"`
		Data                 json.RawMessage `json:"data"`
	}
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	rev, gen := body.SectionValueRevision, body.ValidationGeneration
	cmd := fixture_reducer.EventSubmission{
		OperationKey:                   body.OperationKey,
		OperationKind:                  fixture_reducer.OpHistory,
		AttemptID:                      body.AttemptID,
		ExpectedRevision:               body.ExpectedRevision,
		Section:                        "history",
		SectionValueRevision:           &rev,
		SectionValueRevisionApplicable: true,
		ValidationGeneration:           &gen,
		ValidationGenerationApplicable: true,
		Payload:                        body.Data,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, nil)
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

// serveUpload binds, hashes, and durably installs the submitted document
// before the owner-local commit that acknowledges it. No upload is
// acknowledged before its bytes are installed and the commit is durable.
// Caller-supplied digests are never trusted: the server computes the digest
// over the received bytes.
func (h *applicationHandler) serveUpload(w http.ResponseWriter, r *http.Request) {
	var body struct {
		mutationEnvelope
		Filename      string `json:"filename"`
		ContentType   string `json:"content_type"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	if strings.TrimSpace(body.Filename) == "" || strings.TrimSpace(body.ContentType) == "" {
		writeError(w, http.StatusBadRequest, "invalid_upload", "filename and content_type are required")
		return
	}
	content, err := base64.StdEncoding.DecodeString(body.ContentBase64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_upload", "content_base64 is not valid base64")
		return
	}
	// Server-computed digest over the received bytes; nothing
	// caller-supplied is trusted for the byte identity.
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	uploadRef, err := owner_store.InstallArtifact(r.Context(), h.store, bytes.NewReader(content), body.ContentType, "restricted")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "storage_failure", err.Error())
		return
	}
	if uploadRef.Digest != digest {
		writeError(w, http.StatusInternalServerError, "digest_mismatch", "installed digest does not match computed digest")
		return
	}
	payload, err := json.Marshal(map[string]any{
		"filename":     body.Filename,
		"content_type": body.ContentType,
		"size_bytes":   int64(len(content)),
		"digest":       digest,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode_error", err.Error())
		return
	}
	cmd := fixture_reducer.EventSubmission{
		OperationKey:     body.OperationKey,
		OperationKind:    fixture_reducer.OpUpload,
		AttemptID:        body.AttemptID,
		ExpectedRevision: body.ExpectedRevision,
		Payload:          payload,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, []owner_store.ArtifactReference{uploadRef})
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

// serveIdentityVerify verifies a local attempt- and epoch-bound receipt.
// Token possession without a valid verification receipt verifies nothing:
// the pinned epoch must match and the receipt must bind this attempt.
func (h *applicationHandler) serveIdentityVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		mutationEnvelope
		Epoch   string `json:"epoch"`
		Receipt string `json:"receipt"`
	}
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"epoch":      body.Epoch,
		"receipt":    body.Receipt,
		"attempt_id": body.AttemptID,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode_error", err.Error())
		return
	}
	cmd := fixture_reducer.EventSubmission{
		OperationKey:     body.OperationKey,
		OperationKind:    fixture_reducer.OpIdentityVerify,
		AttemptID:        body.AttemptID,
		ExpectedRevision: body.ExpectedRevision,
		Payload:          payload,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, nil)
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

func (h *applicationHandler) serveReviewValidate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		mutationEnvelope
		ContactValueRevision int `json:"contact_value_revision"`
		ContactGeneration    int `json:"contact_generation"`
		HistoryValueRevision int `json:"history_value_revision"`
		HistoryGeneration    int `json:"history_generation"`
	}
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"contact_value_revision": body.ContactValueRevision,
		"contact_generation":     body.ContactGeneration,
		"history_value_revision": body.HistoryValueRevision,
		"history_generation":     body.HistoryGeneration,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode_error", err.Error())
		return
	}
	cmd := fixture_reducer.EventSubmission{
		OperationKey:     body.OperationKey,
		OperationKind:    fixture_reducer.OpReviewValidate,
		AttemptID:        body.AttemptID,
		ExpectedRevision: body.ExpectedRevision,
		Payload:          payload,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, nil)
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

// serveSubmit revalidates the current accepted prerequisites and commits at
// most one application per attempt. An accepted repeat with current content
// resolves to the existing commitment; stale or conflicting content rejects.
func (h *applicationHandler) serveSubmit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		mutationEnvelope
		Pins map[string]any `json:"pins"`
	}
	if err := decodeRequestBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_body", err.Error())
		return
	}
	if err := body.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_mutation", err.Error())
		return
	}
	if err := checkQueryBinding(r, body.AttemptID); err != nil {
		writeError(w, http.StatusBadRequest, "ambiguous_binding", err.Error())
		return
	}
	if err := h.authorizeAttempt(r, "write", body.AttemptID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized", err.Error())
		return
	}
	rt, ok := h.runtimeFor(w, body.AttemptID)
	if !ok {
		return
	}
	var payload json.RawMessage
	if body.Pins != nil {
		raw, err := json.Marshal(body.Pins)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode_error", err.Error())
			return
		}
		payload = raw
	}
	cmd := fixture_reducer.EventSubmission{
		OperationKey:     body.OperationKey,
		OperationKind:    fixture_reducer.OpSubmit,
		AttemptID:        body.AttemptID,
		ExpectedRevision: body.ExpectedRevision,
		Payload:          payload,
	}
	resp, code, err := h.commitMutation(r.Context(), rt, cmd, nil)
	if err != nil {
		writeError(w, code, "mutation_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

// ---------------------------------------------------------------------------
// SealApplication.
// ---------------------------------------------------------------------------

// SealApplication fences the attempt's mutation authority and publishes the
// first application-axis revision for the attempt. The seal commit records
// the already admitted transaction count and head so the publication
// accounts for every admitted transaction; later mutations are rejected
// while identical replays still return their stored responses.
//
// The authority reference must cite already admitted owner evidence for this
// attempt journal; it is embedded as the actual seal evidence. Sealing is
// finality for the fixture attempt, not cancellation or rollback.
func SealApplication(ctx context.Context, store *OwnerStore, attempt AttemptReference, authorityRef EvidenceRef) (AxisRevision, error) {
	var zero AxisRevision
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if strings.TrimSpace(attempt.AttemptID) == "" {
		return zero, fmt.Errorf("%w: attempt_id is required", ErrInvalid)
	}
	if attempt.Kind != "practice" {
		return zero, fmt.Errorf("%w: fixture sealing admits only practice attempts, got kind %q", ErrInvalid, attempt.Kind)
	}
	if err := authority.Authorize(ctx, ownerDomain, "write", attempt.AttemptID); err != nil {
		return zero, fmt.Errorf("%w: seal: %v", ErrUnauthorized, err)
	}
	rt, ok := lookupRuntime(store, attempt.AttemptID)
	if !ok {
		return zero, fmt.Errorf("%w: attempt %q", ErrUnknownAttempt, attempt.AttemptID)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.sealed && len(rt.publications) > 0 {
		return rt.publications[0], nil
	}
	if err := checkSealAuthority(authorityRef, rt.journalID, rt.head.LastSequence); err != nil {
		return zero, err
	}
	snap, err := decodeSnapshot(rt.state)
	if err != nil {
		return zero, err
	}
	if snap.MutationAuthority == fixture_reducer.AuthoritySealed {
		return zero, fmt.Errorf("%w: attempt %q is already sealed", ErrSealed, attempt.AttemptID)
	}
	admitted := len(snap.Journal)
	admittedHead := rt.head.HeadHash
	preSealRevision := snap.StateRevision

	sealRefText := fmt.Sprintf("journal:%s/sequence:%d/event:%s/hash:%s",
		authorityRef.JournalID, authorityRef.Sequence, authorityRef.EventID, authorityRef.EventHash)
	sealPayload, err := json.Marshal(map[string]any{"seal_ref": sealRefText})
	if err != nil {
		return zero, fmt.Errorf("%w: cannot encode seal payload: %v", ErrInvalid, err)
	}
	cmd := fixture_reducer.EventSubmission{
		OperationKey:     "seal-1",
		OperationKind:    fixture_reducer.OpSeal,
		AttemptID:        attempt.AttemptID,
		ExpectedRevision: preSealRevision,
		Payload:          sealPayload,
	}
	nextState, events, response, err := fixture_reducer.ReduceFixture(rt.manifest, rt.config, rt.state, cmd)
	if err != nil {
		return zero, fmt.Errorf("%w: seal rejected: %v", ErrInvalid, err)
	}
	if len(events) == 0 {
		return zero, fmt.Errorf("%w: seal replayed without a seal event", ErrInvalid)
	}
	resp, err := decodeReducerResponse(response)
	if err != nil {
		return zero, err
	}
	if resp.Status == fixture_reducer.OutcomeRejected {
		return zero, fmt.Errorf("%w: seal rejected (%s): %s", ErrInvalid, resp.Reason, resp.ReasonDetail)
	}
	canonicalState, err := evidence_codec.CanonicalJSON(nextState, "application/json")
	if err != nil {
		return zero, fmt.Errorf("application_owner: canonicalize sealed state: %w", err)
	}
	canonicalResponse, err := evidence_codec.CanonicalJSON(response, "application/json")
	if err != nil {
		return zero, fmt.Errorf("application_owner: canonicalize seal response: %w", err)
	}
	stateRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalState), "application/json", "restricted")
	if err != nil {
		return zero, fmt.Errorf("application_owner: install sealed state: %w", err)
	}
	responseRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalResponse), "application/json", "restricted")
	if err != nil {
		return zero, fmt.Errorf("application_owner: install seal response: %w", err)
	}
	rt.producerSeq++
	submission := owner_store.EventSubmission{
		ProducerSequence:   rt.producerSeq,
		EventKind:          eventSeal,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         owner_store.NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"attempt_id":          attempt.AttemptID,
				"operation_key":       cmd.OperationKey,
				"operation_kind":      cmd.OperationKind,
				"state_revision":      int64(resp.StateRevision),
				"workflow_state":      resp.WorkflowState,
				"status":              resp.Status,
				"request_digest":      resp.RequestDigest,
				"state_digest":        stateRef.Digest,
				"response_digest":     responseRef.Digest,
				"admitted_operations": int64(admitted),
				"admitted_head":       admittedHead,
				"seal_authority":      sealRefText,
			},
			Measurements: []owner_store.Measurement{},
			EvidenceRefs: []owner_store.EvidenceRef{},
			ArtifactRefs: []owner_store.ArtifactReference{stateRef, responseRef},
		},
	}
	envelopes, err := owner_store.CommitOwner(ctx, store, rt.journalID, []owner_store.EventSubmission{submission}, nil)
	if err != nil {
		return zero, fmt.Errorf("application_owner: commit seal: %w", err)
	}
	sealEnv := envelopes[len(envelopes)-1]
	rt.state = append([]byte(nil), canonicalState...)
	rt.head = JournalPrefix{JournalID: rt.journalID, LastSequence: sealEnv.Sequence, HeadHash: sealEnv.EventHash}
	rt.sealed = true

	sealedSnap, err := decodeSnapshot(rt.state)
	if err != nil {
		return zero, err
	}
	pub, err := buildSealPublication(ctx, store, rt, attempt, sealedSnap)
	if err != nil {
		return zero, err
	}
	rt.publications = append(rt.publications, pub)
	return pub, nil
}

func checkSealAuthority(ref EvidenceRef, journalID string, headSequence int64) error {
	if strings.TrimSpace(ref.JournalID) == "" || strings.TrimSpace(ref.EventID) == "" {
		return fmt.Errorf("%w: seal authority must cite a journal coordinate", ErrInvalid)
	}
	if !validDigest(ref.EventHash) {
		return fmt.Errorf("%w: seal authority event_hash is not a valid digest", ErrInvalid)
	}
	if ref.JournalID != journalID {
		return fmt.Errorf("%w: seal authority journal %q does not match attempt journal %q", ErrInvalid, ref.JournalID, journalID)
	}
	if ref.Sequence < 1 || ref.Sequence > headSequence {
		return fmt.Errorf("%w: seal authority sequence %d is not admitted (head %d)", ErrInvalid, ref.Sequence, headSequence)
	}
	return nil
}

// buildSealPublication constructs the first application-axis revision from
// the sealed reducer snapshot and validates it through the lifecycle rules
// against the retained owner journal evidence.
func buildSealPublication(ctx context.Context, store *OwnerStore, rt *attemptRuntime, attempt AttemptReference, snap fixtureSnapshot) (AxisRevision, error) {
	var zero AxisRevision
	commission := buildCommission(rt, attempt, snap)
	rawCommission, err := json.Marshal(commission)
	if err != nil {
		return zero, fmt.Errorf("application_owner: encode commission: %w", err)
	}
	canonicalCommission, err := evidence_codec.CanonicalJSON(rawCommission, "application/json")
	if err != nil {
		return zero, fmt.Errorf("application_owner: canonicalize commission: %w", err)
	}
	commissionDigest := hashDigest(canonicalCommission)

	sealRef := EvidenceRef{
		JournalID: rt.head.JournalID,
		Sequence:  rt.head.LastSequence,
		EventHash: rt.head.HeadHash,
	}
	// The seal event ID is read back from the retained prefix below; fill
	// the remaining coordinate first by loading the sealed prefix.
	evidence, err := owner_store.LoadPrefix(ctx, store, owner_store.JournalPrefix{
		JournalID: rt.head.JournalID, LastSequence: rt.head.LastSequence, HeadHash: rt.head.HeadHash,
	})
	if err != nil {
		return zero, fmt.Errorf("application_owner: load seal evidence: %w", err)
	}
	var sealEventID string
	for _, env := range evidence {
		if env.Sequence == rt.head.LastSequence && env.JournalID == rt.head.JournalID {
			sealEventID = env.EventID
		}
	}
	if sealEventID == "" {
		return zero, fmt.Errorf("%w: seal event is not retained", ErrInvalid)
	}
	sealRef.EventID = sealEventID
	sealRef.Pointer = ""

	state := "not_committed"
	var originAppID any = lifecycle_rules.NewMissing("not_applicable")
	var originRevision any = lifecycle_rules.NewMissing("not_applicable")
	if snap.Submission != nil {
		state = "committed"
		originAppID = snap.Submission.ApplicationID
		originRevision = fmt.Sprintf("revision:%d", snap.StateRevision)
	}
	receiptDoc := map[string]any{
		"fact_id":    "fact-" + attempt.AttemptID + "-1",
		"attempt_id": attempt.AttemptID,
		"state":      state,
		"coverage":   "final_for_attempt",
		"revision":   snap.StateRevision,
		"seal_head":  rt.head.HeadHash,
	}
	if snap.Submission != nil {
		receiptDoc["application_id"] = snap.Submission.ApplicationID
		receiptDoc["request_digest"] = snap.Submission.RequestDigest
		receiptDoc["commit_ref"] = snap.Submission.CommitRef
	}
	rawReceipt, err := json.Marshal(receiptDoc)
	if err != nil {
		return zero, fmt.Errorf("application_owner: encode receipt: %w", err)
	}
	canonicalReceipt, err := evidence_codec.CanonicalJSON(rawReceipt, "application/json")
	if err != nil {
		return zero, fmt.Errorf("application_owner: canonicalize receipt: %w", err)
	}
	receiptRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalReceipt), "application/json", "restricted")
	if err != nil {
		return zero, fmt.Errorf("application_owner: install receipt: %w", err)
	}

	clockID := "clock-" + rt.journalID
	bootID := "boot-" + rt.journalID
	fact := lifecycle_rules.OriginFact{
		FactID:              "fact-" + attempt.AttemptID + "-1",
		OriginID:            commission.Attempt.TargetID,
		CandidateID:         commission.CandidateID,
		JobID:               commission.Job.JobID,
		State:               state,
		Coverage:            "final_for_attempt",
		BoundaryRef:         sealRef,
		OriginApplicationID: originAppID,
		OriginRevision:      originRevision,
		Receipt:             receiptRef,
		VerificationKind:    "local_origin_transaction",
		SourceChecks: lifecycle_rules.SourceChecks{
			Authentication:     "verified",
			Correlation:        "matched",
			TraceCorrelation:   "matched",
			VerificationPolicy: lifecycle_rules.VersionPin{ID: "verify-policy", Version: "v1", ArtifactDigest: hashDigest([]byte("verify-policy/v1"))},
			MatchedBy:          []string{"attempt-binding"},
			EvidenceRefs:       []EvidenceRef{sealRef},
		},
		AuthoritySealRef: sealRef,
		OccurredAt:       lifecycle_rules.NewMissing("not_observed"),
		ReceivedAt: lifecycle_rules.TimePoint{
			ClockID: clockID, BootID: bootID, Origin: "engine_measured",
			MonotonicOffsetMs: float64(rt.head.LastSequence), UTCAnnotation: lifecycle_rules.NewMissing("not_applicable"),
		},
		EvidenceRefs: []EvidenceRef{sealRef},
	}
	next := AxisRevision{
		RecordType:       lifecycle_rules.RecordAxis,
		SchemaVersion:    lifecycle_rules.SchemaLifecycle,
		Attempt:          attempt,
		CommissionDigest: commissionDigest,
		Axis:             lifecycle_rules.AxisApplication,
		OwnerDomain:      commission.Owners.Application.OwnerDomain,
		WriterID:         "app-writer-" + attempt.AttemptID,
		Revision:         1,
		PreviousRevision: 0,
		EvidencePrefix:   rt.head,
		EvidenceRefs:     []EvidenceRef{sealRef},
		Value:            lifecycle_rules.ApplicationValue{Facts: []lifecycle_rules.OriginFact{fact}},
	}
	lifecycleEvidence := make([]lifecycle_rules.JournalEnvelope, len(evidence))
	copy(lifecycleEvidence, evidence)
	if err := lifecycle_rules.ValidateAxisTransition(commission, nil, next, lifecycleEvidence); err != nil {
		return zero, fmt.Errorf("application_owner: seal publication rejected: %w", err)
	}
	return next, nil
}

// buildCommission synthesizes the attempt commission pinned by the fixture
// manifest and session registration. The fixture admits manual practice
// attempts on a laboratory target exclusively.
func buildCommission(rt *attemptRuntime, attempt AttemptReference, snap fixtureSnapshot) lifecycle_rules.AttemptCommission {
	targetID := "origin-" + attempt.AttemptID
	candidateID := "candidate-" + attempt.AttemptID
	jobID := snap.SelectedJob
	if strings.TrimSpace(jobID) == "" {
		jobID = "job-1"
	}
	clockID := "clock-" + rt.journalID
	bootID := "boot-" + rt.journalID
	snapshotRef := ArtifactReference{
		Digest: hashDigest([]byte("job-snapshot/" + jobID)), SizeBytes: 64,
		MediaType: "application/json", OwnerDomain: rt.ownerDomain, Access: "restricted",
	}
	taskRef := ArtifactReference{
		Digest: hashDigest([]byte("task/" + attempt.AttemptID)), SizeBytes: 64,
		MediaType: "application/json", OwnerDomain: rt.ownerDomain, Access: "restricted",
	}
	pubPolicy := lifecycle_rules.VersionPin{ID: "pub-policy", Version: "v1", ArtifactDigest: hashDigest([]byte("pub-policy/v1"))}
	return lifecycle_rules.AttemptCommission{
		RecordType:     "attempt_commission",
		SchemaVersion:  lifecycle_rules.SchemaLifecycle,
		KernelVersion:  lifecycle_rules.SchemaKernel,
		CommissionID:   "commission-" + attempt.AttemptID,
		RunID:          rt.manifest.RunID,
		JournalID:      rt.journalID,
		ManifestHash:   rt.manifestHash,
		AdmissionRef:   rt.admissionRef,
		CommissionedBy: "operator-1",
		CommissionedAt: lifecycle_rules.TimePoint{
			ClockID: clockID, BootID: bootID, Origin: "engine_measured",
			MonotonicOffsetMs: 0, UTCAnnotation: lifecycle_rules.NewMissing("not_applicable"),
		},
		Attempt: lifecycle_rules.AttemptContext{
			AttemptID: attempt.AttemptID, Kind: "practice",
			TargetClass: "laboratory_fixture", TargetID: targetID,
			EvaluationPartition: "held_in",
			RehearsalOf:         []AttemptReference{},
			PerformanceOf:       []AttemptReference{},
			DerivedFrom:         []AttemptReference{},
		},
		CandidateID:      candidateID,
		CandidateProfile: lifecycle_rules.NewMissing("not_observed"),
		Job: lifecycle_rules.JobReference{
			JobID:        jobID,
			SourceTarget: lifecycle_rules.NewMissing("not_observed"),
			SourceJobID:  lifecycle_rules.NewMissing("not_observed"),
			Snapshot:     snapshotRef,
		},
		SelectionEvidence: lifecycle_rules.NewMissing("not_observed"),
		Task:              taskRef,
		TaskSemanticHash:  hashDigest([]byte("task-semantic/" + attempt.AttemptID)),
		InitialMaterials:  []ArtifactReference{},
		Execution: lifecycle_rules.ExecutionDescriptor{
			Mode:             "manual",
			Subject:          lifecycle_rules.NewMissing("not_applicable"),
			ConnectorVersion: lifecycle_rules.NewMissing("not_applicable"),
			BindingVersion:   lifecycle_rules.NewMissing("not_applicable"),
			Assistance: lifecycle_rules.AssistanceRecord{
				PlanningOwner: "none", AssistanceTrack: "manual-track",
				PlannerIdentity:  lifecycle_rules.NewMissing("not_applicable"),
				Plan:             lifecycle_rules.NewMissing("not_observed"),
				OnlineReplanning: false, Description: "manual walkthrough",
			},
		},
		Owners: lifecycle_rules.OwnerBindings{
			Dispatch:    lifecycle_rules.AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "dispatch-writer-" + attempt.AttemptID, OwnerDomain: "dispatch-" + attempt.AttemptID, PublicationPolicy: pubPolicy},
			Observation: lifecycle_rules.AuthorityBinding{Role: "connector", SourceID: "connector-1", WriterID: "obs-writer-" + attempt.AttemptID, OwnerDomain: "obs-" + attempt.AttemptID, PublicationPolicy: pubPolicy},
			Execution:   lifecycle_rules.AuthorityBinding{Role: "subject", SourceID: lifecycle_rules.NewMissing("not_applicable"), WriterID: lifecycle_rules.NewMissing("not_applicable"), OwnerDomain: "exec-" + attempt.AttemptID, PublicationPolicy: pubPolicy},
			Application: lifecycle_rules.AuthorityBinding{Role: "origin", SourceID: targetID, WriterID: "app-writer-" + attempt.AttemptID, OwnerDomain: rt.ownerDomain, PublicationPolicy: pubPolicy},
			Report:      lifecycle_rules.AuthorityBinding{Role: "reconciler", SourceID: "reconciler-1", WriterID: "report-writer-" + attempt.AttemptID, OwnerDomain: "report-" + attempt.AttemptID, PublicationPolicy: pubPolicy},
		},
		IdempotencyKey:     "idem-" + attempt.AttemptID,
		AuthorizationRefs:  []EvidenceRef{rt.admissionRef},
		RecoveryReviewRefs: []EvidenceRef{},
		ObservationPolicy: lifecycle_rules.ObservationPolicy{
			ActiveLimit:           lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			DrainLimit:            lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 10000},
			NativeCancelWaitLimit: lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			CleanupWaitLimit:      lifecycle_rules.DurationLimit{Kind: "exact", Unit: "ms", Value: 5000},
			FixtureCloseAction:    "seal_after_drain",
		},
		OriginPolicy: lifecycle_rules.VersionPin{ID: "origin-policy", Version: "v1", ArtifactDigest: hashDigest([]byte("origin-policy/v1"))},
	}
}
