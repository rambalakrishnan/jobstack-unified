// Package admission implements the tier-7 Hellscape admission saga.
//
// Admission proceeds through independently durable steps (seam 5.1):
//
//  1. Authenticate and authorize the commissioner.
//  2. Validate complete configuration and finite limits.
//  3. Enforce practice/held-in partitioning.
//  4. Install primary manifest and required artifacts.
//  5. Commit primary manifest admission.
//  6. Register the attempt commission.
//  7. Register attempt and session owner bindings.
//  8. Asynchronously initialize application and observation owners.
//  9. Record their initialization receipts.
//  10. Make the entry usable and permit subject preparation only after
//     required initialization.
//
// AdmitSession performs steps 1-7 against the primary (diagnostic) store
// only. It never touches the application or observation stores, never holds
// a primary transaction while initializing another owner, and never
// acknowledges durable admission before the immutable primary manifest and
// required inputs exist. A failure before the durable CommitOwner is an
// admission refusal, not a lost admitted session.
//
// AdvanceAdmission performs steps 8-10. It initializes the application and
// observation owners through their own owner-local CommitOwner boundaries,
// sequentially, then records their receipts and the entry_usable marker
// through separate primary-local commits. A later owner-initialization
// failure never rolls back the durable primary admission, and no
// cross-owner atomic commit is ever used.
//
// Boundaries honored:
//
//   - Practice only: laboratory fixtures are practice / laboratory_fixture /
//     held_in. Production requires an employer origin and is refused here.
//   - Manual mode has no automation subject, connector version, binding
//     version, native run ID, or active execution writer. Those fields are
//     Missing(not_applicable) and dispatch/execution slots stay at revision
//     zero.
//   - Attempt identity is immutable: changing subject version, target, kind,
//     task, or permissions requires a new attempt ID. The commissioning
//     idempotency key is scoped to the commissioning principal and the
//     immutable attempt request.
//   - Lineage links (derived_from same-kind acyclic, rehearsal_of practice
//     to production, performance_of production to practice) convey lineage,
//     never inherited commitment or qualification. Hellscape practice
//     attempts carry empty performance links.
//   - No in-band nulls; absent values are typed Missing envelopes.
//   - No shared database writes or cross-domain transactions.
package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"application_owner"
	"authority"
	"evidence_codec"
	"fixture_policy"
	"observation_owner"
	"owner_store"
	"publication"
)

// ---------------------------------------------------------------------------
// Shared types (aliases keep CONSUMES calls translation-free where possible).
// ---------------------------------------------------------------------------

type (
	// OwnerStore is one owner-local durable boundary (one SQLite database
	// plus one content-addressed artifact root).
	OwnerStore = owner_store.OwnerStore
	// Manifest is the admitted laboratory fixture manifest projection.
	Manifest = fixture_policy.Manifest
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = owner_store.EvidenceRef
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = owner_store.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = owner_store.JournalPrefix
	// ArtifactReference is an immutable byte identity plus metadata.
	ArtifactReference = owner_store.ArtifactReference
	// EventSubmission is the ingress shape for owner-local commits.
	EventSubmission = owner_store.EventSubmission
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = owner_store.TimePoint
	// MissingEnvelope is the typed EK Missing value.
	MissingEnvelope = owner_store.MissingEnvelope
	// ClockDescriptor registers one clock lifetime.
	ClockDescriptor = owner_store.ClockDescriptor
	// Measurement is the EK Measurement record.
	Measurement = owner_store.Measurement
	// LogicalRow is the complete derived read value sealed by publication.
	LogicalRow = publication.LogicalRow
)

// Compile-time CONSUMES linkage: fail compilation if a declared upstream
// signature disappears.
var (
	_ = application_owner.InitializeApplication
	_ = observation_owner.InitializeObservation
	_ = publication.SealRow
	_ = fixture_policy.ValidateFixture
	_ = owner_store.CommitOwner
	_ = owner_store.InstallArtifact
	_ = owner_store.ReadArtifact
	_ = authority.Authorize
	_ = evidence_codec.ValidateRecord
)

// ---------------------------------------------------------------------------
// Lifecycle-shaped local types (attempt commission and lineage).
// ---------------------------------------------------------------------------

// AttemptReference identifies one attempt and kind.
type AttemptReference struct {
	AttemptID string `json:"attempt_id"`
	Kind      string `json:"kind"`
}

// AttemptContext is the full attempt identity and lineage.
type AttemptContext struct {
	AttemptID           string             `json:"attempt_id"`
	Kind                string             `json:"kind"`
	TargetClass         string             `json:"target_class"`
	TargetID            string             `json:"target_id"`
	EvaluationPartition string             `json:"evaluation_partition"`
	RehearsalOf         []AttemptReference `json:"rehearsal_of"`
	PerformanceOf       []AttemptReference `json:"performance_of"`
	DerivedFrom         []AttemptReference `json:"derived_from"`
}

// VersionPin pins an immutable versioned artifact.
type VersionPin struct {
	ID             string `json:"id"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

// ComponentIdentity is one stack component of a subject.
type ComponentIdentity struct {
	Component           string `json:"component"`
	ReportedVersion     any    `json:"reported_version"`
	BuildDigest         any    `json:"build_digest"`
	ConfigurationDigest any    `json:"configuration_digest"`
}

// SubjectIdentity identifies the commissioned automation subject.
type SubjectIdentity struct {
	SubjectID           string              `json:"subject_id"`
	SubjectVersion      string              `json:"subject_version"`
	RevisionBasis       string              `json:"revision_basis"`
	NativeRevision      any                 `json:"native_revision"`
	ConfiguredMode      string              `json:"configured_mode"`
	InterfaceSurface    string              `json:"interface_surface"`
	ConfigurationDigest string              `json:"configuration_digest"`
	Stack               []ComponentIdentity `json:"stack"`
}

// AssistanceRecord describes planning assistance.
type AssistanceRecord struct {
	PlanningOwner    string `json:"planning_owner"`
	AssistanceTrack  string `json:"assistance_track"`
	PlannerIdentity  any    `json:"planner_identity"`
	Plan             any    `json:"plan"`
	OnlineReplanning bool   `json:"online_replanning"`
	Description      string `json:"description"`
}

// ExecutionDescriptor restricts attempts to manual or subject.
type ExecutionDescriptor struct {
	Mode             string           `json:"mode"`
	Subject          any              `json:"subject"`
	ConnectorVersion any              `json:"connector_version"`
	BindingVersion   any              `json:"binding_version"`
	Assistance       AssistanceRecord `json:"assistance"`
}

// AuthorityBinding declares one axis authority and its sole writer.
type AuthorityBinding struct {
	Role              string     `json:"role"`
	SourceID          any        `json:"source_id"`
	WriterID          any        `json:"writer_id"`
	OwnerDomain       string     `json:"owner_domain"`
	PublicationPolicy VersionPin `json:"publication_policy"`
}

// OwnerBindings carries the five axis bindings.
type OwnerBindings struct {
	Dispatch    AuthorityBinding `json:"dispatch"`
	Observation AuthorityBinding `json:"observation"`
	Execution   AuthorityBinding `json:"execution"`
	Application AuthorityBinding `json:"application"`
	Report      AuthorityBinding `json:"report"`
}

// DurationLimit is configuration, never a measurement.
type DurationLimit struct {
	Kind  string  `json:"kind"`
	Unit  string  `json:"unit"`
	Value float64 `json:"value"`
}

// ObservationPolicy carries the commissioned local bounds.
type ObservationPolicy struct {
	ActiveLimit           DurationLimit `json:"active_limit"`
	DrainLimit            DurationLimit `json:"drain_limit"`
	NativeCancelWaitLimit DurationLimit `json:"native_cancel_wait_limit"`
	CleanupWaitLimit      DurationLimit `json:"cleanup_wait_limit"`
	FixtureCloseAction    string        `json:"fixture_close_action"`
}

// JobReference pins the job content used for the decision.
type JobReference struct {
	JobID        string            `json:"job_id"`
	SourceTarget any               `json:"source_target"`
	SourceJobID  any               `json:"source_job_id"`
	Snapshot     ArtifactReference `json:"snapshot"`
}

// AttemptCommission freezes the attempt identity and owner bindings.
type AttemptCommission struct {
	RecordType         string              `json:"record_type"`
	SchemaVersion      string              `json:"schema_version"`
	KernelVersion      string              `json:"kernel_version"`
	CommissionID       string              `json:"commission_id"`
	RunID              string              `json:"run_id"`
	JournalID          string              `json:"journal_id"`
	ManifestHash       string              `json:"manifest_hash"`
	AdmissionRef       EvidenceRef         `json:"admission_ref"`
	CommissionedBy     string              `json:"commissioned_by"`
	CommissionedAt     TimePoint           `json:"commissioned_at"`
	Attempt            AttemptContext      `json:"attempt"`
	CandidateID        string              `json:"candidate_id"`
	CandidateProfile   any                 `json:"candidate_profile"`
	Job                JobReference        `json:"job"`
	SelectionEvidence  any                 `json:"selection_evidence"`
	Task               ArtifactReference   `json:"task"`
	TaskSemanticHash    string              `json:"task_semantic_hash"`
	InitialMaterials   []ArtifactReference `json:"initial_materials"`
	Execution          ExecutionDescriptor `json:"execution"`
	Owners             OwnerBindings       `json:"owners"`
	IdempotencyKey     string              `json:"idempotency_key"`
	AuthorizationRefs  []EvidenceRef       `json:"authorization_refs"`
	RecoveryReviewRefs []EvidenceRef       `json:"recovery_review_refs"`
	ObservationPolicy  ObservationPolicy   `json:"observation_policy"`
	OriginPolicy       VersionPin          `json:"origin_policy"`
}

// EntityRegistration is the immutable, authenticated registration of one
// Hellscape session entity. Configuration carries the effective fixture
// configuration pinned at admission; when absent the M1 default applies.
type EntityRegistration struct {
	RecordType     string         `json:"record_type"`
	SchemaVersion  string         `json:"schema_version"`
	RegistrationID string         `json:"registration_id"`
	Entity         map[string]any `json:"entity"`
	Identity       map[string]any `json:"identity"`
	Owners         map[string]any `json:"owners"`
	EvidencePrefix JournalPrefix  `json:"evidence_prefix"`
	EvidenceRefs   []EvidenceRef  `json:"evidence_refs"`
	Configuration  json.RawMessage `json:"configuration,omitempty"`
}

// ---------------------------------------------------------------------------
// Constants and sentinel errors.
// ---------------------------------------------------------------------------

const (
	schemaLifecycle = "application-attempt-lifecycle/0.1.0"
	schemaKernel    = "evidence-kernel/0.1.0"

	eventManifestAdmitted = "manifest_admitted"
	eventSessionAdmitted  = "session_admitted"
	eventAppReceipt       = "application_init_receipt"
	eventObsReceipt       = "observation_init_receipt"
	eventEntryUsable      = "entry_usable"
)

var (
	ErrInvalid       = errors.New("admission: invalid input")
	ErrUnauthorized  = errors.New("admission: unauthorized")
	ErrConflict      = errors.New("admission: idempotency conflict")
	ErrNotAdmitted   = errors.New("admission: session is not admitted")
	ErrNotReady      = errors.New("admission: required initialization is not complete")
	ErrNeedsNewAttempt = errors.New("admission: commission change requires a new immutable attempt identity")
)

// NewMissing builds a typed Missing envelope with a null value and reason.
func NewMissing(reason string) MissingEnvelope { return owner_store.NewMissing(reason) }

// ---------------------------------------------------------------------------
// Small validators.
// ---------------------------------------------------------------------------

var validNullReasons = map[string]bool{
	"not_enabled": true, "not_applicable": true, "not_observed": true,
	"observation_lost": true, "unsupported_by_subject": true, "manual_override": true,
}

var validOrigins = map[string]bool{
	"engine_measured": true, "browser_measured": true,
	"subject_reported": true, "manual_reference": true,
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

func validIdentifier(s string) bool { return strings.TrimSpace(s) != "" }

func validJSONPointer(s string) bool {
	if s == "" {
		return true
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' {
			i++
			if i >= len(s) || (s[i] != '0' && s[i] != '1') {
				return false
			}
		}
	}
	return true
}

func asMissing(v any) (MissingEnvelope, bool) {
	switch t := v.(type) {
	case MissingEnvelope:
		if t.Value != nil {
			return MissingEnvelope{}, false
		}
		if !validNullReasons[t.Reason] {
			return MissingEnvelope{}, false
		}
		return t, true
	case *MissingEnvelope:
		if t == nil {
			return MissingEnvelope{}, false
		}
		return asMissing(*t)
	case map[string]any:
		raw, ok := t["value"]
		if !ok || raw != nil {
			return MissingEnvelope{}, false
		}
		r, _ := t["reason"].(string)
		if !validNullReasons[r] {
			return MissingEnvelope{}, false
		}
		detail := ""
		if d, ok := t["detail"].(string); ok {
			detail = d
		}
		return MissingEnvelope{Value: nil, Reason: r, Detail: detail}, true
	default:
		return MissingEnvelope{}, false
	}
}

func isMissing(v any) bool { _, ok := asMissing(v); return ok }

func isMissingWithReason(v any, reason string) bool {
	m, ok := asMissing(v)
	return ok && m.Reason == reason
}

func asStringValue(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

func asArtifactValue(v any) (ArtifactReference, bool) {
	switch t := v.(type) {
	case ArtifactReference:
		return t, true
	case *ArtifactReference:
		if t == nil {
			return ArtifactReference{}, false
		}
		return *t, true
	case map[string]any:
		digest, _ := t["digest"].(string)
		media, _ := t["media_type"].(string)
		owner, _ := t["owner_domain"].(string)
		access, _ := t["access"].(string)
		var size int64
		switch n := t["size_bytes"].(type) {
		case int64:
			size = n
		case int:
			size = int64(n)
		case float64:
			size = int64(n)
		case json.Number:
			if parsed, err := n.Int64(); err == nil {
				size = parsed
			}
		}
		if digest == "" && media == "" && owner == "" && access == "" && size == 0 {
			return ArtifactReference{}, false
		}
		return ArtifactReference{Digest: digest, SizeBytes: size, MediaType: media, OwnerDomain: owner, Access: access}, true
	default:
		return ArtifactReference{}, false
	}
}

func validateArtifact(a ArtifactReference, field string) error {
	if !validDigest(a.Digest) {
		return fmt.Errorf("%w: %s digest %q is not a valid digest", ErrInvalid, field, a.Digest)
	}
	if a.SizeBytes < 0 {
		return fmt.Errorf("%w: %s size_bytes must not be negative", ErrInvalid, field)
	}
	if !validIdentifier(a.MediaType) {
		return fmt.Errorf("%w: %s media_type must be a nonempty identifier", ErrInvalid, field)
	}
	if !validIdentifier(a.OwnerDomain) {
		return fmt.Errorf("%w: %s owner_domain must be a nonempty identifier", ErrInvalid, field)
	}
	if a.Access != "public" && a.Access != "restricted" {
		return fmt.Errorf("%w: %s access %q must be public or restricted", ErrInvalid, field, a.Access)
	}
	return nil
}

func validateEvidenceRefShape(r EvidenceRef, field string) error {
	if !validIdentifier(r.JournalID) {
		return fmt.Errorf("%w: %s journal_id is required", ErrInvalid, field)
	}
	if r.Sequence < 1 {
		return fmt.Errorf("%w: %s sequence starts at 1", ErrInvalid, field)
	}
	if !validIdentifier(r.EventID) {
		return fmt.Errorf("%w: %s event_id is required", ErrInvalid, field)
	}
	if !validDigest(r.EventHash) {
		return fmt.Errorf("%w: %s event_hash is not a valid digest", ErrInvalid, field)
	}
	if !validJSONPointer(r.Pointer) {
		return fmt.Errorf("%w: %s pointer %q is not a valid JSON pointer", ErrInvalid, field, r.Pointer)
	}
	return nil
}

func validateTimePointShape(tp TimePoint, field string) error {
	if !validIdentifier(tp.ClockID) {
		return fmt.Errorf("%w: %s clock_id must be a nonempty identifier", ErrInvalid, field)
	}
	if !validIdentifier(tp.BootID) {
		return fmt.Errorf("%w: %s boot_id must be a nonempty identifier", ErrInvalid, field)
	}
	if !validOrigins[tp.Origin] {
		return fmt.Errorf("%w: %s has invalid origin %q", ErrInvalid, field, tp.Origin)
	}
	if tp.MonotonicOffsetMs < 0 || math.IsNaN(tp.MonotonicOffsetMs) || math.IsInf(tp.MonotonicOffsetMs, 0) {
		return fmt.Errorf("%w: %s monotonic_offset_ms must be finite and nonnegative", ErrInvalid, field)
	}
	if tp.UTCAnnotation == nil {
		return fmt.Errorf("%w: %s utc_annotation is an in-band null: use a date-time or Missing", ErrInvalid, field)
	}
	if _, ok := asMissing(tp.UTCAnnotation); ok {
		return nil
	}
	if _, ok := tp.UTCAnnotation.(string); ok {
		return nil
	}
	return fmt.Errorf("%w: %s utc_annotation must be a date-time or Missing, got %T", ErrInvalid, field, tp.UTCAnnotation)
}

func validateVersionPin(p VersionPin, field string) error {
	if !validIdentifier(p.ID) {
		return fmt.Errorf("%w: %s id must be a nonempty identifier", ErrInvalid, field)
	}
	if !validIdentifier(p.Version) {
		return fmt.Errorf("%w: %s version must be a nonempty identifier", ErrInvalid, field)
	}
	if !validDigest(p.ArtifactDigest) {
		return fmt.Errorf("%w: %s artifact_digest %q is not a valid digest", ErrInvalid, field, p.ArtifactDigest)
	}
	return nil
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

// extractSubjectVersion returns the automation subject version for
// immutability comparison. Manual execution has no subject version.
func extractSubjectVersion(ex ExecutionDescriptor) string {
	if ex.Mode == "manual" {
		return "manual:not_applicable"
	}
	switch t := ex.Subject.(type) {
	case SubjectIdentity:
		return t.SubjectVersion
	case *SubjectIdentity:
		if t != nil {
			return t.SubjectVersion
		}
	case map[string]any:
		if v, _ := t["subject_version"].(string); v != "" {
			return v
		}
		if v, _ := t["SubjectVersion"].(string); v != "" {
			return v
		}
	}
	// Fall back to a canonical encoding so distinct subjects hash distinctly.
	raw, err := json.Marshal(ex.Subject)
	if err != nil {
		return fmt.Sprintf("%T", ex.Subject)
	}
	return string(raw)
}

func ownersFingerprint(o OwnerBindings) string {
	raw, err := json.Marshal(o)
	if err != nil {
		return fmt.Sprintf("%v", o)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return string(raw)
	}
	return string(evidence_codec.HashBytes(canonical))
}

// requestHash covers the immutable attempt request: attempt identity and
// lineage, candidate, job snapshot, task, execution configuration, owner
// bindings, and observation/origin policy. Server-assigned coordinates
// (commission/run/journal identities, manifest hash, admission ref,
// commissioner/time, authorization receipts) are excluded so a byte-identical
// retry under the same idempotency key reproduces the same hash.
func requestHash(c AttemptCommission) (string, error) {
	projection := map[string]any{
		"attempt":            c.Attempt,
		"candidate_id":       c.CandidateID,
		"candidate_profile":  c.CandidateProfile,
		"job":                c.Job,
		"selection_evidence": c.SelectionEvidence,
		"task":               c.Task,
		"task_semantic_hash": c.TaskSemanticHash,
		"initial_materials":  c.InitialMaterials,
		"execution":          c.Execution,
		"owners":             c.Owners,
		"observation_policy": c.ObservationPolicy,
		"origin_policy":      c.OriginPolicy,
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return "", err
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

// ---------------------------------------------------------------------------
// Registries (in-memory admission index; durable truth is the primary journal).
// ---------------------------------------------------------------------------

type storedAttempt struct {
	attemptID       string
	kind            string
	targetClass     string
	targetID        string
	partition       string
	subjectVersion  string
	taskDigest      string
	taskSemantic    string
	ownersHash      string
	commissionID    string
	manifestHash    string
	commissionRef   EvidenceRef
	derivedFrom     []AttemptReference
	rehearsalOf     []AttemptReference
	performanceOf   []AttemptReference
	commissionCopy  AttemptCommission
}

type storedKey struct {
	attemptID   string
	requestHash string
	ref         EvidenceRef
}

type sessionRecord struct {
	sessionID       string
	journalID       string
	runID           string
	manifest        Manifest
	commission      AttemptCommission
	registrations   []EntityRegistration
	config          []byte
	manifestRef     ArtifactReference
	fixtureRef      ArtifactReference
	commissionRef   ArtifactReference
	registrationsRef ArtifactReference
	admissionRef    EvidenceRef
	admissionPrefix JournalPrefix
	appReceipt      *EvidenceRef
	obsReceipt      *EvidenceRef
	appReceiptRef   *EvidenceRef // primary-local receipt event ref (sequence 3)
	obsReceiptRef   *EvidenceRef // primary-local receipt event ref (sequence 4)
	usableRef       *EvidenceRef
	usable          bool
	headSequence    int64
	headHash        string
}

var (
	registryMu sync.Mutex
	byAttempt  = map[string]*storedAttempt{}
	byKey      = map[string]*storedKey{}
	sessions   = map[*OwnerStore]map[string]*sessionRecord{}
)

func lookupSession(primary *OwnerStore, sessionID string) (*sessionRecord, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	bySession, ok := sessions[primary]
	if !ok {
		return nil, false
	}
	rec, ok := bySession[sessionID]
	return rec, ok
}

func storeSession(primary *OwnerStore, rec *sessionRecord) {
	registryMu.Lock()
	defer registryMu.Unlock()
	bySession, ok := sessions[primary]
	if !ok {
		bySession = map[string]*sessionRecord{}
		sessions[primary] = bySession
	}
	bySession[rec.sessionID] = rec
	// Index aliases so callers may address the session by run ID as well.
	if rec.runID != "" && rec.runID != rec.sessionID {
		bySession[rec.runID] = rec
	}
	if rec.commission.CommissionID != "" {
		bySession[rec.commission.CommissionID] = rec
	}
}

// GetAdmittedCommission returns a copy of the registered commission for an
// admitted attempt. It reports whether the attempt is known. Stored
// commissions are never mutated after registration.
func GetAdmittedCommission(attemptID string) (AttemptCommission, bool) {
	registryMu.Lock()
	defer registryMu.Unlock()
	stored, ok := byAttempt[attemptID]
	if !ok {
		return AttemptCommission{}, false
	}
	return stored.commissionCopy, true
}

// IsEntryUsable reports whether the named session's entry has been marked
// usable after required initialization receipts.
func IsEntryUsable(primary *OwnerStore, sessionID string) bool {
	rec, ok := lookupSession(primary, sessionID)
	if !ok {
		return false
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	return rec.usable
}

// MinimalPrimaryManifest derives the owner-local primary journal manifest
// pinned by admission for the given fixture manifest. The primary journal
// manifest is a distinct complete manifest with its own digest; the fixture
// manifest bytes are retained as a separate required artifact.
func MinimalPrimaryManifest(m Manifest) owner_store.Manifest {
	journalID := strings.TrimSpace(m.JournalID)
	clockID := "clock-" + journalID
	bootID := "boot-" + journalID
	return owner_store.Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         m.RunID,
		JournalID:     journalID,
		OwnerDomain:   m.OwnerDomain,
		Clocks: []ClockDescriptor{{
			ClockID: clockID, BootID: bootID,
			Origin: "engine_measured", SourceID: "admission",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
}

// PrimaryManifestDigest returns the canonical digest of the minimal primary
// manifest. Commissions must agree with the admitted manifest: their
// manifest_hash pins exactly this digest.
func PrimaryManifestDigest(m Manifest) (string, error) {
	minimal := MinimalPrimaryManifest(m)
	raw, err := json.Marshal(minimal)
	if err != nil {
		return "", err
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

// ---------------------------------------------------------------------------
// Commission, lineage, manual, and registration validation.
// ---------------------------------------------------------------------------

func validateAuthorityBinding(b AuthorityBinding, axis, wantRole string) error {
	field := "commission.owners." + axis
	if b.Role != wantRole {
		return fmt.Errorf("%w: %s role must be %q, got %q", ErrInvalid, field, wantRole, b.Role)
	}
	if b.SourceID == nil || b.WriterID == nil {
		return fmt.Errorf("%w: %s source_id/writer_id must not be in-band nulls", ErrInvalid, field)
	}
	if !isMissing(b.SourceID) {
		if _, ok := asStringValue(b.SourceID); !ok {
			return fmt.Errorf("%w: %s source_id must be an identifier or Missing", ErrInvalid, field)
		}
	}
	if !isMissing(b.WriterID) {
		if _, ok := asStringValue(b.WriterID); !ok {
			return fmt.Errorf("%w: %s writer_id must be an identifier or Missing", ErrInvalid, field)
		}
	}
	if !validIdentifier(b.OwnerDomain) {
		return fmt.Errorf("%w: %s owner_domain must be a nonempty identifier", ErrInvalid, field)
	}
	if err := validateVersionPin(b.PublicationPolicy, field+".publication_policy"); err != nil {
		return err
	}
	return nil
}

func validateCommission(c AttemptCommission) error {
	if c.RecordType != "attempt_commission" {
		return fmt.Errorf("%w: commission record_type must be attempt_commission, got %q", ErrInvalid, c.RecordType)
	}
	if c.SchemaVersion != schemaLifecycle {
		return fmt.Errorf("%w: commission schema_version must be %q, got %q", ErrInvalid, schemaLifecycle, c.SchemaVersion)
	}
	if c.KernelVersion != schemaKernel {
		return fmt.Errorf("%w: commission kernel_version must be %q, got %q", ErrInvalid, schemaKernel, c.KernelVersion)
	}
	if !validIdentifier(c.CommissionID) {
		return fmt.Errorf("%w: commission commission_id must be a nonempty identifier", ErrInvalid)
	}
	if !validIdentifier(c.RunID) || !validIdentifier(c.JournalID) {
		return fmt.Errorf("%w: commission run_id/journal_id must be nonempty identifiers", ErrInvalid)
	}
	if !validDigest(c.ManifestHash) {
		return fmt.Errorf("%w: commission manifest_hash %q is not a valid digest", ErrInvalid, c.ManifestHash)
	}
	if err := validateEvidenceRefShape(c.AdmissionRef, "commission.admission_ref"); err != nil {
		return err
	}
	if !validIdentifier(c.CommissionedBy) {
		return fmt.Errorf("%w: commission commissioned_by must be a nonempty identifier", ErrInvalid)
	}
	if err := validateTimePointShape(c.CommissionedAt, "commission.commissioned_at"); err != nil {
		return err
	}
	a := c.Attempt
	if !validIdentifier(a.AttemptID) {
		return fmt.Errorf("%w: commission attempt_id must be a nonempty identifier", ErrInvalid)
	}
	if a.Kind != "practice" && a.Kind != "production" {
		return fmt.Errorf("%w: commission attempt kind %q must be practice or production", ErrInvalid, a.Kind)
	}
	if a.TargetClass != "laboratory_fixture" && a.TargetClass != "employer_origin" {
		return fmt.Errorf("%w: commission target_class %q is invalid", ErrInvalid, a.TargetClass)
	}
	if !validIdentifier(a.TargetID) {
		return fmt.Errorf("%w: commission target_id must be a nonempty identifier", ErrInvalid)
	}
	if a.EvaluationPartition != "held_in" && a.EvaluationPartition != "held_out" {
		return fmt.Errorf("%w: commission evaluation_partition %q is invalid", ErrInvalid, a.EvaluationPartition)
	}
	if a.TargetClass == "laboratory_fixture" && (a.Kind != "practice" || a.EvaluationPartition != "held_in") {
		return fmt.Errorf("%w: laboratory_fixture attempts are practice held_in", ErrInvalid)
	}
	// Hellscape admits practice laboratory fixtures exclusively.
	if a.Kind != "practice" || a.TargetClass != "laboratory_fixture" || a.EvaluationPartition != "held_in" {
		return fmt.Errorf("%w: Hellscape admits only practice/laboratory_fixture/held_in; production requires an employer origin", ErrInvalid)
	}
	if !validIdentifier(c.CandidateID) {
		return fmt.Errorf("%w: commission candidate_id must be a nonempty identifier", ErrInvalid)
	}
	if c.CandidateProfile == nil {
		return fmt.Errorf("%w: commission candidate_profile is an in-band null", ErrInvalid)
	}
	if !isMissing(c.CandidateProfile) {
		if art, ok := asArtifactValue(c.CandidateProfile); ok {
			if err := validateArtifact(art, "commission.candidate_profile"); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%w: commission candidate_profile must be an artifact or Missing", ErrInvalid)
		}
	}
	if !validIdentifier(c.Job.JobID) {
		return fmt.Errorf("%w: commission job job_id must be a nonempty identifier", ErrInvalid)
	}
	if c.Job.SourceTarget == nil || c.Job.SourceJobID == nil {
		return fmt.Errorf("%w: commission job source_target/source_job_id must not be in-band nulls", ErrInvalid)
	}
	if err := validateArtifact(c.Job.Snapshot, "commission.job.snapshot"); err != nil {
		return err
	}
	if c.SelectionEvidence == nil {
		return fmt.Errorf("%w: commission selection_evidence is an in-band null", ErrInvalid)
	}
	if !isMissing(c.SelectionEvidence) {
		if art, ok := asArtifactValue(c.SelectionEvidence); ok {
			if err := validateArtifact(art, "commission.selection_evidence"); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%w: commission selection_evidence must be an artifact or Missing", ErrInvalid)
		}
	}
	if err := validateArtifact(c.Task, "commission.task"); err != nil {
		return err
	}
	if !validDigest(c.TaskSemanticHash) {
		return fmt.Errorf("%w: commission task_semantic_hash %q is not a valid digest", ErrInvalid, c.TaskSemanticHash)
	}
	if c.InitialMaterials == nil {
		return fmt.Errorf("%w: commission initial_materials is an in-band null: use an array", ErrInvalid)
	}
	for i, m := range c.InitialMaterials {
		if err := validateArtifact(m, fmt.Sprintf("commission.initial_materials[%d]", i)); err != nil {
			return err
		}
	}
	ex := c.Execution
	if ex.Mode != "manual" && ex.Mode != "subject" {
		return fmt.Errorf("%w: commission execution mode %q must be manual or subject", ErrInvalid, ex.Mode)
	}
	if ex.Subject == nil || ex.ConnectorVersion == nil || ex.BindingVersion == nil {
		return fmt.Errorf("%w: commission execution subject/connector/binding must not be in-band nulls", ErrInvalid)
	}
	if ex.Mode == "manual" {
		if !isMissingWithReason(ex.Subject, "not_applicable") {
			return fmt.Errorf("%w: manual execution subject must be Missing(not_applicable)", ErrInvalid)
		}
		if !isMissingWithReason(ex.ConnectorVersion, "not_applicable") {
			return fmt.Errorf("%w: manual connector_version must be Missing(not_applicable)", ErrInvalid)
		}
		if !isMissingWithReason(ex.BindingVersion, "not_applicable") {
			return fmt.Errorf("%w: manual binding_version must be Missing(not_applicable)", ErrInvalid)
		}
	} else {
		if isMissing(ex.Subject) {
			return fmt.Errorf("%w: subject-mode execution subject must be a SubjectIdentity", ErrInvalid)
		}
		if _, ok := asStringValue(ex.ConnectorVersion); !ok {
			return fmt.Errorf("%w: subject-mode connector_version must be an identifier", ErrInvalid)
		}
		if _, ok := asStringValue(ex.BindingVersion); !ok {
			return fmt.Errorf("%w: subject-mode binding_version must be an identifier", ErrInvalid)
		}
	}
	if err := validateAuthorityBinding(c.Owners.Dispatch, "dispatch", "connector"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Observation, "observation", "connector"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Execution, "execution", "subject"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Application, "application", "origin"); err != nil {
		return err
	}
	if err := validateAuthorityBinding(c.Owners.Report, "report", "reconciler"); err != nil {
		return err
	}
	if ex.Mode == "manual" {
		if !isMissingWithReason(c.Owners.Execution.SourceID, "not_applicable") {
			return fmt.Errorf("%w: manual execution source_id must be Missing(not_applicable)", ErrInvalid)
		}
		if !isMissingWithReason(c.Owners.Execution.WriterID, "not_applicable") {
			return fmt.Errorf("%w: manual execution writer_id must be Missing(not_applicable): no fabricated automation writer", ErrInvalid)
		}
	} else {
		if _, ok := asStringValue(c.Owners.Execution.SourceID); !ok {
			return fmt.Errorf("%w: subject-mode execution source_id must be an identifier", ErrInvalid)
		}
		if _, ok := asStringValue(c.Owners.Execution.WriterID); !ok {
			return fmt.Errorf("%w: subject-mode execution writer_id must be an identifier", ErrInvalid)
		}
	}
	for _, axis := range []string{"dispatch", "observation", "application", "report"} {
		var b AuthorityBinding
		switch axis {
		case "dispatch":
			b = c.Owners.Dispatch
		case "observation":
			b = c.Owners.Observation
		case "application":
			b = c.Owners.Application
		case "report":
			b = c.Owners.Report
		}
		if _, ok := asStringValue(b.SourceID); !ok {
			return fmt.Errorf("%w: commission owners.%s source_id must be an identifier", ErrInvalid, axis)
		}
		if _, ok := asStringValue(b.WriterID); !ok {
			return fmt.Errorf("%w: commission owners.%s writer_id must be an identifier", ErrInvalid, axis)
		}
	}
	if src, ok := asStringValue(c.Owners.Application.SourceID); ok && src != a.TargetID {
		return fmt.Errorf("%w: application source_id %q must equal attempt target_id %q", ErrInvalid, src, a.TargetID)
	}
	if rw, ok := asStringValue(c.Owners.Report.WriterID); ok {
		if ew, ok := asStringValue(c.Owners.Execution.WriterID); ok && rw == ew {
			return fmt.Errorf("%w: report writer must not hold execution write authority", ErrInvalid)
		}
		if aw, ok := asStringValue(c.Owners.Application.WriterID); ok && rw == aw {
			return fmt.Errorf("%w: report writer must not hold application write authority", ErrInvalid)
		}
	}
	// Owner domains are distinct within the attempt.
	seenDomains := map[string]string{}
	for _, entry := range []struct {
		axis   string
		domain string
	}{
		{"dispatch", c.Owners.Dispatch.OwnerDomain},
		{"observation", c.Owners.Observation.OwnerDomain},
		{"execution", c.Owners.Execution.OwnerDomain},
		{"application", c.Owners.Application.OwnerDomain},
		{"report", c.Owners.Report.OwnerDomain},
	} {
		if prev, dup := seenDomains[entry.domain]; dup {
			return fmt.Errorf("%w: owners %q and %q share owner_domain %q: each domain has one distinct writer", ErrInvalid, prev, entry.axis, entry.domain)
		}
		seenDomains[entry.domain] = entry.axis
	}
	if !validIdentifier(c.IdempotencyKey) {
		return fmt.Errorf("%w: commission idempotency_key must be a nonempty identifier", ErrInvalid)
	}
	if len(c.AuthorizationRefs) == 0 {
		return fmt.Errorf("%w: commission authorization_refs needs at least one reference", ErrInvalid)
	}
	for i, r := range c.AuthorizationRefs {
		if err := validateEvidenceRefShape(r, fmt.Sprintf("commission.authorization_refs[%d]", i)); err != nil {
			return err
		}
	}
	if c.RecoveryReviewRefs == nil {
		return fmt.Errorf("%w: commission recovery_review_refs is an in-band null: use an array", ErrInvalid)
	}
	for i, r := range c.RecoveryReviewRefs {
		if err := validateEvidenceRefShape(r, fmt.Sprintf("commission.recovery_review_refs[%d]", i)); err != nil {
			return err
		}
	}
	for _, dl := range []struct {
		name string
		v    DurationLimit
	}{
		{"active_limit", c.ObservationPolicy.ActiveLimit},
		{"drain_limit", c.ObservationPolicy.DrainLimit},
		{"native_cancel_wait_limit", c.ObservationPolicy.NativeCancelWaitLimit},
		{"cleanup_wait_limit", c.ObservationPolicy.CleanupWaitLimit},
	} {
		if dl.v.Kind != "exact" || dl.v.Unit != "ms" || math.IsNaN(dl.v.Value) || math.IsInf(dl.v.Value, 0) || dl.v.Value < 0 {
			return fmt.Errorf("%w: commission observation_policy %s must be an exact finite ms bound >= 0", ErrInvalid, dl.name)
		}
	}
	if c.ObservationPolicy.FixtureCloseAction != "seal_after_drain" && c.ObservationPolicy.FixtureCloseAction != "not_applicable" {
		return fmt.Errorf("%w: commission fixture_close_action %q is invalid", ErrInvalid, c.ObservationPolicy.FixtureCloseAction)
	}
	if err := validateVersionPin(c.OriginPolicy, "commission.origin_policy"); err != nil {
		return err
	}
	// Hellscape practice attempts use the laboratory close action.
	if a.TargetClass == "laboratory_fixture" && c.ObservationPolicy.FixtureCloseAction != "seal_after_drain" {
		return fmt.Errorf("%w: laboratory_fixture attempts require fixture_close_action seal_after_drain", ErrInvalid)
	}
	return nil
}

// validateLineage enforces LIFE-LINEAGE for a Hellscape practice attempt:
// performance links are empty, derivation links point only to practice
// attempts, rehearsal links may point to already commissioned production
// identities, links resolve and match kind, and no derivation cycle forms.
// Links convey lineage, never inherited commitment.
func validateLineage(a AttemptContext, admitted map[string]*storedAttempt) error {
	if a.RehearsalOf == nil || a.PerformanceOf == nil || a.DerivedFrom == nil {
		return fmt.Errorf("%w: attempt lineage arrays must not be in-band nulls: use arrays", ErrInvalid)
	}
	if len(a.PerformanceOf) != 0 {
		return fmt.Errorf("%w: performance_of links production to practice; a practice attempt must not declare performance_of", ErrInvalid)
	}
	seenDerived := map[string]bool{}
	for i, d := range a.DerivedFrom {
		where := fmt.Sprintf("attempt.derived_from[%d]", i)
		if !validIdentifier(d.AttemptID) {
			return fmt.Errorf("%w: %s attempt_id is required", ErrInvalid, where)
		}
		if d.AttemptID == a.AttemptID {
			return fmt.Errorf("%w: %s is acyclic: self-reference %q", ErrInvalid, where, d.AttemptID)
		}
		if seenDerived[d.AttemptID] {
			return fmt.Errorf("%w: %s contains duplicate identity %q", ErrInvalid, where, d.AttemptID)
		}
		seenDerived[d.AttemptID] = true
		if d.Kind != "practice" {
			return fmt.Errorf("%w: %s references only the same kind: practice attempt derives from kind %q", ErrInvalid, where, d.Kind)
		}
		stored, ok := admitted[d.AttemptID]
		if !ok {
			return fmt.Errorf("%w: %s cites unknown attempt %q: links must resolve to already commissioned attempts", ErrInvalid, where, d.AttemptID)
		}
		if stored.kind != d.Kind {
			return fmt.Errorf("%w: %s kind %q does not match commissioned kind %q", ErrInvalid, where, d.Kind, stored.kind)
		}
	}
	seenRehearsal := map[string]bool{}
	for i, r := range a.RehearsalOf {
		where := fmt.Sprintf("attempt.rehearsal_of[%d]", i)
		if !validIdentifier(r.AttemptID) {
			return fmt.Errorf("%w: %s attempt_id is required", ErrInvalid, where)
		}
		if r.AttemptID == a.AttemptID {
			return fmt.Errorf("%w: %s must reference an already commissioned production identity distinct from self", ErrInvalid, where)
		}
		if seenRehearsal[r.AttemptID] {
			return fmt.Errorf("%w: %s contains duplicate identity %q", ErrInvalid, where, r.AttemptID)
		}
		seenRehearsal[r.AttemptID] = true
		if r.Kind != "production" {
			return fmt.Errorf("%w: %s links practice to production; rehearsal kind must be production, got %q", ErrInvalid, where, r.Kind)
		}
		// Production commissions live outside the Hellscape practice
		// registry; the link is recorded as lineage only and never
		// promotes commitment or qualification.
	}
	// Cycle check over the derivation graph including the new node.
	graph := map[string][]string{}
	for id, stored := range admitted {
		for _, d := range stored.derivedFrom {
			graph[id] = append(graph[id], d.AttemptID)
		}
	}
	var newDerived []string
	for _, d := range a.DerivedFrom {
		newDerived = append(newDerived, d.AttemptID)
	}
	graph[a.AttemptID] = newDerived
	visited := map[string]bool{}
	inStack := map[string]bool{}
	var visit func(id string) bool
	visit = func(id string) bool {
		if inStack[id] {
			return true
		}
		if visited[id] {
			return false
		}
		visited[id] = true
		inStack[id] = true
		for _, next := range graph[id] {
			if visit(next) {
				return true
			}
		}
		inStack[id] = false
		return false
	}
	if visit(a.AttemptID) {
		return fmt.Errorf("%w: derived_from links form a derivation cycle", ErrInvalid)
	}
	return nil
}

func validateRegistrations(regs []EntityRegistration, m Manifest, c AttemptCommission) error {
	if len(regs) == 0 {
		return fmt.Errorf("%w: at least one entity registration is required", ErrInvalid)
	}
	for i, reg := range regs {
		where := fmt.Sprintf("registrations[%d]", i)
		if reg.RecordType != "write_domain_entity" {
			return fmt.Errorf("%w: %s record_type must be write_domain_entity, got %q", ErrInvalid, where, reg.RecordType)
		}
		if !validIdentifier(reg.RegistrationID) {
			return fmt.Errorf("%w: %s registration_id is required", ErrInvalid, where)
		}
		entityType := nestedString(reg.Entity, "entity_type")
		if entityType != "hellscape_session" && entityType != "application_attempt" {
			return fmt.Errorf("%w: %s entity_type %q is not a Hellscape session", ErrInvalid, where, entityType)
		}
		if reg.Entity == nil || reg.Identity == nil || reg.Owners == nil {
			return fmt.Errorf("%w: %s entity/identity/owners are required", ErrInvalid, where)
		}
		if kind := nestedString(reg.Identity, "attempt", "kind"); kind == "production" {
			return fmt.Errorf("%w: %s declares a production attempt: production requires an employer origin", ErrInvalid, where)
		}
		if runID := nestedString(reg.Identity, "run_id"); runID != "" && runID != m.RunID {
			return fmt.Errorf("%w: %s run_id %q does not match manifest %q", ErrInvalid, where, runID, m.RunID)
		}
		if journalID := nestedString(reg.Identity, "journal_id"); journalID != "" && journalID != m.JournalID {
			return fmt.Errorf("%w: %s journal_id %q does not match manifest %q", ErrInvalid, where, journalID, m.JournalID)
		}
		// Owner domains mentioned explicitly must be distinct.
		seenOwners := map[string]string{}
		for domain, raw := range reg.Owners {
			binding, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			ownerDomain, _ := binding["owner_domain"].(string)
			if strings.TrimSpace(ownerDomain) == "" {
				continue
			}
			if prev, dup := seenOwners[ownerDomain]; dup {
				return fmt.Errorf("%w: %s domains %q and %q share owner_domain %q", ErrInvalid, where, prev, domain, ownerDomain)
			}
			seenOwners[ownerDomain] = domain
		}
		if reg.EvidenceRefs == nil {
			return fmt.Errorf("%w: %s evidence_refs is an in-band null: use an array", ErrInvalid, where)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AdmitSession (saga steps 1-7, primary store only).
// ---------------------------------------------------------------------------

// AdmitSession authenticates and authorizes the commissioner, validates the
// complete configuration and finite limits, enforces practice/held-in
// partitioning, installs the primary manifest and required artifacts, commits
// the primary manifest admission, and registers the attempt commission and
// owner bindings.
//
// It touches only the primary store. Owner initialization happens later in
// AdvanceAdmission through separate owner-local commits.
func AdmitSession(ctx context.Context, store *OwnerStore, manifest Manifest, commission AttemptCommission, registrations []EntityRegistration) (EvidenceRef, error) {
	var zero EvidenceRef
	if store == nil {
		return zero, fmt.Errorf("%w: store is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	// Step 1: authenticate and authorize the commissioner.
	ownerDomain := strings.TrimSpace(manifest.OwnerDomain)
	if ownerDomain == "" {
		ownerDomain = "diagnostic"
	}
	resource := strings.TrimSpace(commission.Attempt.AttemptID)
	if resource == "" {
		resource = strings.TrimSpace(manifest.RunID)
	}
	if resource == "" {
		resource = strings.TrimSpace(manifest.JournalID)
	}
	if err := authority.Authorize(ctx, ownerDomain, "write", resource); err != nil {
		return zero, fmt.Errorf("%w: admit: %v", ErrUnauthorized, err)
	}

	// Basic identity presence before any durable work.
	if strings.TrimSpace(manifest.ManifestID) == "" ||
		strings.TrimSpace(manifest.RunID) == "" ||
		strings.TrimSpace(manifest.JournalID) == "" ||
		strings.TrimSpace(manifest.OwnerDomain) == "" {
		return zero, fmt.Errorf("%w: manifest must name manifest_id, run_id, journal_id, and owner_domain", ErrInvalid)
	}

	// Step 2: validate complete configuration and finite limits.
	config := []byte(nil)
	for _, reg := range registrations {
		if len(bytes.TrimSpace(reg.Configuration)) > 0 {
			config = reg.Configuration
			break
		}
	}
	if len(bytes.TrimSpace(config)) == 0 {
		config = application_owner.DefaultFixtureConfiguration()
	}
	if err := fixture_policy.ValidateFixture(manifest, config); err != nil {
		return zero, fmt.Errorf("%w: fixture gate: %v", ErrInvalid, err)
	}
	// Structural manifest gate (explicit evidence_codec use).
	{
		projection := map[string]any{
			"record_type":  "manifest",
			"schema_version": "1.0.0",
			"manifest_id":  manifest.ManifestID,
			"run_id":       manifest.RunID,
			"journal_id":   manifest.JournalID,
			"owner_domain": manifest.OwnerDomain,
		}
		if strings.TrimSpace(manifest.CommissionerID) != "" {
			projection["commissioner_id"] = manifest.CommissionerID
		}
		if strings.TrimSpace(manifest.Activity) != "" {
			projection["activity"] = manifest.Activity
		}
		raw, err := json.Marshal(projection)
		if err != nil {
			return zero, fmt.Errorf("%w: cannot encode manifest projection: %v", ErrInvalid, err)
		}
		if err := evidence_codec.ValidateRecord("1.0.0", "manifest", raw); err != nil {
			return zero, fmt.Errorf("%w: manifest structural gate: %v", ErrInvalid, err)
		}
	}

	// Step 3: practice/held-in partitioning is enforced inside
	// validateCommission and the manifest/commission agreement checks below,
	// after the full commission shape is known.
	if err := validateCommission(commission); err != nil {
		return zero, err
	}
	if err := validateRegistrations(registrations, manifest, commission); err != nil {
		return zero, err
	}

	// Manifest/commission agreement (LIFE-COMMISSION).
	if commission.RunID != manifest.RunID {
		return zero, fmt.Errorf("%w: commission run_id %q does not agree with admitted manifest %q", ErrInvalid, commission.RunID, manifest.RunID)
	}
	if commission.JournalID != manifest.JournalID {
		return zero, fmt.Errorf("%w: commission journal_id %q does not agree with admitted manifest %q", ErrInvalid, commission.JournalID, manifest.JournalID)
	}
	if commission.Attempt.AttemptID != manifest.RunID {
		return zero, fmt.Errorf("%w: commission attempt_id %q does not agree with admitted run %q", ErrInvalid, commission.Attempt.AttemptID, manifest.RunID)
	}
	if commission.AdmissionRef.JournalID != manifest.JournalID {
		return zero, fmt.Errorf("%w: commission admission_ref journal %q does not agree with admitted manifest %q", ErrInvalid, commission.AdmissionRef.JournalID, manifest.JournalID)
	}
	expectedManifestHash, err := PrimaryManifestDigest(manifest)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot digest primary manifest: %v", ErrInvalid, err)
	}
	if commission.ManifestHash != expectedManifestHash {
		return zero, fmt.Errorf("%w: commission manifest_hash does not agree with the admitted primary manifest", ErrInvalid)
	}

	// Lineage validation against already admitted attempts (snapshot the
	// registry; no durable work has happened yet).
	registryMu.Lock()
	admittedSnapshot := make(map[string]*storedAttempt, len(byAttempt))
	for id, stored := range byAttempt {
		admittedSnapshot[id] = stored
	}
	registryMu.Unlock()
	if err := validateLineage(commission.Attempt, admittedSnapshot); err != nil {
		return zero, err
	}

	// Idempotency and immutability checks before any durable work.
	reqHash, err := requestHash(commission)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot hash attempt request: %v", ErrInvalid, err)
	}
	registryMu.Lock()
	if prior, ok := byKey[commission.IdempotencyKey]; ok {
		if prior.requestHash == reqHash && prior.attemptID == commission.Attempt.AttemptID {
			ref := prior.ref
			registryMu.Unlock()
			return ref, nil
		}
		registryMu.Unlock()
		return zero, fmt.Errorf("%w: idempotency key %q already binds a different attempt request", ErrConflict, commission.IdempotencyKey)
	}
	if prior, ok := byAttempt[commission.Attempt.AttemptID]; ok {
		subjectVersion := extractSubjectVersion(commission.Execution)
		mismatch := prior.kind != commission.Attempt.Kind ||
			prior.targetClass != commission.Attempt.TargetClass ||
			prior.targetID != commission.Attempt.TargetID ||
			prior.partition != commission.Attempt.EvaluationPartition ||
			prior.subjectVersion != subjectVersion ||
			prior.taskDigest != commission.Task.Digest ||
			prior.taskSemantic != commission.TaskSemanticHash ||
			prior.ownersHash != ownersFingerprint(commission.Owners)
		if mismatch {
			registryMu.Unlock()
			return zero, fmt.Errorf("%w: attempt %q already commissions a different subject version, target, kind, task, or permissions", ErrNeedsNewAttempt, commission.Attempt.AttemptID)
		}
		// Same immutable content under a new key: return the original
		// admission rather than fabricating a second session.
		ref := prior.commissionRef
		registryMu.Unlock()
		return ref, nil
	}
	registryMu.Unlock()

	// Steps 4-5: install primary manifest and required artifacts, then
	// commit the primary manifest admission. Each InstallArtifact and the
	// single CommitOwner below touches only the primary store.
	minimal := MinimalPrimaryManifest(manifest)
	rawMinimal, err := json.Marshal(minimal)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot encode primary manifest: %v", ErrInvalid, err)
	}
	canonicalMinimal, err := evidence_codec.CanonicalJSON(rawMinimal, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize primary manifest: %v", ErrInvalid, err)
	}
	minimalRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalMinimal), "application/json", "public")
	if err != nil {
		return zero, fmt.Errorf("admission: install primary manifest: %w", err)
	}
	// Required inputs: fixture manifest, commission, and registrations.
	rawFixture, err := json.Marshal(manifest)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot encode fixture manifest: %v", ErrInvalid, err)
	}
	canonicalFixture, err := evidence_codec.CanonicalJSON(rawFixture, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize fixture manifest: %v", ErrInvalid, err)
	}
	fixtureRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalFixture), "application/json", "public")
	if err != nil {
		return zero, fmt.Errorf("admission: install fixture manifest: %w", err)
	}
	rawCommission, err := json.Marshal(commission)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot encode commission: %v", ErrInvalid, err)
	}
	canonicalCommission, err := evidence_codec.CanonicalJSON(rawCommission, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize commission: %v", ErrInvalid, err)
	}
	commissionRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalCommission), "application/json", "restricted")
	if err != nil {
		return zero, fmt.Errorf("admission: install commission: %w", err)
	}
	rawRegs, err := json.Marshal(registrations)
	if err != nil {
		return zero, fmt.Errorf("%w: cannot encode registrations: %v", ErrInvalid, err)
	}
	canonicalRegs, err := evidence_codec.CanonicalJSON(rawRegs, "application/json")
	if err != nil {
		return zero, fmt.Errorf("%w: cannot canonicalize registrations: %v", ErrInvalid, err)
	}
	regsRef, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonicalRegs), "application/json", "restricted")
	if err != nil {
		return zero, fmt.Errorf("admission: install registrations: %w", err)
	}

	clock := minimal.Clocks[0]
	admissionEvent := EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          eventManifestAdmitted,
		EventSchemaVersion: "0.1.0",
		OccurredAt: TimePoint{
			ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
			MonotonicOffsetMs: 0, UTCAnnotation: NewMissing("not_applicable"),
		},
		Payload: owner_store.Payload{
			Data:         map[string]any{"manifest": artifactRefMap(minimalRef)},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{minimalRef},
		},
	}
	var derivedIDs, rehearsalIDs []string
	for _, d := range commission.Attempt.DerivedFrom {
		derivedIDs = append(derivedIDs, d.AttemptID)
	}
	for _, r := range commission.Attempt.RehearsalOf {
		rehearsalIDs = append(rehearsalIDs, r.AttemptID)
	}
	if derivedIDs == nil {
		derivedIDs = []string{}
	}
	if rehearsalIDs == nil {
		rehearsalIDs = []string{}
	}
	var registrationIDs []string
	for _, reg := range registrations {
		registrationIDs = append(registrationIDs, reg.RegistrationID)
	}
	sessionEvent := EventSubmission{
		ProducerSequence:   int64(2),
		EventKind:          eventSessionAdmitted,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id":          commission.Attempt.AttemptID,
				"attempt_id":          commission.Attempt.AttemptID,
				"manifest_id":         manifest.ManifestID,
				"run_id":              manifest.RunID,
				"journal_id":          manifest.JournalID,
				"commission_id":       commission.CommissionID,
				"commission_digest":   commissionRef.Digest,
				"manifest_digest":     minimalRef.Digest,
				"fixture_digest":      fixtureRef.Digest,
				"registrations_digest": regsRef.Digest,
				"kind":                commission.Attempt.Kind,
				"target_class":        commission.Attempt.TargetClass,
				"target_id":           commission.Attempt.TargetID,
				"evaluation_partition": commission.Attempt.EvaluationPartition,
				"execution_mode":      commission.Execution.Mode,
				"subject_version":     extractSubjectVersion(commission.Execution),
				"task_digest":         commission.Task.Digest,
				"task_semantic_hash": commission.TaskSemanticHash,
				"idempotency_key":     commission.IdempotencyKey,
				"registration_ids":    registrationIDs,
				"derived_from":        derivedIDs,
				"rehearsal_of":        rehearsalIDs,
				"lineage_note":        "lineage links only; no inherited commitment or qualification",
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{fixtureRef, commissionRef, regsRef},
		},
	}
	// One primary-local atomic commit. The effect is nil: no peer-owned
	// write lock is acquired and no peer transaction is awaited.
	envelopes, err := owner_store.CommitOwner(ctx, store, manifest.JournalID, []EventSubmission{admissionEvent, sessionEvent}, nil)
	if err != nil {
		return zero, fmt.Errorf("admission: commit primary admission: %w", err)
	}
	if len(envelopes) != 2 {
		return zero, fmt.Errorf("%w: admission committed %d events, want 2", ErrInvalid, len(envelopes))
	}
	admEnv := envelopes[1]
	admissionRef := EvidenceRef{JournalID: admEnv.JournalID, Sequence: admEnv.Sequence, EventID: admEnv.EventID, EventHash: admEnv.EventHash, Pointer: ""}
	prefix := JournalPrefix{JournalID: manifest.JournalID, LastSequence: admEnv.Sequence, HeadHash: admEnv.EventHash}

	// Steps 6-7: register the commission (with the actual admission event)
	// and the owner bindings. The stored commission is immutable from here.
	registered := commission
	registered.AdmissionRef = admissionRef
	registeredCopy := registered
	snapshot := &storedAttempt{
		attemptID:      commission.Attempt.AttemptID,
		kind:           commission.Attempt.Kind,
		targetClass:    commission.Attempt.TargetClass,
		targetID:       commission.Attempt.TargetID,
		partition:      commission.Attempt.EvaluationPartition,
		subjectVersion: extractSubjectVersion(commission.Execution),
		taskDigest:     commission.Task.Digest,
		taskSemantic:   commission.TaskSemanticHash,
		ownersHash:     ownersFingerprint(commission.Owners),
		commissionID:   commission.CommissionID,
		manifestHash:   commission.ManifestHash,
		commissionRef:  admissionRef,
		derivedFrom:    append([]AttemptReference(nil), commission.Attempt.DerivedFrom...),
		rehearsalOf:    append([]AttemptReference(nil), commission.Attempt.RehearsalOf...),
		performanceOf:  append([]AttemptReference(nil), commission.Attempt.PerformanceOf...),
		commissionCopy: registeredCopy,
	}
	registryMu.Lock()
	byAttempt[commission.Attempt.AttemptID] = snapshot
	byKey[commission.IdempotencyKey] = &storedKey{attemptID: commission.Attempt.AttemptID, requestHash: reqHash, ref: admissionRef}
	registryMu.Unlock()

	rec := &sessionRecord{
		sessionID:        commission.Attempt.AttemptID,
		journalID:        manifest.JournalID,
		runID:            manifest.RunID,
		manifest:         manifest,
		commission:       registered,
		registrations:    append([]EntityRegistration(nil), registrations...),
		config:           append([]byte(nil), config...),
		manifestRef:      minimalRef,
		fixtureRef:       fixtureRef,
		commissionRef:    commissionRef,
		registrationsRef: regsRef,
		admissionRef:     admissionRef,
		admissionPrefix:  prefix,
		headSequence:     admEnv.Sequence,
		headHash:         admEnv.EventHash,
	}
	storeSession(store, rec)
	return admissionRef, nil
}

// ---------------------------------------------------------------------------
// AdvanceAdmission (saga steps 8-10).
// ---------------------------------------------------------------------------

// discoverStoreDomain learns a store's owner domain through one owner-local
// artifact installation. It touches only the given store.
func discoverStoreDomain(ctx context.Context, store *OwnerStore) (string, error) {
	if store == nil {
		return "", fmt.Errorf("%w: store is required", ErrInvalid)
	}
	probe := []byte(`{"probe":"admission-domain"}`)
	canonical, err := evidence_codec.CanonicalJSON(probe, "application/json")
	if err != nil {
		return "", err
	}
	ref, err := owner_store.InstallArtifact(ctx, store, bytes.NewReader(canonical), "application/json", "public")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(ref.OwnerDomain) == "" {
		return "", fmt.Errorf("%w: store names no owner domain", ErrInvalid)
	}
	return ref.OwnerDomain, nil
}

func toApplicationRegistration(reg EntityRegistration, config []byte) application_owner.EntityRegistration {
	evidenceRefs := make([]application_owner.EvidenceRef, 0, len(reg.EvidenceRefs))
	for _, r := range reg.EvidenceRefs {
		evidenceRefs = append(evidenceRefs, application_owner.EvidenceRef{
			JournalID: r.JournalID, Sequence: r.Sequence, EventID: r.EventID, EventHash: r.EventHash, Pointer: r.Pointer,
		})
	}
	return application_owner.EntityRegistration{
		RecordType:     reg.RecordType,
		SchemaVersion:  reg.SchemaVersion,
		RegistrationID: reg.RegistrationID,
		Entity:         reg.Entity,
		Identity:       reg.Identity,
		Owners:         reg.Owners,
		EvidencePrefix: application_owner.JournalPrefix{
			JournalID: reg.EvidencePrefix.JournalID, LastSequence: reg.EvidencePrefix.LastSequence, HeadHash: reg.EvidencePrefix.HeadHash,
		},
		EvidenceRefs:  evidenceRefs,
		Configuration: append([]byte(nil), config...),
	}
}

func toObservationRegistration(reg EntityRegistration) observation_owner.EntityRegistration {
	evidenceRefs := make([]observation_owner.EvidenceRef, 0, len(reg.EvidenceRefs))
	for _, r := range reg.EvidenceRefs {
		evidenceRefs = append(evidenceRefs, observation_owner.EvidenceRef{
			JournalID: r.JournalID, Sequence: r.Sequence, EventID: r.EventID, EventHash: r.EventHash, Pointer: r.Pointer,
		})
	}
	return observation_owner.EntityRegistration{
		RecordType:     reg.RecordType,
		SchemaVersion:  reg.SchemaVersion,
		RegistrationID: reg.RegistrationID,
		Entity:         reg.Entity,
		Identity:       reg.Identity,
		Owners:         reg.Owners,
		EvidencePrefix: observation_owner.JournalPrefix{
			JournalID: reg.EvidencePrefix.JournalID, LastSequence: reg.EvidencePrefix.LastSequence, HeadHash: reg.EvidencePrefix.HeadHash,
		},
		EvidenceRefs: evidenceRefs,
	}
}

func cloneIdentityWithJournal(identity map[string]any, runID, journalID string) map[string]any {
	out := map[string]any{}
	for k, v := range identity {
		out[k] = v
	}
	if runID != "" {
		out["run_id"] = runID
	}
	if journalID != "" {
		out["journal_id"] = journalID
	}
	return out
}

// AdvanceAdmission asynchronously initializes the application and observation
// owners, records their initialization receipts, and makes the entry usable.
// Subject preparation is permitted only after required initialization.
//
// Each step is an independent owner-local commit: application and observation
// initialization touch only their own stores, and receipt/usable markers
// touch only the primary store. A later initialization failure never rolls
// back the durable primary admission.
func AdvanceAdmission(ctx context.Context, primary *OwnerStore, application *OwnerStore, observation *OwnerStore, sessionID string) error {
	if primary == nil || application == nil || observation == nil {
		return fmt.Errorf("%w: primary, application, and observation stores are required", ErrInvalid)
	}
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("%w: session_id is required", ErrInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rec, ok := lookupSession(primary, sessionID)
	if !ok {
		return fmt.Errorf("%w: session %q", ErrNotAdmitted, sessionID)
	}
	registryMu.Lock()
	if rec.usable {
		registryMu.Unlock()
		return nil
	}
	registryMu.Unlock()

	// The commissioner must still be authorized for the primary domain.
	if err := authority.Authorize(ctx, strings.TrimSpace(rec.manifest.OwnerDomain), "write", rec.sessionID); err != nil {
		return fmt.Errorf("%w: advance: %v", ErrUnauthorized, err)
	}

	// A durably admitted session keeps its diagnostic even if later
	// initialization fails: prove the primary admission is still readable
	// before attempting any peer work.
	if _, err := owner_store.LoadPrefix(ctx, primary, rec.admissionPrefix); err != nil {
		return fmt.Errorf("admission: primary admission is not durable: %w", err)
	}
	if _, err := owner_store.ReadArtifact(ctx, primary, rec.manifestRef); err != nil {
		return fmt.Errorf("admission: primary manifest bytes are not durable: %w", err)
	}

	// Step 8: initialize the application owner (owner-local only).
	appDomain, err := discoverStoreDomain(ctx, application)
	if err != nil {
		return fmt.Errorf("%w: application initialization: learn domain: %v", ErrNotReady, err)
	}
	appManifest := rec.manifest
	appManifest.OwnerDomain = appDomain
	appRegSource := rec.registrations[0]
	appRegSource.Identity = cloneIdentityWithJournal(appRegSource.Identity, appManifest.RunID, appManifest.JournalID)
	appReg := toApplicationRegistration(appRegSource, rec.config)
	appInitRef, err := application_owner.InitializeApplication(ctx, application, appManifest, appReg)
	if err != nil {
		return fmt.Errorf("%w: application initialization: %v", ErrNotReady, err)
	}

	// Step 8 continued: initialize the observation owner (owner-local only,
	// after the application commit has fully returned).
	obsDomain, err := discoverStoreDomain(ctx, observation)
	if err != nil {
		return fmt.Errorf("%w: observation initialization: learn domain: %v", ErrNotReady, err)
	}
	obsManifest := observation_owner.Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + rec.journalID,
		RunID:         rec.manifest.RunID,
		JournalID:     rec.journalID,
		OwnerDomain:   obsDomain,
		Clocks: []observation_owner.ClockDescriptor{{
			ClockID: "clock-" + rec.journalID, BootID: "boot-" + rec.journalID,
			Origin: "engine_measured", SourceID: "admission",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
	obsRegSource := rec.registrations[0]
	obsRegSource.Identity = cloneIdentityWithJournal(obsRegSource.Identity, obsManifest.RunID, obsManifest.JournalID)
	obsReg := toObservationRegistration(obsRegSource)
	obsInitRef, err := observation_owner.InitializeObservation(ctx, observation, obsManifest, obsReg)
	if err != nil {
		return fmt.Errorf("%w: observation initialization: %v", ErrNotReady, err)
	}

	// Step 9: record initialization receipts in the primary journal through
	// separate primary-local commits. Cross-journal coordinates ride under
	// renamed keys so they are retained as receipt data, never as embedded
	// same-journal evidence references (which must all agree).
	registryMu.Lock()
	nextSequence := rec.headSequence + 1
	registryMu.Unlock()
	appReceiptSubmission := EventSubmission{
		ProducerSequence:   nextSequence,
		EventKind:          eventAppReceipt,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id":            rec.sessionID,
				"attempt_id":            rec.sessionID,
				"receipt_journal":       appInitRef.JournalID,
				"receipt_sequence":      appInitRef.Sequence,
				"receipt_event":         appInitRef.EventID,
				"receipt_hash":          appInitRef.EventHash,
				"receipt_kind":          "application_initialized",
				"initialization_receipt": true,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{rec.admissionRef},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	appEnvelopes, err := owner_store.CommitOwner(ctx, primary, rec.journalID, []EventSubmission{appReceiptSubmission}, nil)
	if err != nil {
		return fmt.Errorf("admission: record application receipt: %w", err)
	}
	appLocalRef := EvidenceRef{JournalID: appEnvelopes[0].JournalID, Sequence: appEnvelopes[0].Sequence, EventID: appEnvelopes[0].EventID, EventHash: appEnvelopes[0].EventHash, Pointer: ""}
	registryMu.Lock()
	rec.headSequence = appEnvelopes[0].Sequence
	rec.headHash = appEnvelopes[0].EventHash
	registryMu.Unlock()

	registryMu.Lock()
	nextSequence = rec.headSequence + 1
	registryMu.Unlock()
	obsReceiptSubmission := EventSubmission{
		ProducerSequence:   nextSequence,
		EventKind:          eventObsReceipt,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id":            rec.sessionID,
				"attempt_id":            rec.sessionID,
				"receipt_journal":       obsInitRef.JournalID,
				"receipt_sequence":      obsInitRef.Sequence,
				"receipt_event":         obsInitRef.EventID,
				"receipt_hash":          obsInitRef.EventHash,
				"receipt_kind":          "observation_opened",
				"initialization_receipt": true,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{rec.admissionRef},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	obsEnvelopes, err := owner_store.CommitOwner(ctx, primary, rec.journalID, []EventSubmission{obsReceiptSubmission}, nil)
	if err != nil {
		return fmt.Errorf("admission: record observation receipt: %w", err)
	}
	obsLocalRef := EvidenceRef{JournalID: obsEnvelopes[0].JournalID, Sequence: obsEnvelopes[0].Sequence, EventID: obsEnvelopes[0].EventID, EventHash: obsEnvelopes[0].EventHash, Pointer: ""}
	registryMu.Lock()
	rec.headSequence = obsEnvelopes[0].Sequence
	rec.headHash = obsEnvelopes[0].EventHash
	registryMu.Unlock()

	// Step 10: make the entry usable only after both required receipts are
	// durable. This is a third primary-local commit citing both receipts.
	registryMu.Lock()
	nextSequence = rec.headSequence + 1
	registryMu.Unlock()
	usableSubmission := EventSubmission{
		ProducerSequence:   nextSequence,
		EventKind:          eventEntryUsable,
		EventSchemaVersion: "1.0.0",
		OccurredAt:         NewMissing("not_observed"),
		Payload: owner_store.Payload{
			Data: map[string]any{
				"session_id":            rec.sessionID,
				"attempt_id":            rec.sessionID,
				"entry_usable":          true,
				"preparation_permitted": true,
				"execution_mode":        rec.commission.Execution.Mode,
			},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{appLocalRef, obsLocalRef},
			ArtifactRefs: []ArtifactReference{},
		},
	}
	usableEnvelopes, err := owner_store.CommitOwner(ctx, primary, rec.journalID, []EventSubmission{usableSubmission}, nil)
	if err != nil {
		return fmt.Errorf("admission: mark entry usable: %w", err)
	}
	usableRef := EvidenceRef{JournalID: usableEnvelopes[0].JournalID, Sequence: usableEnvelopes[0].Sequence, EventID: usableEnvelopes[0].EventID, EventHash: usableEnvelopes[0].EventHash, Pointer: ""}

	// Seal the session_admitted row over the primary view. The seal cites
	// the durable admission prefix; unpublished domain slots stay at
	// revision zero with Missing.
	sealPrefix := JournalPrefix{JournalID: rec.journalID, LastSequence: usableEnvelopes[0].Sequence, HeadHash: usableEnvelopes[0].EventHash}
	pubReg := publication.EntityRegistration{
		RecordType:     "write_domain_entity",
		SchemaVersion:  "owner-separated-write-domains/0.1.0",
		RegistrationID: "registration-" + rec.sessionID,
		Entity: map[string]any{
			"entity_type": "hellscape_session",
			"session_id":  rec.sessionID,
		},
		Identity: map[string]any{
			"run_id":     rec.runID,
			"journal_id": rec.journalID,
			"attempt": map[string]any{
				"kind": "practice", "target_class": "laboratory_fixture",
				"evaluation_partition": "held_in",
			},
		},
		Owners: map[string]any{
			"application": map[string]any{
				"role": "origin", "source_id": rec.commission.Attempt.TargetID,
				"writer_id": "app-writer-" + rec.sessionID, "owner_domain": "application",
				"publication_policy": map[string]any{"id": "pub", "version": "1.0", "artifact_digest": "sha256:" + strings.Repeat("0", 64)},
			},
			"observation": map[string]any{
				"role": "observer", "source_id": "obs-source-" + rec.sessionID,
				"writer_id": "obs-writer-" + rec.sessionID, "owner_domain": "observation",
				"publication_policy": map[string]any{"id": "pub", "version": "1.0", "artifact_digest": "sha256:" + strings.Repeat("1", 64)},
			},
			"diagnostic": map[string]any{
				"role": "analyzer", "source_id": "diag-source-" + rec.sessionID,
				"writer_id": "diag-writer-" + rec.sessionID, "owner_domain": "diagnostic",
				"publication_policy": map[string]any{"id": "pub", "version": "1.0", "artifact_digest": "sha256:" + strings.Repeat("2", 64)},
			},
		},
		EvidencePrefix: publication.JournalPrefix{JournalID: sealPrefix.JournalID, LastSequence: sealPrefix.LastSequence, HeadHash: sealPrefix.HeadHash},
		EvidenceRefs: []publication.EvidenceRef{
			{JournalID: rec.admissionRef.JournalID, Sequence: rec.admissionRef.Sequence, EventID: rec.admissionRef.EventID, EventHash: rec.admissionRef.EventHash, Pointer: ""},
			{JournalID: usableRef.JournalID, Sequence: usableRef.Sequence, EventID: usableRef.EventID, EventHash: usableRef.EventHash, Pointer: ""},
		},
	}
	if _, err := publication.SealRow(ctx, primary, pubReg, "session_admitted", "primary-"+rec.sessionID); err != nil {
		return fmt.Errorf("admission: seal session row: %w", err)
	}

	registryMu.Lock()
	appPeer := EvidenceRef{JournalID: appInitRef.JournalID, Sequence: appInitRef.Sequence, EventID: appInitRef.EventID, EventHash: appInitRef.EventHash, Pointer: appInitRef.Pointer}
	obsPeer := EvidenceRef{JournalID: obsInitRef.JournalID, Sequence: obsInitRef.Sequence, EventID: obsInitRef.EventID, EventHash: obsInitRef.EventHash, Pointer: obsInitRef.Pointer}
	rec.appReceipt = &appPeer
	rec.obsReceipt = &obsPeer
	rec.appReceiptRef = &appLocalRef
	rec.obsReceiptRef = &obsLocalRef
	rec.usableRef = &usableRef
	rec.usable = true
	rec.headSequence = usableEnvelopes[0].Sequence
	rec.headHash = usableEnvelopes[0].EventHash
	registryMu.Unlock()
	return nil
}
