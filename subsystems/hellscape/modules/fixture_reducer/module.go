// Package fixture_reducer implements the tier-2 Hellscape application reducer.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 6.1 (attempt
// binding and common mutation semantics), 6.3 (eight-state transition
// table), 6.4 (revision and validation rules), and 6.5 (submission checks),
// plus the OWD-SESSION reducer-ownership boundary.
//
// The reducer is pure and deterministic: it reads no wall time, generates no
// unrecorded randomness, and performs no database, network, or filesystem
// effects. Durable installation of artifact bytes and owner-local atomic
// commit are the application owner's responsibility; the reducer computes the
// next state, the journal-bound business events, and the replayable
// response for one admitted command.
//
// Processing order (seam 6.1):
//
//  1. Authenticate and authorize the attempt (opaque binding, not a global
//     session cookie).
//  2. Resolve operation identity (idempotency key).
//  3. Return the stored response for identical key/digest (no new effect,
//     including after authority sealing).
//  4. Reject changed content under an existing key (key conflict, no new
//     effect, not journaled: the key is already bound).
//  5. Check authority, revisions, generation, and business guards.
//  6. Commit accepted effect or durable rejection (revision advance, journal
//     append, operation-response ledger store).
//  7. The owner acknowledges after commit.
//
// Every new key that passes steps 1-4 commits durably (revision + 1, journal
// append, ledger store) whether accepted, resolved, or rejected. Rejected
// attempts remain in the journal. Only identical replays, key conflicts, and
// malformed inputs (bad state, manifest/configuration mismatch, unknown
// operation, attempt mismatch) leave state untouched.
//
// Error convention: malformed inputs and key conflicts return a Go error
// with the input state bytes unchanged, no events, and no response.
// Business rejections (stale revision/generation, invalid payload,
// missing/stale prerequisites, sealed authority, second-commitment
// violations) return a new state, one rejection event, a structured
// rejection response, and a nil error, so the owner commits the rejection
// exactly like an acceptance.
//
// State, responses, and digests are canonicalized with
// evidence_codec.CanonicalJSON. Request digests cover operation kind,
// attempt identity, payload, and applicable revision/generation references;
// transport credentials and ingress metadata are excluded. Manifest and
// configuration admission is delegated to fixture_policy.ValidateFixture.
//
// Note on evidence_codec.ValidateRecord: its tier-0 closed shapes cover only
// manifest, journal_event, diagnostic, replay_receipt, lease_record, and
// capability_descriptor records. Reducer snapshots, commands, and responses
// are not durable EK records in those shapes, so the reducer enforces the
// EK null discipline locally (no bare nulls; reasoned Missing envelopes
// tolerated in admitted payload objects) instead of gating on
// ValidateRecord. This mirrors the diagnostic_render precedent.
package fixture_reducer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"evidence_codec"
	"fixture_policy"
)

// Manifest is the admitted laboratory manifest projection. It aliases the
// fixture_policy gate type so the reducer and the gate agree byte for byte.
type Manifest = fixture_policy.Manifest

// Workflow states (seam 6.3).
const (
	StateListing      = "LISTING"
	StateDetail       = "DETAIL"
	StateContact      = "CONTACT"
	StateHistory      = "HISTORY"
	StateUpload       = "UPLOAD"
	StateIdentity     = "IDENTITY"
	StateReview       = "REVIEW"
	StateConfirmation = "CONFIRMATION"
)

// Operation kinds (normalized admitted commands, seam 6.1/6.2).
const (
	OpJobSelection   = "job-selection"
	OpContact        = "contact"
	OpHistoryEnter   = "history-enter"
	OpHistory        = "history"
	OpUpload         = "upload"
	OpIdentityVerify = "identity-verify"
	OpReviewValidate = "review-validate"
	OpSubmit         = "submit"
	OpSeal           = "seal"
)

// Mutation authority values (seam 6.6).
const (
	AuthorityOpen   = "open"
	AuthoritySealed = "sealed"
)

// Outcomes recorded in the journal and returned in responses.
const (
	OutcomeAccepted         = "accepted"
	OutcomeCommitted        = "committed"
	OutcomeResolvedExisting = "resolved_existing"
	OutcomeRejected         = "rejected"
)

// Journal event categories emitted by the reducer (seam 7.3 vocabulary).
const (
	EventValidationAccepted  = "validation_accepted"
	EventValidationRejected  = "validation_rejected"
	EventWorkflowTransition  = "workflow_transition"
	EventUploadStored        = "upload_stored"
	EventIdentityVerified    = "identity_verified"
	EventSubmissionCommitted = "submission_committed"
	EventRequestCompleted    = "request_completed"
	EventRequestRejected     = "request_rejected"
	EventFixtureSeal         = "fixture_seal"
)

// EventSubmission is the normalized admitted application command (seam 6.1)
// and, on output, the journal-bound business event envelope. Untrusted
// callers submit commands; the reducer emits events for the owner to commit.
//
// Every mutation carries operation identity, expected state revision,
// applicable section value revision, applicable validation generation, an
// endpoint-specific validated payload, and a server-computed canonical
// request digest (returned in the response, never trusted from the caller).
// Inapplicable section coordinates are explicitly represented by the
// Applicable flags set to false with no values; contact and history are the
// only commands with applicable coordinates in this M1 reducer.
type EventSubmission struct {
	OperationKey                   string          `json:"operation_key"`
	OperationKind                  string          `json:"operation_kind"`
	AttemptID                      string          `json:"attempt_id"`
	ExpectedRevision               int             `json:"expected_revision"`
	Section                        string          `json:"section,omitempty"`
	SectionValueRevision           *int            `json:"section_value_revision,omitempty"`
	SectionValueRevisionApplicable bool            `json:"section_value_revision_applicable"`
	ValidationGeneration           *int            `json:"validation_generation,omitempty"`
	ValidationGenerationApplicable bool            `json:"validation_generation_applicable"`
	Payload                        json.RawMessage `json:"payload,omitempty"`
	// Output-only journal coordinates, ignored on input and excluded from
	// the request digest.
	ProducerSequence   int    `json:"producer_sequence,omitempty"`
	EventKind          string `json:"event_kind,omitempty"`
	EventSchemaVersion string `json:"event_schema_version,omitempty"`
}

// sectionAcceptance is one current section acceptance: section, value
// revision, validation generation, accepted-data artifact, and support
// (seam 6.6). The complete schema-validated value object is preserved
// verbatim in Data; no undocumented native fields are invented.
type sectionAcceptance struct {
	Section              string          `json:"section"`
	ValueRevision        int             `json:"value_revision"`
	ValidationGeneration int             `json:"validation_generation"`
	DataDigest           string          `json:"data_digest"`
	Data                 json.RawMessage `json:"data"`
	Support              string          `json:"support"`
}

// reviewAcceptance pins the exact prerequisite revisions the review
// validated. The review is current only while all pins match.
type reviewAcceptance struct {
	ValueRevision        int    `json:"value_revision"`
	ValidationGeneration int    `json:"validation_generation"`
	ContactValueRevision int    `json:"contact_value_revision"`
	ContactGeneration    int    `json:"contact_generation"`
	HistoryValueRevision int    `json:"history_value_revision"`
	HistoryGeneration    int    `json:"history_generation"`
	Support              string `json:"support"`
}

// uploadAcceptance records the accepted document metadata and digest. Byte
// installation and digest re-verification are the owner's commit path; the
// reducer records the validated reference.
type uploadAcceptance struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	Digest      string `json:"digest"`
	Support     string `json:"support"`
}

// identityAcceptance records the verified local attempt/epoch receipt.
// Token possession alone never verifies.
type identityAcceptance struct {
	Epoch     string `json:"epoch"`
	Receipt   string `json:"receipt"`
	AttemptID string `json:"attempt_id"`
	Verified  bool   `json:"verified"`
	Support   string `json:"support"`
}

// commitment is the single immutable fixture submission (seam 6.6).
// CommittedAt is a logical journal coordinate, never wall time.
type commitment struct {
	ApplicationID string `json:"application_id"`
	OperationKey  string `json:"operation_key"`
	RequestDigest string `json:"request_digest"`
	Receipt       string `json:"receipt"`
	CommittedAt   string `json:"committed_at"`
	CommitRef     string `json:"commit_ref"`
}

// operationRecord binds one idempotency key to its canonical digest and
// exact stored response for replay.
type operationRecord struct {
	Digest   string          `json:"digest"`
	Response json.RawMessage `json:"response"`
}

// journalEntry retains one committed attempt, accepted or rejected. The
// journal is append-only; nothing is erased.
type journalEntry struct {
	Sequence       int    `json:"sequence"`
	OperationKey   string `json:"operation_key"`
	OperationKind  string `json:"operation_kind"`
	Digest         string `json:"digest"`
	Outcome        string `json:"outcome"`
	Reason         string `json:"reason,omitempty"`
	RevisionBefore int    `json:"revision_before"`
	RevisionAfter  int    `json:"revision_after"`
	WorkflowBefore string `json:"workflow_before"`
	WorkflowAfter  string `json:"workflow_after"`
	Detail         string `json:"detail,omitempty"`
}

// fixtureState is the authoritative reducer snapshot. Absent sections are
// omitted, never bare nulls. Operations and Journal are always present
// (possibly empty) so round-trips never produce null.
type fixtureState struct {
	ManifestID         string                     `json:"manifest_id"`
	AttemptID          string                     `json:"attempt_id"`
	WorkflowState      string                     `json:"workflow_state"`
	StateRevision      int                        `json:"state_revision"`
	MutationAuthority  string                     `json:"mutation_authority"`
	AuthoritySealRef   string                     `json:"authority_seal_ref,omitempty"`
	IdentityEpoch      string                     `json:"identity_epoch"`
	KnownJobs          []string                   `json:"known_jobs"`
	ReviewDependencies []string                   `json:"review_dependencies,omitempty"`
	UploadMaxBytes     int64                      `json:"upload_max_bytes"`
	UploadAllowedTypes []string                   `json:"upload_allowed_types,omitempty"`
	SelectedJob        string                     `json:"selected_job,omitempty"`
	Contact            *sectionAcceptance         `json:"contact,omitempty"`
	History            *sectionAcceptance         `json:"history,omitempty"`
	Upload             *uploadAcceptance          `json:"upload,omitempty"`
	Identity           *identityAcceptance        `json:"identity,omitempty"`
	Review             *reviewAcceptance          `json:"review,omitempty"`
	Submission         *commitment                `json:"submission,omitempty"`
	Operations         map[string]operationRecord `json:"operations"`
	Journal            []journalEntry             `json:"journal"`
}

// reducerResponse is the replayable structured response for one command.
type reducerResponse struct {
	Status            string      `json:"status"`
	OperationKey      string      `json:"operation_key"`
	OperationKind     string      `json:"operation_kind"`
	RequestDigest     string      `json:"request_digest"`
	StateRevision     int         `json:"state_revision"`
	WorkflowState     string      `json:"workflow_state"`
	Reason            string      `json:"reason,omitempty"`
	ReasonDetail      string      `json:"reason_detail,omitempty"`
	Commitment        *commitment `json:"commitment,omitempty"`
	InvalidatedReview bool        `json:"invalidated_review,omitempty"`
}

// reducerPolicy is the pinned fixture semantics extracted from the
// effective configuration: validation dependency policy, identity epoch
// policy, known synthetic jobs, and upload bounds (seam 5.2/6.4).
type reducerPolicy struct {
	IdentityEpoch      string
	KnownJobs          []string
	ReviewDependencies []string
	UploadMaxBytes     int64
	UploadAllowedTypes []string
}

// nullReasons are the six EK NullReason values tolerated inside Missing
// envelopes in admitted payload objects.
var nullReasons = map[string]bool{
	"not_enabled":            true,
	"not_applicable":         true,
	"not_observed":           true,
	"observation_lost":       true,
	"unsupported_by_subject": true,
	"manual_override":        true,
}

// InitialFixtureState validates the manifest and configuration through the
// fixture policy gate and returns the canonical initial snapshot: LISTING,
// revision 0, open authority, no sections, no commitment, empty
// operation-response ledger and journal.
func InitialFixtureState(manifest Manifest, configuration []byte) ([]byte, error) {
	if err := fixture_policy.ValidateFixture(manifest, configuration); err != nil {
		return nil, fmt.Errorf("fixture_reducer: fixture policy rejects manifest/configuration: %w", err)
	}
	policy, err := parseReducerPolicy(configuration)
	if err != nil {
		return nil, err
	}
	st := fixtureState{
		ManifestID:         manifest.ManifestID,
		AttemptID:          manifest.RunID,
		WorkflowState:      StateListing,
		StateRevision:      0,
		MutationAuthority:  AuthorityOpen,
		IdentityEpoch:      policy.IdentityEpoch,
		KnownJobs:          policy.KnownJobs,
		ReviewDependencies: policy.ReviewDependencies,
		UploadMaxBytes:     policy.UploadMaxBytes,
		UploadAllowedTypes: policy.UploadAllowedTypes,
		Operations:         map[string]operationRecord{},
		Journal:            []journalEntry{},
	}
	return marshalState(st)
}

// ReduceFixture applies one normalized command to the authoritative state
// and returns the canonical next state, the journal-bound business events
// to commit (empty for replays and malformed inputs), and the canonical
// replayable response.
func ReduceFixture(manifest Manifest, configuration []byte, state []byte, command EventSubmission) ([]byte, []EventSubmission, []byte, error) {
	if err := fixture_policy.ValidateFixture(manifest, configuration); err != nil {
		return nil, nil, nil, fmt.Errorf("fixture_reducer: fixture policy rejects manifest/configuration: %w", err)
	}
	policy, err := parseReducerPolicy(configuration)
	if err != nil {
		return nil, nil, nil, err
	}
	st, err := unmarshalState(state)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fixture_reducer: invalid state: %w", err)
	}
	if st.ManifestID != manifest.ManifestID || st.AttemptID != manifest.RunID {
		return state, nil, nil, fmt.Errorf("fixture_reducer: manifest does not match state (manifest %q run %q vs state manifest %q attempt %q)",
			manifest.ManifestID, manifest.RunID, st.ManifestID, st.AttemptID)
	}
	if err := checkPinnedPolicy(st, policy); err != nil {
		return state, nil, nil, err
	}
	// Step 1: authenticate and authorize the attempt via the opaque binding.
	if strings.TrimSpace(command.AttemptID) == "" || command.AttemptID != st.AttemptID {
		return state, nil, nil, fmt.Errorf("fixture_reducer: attempt binding mismatch: command attempt %q does not match %q",
			command.AttemptID, st.AttemptID)
	}
	// Step 2: validate normalized command shape.
	if err := validateCommandShape(command); err != nil {
		return state, nil, nil, err
	}
	digest, err := computeDigest(command)
	if err != nil {
		return state, nil, nil, fmt.Errorf("fixture_reducer: cannot compute request digest: %w", err)
	}
	// Step 3: identical key/digest replays the exact stored response with
	// no new effect, including after authority sealing.
	if rec, ok := st.Operations[command.OperationKey]; ok {
		if rec.Digest == digest {
			return state, nil, rec.Response, nil
		}
		// Step 4: changed content under an existing key conflicts. The key
		// is already bound, so the conflict cannot be journaled under it.
		return state, nil, nil, fmt.Errorf("fixture_reducer: operation key %q already bound to digest %q, conflicting digest %q",
			command.OperationKey, rec.Digest, digest)
	}
	// Step 5: authority, revisions, generation, business guards.
	if st.MutationAuthority == AuthoritySealed {
		return commitRejection(st, command, digest, "authority_sealed",
			"mutation authority is sealed; new operations cannot create new effects")
	}
	if command.ExpectedRevision != st.StateRevision {
		return commitRejection(st, command, digest, "stale_revision",
			fmt.Sprintf("expected revision %d does not match current %d", command.ExpectedRevision, st.StateRevision))
	}
	if command.SectionValueRevisionApplicable {
		curRev, curGen := currentSectionCoords(st, command.Section)
		if *command.SectionValueRevision != curRev {
			return commitRejection(st, command, digest, "stale_section_revision",
				fmt.Sprintf("section %q value revision %d is stale; current is %d", command.Section, *command.SectionValueRevision, curRev))
		}
		if *command.ValidationGeneration != curGen {
			return commitRejection(st, command, digest, "stale_generation",
				fmt.Sprintf("section %q validation generation %d is stale; current is %d", command.Section, *command.ValidationGeneration, curGen))
		}
	}
	// Step 6: endpoint business guards and effects.
	switch command.OperationKind {
	case OpJobSelection:
		return applyJobSelection(st, command, digest, policy)
	case OpContact:
		return applyContact(st, command, digest)
	case OpHistoryEnter:
		return applyHistoryEnter(st, command, digest)
	case OpHistory:
		return applyHistory(st, command, digest)
	case OpUpload:
		return applyUpload(st, command, digest, policy)
	case OpIdentityVerify:
		return applyIdentityVerify(st, command, digest)
	case OpReviewValidate:
		return applyReviewValidate(st, command, digest)
	case OpSubmit:
		return applySubmit(st, command, digest)
	case OpSeal:
		return applySeal(st, command, digest)
	default:
		return state, nil, nil, fmt.Errorf("fixture_reducer: unknown operation kind %q", command.OperationKind)
	}
}

func currentSectionCoords(st fixtureState, section string) (int, int) {
	switch section {
	case "contact":
		if st.Contact != nil {
			return st.Contact.ValueRevision, st.Contact.ValidationGeneration
		}
	case "history":
		if st.History != nil {
			return st.History.ValueRevision, st.History.ValidationGeneration
		}
	}
	return 0, 0
}

func applyJobSelection(st fixtureState, cmd EventSubmission, digest string, policy reducerPolicy) ([]byte, []EventSubmission, []byte, error) {
	if st.WorkflowState != StateListing {
		return commitRejection(st, cmd, digest, "invalid_state",
			fmt.Sprintf("job-selection requires %s, got %q", StateListing, st.WorkflowState))
	}
	payload, err := payloadObject(cmd.Payload)
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", "job-selection requires a JSON object payload with job_id")
	}
	rawID, ok := payload["job_id"]
	id, ok2 := rawID.(string)
	if !ok || !ok2 || strings.TrimSpace(id) == "" {
		return commitRejection(st, cmd, digest, "invalid_payload", "job-selection payload must contain a nonempty string job_id")
	}
	if !containsString(policy.KnownJobs, id) {
		return commitRejection(st, cmd, digest, "unknown_job", fmt.Sprintf("unknown job %q is not selection", id))
	}
	orig := st
	st.SelectedJob = id
	st.WorkflowState = StateDetail
	return finalizeAccept(orig, st, cmd, digest, EventWorkflowTransition, OutcomeAccepted, nil, false)
}

func applyContact(st fixtureState, cmd EventSubmission, digest string) ([]byte, []EventSubmission, []byte, error) {
	if st.SelectedJob == "" || st.WorkflowState == StateListing {
		return commitRejection(st, cmd, digest, "missing_prerequisite", "contact requires a selected job")
	}
	if st.WorkflowState == StateConfirmation {
		return commitRejection(st, cmd, digest, "committed_immutable", "a committed submission is immutable; contact edits are rejected")
	}
	payload, err := payloadObject(cmd.Payload)
	if err != nil || len(payload) == 0 {
		return commitRejection(st, cmd, digest, "invalid_payload", "contact requires a nonempty JSON object payload; the complete value object is preserved")
	}
	canonicalPayload, err := evidence_codec.CanonicalJSON(bytes.TrimSpace(cmd.Payload), "application/json")
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", fmt.Sprintf("contact payload is not canonicalizable: %v", err))
	}
	dataDigest := hashCanonical(canonicalPayload)
	orig := st
	newRev, newGen := 1, 1
	if st.Contact != nil {
		newRev = st.Contact.ValueRevision + 1
		newGen = st.Contact.ValidationGeneration + 1
	}
	st.Contact = &sectionAcceptance{
		Section:              "contact",
		ValueRevision:        newRev,
		ValidationGeneration: newGen,
		DataDigest:           dataDigest,
		Data:                 json.RawMessage(append([]byte(nil), canonicalPayload...)),
		Support:              "key:" + cmd.OperationKey + "/digest:" + digest,
	}
	invalidated := false
	if st.Review != nil {
		st.Review = nil
		invalidated = true
	}
	if st.WorkflowState == StateDetail {
		st.WorkflowState = StateContact
	}
	return finalizeAccept(orig, st, cmd, digest, EventValidationAccepted, OutcomeAccepted, nil, invalidated)
}

func applyHistoryEnter(st fixtureState, cmd EventSubmission, digest string) ([]byte, []EventSubmission, []byte, error) {
	if st.WorkflowState != StateContact {
		return commitRejection(st, cmd, digest, "invalid_state",
			fmt.Sprintf("history-enter requires %s, got %q", StateContact, st.WorkflowState))
	}
	if st.Contact == nil {
		return commitRejection(st, cmd, digest, "missing_prerequisite", "history-enter requires current contact acceptance")
	}
	orig := st
	// Entering a section does not imply acceptance.
	st.WorkflowState = StateHistory
	return finalizeAccept(orig, st, cmd, digest, EventWorkflowTransition, OutcomeAccepted, nil, false)
}

func applyHistory(st fixtureState, cmd EventSubmission, digest string) ([]byte, []EventSubmission, []byte, error) {
	switch st.WorkflowState {
	case StateHistory, StateUpload, StateIdentity, StateReview:
	case StateConfirmation:
		return commitRejection(st, cmd, digest, "committed_immutable", "a committed submission is immutable; history edits are rejected")
	default:
		return commitRejection(st, cmd, digest, "invalid_state",
			fmt.Sprintf("history requires an active history section, got %q", st.WorkflowState))
	}
	payload, err := payloadObject(cmd.Payload)
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", "history requires a JSON object payload with start_date and end_date")
	}
	startRaw, ok1 := payload["start_date"].(string)
	endRaw, ok2 := payload["end_date"].(string)
	if !ok1 || !ok2 || strings.TrimSpace(startRaw) == "" || strings.TrimSpace(endRaw) == "" {
		return commitRejection(st, cmd, digest, "invalid_payload", "history payload must contain nonempty string start_date and end_date")
	}
	if !validDate(startRaw) || !validDate(endRaw) {
		return commitRejection(st, cmd, digest, "invalid_payload", "history start_date and end_date must be YYYY-MM-DD dates")
	}
	if startRaw > endRaw {
		return commitRejection(st, cmd, digest, "invalid_interval",
			fmt.Sprintf("history interval end %q precedes start %q; invalid interval remains %s", endRaw, startRaw, st.WorkflowState))
	}
	canonicalPayload, err := evidence_codec.CanonicalJSON(bytes.TrimSpace(cmd.Payload), "application/json")
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", fmt.Sprintf("history payload is not canonicalizable: %v", err))
	}
	dataDigest := hashCanonical(canonicalPayload)
	orig := st
	newRev, newGen := 1, 1
	if st.History != nil {
		newRev = st.History.ValueRevision + 1
		newGen = st.History.ValidationGeneration + 1
	}
	st.History = &sectionAcceptance{
		Section:              "history",
		ValueRevision:        newRev,
		ValidationGeneration: newGen,
		DataDigest:           dataDigest,
		Data:                 json.RawMessage(append([]byte(nil), canonicalPayload...)),
		Support:              "key:" + cmd.OperationKey + "/digest:" + digest,
	}
	invalidated := false
	if st.Review != nil {
		st.Review = nil
		invalidated = true
	}
	if st.WorkflowState == StateHistory {
		st.WorkflowState = StateUpload
	}
	return finalizeAccept(orig, st, cmd, digest, EventValidationAccepted, OutcomeAccepted, nil, invalidated)
}

func applyUpload(st fixtureState, cmd EventSubmission, digest string, policy reducerPolicy) ([]byte, []EventSubmission, []byte, error) {
	if st.WorkflowState == StateConfirmation {
		return commitRejection(st, cmd, digest, "committed_immutable", "a committed submission is immutable; uploads are rejected")
	}
	if st.WorkflowState != StateUpload {
		return commitRejection(st, cmd, digest, "invalid_state",
			fmt.Sprintf("upload requires %s, got %q", StateUpload, st.WorkflowState))
	}
	payload, err := payloadObject(cmd.Payload)
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", "upload requires a JSON object payload with filename, content_type, size_bytes, and digest")
	}
	filename, _ := payload["filename"].(string)
	if strings.TrimSpace(filename) == "" {
		return commitRejection(st, cmd, digest, "invalid_payload", "upload payload must contain a nonempty string filename")
	}
	contentType, _ := payload["content_type"].(string)
	if strings.TrimSpace(contentType) == "" {
		return commitRejection(st, cmd, digest, "invalid_payload", "upload payload must contain a nonempty string content_type")
	}
	if len(policy.UploadAllowedTypes) > 0 && !containsString(policy.UploadAllowedTypes, contentType) {
		return commitRejection(st, cmd, digest, "unsupported_type", fmt.Sprintf("upload content type %q is not admitted", contentType))
	}
	sizeRaw, ok := payload["size_bytes"]
	if !ok {
		return commitRejection(st, cmd, digest, "invalid_payload", "upload payload must contain size_bytes")
	}
	size, ok := asInt64(sizeRaw)
	if !ok || size < 0 {
		return commitRejection(st, cmd, digest, "invalid_payload", "upload size_bytes must be a nonnegative integer")
	}
	if size > policy.UploadMaxBytes {
		return commitRejection(st, cmd, digest, "size_exceeded",
			fmt.Sprintf("upload size %d exceeds bound %d", size, policy.UploadMaxBytes))
	}
	digestStr, _ := payload["digest"].(string)
	if !validDigest(digestStr) {
		return commitRejection(st, cmd, digest, "invalid_digest", "upload digest must match sha256:<64 lowercase hex>")
	}
	orig := st
	st.Upload = &uploadAcceptance{
		Filename:    filename,
		ContentType: contentType,
		SizeBytes:   size,
		Digest:      digestStr,
		Support:     "key:" + cmd.OperationKey + "/digest:" + digest,
	}
	st.WorkflowState = StateIdentity
	return finalizeAccept(orig, st, cmd, digest, EventUploadStored, OutcomeAccepted, nil, false)
}

func applyIdentityVerify(st fixtureState, cmd EventSubmission, digest string) ([]byte, []EventSubmission, []byte, error) {
	if st.WorkflowState == StateConfirmation {
		return commitRejection(st, cmd, digest, "committed_immutable", "a committed submission is immutable; identity verification is rejected")
	}
	if st.WorkflowState != StateIdentity {
		return commitRejection(st, cmd, digest, "invalid_state",
			fmt.Sprintf("identity-verify requires %s, got %q", StateIdentity, st.WorkflowState))
	}
	payload, err := payloadObject(cmd.Payload)
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", "identity-verify requires a JSON object payload with epoch and receipt")
	}
	epoch, _ := payload["epoch"].(string)
	if strings.TrimSpace(epoch) == "" {
		return commitRejection(st, cmd, digest, "invalid_payload", "identity-verify payload must contain a nonempty string epoch")
	}
	if epoch != st.IdentityEpoch {
		return commitRejection(st, cmd, digest, "epoch_mismatch",
			fmt.Sprintf("identity epoch %q does not match pinned epoch %q; identity remains attempt- and epoch-bound", epoch, st.IdentityEpoch))
	}
	receipt, _ := payload["receipt"].(string)
	if strings.TrimSpace(receipt) == "" {
		return commitRejection(st, cmd, digest, "unverified_identity", "token possession without a valid verification receipt cannot verify identity")
	}
	if attemptRaw, ok := payload["attempt_id"]; ok {
		attemptStr, ok2 := attemptRaw.(string)
		if !ok2 || attemptStr != st.AttemptID {
			return commitRejection(st, cmd, digest, "unverified_identity", "identity receipt is not bound to this attempt")
		}
	}
	orig := st
	st.Identity = &identityAcceptance{
		Epoch:     epoch,
		Receipt:   receipt,
		AttemptID: st.AttemptID,
		Verified:  true,
		Support:   "key:" + cmd.OperationKey + "/digest:" + digest,
	}
	st.WorkflowState = StateReview
	return finalizeAccept(orig, st, cmd, digest, EventIdentityVerified, OutcomeAccepted, nil, false)
}

func applyReviewValidate(st fixtureState, cmd EventSubmission, digest string) ([]byte, []EventSubmission, []byte, error) {
	if st.WorkflowState == StateConfirmation {
		return commitRejection(st, cmd, digest, "committed_immutable", "a committed submission is immutable; review validation is rejected")
	}
	if st.WorkflowState != StateReview {
		return commitRejection(st, cmd, digest, "invalid_state",
			fmt.Sprintf("review-validate requires %s, got %q", StateReview, st.WorkflowState))
	}
	if st.Contact == nil || st.History == nil {
		return commitRejection(st, cmd, digest, "missing_prerequisite", "review requires current contact and history acceptance")
	}
	payload, err := payloadObject(cmd.Payload)
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", "review-validate requires a JSON object payload citing prerequisite revisions")
	}
	cRev, ok1 := asInt(payload["contact_value_revision"])
	cGen, ok2 := asInt(payload["contact_generation"])
	hRev, ok3 := asInt(payload["history_value_revision"])
	hGen, ok4 := asInt(payload["history_generation"])
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return commitRejection(st, cmd, digest, "invalid_payload",
			"review-validate payload must cite integer contact_value_revision, contact_generation, history_value_revision, and history_generation")
	}
	if cRev != st.Contact.ValueRevision || cGen != st.Contact.ValidationGeneration ||
		hRev != st.History.ValueRevision || hGen != st.History.ValidationGeneration {
		return commitRejection(st, cmd, digest, "stale_dependency",
			"review references a stale prerequisite; stale validation cannot authorize current progress")
	}
	orig := st
	newRev, newGen := 1, 1
	if st.Review != nil {
		newRev = st.Review.ValueRevision + 1
		newGen = st.Review.ValidationGeneration + 1
	}
	st.Review = &reviewAcceptance{
		ValueRevision:        newRev,
		ValidationGeneration: newGen,
		ContactValueRevision: cRev,
		ContactGeneration:    cGen,
		HistoryValueRevision: hRev,
		HistoryGeneration:    hGen,
		Support:              "key:" + cmd.OperationKey + "/digest:" + digest,
	}
	return finalizeAccept(orig, st, cmd, digest, EventValidationAccepted, OutcomeAccepted, nil, false)
}

func applySubmit(st fixtureState, cmd EventSubmission, digest string) ([]byte, []EventSubmission, []byte, error) {
	if st.WorkflowState != StateReview && st.WorkflowState != StateConfirmation {
		return commitRejection(st, cmd, digest, "invalid_state",
			fmt.Sprintf("submit requires %s, got %q", StateReview, st.WorkflowState))
	}
	// Optional payload pins, when present, must be current; stale content
	// rejects without creating a commitment.
	if len(bytes.TrimSpace(cmd.Payload)) > 0 {
		payload, err := payloadObject(cmd.Payload)
		if err != nil {
			return commitRejection(st, cmd, digest, "invalid_payload", "submit payload must be a JSON object when present")
		}
		if v, ok := payload["contact_value_revision"]; ok {
			cRev, ok2 := asInt(v)
			if !ok2 || st.Contact == nil || cRev != st.Contact.ValueRevision {
				return commitRejection(st, cmd, digest, "stale_dependency", "submit cites a stale contact value revision")
			}
		}
		if v, ok := payload["contact_generation"]; ok {
			cGen, ok2 := asInt(v)
			if !ok2 || st.Contact == nil || cGen != st.Contact.ValidationGeneration {
				return commitRejection(st, cmd, digest, "stale_dependency", "submit cites a stale contact generation")
			}
		}
		if v, ok := payload["history_value_revision"]; ok {
			hRev, ok2 := asInt(v)
			if !ok2 || st.History == nil || hRev != st.History.ValueRevision {
				return commitRejection(st, cmd, digest, "stale_dependency", "submit cites a stale history value revision")
			}
		}
		if v, ok := payload["history_generation"]; ok {
			hGen, ok2 := asInt(v)
			if !ok2 || st.History == nil || hGen != st.History.ValidationGeneration {
				return commitRejection(st, cmd, digest, "stale_dependency", "submit cites a stale history generation")
			}
		}
	}
	// Submission checks in the same application transaction (seam 6.5).
	if st.SelectedJob == "" {
		return commitRejection(st, cmd, digest, "missing_job", "submission requires a selected job")
	}
	if st.Contact == nil {
		return commitRejection(st, cmd, digest, "missing_contact", "submission requires current contact acceptance")
	}
	if st.History == nil {
		return commitRejection(st, cmd, digest, "missing_history", "submission requires current history acceptance")
	}
	if st.Upload == nil || !validDigest(st.Upload.Digest) {
		return commitRejection(st, cmd, digest, "missing_upload", "submission requires accepted upload bytes with a matching digest")
	}
	if st.Identity == nil || !st.Identity.Verified || st.Identity.Epoch != st.IdentityEpoch || st.Identity.AttemptID != st.AttemptID {
		return commitRejection(st, cmd, digest, "unverified_identity", "submission requires an identity receipt verified for the attempt and epoch")
	}
	if st.Review == nil {
		return commitRejection(st, cmd, digest, "missing_review", "submission requires a current review")
	}
	if st.Review.ContactValueRevision != st.Contact.ValueRevision ||
		st.Review.ContactGeneration != st.Contact.ValidationGeneration ||
		st.Review.HistoryValueRevision != st.History.ValueRevision ||
		st.Review.HistoryGeneration != st.History.ValidationGeneration {
		return commitRejection(st, cmd, digest, "stale_review", "review references stale accepted data; re-validate before submit")
	}
	if st.WorkflowState == StateConfirmation {
		// A different key never authorizes a second application. An
		// accepted repeat with current content resolves to the existing
		// commitment; stale or incompatible content rejects above.
		orig := st
		existing := *st.Submission
		return finalizeAccept(orig, st, cmd, digest, EventRequestCompleted, OutcomeResolvedExisting, &existing, false)
	}
	orig := st
	appID := "app-" + digestSuffix(digest, 12)
	commitRef := fmt.Sprintf("journal:%d", orig.StateRevision+1)
	sub := &commitment{
		ApplicationID: appID,
		OperationKey:  cmd.OperationKey,
		RequestDigest: digest,
		Receipt:       digest,
		CommittedAt:   fmt.Sprintf("revision:%d", orig.StateRevision+1),
		CommitRef:     commitRef,
	}
	st.Submission = sub
	st.WorkflowState = StateConfirmation
	committed := *sub
	return finalizeAccept(orig, st, cmd, digest, EventSubmissionCommitted, OutcomeCommitted, &committed, false)
}

func applySeal(st fixtureState, cmd EventSubmission, digest string) ([]byte, []EventSubmission, []byte, error) {
	if st.MutationAuthority == AuthoritySealed {
		return commitRejection(st, cmd, digest, "authority_sealed", "mutation authority is already sealed")
	}
	payload, err := payloadObject(cmd.Payload)
	if err != nil {
		return commitRejection(st, cmd, digest, "invalid_payload", "seal requires a JSON object payload with seal_ref")
	}
	sealRef, _ := payload["seal_ref"].(string)
	if strings.TrimSpace(sealRef) == "" {
		return commitRejection(st, cmd, digest, "invalid_payload", "seal payload must contain actual seal evidence in seal_ref")
	}
	orig := st
	st.MutationAuthority = AuthoritySealed
	st.AuthoritySealRef = sealRef
	return finalizeAccept(orig, st, cmd, digest, EventFixtureSeal, OutcomeAccepted, nil, false)
}

// commitRejection durably records a business rejection: revision advance,
// journal append, ledger store for future identical replays, one rejection
// event, and a structured rejection response. Business state is unchanged.
func commitRejection(st fixtureState, cmd EventSubmission, digest, reason, detail string) ([]byte, []EventSubmission, []byte, error) {
	newRev := st.StateRevision + 1
	resp := reducerResponse{
		Status:        OutcomeRejected,
		OperationKey:  cmd.OperationKey,
		OperationKind: cmd.OperationKind,
		RequestDigest: digest,
		StateRevision: newRev,
		WorkflowState: st.WorkflowState,
		Reason:        reason,
		ReasonDetail:  detail,
	}
	respBytes, err := marshalResponse(resp)
	if err != nil {
		return nil, nil, nil, err
	}
	st.Journal = append(st.Journal, journalEntry{
		Sequence:       newRev,
		OperationKey:   cmd.OperationKey,
		OperationKind:  cmd.OperationKind,
		Digest:         digest,
		Outcome:        OutcomeRejected,
		Reason:         reason,
		RevisionBefore: st.StateRevision,
		RevisionAfter:  newRev,
		WorkflowBefore: st.WorkflowState,
		WorkflowAfter:  st.WorkflowState,
		Detail:         detail,
	})
	if st.Operations == nil {
		st.Operations = map[string]operationRecord{}
	}
	st.Operations[cmd.OperationKey] = operationRecord{Digest: digest, Response: json.RawMessage(append([]byte(nil), respBytes...))}
	st.StateRevision = newRev
	newState, err := marshalState(st)
	if err != nil {
		return nil, nil, nil, err
	}
	evt := EventSubmission{
		OperationKey:       cmd.OperationKey,
		OperationKind:      cmd.OperationKind,
		AttemptID:          st.AttemptID,
		ExpectedRevision:   newRev,
		Payload:            json.RawMessage(append([]byte(nil), respBytes...)),
		ProducerSequence:   newRev,
		EventKind:          rejectionEventKind(reason),
		EventSchemaVersion: "1.0.0",
	}
	return newState, []EventSubmission{evt}, respBytes, nil
}

// finalizeAccept commits an accepted effect or an accepted repeat that
// resolves to the existing commitment. The caller has already applied
// business mutations to mutated; this function advances the revision,
// appends the journal, stores the replayable response, and emits one
// business event.
func finalizeAccept(orig, mutated fixtureState, cmd EventSubmission, digest, eventKind, outcome string, cm *commitment, invalidatedReview bool) ([]byte, []EventSubmission, []byte, error) {
	newRev := orig.StateRevision + 1
	mutated.StateRevision = newRev
	resp := reducerResponse{
		Status:            outcome,
		OperationKey:      cmd.OperationKey,
		OperationKind:     cmd.OperationKind,
		RequestDigest:     digest,
		StateRevision:     newRev,
		WorkflowState:     mutated.WorkflowState,
		Commitment:        cm,
		InvalidatedReview: invalidatedReview,
	}
	respBytes, err := marshalResponse(resp)
	if err != nil {
		return nil, nil, nil, err
	}
	entry := journalEntry{
		Sequence:       newRev,
		OperationKey:   cmd.OperationKey,
		OperationKind:  cmd.OperationKind,
		Digest:         digest,
		Outcome:        outcome,
		RevisionBefore: orig.StateRevision,
		RevisionAfter:  newRev,
		WorkflowBefore: orig.WorkflowState,
		WorkflowAfter:  mutated.WorkflowState,
	}
	if invalidatedReview {
		entry.Detail = "invalidated_review"
	}
	if outcome == OutcomeResolvedExisting {
		entry.Detail = "resolved_to_existing_commitment"
	}
	mutated.Journal = append(mutated.Journal, entry)
	if mutated.Operations == nil {
		mutated.Operations = map[string]operationRecord{}
	}
	mutated.Operations[cmd.OperationKey] = operationRecord{Digest: digest, Response: json.RawMessage(append([]byte(nil), respBytes...))}
	newState, err := marshalState(mutated)
	if err != nil {
		return nil, nil, nil, err
	}
	evt := EventSubmission{
		OperationKey:       cmd.OperationKey,
		OperationKind:      cmd.OperationKind,
		AttemptID:          mutated.AttemptID,
		ExpectedRevision:   newRev,
		Payload:            json.RawMessage(append([]byte(nil), respBytes...)),
		ProducerSequence:   newRev,
		EventKind:          eventKind,
		EventSchemaVersion: "1.0.0",
	}
	return newState, []EventSubmission{evt}, respBytes, nil
}

func rejectionEventKind(reason string) string {
	switch reason {
	case "invalid_payload", "invalid_interval", "invalid_digest", "unknown_job",
		"stale_section_revision", "stale_generation", "stale_dependency",
		"stale_review", "unverified_identity", "epoch_mismatch":
		return EventValidationRejected
	default:
		return EventRequestRejected
	}
}

func validateCommandShape(cmd EventSubmission) error {
	if strings.TrimSpace(cmd.OperationKey) == "" {
		return fmt.Errorf("fixture_reducer: command is missing operation_key")
	}
	switch cmd.OperationKind {
	case OpJobSelection, OpContact, OpHistoryEnter, OpHistory, OpUpload, OpIdentityVerify, OpReviewValidate, OpSubmit, OpSeal:
	default:
		return fmt.Errorf("fixture_reducer: unknown operation kind %q", cmd.OperationKind)
	}
	needsApplicable := cmd.OperationKind == OpContact || cmd.OperationKind == OpHistory
	if needsApplicable {
		if !cmd.SectionValueRevisionApplicable || !cmd.ValidationGenerationApplicable {
			return fmt.Errorf("fixture_reducer: %s requires applicable section coordinates", cmd.OperationKind)
		}
		if cmd.SectionValueRevision == nil || cmd.ValidationGeneration == nil {
			return fmt.Errorf("fixture_reducer: %s is missing section value revision or validation generation", cmd.OperationKind)
		}
		want := "contact"
		if cmd.OperationKind == OpHistory {
			want = "history"
		}
		if cmd.Section != want {
			return fmt.Errorf("fixture_reducer: %s requires section %q, got %q", cmd.OperationKind, want, cmd.Section)
		}
	} else {
		if cmd.SectionValueRevisionApplicable || cmd.ValidationGenerationApplicable {
			return fmt.Errorf("fixture_reducer: %s requires inapplicable section coordinates", cmd.OperationKind)
		}
		if cmd.SectionValueRevision != nil || cmd.ValidationGeneration != nil {
			return fmt.Errorf("fixture_reducer: %s must not carry section coordinates", cmd.OperationKind)
		}
		if strings.TrimSpace(cmd.Section) != "" {
			return fmt.Errorf("fixture_reducer: %s must leave section empty when coordinates are inapplicable", cmd.OperationKind)
		}
	}
	if len(bytes.TrimSpace(cmd.Payload)) > 0 {
		if _, err := evidence_codec.CanonicalJSON(cmd.Payload, "application/json"); err != nil {
			return fmt.Errorf("fixture_reducer: command payload is not valid JSON: %w", err)
		}
		var v any
		if err := json.Unmarshal(cmd.Payload, &v); err != nil {
			return fmt.Errorf("fixture_reducer: command payload cannot be decoded: %w", err)
		}
		if err := rejectBareNulls(v, "$"); err != nil {
			return err
		}
	}
	return nil
}

// computeDigest builds the server-computed canonical request digest over
// operation kind, attempt identity, payload, and applicable
// revision/generation references. Ingress metadata and transport
// credentials are excluded.
func computeDigest(cmd EventSubmission) (string, error) {
	payloadSHA := "absent"
	if trimmed := bytes.TrimSpace(cmd.Payload); len(trimmed) > 0 {
		canonicalPayload, err := evidence_codec.CanonicalJSON(trimmed, "application/json")
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(canonicalPayload)
		payloadSHA = hex.EncodeToString(sum[:])
	}
	input := map[string]any{
		"operation_kind":    cmd.OperationKind,
		"attempt_id":        cmd.AttemptID,
		"expected_revision": cmd.ExpectedRevision,
		"payload_sha":       payloadSHA,
	}
	if cmd.SectionValueRevisionApplicable {
		if cmd.SectionValueRevision == nil {
			return "", fmt.Errorf("fixture_reducer: applicable section value revision is missing")
		}
		input["section"] = cmd.Section
		input["section_value_revision"] = *cmd.SectionValueRevision
	} else {
		input["section"] = "inapplicable"
		input["section_value_revision"] = "inapplicable"
	}
	if cmd.ValidationGenerationApplicable {
		if cmd.ValidationGeneration == nil {
			return "", fmt.Errorf("fixture_reducer: applicable validation generation is missing")
		}
		input["validation_generation"] = *cmd.ValidationGeneration
	} else {
		input["validation_generation"] = "inapplicable"
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func hashCanonical(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestSuffix(digest string, n int) string {
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) < n {
		return hexPart
	}
	return hexPart[:n]
}

func parseReducerPolicy(configuration []byte) (reducerPolicy, error) {
	p := reducerPolicy{
		IdentityEpoch:      "epoch-1",
		KnownJobs:          []string{"job-1", "job-2"},
		ReviewDependencies: []string{"contact", "history"},
		UploadMaxBytes:     5 * 1024 * 1024,
		UploadAllowedTypes: nil,
	}
	var obj map[string]any
	if err := json.Unmarshal(configuration, &obj); err != nil {
		return p, fmt.Errorf("fixture_reducer: effective_configuration is not a JSON object: %w", err)
	}
	if v, ok := obj["identity_epoch"]; ok {
		s, ok := v.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return p, fmt.Errorf("fixture_reducer: identity_epoch must be a nonempty string")
		}
		p.IdentityEpoch = s
	}
	if v, ok := obj["known_jobs"]; ok {
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			return p, fmt.Errorf("fixture_reducer: known_jobs must be a nonempty array of job IDs")
		}
		jobs := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return p, fmt.Errorf("fixture_reducer: known_jobs must contain nonempty strings")
			}
			jobs = append(jobs, s)
		}
		p.KnownJobs = jobs
	}
	if v, ok := obj["review_dependencies"]; ok {
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			return p, fmt.Errorf("fixture_reducer: review_dependencies must be a nonempty array")
		}
		deps := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return p, fmt.Errorf("fixture_reducer: review_dependencies must contain nonempty strings")
			}
			deps = append(deps, s)
		}
		// This M1 reducer pins review to contact and history. The policy
		// enumerates the dependency; anything else is a different fixture.
		if len(deps) != 2 || !containsString(deps, "contact") || !containsString(deps, "history") {
			return p, fmt.Errorf("fixture_reducer: review_dependencies must enumerate [contact history] in this fixture")
		}
		p.ReviewDependencies = deps
	}
	if v, ok := obj["upload_max_bytes"]; ok {
		n, ok := asInt64(v)
		if !ok || n <= 0 {
			return p, fmt.Errorf("fixture_reducer: upload_max_bytes must be a positive integer")
		}
		p.UploadMaxBytes = n
	}
	if v, ok := obj["upload_allowed_types"]; ok {
		arr, ok := v.([]any)
		if !ok {
			return p, fmt.Errorf("fixture_reducer: upload_allowed_types must be an array")
		}
		types := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return p, fmt.Errorf("fixture_reducer: upload_allowed_types must contain nonempty strings")
			}
			types = append(types, s)
		}
		p.UploadAllowedTypes = types
	}
	return p, nil
}

func checkPinnedPolicy(st fixtureState, p reducerPolicy) error {
	if st.IdentityEpoch != p.IdentityEpoch {
		return fmt.Errorf("fixture_reducer: configuration identity_epoch %q does not match pinned %q", p.IdentityEpoch, st.IdentityEpoch)
	}
	if !equalStringSets(st.KnownJobs, p.KnownJobs) {
		return fmt.Errorf("fixture_reducer: configuration known_jobs do not match pinned policy")
	}
	if !equalStringSets(st.ReviewDependencies, p.ReviewDependencies) {
		return fmt.Errorf("fixture_reducer: configuration review_dependencies do not match pinned policy")
	}
	if st.UploadMaxBytes != p.UploadMaxBytes {
		return fmt.Errorf("fixture_reducer: configuration upload_max_bytes does not match pinned policy")
	}
	if !equalStringSets(st.UploadAllowedTypes, p.UploadAllowedTypes) {
		return fmt.Errorf("fixture_reducer: configuration upload_allowed_types do not match pinned policy")
	}
	return nil
}

func marshalState(st fixtureState) ([]byte, error) {
	if st.Operations == nil {
		st.Operations = map[string]operationRecord{}
	}
	if st.Journal == nil {
		st.Journal = []journalEntry{}
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("fixture_reducer: cannot encode state: %w", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return nil, fmt.Errorf("fixture_reducer: cannot canonicalize state: %w", err)
	}
	return canonical, nil
}

func unmarshalState(data []byte) (fixtureState, error) {
	var st fixtureState
	if len(bytes.TrimSpace(data)) == 0 {
		return st, fmt.Errorf("empty state")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&st); err != nil {
		return st, err
	}
	switch st.WorkflowState {
	case StateListing, StateDetail, StateContact, StateHistory, StateUpload, StateIdentity, StateReview, StateConfirmation:
	default:
		return st, fmt.Errorf("unknown workflow state %q", st.WorkflowState)
	}
	switch st.MutationAuthority {
	case AuthorityOpen, AuthoritySealed:
	default:
		return st, fmt.Errorf("unknown mutation authority %q", st.MutationAuthority)
	}
	if st.StateRevision < 0 {
		return st, fmt.Errorf("negative state revision %d", st.StateRevision)
	}
	if strings.TrimSpace(st.ManifestID) == "" || strings.TrimSpace(st.AttemptID) == "" {
		return st, fmt.Errorf("state is missing manifest or attempt binding")
	}
	if st.Operations == nil {
		return st, fmt.Errorf("state is missing the operation-response ledger")
	}
	if st.Journal == nil {
		return st, fmt.Errorf("state is missing the journal")
	}
	return st, nil
}

func marshalResponse(resp reducerResponse) ([]byte, error) {
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("fixture_reducer: cannot encode response: %w", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return nil, fmt.Errorf("fixture_reducer: cannot canonicalize response: %w", err)
	}
	return canonical, nil
}

// payloadObject decodes a required JSON object payload.
func payloadObject(payload json.RawMessage) (map[string]any, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("missing payload")
	}
	var v any
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload must be a JSON object")
	}
	return obj, nil
}

func rejectBareNulls(v any, path string) error {
	switch t := v.(type) {
	case nil:
		return fmt.Errorf("fixture_reducer: bare null at %s: missing fields must use typed Missing envelopes with value null and a reason", path)
	case map[string]any:
		if raw, ok := t["value"]; ok && raw == nil {
			for k := range t {
				if k != "value" && k != "reason" && k != "detail" {
					return fmt.Errorf("fixture_reducer: unknown field %q in Missing envelope at %s", k, path)
				}
			}
			r, _ := t["reason"].(string)
			if !nullReasons[r] {
				return fmt.Errorf("fixture_reducer: invalid NullReason %q at %s", r, path)
			}
			if d, ok := t["detail"]; ok {
				s, ok := d.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return fmt.Errorf("fixture_reducer: Missing detail at %s must be a nonempty string", path)
				}
			}
			return nil
		}
		for k, e := range t {
			if err := rejectBareNulls(e, path+"."+k); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for i, e := range t {
			if err := rejectBareNulls(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

func validDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") {
		return false
	}
	hexPart := strings.TrimPrefix(s, "sha256:")
	if len(hexPart) != 64 {
		return false
	}
	for _, r := range hexPart {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, r := range s {
		if i == 4 || i == 7 {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	month := (s[5]-'0')*10 + (s[6] - '0')
	day := (s[8]-'0')*10 + (s[9] - '0')
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	return true
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	default:
		return 0, false
	}
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}
