package owner_store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authority "authority"
	evidence_codec "evidence_codec"
)

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

type fixture struct {
	t            *testing.T
	store        *OwnerStore
	ctx          context.Context
	dbPath       string
	artifactRoot string
	domain       string
	manifest     Manifest
	journalID    string
	admission    []JournalEnvelope
	prefix       JournalPrefix
}

func newFixture(t *testing.T, domain string, journalID string) *fixture {
	t.Helper()
	home := t.TempDir()
	f := &fixture{
		t:            t,
		dbPath:       filepath.Join(home, domain+".db"),
		artifactRoot: filepath.Join(home, domain+"-artifacts"),
		domain:       domain,
		manifest:     testManifest(domain, journalID),
		journalID:    journalID,
	}
	store, err := OpenOwner(f.dbPath, f.artifactRoot, domain)
	if err != nil {
		t.Fatalf("OpenOwner(%s): %v", domain, err)
	}
	f.store = store
	t.Cleanup(func() {
		if f.store != nil {
			_ = f.store.Close()
		}
	})
	f.ctx = testContext(t, domain)
	f.admission, f.prefix = admitJournal(t, f.ctx, store, f.manifest)
	return f
}

func (f *fixture) reopen() {
	f.t.Helper()
	if err := f.store.Close(); err != nil {
		f.t.Fatalf("close store before reopen: %v", err)
	}
	store, err := OpenOwner(f.dbPath, f.artifactRoot, f.domain)
	if err != nil {
		f.t.Fatalf("reopen %s: %v", f.domain, err)
	}
	f.store = store
}

func testPolicy(domain string) []byte {
	return []byte(fmt.Sprintf(
		`{"channels":{"channel-%s":{"principal":"writer-%s","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`,
		domain, domain))
}

func testContext(t *testing.T, domain string) context.Context {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://owner-store.test/"+domain, nil)
	if err != nil {
		t.Fatalf("build authentication request: %v", err)
	}
	request.Header.Set("Authorization", "Channel channel-"+domain)
	ctx, err := authority.Authenticate(request, testPolicy(domain))
	if err != nil {
		t.Fatalf("authenticate %s writer: %v", domain, err)
	}
	return ctx
}

func testManifest(domain, journalID string) Manifest {
	return Manifest{
		RecordType:    "manifest",
		SchemaVersion: "0.1.0",
		ManifestID:    "manifest-" + journalID,
		RunID:         "run-" + domain,
		JournalID:     journalID,
		OwnerDomain:   domain,
		Clocks: []ClockDescriptor{{
			ClockID: "clock-" + domain, BootID: "boot-" + domain,
			Origin: "engine_measured", SourceID: "owner-store",
			Basis: "monotonic_offset", Unit: "ms",
		}},
	}
}

func testTimePoint(m Manifest, offsetMs float64) TimePoint {
	clock := m.Clocks[0]
	return TimePoint{
		ClockID: clock.ClockID, BootID: clock.BootID, Origin: clock.Origin,
		MonotonicOffsetMs: offsetMs, UTCAnnotation: NewMissing("not_applicable"),
	}
}

func canonicalManifest(t *testing.T, m Manifest) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize manifest: %v", err)
	}
	return canonical
}

func installTestArtifact(t *testing.T, ctx context.Context, store *OwnerStore, content []byte,
	mediaType, access string) ArtifactReference {
	t.Helper()
	ref, err := InstallArtifact(ctx, store, bytes.NewReader(content), mediaType, access)
	if err != nil {
		t.Fatalf("InstallArtifact: %v", err)
	}
	return ref
}

func artifactRefMap(ref ArtifactReference) map[string]any {
	return map[string]any{
		"digest":       string(ref.Digest),
		"size_bytes":   ref.SizeBytes,
		"media_type":   ref.MediaType,
		"owner_domain": ref.OwnerDomain,
		"access":       ref.Access,
	}
}

func admitJournal(t *testing.T, ctx context.Context, store *OwnerStore, m Manifest) ([]JournalEnvelope, JournalPrefix) {
	t.Helper()
	ref := installTestArtifact(t, ctx, store, canonicalManifest(t, m), "application/json", accessPublic)
	submission := EventSubmission{
		ProducerSequence:   int64(1),
		EventKind:          "manifest_admitted",
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(m, 0),
		Payload: Payload{
			Data:         map[string]any{"manifest": artifactRefMap(ref)},
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: []ArtifactReference{ref},
		},
	}
	envelopes, err := CommitOwner(ctx, store, m.JournalID, []EventSubmission{submission}, nil)
	if err != nil {
		t.Fatalf("admit journal: %v", err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("admission returned %d envelopes", len(envelopes))
	}
	return envelopes, JournalPrefix{
		JournalID:    m.JournalID,
		LastSequence: envelopes[0].Sequence,
		HeadHash:     envelopes[0].EventHash,
	}
}

func eventSubmission(m Manifest, sequence int64, kind string, data map[string]any,
	refs ...ArtifactReference) EventSubmission {
	if data == nil {
		data = map[string]any{}
	}
	if refs == nil {
		refs = []ArtifactReference{}
	}
	return EventSubmission{
		ProducerSequence:   sequence,
		EventKind:          kind,
		EventSchemaVersion: "0.1.0",
		OccurredAt:         testTimePoint(m, float64(sequence)),
		Payload: Payload{
			Data:         data,
			Measurements: []Measurement{},
			EvidenceRefs: []EvidenceRef{},
			ArtifactRefs: refs,
		},
	}
}

func mustCommit(t *testing.T, ctx context.Context, store *OwnerStore, journalID string,
	effect func(*sql.Tx) error, events ...EventSubmission) []JournalEnvelope {
	t.Helper()
	envelopes, err := CommitOwner(ctx, store, journalID, events, effect)
	if err != nil {
		t.Fatalf("CommitOwner: %v", err)
	}
	return envelopes
}

func prefixThrough(envelopes []JournalEnvelope) JournalPrefix {
	last := envelopes[len(envelopes)-1]
	return JournalPrefix{JournalID: last.JournalID, LastSequence: last.Sequence, HeadHash: last.EventHash}
}

func canonicalEnvelopes(t *testing.T, envelopes []JournalEnvelope) string {
	t.Helper()
	raw, err := json.Marshal(envelopes)
	if err != nil {
		t.Fatalf("marshal envelopes: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		t.Fatalf("canonicalize envelopes: %v", err)
	}
	return string(canonical)
}

func assertDatabaseListOnlyMain(t *testing.T, ctx context.Context, store *OwnerStore) {
	t.Helper()
	rows, err := store.db.QueryContext(ctx, `PRAGMA database_list;`)
	if err != nil {
		t.Fatalf("read database_list: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan database_list: %v", err)
		}
		if name != "main" && name != "temp" {
			t.Fatalf("cross-database attachment is visible: %q -> %q", name, file)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate database_list: %v", err)
	}
}

type failingReader struct {
	payload []byte
	err     error
	sent    bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, r.err
	}
	r.sent = true
	return copy(p, r.payload), nil
}

func retryableArtifactRace(err error) bool {
	return errors.Is(err, ErrArtifactMissing) || errors.Is(err, ErrArtifactLost) ||
		errors.Is(err, ErrIntegrityConflict)
}

// ---------------------------------------------------------------------------
// Conformance assertions.
// ---------------------------------------------------------------------------

// A busy observation writer must not delay an application owner commit: the
// stores have independent connections, writer queues, and transaction
// admission.
func TestBusyObservationWriterDoesNotBlockApplicationCommit(t *testing.T) {
	application := newFixture(t, "application", "journal-busy-observation-app")
	observation := newFixture(t, "observation", "journal-busy-observation-obs")

	entered := make(chan struct{})
	release := make(chan struct{})
	observationDone := make(chan error, 1)
	go func() {
		_, err := CommitOwner(observation.ctx, observation.store, observation.journalID,
			[]EventSubmission{eventSubmission(observation.manifest, 2, "observation_recorded",
				map[string]any{"marker": "observation"})},
			func(tx *sql.Tx) error {
				close(entered)
				<-release
				return nil
			})
		observationDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("observation writer never entered its owner-local transaction")
	}

	start := time.Now()
	applicationEnvelopes := mustCommit(t, application.ctx, application.store, application.journalID, nil,
		eventSubmission(application.manifest, 2, "application_recorded", map[string]any{"marker": "application"}))
	elapsed := time.Since(start)
	if elapsed > 3*time.Second {
		t.Fatalf("application commit waited %s on a busy observation writer", elapsed)
	}
	if len(applicationEnvelopes) != 1 {
		t.Fatalf("application commit returned %d envelopes", len(applicationEnvelopes))
	}

	close(release)
	select {
	case err := <-observationDone:
		if err != nil {
			t.Fatalf("observation commit failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observation commit did not finish after release")
	}
}

// Saturating diagnostic work must not block application or observation owner
// writes: no shared serialized I/O admission gate exists across owners.
func TestSaturatedDiagnosticWorkDoesNotBlockSourceWriters(t *testing.T) {
	diagnostic := newFixture(t, "diagnostic", "journal-saturated-diagnostic")
	application := newFixture(t, "application", "journal-saturated-app")
	observation := newFixture(t, "observation", "journal-saturated-obs")

	stop := make(chan struct{})
	var churn sync.WaitGroup
	var churnRuns atomic.Int32
	for worker := range 4 {
		churn.Add(1)
		go func(worker int) {
			defer churn.Done()
			for round := range 6 {
				select {
				case <-stop:
					return
				default:
				}
				content := bytes.Repeat([]byte{byte(worker), byte(round), 0xA5}, 64*1024)
				if _, err := InstallArtifact(diagnostic.ctx, diagnostic.store, bytes.NewReader(content),
					"application/octet-stream", accessPublic); err != nil {
					return
				}
				churnRuns.Add(1)
			}
		}(worker)
	}

	diagnosticEntered := make(chan struct{})
	diagnosticDone := make(chan error, 1)
	go func() {
		_, err := CommitOwner(diagnostic.ctx, diagnostic.store, diagnostic.journalID,
			[]EventSubmission{eventSubmission(diagnostic.manifest, 2, "diagnostic_computed",
				map[string]any{"phase": "saturated"})},
			func(tx *sql.Tx) error {
				close(diagnosticEntered)
				time.Sleep(250 * time.Millisecond)
				return nil
			})
		diagnosticDone <- err
	}()
	select {
	case <-diagnosticEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("diagnostic writer never saturated its owner-local transaction")
	}

	results := make(chan error, 2)
	go func() {
		_, err := CommitOwner(application.ctx, application.store, application.journalID,
			[]EventSubmission{eventSubmission(application.manifest, 2, "application_recorded",
				map[string]any{"marker": "under-saturation"})}, nil)
		results <- err
	}()
	go func() {
		_, err := CommitOwner(observation.ctx, observation.store, observation.journalID,
			[]EventSubmission{eventSubmission(observation.manifest, 2, "observation_recorded",
				map[string]any{"marker": "under-saturation"})}, nil)
		results <- err
	}()
	deadline := time.After(3 * time.Second)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("source owner write blocked or failed under diagnostic saturation: %v", err)
			}
		case <-deadline:
			t.Fatal("source owner writes did not reach admission under diagnostic saturation")
		}
	}

	close(stop)
	churn.Wait()
	select {
	case err := <-diagnosticDone:
		if err != nil {
			t.Fatalf("diagnostic commit failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("diagnostic commit did not finish")
	}
	if churnRuns.Load() == 0 {
		t.Fatal("diagnostic saturation work never executed")
	}
}

// A busy application writer must not delay telemetry ingestion.
func TestBusyApplicationWriterDoesNotBlockTelemetryCommit(t *testing.T) {
	application := newFixture(t, "application", "journal-busy-application-app")
	observation := newFixture(t, "observation", "journal-busy-application-obs")

	entered := make(chan struct{})
	release := make(chan struct{})
	applicationDone := make(chan error, 1)
	go func() {
		_, err := CommitOwner(application.ctx, application.store, application.journalID,
			[]EventSubmission{eventSubmission(application.manifest, 2, "application_recorded",
				map[string]any{"marker": "blocking"})},
			func(tx *sql.Tx) error {
				close(entered)
				<-release
				return nil
			})
		applicationDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("application writer never entered its owner-local transaction")
	}

	start := time.Now()
	telemetryEnvelopes := mustCommit(t, observation.ctx, observation.store, observation.journalID, nil,
		eventSubmission(observation.manifest, 2, "telemetry_received", map[string]any{"marker": "telemetry"}))
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("telemetry commit waited %s on a busy application writer", elapsed)
	}
	if len(telemetryEnvelopes) != 1 {
		t.Fatalf("telemetry commit returned %d envelopes", len(telemetryEnvelopes))
	}

	close(release)
	select {
	case err := <-applicationDone:
		if err != nil {
			t.Fatalf("application commit failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("application commit did not finish after release")
	}
}

// A crash before artifact installation cannot acknowledge a reference: the
// partial upload is not installed, is not registered, and no journal event may
// cite it.
func TestCrashBeforeArtifactInstallCannotAcknowledgeReference(t *testing.T) {
	f := newFixture(t, "observation", "journal-crash-before-install")
	wanted := []byte("bytes that must never become an acknowledged reference")
	reader := &failingReader{payload: wanted[:12], err: errors.New("simulated crash during upload")}

	if _, err := InstallArtifact(f.ctx, f.store, reader, "text/plain", accessPublic); err == nil {
		t.Fatal("truncated artifact installation unexpectedly succeeded")
	} else if !errors.Is(err, ErrInvalid) {
		t.Fatalf("truncated installation error = %v, want ErrInvalid", err)
	}

	digest := string(evidence_codec.HashBytes(wanted))
	var registered int
	if err := f.store.db.QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM artifacts WHERE digest = ?;`, digest).Scan(&registered); err != nil {
		t.Fatalf("count artifact registrations: %v", err)
	}
	if registered != 0 {
		t.Fatalf("crash-before-install registered %d artifact rows", registered)
	}
	reference := ArtifactReference{
		Digest: digest, SizeBytes: int64(len(wanted)),
		MediaType: "text/plain", OwnerDomain: f.domain, Access: accessPublic,
	}
	if _, err := ReadArtifact(f.ctx, f.store, reference); !errors.Is(err, ErrArtifactMissing) {
		t.Fatalf("ReadArtifact after failed installation = %v, want ErrArtifactMissing", err)
	}

	envelopes, err := CommitOwner(f.ctx, f.store, f.journalID,
		[]EventSubmission{eventSubmission(f.manifest, 2, "upload_recorded",
			map[string]any{"upload": "partial"}, reference)}, nil)
	if err == nil {
		t.Fatal("commit acknowledged an uninstalled artifact reference")
	}
	if !errors.Is(err, ErrArtifactMissing) {
		t.Fatalf("commit referenced missing bytes: %v", err)
	}
	if envelopes != nil {
		t.Fatalf("failed commit returned %d fabricated envelopes", len(envelopes))
	}
	loaded, err := LoadPrefix(f.ctx, f.store, f.prefix)
	if err != nil {
		t.Fatalf("load retained prefix: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("journal holds %d events after unacknowledged failure, want 1", len(loaded))
	}
	var events int
	if err := f.store.db.QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM journal_events WHERE journal_id = ?;`, f.journalID).Scan(&events); err != nil {
		t.Fatalf("count journal events: %v", err)
	}
	if events != 1 {
		t.Fatalf("durable journal holds %d events, want 1", events)
	}
}

// A crash after installation but before the owner commit leaves only an
// unreferenced orphan; collection removes it without touching retained roots.
func TestCrashAfterArtifactInstallBeforeCommitLeavesOnlyOrphan(t *testing.T) {
	f := newFixture(t, "observation", "journal-crash-after-install")
	orphan := installTestArtifact(t, f.ctx, f.store, []byte("installed but never referenced"), "text/plain", accessPublic)
	if _, err := ReadArtifact(f.ctx, f.store, orphan); err != nil {
		t.Fatalf("installed orphan is unreadable before collection: %v", err)
	}

	// Collection requires journaled proof: a fabricated prefix is rejected
	// and nothing is deleted.
	forged := JournalPrefix{
		JournalID:    f.journalID,
		LastSequence: 1,
		HeadHash:     "sha256:" + strings.Repeat("a", 64),
	}
	if _, err := CollectUnreachable(f.ctx, f.store, forged); err == nil {
		t.Fatal("collection accepted a fabricated journal proof")
	}
	if _, err := ReadArtifact(f.ctx, f.store, orphan); err != nil {
		t.Fatalf("rejected collection proof still deleted the orphan: %v", err)
	}

	collected, err := CollectUnreachable(f.ctx, f.store, f.prefix)
	if err != nil {
		t.Fatalf("CollectUnreachable: %v", err)
	}
	if len(collected) != 1 || string(collected[0]) != string(orphan.Digest) {
		t.Fatalf("collection returned %v, want only orphan %s", collected, orphan.Digest)
	}
	if _, err := ReadArtifact(f.ctx, f.store, orphan); !errors.Is(err, ErrArtifactMissing) {
		t.Fatalf("collected orphan read error = %v, want ErrArtifactMissing", err)
	}
	orphanPath, err := f.store.objectPath(orphan.Digest)
	if err != nil {
		t.Fatalf("orphan path: %v", err)
	}
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatalf("orphan bytes still present after collection: %v", err)
	}

	loaded, err := LoadPrefix(f.ctx, f.store, f.prefix)
	if err != nil {
		t.Fatalf("load retained prefix: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("retained journal holds %d events", len(loaded))
	}
	for _, ref := range loaded[0].Payload.ArtifactRefs {
		if ref.Digest == orphan.Digest {
			t.Fatal("an acknowledged journal event references the orphan artifact")
		}
	}
	if len(loaded[0].Payload.ArtifactRefs) == 0 {
		t.Fatal("admitted manifest reference is not retained")
	}
	if _, err := ReadArtifact(f.ctx, f.store, loaded[0].Payload.ArtifactRefs[0]); err != nil {
		t.Fatalf("collection deleted a retained manifest artifact: %v", err)
	}
}

// A crash after the owner commit but before the response reached the caller
// preserves a replayable response: the retry returns the original envelopes,
// does not re-run the effect, and appends nothing.
func TestCrashAfterCommitBeforeResponsePreservesReplayableResponse(t *testing.T) {
	f := newFixture(t, "application", "journal-crash-after-commit")
	submissions := []EventSubmission{
		eventSubmission(f.manifest, 2, "application_effect", map[string]any{"step": "one"}),
		eventSubmission(f.manifest, 3, "application_effect", map[string]any{"step": "two"}),
	}
	committed := mustCommit(t, f.ctx, f.store, f.journalID, nil, submissions...)
	acknowledged := prefixThrough(committed)

	// Simulate a crash after durable commit and before the response was
	// observed: restart the store and retry the identical command.
	f.reopen()
	retried, err := CommitOwner(f.ctx, f.store, f.journalID, submissions, func(tx *sql.Tx) error {
		return errors.New("the owner effect must not run for a replay")
	})
	if err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
	if canonicalEnvelopes(t, committed) != canonicalEnvelopes(t, retried) {
		t.Fatal("replay returned different envelopes than the original acknowledgement")
	}
	loaded, err := LoadPrefix(f.ctx, f.store, acknowledged)
	if err != nil {
		t.Fatalf("load acknowledged prefix: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("journal holds %d events after replay, want 3", len(loaded))
	}
	var events int
	if err := f.store.db.QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM journal_events WHERE journal_id = ?;`, f.journalID).Scan(&events); err != nil {
		t.Fatalf("count journal events: %v", err)
	}
	if events != 3 {
		t.Fatalf("durable journal holds %d events after replay, want 3", events)
	}

	conflicting := []EventSubmission{
		eventSubmission(f.manifest, 3, "application_effect", map[string]any{"step": "different bytes"}),
	}
	if _, err := CommitOwner(f.ctx, f.store, f.journalID, conflicting, nil); !errors.Is(err, ErrIntegrityConflict) {
		t.Fatalf("changed bytes under a committed producer sequence = %v, want ErrIntegrityConflict", err)
	}
}

// Collection is fenced against concurrent pin creation: a successful pin is
// only recorded when its bytes are present, and no retained root or
// transitive dependency is ever deleted.
func TestGarbageCollectionIsFencedAgainstConcurrentPinCreation(t *testing.T) {
	f := newFixture(t, "diagnostic", "journal-gc-fence")
	support := EvidenceRef{
		JournalID: f.journalID,
		Sequence:  f.admission[0].Sequence,
		EventID:   f.admission[0].EventID,
		EventHash: f.admission[0].EventHash,
		Pointer:   "",
	}

	const rootCount = 6
	type pinnedPair struct {
		root string
		dep  string
	}
	var pinsMu sync.Mutex
	pinned := make([]pinnedPair, 0, rootCount)
	pinErrors := make(chan error, rootCount)

	// Establish that collection runs against this retained proof.
	if _, err := CollectUnreachable(f.ctx, f.store, f.prefix); err != nil {
		t.Fatalf("initial collection: %v", err)
	}

	// Fencing is observable without timing: bytes collected before a pin
	// attempt cannot be pinned, so no durable pin ever claims protection for
	// an object the collector removed.
	victim := installTestArtifact(t, f.ctx, f.store, []byte("collected before pinning"), "text/plain", accessPublic)
	if _, err := CollectUnreachable(f.ctx, f.store, f.prefix); err != nil {
		t.Fatalf("collection of victim: %v", err)
	}
	if err := RetainRoot(f.ctx, f.store, victim, nil, support); !errors.Is(err, ErrArtifactMissing) {
		t.Fatalf("pin on collected bytes = %v, want ErrArtifactMissing", err)
	}
	var victimPins int
	if err := f.store.db.QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM retention_pins WHERE root_digest = ?;`, victim.Digest).Scan(&victimPins); err != nil {
		t.Fatalf("count victim pins: %v", err)
	}
	if victimPins != 0 {
		t.Fatal("a pin was recorded for collected bytes")
	}

	gcDone := make(chan struct{})
	var gcRuns atomic.Int32
	gcErrors := make(chan error, 1)
	go func() {
		defer close(gcDone)
		// A bounded collection burst overlaps pin creation. Collection is
		// allowed to win a race for an as-yet-unpinned root: the pin then
		// fails rather than claiming protection for absent bytes, and the
		// caller re-installs and retries. Once the burst ends, every pin
		// attempt can complete, so the test terminates deterministically.
		for range 25 {
			if _, err := CollectUnreachable(f.ctx, f.store, f.prefix); err != nil {
				select {
				case gcErrors <- err:
				default:
				}
				return
			}
			gcRuns.Add(1)
			time.Sleep(500 * time.Microsecond)
		}
	}()

	var pinning sync.WaitGroup
	for index := range rootCount {
		pinning.Add(1)
		go func(index int) {
			defer pinning.Done()
			rootContent := []byte(fmt.Sprintf("retained-root-%d", index))
			depContent := []byte(fmt.Sprintf("retained-dependency-%d", index))
			for range 300 {
				rootRef, err := InstallArtifact(f.ctx, f.store, bytes.NewReader(rootContent), "text/plain", accessPublic)
				if err != nil {
					if retryableArtifactRace(err) {
						time.Sleep(300 * time.Microsecond)
						continue
					}
					pinErrors <- fmt.Errorf("install root %d: %w", index, err)
					return
				}
				depRef, err := InstallArtifact(f.ctx, f.store, bytes.NewReader(depContent), "text/plain", accessPublic)
				if err != nil {
					if retryableArtifactRace(err) {
						time.Sleep(300 * time.Microsecond)
						continue
					}
					pinErrors <- fmt.Errorf("install dependency %d: %w", index, err)
					return
				}
				if err := RetainRoot(f.ctx, f.store, rootRef, []ArtifactReference{depRef}, support); err != nil {
					if retryableArtifactRace(err) {
						time.Sleep(300 * time.Microsecond)
						continue
					}
					pinErrors <- fmt.Errorf("retain root %d: %w", index, err)
					return
				}
				pinsMu.Lock()
				pinned = append(pinned, pinnedPair{root: rootRef.Digest, dep: depRef.Digest})
				pinsMu.Unlock()
				return
			}
			pinErrors <- fmt.Errorf("root %d was never pinned under concurrent collection", index)
		}(index)
	}
	pinning.Wait()
	<-gcDone
	close(pinErrors)
	for err := range pinErrors {
		t.Fatalf("pin creation failed: %v", err)
	}
	select {
	case err := <-gcErrors:
		t.Fatalf("concurrent collection failed: %v", err)
	default:
	}
	if gcRuns.Load() == 0 {
		t.Fatal("collection never ran during the pin race")
	}

	pinsMu.Lock()
	finalPins := append([]pinnedPair(nil), pinned...)
	pinsMu.Unlock()
	if len(finalPins) != rootCount {
		t.Fatalf("pinned %d roots, want %d", len(finalPins), rootCount)
	}

	// Final collection must not delete any successfully retained root or
	// transitive dependency.
	collected, err := CollectUnreachable(f.ctx, f.store, f.prefix)
	if err != nil {
		t.Fatalf("final collection: %v", err)
	}
	for _, digest := range collected {
		for _, pin := range finalPins {
			if string(digest) == pin.root || string(digest) == pin.dep {
				t.Fatalf("collection deleted retained artifact %s", digest)
			}
		}
	}
	for _, pin := range finalPins {
		rootRef := ArtifactReference{Digest: pin.root}
		if _, err := ReadArtifact(f.ctx, f.store, rootRef); err != nil {
			t.Fatalf("retained root %s is unreadable after collection: %v", pin.root, err)
		}
		depRef := ArtifactReference{Digest: pin.dep}
		if _, err := ReadArtifact(f.ctx, f.store, depRef); err != nil {
			t.Fatalf("retained dependency %s is unreadable after collection: %v", pin.dep, err)
		}
	}
}

// Cross-database transactions and attached commits are rejected: the owner
// connection authorizer denies ATTACH, and the commit callback cannot widen
// the transaction to a peer database.
func TestCrossDatabaseTransactionsAndAttachedCommitsAreRejected(t *testing.T) {
	application := newFixture(t, "application", "journal-cross-db-application")
	observation := newFixture(t, "observation", "journal-cross-db-observation")

	// The connection-level authorizer denies ATTACH even outside a
	// transaction, so no code path can open a peer database.
	if _, err := application.store.db.ExecContext(application.ctx,
		`ATTACH DATABASE ? AS peer;`, observation.dbPath); err == nil {
		t.Fatal("ATTACH DATABASE was not rejected")
	}
	assertDatabaseListOnlyMain(t, application.ctx, application.store)

	// A transaction callback cannot attach a peer database inside the owner
	// commit: the statement is rejected and the whole commit rolls back.
	attempted := false
	envelopes, err := CommitOwner(application.ctx, application.store, application.journalID,
		[]EventSubmission{eventSubmission(application.manifest, 2, "cross_database_attempt",
			map[string]any{"surface": "effect"})},
		func(tx *sql.Tx) error {
			attempted = true
			_, attachErr := tx.Exec(`ATTACH DATABASE ? AS peer;`, observation.dbPath)
			return attachErr
		})
	if err == nil {
		t.Fatal("commit effect attached a peer database")
	}
	if !attempted {
		t.Fatal("commit effect did not run")
	}
	if envelopes != nil {
		t.Fatalf("rejected cross-database commit returned %d envelopes", len(envelopes))
	}

	// A qualified write to a peer database is rejected as well.
	if _, err := CommitOwner(application.ctx, application.store, application.journalID,
		[]EventSubmission{eventSubmission(application.manifest, 2, "cross_database_attempt",
			map[string]any{"surface": "qualified-write"})},
		func(tx *sql.Tx) error {
			_, writeErr := tx.Exec(`INSERT INTO peer.journal_events (journal_id, sequence) VALUES ('peer', 1);`)
			return writeErr
		}); err == nil {
		t.Fatal("qualified cross-database write was accepted")
	}

	// The owner-local journal did not advance, and no peer database is
	// attached to the application connection.
	loaded, err := LoadPrefix(application.ctx, application.store, application.prefix)
	if err != nil {
		t.Fatalf("load application prefix: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("application journal advanced during rejected cross-database attempts: %d events", len(loaded))
	}
	assertDatabaseListOnlyMain(t, application.ctx, application.store)
}

// Acknowledged owner writes use WAL and synchronous=FULL, and remain readable
// after the store is reopened.
func TestAcknowledgedOwnerWritesUseWALAndFullSynchronization(t *testing.T) {
	f := newFixture(t, "application", "journal-durability")

	envelopes := mustCommit(t, f.ctx, f.store, f.journalID, nil,
		eventSubmission(f.manifest, 2, "application_effect", map[string]any{"durable": "yes"}))
	acknowledged := prefixThrough(envelopes)

	var mode string
	if err := f.store.db.QueryRowContext(f.ctx, `PRAGMA journal_mode;`).Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
	var synchronous int64
	if err := f.store.db.QueryRowContext(f.ctx, `PRAGMA synchronous;`).Scan(&synchronous); err != nil {
		t.Fatalf("read synchronous: %v", err)
	}
	if synchronous != 2 {
		t.Fatalf("synchronous = %d, want FULL (2)", synchronous)
	}
	if stats := f.store.db.Stats(); stats.MaxOpenConnections != 1 {
		t.Fatalf("store owns %d connections, want exactly one writer connection", stats.MaxOpenConnections)
	}

	f.reopen()
	loaded, err := LoadPrefix(f.ctx, f.store, acknowledged)
	if err != nil {
		t.Fatalf("acknowledged prefix is unreadable after reopen: %v", err)
	}
	if int64(len(loaded)) != acknowledged.LastSequence {
		t.Fatalf("reopened journal holds %d events, want %d", len(loaded), acknowledged.LastSequence)
	}
	if loaded[len(loaded)-1].EventHash != acknowledged.HeadHash {
		t.Fatal("reopened journal head does not match the acknowledged head")
	}
}

// A storage failure stops new admission without fabricating evidence; the
// failure is not papered over when the disk becomes writable again, and a
// restart supplies a clean admission path with no invented events.
func TestStorageFailureStopsAdmissionWithoutFabricatedEvidence(t *testing.T) {
	f := newFixture(t, "observation", "journal-storage-failure")
	submission := eventSubmission(f.manifest, 2, "observation_recorded", map[string]any{"phase": "after-failure"})

	if _, err := f.store.db.ExecContext(f.ctx, `PRAGMA query_only = ON;`); err != nil {
		t.Fatalf("make connection read-only: %v", err)
	}
	envelopes, err := CommitOwner(f.ctx, f.store, f.journalID, []EventSubmission{submission}, nil)
	if err == nil {
		t.Fatal("commit succeeded despite a durable storage failure")
	}
	if !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("storage failure error = %v, want ErrStorageUnavailable", err)
	}
	if envelopes != nil {
		t.Fatalf("storage failure returned %d fabricated envelopes", len(envelopes))
	}

	if _, err := f.store.db.ExecContext(f.ctx, `PRAGMA query_only = OFF;`); err != nil {
		t.Fatalf("restore connection writability: %v", err)
	}
	if _, err := CommitOwner(f.ctx, f.store, f.journalID, []EventSubmission{submission}, nil); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("admission resumed without recovery: %v", err)
	}

	// Reads remain available and contain no fabricated evidence.
	loaded, err := LoadPrefix(f.ctx, f.store, f.prefix)
	if err != nil {
		t.Fatalf("load retained prefix after storage failure: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("journal holds %d events after failed admission, want 1", len(loaded))
	}
	var events int
	if err := f.store.db.QueryRowContext(f.ctx,
		`SELECT COUNT(*) FROM journal_events WHERE journal_id = ?;`, f.journalID).Scan(&events); err != nil {
		t.Fatalf("count journal events: %v", err)
	}
	if events != 1 {
		t.Fatalf("durable journal holds %d events, want 1", events)
	}

	// A fresh owner instance is a new, trustworthy durability boundary and
	// admits the same operation normally.
	f.reopen()
	if _, err := CommitOwner(f.ctx, f.store, f.journalID, []EventSubmission{submission}, nil); err != nil {
		t.Fatalf("restarted store refused admission: %v", err)
	}
}

// A stale lease authority epoch cannot commit or charge a retry twice: tokens
// are fenced to the current epoch and boot, and one retry generation is
// charged at most once.
func TestStaleLeaseEpochCannotCommitOrChargeRetryTwice(t *testing.T) {
	f := newFixture(t, "application", "journal-stale-lease")

	token1, err := f.store.ClaimLease(f.ctx, "resource-one", 1, 3, time.Minute)
	if err != nil {
		t.Fatalf("ClaimLease: %v", err)
	}
	leased := mustCommitLeased(t, f, token1,
		eventSubmission(f.manifest, 2, "leased_effect", map[string]any{"attempt": "first"}))
	leasedPrefix := prefixThrough(leased)

	// A completed lease cannot commit a second effect.
	if _, err := f.store.CommitLeased(f.ctx, f.journalID, token1,
		[]EventSubmission{eventSubmission(f.manifest, 3, "leased_effect", map[string]any{"attempt": "second"})}, nil); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("completed lease commit error = %v, want ErrStaleLease", err)
	}
	loaded, err := LoadPrefix(f.ctx, f.store, leasedPrefix)
	if err != nil {
		t.Fatalf("load leased prefix: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("journal holds %d events after stale completion, want 2", len(loaded))
	}

	// Restarting the authority durably fences the old epoch before any lease
	// can be reclaimed: the old token can neither commit nor charge.
	f.reopen()
	if _, err := f.store.CommitLeased(f.ctx, f.journalID, token1,
		[]EventSubmission{eventSubmission(f.manifest, 3, "leased_effect", map[string]any{"attempt": "after-restart"})}, nil); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pre-restart token commit error = %v, want ErrStaleLease", err)
	}
	loaded, err = LoadPrefix(f.ctx, f.store, leasedPrefix)
	if err != nil {
		t.Fatalf("load leased prefix after restart: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("journal holds %d events after pre-restart token, want 2", len(loaded))
	}

	token2, err := f.store.ClaimLease(f.ctx, "resource-two", 1, 3, time.Minute)
	if err != nil {
		t.Fatalf("ClaimLease after restart: %v", err)
	}
	if token2.AuthorityEpoch != token1.AuthorityEpoch+1 {
		t.Fatalf("authority epoch = %d after restart, want %d", token2.AuthorityEpoch, token1.AuthorityEpoch+1)
	}
	if token2.EntityRevision != 1 {
		t.Fatalf("first claim entity revision = %d, want 1", token2.EntityRevision)
	}

	count, err := f.store.ChargeFailedAttempt(f.ctx, token2, "native_timeout")
	if err != nil {
		t.Fatalf("first retry charge: %v", err)
	}
	if count != 1 {
		t.Fatalf("first retry charge count = %d, want 1", count)
	}
	count, err = f.store.ChargeFailedAttempt(f.ctx, token2, "native_timeout")
	if err != nil {
		t.Fatalf("duplicate retry charge: %v", err)
	}
	if count != 1 {
		t.Fatalf("duplicate retry charge count = %d, want 1: a generation was charged twice", count)
	}

	// A second restart fences token2; the charged generation stays charged
	// exactly once and the stale token cannot append events.
	f.reopen()
	if _, err := f.store.ChargeFailedAttempt(f.ctx, token2, "native_timeout"); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pre-restart token charge error = %v, want ErrStaleLease", err)
	}
	var retryCount int64
	if err := f.store.db.QueryRowContext(f.ctx,
		`SELECT retry_count FROM work_leases WHERE resource_id = ?;`, "resource-two").Scan(&retryCount); err != nil {
		t.Fatalf("read retry count: %v", err)
	}
	if retryCount != 1 {
		t.Fatalf("durable retry count = %d, want 1", retryCount)
	}
	if _, err := f.store.CommitLeased(f.ctx, f.journalID, token2,
		[]EventSubmission{eventSubmission(f.manifest, 3, "leased_effect", map[string]any{"attempt": "fenced"})}, nil); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("pre-restart token commit after second restart = %v, want ErrStaleLease", err)
	}

	token3, err := f.store.ClaimLease(f.ctx, "resource-two", 2, 3, time.Minute)
	if err != nil {
		t.Fatalf("ClaimLease after second restart: %v", err)
	}
	if token3.EntityRevision != token2.EntityRevision+1 {
		t.Fatalf("reclaimed entity revision = %d, want %d", token3.EntityRevision, token2.EntityRevision+1)
	}
	final := mustCommitLeased(t, f, token3,
		eventSubmission(f.manifest, 3, "leased_effect", map[string]any{"attempt": "current"}))
	if final[0].Sequence != 3 {
		t.Fatalf("leased commit appended sequence %d, want 3", final[0].Sequence)
	}
}

func mustCommitLeased(t *testing.T, f *fixture, token LeaseToken, events ...EventSubmission) []JournalEnvelope {
	t.Helper()
	envelopes, err := f.store.CommitLeased(f.ctx, f.journalID, token, events, nil)
	if err != nil {
		t.Fatalf("CommitLeased: %v", err)
	}
	return envelopes
}
