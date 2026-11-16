// Package owner_store implements the tier-3 Hellscape owner-local durable
// store.
//
// An OwnerStore is exactly one SQLite database (WAL journal, synchronous=FULL)
// plus one content-addressed artifact root, owned by exactly one owner domain.
// Each store has its own connection, writer queue, transaction admission,
// journal sequencing, artifact installation, and publication outbox. No store
// acquires another owner's write lock or waits for a peer's transaction,
// acknowledgement, or large-payload serialization: database separation is
// implemented here by never sharing a connection, mutex, or transaction across
// stores. ATTACH DATABASE is denied on every connection this package opens, and
// the package offers no API that spans two databases.
//
// Commits implement the EK-ATOMICITY, EK-JOURNAL, OWD-LOCAL-COMMIT and
// OWD-REVISION sourcing rules at the owner durability boundary: the caller's
// admitted submissions, the owner-local reducer effect, journal events,
// outbox metadata, and a replayable response are written in one SQLite
// transaction and acknowledged only after COMMIT returns. Artifact bytes are
// installed (write, hash, flush, atomic rename, directory sync) before any
// database reference may be acknowledged. Artifact references are only
// accepted when the exact bytes are durable and registered.
//
// Retention follows EK-ARTIFACTS and seam 11.6: retained journal prefixes and
// explicit retention pins protect artifact identities and their transitive
// dependencies. Collection requires a current, journal-derived proof prefix,
// runs under an owner-local write fence, and deletes only artifacts that are
// unreachable from every retained root. TTL expiry or a newer publication is
// never a collection trigger here.
package owner_store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	authority "authority"
	clock_rules "clock_rules"
	evidence_codec "evidence_codec"
	journal_rules "journal_rules"
	sqlite "modernc.org/sqlite"
)

// Shared wire types are aliased so callers use the same kernels this module
// consumes: journal_rules for envelopes/prefixes/artifacts and evidence_codec
// for digests.
type (
	// Digest is the shared content digest ("sha256:" + 64 lowercase hex).
	Digest = evidence_codec.Digest
	// MissingEnvelope is the typed EK Missing value.
	MissingEnvelope = journal_rules.MissingEnvelope
	// TimePoint is a coordinate in a registered monotonic clock.
	TimePoint = journal_rules.TimePoint
	// ClockDescriptor registers one clock lifetime.
	ClockDescriptor = journal_rules.ClockDescriptor
	// Measurement is the EK Measurement record carried in payloads.
	Measurement = journal_rules.Measurement
	// Manifest is the admitted journal manifest.
	Manifest = journal_rules.Manifest
	// Payload is the closed evidence payload.
	Payload = journal_rules.Payload
	// JournalEnvelope is the complete stored journal event envelope.
	JournalEnvelope = journal_rules.JournalEnvelope
	// JournalPrefix is an immutable journal prefix.
	JournalPrefix = journal_rules.JournalPrefix
	// EvidenceRef cites one retained journal event coordinate.
	EvidenceRef = journal_rules.EvidenceRef
	// ArtifactReference is an immutable byte identity plus resolver metadata.
	ArtifactReference = journal_rules.ArtifactReference
)

// NewMissing builds a typed Missing envelope with a null value and reason.
func NewMissing(reason string) MissingEnvelope { return journal_rules.NewMissing(reason) }

// EventSubmission is the ingress shape an authenticated caller submits to
// CommitOwner. It carries no server-assigned authority field: producer
// identity, provenance, owner_domain, role, assertion_kind, event ID,
// sequence, receipt time, manifest pin, and hashes are all assigned by this
// owner-local ingestion authority. Submissions are validated structurally
// before any authority value is derived from them.
type EventSubmission struct {
	// ProducerSequence is the caller's per-producer ordering claim: a
	// nonnegative integer or a typed Missing envelope. It is required (an
	// in-band null is rejected).
	ProducerSequence any `json:"producer_sequence"`
	// EventKind is a nonempty event identifier from the admitted registry.
	EventKind string `json:"event_kind"`
	// EventSchemaVersion names the event document version.
	EventSchemaVersion string `json:"event_schema_version"`
	// OccurredAt is a registered TimePoint or a typed Missing envelope.
	OccurredAt any `json:"occurred_at"`
	// Payload is the closed evidence payload.
	Payload Payload `json:"payload"`
}

// LeaseToken is the fencing token returned by ClaimLease. Every field is
// authority-assigned; a caller cannot construct a valid token for a resource
// it did not claim in the current authority epoch and boot.
type LeaseToken struct {
	ResourceID     string
	LeaseID        string
	AuthorityEpoch int64
	BootID         string
	ClockID        string
	Origin         string
	ExpiresAtMs    float64
	EntityRevision int64
	InputRevision  int64
	GenerationID   string
}

// Sentinel errors let callers distinguish durable-storage failure, integrity
// conflicts, lost or absent artifact bytes, stale lease authority, and
// prefix/proof mismatches without parsing messages.
var (
	ErrInvalid            = errors.New("owner_store: invalid input")
	ErrUnauthorized       = errors.New("owner_store: unauthorized")
	ErrClosed             = errors.New("owner_store: store is closed")
	ErrStorageUnavailable = errors.New("owner_store: durable storage unavailable: admission halted")
	ErrArtifactMissing    = errors.New("owner_store: artifact bytes are not installed")
	ErrArtifactLost       = errors.New("owner_store: retained artifact bytes are lost")
	ErrIntegrityConflict  = errors.New("owner_store: integrity conflict")
	ErrStaleLease         = errors.New("owner_store: stale lease authority epoch or token")
	ErrLeaseHeld          = errors.New("owner_store: resource lease is held")
	ErrJournalUnknown     = errors.New("owner_store: unknown journal")
	ErrPrefixMismatch     = errors.New("owner_store: journal prefix does not match retained events")
	ErrCrossDatabase      = errors.New("owner_store: cross-database access denied")
)

// Store layout and policy constants.
const (
	storeSchemaVersion  = "owner_store/0.1.0"
	recordSchemaVersion = "0.1.0"
	journalRecordType   = "journal_event"

	// maxArtifactBytes bounds the temporary spool file for one artifact.
	maxArtifactBytes = int64(1) << 30

	accessPublic     = "public"
	accessRestricted = "restricted"

	opCommit         = "commit"
	opRead           = "read"
	opInstall        = "install_artifact"
	opReadArtifact   = "read_artifact"
	opReadRestricted = "read_restricted_artifact"
	opRetain         = "retain_root"
	opCollect        = "collect_unreachable"
	opClaimLease     = "claim_lease"
	opCommitLeased   = "commit_leased"
	opChargeRetry    = "charge_retry"

	leaseAuthorityClockID = "lease-authority-clock"
	leaseAuthorityOrigin  = clock_rules.OriginEngineMeasured
	leaseAuthorityBasis   = clock_rules.BasisMonotonicOffset
	leaseAuthorityUnit    = "ms"

	leaseStateHeld      = "held"
	leaseStateCompleted = "completed"
	leaseStateFenced    = "fenced"
	leaseStateExhausted = "exhausted"
)

// OwnerStore is one owner-local durable boundary: one SQLite database plus one
// content-addressed artifact root owned by exactly one owner domain. The
// database handle and artifact path are private; no control or application API
// exposes them.
type OwnerStore struct {
	db           *sql.DB
	artifactRoot string
	ownerDomain  string

	startedAt time.Time
	halted    atomic.Bool
	closed    atomic.Bool
}

// ownerQueryer is satisfied by *sql.DB and *sql.Tx: all owner-local statements
// run through one of the two, never a peer connection.
type ownerQueryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ---------------------------------------------------------------------------
// Opening and durability configuration.
// ---------------------------------------------------------------------------

var attachGuardOnce sync.Once

// installAttachGuard registers one connection hook for every SQLite
// connection this package opens. The hook denies ATTACH DATABASE, so no owner
// commit can open a second database or start a transaction that spans one.
func installAttachGuard() {
	attachGuardOnce.Do(func() {
		sqlite.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, _ string) error {
			registerer, ok := conn.(sqlite.AuthorizerRegisterer)
			if !ok {
				return fmt.Errorf("%w: sqlite connection does not support an authorizer", ErrCrossDatabase)
			}
			return registerer.RegisterAuthorizer(denyAttachAuthorizer)
		})
	})
}

func denyAttachAuthorizer(action sqlite.AuthorizerActionCode, _, _, _, _ string) sqlite.AuthorizerReturnCode {
	if action == sqlite.AuthAttach {
		return sqlite.AuthorizerDeny
	}
	return sqlite.AuthorizerOK
}

// sqliteDSN builds a file DSN that pins WAL journaling, FULL synchronization,
// immediate write transactions, foreign-key enforcement, and a bounded busy
// timeout for every physical connection this store opens.
func sqliteDSN(path string) string {
	var b strings.Builder
	b.WriteString("file:")
	b.WriteString(filepath.ToSlash(path))
	b.WriteString("?_journal_mode=WAL")
	b.WriteString("&_synchronous=FULL")
	b.WriteString("&_foreign_keys=ON")
	b.WriteString("&_busy_timeout=5000")
	b.WriteString("&_txlock=immediate")
	return b.String()
}

// OpenOwner opens (or creates) the owner-local database at databasePath with
// WAL journaling and synchronous=FULL, then ensures the content-addressed
// artifact root exists. Each call creates an independent connection and
// durability boundary; no state is shared between stores. Opening an existing
// database advances the durable lease-authority epoch before any lease can be
// reclaimed, fencing tokens issued by an earlier authority instance.
func OpenOwner(databasePath string, artifactRoot string, ownerDomain string) (*OwnerStore, error) {
	if strings.TrimSpace(databasePath) == "" {
		return nil, fmt.Errorf("%w: database path is required", ErrInvalid)
	}
	if strings.TrimSpace(artifactRoot) == "" {
		return nil, fmt.Errorf("%w: artifact root is required", ErrInvalid)
	}
	if strings.TrimSpace(ownerDomain) == "" {
		return nil, fmt.Errorf("%w: owner domain is required", ErrInvalid)
	}
	absDB, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve database path: %v", ErrInvalid, err)
	}
	absRoot, err := filepath.Abs(artifactRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve artifact root: %v", ErrInvalid, err)
	}
	if err := os.MkdirAll(filepath.Dir(absDB), 0o755); err != nil {
		return nil, fmt.Errorf("owner_store: create database directory: %w", err)
	}
	for _, dir := range []string{absRoot, filepath.Join(absRoot, "objects"), filepath.Join(absRoot, "tmp")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("owner_store: create artifact directory: %w", err)
		}
	}
	installAttachGuard()
	db, err := sql.Open("sqlite", sqliteDSN(absDB))
	if err != nil {
		return nil, fmt.Errorf("owner_store: open %s: %w", absDB, err)
	}
	// One store owns exactly one connection and therefore one writer queue.
	// database/sql still pools, so cap it: no second connection may silently
	// become a second writer or a cross-owner transaction participant.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	store := &OwnerStore{db: db, artifactRoot: absRoot, ownerDomain: ownerDomain, startedAt: time.Now()}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("owner_store: ping %s: %w", absDB, err)
	}
	if err := store.verifyDurabilitySettings(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.initSchema(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// verifyDurabilitySettings refuses to acknowledge writes on a connection whose
// journal mode or synchronization level is weaker than the owner boundary
// promises.
func (s *OwnerStore) verifyDurabilitySettings(ctx context.Context) error {
	var mode string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode;`).Scan(&mode); err != nil {
		return fmt.Errorf("owner_store: read journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		return fmt.Errorf("owner_store: journal_mode %q is not WAL", mode)
	}
	var sync int64
	if err := s.db.QueryRowContext(ctx, `PRAGMA synchronous;`).Scan(&sync); err != nil {
		return fmt.Errorf("owner_store: read synchronous: %w", err)
	}
	if sync != 2 {
		return fmt.Errorf("owner_store: synchronous setting %d is not FULL (2)", sync)
	}
	return nil
}

// schemaStatements is the owner-local schema. Every table belongs to this
// owner's database; none is shared with a peer.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS owner_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);`,
	`CREATE TABLE IF NOT EXISTS journals (
		journal_id TEXT PRIMARY KEY,
		run_id TEXT NOT NULL,
		owner_domain TEXT NOT NULL,
		manifest_hash TEXT NOT NULL,
		manifest_json BLOB NOT NULL,
		head_sequence INTEGER NOT NULL,
		head_hash TEXT NOT NULL,
		created_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS journal_events (
		journal_id TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		event_id TEXT NOT NULL,
		event_hash TEXT NOT NULL,
		event_kind TEXT NOT NULL,
		producer_id TEXT NOT NULL,
		producer_sequence INTEGER,
		envelope_json BLOB NOT NULL,
		recorded_at TEXT NOT NULL,
		PRIMARY KEY (journal_id, sequence),
		UNIQUE (journal_id, event_id)
	);`,
	`CREATE UNIQUE INDEX IF NOT EXISTS journal_events_producer
		ON journal_events(journal_id, producer_id, producer_sequence)
		WHERE producer_sequence IS NOT NULL;`,
	`CREATE TABLE IF NOT EXISTS commit_receipts (
		receipt_key TEXT PRIMARY KEY,
		journal_id TEXT NOT NULL,
		last_sequence INTEGER NOT NULL,
		envelope_json BLOB NOT NULL,
		created_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS outbox (
		journal_id TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		event_hash TEXT NOT NULL,
		published INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL,
		PRIMARY KEY (journal_id, sequence)
	);`,
	`CREATE TABLE IF NOT EXISTS artifacts (
		digest TEXT PRIMARY KEY,
		size_bytes INTEGER NOT NULL,
		media_type TEXT NOT NULL,
		owner_domain TEXT NOT NULL,
		access TEXT NOT NULL,
		installed_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS artifact_dependencies (
		root_digest TEXT NOT NULL,
		dependency_digest TEXT NOT NULL,
		PRIMARY KEY (root_digest, dependency_digest)
	);`,
	`CREATE TABLE IF NOT EXISTS retention_pins (
		root_digest TEXT PRIMARY KEY,
		support_journal TEXT NOT NULL,
		support_sequence INTEGER NOT NULL,
		support_event_id TEXT NOT NULL,
		support_event_hash TEXT NOT NULL,
		support_pointer TEXT NOT NULL,
		fence_generation INTEGER NOT NULL,
		pinned_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS retention_generation (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		generation INTEGER NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS gc_runs (
		generation INTEGER PRIMARY KEY,
		proof_journal TEXT NOT NULL,
		proof_last_sequence INTEGER NOT NULL,
		proof_head_hash TEXT NOT NULL,
		collected INTEGER NOT NULL,
		created_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS clock_offsets (
		clock_id TEXT NOT NULL,
		boot_id TEXT NOT NULL,
		offset_ms REAL NOT NULL,
		PRIMARY KEY (clock_id, boot_id)
	);`,
	`CREATE TABLE IF NOT EXISTS lease_authority (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		authority_epoch INTEGER NOT NULL,
		boot_id TEXT NOT NULL,
		clock_id TEXT NOT NULL,
		origin TEXT NOT NULL,
		source_id TEXT NOT NULL,
		basis TEXT NOT NULL,
		unit TEXT NOT NULL,
		registered_at TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS work_leases (
		resource_id TEXT PRIMARY KEY,
		lease_id TEXT NOT NULL,
		authority_epoch INTEGER NOT NULL,
		boot_id TEXT NOT NULL,
		clock_id TEXT NOT NULL,
		origin TEXT NOT NULL,
		leased_at_ms REAL NOT NULL,
		expires_at_ms REAL NOT NULL,
		entity_revision INTEGER NOT NULL,
		input_revision INTEGER NOT NULL,
		generation_id TEXT NOT NULL,
		lease_state TEXT NOT NULL,
		retry_count INTEGER NOT NULL,
		max_retries INTEGER NOT NULL,
		last_failure_reason TEXT NOT NULL,
		completed_at TEXT NOT NULL DEFAULT ''
	);`,
	`CREATE TABLE IF NOT EXISTS retry_charges (
		resource_id TEXT NOT NULL,
		generation_id TEXT NOT NULL,
		lease_id TEXT NOT NULL,
		reason TEXT NOT NULL,
		charged_at TEXT NOT NULL,
		PRIMARY KEY (resource_id, generation_id)
	);`,
}

func (s *OwnerStore) initSchema(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("owner_store: begin schema transaction: %w", err)
	}
	defer tx.Rollback()
	for _, stmt := range schemaStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("owner_store: create schema: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO retention_generation (id, generation) VALUES (1, 0);`); err != nil {
		return fmt.Errorf("owner_store: seed retention generation: %w", err)
	}
	// Record the owner identity once; a later open may not relabel the store.
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT v FROM owner_meta WHERE k = 'owner_domain';`).Scan(&existing)
	switch {
	case err == sql.ErrNoRows:
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO owner_meta (k, v) VALUES ('owner_domain', ?), ('schema_version', ?);`,
			s.ownerDomain, storeSchemaVersion); err != nil {
			return fmt.Errorf("owner_store: record owner metadata: %w", err)
		}
	case err != nil:
		return fmt.Errorf("owner_store: read owner metadata: %w", err)
	case existing != s.ownerDomain:
		return fmt.Errorf("%w: database belongs to owner domain %q, not %q", ErrUnauthorized, existing, s.ownerDomain)
	}

	// EK-LEASE-RESTART: durably fence the old authority epoch before any
	// lease can be reclaimed under this instance. Offsets from the old boot
	// are never compared with the new boot.
	var epoch int64
	err = tx.QueryRowContext(ctx, `SELECT authority_epoch FROM lease_authority WHERE id = 1;`).Scan(&epoch)
	switch {
	case err == sql.ErrNoRows:
		epoch = 1
	case err != nil:
		return fmt.Errorf("owner_store: read lease authority: %w", err)
	default:
		epoch++
	}
	bootID, err := newID("boot")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO lease_authority
		(id, authority_epoch, boot_id, clock_id, origin, source_id, basis, unit, registered_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?);`,
		epoch, bootID, leaseAuthorityClockID, leaseAuthorityOrigin,
		"owner-store", leaseAuthorityBasis, leaseAuthorityUnit, nowUTC()); err != nil {
		return fmt.Errorf("owner_store: register lease authority: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE work_leases SET lease_state = ?
		WHERE lease_state = ? AND authority_epoch < ?;`, leaseStateFenced, leaseStateHeld, epoch); err != nil {
		return fmt.Errorf("owner_store: fence stale leases: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("owner_store: commit schema: %w", err)
	}
	return nil
}

// Close releases this store's connection. It is idempotent.
func (s *OwnerStore) Close() error {
	if s == nil {
		return nil
	}
	if s.closed.Swap(true) {
		return nil
	}
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// Preconditions, authorization, and failure classification.
// ---------------------------------------------------------------------------

func (s *OwnerStore) checkOpen() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("%w: nil store", ErrInvalid)
	}
	if s.closed.Load() {
		return ErrClosed
	}
	return nil
}

// checkWritable refuses all new owner writes once a durability failure has
// been observed: admission stops where durability cannot be trusted. Reads are
// not halted, so retained evidence remains inspectable without fabricating a
// new acknowledgement.
func (s *OwnerStore) checkWritable() error {
	if err := s.checkOpen(); err != nil {
		return err
	}
	if s.halted.Load() {
		return ErrStorageUnavailable
	}
	return nil
}

func (s *OwnerStore) authorize(ctx context.Context, operation string, resourceID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authority.Authorize(ctx, s.ownerDomain, operation, resourceID); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

// fail records a durability failure. A storage failure halts new admission;
// integrity, input, and authorization failures do not, because the durable
// boundary is still trustworthy.
func (s *OwnerStore) fail(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrStorageUnavailable) {
		s.halted.Store(true)
		return err
	}
	if isStorageFailure(err) {
		s.halted.Store(true)
		return fmt.Errorf("%w: %v", ErrStorageUnavailable, err)
	}
	return err
}

func isStorageFailure(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xff {
		case 8, 10, 11, 13, 14: // READONLY, IOERR, CORRUPT, FULL, CANTOPEN
			return true
		}
	}
	if errors.Is(err, sql.ErrConnDone) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, fragment := range []string{
		"disk i/o error",
		"database or disk is full",
		"attempt to write a readonly database",
		"database is closed",
		"file is not a database",
		"malformed database",
	} {
		if strings.Contains(msg, fragment) {
			return true
		}
	}
	return false
}

func isConstraintFailure(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		if se.Code()&0xff == 19 { // SQLITE_CONSTRAINT
			return true
		}
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

func nowUTC() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("owner_store: generate %s id: %w", prefix, err)
	}
	return prefix + "-" + hex.EncodeToString(raw[:]), nil
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

func digestHex(d string) (string, error) {
	if !validDigest(d) {
		return "", fmt.Errorf("%w: invalid digest %q", ErrInvalid, d)
	}
	return strings.TrimPrefix(d, "sha256:"), nil
}

// ---------------------------------------------------------------------------
// Journal state and hashing.
// ---------------------------------------------------------------------------

type journalState struct {
	journalID    string
	runID        string
	ownerDomain  string
	manifestHash string
	manifestJSON []byte
	manifest     journal_rules.Manifest
	headSequence int64
	headHash     string
}

func (s *OwnerStore) loadJournalState(ctx context.Context, q ownerQueryer, journalID string) (*journalState, error) {
	var st journalState
	err := q.QueryRowContext(ctx, `SELECT journal_id, run_id, owner_domain, manifest_hash,
		manifest_json, head_sequence, head_hash FROM journals WHERE journal_id = ?;`, journalID).
		Scan(&st.journalID, &st.runID, &st.ownerDomain, &st.manifestHash, &st.manifestJSON, &st.headSequence, &st.headHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("owner_store: read journal: %w", err)
	}
	if err := json.Unmarshal(st.manifestJSON, &st.manifest); err != nil {
		return nil, fmt.Errorf("%w: stored manifest is unreadable: %v", ErrIntegrityConflict, err)
	}
	if st.ownerDomain != s.ownerDomain {
		return nil, fmt.Errorf("%w: journal %q belongs to owner domain %q", ErrUnauthorized, journalID, st.ownerDomain)
	}
	return &st, nil
}

func loadEvents(ctx context.Context, q ownerQueryer, journalID string, through int64) ([]journal_rules.JournalEnvelope, error) {
	query := `SELECT sequence, envelope_json FROM journal_events WHERE journal_id = ?`
	args := []any{journalID}
	if through > 0 {
		query += ` AND sequence <= ?`
		args = append(args, through)
	}
	query += ` ORDER BY sequence;`
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("owner_store: read journal events: %w", err)
	}
	defer rows.Close()
	events := make([]journal_rules.JournalEnvelope, 0)
	for rows.Next() {
		var sequence int64
		var raw []byte
		if err := rows.Scan(&sequence, &raw); err != nil {
			return nil, fmt.Errorf("owner_store: scan journal event: %w", err)
		}
		env, err := decodeEnvelope(raw)
		if err != nil {
			return nil, err
		}
		if env.Sequence != sequence {
			return nil, fmt.Errorf("%w: stored event at %d carries sequence %d", ErrIntegrityConflict, sequence, env.Sequence)
		}
		events = append(events, env)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("owner_store: iterate journal events: %w", err)
	}
	return events, nil
}

func decodeEnvelope(raw []byte) (journal_rules.JournalEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var env journal_rules.JournalEnvelope
	if err := dec.Decode(&env); err != nil {
		return env, fmt.Errorf("%w: stored envelope is unreadable: %v", ErrIntegrityConflict, err)
	}
	return env, nil
}

func decodeEnvelopes(raw []byte) ([]journal_rules.JournalEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var list []journal_rules.JournalEnvelope
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("%w: stored receipt is unreadable: %v", ErrIntegrityConflict, err)
	}
	if list == nil {
		list = []journal_rules.JournalEnvelope{}
	}
	return list, nil
}

// canonicalEventBytesWithoutHash reproduces the journal_rules event-hash
// profile: kernel-jcs-sha256/1 over the canonical envelope with only
// event_hash removed. Nil causal_refs/payload are normalized to empty
// collections so a missing collection cannot fork the digest.
func canonicalEventBytesWithoutHash(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("owner_store: cannot decode envelope: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("owner_store: envelope must be a JSON object")
	}
	delete(m, "event_hash")
	if m["causal_refs"] == nil {
		m["causal_refs"] = []any{}
	}
	if m["payload"] == nil {
		m["payload"] = map[string]any{}
	}
	remarshaled, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("owner_store: cannot re-encode envelope: %v", err)
	}
	return evidence_codec.CanonicalJSON(remarshaled, "application/json")
}

func computeEventHash(env journal_rules.JournalEnvelope) (string, error) {
	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("owner_store: cannot marshal envelope: %v", err)
	}
	canonical, err := canonicalEventBytesWithoutHash(raw)
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

func canonicalManifestDigest(manifest journal_rules.Manifest) (string, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("owner_store: cannot marshal manifest: %v", err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return "", err
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

// Compile-time dependency checks: the declared CONSUMES signature must remain
// available even where this module enforces the rule through a sibling gate.
var (
	_ = evidence_codec.ValidateRecord
	_ = clock_rules.ValidateMeasurement
)

// ---------------------------------------------------------------------------
// Submission normalization and authority assignment.
// ---------------------------------------------------------------------------

type normalizedSubmission struct {
	producerSequence any
	eventKind        string
	eventSchema      string
	occurredAt       any
	payload          journal_rules.Payload
}

func normalizeSubmissions(submissions []EventSubmission) ([]normalizedSubmission, error) {
	out := make([]normalizedSubmission, 0, len(submissions))
	for i, sub := range submissions {
		if strings.TrimSpace(sub.EventKind) == "" {
			return nil, fmt.Errorf("%w: events[%d] event_kind is required", ErrInvalid, i)
		}
		if strings.TrimSpace(sub.EventSchemaVersion) == "" {
			return nil, fmt.Errorf("%w: events[%d] event_schema_version is required", ErrInvalid, i)
		}
		producerSequence, err := normalizeProducerSequence(sub.ProducerSequence)
		if err != nil {
			return nil, fmt.Errorf("%w: events[%d] producer_sequence: %v", ErrInvalid, i, err)
		}
		occurredAt, err := normalizeJSONValue(sub.OccurredAt)
		if err != nil {
			return nil, fmt.Errorf("%w: events[%d] occurred_at: %v", ErrInvalid, i, err)
		}
		if occurredAt == nil {
			return nil, fmt.Errorf("%w: events[%d] occurred_at is an in-band null: a TimePoint or typed Missing is required", ErrInvalid, i)
		}
		payload, err := normalizePayload(sub.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: events[%d] payload: %v", ErrInvalid, i, err)
		}
		out = append(out, normalizedSubmission{
			producerSequence: producerSequence,
			eventKind:        sub.EventKind,
			eventSchema:      sub.EventSchemaVersion,
			occurredAt:       occurredAt,
			payload:          payload,
		})
	}
	return out, nil
}

func normalizeProducerSequence(v any) (any, error) {
	if v == nil {
		return nil, errors.New("is an in-band null: use an integer or a typed Missing envelope")
	}
	if missing, ok := asMissing(v); ok {
		return missing, nil
	}
	switch n := v.(type) {
	case int:
		if n < 0 {
			return nil, errors.New("must not be negative")
		}
		return int64(n), nil
	case int32:
		if n < 0 {
			return nil, errors.New("must not be negative")
		}
		return int64(n), nil
	case int64:
		if n < 0 {
			return nil, errors.New("must not be negative")
		}
		return n, nil
	case uint:
		if uint64(n) > uint64(1<<63-1) {
			return nil, errors.New("out of range")
		}
		return int64(n), nil
	case uint32:
		return int64(n), nil
	case uint64:
		if n > uint64(1<<63-1) {
			return nil, errors.New("out of range")
		}
		return int64(n), nil
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n != math.Trunc(n) || n < 0 || n > float64(1<<63-1) {
			return nil, errors.New("must be a nonnegative integer")
		}
		return int64(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 0 {
			return nil, errors.New("must be a nonnegative integer or Missing")
		}
		return i, nil
	default:
		return nil, fmt.Errorf("has unsupported type %T", v)
	}
}

func asMissing(v any) (journal_rules.MissingEnvelope, bool) {
	switch m := v.(type) {
	case journal_rules.MissingEnvelope:
		return m, true
	case *journal_rules.MissingEnvelope:
		if m == nil {
			return journal_rules.MissingEnvelope{}, false
		}
		return *m, true
	case map[string]any:
		raw, hasValue := m["value"]
		if !hasValue || raw != nil {
			return journal_rules.MissingEnvelope{}, false
		}
		reason, _ := m["reason"].(string)
		if reason == "" {
			return journal_rules.MissingEnvelope{}, false
		}
		detail, _ := m["detail"].(string)
		return journal_rules.MissingEnvelope{Value: nil, Reason: reason, Detail: detail}, true
	default:
		return journal_rules.MissingEnvelope{}, false
	}
}

func normalizeJSONValue(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizePayload(payload journal_rules.Payload) (journal_rules.Payload, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return payload, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out journal_rules.Payload
	if err := dec.Decode(&out); err != nil {
		return payload, err
	}
	if out.Data == nil {
		out.Data = map[string]any{}
	}
	if out.Measurements == nil {
		out.Measurements = []journal_rules.Measurement{}
	}
	if out.EvidenceRefs == nil {
		out.EvidenceRefs = []journal_rules.EvidenceRef{}
	}
	if out.ArtifactRefs == nil {
		out.ArtifactRefs = []journal_rules.ArtifactReference{}
	}
	return out, nil
}

// assignEventAuthority derives role, assertion kind, provenance, and evidence
// scope from the event kind. The caller never supplies these values: untrusted
// submissions carry only the ingress shape, and the owner-local ingestion
// authority assigns them, matching the kernel event registry per event kind.
func assignEventAuthority(eventKind string) (role, assertion, provenance, scope string) {
	role = "derived_output"
	switch eventKind {
	case "manifest_admitted":
		role = "external_input"
	case "clock_registered", "producer_registered", "analysis_requested",
		"session_opened", "session_closed", "close_requested", "lease_claimed":
		role = "lifecycle_observation"
	}
	return role, "authoritative_effect", "server", "current_run"
}

// ---------------------------------------------------------------------------
// CommitOwner.
// ---------------------------------------------------------------------------

// CommitOwner commits one admitted owner operation: the supplied events, the
// owner-local reducer effect, the local outbox rows, and a content-addressed
// idempotency receipt are written in one transaction and returned only after
// durability. A byte-identical retry returns the original response without
// re-running the effect, so a crash after commit but before the caller saw the
// response is recoverable. Reusing a producer sequence with different content
// is an integrity conflict.
//
// A journal begins with exactly one manifest_admitted submission. Its
// payload.data.manifest artifact reference must point at the canonical JSON
// bytes of the admitted reduced Manifest, already installed with
// InstallArtifact; those bytes are the journal's immutable manifest pin and
// their content digest is the event manifest_hash. Later commits may not
// submit manifest_admitted.
func CommitOwner(ctx context.Context, store *OwnerStore, journalID string, events []EventSubmission, effect func(*sql.Tx) error) ([]JournalEnvelope, error) {
	if err := store.checkWritable(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(journalID) == "" {
		return nil, fmt.Errorf("%w: journal_id is required", ErrInvalid)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("%w: at least one event submission is required", ErrInvalid)
	}
	if err := store.authorize(ctx, opCommit, journalID); err != nil {
		return nil, err
	}
	receiptKey, err := commitReceiptKey(journalID, events)
	if err != nil {
		return nil, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, store.fail(fmt.Errorf("owner_store: begin commit: %w", err))
	}
	envelopes, replay, err := store.commitWithinTx(ctx, tx, journalID, events, effect, receiptKey)
	if err != nil {
		tx.Rollback()
		return nil, store.fail(err)
	}
	if replay {
		tx.Rollback()
		return envelopes, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, store.fail(fmt.Errorf("owner_store: commit journal: %w", err))
	}
	return envelopes, nil
}

func commitReceiptKey(journalID string, events []EventSubmission) (string, error) {
	type receiptRequest struct {
		Version   string            `json:"receipt_version"`
		JournalID string            `json:"journal_id"`
		Events    []EventSubmission `json:"events"`
	}
	raw, err := json.Marshal(receiptRequest{
		Version:   "owner_store.receipt/1",
		JournalID: journalID,
		Events:    events,
	})
	if err != nil {
		return "", fmt.Errorf("%w: cannot encode commit request: %v", ErrInvalid, err)
	}
	canonical, err := evidence_codec.CanonicalJSON(raw, "application/json")
	if err != nil {
		return "", fmt.Errorf("%w: cannot canonicalize commit request: %v", ErrInvalid, err)
	}
	return string(evidence_codec.HashBytes(canonical)), nil
}

func (s *OwnerStore) commitWithinTx(ctx context.Context, tx *sql.Tx, journalID string,
	events []EventSubmission, effect func(*sql.Tx) error,
	receiptKey string) ([]JournalEnvelope, bool, error) {

	receipt, found, err := s.loadReceipt(ctx, tx, receiptKey, journalID)
	if err != nil {
		return nil, false, err
	}
	if found {
		return receipt, true, nil
	}

	state, err := s.loadJournalState(ctx, tx, journalID)
	if err != nil {
		return nil, false, err
	}
	normalized, err := normalizeSubmissions(events)
	if err != nil {
		return nil, false, err
	}
	manifest, manifestHash, err := s.resolveManifest(ctx, tx, journalID, state, normalized)
	if err != nil {
		return nil, false, err
	}
	if err := s.checkProducerSequences(ctx, tx, journalID, state, normalized); err != nil {
		return nil, false, err
	}
	newEnvelopes, err := s.buildEnvelopes(ctx, tx, journalID, manifest, manifestHash, state, normalized)
	if err != nil {
		return nil, false, err
	}
	var existing []journal_rules.JournalEnvelope
	if state != nil {
		existing, err = loadEvents(ctx, tx, journalID, 0)
		if err != nil {
			return nil, false, err
		}
	}
	all := make([]journal_rules.JournalEnvelope, 0, len(existing)+len(newEnvelopes))
	all = append(all, existing...)
	all = append(all, newEnvelopes...)
	prefix, err := journal_rules.ValidateJournal(manifest, all)
	if err != nil {
		return nil, false, fmt.Errorf("%w: journal validation: %v", ErrInvalid, err)
	}
	if prefix.JournalID != journalID || prefix.LastSequence != int64(len(all)) ||
		prefix.HeadHash != newEnvelopes[len(newEnvelopes)-1].EventHash {
		return nil, false, fmt.Errorf("%w: journal validation returned an unexpected prefix", ErrIntegrityConflict)
	}
	if err := s.requireInstalledArtifacts(ctx, tx, newEnvelopes); err != nil {
		return nil, false, err
	}
	if err := s.persistJournal(ctx, tx, journalID, manifest, manifestHash, state, prefix); err != nil {
		return nil, false, err
	}
	now := nowUTC()
	for _, env := range newEnvelopes {
		if err := insertEvent(ctx, tx, env); err != nil {
			return nil, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbox (journal_id, sequence, event_hash, created_at)
			VALUES (?, ?, ?, ?);`, env.JournalID, env.Sequence, env.EventHash, now); err != nil {
			return nil, false, fmt.Errorf("owner_store: append outbox: %w", err)
		}
	}
	if effect != nil {
		if err := effect(tx); err != nil {
			return nil, false, fmt.Errorf("owner_store: local effect failed: %w", err)
		}
	}
	responseJSON, err := json.Marshal(newEnvelopes)
	if err != nil {
		return nil, false, fmt.Errorf("%w: cannot encode response: %v", ErrIntegrityConflict, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO commit_receipts
		(receipt_key, journal_id, last_sequence, envelope_json, created_at)
		VALUES (?, ?, ?, ?, ?);`,
		receiptKey, journalID, prefix.LastSequence, responseJSON, now); err != nil {
		if isConstraintFailure(err) {
			return nil, false, fmt.Errorf("%w: duplicate commit receipt", ErrIntegrityConflict)
		}
		return nil, false, fmt.Errorf("owner_store: record commit receipt: %w", err)
	}
	return newEnvelopes, false, nil
}

func (s *OwnerStore) loadReceipt(ctx context.Context, q ownerQueryer, receiptKey string,
	journalID string) ([]journal_rules.JournalEnvelope, bool, error) {
	var storedJournal string
	var raw []byte
	err := q.QueryRowContext(ctx, `SELECT journal_id, envelope_json FROM commit_receipts WHERE receipt_key = ?;`,
		receiptKey).Scan(&storedJournal, &raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("owner_store: read commit receipt: %w", err)
	}
	if storedJournal != journalID {
		return nil, false, fmt.Errorf("%w: receipt belongs to journal %q", ErrIntegrityConflict, storedJournal)
	}
	envelopes, err := decodeEnvelopes(raw)
	if err != nil {
		return nil, false, err
	}
	return envelopes, true, nil
}

func (s *OwnerStore) checkProducerSequences(ctx context.Context, tx *sql.Tx, journalID string,
	state *journalState, submissions []normalizedSubmission) error {
	seen := make(map[int64]bool)
	for _, sub := range submissions {
		sequence, ok := sub.producerSequence.(int64)
		if !ok {
			continue
		}
		if seen[sequence] {
			return fmt.Errorf("%w: producer_sequence %d appears twice in one commit", ErrIntegrityConflict, sequence)
		}
		seen[sequence] = true
		if state == nil {
			continue
		}
		var existing string
		err := tx.QueryRowContext(ctx, `SELECT event_hash FROM journal_events
			WHERE journal_id = ? AND producer_id = ? AND producer_sequence = ?;`,
			journalID, s.ownerDomain, sequence).Scan(&existing)
		if err == nil {
			return fmt.Errorf("%w: producer_sequence %d is already committed for this producer", ErrIntegrityConflict, sequence)
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("owner_store: read producer sequence: %w", err)
		}
	}
	return nil
}

// resolveManifest verifies the admission pin for a new journal or reloads the
// stored manifest for an existing one. The sequence-1 manifest artifact must be
// canonical JSON of the reduced admitted manifest, so its content digest is
// exactly the journal manifest hash.
func (s *OwnerStore) resolveManifest(ctx context.Context, tx *sql.Tx, journalID string,
	state *journalState, submissions []normalizedSubmission) (journal_rules.Manifest, string, error) {

	if state != nil {
		for _, sub := range submissions {
			if sub.eventKind == "manifest_admitted" {
				return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest_admitted appears only at sequence 1", ErrInvalid)
			}
		}
		return state.manifest, state.manifestHash, nil
	}
	if len(submissions) == 0 || submissions[0].eventKind != "manifest_admitted" {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: a journal begins with manifest_admitted", ErrInvalid)
	}
	for _, sub := range submissions[1:] {
		if sub.eventKind == "manifest_admitted" {
			return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest_admitted appears only at sequence 1", ErrInvalid)
		}
	}
	rawManifest, ok := submissions[0].payload.Data["manifest"]
	if !ok {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: sequence 1 data must pin the admitted manifest under data.manifest", ErrInvalid)
	}
	ref, err := artifactRefFromAny(rawManifest)
	if err != nil {
		return journal_rules.Manifest{}, "", err
	}
	if !containsArtifactRef(submissions[0].payload.ArtifactRefs, ref.Digest) {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: the manifest artifact must appear in payload.artifact_refs", ErrInvalid)
	}
	if err := s.requireArtifact(ctx, tx, ref); err != nil {
		return journal_rules.Manifest{}, "", err
	}
	bytesRaw, err := s.readInstalledArtifact(ref)
	if err != nil {
		return journal_rules.Manifest{}, "", err
	}
	if int64(len(bytesRaw)) != ref.SizeBytes {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest artifact size %d does not match reference %d",
			ErrIntegrityConflict, len(bytesRaw), ref.SizeBytes)
	}
	canonical, err := evidence_codec.CanonicalJSON(bytesRaw, "application/json")
	if err != nil {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest artifact is not canonical JSON: %v", ErrInvalid, err)
	}
	if !bytes.Equal(canonical, bytesRaw) {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest artifact bytes must be canonical JSON", ErrInvalid)
	}
	var manifest journal_rules.Manifest
	if err := json.Unmarshal(bytesRaw, &manifest); err != nil {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest artifact is unreadable: %v", ErrInvalid, err)
	}
	manifestHash, err := canonicalManifestDigest(manifest)
	if err != nil {
		return journal_rules.Manifest{}, "", err
	}
	if string(evidence_codec.HashBytes(bytesRaw)) != ref.Digest || manifestHash != ref.Digest {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest artifact digest does not match its exact bytes", ErrIntegrityConflict)
	}
	if manifest.JournalID != journalID {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest pins journal %q, commit targets %q", ErrInvalid, manifest.JournalID, journalID)
	}
	if manifest.OwnerDomain != s.ownerDomain {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: manifest owner_domain %q does not match store %q",
			ErrUnauthorized, manifest.OwnerDomain, s.ownerDomain)
	}
	if len(manifest.Clocks) == 0 {
		return journal_rules.Manifest{}, "", fmt.Errorf("%w: the manifest must register at least one clock", ErrInvalid)
	}
	return manifest, manifestHash, nil
}

func (s *OwnerStore) buildEnvelopes(ctx context.Context, tx *sql.Tx, journalID string,
	manifest journal_rules.Manifest, manifestHash string, state *journalState,
	submissions []normalizedSubmission) ([]journal_rules.JournalEnvelope, error) {

	receiptClock := manifest.Clocks[0]
	headSequence := int64(0)
	var previous any = journal_rules.NewMissing("not_applicable")
	if state != nil {
		headSequence = state.headSequence
		previous = state.headHash
	}
	out := make([]journal_rules.JournalEnvelope, 0, len(submissions))
	for i, sub := range submissions {
		sequence := headSequence + int64(i) + 1
		prevHash := previous
		if i > 0 {
			prevHash = out[i-1].EventHash
		}
		offset, err := s.nextClockOffset(ctx, tx, receiptClock)
		if err != nil {
			return nil, err
		}
		eventID, err := newID("evt")
		if err != nil {
			return nil, err
		}
		role, assertion, provenance, scope := assignEventAuthority(sub.eventKind)
		env := journal_rules.JournalEnvelope{
			RecordType:         journalRecordType,
			SchemaVersion:      recordSchemaVersion,
			RunID:              manifest.RunID,
			JournalID:          journalID,
			ManifestHash:       manifestHash,
			Sequence:           sequence,
			EventID:            eventID,
			EventKind:          sub.eventKind,
			EventSchemaVersion: sub.eventSchema,
			Role:               role,
			AssertionKind:      assertion,
			OwnerDomain:        s.ownerDomain,
			ProducerID:         s.ownerDomain,
			ProducerSequence:   sub.producerSequence,
			Provenance:         provenance,
			EvidenceScope:      scope,
			RecordedAt: journal_rules.TimePoint{
				ClockID:           receiptClock.ClockID,
				BootID:            receiptClock.BootID,
				Origin:            receiptClock.Origin,
				MonotonicOffsetMs: offset,
				UTCAnnotation:     journal_rules.NewMissing("not_applicable"),
			},
			OccurredAt:        sub.occurredAt,
			CausalRefs:        []journal_rules.EvidenceRef{},
			Payload:           sub.payload,
			PreviousEventHash: prevHash,
		}
		hash, err := computeEventHash(env)
		if err != nil {
			return nil, err
		}
		env.EventHash = hash
		out = append(out, env)
	}
	return out, nil
}

// nextClockOffset returns a strictly increasing monotonically offset on the
// named clock/boot for this receipt, persisting the high-water mark in the same
// owner transaction.
func (s *OwnerStore) nextClockOffset(ctx context.Context, tx *sql.Tx, clock journal_rules.ClockDescriptor) (float64, error) {
	last := -1.0
	err := tx.QueryRowContext(ctx, `SELECT offset_ms FROM clock_offsets WHERE clock_id = ? AND boot_id = ?;`,
		clock.ClockID, clock.BootID).Scan(&last)
	if err != nil && err != sql.ErrNoRows {
		return 0, fmt.Errorf("owner_store: read clock offset: %w", err)
	}
	observed := float64(time.Since(s.startedAt).Microseconds()) / 1000.0
	next := observed
	if next <= last {
		next = last + 1
	}
	if next < 0 {
		next = 0
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO clock_offsets (clock_id, boot_id, offset_ms)
		VALUES (?, ?, ?);`, clock.ClockID, clock.BootID, next); err != nil {
		return 0, fmt.Errorf("owner_store: record clock offset: %w", err)
	}
	return next, nil
}

func (s *OwnerStore) persistJournal(ctx context.Context, tx *sql.Tx, journalID string,
	manifest journal_rules.Manifest, manifestHash string, state *journalState,
	prefix journal_rules.JournalPrefix) error {
	if state == nil {
		rawManifest, err := json.Marshal(manifest)
		if err != nil {
			return fmt.Errorf("owner_store: encode admitted manifest: %w", err)
		}
		canonicalManifest, err := evidence_codec.CanonicalJSON(rawManifest, "application/json")
		if err != nil {
			return fmt.Errorf("owner_store: canonicalize admitted manifest: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO journals
			(journal_id, run_id, owner_domain, manifest_hash, manifest_json, head_sequence, head_hash, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?);`,
			journalID, manifest.RunID, s.ownerDomain, manifestHash, canonicalManifest,
			prefix.LastSequence, prefix.HeadHash, nowUTC()); err != nil {
			if isConstraintFailure(err) {
				return fmt.Errorf("%w: journal already exists", ErrIntegrityConflict)
			}
			return fmt.Errorf("owner_store: create journal: %w", err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE journals SET head_sequence = ?, head_hash = ? WHERE journal_id = ?;`,
		prefix.LastSequence, prefix.HeadHash, journalID); err != nil {
		return fmt.Errorf("owner_store: advance journal head: %w", err)
	}
	return nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, env journal_rules.JournalEnvelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("owner_store: encode journal event: %w", err)
	}
	var producerSequence any
	switch v := env.ProducerSequence.(type) {
	case int64:
		producerSequence = v
	case int:
		producerSequence = int64(v)
	case json.Number:
		if parsed, err := v.Int64(); err == nil {
			producerSequence = parsed
		}
	default:
		producerSequence = nil
	}
	recordedAt := ""
	if rawRecorded, err := json.Marshal(env.RecordedAt); err == nil {
		recordedAt = string(rawRecorded)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO journal_events
		(journal_id, sequence, event_id, event_hash, event_kind, producer_id, producer_sequence, envelope_json, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		env.JournalID, env.Sequence, env.EventID, env.EventHash, env.EventKind,
		env.ProducerID, producerSequence, raw, recordedAt); err != nil {
		if isConstraintFailure(err) {
			return fmt.Errorf("%w: duplicate journal event or producer sequence", ErrIntegrityConflict)
		}
		return fmt.Errorf("owner_store: insert journal event: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Artifact installation, reading, and requirement checks.
// ---------------------------------------------------------------------------

func (s *OwnerStore) objectPath(digest string) (string, error) {
	hexPart, err := digestHex(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.artifactRoot, "objects", hexPart[:2], hexPart), nil
}

// InstallArtifact installs exact bytes durably under the owner's
// content-addressed root and registers their identity. The procedure is the
// seam 4.8 installation order: bounded temporary file, hash exact bytes, flush
// data, atomically rename into place, sync directories, then commit the
// database reference. A crash before installation leaves no acknowledged
// reference; a crash after installation but before an owner commit leaves only
// an unreferenced artifact that garbage collection may collect.
func InstallArtifact(ctx context.Context, store *OwnerStore, content io.Reader, mediaType string, access string) (ArtifactReference, error) {
	if err := store.checkWritable(); err != nil {
		return ArtifactReference{}, err
	}
	if content == nil {
		return ArtifactReference{}, fmt.Errorf("%w: artifact content is required", ErrInvalid)
	}
	if strings.TrimSpace(mediaType) == "" {
		return ArtifactReference{}, fmt.Errorf("%w: media_type is required", ErrInvalid)
	}
	if access != accessPublic && access != accessRestricted {
		return ArtifactReference{}, fmt.Errorf("%w: access must be public or restricted", ErrInvalid)
	}
	if err := store.authorize(ctx, opInstall, mediaType); err != nil {
		return ArtifactReference{}, err
	}
	if err := os.MkdirAll(filepath.Join(store.artifactRoot, "tmp"), 0o755); err != nil {
		return ArtifactReference{}, store.fail(fmt.Errorf("owner_store: prepare artifact spool: %w", err))
	}
	tmp, err := os.CreateTemp(filepath.Join(store.artifactRoot, "tmp"), "artifact-*")
	if err != nil {
		return ArtifactReference{}, store.fail(fmt.Errorf("owner_store: create artifact spool: %w", err))
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	hasher := sha256.New()
	buffer := make([]byte, 256*1024)
	var total int64
	emptyReads := 0
	for {
		if err := ctx.Err(); err != nil {
			tmp.Close()
			return ArtifactReference{}, err
		}
		n, readErr := content.Read(buffer)
		if n == 0 && readErr == nil {
			emptyReads++
			if emptyReads > 100 {
				tmp.Close()
				return ArtifactReference{}, fmt.Errorf("%w: artifact reader makes no progress", ErrInvalid)
			}
			continue
		}
		emptyReads = 0
		if n > 0 {
			total += int64(n)
			if total > maxArtifactBytes {
				tmp.Close()
				return ArtifactReference{}, fmt.Errorf("%w: artifact exceeds the bounded spool size", ErrInvalid)
			}
			if _, writeErr := tmp.Write(buffer[:n]); writeErr != nil {
				tmp.Close()
				return ArtifactReference{}, store.fail(fmt.Errorf("owner_store: write artifact bytes: %w", writeErr))
			}
			hasher.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			tmp.Close()
			return ArtifactReference{}, fmt.Errorf("%w: artifact stream failed before installation: %v", ErrInvalid, readErr)
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return ArtifactReference{}, store.fail(fmt.Errorf("owner_store: flush artifact bytes: %w", err))
	}
	if err := tmp.Close(); err != nil {
		return ArtifactReference{}, store.fail(fmt.Errorf("owner_store: close artifact spool: %w", err))
	}
	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	ref := ArtifactReference{
		Digest:      digest,
		SizeBytes:   total,
		MediaType:   mediaType,
		OwnerDomain: store.ownerDomain,
		Access:      access,
	}
	finalPath, err := store.objectPath(digest)
	if err != nil {
		return ArtifactReference{}, err
	}
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return ArtifactReference{}, store.fail(fmt.Errorf("owner_store: prepare object directory: %w", err))
	}
	if err := store.installBytes(tmpName, finalPath, digest, total); err != nil {
		return ArtifactReference{}, err
	}
	if err := store.registerArtifact(ctx, ref); err != nil {
		return ArtifactReference{}, err
	}
	return ref, nil
}

func (s *OwnerStore) installBytes(tmpName, finalPath, digest string, size int64) error {
	if _, err := os.Stat(finalPath); err == nil {
		if err := fileMatchesDigest(finalPath, digest, size); err != nil {
			return err
		}
		return nil
	} else if !os.IsNotExist(err) {
		return s.fail(fmt.Errorf("owner_store: inspect object: %w", err))
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		// A concurrent installer may have won the rename without overwriting
		// on a platform that refuses replacement. Accept only identical bytes.
		if _, statErr := os.Stat(finalPath); statErr == nil {
			if verifyErr := fileMatchesDigest(finalPath, digest, size); verifyErr == nil {
				return nil
			}
		}
		return s.fail(fmt.Errorf("owner_store: install artifact object: %w", err))
	}
	if err := syncDir(filepath.Dir(finalPath)); err != nil {
		return s.fail(fmt.Errorf("owner_store: sync object directory: %w", err))
	}
	if err := syncDir(filepath.Join(s.artifactRoot, "objects")); err != nil {
		return s.fail(fmt.Errorf("owner_store: sync objects directory: %w", err))
	}
	return nil
}

func (s *OwnerStore) registerArtifact(ctx context.Context, ref ArtifactReference) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return s.fail(fmt.Errorf("owner_store: begin artifact registration: %w", err))
	}
	defer tx.Rollback()
	var size int64
	var media, ownerDomain, access string
	err = tx.QueryRowContext(ctx, `SELECT size_bytes, media_type, owner_domain, access FROM artifacts WHERE digest = ?;`,
		ref.Digest).Scan(&size, &media, &ownerDomain, &access)
	switch {
	case err == sql.ErrNoRows:
		if _, err := tx.ExecContext(ctx, `INSERT INTO artifacts
			(digest, size_bytes, media_type, owner_domain, access, installed_at)
			VALUES (?, ?, ?, ?, ?, ?);`,
			ref.Digest, ref.SizeBytes, ref.MediaType, ref.OwnerDomain, ref.Access, nowUTC()); err != nil {
			if isConstraintFailure(err) {
				return fmt.Errorf("%w: concurrent artifact registration", ErrIntegrityConflict)
			}
			return s.fail(fmt.Errorf("owner_store: register artifact: %w", err))
		}
	case err != nil:
		return s.fail(fmt.Errorf("owner_store: read artifact registration: %w", err))
	default:
		if size != ref.SizeBytes || media != ref.MediaType || ownerDomain != ref.OwnerDomain || access != ref.Access {
			return fmt.Errorf("%w: artifact %s is already registered with different metadata", ErrIntegrityConflict, ref.Digest)
		}
	}
	// Verify the exact object is still present under the same write fence
	// that publishes the identity. Exact bytes were hashed while streaming
	// into the spool (and, for a pre-existing object, verified before the
	// rename decision), so presence and size are the only properties a
	// concurrent collector can invalidate here. A collector removes bytes
	// only while holding this fence, so successful registration can never
	// point at bytes it already removed.
	path, err := s.objectPath(ref.Digest)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s was collected before registration", ErrArtifactLost, ref.Digest)
		}
		return s.fail(fmt.Errorf("owner_store: inspect installed object: %w", err))
	}
	if info.Size() != ref.SizeBytes {
		return fmt.Errorf("%w: installed object size changed before registration", ErrArtifactLost)
	}
	if err := tx.Commit(); err != nil {
		return s.fail(fmt.Errorf("owner_store: commit artifact registration: %w", err))
	}
	return nil
}

// ReadArtifact returns the exact installed bytes. A missing registration is
// ErrArtifactMissing; a registered identity whose bytes are absent or corrupt
// is ErrArtifactLost, preserving the known identity rather than pretending the
// artifact never existed.
func ReadArtifact(ctx context.Context, store *OwnerStore, reference ArtifactReference) ([]byte, error) {
	if err := store.checkOpen(); err != nil {
		return nil, err
	}
	if !validDigest(reference.Digest) {
		return nil, fmt.Errorf("%w: invalid artifact digest", ErrInvalid)
	}
	if err := store.authorize(ctx, opReadArtifact, reference.Digest); err != nil {
		return nil, err
	}
	var size int64
	var media, ownerDomain, access string
	err := store.db.QueryRowContext(ctx, `SELECT size_bytes, media_type, owner_domain, access FROM artifacts WHERE digest = ?;`,
		reference.Digest).Scan(&size, &media, &ownerDomain, &access)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: %s", ErrArtifactMissing, reference.Digest)
	}
	if err != nil {
		return nil, fmt.Errorf("owner_store: read artifact identity: %w", err)
	}
	if access == accessRestricted {
		if err := store.authorize(ctx, opReadRestricted, reference.Digest); err != nil {
			return nil, err
		}
	}
	if reference.SizeBytes != 0 && reference.SizeBytes != size {
		return nil, fmt.Errorf("%w: reference size does not match registered size", ErrIntegrityConflict)
	}
	if reference.MediaType != "" && reference.MediaType != media {
		return nil, fmt.Errorf("%w: reference media_type does not match registration", ErrIntegrityConflict)
	}
	if reference.OwnerDomain != "" && reference.OwnerDomain != ownerDomain {
		return nil, fmt.Errorf("%w: reference owner_domain does not match registration", ErrIntegrityConflict)
	}
	if reference.Access != "" && reference.Access != access {
		return nil, fmt.Errorf("%w: reference access does not match registration", ErrIntegrityConflict)
	}
	path, err := store.objectPath(reference.Digest)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrArtifactLost, reference.Digest)
		}
		return nil, fmt.Errorf("owner_store: read artifact bytes: %w", err)
	}
	if int64(len(content)) != size || string(evidence_codec.HashBytes(content)) != reference.Digest {
		return nil, fmt.Errorf("%w: %s bytes no longer match the registered identity", ErrArtifactLost, reference.Digest)
	}
	return content, nil
}

func (s *OwnerStore) readInstalledArtifact(ref ArtifactReference) ([]byte, error) {
	path, err := s.objectPath(ref.Digest)
	if err != nil {
		return nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrArtifactLost, ref.Digest)
		}
		return nil, fmt.Errorf("owner_store: read artifact bytes: %w", err)
	}
	return content, nil
}

func (s *OwnerStore) requireInstalledArtifacts(ctx context.Context, q ownerQueryer, envelopes []journal_rules.JournalEnvelope) error {
	for _, env := range envelopes {
		for _, ref := range env.Payload.ArtifactRefs {
			if err := s.requireArtifact(ctx, q, ref); err != nil {
				return err
			}
		}
		nested, err := nestedArtifactRefs(env.Payload.Data)
		if err != nil {
			return err
		}
		for _, ref := range nested {
			if !containsArtifactRef(env.Payload.ArtifactRefs, ref.Digest) {
				return fmt.Errorf("%w: nested artifact %s is not listed in payload.artifact_refs for retention",
					ErrInvalid, ref.Digest)
			}
		}
	}
	return nil
}

func (s *OwnerStore) requireArtifact(ctx context.Context, q ownerQueryer, ref ArtifactReference) error {
	if !validDigest(ref.Digest) {
		return fmt.Errorf("%w: invalid artifact digest %q", ErrInvalid, ref.Digest)
	}
	var size int64
	var media, ownerDomain, access string
	err := q.QueryRowContext(ctx, `SELECT size_bytes, media_type, owner_domain, access FROM artifacts WHERE digest = ?;`,
		ref.Digest).Scan(&size, &media, &ownerDomain, &access)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: %s", ErrArtifactMissing, ref.Digest)
	}
	if err != nil {
		return fmt.Errorf("owner_store: read artifact identity: %w", err)
	}
	if ref.SizeBytes != size || ref.MediaType != media || ref.OwnerDomain != ownerDomain || ref.Access != access {
		return fmt.Errorf("%w: artifact reference metadata for %s disagrees with registration", ErrIntegrityConflict, ref.Digest)
	}
	path, err := s.objectPath(ref.Digest)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrArtifactLost, ref.Digest)
		}
		return fmt.Errorf("owner_store: inspect artifact bytes: %w", err)
	}
	if info.Size() != size {
		return fmt.Errorf("%w: %s size no longer matches the registered identity", ErrArtifactLost, ref.Digest)
	}
	return nil
}

func artifactRefFromAny(v any) (ArtifactReference, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return ArtifactReference{}, fmt.Errorf("%w: artifact reference is not JSON-encodable: %v", ErrInvalid, err)
	}
	var ref ArtifactReference
	if err := json.Unmarshal(raw, &ref); err != nil {
		return ArtifactReference{}, fmt.Errorf("%w: artifact reference is unreadable: %v", ErrInvalid, err)
	}
	if !validDigest(ref.Digest) {
		return ArtifactReference{}, fmt.Errorf("%w: invalid artifact digest %q", ErrInvalid, ref.Digest)
	}
	if ref.SizeBytes < 0 {
		return ArtifactReference{}, fmt.Errorf("%w: artifact size must not be negative", ErrInvalid)
	}
	if strings.TrimSpace(ref.MediaType) == "" {
		return ArtifactReference{}, fmt.Errorf("%w: artifact media_type is required", ErrInvalid)
	}
	if strings.TrimSpace(ref.OwnerDomain) == "" {
		return ArtifactReference{}, fmt.Errorf("%w: artifact owner_domain is required", ErrInvalid)
	}
	if ref.Access != accessPublic && ref.Access != accessRestricted {
		return ArtifactReference{}, fmt.Errorf("%w: artifact access must be public or restricted", ErrInvalid)
	}
	return ref, nil
}

func containsArtifactRef(refs []ArtifactReference, digest string) bool {
	for _, ref := range refs {
		if ref.Digest == digest {
			return true
		}
	}
	return false
}

// nestedArtifactRefs finds artifact-reference-shaped objects embedded in
// payload data. Every such identity must be listed in payload.artifact_refs so
// retention and collection can reason about it.
func nestedArtifactRefs(value any) ([]ArtifactReference, error) {
	found := make(map[string]ArtifactReference)
	var walk func(any) error
	walk = func(v any) error {
		switch node := v.(type) {
		case map[string]any:
			if looksLikeArtifactRef(node) {
				ref, err := artifactRefFromAny(node)
				if err != nil {
					return err
				}
				found[ref.Digest] = ref
			}
			for _, child := range node {
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range node {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(value); err != nil {
		return nil, err
	}
	out := make([]ArtifactReference, 0, len(found))
	for _, ref := range found {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Digest < out[j].Digest })
	return out, nil
}

func looksLikeArtifactRef(m map[string]any) bool {
	if _, ok := m["digest"].(string); !ok {
		return false
	}
	if _, ok := m["size_bytes"]; !ok {
		return false
	}
	for key := range m {
		switch key {
		case "digest", "size_bytes", "media_type", "owner_domain", "access":
		default:
			return false
		}
	}
	return true
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
		return err
	}
	return nil
}

func fileMatchesDigest(path, digest string, size int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != size {
		return fmt.Errorf("%w: existing object %s has size %d, expected %d", ErrIntegrityConflict, digest, info.Size(), size)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	if "sha256:"+hex.EncodeToString(hasher.Sum(nil)) != digest {
		return fmt.Errorf("%w: existing object %s does not match its content address", ErrIntegrityConflict, digest)
	}
	return nil
}

// ---------------------------------------------------------------------------
// LoadPrefix.
// ---------------------------------------------------------------------------

// LoadPrefix returns the retained events through the pinned prefix after
// verifying the complete chain, every event hash, and the prefix head. Evidence
// beyond the pinned prefix is rejected.
func LoadPrefix(ctx context.Context, store *OwnerStore, prefix JournalPrefix) ([]JournalEnvelope, error) {
	if err := store.checkOpen(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(prefix.JournalID) == "" {
		return nil, fmt.Errorf("%w: prefix journal_id is required", ErrInvalid)
	}
	if prefix.LastSequence < 1 {
		return nil, fmt.Errorf("%w: prefix last_sequence starts at 1", ErrInvalid)
	}
	if err := store.authorize(ctx, opRead, prefix.JournalID); err != nil {
		return nil, err
	}
	state, err := store.loadJournalState(ctx, store.db, prefix.JournalID)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, fmt.Errorf("%w: %s", ErrJournalUnknown, prefix.JournalID)
	}
	if prefix.LastSequence > state.headSequence {
		return nil, fmt.Errorf("%w: prefix ends at %d, journal head is %d",
			ErrPrefixMismatch, prefix.LastSequence, state.headSequence)
	}
	events, err := loadEvents(ctx, store.db, prefix.JournalID, prefix.LastSequence)
	if err != nil {
		return nil, err
	}
	if int64(len(events)) != prefix.LastSequence {
		return nil, fmt.Errorf("%w: prefix ends at %d, retained events: %d",
			ErrPrefixMismatch, prefix.LastSequence, len(events))
	}
	for _, env := range events {
		raw, err := json.Marshal(env)
		if err != nil {
			return nil, fmt.Errorf("%w: encode retained event: %v", ErrIntegrityConflict, err)
		}
		if err := evidence_codec.ValidateRecord(env.SchemaVersion, journalRecordType, raw); err != nil {
			return nil, fmt.Errorf("%w: retained event structural gate: %v", ErrIntegrityConflict, err)
		}
	}
	verified, err := journal_rules.ValidateJournal(state.manifest, events)
	if err != nil {
		return nil, fmt.Errorf("%w: retained journal validation: %v", ErrIntegrityConflict, err)
	}
	if verified.JournalID != prefix.JournalID || verified.LastSequence != prefix.LastSequence ||
		verified.HeadHash != prefix.HeadHash {
		return nil, fmt.Errorf("%w: supplied prefix does not match the verified prefix", ErrPrefixMismatch)
	}
	return events, nil
}

// ---------------------------------------------------------------------------
// Retention and collection.
// ---------------------------------------------------------------------------

// RetainRoot durably pins a retained root and its dependency edges, backed by
// a resolvable journal evidence reference. Every pinned identity and every
// dependency must currently exist with its exact bytes; a root is never
// recorded as protected unless its bytes are present and readable, so a
// concurrent collection cannot leave a successful pin pointing at absent data.
func RetainRoot(ctx context.Context, store *OwnerStore, root ArtifactReference,
	dependencies []ArtifactReference, support EvidenceRef) error {
	if err := store.checkWritable(); err != nil {
		return err
	}
	if !validDigest(root.Digest) {
		return fmt.Errorf("%w: root digest is invalid", ErrInvalid)
	}
	if strings.TrimSpace(support.JournalID) == "" {
		return fmt.Errorf("%w: retention support must name a journal", ErrInvalid)
	}
	if err := store.authorize(ctx, opRetain, root.Digest); err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return store.fail(fmt.Errorf("owner_store: begin retention pin: %w", err))
	}
	defer tx.Rollback()

	if err := store.requireArtifact(ctx, tx, root); err != nil {
		return store.fail(err)
	}
	seen := map[string]bool{root.Digest: true}
	for _, dependency := range dependencies {
		if seen[dependency.Digest] {
			continue
		}
		seen[dependency.Digest] = true
		if err := store.requireArtifact(ctx, tx, dependency); err != nil {
			return store.fail(err)
		}
	}
	if err := store.requireSupport(ctx, tx, support); err != nil {
		return err
	}
	var generation int64
	if err := tx.QueryRowContext(ctx, `SELECT generation FROM retention_generation WHERE id = 1;`).Scan(&generation); err != nil {
		return store.fail(fmt.Errorf("owner_store: read retention fence: %w", err))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO retention_pins
		(root_digest, support_journal, support_sequence, support_event_id, support_event_hash,
		 support_pointer, fence_generation, pinned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(root_digest) DO UPDATE SET
			support_journal = excluded.support_journal,
			support_sequence = excluded.support_sequence,
			support_event_id = excluded.support_event_id,
			support_event_hash = excluded.support_event_hash,
			support_pointer = excluded.support_pointer,
			fence_generation = excluded.fence_generation,
			pinned_at = excluded.pinned_at;`,
		root.Digest, support.JournalID, support.Sequence, support.EventID, support.EventHash,
		support.Pointer, generation, nowUTC()); err != nil {
		return store.fail(fmt.Errorf("owner_store: record retention pin: %w", err))
	}
	for digest := range seen {
		if digest == root.Digest {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO artifact_dependencies
			(root_digest, dependency_digest) VALUES (?, ?);`, root.Digest, digest); err != nil {
			return store.fail(fmt.Errorf("owner_store: record artifact dependency: %w", err))
		}
	}
	if err := tx.Commit(); err != nil {
		return store.fail(fmt.Errorf("owner_store: commit retention pin: %w", err))
	}
	return nil
}

func (s *OwnerStore) requireSupport(ctx context.Context, q ownerQueryer, support EvidenceRef) error {
	state, err := s.loadJournalState(ctx, q, support.JournalID)
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("%w: %s", ErrJournalUnknown, support.JournalID)
	}
	events, err := loadEvents(ctx, q, support.JournalID, 0)
	if err != nil {
		return err
	}
	prefix := JournalPrefix{JournalID: state.journalID, LastSequence: state.headSequence, HeadHash: state.headHash}
	if _, err := journal_rules.ResolveEvidence(prefix, events, support); err != nil {
		return fmt.Errorf("%w: retention support does not resolve in the retained prefix: %v", ErrInvalid, err)
	}
	return nil
}

// CollectUnreachable deletes artifacts unreachable from every retained root
// after verifying the supplied journal proof prefix against the retained
// journal. Collection runs in one immediate transaction that advances the
// retention fence; a concurrent pin either commits first and protects its root
// or runs after deletion and fails instead of claiming protection for absent
// bytes. No retained root or transitive dependency is ever deleted.
func CollectUnreachable(ctx context.Context, store *OwnerStore, proof JournalPrefix) ([]Digest, error) {
	if err := store.checkWritable(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(proof.JournalID) == "" {
		return nil, fmt.Errorf("%w: proof journal_id is required", ErrInvalid)
	}
	if proof.LastSequence < 1 {
		return nil, fmt.Errorf("%w: proof last_sequence starts at 1", ErrInvalid)
	}
	if err := store.authorize(ctx, opCollect, proof.JournalID); err != nil {
		return nil, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, store.fail(fmt.Errorf("owner_store: begin collection: %w", err))
	}
	defer tx.Rollback()

	if err := store.verifyProof(ctx, tx, proof); err != nil {
		return nil, err
	}
	reachable, err := store.reachableDigests(ctx, tx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT digest FROM artifacts ORDER BY digest;`)
	if err != nil {
		return nil, store.fail(fmt.Errorf("owner_store: list artifacts: %w", err))
	}
	var unreachable []string
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			rows.Close()
			return nil, store.fail(fmt.Errorf("owner_store: scan artifact: %w", err))
		}
		if !reachable[digest] {
			unreachable = append(unreachable, digest)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, store.fail(fmt.Errorf("owner_store: iterate artifacts: %w", err))
	}
	rows.Close()

	var generation int64
	if err := tx.QueryRowContext(ctx, `UPDATE retention_generation SET generation = generation + 1 WHERE id = 1 RETURNING generation;`).
		Scan(&generation); err != nil {
		return nil, store.fail(fmt.Errorf("owner_store: advance retention fence: %w", err))
	}
	for _, digest := range unreachable {
		if _, err := tx.ExecContext(ctx, `DELETE FROM artifacts WHERE digest = ?;`, digest); err != nil {
			return nil, store.fail(fmt.Errorf("owner_store: delete artifact identity: %w", err))
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM artifact_dependencies
			WHERE root_digest = ? OR dependency_digest = ?;`, digest, digest); err != nil {
			return nil, store.fail(fmt.Errorf("owner_store: delete artifact dependencies: %w", err))
		}
		// Bytes are removed while this transaction still holds the owner's
		// write fence, so no concurrent pin or install can observe a
		// successful registration for bytes this transaction is deleting.
		// A concurrent installation that loses this race re-verifies the
		// installed object under its own write transaction and fails rather
		// than registering absent bytes.
		path, pathErr := store.objectPath(digest)
		if pathErr != nil {
			return nil, pathErr
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return nil, store.fail(fmt.Errorf("owner_store: remove collected artifact: %w", removeErr))
		}
		_ = syncDir(filepath.Dir(path))
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gc_runs
		(generation, proof_journal, proof_last_sequence, proof_head_hash, collected, created_at)
		VALUES (?, ?, ?, ?, ?, ?);`,
		generation, proof.JournalID, proof.LastSequence, proof.HeadHash, len(unreachable), nowUTC()); err != nil {
		return nil, store.fail(fmt.Errorf("owner_store: record collection run: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return nil, store.fail(fmt.Errorf("owner_store: commit collection: %w", err))
	}
	results := make([]Digest, 0, len(unreachable))
	for _, digest := range unreachable {
		results = append(results, Digest(digest))
	}
	sort.Slice(results, func(i, j int) bool { return results[i] < results[j] })
	return results, nil
}

func (s *OwnerStore) verifyProof(ctx context.Context, q ownerQueryer, proof JournalPrefix) error {
	state, err := s.loadJournalState(ctx, q, proof.JournalID)
	if err != nil {
		return err
	}
	if state == nil {
		return fmt.Errorf("%w: %s", ErrJournalUnknown, proof.JournalID)
	}
	events, err := loadEvents(ctx, q, proof.JournalID, 0)
	if err != nil {
		return err
	}
	verified, err := journal_rules.ValidateJournal(state.manifest, events)
	if err != nil {
		return fmt.Errorf("%w: collection proof journal: %v", ErrInvalid, err)
	}
	if verified.JournalID != proof.JournalID || verified.LastSequence != proof.LastSequence ||
		verified.HeadHash != proof.HeadHash {
		return fmt.Errorf("%w: collection proof is not the current retained prefix", ErrPrefixMismatch)
	}
	return nil
}

func (s *OwnerStore) reachableDigests(ctx context.Context, q ownerQueryer) (map[string]bool, error) {
	reachable := make(map[string]bool)
	edges := make(map[string][]string)

	// Every acknowledged journal event is a retained root for the artifacts it
	// declares; the admitted manifest artifact is retained by sequence 1.
	rows, err := q.QueryContext(ctx, `SELECT journal_id FROM journals ORDER BY journal_id;`)
	if err != nil {
		return nil, fmt.Errorf("owner_store: list journals: %w", err)
	}
	var journalIDs []string
	for rows.Next() {
		var journalID string
		if err := rows.Scan(&journalID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("owner_store: scan journal: %w", err)
		}
		journalIDs = append(journalIDs, journalID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("owner_store: iterate journals: %w", err)
	}
	rows.Close()
	for _, journalID := range journalIDs {
		events, err := loadEvents(ctx, q, journalID, 0)
		if err != nil {
			return nil, err
		}
		for i, env := range events {
			for _, ref := range env.Payload.ArtifactRefs {
				reachable[ref.Digest] = true
			}
			if i == 0 {
				if manifestRef, ok := env.Payload.Data["manifest"]; ok {
					ref, err := artifactRefFromAny(manifestRef)
					if err != nil {
						return nil, fmt.Errorf("%w: retained manifest pin is unreadable: %v", ErrIntegrityConflict, err)
					}
					reachable[ref.Digest] = true
				}
			}
		}
	}

	pinRows, err := q.QueryContext(ctx, `SELECT root_digest FROM retention_pins;`)
	if err != nil {
		return nil, fmt.Errorf("owner_store: list retention pins: %w", err)
	}
	for pinRows.Next() {
		var digest string
		if err := pinRows.Scan(&digest); err != nil {
			pinRows.Close()
			return nil, fmt.Errorf("owner_store: scan retention pin: %w", err)
		}
		reachable[digest] = true
	}
	if err := pinRows.Err(); err != nil {
		pinRows.Close()
		return nil, fmt.Errorf("owner_store: iterate retention pins: %w", err)
	}
	pinRows.Close()

	depRows, err := q.QueryContext(ctx, `SELECT root_digest, dependency_digest FROM artifact_dependencies;`)
	if err != nil {
		return nil, fmt.Errorf("owner_store: list artifact dependencies: %w", err)
	}
	for depRows.Next() {
		var rootDigest, dependencyDigest string
		if err := depRows.Scan(&rootDigest, &dependencyDigest); err != nil {
			depRows.Close()
			return nil, fmt.Errorf("owner_store: scan artifact dependency: %w", err)
		}
		edges[rootDigest] = append(edges[rootDigest], dependencyDigest)
	}
	if err := depRows.Err(); err != nil {
		depRows.Close()
		return nil, fmt.Errorf("owner_store: iterate artifact dependencies: %w", err)
	}
	depRows.Close()

	queue := make([]string, 0, len(reachable))
	for digest := range reachable {
		queue = append(queue, digest)
	}
	for len(queue) > 0 {
		digest := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, dependency := range edges[digest] {
			if !reachable[dependency] {
				reachable[dependency] = true
				queue = append(queue, dependency)
			}
		}
	}
	return reachable, nil
}

// ---------------------------------------------------------------------------
// Lease fencing.
// ---------------------------------------------------------------------------

type leaseAuthority struct {
	epoch   int64
	bootID  string
	clockID string
	origin  string
}

func (s *OwnerStore) loadLeaseAuthority(ctx context.Context, q ownerQueryer) (leaseAuthority, error) {
	var a leaseAuthority
	err := q.QueryRowContext(ctx, `SELECT authority_epoch, boot_id, clock_id, origin FROM lease_authority WHERE id = 1;`).
		Scan(&a.epoch, &a.bootID, &a.clockID, &a.origin)
	if err != nil {
		return leaseAuthority{}, fmt.Errorf("owner_store: read lease authority: %w", err)
	}
	return a, nil
}

type leaseRow struct {
	resourceID     string
	leaseID        string
	authorityEpoch int64
	bootID         string
	clockID        string
	origin         string
	leasedAtMs     float64
	expiresAtMs    float64
	entityRevision int64
	inputRevision  int64
	generationID   string
	state          string
	retryCount     int64
	maxRetries     int64
}

func (s *OwnerStore) loadLeaseRow(ctx context.Context, q ownerQueryer, resourceID string) (*leaseRow, error) {
	var row leaseRow
	err := q.QueryRowContext(ctx, `SELECT resource_id, lease_id, authority_epoch, boot_id, clock_id, origin,
		leased_at_ms, expires_at_ms, entity_revision, input_revision, generation_id, lease_state,
		retry_count, max_retries FROM work_leases WHERE resource_id = ?;`, resourceID).
		Scan(&row.resourceID, &row.leaseID, &row.authorityEpoch, &row.bootID, &row.clockID, &row.origin,
			&row.leasedAtMs, &row.expiresAtMs, &row.entityRevision, &row.inputRevision, &row.generationID,
			&row.state, &row.retryCount, &row.maxRetries)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("owner_store: read work lease: %w", err)
	}
	return &row, nil
}

// ClaimLease atomically checks that the resource is not held under an
// unexpired lease in the current authority epoch/boot, assigns a unique
// fencing lease ID, advances the entity revision, clears the failure reason,
// and leaves the resource state untouched. Offsets from a previous boot are
// never compared with the current boot.
func (s *OwnerStore) ClaimLease(ctx context.Context, resourceID string, inputRevision int64, maxRetries int, ttl time.Duration) (LeaseToken, error) {
	if err := s.checkWritable(); err != nil {
		return LeaseToken{}, err
	}
	if strings.TrimSpace(resourceID) == "" {
		return LeaseToken{}, fmt.Errorf("%w: resource_id is required", ErrInvalid)
	}
	if inputRevision < 0 || maxRetries < 0 {
		return LeaseToken{}, fmt.Errorf("%w: revisions and retry limits must not be negative", ErrInvalid)
	}
	if ttl < time.Millisecond {
		return LeaseToken{}, fmt.Errorf("%w: lease ttl must be at least one millisecond", ErrInvalid)
	}
	if err := s.authorize(ctx, opClaimLease, resourceID); err != nil {
		return LeaseToken{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LeaseToken{}, s.fail(fmt.Errorf("owner_store: begin lease claim: %w", err))
	}
	defer tx.Rollback()

	auth, err := s.loadLeaseAuthority(ctx, tx)
	if err != nil {
		return LeaseToken{}, err
	}
	issuedAt, err := s.nextClockOffset(ctx, tx, journal_rules.ClockDescriptor{
		ClockID: auth.clockID, BootID: auth.bootID, Origin: auth.origin,
	})
	if err != nil {
		return LeaseToken{}, err
	}
	deadline, err := clock_rules.ComputeDeadline(
		clock_rules.TimePoint{
			ClockID:           auth.clockID,
			BootID:            auth.bootID,
			Origin:            auth.origin,
			MonotonicOffsetMs: issuedAt,
			UTCAnnotation:     clock_rules.Missing{Reason: "not_applicable"},
		},
		clock_rules.DurationLimit{
			Kind:  clock_rules.EstimateExact,
			Unit:  "ms",
			Value: float64(ttl.Milliseconds()),
		},
	)
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: lease deadline: %v", ErrInvalid, err)
	}
	if deadline.MonotonicOffsetMs <= issuedAt {
		return LeaseToken{}, fmt.Errorf("%w: lease expiry must be later than issue", ErrInvalid)
	}
	existing, err := s.loadLeaseRow(ctx, tx, resourceID)
	if err != nil {
		return LeaseToken{}, err
	}
	if existing != nil && existing.state == leaseStateHeld &&
		existing.authorityEpoch == auth.epoch && existing.bootID == auth.bootID &&
		existing.expiresAtMs > issuedAt {
		return LeaseToken{}, fmt.Errorf("%w: %s", ErrLeaseHeld, resourceID)
	}
	entityRevision := int64(1)
	retryCount := int64(0)
	generationID := ""
	if existing != nil {
		entityRevision = existing.entityRevision + 1
		switch existing.state {
		case leaseStateCompleted, leaseStateExhausted:
			// A new work generation: retries and failures reset.
		default:
			// Reclaiming an expired or fenced lease within the same
			// generation preserves retry accounting.
			generationID = existing.generationID
			retryCount = existing.retryCount
		}
	}
	if generationID == "" {
		generationID, err = newID("gen")
		if err != nil {
			return LeaseToken{}, err
		}
	}
	leaseID, err := newID("lease")
	if err != nil {
		return LeaseToken{}, err
	}
	failureJSON, err := json.Marshal(journal_rules.NewMissing("not_applicable"))
	if err != nil {
		return LeaseToken{}, fmt.Errorf("%w: encode cleared failure reason: %v", ErrInvalid, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO work_leases
		(resource_id, lease_id, authority_epoch, boot_id, clock_id, origin,
		 leased_at_ms, expires_at_ms, entity_revision, input_revision, generation_id,
		 lease_state, retry_count, max_retries, last_failure_reason, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '');`,
		resourceID, leaseID, auth.epoch, auth.bootID, auth.clockID, auth.origin,
		issuedAt, deadline.MonotonicOffsetMs, entityRevision, inputRevision, generationID,
		leaseStateHeld, retryCount, int64(maxRetries), string(failureJSON)); err != nil {
		return LeaseToken{}, s.fail(fmt.Errorf("owner_store: record lease claim: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return LeaseToken{}, s.fail(fmt.Errorf("owner_store: commit lease claim: %w", err))
	}
	return LeaseToken{
		ResourceID:     resourceID,
		LeaseID:        leaseID,
		AuthorityEpoch: auth.epoch,
		BootID:         auth.bootID,
		ClockID:        auth.clockID,
		Origin:         auth.origin,
		ExpiresAtMs:    deadline.MonotonicOffsetMs,
		EntityRevision: entityRevision,
		InputRevision:  inputRevision,
		GenerationID:   generationID,
	}, nil
}

// validateLeaseToken checks the fencing token against durable owner-local
// lease state. A token from a previous authority epoch or boot, an expired
// lease, a completed/reclaimed lease, or a mismatched entity/input revision is
// stale and has no effect.
func (s *OwnerStore) validateLeaseToken(ctx context.Context, tx *sql.Tx, token LeaseToken) (*leaseRow, error) {
	auth, err := s.loadLeaseAuthority(ctx, tx)
	if err != nil {
		return nil, err
	}
	row, err := s.loadLeaseRow(ctx, tx, token.ResourceID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("%w: no durable lease for %s", ErrStaleLease, token.ResourceID)
	}
	if token.AuthorityEpoch != auth.epoch || row.authorityEpoch != auth.epoch ||
		token.BootID != auth.bootID || row.bootID != auth.bootID {
		return nil, fmt.Errorf("%w: token epoch/boot is not the current authority", ErrStaleLease)
	}
	if token.LeaseID != row.leaseID || token.GenerationID != row.generationID {
		return nil, fmt.Errorf("%w: token is not the current fencing lease", ErrStaleLease)
	}
	if row.state != leaseStateHeld {
		return nil, fmt.Errorf("%w: lease is in state %q", ErrStaleLease, row.state)
	}
	if row.entityRevision != token.EntityRevision || row.inputRevision != token.InputRevision {
		return nil, fmt.Errorf("%w: entity/input revision moved", ErrStaleLease)
	}
	now, err := s.nextClockOffset(ctx, tx, journal_rules.ClockDescriptor{
		ClockID: auth.clockID, BootID: auth.bootID, Origin: auth.origin,
	})
	if err != nil {
		return nil, err
	}
	if row.expiresAtMs <= now {
		return nil, fmt.Errorf("%w: lease expired", ErrStaleLease)
	}
	return row, nil
}

// CommitLeased commits through CommitOwner's owner-local transaction while
// holding a current fencing lease. A stale token cannot append events, record a
// receipt, or run the effect; a successful commit completes the lease in the
// same transaction. An identical retry returns the stored response without
// re-running the effect.
func (s *OwnerStore) CommitLeased(ctx context.Context, journalID string, token LeaseToken,
	events []EventSubmission, effect func(*sql.Tx) error) ([]JournalEnvelope, error) {
	if err := s.checkWritable(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(journalID) == "" {
		return nil, fmt.Errorf("%w: journal_id is required", ErrInvalid)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("%w: at least one event submission is required", ErrInvalid)
	}
	if err := s.authorize(ctx, opCommitLeased, token.ResourceID); err != nil {
		return nil, err
	}
	receiptKey, err := commitReceiptKey(journalID, events)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, s.fail(fmt.Errorf("owner_store: begin leased commit: %w", err))
	}
	if replay, found, err := s.loadReceipt(ctx, tx, receiptKey, journalID); err != nil {
		tx.Rollback()
		return nil, s.fail(err)
	} else if found {
		tx.Rollback()
		return replay, nil
	}
	if _, err := s.validateLeaseToken(ctx, tx, token); err != nil {
		tx.Rollback()
		return nil, s.fail(err)
	}
	envelopes, _, err := s.commitWithinTx(ctx, tx, journalID, events, effect, receiptKey)
	if err != nil {
		tx.Rollback()
		return nil, s.fail(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE work_leases SET lease_state = ?, completed_at = ?
		WHERE resource_id = ? AND lease_id = ?;`,
		leaseStateCompleted, nowUTC(), token.ResourceID, token.LeaseID); err != nil {
		tx.Rollback()
		return nil, s.fail(fmt.Errorf("owner_store: complete lease: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return nil, s.fail(fmt.Errorf("owner_store: commit leased transaction: %w", err))
	}
	return envelopes, nil
}

// ChargeFailedAttempt charges one failed retry generation at most once. A
// duplicate reclamation with the same generation returns the existing count
// without charging again; a token from a fenced authority epoch or boot cannot
// charge at all.
func (s *OwnerStore) ChargeFailedAttempt(ctx context.Context, token LeaseToken, reason string) (int64, error) {
	if err := s.checkWritable(); err != nil {
		return 0, err
	}
	if strings.TrimSpace(token.ResourceID) == "" {
		return 0, fmt.Errorf("%w: lease token resource_id is required", ErrInvalid)
	}
	if strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("%w: failure reason is required", ErrInvalid)
	}
	if err := s.authorize(ctx, opChargeRetry, token.ResourceID); err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, s.fail(fmt.Errorf("owner_store: begin retry charge: %w", err))
	}
	defer tx.Rollback()

	auth, err := s.loadLeaseAuthority(ctx, tx)
	if err != nil {
		return 0, err
	}
	row, err := s.loadLeaseRow(ctx, tx, token.ResourceID)
	if err != nil {
		return 0, err
	}
	if row == nil {
		return 0, fmt.Errorf("%w: no durable lease for %s", ErrStaleLease, token.ResourceID)
	}
	if token.AuthorityEpoch != auth.epoch || row.authorityEpoch != auth.epoch ||
		token.BootID != auth.bootID || row.bootID != auth.bootID {
		return 0, fmt.Errorf("%w: token epoch/boot is not the current authority", ErrStaleLease)
	}
	if token.GenerationID != row.generationID {
		return 0, fmt.Errorf("%w: token generation is not the current generation", ErrStaleLease)
	}
	if row.state == leaseStateCompleted {
		return 0, fmt.Errorf("%w: a completed lease is not a failed retry", ErrStaleLease)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO retry_charges
		(resource_id, generation_id, lease_id, reason, charged_at) VALUES (?, ?, ?, ?, ?);`,
		row.resourceID, row.generationID, token.LeaseID, reason, nowUTC()); err != nil {
		if isConstraintFailure(err) {
			// This generation was already charged: duplicated reclamation
			// must not consume retries twice.
			var count int64
			if scanErr := tx.QueryRowContext(ctx,
				`SELECT retry_count FROM work_leases WHERE resource_id = ?;`, row.resourceID).Scan(&count); scanErr != nil {
				return 0, s.fail(fmt.Errorf("owner_store: read retry count: %w", scanErr))
			}
			return count, nil
		}
		return 0, s.fail(fmt.Errorf("owner_store: charge retry: %w", err))
	}
	count := row.retryCount + 1
	nextState := row.state
	if count > row.maxRetries {
		nextState = leaseStateExhausted
	}
	if _, err := tx.ExecContext(ctx, `UPDATE work_leases SET retry_count = ?, lease_state = ?, last_failure_reason = ?
		WHERE resource_id = ?;`, count, nextState, reason, row.resourceID); err != nil {
		return 0, s.fail(fmt.Errorf("owner_store: record retry charge: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return 0, s.fail(fmt.Errorf("owner_store: commit retry charge: %w", err))
	}
	return count, nil
}
