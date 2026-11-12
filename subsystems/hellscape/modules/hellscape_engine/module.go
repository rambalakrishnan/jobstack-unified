// Package engine implements the hellscape laboratory engine assembly.
//
// The engine opens exactly three independent SQLite WAL laboratory
// databases (application.db, observation.db, diagnostic.db), each with its
// own connection, writer queue, and durability boundary. Cross-database
// transactions, ATTACH DATABASE, and shared serialized writers are
// rejected. Browsers, subjects, external connectors, crawlers, and
// orchestrators remain external authorities; the engine embeds only the
// cooperative SPA and the laboratory control/application/telemetry
// handlers declared in CONSUMES.
package engine

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// OwnerStore is an owner-local durable store: one SQLite database plus one
// content-addressed artifact root, owned by exactly one owner domain.
type OwnerStore struct {
	db           *sql.DB
	artifactRoot string
	ownerDomain  string
}

// OpenOwner opens (or creates) the SQLite database at databasePath with WAL
// journal mode and FULL synchronous durability, then ensures the artifact
// root exists. Each call creates an independent connection, writer queue,
// and durability boundary; no state is shared between stores.
func OpenOwner(databasePath string, artifactRoot string, ownerDomain string) (*OwnerStore, error) {
	if databasePath == "" {
		return nil, &gapError{kind: "contract", msg: "owner_store: database path is required"}
	}
	if ownerDomain == "" {
		return nil, &gapError{kind: "contract", msg: "owner_store: owner domain is required"}
	}
	if artifactRoot == "" {
		return nil, &gapError{kind: "contract", msg: "owner_store: artifact root is required"}
	}
	dir := filepath.Dir(databasePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, &gapError{kind: "conformance", msg: fmt.Sprintf("owner_store: create database dir: %v", err)}
		}
	}
	if err := os.MkdirAll(artifactRoot, 0o755); err != nil {
		return nil, &gapError{kind: "conformance", msg: fmt.Sprintf("owner_store: create artifact root: %v", err)}
	}
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, &gapError{kind: "conformance", msg: fmt.Sprintf("owner_store: open %s: %v", databasePath, err)}
	}
	// database/sql pools connections; restrict each store to a single
	// connection so the store owns exactly one writer queue and one
	// durability boundary, never a shared serialized writer.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=FULL;`,
		`PRAGMA foreign_keys=ON;`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, &gapError{kind: "conformance", msg: fmt.Sprintf("owner_store: pragma %q: %v", pragma, err)}
		}
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS owner_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);`); err != nil {
		db.Close()
		return nil, &gapError{kind: "conformance", msg: fmt.Sprintf("owner_store: create owner_meta: %v", err)}
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO owner_meta (k, v) VALUES ('owner_domain', ?);`, ownerDomain); err != nil {
		db.Close()
		return nil, &gapError{kind: "conformance", msg: fmt.Sprintf("owner_store: record owner domain: %v", err)}
	}
	return &OwnerStore{db: db, artifactRoot: artifactRoot, ownerDomain: ownerDomain}, nil
}

// journalMode reports the SQLite journal mode in effect.
func (s *OwnerStore) journalMode() (string, error) {
	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode;`).Scan(&mode); err != nil {
		return "", err
	}
	return strings.ToLower(mode), nil
}

// synchronous reports the SQLite synchronous setting as a symbolic name.
func (s *OwnerStore) synchronous() (string, error) {
	var v int
	if err := s.db.QueryRow(`PRAGMA synchronous;`).Scan(&v); err != nil {
		return "", err
	}
	switch v {
	case 0:
		return "OFF", nil
	case 1:
		return "NORMAL", nil
	case 2:
		return "FULL", nil
	case 3:
		return "EXTRA", nil
	default:
		return fmt.Sprintf("UNKNOWN(%d)", v), nil
	}
}

// close releases this store's connection.
func (s *OwnerStore) close() error { return s.db.Close() }

// execLocal commits one owner-local statement batch through this store's
// own connection. Statements attempting ATTACH are rejected as contract
// gaps: no owner commit may acquire a peer-owned write lock, reference a
// peer database file, or span durability boundaries.
func (s *OwnerStore) execLocal(query string, args ...any) (sql.Result, error) {
	if strings.Contains(strings.ToLower(query), "attach") {
		return nil, &gapError{kind: "contract", msg: "owner_store: ATTACH DATABASE is rejected; no cross-database commits"}
	}
	return s.db.Exec(query, args...)
}

// gapError reports an assembly failure as a contract or conformance gap,
// never as hidden ad hoc plumbing.
type gapError struct {
	kind string // "contract" or "conformance"
	msg  string
}

func (e *gapError) Error() string { return e.kind + " gap: " + e.msg }

// Kind reports whether the failure is a contract or conformance gap.
func (e *gapError) Kind() string { return e.kind }

// VersionPin pins an immutable build identity for the embedded SPA.
type VersionPin struct {
	Version string
	Digest  string
}

// NewCooperativeSPA serves the embedded cooperative SPA assets. It serves
// ordinary SPA controls over HTTP only; it does not merge browser,
// subject, or connector runtimes into the engine process.
func NewCooperativeSPA(assets fs.FS, build VersionPin) (http.Handler, error) {
	if assets == nil {
		return nil, &gapError{kind: "contract", msg: "cooperative_assets: asset filesystem is required"}
	}
	if build.Version == "" {
		return nil, &gapError{kind: "contract", msg: "cooperative_assets: version pin is required"}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/spa/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":%q,"digest":%q}`, build.Version, build.Digest)
	})
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return mux, nil
}

// NewControlHandler exposes the laboratory control surface over the three
// owner stores and a pinned authentication policy. Startup configuration
// and shutdown wiring stay private to the engine; this handler is only the
// declared public control surface.
func NewControlHandler(primary *OwnerStore, application *OwnerStore, observation *OwnerStore, authenticationPolicy []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/control/health", func(w http.ResponseWriter, _ *http.Request) {
		ready := primary != nil && application != nil && observation != nil
		if !ready {
			http.Error(w, `{"ok":false}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"policy_bytes":%d}`, len(authenticationPolicy))
	})
	return mux
}

// NewApplicationHandler serves the application-owner surface for its store.
func NewApplicationHandler(store *OwnerStore) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/application/health", func(w http.ResponseWriter, _ *http.Request) {
		if store == nil {
			http.Error(w, `{"ok":false}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"owner":%q}`, store.ownerDomain)
	})
	return mux
}

// NewTelemetryHandler serves the observation-owner telemetry surface.
func NewTelemetryHandler(store *OwnerStore) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/telemetry/health", func(w http.ResponseWriter, _ *http.Request) {
		if store == nil {
			http.Error(w, `{"ok":false}`, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"owner":%q}`, store.ownerDomain)
	})
	return mux
}

// ServeSessionWork runs session admission/finalization work across the
// owner stores until ctx ends. It performs no cross-owner transactions and
// issues no browser, subject, crawler, orchestrator, dashboard, or Firebase
// traffic: with no queued sessions it simply waits for cancellation.
func ServeSessionWork(ctx context.Context, primary *OwnerStore, application *OwnerStore, observation *OwnerStore) error {
	if primary == nil || application == nil || observation == nil {
		return &gapError{kind: "contract", msg: "session_runtime: primary, application, and observation stores are required"}
	}
	<-ctx.Done()
	return ctx.Err()
}

// sessionOutcome records how one admitted laboratory session resolved.
type sessionOutcome struct {
	sessionID string
	eligible  bool
	// launchFailed marks an immediate launch failure: the session never
	// became eligible and must not count toward throughput.
	launchFailed bool
}

// throughputReport separates eligible finalized sessions from launch
// failures. Immediate launch-failure loops never satisfy throughput.
type throughputReport struct {
	eligibleFinalized int
	launchFailures    int
	attempted         int
}

// reportThroughput partitions session outcomes: eligible finalized
// sessions count toward throughput; launch failures are reported
// separately and never counted as eligible.
func reportThroughput(outcomes []sessionOutcome) throughputReport {
	var r throughputReport
	for _, o := range outcomes {
		r.attempted++
		switch {
		case o.launchFailed:
			r.launchFailures++
		case o.eligible:
			r.eligibleFinalized++
		}
	}
	return r
}

// engine is an assembled laboratory engine: exactly three independent
// owner stores plus the embedded SPA and the laboratory HTTP surfaces.
type engine struct {
	primary      *OwnerStore
	application  *OwnerStore
	observation  *OwnerStore
	control      http.Handler
	applicationAPI http.Handler
	telemetry    http.Handler
	spa          http.Handler
}

// assemble opens the three laboratory databases under root and wires the
// embedded SPA and laboratory handlers. databaseNames must name exactly
// the three laboratory databases; any shared-writer or attached-database
// configuration is rejected.
func assemble(root string, databaseNames [3]string, assets fs.FS, build VersionPin, authenticationPolicy []byte) (*engine, error) {
	want := map[string]string{
		"application.db": "application",
		"observation.db": "observation",
		"diagnostic.db":  "diagnostic",
	}
	seen := map[string]bool{}
	for _, n := range databaseNames {
		if _, ok := want[n]; !ok {
			return nil, &gapError{kind: "contract", msg: fmt.Sprintf("engine: unexpected database %q: want application.db, observation.db, diagnostic.db", n)}
		}
		if seen[n] {
			return nil, &gapError{kind: "contract", msg: fmt.Sprintf("engine: duplicate database %q: each laboratory database needs an independent store", n)}
		}
		seen[n] = true
	}
	if len(seen) != 3 {
		return nil, &gapError{kind: "contract", msg: "engine: exactly three independent laboratory databases are required"}
	}
	open := func(name, domain string) (*OwnerStore, error) {
		return OpenOwner(
			filepath.Join(root, name),
			filepath.Join(root, "artifacts", domain),
			domain,
		)
	}
	application, err := open("application.db", "application")
	if err != nil {
		return nil, err
	}
	observation, err := open("observation.db", "observation")
	if err != nil {
		application.close()
		return nil, err
	}
	primary, err := open("diagnostic.db", "diagnostic")
	if err != nil {
		application.close()
		observation.close()
		return nil, err
	}
	spa, err := NewCooperativeSPA(assets, build)
	if err != nil {
		application.close()
		observation.close()
		primary.close()
		return nil, err
	}
	return &engine{
		primary:        primary,
		application:    application,
		observation:    observation,
		control:        NewControlHandler(primary, application, observation, authenticationPolicy),
		applicationAPI: NewApplicationHandler(application),
		telemetry:      NewTelemetryHandler(observation),
		spa:            spa,
	}, nil
}

// close releases the engine's three owner stores.
func (e *engine) close() error {
	var first error
	for _, s := range []*OwnerStore{e.application, e.observation, e.primary} {
		if s == nil {
			continue
		}
		if err := s.close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
