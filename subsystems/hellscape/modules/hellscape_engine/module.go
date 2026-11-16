// Package engine assembles the hellscape laboratory engine from its
// owner-separated siblings.
//
// The engine opens exactly three independent laboratory databases
// (application.db, observation.db, diagnostic.db) through owner_store, each
// with its own connection, writer queue, and durability boundary. Publication
// stays asynchronous; no cross-database transaction is ever attempted.
// The cooperative SPA is embedded through cooperative_assets and the
// laboratory surfaces through control_http, application_owner, and
// observation_owner. Session work runs through session_runtime. External
// runtimes stay external authorities.
//
// All wiring stays private: executable main, startup configuration, and
// shutdown wiring are not exported.
package engine

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"

	"application_owner"
	"control_http"
	"cooperative_assets"
	"observation_owner"
	"owner_store"
	"session_runtime"
)

// gapError reports an assembly failure as a contract or conformance gap,
// never as hidden ad hoc plumbing.
type gapError struct {
	kind string // "contract" or "conformance"
	msg  string
}

func (e *gapError) Error() string { return e.kind + " gap: " + e.msg }

// Kind reports whether the failure is a contract or conformance gap.
func (e *gapError) Kind() string { return e.kind }

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
	primary        *owner_store.OwnerStore
	application    *owner_store.OwnerStore
	observation    *owner_store.OwnerStore
	control        http.Handler
	applicationAPI http.Handler
	telemetry      http.Handler
	spa            http.Handler
}

// assemble opens the three laboratory databases under root and wires the
// embedded SPA and laboratory handlers. databaseNames must name exactly
// the three laboratory databases; any shared-writer or attached-database
// configuration is rejected as a contract gap. Owner-store and SPA
// failures are wrapped as contract or conformance gaps.
func assemble(root string, databaseNames [3]string, assets fs.FS, build cooperative_assets.VersionPin, authenticationPolicy []byte) (*engine, error) {
	if root == "" {
		return nil, &gapError{kind: "contract", msg: "engine: laboratory root is required"}
	}
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
	open := func(name, domain string) (*owner_store.OwnerStore, error) {
		store, err := owner_store.OpenOwner(
			filepath.Join(root, name),
			filepath.Join(root, "artifacts", domain),
			domain,
		)
		if err != nil {
			return nil, &gapError{kind: "conformance", msg: fmt.Sprintf("engine: open %s: %v", name, err)}
		}
		return store, nil
	}
	application, err := open("application.db", "application")
	if err != nil {
		return nil, err
	}
	observation, err := open("observation.db", "observation")
	if err != nil {
		_ = application.Close()
		return nil, err
	}
	primary, err := open("diagnostic.db", "diagnostic")
	if err != nil {
		_ = application.Close()
		_ = observation.Close()
		return nil, err
	}
	spa, err := cooperative_assets.NewCooperativeSPA(assets, build)
	if err != nil {
		_ = application.Close()
		_ = observation.Close()
		_ = primary.Close()
		return nil, &gapError{kind: "contract", msg: fmt.Sprintf("engine: embed cooperative SPA: %v", err)}
	}
	return &engine{
		primary:        primary,
		application:    application,
		observation:    observation,
		control:        control_http.NewControlHandler(primary, application, observation, authenticationPolicy),
		applicationAPI: application_owner.NewApplicationHandler(application),
		telemetry:      observation_owner.NewTelemetryHandler(observation),
		spa:            spa,
	}, nil
}

// serve runs bounded session work across the owner stores until ctx ends.
// It performs no cross-owner transaction and issues no external traffic
// with no queued sessions; it simply waits for cancellation.
func (e *engine) serve(ctx context.Context) error {
	return session_runtime.ServeSessionWork(ctx, e.primary, e.application, e.observation)
}

// close releases the engine's three owner stores.
func (e *engine) close() error {
	var first error
	for _, s := range []*owner_store.OwnerStore{e.application, e.observation, e.primary} {
		if s == nil {
			continue
		}
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
