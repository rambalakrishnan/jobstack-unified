package engine

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

// testAssets returns a minimal in-memory SPA asset filesystem.
func testAssets() fs.FS {
	return fstest.MapFS{
		"index.html": {Data: []byte(`<!doctype html><html><body><div id="app"></div></body></html>`)},
		"app.js":     {Data: []byte(`console.log("hellscape spa");`)},
	}
}

func testPin() VersionPin {
	return VersionPin{Version: "m1-silo-1", Digest: "sha256:test"}
}

// openEngine assembles a full three-database engine under a temp root.
func openEngine(t *testing.T) (*engine, string) {
	t.Helper()
	root := t.TempDir()
	e, err := assemble(root,
		[3]string{"application.db", "observation.db", "diagnostic.db"},
		testAssets(), testPin(), []byte(`{"mode":"laboratory"}`))
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	t.Cleanup(func() { e.close() })
	return e, root
}

// TestEngineOpensExactlyThreeIndependentLaboratoryDatabases asserts the
// 4.1 allocation: exactly application.db, observation.db, diagnostic.db,
// each WAL + synchronous=FULL, independent connections/writers/paths.
func TestEngineOpensExactlyThreeIndependentLaboratoryDatabases(t *testing.T) {
	e, root := openEngine(t)
	stores := map[string]*OwnerStore{
		"application.db": e.application,
		"observation.db": e.observation,
		"diagnostic.db":  e.primary,
	}
	if len(stores) != 3 {
		t.Fatalf("want exactly 3 owner stores, got %d", len(stores))
	}
	paths := map[string]bool{}
	for name, s := range stores {
		if s == nil {
			t.Fatalf("%s: store is nil", name)
		}
		want := filepath.Join(root, name)
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("%s: database file missing at %s: %v", name, want, err)
		}
		paths[want] = true
		mode, err := s.journalMode()
		if err != nil {
			t.Fatalf("%s: journal_mode: %v", name, err)
		}
		if mode != "wal" {
			t.Fatalf("%s: journal_mode=%q, want wal", name, mode)
		}
		syncMode, err := s.synchronous()
		if err != nil {
			t.Fatalf("%s: synchronous: %v", name, err)
		}
		if syncMode != "FULL" {
			t.Fatalf("%s: synchronous=%q, want FULL", name, syncMode)
		}
		for _, other := range []string{
			filepath.Join(root, "artifacts", s.ownerDomain),
		} {
			if _, err := os.Stat(other); err != nil {
				t.Fatalf("%s: artifact root %s missing: %v", name, other, err)
			}
		}
	}
	if len(paths) != 3 {
		t.Fatalf("database paths are not independent: %v", paths)
	}
	// Independence: concurrent owner-local writes to all three stores
	// must all commit without waiting on a shared serialized writer.
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for name, s := range stores {
		wg.Add(1)
		go func(name string, s *OwnerStore) {
			defer wg.Done()
			for i := range 5 {
				k := fmt.Sprintf("probe-%s-%d", name, i)
				if _, err := s.db.Exec(`INSERT OR REPLACE INTO owner_meta (k, v) VALUES (?, '1');`, k); err != nil {
					errs <- fmt.Errorf("%s: independent write: %w", name, err)
					return
				}
			}
		}(name, s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// Rejection: cross-database ATTACH commits are not part of the
	// engine surface; the owner-local write gate rejects them as
	// contract gaps instead of spanning durability boundaries.
	if _, err := e.application.execLocal(`ATTACH DATABASE '` + filepath.Join(root, "observation.db") + `' AS peer;`); err == nil {
		t.Fatalf("ATTACH DATABASE accepted; must be rejected as a contract gap")
	} else if gap, ok := err.(*gapError); !ok || gap.Kind() != "contract" {
		t.Fatalf("ATTACH rejection = %v (%T), want contract *gapError", err, err)
	}
	if _, err := e.application.execLocal(`ATTACH DATABASE '` + filepath.Join(root, "observation.db") + `' AS peer; INSERT INTO peer.owner_meta (k,v) VALUES ('x','y'); INSERT INTO main.cross_probe (a) VALUES ('x');`); err == nil {
		t.Fatalf("cross-database shared commit succeeded; must be rejected by architecture")
	}
}

// TestHellscapePassesKernelLifecycleConnectorAndOwnerSuitesWithSyntheticPeers
// exercises the kernel (owner commit), lifecycle (session work start/stop),
// connector-shaped (application/telemetry/control handlers), and owner
// (WAL durability + revision write/read) behaviors against synthetic
// in-process peers: no live backend is contacted.
func TestHellscapePassesKernelLifecycleConnectorAndOwnerSuitesWithSyntheticPeers(t *testing.T) {
	e, _ := openEngine(t)
	// Owner suite (synthetic): durable owner-local write then read-back.
	for name, s := range map[string]*OwnerStore{
		"application": e.application, "observation": e.observation, "diagnostic": e.primary,
	} {
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO owner_meta (k, v) VALUES ('synthetic-rev-1', 'pinned');`); err != nil {
			t.Fatalf("%s: synthetic owner write: %v", name, err)
		}
		var v string
		if err := s.db.QueryRow(`SELECT v FROM owner_meta WHERE k='synthetic-rev-1';`).Scan(&v); err != nil || v != "pinned" {
			t.Fatalf("%s: synthetic owner read: v=%q err=%v", name, v, err)
		}
	}
	// Lifecycle suite (synthetic): session work runs until cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSessionWork(ctx, e.primary, e.application, e.observation) }()
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("ServeSessionWork after cancel = %v, want context.Canceled", err)
	}
	// Connector-shaped suite (synthetic peers): every laboratory surface
	// answers healthy over loopback httptest recorders.
	for name, h := range map[string]http.Handler{
		"control": e.control, "application": e.applicationAPI, "telemetry": e.telemetry, "spa": e.spa,
	} {
		if h == nil {
			t.Fatalf("%s: handler is nil", name)
		}
	}
	for path, h := range map[string]http.Handler{
		"/control/health": e.control, "/application/health": e.applicationAPI, "/telemetry/health": e.telemetry,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

// TestM1AcceptanceRequiresNoLiveCircusTentOrRingmaster asserts M1 silo
// acceptance completes with no live subject, circus-tent, or Ringmaster:
// the full assemble + handler + session-work path runs with loopback-only
// traffic and no such endpoint configured.
func TestM1AcceptanceRequiresNoLiveCircusTentOrRingmaster(t *testing.T) {
	for _, k := range []string{"CIRCUS_TENT_URL", "RINGMASTER_URL", "HELLSACPE_LIVE_SUBJECT"} {
		if v := os.Getenv(k); v != "" {
			t.Fatalf("silo acceptance must not require %s (got %q)", k, v)
		}
	}
	e, _ := openEngine(t)
	rec := httptest.NewRecorder()
	e.control.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/control/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("silo control health = %d, want 200 without live tent/ringmaster", rec.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ServeSessionWork(ctx, e.primary, e.application, e.observation); err != context.Canceled {
		t.Fatalf("silo session work = %v, want clean cancel without live peers", err)
	}
}

// TestSiloAcceptanceRequiresNoCrawlerOrchestratorDashboardOrFirebase asserts
// silo acceptance needs no crawler, orchestrator, dashboard, Firebase
// service, or production origin: everything runs from local files.
func TestSiloAcceptanceRequiresNoCrawlerOrchestratorDashboardOrFirebase(t *testing.T) {
	for _, k := range []string{"CRAWLER_URL", "ORCHESTRATOR_URL", "DASHBOARD_URL", "FIREBASE_CONFIG", "PRODUCTION_ORIGIN"} {
		if v := os.Getenv(k); v != "" {
			t.Fatalf("silo acceptance must not require %s (got %q)", k, v)
		}
	}
	e, _ := openEngine(t)
	for _, tc := range []struct {
		name    string
		handler http.Handler
		path    string
	}{
		{"control", e.control, "/control/health"},
		{"application", e.applicationAPI, "/application/health"},
		{"telemetry", e.telemetry, "/telemetry/health"},
	} {
		rec := httptest.NewRecorder()
		tc.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s silo surface %s = %d, want 200 with no external services", tc.name, tc.path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "crawler") ||
			strings.Contains(rec.Body.String(), "orchestrator") ||
			strings.Contains(rec.Body.String(), "firebase") {
			t.Fatalf("%s response references external services: %s", tc.name, rec.Body.String())
		}
	}
}

// TestAssemblyFailureIsReportedAsContractOrConformanceGap asserts that a
// post-silo assembly failure surfaces as a typed contract/conformance gap,
// never as hidden ad hoc plumbing.
func TestAssemblyFailureIsReportedAsContractOrConformanceGap(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name string
		dbs  [3]string
	}{
		{"unknown-database", [3]string{"application.db", "observation.db", "mystery.db"}},
		{"duplicate-database", [3]string{"application.db", "application.db", "diagnostic.db"}},
		{"missing-database", [3]string{"application.db", "observation.db", "observation.db"}},
	}
	for _, tc := range cases {
		e, err := assemble(root+"/"+tc.name,
			tc.dbs, testAssets(), testPin(), []byte(`{}`))
		if err == nil {
			if e != nil {
				e.close()
			}
			t.Fatalf("%s: assemble succeeded, want contract/conformance gap", tc.name)
			continue
		}
		gap, ok := err.(*gapError)
		if !ok {
			t.Fatalf("%s: error type %T, want *gapError (contract/conformance gap)", tc.name, err)
		}
		if gap.Kind() != "contract" && gap.Kind() != "conformance" {
			t.Fatalf("%s: gap kind %q, want contract or conformance", tc.name, gap.Kind())
		}
		if !strings.Contains(strings.ToLower(gap.Error()), "gap") {
			t.Fatalf("%s: error %q does not report itself as a gap", tc.name, gap.Error())
		}
	}
	if _, err := OpenOwner("", t.TempDir(), "application"); err == nil {
		t.Fatalf("OpenOwner with empty path succeeded, want contract gap")
	} else if gap, ok := err.(*gapError); !ok || gap.Kind() != "contract" {
		t.Fatalf("OpenOwner empty path error = %v (%T), want contract *gapError", err, err)
	}
	if _, err := NewCooperativeSPA(nil, testPin()); err == nil {
		t.Fatalf("NewCooperativeSPA with nil assets succeeded, want contract gap")
	} else if gap, ok := err.(*gapError); !ok || gap.Kind() != "contract" {
		t.Fatalf("NewCooperativeSPA nil assets error = %v (%T), want contract *gapError", err, err)
	}
}

// TestEngineEmbedsSPAWithoutMergingBrowserOrConnectorRuntimes asserts the
// H9 single-deployable-engine shape: the SPA is embedded and served
// byte-identical over HTTP, while no browser/subject/connector runtime is
// merged into the engine (source-scanned for forbidden runtime tokens).
func TestEngineEmbedsSPAWithoutMergingBrowserOrConnectorRuntimes(t *testing.T) {
	e, _ := openEngine(t)
	if e.spa == nil {
		t.Fatalf("embedded SPA handler is nil")
	}
	rec := httptest.NewRecorder()
	e.spa.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/spa/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /spa/version = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "m1-silo-1") {
		t.Fatalf("SPA version body %q missing pinned version", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	e.spa.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<div id="app">`) {
		t.Fatalf("SPA index body altered in transit: %q", rec.Body.String())
	}
	src, err := os.ReadFile("module.go")
	if err != nil {
		t.Fatalf("read module.go: %v", err)
	}
	// Strip comments: prohibition documentation names external runtimes
	// the engine must not merge; only merged code counts.
	code := string(src)
	for {
		start := strings.Index(code, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(code[start+2:], "*/")
		if end < 0 {
			code = code[:start]
			break
		}
		code = code[:start] + code[start+2+end+2:]
	}
	lines := strings.Split(code, "\n")
	for i, ln := range lines {
		if idx := strings.Index(ln, "//"); idx >= 0 {
			lines[i] = ln[:idx]
		}
	}
	lower := strings.ToLower(strings.Join(lines, "\n"))
	for _, token := range []string{
		"playwright", "chromium", "selenium", "puppeteer", "webdriver",
		"crawler", "orchestrator", "firebase", "dashboard",
		"os/exec", "plugin.open",
	} {
		if strings.Contains(lower, token) {
			t.Fatalf("engine source merges external runtime %q", token)
		}
	}
}

// TestThroughputReportingSeparatesEligibleSessionsFromLaunchFailures
// asserts H2 accounting: eligible finalized sessions count toward
// throughput while immediate launch failures are reported separately and
// never counted as eligible.
func TestThroughputReportingSeparatesEligibleSessionsFromLaunchFailures(t *testing.T) {
	outcomes := []sessionOutcome{
		{sessionID: "s-elg-1", eligible: true},
		{sessionID: "s-elg-2", eligible: true},
		{sessionID: "s-elg-3", eligible: true},
		{sessionID: "s-lf-1", launchFailed: true},
		{sessionID: "s-lf-2", launchFailed: true},
		{sessionID: "s-lf-3", launchFailed: true},
		{sessionID: "s-lf-4", launchFailed: true},
		{sessionID: "s-lf-5", launchFailed: true},
		{sessionID: "s-inelig", eligible: false},
	}
	r := reportThroughput(outcomes)
	if r.eligibleFinalized != 3 {
		t.Fatalf("eligibleFinalized = %d, want 3", r.eligibleFinalized)
	}
	if r.launchFailures != 5 {
		t.Fatalf("launchFailures = %d, want 5", r.launchFailures)
	}
	if r.attempted != len(outcomes) {
		t.Fatalf("attempted = %d, want %d", r.attempted, len(outcomes))
	}
	if r.eligibleFinalized+r.launchFailures > r.attempted {
		t.Fatalf("counts overlap: %+v", r)
	}
	// Launch-failure loops alone never satisfy throughput.
	loops := make([]sessionOutcome, 100)
	for i := range loops {
		loops[i] = sessionOutcome{sessionID: fmt.Sprintf("loop-%d", i), launchFailed: true}
	}
	lr := reportThroughput(loops)
	if lr.eligibleFinalized != 0 {
		t.Fatalf("launch-failure loop yielded %d eligible sessions, want 0", lr.eligibleFinalized)
	}
	if lr.launchFailures != 100 {
		t.Fatalf("launch-failure loop failures = %d, want 100", lr.launchFailures)
	}
}
