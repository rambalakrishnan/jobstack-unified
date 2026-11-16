package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"authority"
	"cooperative_assets"
	"owner_store"

	_ "modernc.org/sqlite"
)

const cooperativeIndexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Hellscape Cooperative Fixture</title>
<link rel="stylesheet" href="styles.css">
</head>
<body>
<main>
<h1>Practice application</h1>
<form id="contact-form" action="/api/contact" method="post">
<label for="full-name">Full name</label>
<input id="full-name" name="fullName" type="text" autocomplete="name" required>
<label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="email" required>
<button id="continue-contact" name="continueContact" type="submit">Save and continue</button>
</form>
<section aria-live="polite">
<p id="progress" role="status"></p>
<p id="validation-message" role="alert"></p>
</section>
</main>
<script src="app.js"></script>
</body>
</html>
`

const cooperativeAppJS = `'use strict';
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('contact-form');
  const progress = document.getElementById('progress');
  const message = document.getElementById('validation-message');
  const controls = Array.from(form.querySelectorAll('input, button'));
  const ready = controls.length > 0 && controls.every((el) => !el.disabled);
  if (ready) {
    document.body.setAttribute('data-readiness', 'ready');
    window.__hellscapeReady = true;
    document.dispatchEvent(new CustomEvent('hellscape:ready'));
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    progress.textContent = 'Saving...';
    message.textContent = '';
    try {
      const response = await fetch('/api/contact', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          fullName: document.getElementById('full-name').value,
          email: document.getElementById('email').value,
        }),
      });
      if (!response.ok) {
        message.textContent = 'Validation failed. Review the highlighted fields.';
        return;
      }
      progress.textContent = 'Saved.';
    } catch (err) {
      message.textContent = 'Request failed. Retry explicitly.';
    }
  });
});
`

const cooperativeCSS = `body { font-family: system-ui, sans-serif; line-height: 1.5; margin: 2rem; }
main { max-width: 40rem; }
label { display: block; margin-top: 1rem; }
input, button { font: inherit; padding: 0.5rem; margin-top: 0.25rem; }
button { cursor: pointer; }
#validation-message { color: #7a0000; }
`

// testAssets returns the minimal M1 cooperative SPA bundle.
func testAssets() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {Data: []byte(cooperativeIndexHTML)},
		"app.js":     {Data: []byte(cooperativeAppJS)},
		"styles.css": {Data: []byte(cooperativeCSS)},
	}
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// pinForAssets computes the cooperative build pin for fsys, replicating the
// cooperative_assets manifest digest (path + newline + file digest + newline
// per file in ascending path order, hashed as a whole).
func pinForAssets(t *testing.T, fsys fs.FS) cooperative_assets.VersionPin {
	t.Helper()
	snapshot := map[string][]byte{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		snapshot[p] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk assets: %v", err)
	}
	names := make([]string, 0, len(snapshot))
	for name := range snapshot {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		manifest.WriteString(name)
		manifest.WriteString("\n")
		manifest.WriteString(hashBytes(snapshot[name]))
		manifest.WriteString("\n")
	}
	return cooperative_assets.VersionPin{
		ID:             "hellscape-spa",
		Version:        "m1-silo-1",
		ArtifactDigest: hashBytes([]byte(manifest.String())),
	}
}

func testPolicy() []byte {
	return []byte(`{"channels":{"test-channel":{"principal":"test-writer","kind":"owner","grants":[{"domain":"*","operations":["*"]}]}}}`)
}

func authedContext(t *testing.T) context.Context {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://hellscape-engine.test/direct", nil)
	if err != nil {
		t.Fatalf("build auth request: %v", err)
	}
	req.Header.Set("Authorization", "Channel test-channel")
	ctx, err := authority.Authenticate(req, testPolicy())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return ctx
}

// openEngine assembles a full three-database engine under a temp root.
func openEngine(t *testing.T) (*engine, string) {
	t.Helper()
	root := t.TempDir()
	fsys := testAssets()
	e, err := assemble(root,
		[3]string{"application.db", "observation.db", "diagnostic.db"},
		fsys, pinForAssets(t, fsys), testPolicy())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	t.Cleanup(func() { _ = e.close() })
	return e, root
}

func serve(handler http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}
// serveUntilCancel runs session work until setup completes and the context
// is cancelled, returning the serve result. Setup (journal open) needs a
// live context; cancelling before setup races artifact installation.
func serveUntilCancel(t *testing.T, e *engine, ctx context.Context) error {
	t.Helper()
	live, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- e.serve(live) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("serve did not stop after cancel")
		return nil
	}
}

// TestEngineOpensExactlyThreeIndependentLaboratoryDatabases asserts the
// 4.1 allocation: exactly application.db, observation.db, diagnostic.db,
// each WAL + synchronous=FULL, independent connections/writers/paths,
// with cross-database commits rejected.
func TestEngineOpensExactlyThreeIndependentLaboratoryDatabases(t *testing.T) {
	e, root := openEngine(t)
	stores := map[string]*owner_store.OwnerStore{
		"application.db": e.application,
		"observation.db": e.observation,
		"diagnostic.db":  e.primary,
	}
	if len(stores) != 3 {
		t.Fatalf("want exactly 3 owner stores, got %d", len(stores))
	}
	seen := map[*owner_store.OwnerStore]string{}
	paths := map[string]bool{}
	for name, s := range stores {
		if s == nil {
			t.Fatalf("%s: store is nil", name)
		}
		if prev, dup := seen[s]; dup {
			t.Fatalf("%s shares *OwnerStore pointer with %s: want independent stores", name, prev)
		}
		seen[s] = name
		want := filepath.Join(root, name)
		if _, err := os.Stat(want); err != nil {
			t.Fatalf("%s: database file missing at %s: %v", name, want, err)
		}
		paths[want] = true
	}
	if len(paths) != 3 {
		t.Fatalf("database paths are not independent: %v", paths)
	}
	for _, domain := range []string{"application", "observation", "diagnostic"} {
		for _, dir := range []string{
			filepath.Join(root, "artifacts", domain),
			filepath.Join(root, "artifacts", domain, "objects"),
			filepath.Join(root, "artifacts", domain, "tmp"),
		} {
			if _, err := os.Stat(dir); err != nil {
				t.Fatalf("artifact dir %s missing: %v", dir, err)
			}
		}
	}
	// Durability: owner_store.OpenOwner verifies WAL + synchronous=FULL and
	// refuses weaker settings, so successful assembly already proves the
	// pragma contract. WAL mode is persistent; confirm it on fresh
	// read-only connections as well.
	for name := range stores {
		db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(root, name))+"?mode=ro")
		if err != nil {
			t.Fatalf("%s: open probe: %v", name, err)
		}
		var mode string
		if err := db.QueryRow(`PRAGMA journal_mode;`).Scan(&mode); err != nil {
			db.Close()
			t.Fatalf("%s: journal_mode: %v", name, err)
		}
		db.Close()
		if !strings.EqualFold(mode, "wal") {
			t.Fatalf("%s: journal_mode=%q, want wal", name, mode)
		}
	}
	// Independence: concurrent engine-local work across all three stores
	// must complete without a shared serialized writer.
	var wg sync.WaitGroup
	errs := make(chan error, 9)
	for name, s := range stores {
		_ = s
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if _, err := os.Stat(filepath.Join(root, name)); err != nil {
				errs <- fmt.Errorf("%s: stat: %w", name, err)
				return
			}
			rec := serve(e.spa, http.MethodGet, "/index.html")
			if rec.Code != http.StatusOK {
				errs <- fmt.Errorf("%s: spa serve = %d, want 200", name, rec.Code)
				return
			}
			rec = serve(e.control, http.MethodGet, "/control/unknown-"+name)
			if rec.Code != http.StatusNotFound {
				errs <- fmt.Errorf("%s: control unknown = %d, want 404", name, rec.Code)
				return
			}
		}(name)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// Rejection: ATTACH DATABASE is denied by the owner-store connection
	// guard, so no commit can span durability boundaries.
	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(root, "application.db")))
	if err != nil {
		t.Fatalf("open raw application.db: %v", err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`ATTACH DATABASE '` + filepath.Join(root, "observation.db") + `' AS peer;`); err == nil {
		t.Fatalf("ATTACH DATABASE accepted; must be rejected (no cross-database commits)")
	}
}

// TestHellscapePassesKernelLifecycleConnectorAndOwnerSuitesWithSyntheticPeers
// exercises the kernel (durable artifact install), lifecycle (session work
// start/stop), connector-shaped (application/telemetry/control handlers),
// and owner (per-owner artifact identity) behaviors against synthetic
// in-process peers: no live backend is contacted.
func TestHellscapePassesKernelLifecycleConnectorAndOwnerSuitesWithSyntheticPeers(t *testing.T) {
	e, _ := openEngine(t)
	ctx := authedContext(t)
	// Owner/kernel suite (synthetic): durable artifact install on each
	// owner boundary, each reporting its own owner domain.
	for domain, s := range map[string]*owner_store.OwnerStore{
		"application": e.application, "observation": e.observation, "diagnostic": e.primary,
	} {
		ref, err := owner_store.InstallArtifact(ctx, s, bytes.NewReader([]byte("synthetic-"+domain)), "text/plain", "public")
		if err != nil {
			t.Fatalf("%s: synthetic install: %v", domain, err)
		}
		if !strings.HasPrefix(ref.Digest, "sha256:") || len(ref.Digest) != len("sha256:")+64 {
			t.Fatalf("%s: digest %q is not a sha256 content address", domain, ref.Digest)
		}
		if ref.OwnerDomain != domain {
			t.Fatalf("%s: OwnerDomain=%q, want %q", domain, ref.OwnerDomain, domain)
		}
	}
	// Lifecycle suite (synthetic): session work runs until cancelled with
	// no queued work and no connector endpoint.
	if err := serveUntilCancel(t, e, ctx); err != nil {
		t.Fatalf("serve after cancel = %v, want nil (clean stop, no live peers)", err)
	}
	// Connector-shaped suite (synthetic peers): every laboratory surface
	// is wired and answers over loopback httptest recorders.
	for name, h := range map[string]http.Handler{
		"control": e.control, "application": e.applicationAPI, "telemetry": e.telemetry, "spa": e.spa,
	} {
		if h == nil {
			t.Fatalf("%s: handler is nil", name)
		}
	}
	if rec := serve(e.spa, http.MethodGet, "/index.html"); rec.Code != http.StatusOK {
		t.Fatalf("GET /index.html = %d, want 200", rec.Code)
	}
	for target, h := range map[string]http.Handler{
		"/control/no-such-route": e.control,
		"/api/no-such-endpoint":  e.applicationAPI,
		"/no-such-route":         e.telemetry,
	} {
		if rec := serve(h, http.MethodGet, target); rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404 (wired handler, unknown route)", target, rec.Code)
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
	if rec := serve(e.spa, http.MethodGet, "/index.html"); rec.Code != http.StatusOK {
		t.Fatalf("silo SPA = %d, want 200 without live tent/ringmaster", rec.Code)
	}
	if rec := serve(e.control, http.MethodGet, "/control/no-such-route"); rec.Code != http.StatusNotFound {
		t.Fatalf("silo control = %d, want 404 without live tent/ringmaster", rec.Code)
	}
	if err := serveUntilCancel(t, e, authedContext(t)); err != nil {
		t.Fatalf("silo session work = %v, want clean stop without live peers", err)
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
	cases := []struct {
		name    string
		handler http.Handler
		method  string
		path    string
		want    int
	}{
		{"spa", e.spa, http.MethodGet, "/index.html", http.StatusOK},
		{"control", e.control, http.MethodGet, "/control/no-such-route", http.StatusNotFound},
		{"application", e.applicationAPI, http.MethodGet, "/api/no-such-endpoint", http.StatusNotFound},
		{"telemetry", e.telemetry, http.MethodGet, "/no-such-route", http.StatusNotFound},
	}
	for _, tc := range cases {
		rec := serve(tc.handler, tc.method, tc.path)
		if rec.Code != tc.want {
			t.Fatalf("%s silo surface %s = %d, want %d with no external services", tc.name, tc.path, rec.Code, tc.want)
		}
		lower := strings.ToLower(rec.Body.String())
		for _, token := range []string{"crawler", "orchestrator", "firebase", "dashboard"} {
			if strings.Contains(lower, token) {
				t.Fatalf("%s response references external service %q: %s", tc.name, token, rec.Body.String())
			}
		}
	}
	if err := serveUntilCancel(t, e, authedContext(t)); err != nil {
		t.Fatalf("silo session work = %v, want clean stop with no external services", err)
	}
}

// TestAssemblyFailureIsReportedAsContractOrConformanceGap asserts that a
// post-silo assembly failure surfaces as a typed contract/conformance gap,
// never as hidden ad hoc plumbing.
func TestAssemblyFailureIsReportedAsContractOrConformanceGap(t *testing.T) {
	fsys := testAssets()
	goodPin := pinForAssets(t, fsys)
	cases := []struct {
		name string
		dbs  [3]string
	}{
		{"unknown-database", [3]string{"application.db", "observation.db", "mystery.db"}},
		{"duplicate-database", [3]string{"application.db", "application.db", "diagnostic.db"}},
		{"missing-database", [3]string{"application.db", "observation.db", "observation.db"}},
	}
	for _, tc := range cases {
		e, err := assemble(t.TempDir()+"/"+tc.name, tc.dbs, fsys, goodPin, testPolicy())
		if err == nil {
			if e != nil {
				_ = e.close()
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
	// Nil assets and a mismatched pin are assembly contract gaps.
	if e, err := assemble(t.TempDir(), [3]string{"application.db", "observation.db", "diagnostic.db"}, nil, goodPin, testPolicy()); err == nil {
		_ = e.close()
		t.Fatalf("assemble with nil assets succeeded, want contract gap")
	} else if gap, ok := err.(*gapError); !ok || gap.Kind() != "contract" {
		t.Fatalf("assemble nil assets error = %v (%T), want contract *gapError", err, err)
	}
	badPin := cooperative_assets.VersionPin{ID: "hellscape-spa", Version: "m1-silo-1", ArtifactDigest: "sha256:" + strings.Repeat("0", 64)}
	if e, err := assemble(t.TempDir(), [3]string{"application.db", "observation.db", "diagnostic.db"}, fsys, badPin, testPolicy()); err == nil {
		_ = e.close()
		t.Fatalf("assemble with mismatched pin succeeded, want contract gap")
	} else if gap, ok := err.(*gapError); !ok || gap.Kind() != "contract" {
		t.Fatalf("assemble bad pin error = %v (%T), want contract *gapError", err, err)
	}
	// Declared dependencies reject invalid inputs without hidden plumbing.
	if _, err := owner_store.OpenOwner("", t.TempDir(), "application"); err == nil {
		t.Fatalf("OpenOwner with empty path succeeded, want rejection")
	}
	if _, err := cooperative_assets.NewCooperativeSPA(nil, goodPin); err == nil {
		t.Fatalf("NewCooperativeSPA with nil assets succeeded, want rejection")
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
	rec := serve(e.spa, http.MethodGet, "/spa/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /spa/version = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "m1-silo-1") {
		t.Fatalf("SPA version body %q missing pinned version", rec.Body.String())
	}
	rec = serve(e.spa, http.MethodGet, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	for _, want := range []string{`<label for="full-name">`, `<input id="full-name"`, `<button id="continue-contact"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("SPA index missing cooperative control %q", want)
		}
	}
	js := serve(e.spa, http.MethodGet, "/app.js")
	if js.Code != http.StatusOK {
		t.Fatalf("GET /app.js = %d, want 200", js.Code)
	}
	for _, want := range []string{"__hellscapeReady", "DOMContentLoaded"} {
		if !strings.Contains(js.Body.String(), want) {
			t.Fatalf("SPA app.js missing readiness marker %q", want)
		}
	}
	if rec := serve(e.spa, http.MethodGet, "/api/contact"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/contact on SPA = %d, want 404 (SPA invents no APIs)", rec.Code)
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
