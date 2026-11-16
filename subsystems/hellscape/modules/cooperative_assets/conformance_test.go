package cooperative_assets

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	evidence_codec "evidence_codec"
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

// cooperativeFixture returns the minimal M1 cooperative SPA bundle.
func cooperativeFixture() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {Data: []byte(cooperativeIndexHTML)},
		"app.js":     {Data: []byte(cooperativeAppJS)},
		"styles.css": {Data: []byte(cooperativeCSS)},
	}
}

// cloneFixture deep-copies a fixture so hostile variants stay isolated.
func cloneFixture(src fstest.MapFS) fstest.MapFS {
	out := make(fstest.MapFS, len(src))
	for k, v := range src {
		data := append([]byte(nil), v.Data...)
		out[k] = &fstest.MapFile{Data: data, Mode: v.Mode}
	}
	return out
}

// pinForFS computes the correct pin for an asset filesystem using the
// module's own snapshot and digest path.
func pinForFS(t *testing.T, fsys fs.FS) VersionPin {
	t.Helper()
	snapshot, err := snapshotAssets(fsys)
	if err != nil {
		t.Fatalf("snapshotAssets: %v", err)
	}
	return VersionPin{
		ID:             "hellscape-spa",
		Version:        "m1-cooperative-1",
		ArtifactDigest: string(computeBuildDigest(snapshot)),
	}
}

// mustHandler builds a handler or fails the test.
func mustHandler(t *testing.T, fsys fs.FS, pin VersionPin) http.Handler {
	t.Helper()
	h, err := NewCooperativeSPA(fsys, pin)
	if err != nil {
		t.Fatalf("NewCooperativeSPA: %v", err)
	}
	return h
}

// serve issues one request against the handler.
func serve(h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// readModuleSource returns module.go with block and line comments stripped,
// so prohibition documentation does not count as merged runtime code.
func readModuleSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("module.go")
	if err != nil {
		t.Fatalf("read module.go: %v", err)
	}
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
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// EmbeddedSPAAssetsMustMatchThePinnedBuild
// ---------------------------------------------------------------------------

func TestEmbeddedSPAAssetsMustMatchThePinnedBuild(t *testing.T) {
	t.Run("correct pin serves byte-identical assets", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		for name, file := range fsys {
			target := "/" + name
			if name == "index.html" {
				// Exercise both the explicit and the root mapping.
				for _, candidate := range []string{"/", "/index.html"} {
					rec := serve(h, http.MethodGet, candidate, nil)
					if rec.Code != http.StatusOK {
						t.Fatalf("GET %s = %d, want 200", candidate, rec.Code)
					}
					if rec.Body.String() != string(file.Data) {
						t.Fatalf("GET %s altered %d bytes in transit", candidate, len(file.Data))
					}
				}
				continue
			}
			rec := serve(h, http.MethodGet, target, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", target, rec.Code)
			}
			if rec.Body.String() != string(file.Data) {
				t.Fatalf("GET %s altered bytes in transit", target)
			}
		}
	})

	t.Run("etags match evidence_codec content identities", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		for name, file := range fsys {
			rec := serve(h, http.MethodGet, "/"+name, nil)
			want := `"` + string(evidence_codec.HashBytes(file.Data)) + `"`
			if rec.Header().Get("ETag") != want {
				t.Fatalf("GET /%s ETag = %q, want %q", name, rec.Header().Get("ETag"), want)
			}
			if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
				t.Fatalf("GET /%s Cache-Control = %q, want immutable", name, cc)
			}
		}
	})

	t.Run("build digest is the canonical manifest hash", func(t *testing.T) {
		fsys := cooperativeFixture()
		// Independently recompute the manifest with evidence_codec only.
		snapshot, err := snapshotAssets(fsys)
		if err != nil {
			t.Fatalf("snapshotAssets: %v", err)
		}
		names := sortedNames(snapshot)
		var manifest strings.Builder
		for _, name := range names {
			manifest.WriteString(name)
			manifest.WriteString("\n")
			manifest.WriteString(string(evidence_codec.HashBytes(snapshot[name])))
			manifest.WriteString("\n")
		}
		want := string(evidence_codec.HashBytes([]byte(manifest.String())))
		pin := VersionPin{ID: "hellscape-spa", Version: "m1-cooperative-1", ArtifactDigest: want}
		h := mustHandler(t, fsys, pin)
		rec := serve(h, http.MethodGet, "/spa/version", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /spa/version = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("version body %q missing build digest %q", rec.Body.String(), want)
		}
		if !strings.Contains(rec.Body.String(), "m1-cooperative-1") {
			t.Fatalf("version body %q missing pinned version", rec.Body.String())
		}
		// The Digest alias spelling pins the same build.
		alias := VersionPin{Version: "m1-cooperative-1", Digest: want}
		if _, err := NewCooperativeSPA(fsys, alias); err != nil {
			t.Fatalf("Digest alias pin rejected: %v", err)
		}
	})

	t.Run("wrong digest is rejected without silent replacement", func(t *testing.T) {
		fsys := cooperativeFixture()
		bad := VersionPin{ID: "hellscape-spa", Version: "m1-cooperative-1", ArtifactDigest: string(evidence_codec.HashBytes([]byte("other build")))}
		if _, err := NewCooperativeSPA(fsys, bad); err == nil {
			t.Fatalf("mismatched pin accepted, want rejection")
		} else if !strings.Contains(strings.ToLower(err.Error()), "match") && !strings.Contains(strings.ToLower(err.Error()), "digest") {
			t.Fatalf("mismatch error %q does not name the digest gap", err)
		}
	})

	t.Run("tampered bytes do not match the committed pin", func(t *testing.T) {
		fsys := cooperativeFixture()
		pin := pinForFS(t, fsys)
		tampered := cloneFixture(fsys)
		tampered["app.js"] = &fstest.MapFile{Data: append(append([]byte(nil), cooperativeAppJS...), []byte("\n// tampered")...)}
		if _, err := NewCooperativeSPA(tampered, pin); err == nil {
			t.Fatalf("tampered assets accepted under committed pin, want rejection")
		}
	})

	t.Run("snapshot is immutable after construction", func(t *testing.T) {
		fsys := cooperativeFixture()
		// Pin against a stable copy so later mutation cannot move the pin.
		stable := cloneFixture(fsys)
		pin := pinForFS(t, stable)
		h := mustHandler(t, fsys, pin)
		before := serve(h, http.MethodGet, "/app.js", nil).Body.String()
		// Mutate the source filesystem after construction.
		fsys["app.js"] = &fstest.MapFile{Data: []byte("mutated after pin")}
		fsys["evil.js"] = &fstest.MapFile{Data: []byte("injected after pin")}
		after := serve(h, http.MethodGet, "/app.js", nil).Body.String()
		if after != before || after != cooperativeAppJS {
			t.Fatalf("handler reflects post-construction mutation")
		}
		if rec := serve(h, http.MethodGet, "/evil.js", nil); rec.Code != http.StatusNotFound {
			t.Fatalf("GET /evil.js = %d, want 404 (no silent replacement)", rec.Code)
		}
	})

	t.Run("malformed construction inputs are rejected", func(t *testing.T) {
		fsys := cooperativeFixture()
		good := pinForFS(t, fsys)
		if _, err := NewCooperativeSPA(nil, good); err == nil {
			t.Fatalf("nil assets accepted, want rejection")
		}
		if _, err := NewCooperativeSPA(fsys, VersionPin{}); err == nil {
			t.Fatalf("empty pin accepted, want rejection")
		}
		if _, err := NewCooperativeSPA(fsys, VersionPin{Version: "v", ArtifactDigest: "not-a-digest"}); err == nil {
			t.Fatalf("non-sha256 pin accepted, want rejection")
		}
		empty := fstest.MapFS{}
		if _, err := NewCooperativeSPA(empty, good); err == nil {
			t.Fatalf("empty filesystem accepted, want rejection")
		}
		noIndex := fstest.MapFS{"app.js": {Data: []byte(cooperativeAppJS)}}
		badPin := VersionPin{Version: "v", ArtifactDigest: string(evidence_codec.HashBytes([]byte("x")))}
		if _, err := NewCooperativeSPA(noIndex, badPin); err == nil {
			t.Fatalf("bundle without index.html accepted, want rejection")
		}
	})

	t.Run("handler invents no application surface", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		for _, target := range []string{"/api/jobs", "/api/draft", "/api/confirmation", "/api", "/no-such-asset.js"} {
			if rec := serve(h, http.MethodGet, target, nil); rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s = %d, want 404 (no invented receipt)", target, rec.Code)
			}
		}
		if rec := serve(h, http.MethodPost, "/app.js", nil); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST /app.js = %d, want 405", rec.Code)
		}
		rec := serve(h, http.MethodHead, "/index.html", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("HEAD /index.html = %d, want 200", rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("HEAD returned %d body bytes, want none", rec.Body.Len())
		}
	})

	t.Run("serving types and access classification", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		cases := map[string]string{
			"/index.html": "text/html",
			"/app.js":     "javascript",
			"/styles.css": "text/css",
		}
		for target, wantType := range cases {
			rec := serve(h, http.MethodGet, target, nil)
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, wantType) {
				t.Fatalf("GET %s Content-Type = %q, want %q", target, ct, wantType)
			}
			if got := rec.Header().Get("X-Access-Class"); got != "public" {
				t.Fatalf("GET %s X-Access-Class = %q, want public", target, got)
			}
			if got := rec.Header().Get("X-Build-Version"); got != "m1-cooperative-1" {
				t.Fatalf("GET %s X-Build-Version = %q", target, got)
			}
		}
	})

	t.Run("module fetches no executable code at runtime", func(t *testing.T) {
		code := readModuleSource(t)
		// The handler serves the snapshot; outbound fetch or plugin loading
		// would silently replace the pinned bundle.
		for _, token := range []string{"http.Get(", "http.Post(", "http.Head(", ".Do(", "os/exec", "plugin.Open", "net.Dial", "ioutil.ReadAll(http"} {
			// ".Do(" is too generic alone; only flag client-shaped calls.
			if token == ".Do(" {
				continue
			}
			if strings.Contains(code, token) {
				t.Fatalf("module.go merges runtime fetch %q", token)
			}
		}
		lower := strings.ToLower(code)
		for _, token := range []string{"playwright", "chromium", "selenium", "puppeteer", "webdriver", "crawler", "orchestrator", "firebase", "dashboard"} {
			if strings.Contains(lower, token) {
				t.Fatalf("module.go merges external runtime %q", token)
			}
		}
		// Serving works with no network peer: every asset is in memory.
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		for name, file := range fsys {
			rec := serve(h, http.MethodGet, "/"+name, nil)
			body, err := io.ReadAll(rec.Body)
			if err != nil {
				t.Fatalf("read /%s: %v", name, err)
			}
			if string(body) != string(file.Data) {
				t.Fatalf("GET /%s not served from immutable snapshot", name)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// CooperativeControlsRemainVisibleStableAndLightDOM
// ---------------------------------------------------------------------------

func TestCooperativeControlsRemainVisibleStableAndLightDOM(t *testing.T) {
	t.Run("cooperative bundle renders native light-DOM controls", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		rec := serve(h, http.MethodGet, "/", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / = %d, want 200", rec.Code)
		}
		body := rec.Body.String()
		lower := strings.ToLower(body)
		for _, want := range []string{"<label", "<input", "<button"} {
			if !strings.Contains(lower, want) {
				t.Fatalf("served index.html missing %q", want)
			}
		}
		for _, forbidden := range []string{"<iframe", "<frame", "shadowroot", "attachshadow"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("served index.html contains %q (M1 is light DOM)", forbidden)
			}
		}
		js := serve(h, http.MethodGet, "/app.js", nil).Body.String()
		jsLower := strings.ToLower(js)
		for _, forbidden := range []string{"attachshadow", "shadowroot", "<iframe", "setinterval", "math.random"} {
			if strings.Contains(jsLower, forbidden) {
				t.Fatalf("served app.js contains %q", forbidden)
			}
		}
	})

	t.Run("hostile structural and timing variants are rejected", func(t *testing.T) {
		cases := []struct {
			name    string
			file    string
			snippet string
			wantErr string
		}{
			{"shadow attach", "app.js", "\nconst root = el.attachShadow({mode:'open'});\n", "shadow"},
			{"shadow root read", "app.js", "\nconst r = el.shadowRoot;\n", "shadow"},
			{"declarative shadow", "index.html", "\n<template shadowrootmode=\"open\"></template>\n", "shadow"},
			{"iframe challenge", "index.html", "\n<iframe src=\"/frame.html\"></iframe>\n", "frame"},
			{"frame challenge", "index.html", "\n<frameset><frame src=\"a\"></frameset>\n", "frame"},
			{"hidden required display none", "index.html", "\n<input id=\"h1\" name=\"h1\" required style=\"display:none\">\n", "required"},
			{"hidden required hidden attr", "index.html", "\n<input id=\"h2\" name=\"h2\" required hidden>\n", "required"},
			{"hidden required type hidden", "index.html", "\n<input id=\"h3\" name=\"h3\" type=\"hidden\" required>\n", "required"},
			{"hidden required visibility", "index.html", "\n<input id=\"h4\" name=\"h4\" required style=\"visibility:hidden\">\n", "required"},
			{"perpetual polling", "app.js", "\nsetInterval(() => fetch('/api/draft'), 1000);\n", "polling"},
			{"randomized identity", "app.js", "\nconst cls = 'field-' + Math.random().toString(36);\n", "stable"},
			{"artificial delay token", "app.js", "\nconst artificialDelay = 5000;\n", "delay"},
			{"long timeout", "app.js", "\nsetTimeout(() => ready(), 5000);\n", "delay"},
			{"hydration skeleton", "app.js", "\n// hydration skeleton placeholder\n", "hydration"},
			{"skeleton treatment", "index.html", "\n<div class=\"skeleton\"></div>\n", "hydration"},
			{"decoy control", "index.html", "\n<input id=\"decoy1\" name=\"decoy\" type=\"text\">\n", "decoy"},
			{"honeypot", "index.html", "\n<input id=\"hp\" name=\"honeypot-trap\" type=\"text\">\n", "decoy"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				fsys := cloneFixture(cooperativeFixture())
				base := string(fsys[tc.file].Data)
				fsys[tc.file] = &fstest.MapFile{Data: []byte(base + tc.snippet)}
				pin := pinForFS(t, fsys)
				_, err := NewCooperativeSPA(fsys, pin)
				if err == nil {
					t.Fatalf("hostile variant %q accepted, want rejection", tc.name)
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
					t.Fatalf("variant %q error %q missing %q", tc.name, err, tc.wantErr)
				}
			})
		}
	})

	t.Run("every hostile mechanism id is rejected", func(t *testing.T) {
		for _, id := range hostileMechanismIDs {
			fsys := cloneFixture(cooperativeFixture())
			base := string(fsys["app.js"].Data)
			fsys["app.js"] = &fstest.MapFile{Data: []byte(base + "\n// pack " + id + "\n")}
			pin := pinForFS(t, fsys)
			if _, err := NewCooperativeSPA(fsys, pin); err == nil {
				t.Fatalf("mechanism %q accepted, want rejection (M1 admits zero)", id)
			}
		}
	})

	t.Run("native controls labels and stable identities are required", func(t *testing.T) {
		t.Run("missing labels", func(t *testing.T) {
			fsys := cloneFixture(cooperativeFixture())
			stripped := strings.ReplaceAll(cooperativeIndexHTML, "<label", "<span")
			stripped = strings.ReplaceAll(stripped, "</label>", "</span>")
			fsys["index.html"] = &fstest.MapFile{Data: []byte(stripped)}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("unlabeled controls accepted, want rejection")
			}
		})
		t.Run("empty labels", func(t *testing.T) {
			fsys := cloneFixture(cooperativeFixture())
			emptied := cooperativeIndexHTML
			emptied = strings.ReplaceAll(emptied, ">Full name<", "><")
			emptied = strings.ReplaceAll(emptied, ">Email address<", "><")
			fsys["index.html"] = &fstest.MapFile{Data: []byte(emptied)}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("empty labels accepted, want rejection")
			}
		})
		t.Run("missing inputs", func(t *testing.T) {
			fsys := cloneFixture(cooperativeFixture())
			lines := strings.Split(cooperativeIndexHTML, "\n")
			var kept []string
			for _, ln := range lines {
				if strings.Contains(strings.ToLower(ln), "<input") {
					continue
				}
				kept = append(kept, ln)
			}
			fsys["index.html"] = &fstest.MapFile{Data: []byte(strings.Join(kept, "\n"))}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("bundle without native inputs accepted, want rejection")
			}
		})
		t.Run("missing buttons", func(t *testing.T) {
			fsys := cloneFixture(cooperativeFixture())
			lines := strings.Split(cooperativeIndexHTML, "\n")
			var kept []string
			for _, ln := range lines {
				if strings.Contains(strings.ToLower(ln), "<button") || strings.Contains(strings.ToLower(ln), "</button>") {
					continue
				}
				kept = append(kept, ln)
			}
			// Keep the submit control reachable only if a button remains;
			// the stripped bundle must fail the native-button gate.
			fsys["index.html"] = &fstest.MapFile{Data: []byte(strings.Join(kept, "\n"))}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("bundle without native buttons accepted, want rejection")
			}
		})
		t.Run("unstable identities", func(t *testing.T) {
			fsys := cloneFixture(cooperativeFixture())
			unstable := strings.ReplaceAll(cooperativeIndexHTML, `id="full-name" name="fullName"`, `class="field"`)
			fsys["index.html"] = &fstest.MapFile{Data: []byte(unstable)}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("control without stable id/name accepted, want rejection")
			}
		})
	})

	t.Run("served controls stay visible and stable", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		first := serve(h, http.MethodGet, "/", nil).Body.String()
		second := serve(h, http.MethodGet, "/", nil).Body.String()
		if first != second {
			t.Fatalf("served markup is not stable across requests")
		}
		if strings.Contains(strings.ToLower(first), "display:none") {
			t.Fatalf("served markup hides controls via display:none")
		}
	})
}

// ---------------------------------------------------------------------------
// ControlReadinessDoesNotRequireNetworkSilence
// ---------------------------------------------------------------------------

func TestControlReadinessDoesNotRequireNetworkSilence(t *testing.T) {
	t.Run("readiness is rendered-and-enabled controls", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		js := serve(h, http.MethodGet, "/app.js", nil).Body.String()
		for _, want := range []string{"DOMContentLoaded", "__hellscapeReady", "data-readiness", "hellscape:ready"} {
			if !strings.Contains(js, want) {
				t.Fatalf("served app.js missing readiness token %q", want)
			}
		}
		lower := strings.ToLower(js)
		for _, forbidden := range []string{"networkidle", "network-idle", "network_idle", "waitforloadstate", "waitfornetworkidle", "requestidlecallback"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("served app.js gates readiness on %q", forbidden)
			}
		}
	})

	t.Run("network-silence gates are rejected", func(t *testing.T) {
		gates := []string{
			"await page.waitForLoadState('networkidle');",
			"await waitForNetworkIdle();",
			"if (networkIdle) { ready(); }",
			"// wait for network-idle before ready",
			"// network_idle gate",
			"requestIdleCallback(ready);",
		}
		for _, gate := range gates {
			fsys := cloneFixture(cooperativeFixture())
			base := string(fsys["app.js"].Data)
			fsys["app.js"] = &fstest.MapFile{Data: []byte(base + "\n" + gate + "\n")}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("network-silence gate %q accepted, want rejection", gate)
			} else if !strings.Contains(strings.ToLower(err.Error()), "network") && !strings.Contains(strings.ToLower(err.Error()), "readiness") {
				t.Fatalf("gate %q error %q does not name readiness", gate, err)
			}
		}
	})

	t.Run("readiness marker and render wiring are required", func(t *testing.T) {
		t.Run("no marker", func(t *testing.T) {
			fsys := cloneFixture(cooperativeFixture())
			stripped := cooperativeAppJS
			stripped = strings.ReplaceAll(stripped, "window.__hellscapeReady = true;", "")
			stripped = strings.ReplaceAll(stripped, "document.body.setAttribute('data-readiness', 'ready');", "")
			stripped = strings.ReplaceAll(stripped, "hellscape:ready", "generic-event")
			stripped = strings.ReplaceAll(stripped, "data-readiness", "data-state")
			stripped = strings.ReplaceAll(stripped, "__hellscapeReady", "__genericReady")
			stripped = strings.ReplaceAll(stripped, "hellscape-ready", "generic-ready")
			fsys["app.js"] = &fstest.MapFile{Data: []byte(stripped)}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("bundle without readiness marker accepted, want rejection")
			}
		})
		t.Run("no render wiring", func(t *testing.T) {
			fsys := cloneFixture(cooperativeFixture())
			stripped := strings.ReplaceAll(cooperativeAppJS, "DOMContentLoaded", "windowLoad")
			fsys["app.js"] = &fstest.MapFile{Data: []byte(stripped)}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("readiness without render wiring accepted, want rejection")
			}
		})
	})

	t.Run("assets serve immediately without polling or silence", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		// First request succeeds with no warmup, polling, or silence wait.
		rec := serve(h, http.MethodGet, "/", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("first GET / = %d, want 200", rec.Code)
		}
		if retry := rec.Header().Get("Retry-After"); retry != "" {
			t.Fatalf("GET / asks for retry (%q); readiness needs no wait", retry)
		}
		version := serve(h, http.MethodGet, "/spa/version", nil)
		if version.Code != http.StatusOK {
			t.Fatalf("GET /spa/version = %d, want 200", version.Code)
		}
		// No polling or idle-trap treatment in any served asset.
		for name := range fsys {
			body := strings.ToLower(serve(h, http.MethodGet, "/"+name, nil).Body.String())
			for _, forbidden := range []string{"setinterval", "networkidle", "network_idle", "idle-trap", "idle_trap"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("served %s contains %q", name, forbidden)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// PublicAssetsExposeNoControlSecretsOrOracleAliases
// ---------------------------------------------------------------------------

func TestPublicAssetsExposeNoControlSecretsOrOracleAliases(t *testing.T) {
	t.Run("cooperative bundle exposes no secrets", func(t *testing.T) {
		fsys := cooperativeFixture()
		h := mustHandler(t, fsys, pinForFS(t, fsys))
		for name := range fsys {
			body := strings.ToLower(serve(h, http.MethodGet, "/"+name, nil).Body.String())
			for _, forbidden := range []string{
				"control_credential", "control-secret", "feature_schedule",
				"private_alias", "target_alias", "frame_alias", "diagnostic_alias",
				"oracle", "expected_failure", "failure_signature",
				"api_key", "apikey", "bearer ", "authorization:",
			} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("served %s exposes %q", name, forbidden)
				}
			}
		}
		version := serve(h, http.MethodGet, "/spa/version", nil).Body.String()
		lower := strings.ToLower(version)
		for _, forbidden := range []string{"credential", "feature_schedule", "oracle", "api_key", "bearer"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("version endpoint exposes %q", forbidden)
			}
		}
	})

	t.Run("secret-bearing variants are rejected", func(t *testing.T) {
		secrets := []string{
			"control_credential=abc123",
			"control-secret: xyz",
			"feature_schedule: [network_idle_trap]",
			"private_alias: field-9",
			"target_alias: contact-email",
			"frame_alias: section-2",
			"diagnostic_alias: r1-render",
			"debug_alias: email-input",
			"selector_alias: #email",
			"oracle_alias: expected-contact",
			"the oracle says pass",
			"expected_failure: timeout",
			"expectedFailure: validation_race",
			"failure_signature: slow_endpoints",
			"private class map: {.a: #email}",
			"hidden field identity: ssn",
			"api_key=deadbeef",
			"Authorization: Bearer token123",
			"control-plane credential",
		}
		for _, secret := range secrets {
			t.Run(secret, func(t *testing.T) {
				for _, file := range []string{"app.js", "index.html"} {
					fsys := cloneFixture(cooperativeFixture())
					base := string(fsys[file].Data)
					fsys[file] = &fstest.MapFile{Data: []byte(base + "\n// " + secret + "\n")}
					if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
						t.Fatalf("%s with %q accepted, want rejection", file, secret)
					}
				}
			})
		}
	})

	t.Run("control-plane fetches are rejected", func(t *testing.T) {
		surfaces := []string{"/control", "/diagnostic", "/manifest", "/evidence", "/replay", "/export", "/journal", "/commission", "/seal", "/analysis"}
		for _, surface := range surfaces {
			fsys := cloneFixture(cooperativeFixture())
			base := string(fsys["app.js"].Data)
			fsys["app.js"] = &fstest.MapFile{Data: []byte(base + "\nfetch('" + surface + "/session');\n")}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("fetch to %s accepted, want rejection", surface)
			}
		}
		// Ordinary application fetches stay allowed.
		fsys := cooperativeFixture()
		if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err != nil {
			t.Fatalf("application fetch to /api/contact rejected: %v", err)
		}
	})

	t.Run("remote executable fetches are rejected", func(t *testing.T) {
		payloads := []struct {
			file    string
			snippet string
		}{
			{"index.html", "<script src=\"https://cdn.example.com/app.js\"></script>"},
			{"index.html", "<script src='http://cdn.example.com/app.js'></script>"},
			{"app.js", "import(\"https://cdn.example.com/extra.js\");"},
			{"app.js", "eval(responseText);"},
			{"app.js", "const f = new Function('return 1');"},
			{"app.js", "document.write('<script>hi</script>');"},
		}
		for _, p := range payloads {
			fsys := cloneFixture(cooperativeFixture())
			base := string(fsys[p.file].Data)
			fsys[p.file] = &fstest.MapFile{Data: []byte(base + "\n" + p.snippet + "\n")}
			if _, err := NewCooperativeSPA(fsys, pinForFS(t, fsys)); err == nil {
				t.Fatalf("%s payload %q accepted, want rejection", p.file, p.snippet)
			}
		}
	})

	t.Run("digests grant no bearer authority", func(t *testing.T) {
		fsys := cooperativeFixture()
		pin := pinForFS(t, fsys)
		h := mustHandler(t, fsys, pin)
		// Presenting the build digest unlocks nothing extra.
		withDigest := map[string]string{"If-None-Match": `"` + pin.ArtifactDigest + `"`}
		for _, target := range []string{"/no-such-path", "/api/draft", "/api/confirmation", "/control/sessions"} {
			if rec := serve(h, http.MethodGet, target, withDigest); rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s with digest = %d, want 404 (digest is not authority)", target, rec.Code)
			}
		}
		if rec := serve(h, http.MethodPost, "/api/submit", withDigest); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
			t.Fatalf("POST /api/submit with digest = %d, want 404/405", rec.Code)
		}
		// Application cookies never authorize control surfaces through this handler.
		withCookie := map[string]string{"Cookie": "attempt=abc; session=def"}
		for _, target := range []string{"/api/draft", "/control/sessions"} {
			if rec := serve(h, http.MethodGet, target, withCookie); rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s with cookie = %d, want 404", target, rec.Code)
			}
		}
	})
}
