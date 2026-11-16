package authority

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// testPolicy returns a channel registration table with an operator (control),
// an application caller, an analyzer, and a reconciler.
func testPolicy() []byte {
	return []byte(`{"channels": {
		"operator-token": {"principal": "operator", "kind": "control", "grants": [
			{"domain": "control", "operations": ["*"]},
			{"domain": "execution", "operations": ["*"]},
			{"domain": "application", "operations": ["*"]},
			{"domain": "diagnostic", "operations": ["*"]},
			{"domain": "observation", "operations": ["*"]}
		]},
		"app-token": {"principal": "fixture-app", "kind": "application", "grants": [
			{"domain": "application", "operations": ["read", "write"]},
			{"domain": "observation", "operations": ["read"]}
		]},
		"analyzer-token": {"principal": "analyzer", "kind": "analyzer", "grants": [
			{"domain": "diagnostic", "operations": ["read", "write", "publish"]},
			{"domain": "execution", "operations": ["Observe", "read"]},
			{"domain": "observation", "operations": ["read", "Observe"]}
		]},
		"reconciler-token": {"principal": "reconciler", "kind": "reconciler", "grants": [
			{"domain": "diagnostic", "operations": ["read", "write"]},
			{"domain": "observation", "operations": ["read"]}
		]}
	}}`)
}

// overprivilegedPolicy attempts to grant the analyzer and reconciler
// execution/application write authority. Hard separation must still deny it.
func overprivilegedPolicy() []byte {
	return []byte(`{"channels": {
		"analyzer-token": {"principal": "analyzer", "kind": "analyzer", "grants": [
			{"domain": "diagnostic", "operations": ["*"]},
			{"domain": "execution", "operations": ["*"]},
			{"domain": "application", "operations": ["*"]},
			{"domain": "source", "operations": ["*"]},
			{"domain": "origin", "operations": ["*"]},
			{"domain": "control", "operations": ["*"]}
		]},
		"reconciler-token": {"principal": "reconciler", "kind": "reconciler", "grants": [
			{"domain": "execution", "operations": ["*"]},
			{"domain": "application", "operations": ["*"]}
		]},
		"operator-token": {"principal": "operator", "kind": "control", "grants": [
			{"domain": "execution", "operations": ["*"]},
			{"domain": "control", "operations": ["*"]}
		]}
	}}`)
}

func channelRequest(t *testing.T, token, target, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(http.MethodPost, target, nil)
	} else {
		r = httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Channel "+token)
	}
	return r
}

func authenticate(t *testing.T, r *http.Request, pol []byte) context.Context {
	t.Helper()
	ctx, err := Authenticate(r, pol)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if ctx == nil {
		t.Fatal("Authenticate() returned nil context")
	}
	return ctx
}

func TestApplicationCookiesCannotAuthorizeControlOperations(t *testing.T) {
	pol := testPolicy()

	// Application cookie alone authenticates nothing.
	r := channelRequest(t, "", "http://lab/internal/control", "")
	r.AddCookie(&http.Cookie{Name: "session", Value: "app-session-1"})
	r.AddCookie(&http.Cookie{Name: "attempt", Value: "attempt-9"})
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() with only application cookies succeeded, want failure")
	}

	// Cookie plus CORS headers still authenticate nothing: CORS is not auth.
	r = channelRequest(t, "", "http://lab/internal/control", "")
	r.AddCookie(&http.Cookie{Name: "session", Value: "app-session-1"})
	r.Header.Set("Origin", "http://fixture.lab")
	r.Header.Set("Access-Control-Request-Method", "POST")
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() with cookie+CORS succeeded, want failure")
	}

	// CORS preflight without a channel credential fails.
	r = httptest.NewRequest(http.MethodOptions, "http://lab/internal/control", nil)
	r.Header.Set("Origin", "http://fixture.lab")
	r.Header.Set("Access-Control-Request-Method", "POST")
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() preflight without channel credential succeeded, want failure")
	}

	// An authenticated application caller still cannot drive control verbs.
	r = channelRequest(t, "app-token", "http://lab/internal/control", "")
	r.AddCookie(&http.Cookie{Name: "session", Value: "app-session-1"})
	r.Header.Set("Origin", "http://fixture.lab")
	appCtx := authenticate(t, r, pol)
	for _, op := range []string{"RequestNativeCancel", "CloseObservationConnection", "ReleaseNativeContext", "Contain", "control"} {
		if err := Authorize(appCtx, "control", op, "op-1"); err == nil {
			t.Fatalf("Authorize(app, control, %s) succeeded, want denial", op)
		}
	}
	if err := Authorize(appCtx, "execution", "Contain", "handle-1"); err == nil {
		t.Fatal("Authorize(app, execution, Contain) succeeded, want denial")
	}

	// Positive controls: the application channel works on its own axis, and
	// the operator channel drives control.
	if err := Authorize(appCtx, "application", "write", "attempt-9"); err != nil {
		t.Fatalf("Authorize(app, application, write) error = %v", err)
	}
	opCtx := authenticate(t, channelRequest(t, "operator-token", "http://lab/internal/control", ""), pol)
	if err := Authorize(opCtx, "control", "Contain", "op-1"); err != nil {
		t.Fatalf("Authorize(operator, control, Contain) error = %v", err)
	}
	if err := Authorize(opCtx, "control", "RequestNativeCancel", "handle-1"); err != nil {
		t.Fatal("Authorize(operator, control, RequestNativeCancel) error = ", err)
	}
}

func TestCallerSuppliedPrincipalAndAuthorityLabelsGrantNoAccess(t *testing.T) {
	pol := testPolicy()

	// Spoofed identity headers without a channel credential fail.
	r := channelRequest(t, "", "http://lab/connector", "")
	r.Header.Set("X-Principal", "operator")
	r.Header.Set("X-Role", "admin")
	r.Header.Set("X-Provenance", "server")
	r.Header.Set("X-Verified", "true")
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() with spoofed principal headers succeeded, want failure")
	}

	// Spoofed labels are rejected even alongside a valid channel credential:
	// they are never trusted to upgrade the caller.
	for _, h := range []string{"X-Principal", "X-Role", "X-Provenance", "X-Verified", "X-Authority", "X-Owner-Domain", "X-Assertion-Kind"} {
		r := channelRequest(t, "app-token", "http://lab/connector", "")
		r.Header.Set(h, "operator")
		if _, err := Authenticate(r, pol); err == nil {
			t.Fatalf("Authenticate() with %s spoof header succeeded, want rejection", h)
		}
	}

	// Spoofed authority fields in the JSON body are rejected too.
	spoofBody := `{"principal": "operator", "role": "admin", "provenance": "server", "verified": true, "event_kind": "note"}`
	r = channelRequest(t, "app-token", "http://lab/connector", spoofBody)
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() with spoofed body authority fields succeeded, want rejection")
	}
	r = channelRequest(t, "", "http://lab/connector", spoofBody)
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() with spoof-only body succeeded, want failure")
	}

	// Spoofed authority labels in the query string are rejected.
	r = channelRequest(t, "app-token", "http://lab/connector?principal=operator&role=admin", "")
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() with spoofed query labels succeeded, want rejection")
	}

	// Positive control: the same caller without spoof labels authenticates,
	// keeps only its own grants, and a clean body passes through.
	cleanBody := `{"event_kind": "note", "producer_sequence": 7}`
	r = channelRequest(t, "app-token", "http://lab/connector", cleanBody)
	appCtx := authenticate(t, r, pol)
	if err := Authorize(appCtx, "control", "Contain", "op-1"); err == nil {
		t.Fatal("Authorize(app, control, Contain) succeeded, want denial")
	}
	if err := Authorize(appCtx, "application", "read", "attempt-1"); err != nil {
		t.Fatalf("Authorize(app, application, read) error = %v", err)
	}
}

func TestArtifactDigestsAndHandlesAreNotBearerCredentials(t *testing.T) {
	pol := testPolicy()

	// Digests, handles, and run IDs presented without a channel credential
	// authenticate nothing.
	target := "http://lab/artifacts?digest=" + testDigest + "&handle=local-1&native_run_id=native-7&session_id=s-1&attempt_id=a-1"
	if _, err := Authenticate(channelRequest(t, "", target, ""), pol); err == nil {
		t.Fatal("Authenticate() with digest/handle query succeeded, want failure")
	}
	r := channelRequest(t, "", "http://lab/artifacts", "")
	r.Header.Set("X-Artifact-Digest", testDigest)
	r.Header.Set("X-Handle", "local-1")
	if _, err := Authenticate(r, pol); err == nil {
		t.Fatal("Authenticate() with digest/handle headers succeeded, want failure")
	}

	// Knowledge of a digest grants no cross-domain access: the application
	// caller holds no execution grant, so citing the exact artifact digest
	// as the resource still fails.
	appCtx := authenticate(t, channelRequest(t, "app-token", "http://lab/artifacts", ""), pol)
	if err := Authorize(appCtx, "execution", "Observe", testDigest); err == nil {
		t.Fatal("Authorize(app, execution, Observe, digest) succeeded, want denial")
	}
	if err := Authorize(appCtx, "execution", "read", "local-1"); err == nil {
		t.Fatal("Authorize(app, execution, read, handle) succeeded, want denial")
	}

	// A principal with no grant for the domain fails for every resource ID,
	// digest or otherwise.
	if err := Authorize(appCtx, "control", "read", testDigest); err == nil {
		t.Fatal("Authorize(app, control, read, digest) succeeded, want denial")
	}

	// Positive control: authorization follows the grant, not the resource
	// ID. The same digest succeeds where granted and the outcome is
	// identical for any other resource value.
	if err := Authorize(appCtx, "application", "read", testDigest); err != nil {
		t.Fatalf("Authorize(app, application, read, digest) error = %v", err)
	}
	if err := Authorize(appCtx, "application", "read", "unrelated-id"); err != nil {
		t.Fatalf("Authorize(app, application, read, other) error = %v", err)
	}
	opCtx := authenticate(t, channelRequest(t, "operator-token", "http://lab/artifacts", ""), pol)
	if err := Authorize(opCtx, "execution", "Observe", testDigest); err != nil {
		t.Fatalf("Authorize(operator, execution, Observe, digest) error = %v", err)
	}
}

func TestAnalyzerSourceMutationRequestsFailAuthorization(t *testing.T) {
	pol := overprivilegedPolicy()

	// The analyzer channel itself authenticates; denial happens at
	// authorization, and the receipt is not a mutation grant.
	analyzerCtx := authenticate(t, channelRequest(t, "analyzer-token", "http://lab/connector", ""), pol)
	reconcilerCtx := authenticate(t, channelRequest(t, "reconciler-token", "http://lab/connector", ""), pol)

	// Analyzer mutations on foreign axes and source material fail even
	// though this policy attempts to grant them.
	for _, tc := range []struct{ domain, op string }{
		{"execution", "write"},
		{"execution", "Start"},
		{"execution", "Prepare"},
		{"application", "write"},
		{"application", "mutate"},
		{"source", "mutate"},
		{"source", "write"},
		{"origin", "write"},
		{"control", "Contain"},
		{"control", "RequestNativeCancel"},
	} {
		if err := Authorize(analyzerCtx, tc.domain, tc.op, "res-1"); err == nil {
			t.Fatalf("Authorize(analyzer, %s, %s) succeeded, want denial", tc.domain, tc.op)
		}
	}

	// The reconciler holds no execution/application write authority either.
	for _, tc := range []struct{ domain, op string }{
		{"execution", "write"},
		{"execution", "Start"},
		{"application", "write"},
		{"application", "update"},
	} {
		if err := Authorize(reconcilerCtx, tc.domain, tc.op, "res-1"); err == nil {
			t.Fatalf("Authorize(reconciler, %s, %s) succeeded, want denial", tc.domain, tc.op)
		}
	}

	// Positive controls: the analyzer still reads evidence and writes its
	// own diagnostic axis, and the operator mutation path works.
	if err := Authorize(analyzerCtx, "diagnostic", "write", "diag-1"); err != nil {
		t.Fatalf("Authorize(analyzer, diagnostic, write) error = %v", err)
	}
	if err := Authorize(analyzerCtx, "diagnostic", "publish", "diag-1"); err != nil {
		t.Fatalf("Authorize(analyzer, diagnostic, publish) error = %v", err)
	}
	opCtx := authenticate(t, channelRequest(t, "operator-token", "http://lab/connector", ""), pol)
	if err := Authorize(opCtx, "execution", "Start", "handle-1"); err != nil {
		t.Fatalf("Authorize(operator, execution, Start) error = %v", err)
	}
}
