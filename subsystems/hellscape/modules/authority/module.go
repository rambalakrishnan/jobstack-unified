// Package authority implements the tier-0 Hellscape authority boundary.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 2.4 (three
// logical surfaces), 7.1 (EventSubmission authority assignment), 8.11
// (SourceChecks), and the EXT-AUTHORITY invariant from
// contracts/02-external-connector.yaml:
//
//   - Caller identity and grants derive ONLY from authenticated channel
//     registration (the policy's channel table, presented via the
//     Authorization header). Request payload principal/role/provenance/
//     verified fields, headers, and query labels are never trusted; explicit
//     authority labels are rejected.
//   - Application cookies, fixture entry credentials, and CORS headers never
//     authorize control-plane operations. CORS is not authentication.
//   - IDs and digests (artifact digests, handles, native run IDs, session or
//     attempt IDs) are identity/correlation keys, never bearer credentials.
//   - The analyzer/reconciler (report writer) holds no execution-axis or
//     application-axis write authority and never mutates source claims or
//     origin facts, even if a policy entry attempts to grant it.
//
// The module performs no database writes, no cross-domain transactions, and
// places no credentials in any normalized payload.
package authority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ctxKey is the private context key carrying the authenticated principal.
type ctxKey struct{}

// grant is one (domain, operations) authorization grant from channel
// registration. Operation "*" matches any operation within the domain;
// domain "*" matches any domain for the listed operations.
type grant struct {
	Domain     string   `json:"domain"`
	Operations []string `json:"operations"`
}

// channelRegistration is one authenticated channel entry: the principal and
// kind bound to a channel credential, plus its grants.
type channelRegistration struct {
	Principal string  `json:"principal"`
	Kind      string  `json:"kind"`
	Grants    []grant `json:"grants"`
}

// policy is the authenticated channel registration table. Credentials are
// configured here, outside any request record (EXT reference carrier).
type policy struct {
	Channels map[string]channelRegistration `json:"channels"`
}

// principalRecord is the authenticated caller identity stored in the context.
type principalRecord struct {
	Principal string
	Kind      string
	Grants    []grant
}

// forbiddenHeaders are caller-supplied authority labels that are rejected
// outright (seam-mapping 7.1: caller-supplied authority fields are rejected).
// Canonical MIME header form; lookup uses Header.Get which canonicalizes.
var forbiddenHeaders = []string{
	"X-Principal",
	"X-Caller-Principal",
	"X-Role",
	"X-Provenance",
	"X-Verified",
	"X-Authentication",
	"X-Authority",
	"X-Owner-Domain",
	"X-Assertion-Kind",
	"X-Event-Id",
	"X-Sequence",
}

// forbiddenBodyKeys are top-level JSON body keys that assert authority. Their
// presence rejects the request; identity is never derived from them.
var forbiddenBodyKeys = map[string]bool{
	"principal":        true,
	"caller_principal": true,
	"role":             true,
	"provenance":       true,
	"verified":         true,
	"authentication":   true,
	"authority":        true,
	"owner_domain":     true,
	"assertion_kind":   true,
	"event_id":         true,
	"sequence":         true,
}

// forbiddenQueryKeys are URL query labels that assert authority. They are
// rejected like headers. Resource selectors such as digest, handle,
// native_run_id, session_id, or attempt_id are NOT in this set: they are
// silently ignored for authentication (never bearer authority) so that
// legitimate resource references do not break authenticated requests.
var forbiddenQueryKeys = map[string]bool{
	"principal":      true,
	"role":           true,
	"provenance":     true,
	"verified":       true,
	"authority":      true,
	"owner_domain":   true,
	"assertion_kind": true,
	"event_id":       true,
	"sequence":       true,
}

// controlOperations are connector/local control verbs plus the control domain
// marker. Application credentials never authorize these (seam-mapping 2.4,
// EXT-AUTHORITY).
var controlOperations = map[string]bool{
	"RequestNativeCancel":        true,
	"CloseObservationConnection": true,
	"ReleaseNativeContext":       true,
	"Contain":                    true,
	"control":                    true,
}

// readOperations are non-mutating verbs. Every other operation is treated as
// mutating (fail-closed) for analyzer/reconciler write separation.
var readOperations = map[string]bool{
	"read":             true,
	"Describe":         true,
	"describe":         true,
	"Observe":          true,
	"observe":          true,
	"CollectArtifacts": true,
	"collect":          true,
	"get":              true,
	"list":             true,
}

// analyzerProtectedDomains are domains an analyzer-family principal must
// never mutate: execution/application axes, origin facts, source claims, and
// the control surface. The analyzer's own diagnostic/report axis remains
// writable per grants (LIFE-AXES: one writer per axis).
var analyzerProtectedDomains = map[string]bool{
	"execution":   true,
	"application": true,
	"origin":      true,
	"source":      true,
	"control":     true,
	"connector":   true,
}

// Authenticate derives the caller identity solely from authenticated channel
// registration: the request MUST carry "Authorization: Channel <token>" where
// <token> is a key in the policy channel table. The policy is JSON of the
// form:
//
//	{"channels": {"<token>": {"principal": "...", "kind": "...",
//	  "grants": [{"domain": "...", "operations": ["...", "..."]}]}}}
//
// where kind is the caller class (e.g. "control", "application", "analyzer")
// and each grant lists authorized (domain, operations) pairs ("*" wildcards
// the respective dimension).
//
// It explicitly never consults Cookie headers, Origin/Referer/CORS headers,
// fixture entry credentials, query resource selectors (digest/handle/IDs), or
// any payload-declared principal/role/provenance/verified fields. Requests
// carrying explicit caller-supplied authority labels (forbidden headers,
// query keys, or top-level JSON body keys) are rejected with an error rather
// than trusted. Failures are generic and never reveal another principal's
// handles or tokens.
//
// On success it returns a context carrying the authenticated principal for
// Authorize.
func Authenticate(request *http.Request, policyJSON []byte) (context.Context, error) {
	if request == nil {
		return nil, errors.New("authority: nil request")
	}
	if len(policyJSON) == 0 {
		return nil, errors.New("authority: empty policy")
	}
	var pol policy
	dec := json.NewDecoder(bytes.NewReader(policyJSON))
	if err := dec.Decode(&pol); err != nil {
		return nil, fmt.Errorf("authority: invalid policy: %w", err)
	}
	if len(pol.Channels) == 0 {
		return nil, errors.New("authority: policy has no channels")
	}

	// Reject caller-supplied authority labels in headers.
	for _, h := range forbiddenHeaders {
		if v := request.Header.Get(h); v != "" {
			return nil, fmt.Errorf("authority: caller-supplied authority field rejected: %s", h)
		}
	}

	// Reject caller-supplied authority labels in query parameters.
	// Resource selectors (digest/handle/IDs) are ignored, not rejected.
	if request.URL != nil {
		q := request.URL.Query()
		for key := range forbiddenQueryKeys {
			if _, present := q[key]; present {
				return nil, fmt.Errorf("authority: caller-supplied authority field rejected: query %q", key)
			}
		}
	}

	// Reject caller-supplied authority fields in a JSON body, restoring the
	// body for downstream handlers. Non-JSON bodies carry no authority labels.
	if request.Body != nil {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, fmt.Errorf("authority: cannot read body: %w", err)
		}
		_ = request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		if len(bytes.TrimSpace(body)) > 0 {
			var obj map[string]any
			if err := json.Unmarshal(body, &obj); err == nil {
				for k := range obj {
					if forbiddenBodyKeys[strings.ToLower(k)] {
						return nil, fmt.Errorf("authority: caller-supplied authority field rejected: body %q", k)
					}
				}
			}
		}
	}

	// Authenticate the channel. Only the Authorization header is consulted;
	// Cookie, Origin, query digests/handles, and body claims grant nothing.
	auth := request.Header.Get("Authorization")
	parts := strings.Fields(auth)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Channel") || parts[1] == "" {
		return nil, errors.New("authority: unauthenticated channel")
	}
	reg, ok := pol.Channels[parts[1]]
	if !ok {
		return nil, errors.New("authority: unauthenticated channel")
	}
	if reg.Principal == "" || reg.Kind == "" {
		return nil, errors.New("authority: channel registration lacks principal")
	}

	rec := &principalRecord{
		Principal: reg.Principal,
		Kind:      reg.Kind,
		Grants:    reg.Grants,
	}
	ctx := request.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ctxKey{}, rec), nil
}

// Authorize checks that the authenticated principal in ctx holds a grant for
// (ownerDomain, operation). The resourceID (artifact digest, handle, run or
// attempt ID, or any other identifier) is accepted for correlation only and
// is NEVER sufficient for authorization: IDs and digests are not bearer
// authority, and hash-valid content from an unauthorized source remains
// unauthorized.
//
// Hard separations apply regardless of configured grants and fail closed:
//
//   - Principals of kind "application" are denied every control operation
//     (control domain and the RequestNativeCancel,
//     CloseObservationConnection, ReleaseNativeContext, Contain verbs).
//     Application cookies and entry credentials never authorize control.
//   - Analyzer-family principals (principal or kind "analyzer"/"reconciler",
//     kind "report") are denied every mutating operation on the execution,
//     application, origin, source, control, and connector domains. They may
//     only mutate their own diagnostic/report axis per grants; reads remain
//     grant-governed.
func Authorize(ctx context.Context, ownerDomain string, operation string, resourceID string) error {
	_ = resourceID // correlation only; never bearer authority.
	if ctx == nil {
		return errors.New("authority: no authenticated principal")
	}
	rec, ok := ctx.Value(ctxKey{}).(*principalRecord)
	if !ok || rec == nil || rec.Principal == "" {
		return errors.New("authority: no authenticated principal")
	}
	if ownerDomain == "" {
		return errors.New("authority: empty owner domain")
	}
	if operation == "" {
		return errors.New("authority: empty operation")
	}

	// Application plane can never drive the control surface, even when a
	// policy entry mistakenly grants it.
	if rec.Kind == "application" && isControl(ownerDomain, operation) {
		return errors.New("authority: application credentials do not grant control access")
	}

	// Analyzer/reconciler/report principals never mutate foreign axes or
	// source material, even when a policy entry mistakenly grants it.
	if isAnalyzerFamily(rec) && analyzerProtectedDomains[ownerDomain] && !readOperations[operation] {
		return fmt.Errorf("authority: %s holds no %s write authority", rec.Principal, ownerDomain)
	}

	for _, g := range rec.Grants {
		if (g.Domain == ownerDomain || g.Domain == "*") && operationAllowed(g.Operations, operation) {
			return nil
		}
	}
	return fmt.Errorf("authority: %s not authorized for %s %s", rec.Principal, operation, ownerDomain)
}

// isControl reports whether (domain, operation) addresses the control
// surface: the control domain or any connector control verb.
func isControl(domain, operation string) bool {
	if domain == "control" {
		return true
	}
	return controlOperations[operation]
}

// isAnalyzerFamily reports whether the principal belongs to the
// judgment/report family (analyzer, reconciler, report writer), which
// evaluates evidence without modifying runs, source claims, or origin facts.
func isAnalyzerFamily(rec *principalRecord) bool {
	switch rec.Principal {
	case "analyzer", "reconciler":
		return true
	}
	switch rec.Kind {
	case "analyzer", "reconciler", "report", "diagnostic":
		return true
	}
	return false
}

// operationAllowed reports whether the grant's operation list covers op.
// "*" covers any operation.
func operationAllowed(allowed []string, op string) bool {
	for _, a := range allowed {
		if a == "*" || a == op {
			return true
		}
	}
	return false
}
