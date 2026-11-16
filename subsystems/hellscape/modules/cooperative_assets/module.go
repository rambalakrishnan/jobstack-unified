// Package cooperative_assets serves the M1 cooperative SPA bundle as
// immutable embedded data pinned to a build digest.
//
// The SPA bundle is built separately and consumed here as an fs.FS snapshot.
// Construction verifies the snapshot against the pinned build digest,
// validates the M1 cooperative profile (visible native controls, stable
// light-DOM identities, rendered-and-enabled readiness, no hostile
// features), and rejects any asset that exposes control secrets or oracle
// aliases. Serving is byte-identical from the in-memory snapshot: the
// handler never fetches executable code at runtime and never silently
// replaces pinned assets.
package cooperative_assets

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"

	evidence_codec "evidence_codec"
)

// VersionPin pins the immutable SPA build identity.
//
// ID and Version name the build; the digest carries the content address of
// the complete asset snapshot. ArtifactDigest is the canonical contract
// spelling (contracts/00-evidence-kernel.yaml VersionPin.artifact_digest);
// Digest is accepted as an alias so engine-style pins keep compiling.
// Exactly one of the two digest spellings must be set and must equal the
// computed build digest.
type VersionPin struct {
	ID             string `json:"id,omitempty"`
	Version        string `json:"version,omitempty"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
	Digest         string `json:"digest,omitempty"`
}

// pinnedDigest returns the effective pinned digest.
func (p VersionPin) pinnedDigest() string {
	if p.ArtifactDigest != "" {
		return p.ArtifactDigest
	}
	return p.Digest
}

// fileEntry is one snapshotted asset: exact bytes plus serving metadata.
type fileEntry struct {
	data        []byte
	contentType string
	digest      string
}

// spaHandler serves a verified immutable SPA snapshot.
type spaHandler struct {
	pin         VersionPin
	buildDigest string
	files       map[string]fileEntry
}

// NewCooperativeSPA verifies assets against the pinned build and returns an
// http.Handler serving the snapshot byte-identically.
//
// Verification steps:
//  1. The pin must carry a version and a digest.
//  2. Assets are snapshotted into memory; index.html is required.
//  3. Every file is hashed with evidence_codec.HashBytes; the sorted
//     manifest (path + "\n" + file digest + "\n" per file) is hashed again
//     to form the build digest, which must equal the pinned digest.
//  4. Assets must satisfy the M1 cooperative profile and expose no control
//     secrets or oracle aliases.
//
// The returned handler serves only the snapshot. Unknown paths (including
// any /api/* application or control path) return 404; the handler invents
// no receipts and infers no application commitment from rendering. Only
// GET and HEAD are served.
func NewCooperativeSPA(assets fs.FS, build VersionPin) (http.Handler, error) {
	if assets == nil {
		return nil, fmt.Errorf("cooperative_assets: asset filesystem is required")
	}
	if strings.TrimSpace(build.Version) == "" {
		return nil, fmt.Errorf("cooperative_assets: version pin is required")
	}
	pinned := strings.TrimSpace(build.pinnedDigest())
	if pinned == "" {
		return nil, fmt.Errorf("cooperative_assets: build digest pin is required")
	}
	if !strings.HasPrefix(pinned, "sha256:") {
		return nil, fmt.Errorf("cooperative_assets: build digest pin must be a sha256 digest")
	}

	snapshot, err := snapshotAssets(assets)
	if err != nil {
		return nil, err
	}
	if err := validateCooperativeAssets(snapshot); err != nil {
		return nil, err
	}
	buildDigest := string(computeBuildDigest(snapshot))
	if buildDigest != pinned {
		return nil, fmt.Errorf("cooperative_assets: pinned build %q does not match asset digest %q", pinned, buildDigest)
	}

	files := make(map[string]fileEntry, len(snapshot))
	for name, data := range snapshot {
		copied := append([]byte(nil), data...)
		files[name] = fileEntry{
			data:        copied,
			contentType: contentTypeFor(name),
			digest:      string(evidence_codec.HashBytes(data)),
		}
	}
	return &spaHandler{pin: build, buildDigest: buildDigest, files: files}, nil
}

// snapshotAssets reads every regular file in assets into memory keyed by
// slash-cleaned relative path. index.html is required.
func snapshotAssets(assets fs.FS) (map[string][]byte, error) {
	out := make(map[string][]byte)
	err := fs.WalkDir(assets, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := path.Clean(p)
		if name == "." || name == "" {
			return nil
		}
		f, err := assets.Open(p)
		if err != nil {
			return fmt.Errorf("cooperative_assets: open %s: %w", p, err)
		}
		data, err := io.ReadAll(f)
		closeErr := f.Close()
		if err != nil {
			return fmt.Errorf("cooperative_assets: read %s: %w", p, err)
		}
		if closeErr != nil {
			return fmt.Errorf("cooperative_assets: close %s: %w", p, err)
		}
		out[name] = data
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cooperative_assets: walk assets: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("cooperative_assets: asset filesystem is empty")
	}
	if _, ok := out["index.html"]; !ok {
		return nil, fmt.Errorf("cooperative_assets: index.html is required")
	}
	return out, nil
}

// computeBuildDigest hashes the sorted asset manifest. Manifest bytes are,
// per file in ascending path order, the path, a newline, the per-file
// evidence_codec.HashBytes digest, and a newline. The manifest itself is
// hashed with evidence_codec.HashBytes to form the build digest.
func computeBuildDigest(snapshot map[string][]byte) evidence_codec.Digest {
	names := make([]string, 0, len(snapshot))
	for name := range snapshot {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		manifest.WriteString(name)
		manifest.WriteString("\n")
		manifest.WriteString(string(evidence_codec.HashBytes(snapshot[name])))
		manifest.WriteString("\n")
	}
	return evidence_codec.HashBytes([]byte(manifest.String()))
}

// contentTypeFor maps an asset path to its serving media type.
func contentTypeFor(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".ico":
		return "image/x-icon"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".map":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

// ServeHTTP serves the immutable snapshot byte-identically.
func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	trimmed := strings.TrimPrefix(path.Clean("/"+strings.TrimPrefix(r.URL.Path, "/")), "/")
	if trimmed == "." || trimmed == "" {
		trimmed = "index.html"
	}
	if trimmed == "spa/version" {
		h.serveVersion(w, r)
		return
	}
	// The SPA handler serves static assets only. It invents no application
	// or control APIs and infers no commitment from rendering.
	if strings.HasPrefix(trimmed, "api/") || trimmed == "api" {
		http.NotFound(w, r)
		return
	}
	entry, ok := h.files[trimmed]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", entry.contentType)
	w.Header().Set("ETag", `"`+entry.digest+`"`)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Build-Version", h.pin.Version)
	w.Header().Set("X-Build-Digest", h.buildDigest)
	w.Header().Set("X-Access-Class", "public")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(entry.data)
	}
}

// serveVersion reports the pinned build identity. The digest is a content
// address, never a bearer credential, and grants no additional access.
func (h *spaHandler) serveVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	body, _ := json.Marshal(map[string]string{
		"id":              h.pin.ID,
		"version":         h.pin.Version,
		"artifact_digest": h.buildDigest,
		"digest":          h.buildDigest,
	})
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// ---------------------------------------------------------------------------
// Cooperative validation
// ---------------------------------------------------------------------------

// validateCooperativeAssets enforces the M1 cooperative profile, the
// rendered-and-enabled readiness contract, and the public-asset secrecy
// boundary over the complete snapshot.
func validateCooperativeAssets(snapshot map[string][]byte) error {
	if err := validateNoHostileMechanisms(snapshot); err != nil {
		return err
	}
	if err := validateVisibleStableLightDOM(snapshot); err != nil {
		return err
	}
	if err := validateReadinessContract(snapshot); err != nil {
		return err
	}
	if err := validateNoControlSecrets(snapshot); err != nil {
		return err
	}
	if err := validateNoRemoteExecutable(snapshot); err != nil {
		return err
	}
	return nil
}

// hostileMechanismIDs are the exact later-pack mechanism identifiers from
// seam-mapping 12.3. M1 admits zero hostile features, so no public asset
// may reference any of them.
var hostileMechanismIDs = []string{
	"shadow_dom", "nested_shadow_dom", "closed_shadow_root",
	"same_origin_iframe", "cross_origin_iframe",
	"dynamic_classes", "node_replacement", "async_routes", "hydration_skeleton",
	"content_visibility", "virtualized_lists", "asset_revision_skew",
	"inconsistent_labels", "icon_buttons", "rtl_section", "semantic_decoys",
	"moving_fields", "inert_sections", "conditional_fields", "repeater_reindex",
	"dnd_upload", "upload_hidden_fallback", "custom_controls", "input_masks",
	"interaction_overlays", "before_unload_guard",
	"async_validation", "validation_races", "session_token_gate", "reload_recovery",
	"session_expiry", "idp_verification",
	"network_idle_trap", "network_faults", "slow_endpoints", "redirect_on_submit",
	"websocket_state", "submit_ambiguity",
	"connection_faults", "websocket_faults",
	"extraction_ambiguity", "instruction_decoys",
	"honeypots", "dom_fingerprint", "behavioral_detection",
	"fingerprint_consistency", "fingerprint_policy_simulation",
	"challenge_orchestration", "simulated_challenge", "real_challenge_widgets",
}

// validateNoHostileMechanisms rejects any reference to later hostile packs,
// structural challenges, polling, or artificial timing treatments.
func validateNoHostileMechanisms(snapshot map[string][]byte) error {
	for _, name := range sortedNames(snapshot) {
		body := string(snapshot[name])
		lower := strings.ToLower(body)
		for _, id := range hostileMechanismIDs {
			if strings.Contains(lower, id) {
				return fmt.Errorf("cooperative_assets: %s references hostile mechanism %q (M1 admits zero)", name, id)
			}
		}
		// Structural challenges: shadow roots and frames.
		for _, token := range []string{"attachshadow", "shadowroot", "createshadowroot", "getshadowroot", "closed-shadow", "shadow-root"} {
			if strings.Contains(lower, token) {
				return fmt.Errorf("cooperative_assets: %s uses shadow-DOM challenge token %q (M1 controls are light DOM)", name, token)
			}
		}
		if strings.Contains(lower, "<iframe") || strings.Contains(lower, "<frame") {
			return fmt.Errorf("cooperative_assets: %s uses a frame challenge (M1 has no frame/root challenge)", name)
		}
		// Class churn / unstable render identity.
		if strings.Contains(lower, "math.random") {
			return fmt.Errorf("cooperative_assets: %s uses Math.random for render identity (M1 identities are stable)", name)
		}
		// Perpetual polling and idle traps.
		if strings.Contains(lower, "setinterval") {
			return fmt.Errorf("cooperative_assets: %s uses setInterval polling (M1 has no perpetual polling)", name)
		}
		for _, token := range []string{"perpetual", "idle-trap", "idle_trap", "network-idle-trap"} {
			if strings.Contains(lower, token) {
				return fmt.Errorf("cooperative_assets: %s references polling/idle treatment %q", name, token)
			}
		}
		// Artificial delays and injected faults.
		for _, token := range []string{"artificialdelay", "artificial-delay", "artificial_delay", "injecteddelay", "injected-delay", "injected-fault", "slow_endpoints", "network_faults", "connection_faults", "websocket_faults", "decoy", "honeypot"} {
			if strings.Contains(lower, token) {
				return fmt.Errorf("cooperative_assets: %s references hostile timing/decoy treatment %q", name, token)
			}
		}
		if delay, ok := longTimeoutDelay(body); ok {
			return fmt.Errorf("cooperative_assets: %s schedules artificial delay %dms (M1 has no artificial delay)", name, delay)
		}
		// Delayed hydration skeletons.
		for _, token := range []string{"hydration", "skeleton", "content-visibility"} {
			if strings.Contains(lower, token) {
				return fmt.Errorf("cooperative_assets: %s references delayed-hydration treatment %q", name, token)
			}
		}
	}
	return nil
}

// longTimeoutDelay reports a setTimeout delay >= 5000ms, the fast-campaign
// artificial-delay bound. Normal sub-second UI timing stays well below it.
func longTimeoutDelay(body string) (int, bool) {
	lower := strings.ToLower(body)
	search := lower
	for {
		idx := strings.Index(search, "settimeout")
		if idx < 0 {
			return 0, false
		}
		rest := search[idx+len("settimeout"):]
		comma := strings.Index(rest, ",")
		if comma < 0 {
			return 0, false
		}
		after := rest[comma+1:]
		// Skip whitespace, closing parens of the callback, and quotes.
		i := 0
		for i < len(after) && (after[i] == ' ' || after[i] == '\t' || after[i] == '\n' || after[i] == '\r' || after[i] == ')' || after[i] == '"' || after[i] == '\'') {
			i++
		}
		j := i
		for j < len(after) && after[j] >= '0' && after[j] <= '9' {
			j++
		}
		if j > i {
			n := 0
			for _, c := range after[i:j] {
				n = n*10 + int(c-'0')
				if n >= 5000 {
					return n, true
				}
			}
		}
		search = rest[comma+1:]
		if len(search) == 0 {
			return 0, false
		}
	}
}

// validateVisibleStableLightDOM requires native controls with visible
// labels and stable identities, and rejects hidden required controls.
func validateVisibleStableLightDOM(snapshot map[string][]byte) error {
	index, ok := snapshot["index.html"]
	if !ok {
		return fmt.Errorf("cooperative_assets: index.html is required")
	}
	html := string(index)
	lower := strings.ToLower(html)
	// Native controls.
	hasInput := strings.Contains(lower, "<input") || strings.Contains(lower, "<select") || strings.Contains(lower, "<textarea")
	hasButton := strings.Contains(lower, "<button")
	if !hasInput {
		return fmt.Errorf("cooperative_assets: index.html has no native input control")
	}
	if !hasButton {
		return fmt.Errorf("cooperative_assets: index.html has no native button control")
	}
	// Visible ordinary labels.
	if !strings.Contains(lower, "<label") {
		return fmt.Errorf("cooperative_assets: index.html has no visible label")
	}
	if emptyLabelsOnly(html) {
		return fmt.Errorf("cooperative_assets: index.html labels are empty (controls must be visibly labeled)")
	}
	// Stable semantic identities: every input/select/textarea carries id or name.
	if err := requireStableIdentities(html); err != nil {
		return err
	}
	// Hidden required controls.
	for _, name := range sortedNames(snapshot) {
		if !strings.HasSuffix(strings.ToLower(name), ".html") {
			continue
		}
		if tag := hiddenRequiredTag(string(snapshot[name])); tag != "" {
			return fmt.Errorf("cooperative_assets: %s hides a required control (%s)", name, tag)
		}
	}
	return nil
}

// emptyLabelsOnly reports whether every <label> element is empty.
func emptyLabelsOnly(html string) bool {
	lower := strings.ToLower(html)
	count := 0
	search := lower
	orig := html
	offset := 0
	for {
		idx := strings.Index(search, "<label")
		if idx < 0 {
			return count > 0
		}
		count++
		// Find the end of the opening tag, then the label text.
		rest := search[idx:]
		end := strings.Index(rest, ">")
		if end < 0 {
			return false
		}
		after := orig[offset+idx+end+1:]
		closeIdx := strings.Index(strings.ToLower(after), "</label>")
		var text string
		if closeIdx < 0 {
			text = after
		} else {
			text = after[:closeIdx]
		}
		// Strip nested tags to find visible text.
		var visible strings.Builder
		inTag := false
		for _, c := range text {
			switch {
			case c == '<':
				inTag = true
			case c == '>':
				inTag = false
			default:
				if !inTag {
					visible.WriteRune(c)
				}
			}
		}
		if strings.TrimSpace(visible.String()) != "" {
			return false
		}
		advance := idx + end + 1
		offset += advance
		search = search[advance:]
	}
}

// requireStableIdentities rejects input-like controls without id or name.
func requireStableIdentities(html string) error {
	lower := strings.ToLower(html)
	for _, tag := range []string{"<input", "<select", "<textarea"} {
		search := lower
		for {
			idx := strings.Index(search, tag)
			if idx < 0 {
				break
			}
			rest := search[idx:]
			end := strings.Index(rest, ">")
			if end < 0 {
				break
			}
			fragment := rest[:end]
			if !strings.Contains(fragment, "id=") && !strings.Contains(fragment, "name=") {
				return fmt.Errorf("cooperative_assets: index.html control %q lacks a stable id/name identity", tag)
			}
			search = rest[end:]
		}
	}
	return nil
}

// hiddenRequiredTag returns a short description of the first tag that marks
// a control required while hiding it, or "" when there is none.
func hiddenRequiredTag(html string) string {
	lower := strings.ToLower(html)
	search := lower
	origSearch := html
	for {
		idx := strings.Index(search, "<input")
		sel := strings.Index(search, "<select")
		area := strings.Index(search, "<textarea")
		next := -1
		kind := ""
		for _, cand := range []struct {
			at   int
			kind string
		}{{idx, "input"}, {sel, "select"}, {area, "textarea"}} {
			if cand.at >= 0 && (next < 0 || cand.at < next) {
				next = cand.at
				kind = cand.kind
			}
		}
		if next < 0 {
			return ""
		}
		rest := search[next:]
		end := strings.Index(rest, ">")
		if end < 0 {
			return ""
		}
		fragment := rest[:end]
		origFragment := origSearch[next : next+end]
		if strings.Contains(fragment, "required") {
			switch {
			case strings.Contains(fragment, "type=\"hidden\"") || strings.Contains(fragment, "type='hidden'"):
				return kind + " type=hidden required"
			case strings.Contains(fragment, " hidden") || strings.Contains(fragment, "\thidden") || strings.Contains(fragment, "\"hidden"):
				return kind + " hidden required"
			case strings.Contains(fragment, "display:none") || strings.Contains(fragment, "display: none"):
				return kind + " display:none required"
			case strings.Contains(fragment, "visibility:hidden") || strings.Contains(fragment, "visibility: hidden"):
				return kind + " visibility:hidden required"
			}
			_ = origFragment
		}
		search = rest[end:]
		origSearch = origSearch[next+end:]
	}
}

// validateReadinessContract requires the rendered-and-enabled readiness
// signal and rejects any network-silence readiness gate.
func validateReadinessContract(snapshot map[string][]byte) error {
	var combined strings.Builder
	for _, name := range sortedNames(snapshot) {
		combined.Write(snapshot[name])
		combined.WriteByte('\n')
	}
	body := combined.String()
	lower := strings.ToLower(body)
	// Network silence must never gate readiness.
	for _, token := range []string{"networkidle", "network-idle", "network_idle", "waitforloadstate", "waitfornetworkidle", "networkidle0", "networkidle2", "requestidlecallback"} {
		if strings.Contains(lower, token) {
			return fmt.Errorf("cooperative_assets: readiness gated on network silence via %q (readiness is rendered-and-enabled controls)", token)
		}
	}
	// The SPA records readiness after the relevant controls render and enable.
	hasMarker := strings.Contains(body, "__hellscapeReady") ||
		strings.Contains(body, "data-readiness") ||
		strings.Contains(body, "hellscape:ready") ||
		strings.Contains(body, "hellscape-ready")
	if !hasMarker {
		return fmt.Errorf("cooperative_assets: no rendered-and-enabled readiness marker (__hellscapeReady/data-readiness/hellscape:ready)")
	}
	if !strings.Contains(body, "DOMContentLoaded") {
		return fmt.Errorf("cooperative_assets: readiness marker is not tied to rendered controls (missing DOMContentLoaded wiring)")
	}
	return nil
}

// validateNoControlSecrets rejects control credentials, feature schedules,
// private aliases, oracle aliases, and expected-failure oracles in public
// assets, plus any fetch to control-plane surfaces.
func validateNoControlSecrets(snapshot map[string][]byte) error {
	for _, name := range sortedNames(snapshot) {
		body := string(snapshot[name])
		lower := strings.ToLower(body)
		for _, token := range []string{
			"control_credential", "control-credential", "controlcredential",
			"control_secret", "control-secret",
			"control-plane", "control_plane", "controlplane", "control plane",
			"feature_schedule", "feature-schedule", "featureschedule",
			"private_alias", "private-alias", "privatealias",
			"target_alias", "target-alias",
			"frame_alias", "frame-alias",
			"diagnostic_alias", "diagnostic-alias",
			"debug_alias", "debug-alias", "selector_alias", "selector-alias",
			"oracle_alias", "oracle-alias",
			"expected_failure", "expected-failure", "expectedfailure",
			"failure_signature", "failure-signature",
			"private class map", "privateclassmap", "private_class_map",
			"hidden field", "hiddenfield",
			"api_key", "api-key", "apikey",
			"bearer ", "authorization:",
		} {
			if strings.Contains(lower, token) {
				return fmt.Errorf("cooperative_assets: %s exposes forbidden control/oracle token %q", name, token)
			}
		}
		// Oracle aliases in any spelling are internal-only.
		if strings.Contains(lower, "oracle") {
			return fmt.Errorf("cooperative_assets: %s exposes oracle reference (diagnostic aliases are internal)", name)
		}
		// Application assets must not reach control-plane surfaces.
		if strings.Contains(lower, "fetch(") || strings.Contains(lower, "xmlhttprequest") {
			for _, surface := range []string{"/control", "/diagnostic", "/manifest", "/evidence", "/replay", "/export", "/journal", "/commission", "/seal", "/analysis"} {
				if strings.Contains(lower, surface) {
					return fmt.Errorf("cooperative_assets: %s fetches control-plane surface %q (application credentials grant no control access)", name, surface)
				}
			}
		}
	}
	return nil
}

// validateNoRemoteExecutable rejects runtime fetching of executable
// frontend code: remote script sources, dynamic code compilation, and
// document writes that could silently replace the pinned bundle.
func validateNoRemoteExecutable(snapshot map[string][]byte) error {
	for _, name := range sortedNames(snapshot) {
		body := string(snapshot[name])
		lower := strings.ToLower(body)
		for _, token := range []string{
			"src=\"http://", "src='http://", "src=\"https://", "src='https://",
			"href=\"http://", "href='http://",
			"from \"http://", "from 'http://", "from \"https://", "from 'https://",
			"import(\"http://", "import('http://", "import(\"https://", "import('https://",
		} {
			if strings.Contains(lower, token) {
				return fmt.Errorf("cooperative_assets: %s fetches remote executable via %q", name, token)
			}
		}
		for _, token := range []string{"eval(", "new function(", "document.write("} {
			if strings.Contains(lower, token) {
				return fmt.Errorf("cooperative_assets: %s uses dynamic code loading %q (pinned assets are immutable)", name, token)
			}
		}
	}
	return nil
}

// sortedNames returns snapshot paths in ascending order for deterministic
// validation and digest order.
func sortedNames(snapshot map[string][]byte) []string {
	names := make([]string, 0, len(snapshot))
	for name := range snapshot {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
