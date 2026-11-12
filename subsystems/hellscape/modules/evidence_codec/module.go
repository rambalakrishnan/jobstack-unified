// Package evidence_codec implements the tier-0 Hellscape evidence codec.
//
// It covers the structural and semantic gates of
// seam-mappings/hellscape-seam-mapping.md sections 3.1 (Missingness),
// 3.2 (Digests and canonicalization), and 16.1 (Structural and semantic
// gates): duplicate mapping-key rejection, non-JSON/non-finite rejection,
// record version and closed-object enforcement, bare-null and required-field
// enforcement, order- and content-preserving canonical JSON, content-addressed
// artifact digests, event hashing, and format assertions for declared dates
// and URIs.
package evidence_codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Digest is a shared content digest of the form "sha256:" followed by 64
// lowercase hexadecimal digits (seam-mapping 3.2).
type Digest string

// DigestPrefix is the required prefix of every shared digest.
const DigestPrefix = "sha256:"

// JournalEnvelope is the complete stored journal event envelope
// (seam-mapping 7.2). The event hash covers the canonical envelope with
// only event_hash removed (seam-mapping 3.2).
type JournalEnvelope struct {
	RecordType        string         `json:"record_type"`
	SchemaVersion     string         `json:"schema_version"`
	RunID             string         `json:"run_id"`
	JournalID         string         `json:"journal_id"`
	ManifestHash      string         `json:"manifest_hash"`
	Sequence          int64          `json:"journal_sequence"`
	EventID           string         `json:"event_id"`
	EventKind         string         `json:"event_kind"`
	EventSchemaVer    string         `json:"event_schema_version"`
	Role              string         `json:"role"`
	AssertionKind     string         `json:"assertion_kind"`
	OwnerDomain       string         `json:"owner_domain"`
	ProducerID        string         `json:"producer_id"`
	ProducerSequence  int64          `json:"producer_sequence"`
	Provenance        string         `json:"provenance"`
	EvidenceScope     string         `json:"evidence_scope"`
	RecordedAt        string         `json:"recorded_at"`
	OccurredAt        string         `json:"occurred_at"`
	CausalRefs        []string       `json:"causal_refs"`
	Payload           map[string]any `json:"payload"`
	PreviousEventHash string         `json:"previous_event_hash"`
	EventHash         Digest         `json:"event_hash"`
}

// validDigest reports whether s matches the shared digest form.
func validDigest(s string) bool {
	if !strings.HasPrefix(s, DigestPrefix) {
		return false
	}
	hexPart := s[len(DigestPrefix):]
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

// HashBytes returns the content-addressed identity of exact stored bytes
// (seam-mapping 3.2: artifact digest basis).
func HashBytes(content []byte) Digest {
	sum := sha256.Sum256(content)
	return Digest(DigestPrefix + hex.EncodeToString(sum[:]))
}

// HashEvent returns the event digest: the sha256 of the canonical envelope
// with only event_hash removed (seam-mapping 3.2).
func HashEvent(event JournalEnvelope) (Digest, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("evidence_codec: cannot marshal envelope: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("evidence_codec: cannot decode envelope: %w", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return "", fmt.Errorf("evidence_codec: envelope must be a JSON object")
	}
	delete(m, "event_hash")
	if m["causal_refs"] == nil {
		m["causal_refs"] = []any{}
	}
	if m["payload"] == nil {
		m["payload"] = map[string]any{}
	}
	var buf bytes.Buffer
	if err := appendCanonical(&buf, m); err != nil {
		return "", err
	}
	return HashBytes(buf.Bytes()), nil
}

// CanonicalJSON returns the canonical JSON form of document: object keys
// sorted, no insignificant whitespace, array order and string contents
// preserved exactly. Missing-value envelopes are preserved verbatim; no
// redaction, Unicode normalization, alias substitution, or reordering is
// applied (seam-mapping 3.2).
func CanonicalJSON(document []byte, mediaType string) ([]byte, error) {
	mt := strings.ToLower(strings.TrimSpace(mediaType))
	isJSON := mt == "" || strings.Contains(mt, "json")
	isYAML := strings.Contains(mt, "yaml") || strings.Contains(mt, "yml")
	switch {
	case isJSON:
		// JSON input: canonicalize directly.
	case isYAML:
		// This binding accepts JSON-compatible documents under a YAML media
		// type; anything else is rejected below by the JSON parse.
	default:
		return nil, fmt.Errorf("evidence_codec: unsupported media type %q", mediaType)
	}
	if len(bytes.TrimSpace(document)) == 0 {
		return nil, fmt.Errorf("evidence_codec: empty document")
	}
	if err := checkDuplicateKeys(document); err != nil {
		return nil, err
	}
	v, err := decodeSingleValue(document)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := appendCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeSingleValue(document []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(document))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("evidence_codec: invalid JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("evidence_codec: trailing data after JSON document")
	}
	return v, nil
}

func appendCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		appendJSONString(buf, t)
	case json.Number:
		s, err := canonicalNumber(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return fmt.Errorf("evidence_codec: non-finite number rejected")
		}
		return fmt.Errorf("evidence_codec: unexpected float64 value")
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			appendJSONString(buf, k)
			buf.WriteByte(':')
			if err := appendCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("evidence_codec: non-JSON value of type %T rejected", v)
	}
	return nil
}

func appendJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString("\\\"")
		case '\\':
			buf.WriteString("\\\\")
		case '\n':
			buf.WriteString("\\n")
		case '\r':
			buf.WriteString("\\r")
		case '\t':
			buf.WriteString("\\t")
		case '\b':
			buf.WriteString("\\b")
		case '\f':
			buf.WriteString("\\f")
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, "\\u%04x", r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func isIntegerLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i = 1
		if len(s) == 1 {
			return false
		}
	}
	if s[i] == '0' {
		return i+1 == len(s)
	}
	if s[i] < '1' || s[i] > '9' {
		return false
	}
	for i++; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func canonicalNumber(n json.Number) (string, error) {
	s := n.String()
	if isIntegerLiteral(s) {
		if s == "-0" {
			return "0", nil
		}
		return s, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", fmt.Errorf("evidence_codec: invalid number %q", s)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("evidence_codec: non-finite number %q rejected", s)
	}
	return strconv.FormatFloat(f, 'g', -1, 64), nil
}

// ---------------------------------------------------------------------------
// Duplicate mapping-key detection. Runs before any other validation so that
// duplicate YAML/JSON mapping keys are rejected before validation
// (seam-mapping 16.1). The scanner also rejects non-JSON values and
// non-finite number literals, since those cannot appear in valid JSON.
// ---------------------------------------------------------------------------

type dupParser struct {
	b   []byte
	pos int
}

func checkDuplicateKeys(data []byte) error {
	p := &dupParser{b: data}
	p.skipWS()
	if p.pos >= len(p.b) {
		return fmt.Errorf("evidence_codec: empty document")
	}
	if err := p.parseValue("$"); err != nil {
		return err
	}
	p.skipWS()
	if p.pos != len(p.b) {
		return fmt.Errorf("evidence_codec: trailing data after JSON document")
	}
	return nil
}

func (p *dupParser) skipWS() {
	for p.pos < len(p.b) {
		switch p.b[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *dupParser) parseValue(path string) error {
	p.skipWS()
	if p.pos >= len(p.b) {
		return fmt.Errorf("evidence_codec: unexpected end of document at %s", path)
	}
	switch c := p.b[p.pos]; c {
	case '{':
		return p.parseObject(path)
	case '[':
		return p.parseArray(path)
	case '"':
		_, err := p.parseString(path)
		return err
	case 't':
		return p.parseLiteral("true", path)
	case 'f':
		return p.parseLiteral("false", path)
	case 'n':
		return p.parseLiteral("null", path)
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return p.parseNumber(path)
	default:
		return fmt.Errorf("evidence_codec: non-JSON value at %s: unexpected byte %q", path, c)
	}
}

func (p *dupParser) parseLiteral(lit, path string) error {
	if strings.HasPrefix(string(p.b[p.pos:]), lit) {
		p.pos += len(lit)
		return nil
	}
	return fmt.Errorf("evidence_codec: non-JSON value at %s", path)
}

func (p *dupParser) parseNumber(path string) error {
	if p.b[p.pos] == '-' {
		p.pos++
		if p.pos >= len(p.b) {
			return fmt.Errorf("evidence_codec: malformed number at %s", path)
		}
	}
	c := p.b[p.pos]
	if c == '0' {
		p.pos++
	} else if c >= '1' && c <= '9' {
		for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
			p.pos++
		}
	} else {
		return fmt.Errorf("evidence_codec: malformed number at %s", path)
	}
	if p.pos < len(p.b) && p.b[p.pos] == '.' {
		p.pos++
		start := p.pos
		for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == start {
			return fmt.Errorf("evidence_codec: malformed number at %s", path)
		}
	}
	if p.pos < len(p.b) && (p.b[p.pos] == 'e' || p.b[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.b) && (p.b[p.pos] == '+' || p.b[p.pos] == '-') {
			p.pos++
		}
		start := p.pos
		for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == start {
			return fmt.Errorf("evidence_codec: malformed number at %s", path)
		}
	}
	return nil
}

func (p *dupParser) parseObject(path string) error {
	p.pos++ // consume '{'
	p.skipWS()
	if p.pos < len(p.b) && p.b[p.pos] == '}' {
		p.pos++
		return nil
	}
	seen := make(map[string]struct{})
	for {
		p.skipWS()
		if p.pos >= len(p.b) || p.b[p.pos] != '"' {
			return fmt.Errorf("evidence_codec: expected object key at %s", path)
		}
		key, err := p.parseString(path)
		if err != nil {
			return err
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("evidence_codec: duplicate mapping key %q at %s rejected before validation", key, path)
		}
		seen[key] = struct{}{}
		p.skipWS()
		if p.pos >= len(p.b) || p.b[p.pos] != ':' {
			return fmt.Errorf("evidence_codec: expected ':' after key %q at %s", key, path)
		}
		p.pos++
		if err := p.parseValue(path+"."+key); err != nil {
			return err
		}
		p.skipWS()
		if p.pos >= len(p.b) {
			return fmt.Errorf("evidence_codec: unterminated object at %s", path)
		}
		switch p.b[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return nil
		default:
			return fmt.Errorf("evidence_codec: expected ',' or '}' at %s", path)
		}
	}
}

func (p *dupParser) parseArray(path string) error {
	p.pos++ // consume '['
	p.skipWS()
	if p.pos < len(p.b) && p.b[p.pos] == ']' {
		p.pos++
		return nil
	}
	for i := 0; ; i++ {
		if err := p.parseValue(fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
		p.skipWS()
		if p.pos >= len(p.b) {
			return fmt.Errorf("evidence_codec: unterminated array at %s", path)
		}
		switch p.b[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return nil
		default:
			return fmt.Errorf("evidence_codec: expected ',' or ']' at %s", path)
		}
	}
}

func (p *dupParser) parseString(path string) (string, error) {
	p.pos++ // consume opening quote
	var sb strings.Builder
	for {
		if p.pos >= len(p.b) {
			return "", fmt.Errorf("evidence_codec: unterminated string at %s", path)
		}
		c := p.b[p.pos]
		switch {
		case c == '"':
			p.pos++
			return sb.String(), nil
		case c == '\\':
			p.pos++
			if p.pos >= len(p.b) {
				return "", fmt.Errorf("evidence_codec: unterminated escape at %s", path)
			}
			e := p.b[p.pos]
			p.pos++
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, err := p.parseHex4(path)
				if err != nil {
					return "", err
				}
				// Combine surrogate pairs so escaped and literal keys compare equal.
				if r >= 0xD800 && r <= 0xDBFF && p.pos+5 < len(p.b) && p.b[p.pos] == '\\' && p.b[p.pos+1] == 'u' {
					save := p.pos
					p.pos += 2
					lo, err := p.parseHex4(path)
					if err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
						r = 0x10000 + (r-0xD800)<<10 + (lo - 0xDC00)
					} else {
						p.pos = save
					}
				}
				sb.WriteRune(r)
			default:
				return "", fmt.Errorf("evidence_codec: invalid string escape at %s", path)
			}
		case c < 0x20:
			return "", fmt.Errorf("evidence_codec: unescaped control character in string at %s", path)
		default:
			sb.WriteByte(c)
			p.pos++
		}
	}
}

func (p *dupParser) parseHex4(path string) (rune, error) {
	if p.pos+4 > len(p.b) {
		return 0, fmt.Errorf("evidence_codec: truncated unicode escape at %s", path)
	}
	var r rune
	for i := range 4 {
		c := p.b[p.pos+i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, fmt.Errorf("evidence_codec: invalid unicode escape at %s", path)
		}
		r = r*16 + rune(v)
	}
	p.pos += 4
	return r, nil
}

// ---------------------------------------------------------------------------
// Record validation (seam-mapping 16.1 structural and semantic gates).
// ---------------------------------------------------------------------------

var knownSchemaVersions = map[string]bool{
	"0.1.0": true,
	"1.0":   true,
	"1.0.0": true,
}

var knownRecordTypes = map[string]bool{
	"manifest":              true,
	"journal_event":         true,
	"diagnostic":            true,
	"replay_receipt":        true,
	"lease_record":          true,
	"capability_descriptor": true,
}

type recordShape struct {
	required []string
	optional []string
}

func recordShapes() map[string]recordShape {
	return map[string]recordShape{
		"manifest": {
			required: []string{"record_type", "schema_version", "manifest_id", "run_id", "journal_id", "owner_domain"},
			optional: []string{"commissioner_id", "activity", "attempt", "execution", "task", "task_semantic_hash", "effective_configuration", "environment", "seed", "build_pins", "event_registry", "producers", "clocks"},
		},
		"journal_event": {
			required: []string{"record_type", "schema_version", "run_id", "journal_id", "manifest_hash", "journal_sequence", "event_id", "event_kind", "event_schema_version", "role", "assertion_kind", "owner_domain", "producer_id", "producer_sequence", "provenance", "evidence_scope", "occurred_at", "payload", "previous_event_hash", "event_hash"},
			optional: []string{"recorded_at", "causal_refs"},
		},
		"diagnostic": {
			required: []string{"record_type", "schema_version", "diagnostic_id", "analysis_revision", "run_id", "input_prefix"},
			optional: []string{"manifest_hash", "analysis_request_ref", "attempt", "execution", "findings", "measurements", "claims", "artifacts", "limitations", "validity", "steps", "observation", "application"},
		},
		"replay_receipt": {
			required: []string{"record_type", "schema_version", "replay_id", "mode", "run_id"},
			optional: []string{"manifest_hash", "source_prefix", "result", "limitations"},
		},
		"lease_record": {
			required: []string{"record_type", "schema_version", "resource", "policy", "issuer_id"},
			optional: []string{"expires_at"},
		},
		"capability_descriptor": {
			required: []string{"record_type", "schema_version", "descriptor_id", "descriptor_revision", "declared_by"},
			optional: []string{"evidence_prefix", "supersedes", "capabilities"},
		},
	}
}

// nullReasons are the six EK NullReason values (seam-mapping 3.1).
// manual_fixture_validation is a rationale, not a seventh reason.
var nullReasons = map[string]bool{
	"not_enabled":          true,
	"not_applicable":       true,
	"not_observed":         true,
	"observation_lost":     true,
	"unsupported_by_subject": true,
	"manual_override":      true,
}

var journalEventRoles = map[string]bool{
	"external_input":         true,
	"derived_output":         true,
	"lifecycle_observation":  true,
}

var payloadFields = map[string]bool{
	"data": true, "measurements": true, "evidence_refs": true, "artifact_refs": true,
}

var artifactAccess = map[string]bool{
	"public": true, "restricted": true,
}

// ValidateRecord enforces the structural and semantic gates for one durable
// record: duplicate keys (rejected before validation), well-formed JSON,
// known record version, closed-object fields, reasoned Missing envelopes
// instead of bare nulls, required fields, digest/reference/size arithmetic,
// and format assertions on declared dates and URIs (seam-mapping 16.1).
//
// Structural validation is not authorization and not semantic conformance:
// unknown writers, producers, or prefix coverage are outside this gate.
func ValidateRecord(schemaVersion string, recordType string, document []byte) error {
	if len(bytes.TrimSpace(document)) == 0 {
		return fmt.Errorf("evidence_codec: empty document")
	}
	// Duplicate mapping keys are rejected before validation.
	if err := checkDuplicateKeys(document); err != nil {
		return err
	}
	v, err := decodeSingleValue(document)
	if err != nil {
		return err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("evidence_codec: record must be a JSON object, not a bare non-object value")
	}
	rt, _ := obj["record_type"].(string)
	if rt == "" {
		return fmt.Errorf("evidence_codec: missing required field \"record_type\"")
	}
	if rt != recordType {
		return fmt.Errorf("evidence_codec: record_type %q does not match declared record type %q", rt, recordType)
	}
	if !knownRecordTypes[rt] {
		return fmt.Errorf("evidence_codec: unknown record type %q", rt)
	}
	sv, _ := obj["schema_version"].(string)
	if sv == "" {
		return fmt.Errorf("evidence_codec: missing required field \"schema_version\"")
	}
	if sv != schemaVersion {
		return fmt.Errorf("evidence_codec: schema_version %q does not match declared version %q", sv, schemaVersion)
	}
	if !knownSchemaVersions[sv] {
		return fmt.Errorf("evidence_codec: unknown record version %q", sv)
	}
	shapes := recordShapes()
	shape := shapes[rt]
	allowed := make(map[string]bool, len(shape.required)+len(shape.optional))
	for _, f := range shape.required {
		allowed[f] = true
	}
	for _, f := range shape.optional {
		allowed[f] = true
	}
	for _, f := range shape.required {
		if _, ok := obj[f]; !ok {
			return fmt.Errorf("evidence_codec: missing required field %q", f)
		}
	}
	for k := range obj {
		if !allowed[k] {
			return fmt.Errorf("evidence_codec: unknown closed-object field %q for record type %q", k, rt)
		}
	}
	if rt == "journal_event" {
		if err := checkJournalEvent(obj); err != nil {
			return err
		}
	}
	if err := walkValue("", obj, "$"); err != nil {
		return err
	}
	return nil
}

func nonEmptyString(obj map[string]any, field, path string) error {
	s, ok := obj[field].(string)
	if !ok || strings.TrimSpace(s) == "" {
		return fmt.Errorf("evidence_codec: field %q at %s must be a nonempty string", field, path)
	}
	return nil
}

func checkJournalEvent(obj map[string]any) error {
	for _, f := range []string{"run_id", "journal_id", "event_id", "event_kind", "event_schema_version", "assertion_kind", "owner_domain", "producer_id", "provenance", "evidence_scope"} {
		if err := nonEmptyString(obj, f, "$"); err != nil {
			return err
		}
	}
	role, _ := obj["role"].(string)
	if !journalEventRoles[role] {
		return fmt.Errorf("evidence_codec: unknown role %q: must be external_input, derived_output, or lifecycle_observation", role)
	}
	pl, ok := obj["payload"].(map[string]any)
	if !ok {
		return fmt.Errorf("evidence_codec: payload must be an object containing exactly data, measurements, evidence_refs, and artifact_refs")
	}
	for k := range pl {
		if !payloadFields[k] {
			return fmt.Errorf("evidence_codec: unknown closed-object field %q in payload", k)
		}
	}
	for k := range payloadFields {
		if _, ok := pl[k]; !ok {
			return fmt.Errorf("evidence_codec: missing required payload field %q", k)
		}
	}
	if refs, ok := pl["evidence_refs"].([]any); ok {
		for i, r := range refs {
			if err := checkEvidenceRef(r, fmt.Sprintf("$.payload.evidence_refs[%d]", i)); err != nil {
				return err
			}
		}
	} else if pl["evidence_refs"] != nil {
		return fmt.Errorf("evidence_codec: evidence_refs must be an array")
	}
	if refs, ok := pl["artifact_refs"].([]any); ok {
		for i, r := range refs {
			if err := checkArtifactRef(r, fmt.Sprintf("$.payload.artifact_refs[%d]", i)); err != nil {
				return err
			}
		}
	} else if pl["artifact_refs"] != nil {
		return fmt.Errorf("evidence_codec: artifact_refs must be an array")
	}
	return nil
}

func checkEvidenceRef(r any, path string) error {
	m, ok := r.(map[string]any)
	if !ok {
		return fmt.Errorf("evidence_codec: evidence reference at %s must be an object", path)
	}
	for _, f := range []string{"journal_id", "sequence", "event_id", "event_hash", "pointer"} {
		if _, ok := m[f]; !ok {
			return fmt.Errorf("evidence_codec: missing required evidence reference field %q at %s", f, path)
		}
	}
	for k := range m {
		switch k {
		case "journal_id", "sequence", "event_id", "event_hash", "pointer":
		default:
			return fmt.Errorf("evidence_codec: unknown evidence reference field %q at %s", k, path)
		}
	}
	h, _ := m["event_hash"].(string)
	if !validDigest(h) {
		return fmt.Errorf("evidence_codec: invalid evidence event_hash at %s", path)
	}
	p, _ := m["pointer"].(string)
	if !validJSONPointer(p) {
		return fmt.Errorf("evidence_codec: invalid JSON pointer %q at %s", p, path)
	}
	return nil
}

func checkArtifactRef(r any, path string) error {
	m, ok := r.(map[string]any)
	if !ok {
		return fmt.Errorf("evidence_codec: artifact reference at %s must be an object", path)
	}
	d, _ := m["digest"].(string)
	if !validDigest(d) {
		return fmt.Errorf("evidence_codec: invalid artifact digest at %s", path)
	}
	for k := range m {
		switch k {
		case "digest", "size_bytes", "media_type", "owner_domain", "access":
		default:
			return fmt.Errorf("evidence_codec: unknown artifact reference field %q at %s", k, path)
		}
	}
	if a, ok := m["access"].(string); ok && !artifactAccess[a] {
		return fmt.Errorf("evidence_codec: invalid artifact access %q at %s: must be public or restricted", a, path)
	}
	return nil
}

func validJSONPointer(s string) bool {
	if s == "" {
		return true
	}
	if !strings.HasPrefix(s, "/") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '~' {
			i++
			if i >= len(s) || (s[i] != '0' && s[i] != '1') {
				return false
			}
		}
	}
	return true
}

func checkMissingEnvelope(m map[string]any, path string) error {
	for k := range m {
		if k != "value" && k != "reason" && k != "detail" {
			return fmt.Errorf("evidence_codec: unknown field %q in Missing envelope at %s", k, path)
		}
	}
	r, _ := m["reason"].(string)
	if !nullReasons[r] {
		return fmt.Errorf("evidence_codec: invalid NullReason %q at %s: must be one of not_enabled, not_applicable, not_observed, observation_lost, unsupported_by_subject, manual_override", r, path)
	}
	if d, ok := m["detail"]; ok {
		s, ok := d.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return fmt.Errorf("evidence_codec: Missing detail at %s must be a nonempty string", path)
		}
	}
	return nil
}

func walkValue(key string, val any, path string) error {
	switch t := val.(type) {
	case nil:
		return fmt.Errorf("evidence_codec: bare normalized null at %s: normalized absences must use a Missing envelope with value null and a reason", path)
	case map[string]any:
		if raw, hasValue := t["value"]; hasValue && raw == nil {
			return checkMissingEnvelope(t, path)
		}
		for k, e := range t {
			if err := walkValue(k, e, path+"."+k); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for i, e := range t {
			if err := walkValue(key, e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case string:
		if isNonFiniteToken(t) {
			return fmt.Errorf("evidence_codec: non-finite/non-JSON value %q at %s", t, path)
		}
		if isDigestField(key) && !validDigest(t) {
			return fmt.Errorf("evidence_codec: invalid digest %q at %s: must match sha256:<64 lowercase hex>", t, path)
		}
		if isDateTimeField(key) {
			if _, err := time.Parse(time.RFC3339, t); err != nil {
				return fmt.Errorf("evidence_codec: invalid date-time %q at %s: format assertion failed: %v", t, path, err)
			}
		}
		if isDateField(key) {
			if _, err := time.Parse("2006-01-02", t); err != nil {
				return fmt.Errorf("evidence_codec: invalid date %q at %s: format assertion failed: %v", t, path, err)
			}
		}
		if isURIField(key) {
			if !validURI(t) {
				return fmt.Errorf("evidence_codec: invalid URI %q at %s: format assertion failed", t, path)
			}
		}
		return nil
	case json.Number:
		s := t.String()
		if isIntegerField(key) {
			if !isIntegerLiteral(s) {
				return fmt.Errorf("evidence_codec: field %q at %s must be an integer, got %q", key, path, s)
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("evidence_codec: field %q at %s out of range: %q", key, path, s)
			}
			if n < 0 {
				return fmt.Errorf("evidence_codec: field %q at %s must not be negative: %d", key, path, n)
			}
			if key == "journal_sequence" && n < 1 {
				return fmt.Errorf("evidence_codec: journal_sequence at %s starts at 1", path)
			}
		} else if _, err := strconv.ParseFloat(s, 64); err != nil {
			return fmt.Errorf("evidence_codec: invalid number %q at %s", s, path)
		}
		return nil
	case bool:
		return nil
	default:
		return fmt.Errorf("evidence_codec: non-JSON value of type %T at %s rejected", val, path)
	}
}

func isNonFiniteToken(s string) bool {
	switch strings.ToLower(s) {
	case "nan", "+nan", "-nan",
		"infinity", "+infinity", "-infinity",
		"inf", "+inf", "-inf",
		"undefined":
		return true
	}
	return false
}

func isDigestField(key string) bool {
	return key == "digest" || key == "manifest_hash" || key == "event_hash" ||
		key == "previous_event_hash" || key == "head_hash" ||
		strings.HasSuffix(key, "_hash") || strings.HasSuffix(key, "_digest")
}

func isDateTimeField(key string) bool {
	return strings.HasSuffix(key, "_at") || key == "timestamp"
}

func isDateField(key string) bool {
	return strings.HasSuffix(key, "_date")
}

func isURIField(key string) bool {
	return strings.HasSuffix(key, "_uri") || strings.HasSuffix(key, "_url")
}

func validURI(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.IsAbs() && u.Host != ""
}

func isIntegerField(key string) bool {
	switch key {
	case "journal_sequence", "producer_sequence", "analysis_revision",
		"descriptor_revision", "last_sequence", "sequence", "size_bytes":
		return true
	}
	return false
}
