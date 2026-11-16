// Package fixture_policy implements the tier-1 Hellscape fixture policy gate.
//
// It enforces seam-mappings/hellscape-seam-mapping.md sections 5.2 (manifest
// field mapping), 12.1 (M1 cooperative profile), 12.2 (feature-pack
// contract), 12.5 (compiler rejection rules), and 12.6 (curriculum and
// recommendations), plus the LIFE-COMMISSION / LIFE-LINEAGE kind and lineage
// rules and the practice / laboratory_fixture / held_in admission boundary.
//
// The gate is pure validation: it never executes manifest JavaScript,
// downloaded feature code, or native plugins, never mutates a manifest, and
// never shares subject curriculum lineages. Structural record gates
// (duplicate keys, canonical JSON, closed objects, reasoned Missing
// envelopes) are delegated to evidence_codec.
package fixture_policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"evidence_codec"
)

// MaxFastCampaignDelayMs bounds fast-campaign artificial delays (seam 12.5).
// Longer waits require a separately declared soak profile.
const MaxFastCampaignDelayMs = 5000

// Manifest is the admitted laboratory manifest projection validated by this
// gate. The EK-owned fields serialize into the closed manifest record
// (seam 5.2); Profile, Subject, and Lineage are policy extensions carried
// out-of-band so they never violate the EK closed-object gate.
type Manifest struct {
	RecordType        string             `json:"record_type"`
	SchemaVersion     string             `json:"schema_version"`
	ManifestID        string             `json:"manifest_id"`
	RunID             string             `json:"run_id"`
	JournalID         string             `json:"journal_id"`
	OwnerDomain       string             `json:"owner_domain"`
	CommissionerID    string             `json:"commissioner_id,omitempty"`
	Activity          string             `json:"activity,omitempty"`
	Attempt           AttemptContext     `json:"attempt,omitempty"`
	Execution         map[string]any     `json:"execution,omitempty"`
	Task              map[string]any     `json:"task,omitempty"`
	TaskSemanticHash   string             `json:"task_semantic_hash,omitempty"`
	Environment       map[string]any     `json:"environment,omitempty"`
	Seed              any                `json:"seed,omitempty"`
	BuildPins         map[string]string  `json:"build_pins,omitempty"`
	EventRegistry     map[string]string  `json:"event_registry,omitempty"`
	Producers         []map[string]any   `json:"producers,omitempty"`
	Clocks            []map[string]any   `json:"clocks,omitempty"`
	Profile           string             `json:"-"`
	Subject           SubjectDescriptor  `json:"-"`
	Lineage           LineageLinks       `json:"-"`
}

// AttemptContext carries the immutable attempt scope. Hellscape fixtures
// admit only practice / laboratory_fixture / held_in.
type AttemptContext struct {
	Kind           string `json:"kind,omitempty"`
	Context        string `json:"context,omitempty"`
	Scope          string `json:"scope,omitempty"`
	SubjectVersion string `json:"subject_version,omitempty"`
	Assistance     string `json:"assistance,omitempty"`
}

// SubjectDescriptor identifies the measured subject and version. Subject
// version, assistance, context policy, and feature exposure are attribution
// boundaries (seam 12.6).
type SubjectDescriptor struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// LineageLinks carries kind and lineage references. derived_from is
// same-kind and acyclic; rehearsal_of links practice to production and
// performance_of links production to practice. These are lineage links,
// never evidence promotion.
type LineageLinks struct {
	Kind          string   `json:"kind,omitempty"`
	DerivedFrom   []string `json:"derived_from,omitempty"`
	RehearsalOf   string   `json:"rehearsal_of,omitempty"`
	PerformanceOf string   `json:"performance_of,omitempty"`
}

// HostileTreatments enumerates deliberate hostile fixture treatments. M1
// admits zero of them (seam 12.1).
type HostileTreatments struct {
	FrameChallenge           bool `json:"frame_challenge"`
	RootChallenge            bool `json:"root_challenge"`
	ClassChurn               bool `json:"class_churn"`
	Decoys                   bool `json:"decoys"`
	DelayedHydration         bool `json:"delayed_hydration"`
	IdleTrap                 bool `json:"idle_trap"`
	TransportFailureInjected bool `json:"transport_failure_injected"`
	InjectedTransportFailure bool `json:"injected_transport_failure"`
	ProductionChallengeSvc   bool `json:"production_challenge_service"`
	ArtificialTimingRace     bool `json:"artificial_timing_race"`
	ShadowDOMControls        bool `json:"shadow_dom_controls"`
	UnstableLayout           bool `json:"unstable_layout"`
	NonNativeControls        bool `json:"non_native_controls"`
	NonOrdinaryLabels        bool `json:"non_ordinary_labels"`
	AbnormalValidation       bool `json:"abnormal_validation"`
	AbnormalUpload           bool `json:"abnormal_upload"`
	AbnormalIdentity         bool `json:"abnormal_identity"`
	AbnormalStateTransition  bool `json:"abnormal_state_transition"`
	AbnormalSubmission       bool `json:"abnormal_submission"`
}

func (h HostileTreatments) reasons() []string {
	var r []string
	if h.FrameChallenge {
		r = append(r, "frame challenge")
	}
	if h.RootChallenge {
		r = append(r, "root challenge")
	}
	if h.ClassChurn {
		r = append(r, "class churn")
	}
	if h.Decoys {
		r = append(r, "decoys")
	}
	if h.DelayedHydration {
		r = append(r, "delayed hydration")
	}
	if h.IdleTrap {
		r = append(r, "idle trap")
	}
	if h.TransportFailureInjected || h.InjectedTransportFailure {
		r = append(r, "injected transport failure")
	}
	if h.ProductionChallengeSvc {
		r = append(r, "production challenge service")
	}
	if h.ArtificialTimingRace {
		r = append(r, "artificial timing race")
	}
	if h.ShadowDOMControls {
		r = append(r, "shadow-DOM controls (M1 requires light DOM)")
	}
	if h.UnstableLayout {
		r = append(r, "unstable layout (M1 requires stable layout)")
	}
	if h.NonNativeControls {
		r = append(r, "non-native controls (M1 requires native controls)")
	}
	if h.NonOrdinaryLabels {
		r = append(r, "non-ordinary labels (M1 requires visible ordinary labels)")
	}
	if h.AbnormalValidation {
		r = append(r, "abnormal validation guards")
	}
	if h.AbnormalUpload {
		r = append(r, "abnormal upload guards")
	}
	if h.AbnormalIdentity {
		r = append(r, "abnormal identity guards")
	}
	if h.AbnormalStateTransition {
		r = append(r, "abnormal state-transition guards")
	}
	if h.AbnormalSubmission {
		r = append(r, "abnormal submission guards")
	}
	return r
}

// ExecutableSignals enumerates executable-code declarations. No runtime eval,
// downloaded executable feature code, or native plugin loading is admitted
// (seam 12.2).
type ExecutableSignals struct {
	Javascript            string `json:"javascript"`
	JavascriptCamel       string `json:"javaScript"`
	Script                string `json:"script"`
	RecipeBody            string `json:"recipe_body"`
	RuntimeEval           bool   `json:"runtime_eval"`
	Eval                  bool   `json:"eval"`
	DownloadedCodeURL     string `json:"downloaded_code_url"`
	DownloadedExecutable  string `json:"downloaded_executable"`
	NativePlugin          string `json:"native_plugin"`
	NativePluginLoading   bool   `json:"native_plugin_loading"`
}

type featureConfig struct {
	HostileTreatments
	ExecutableSignals
	Name                      string            `json:"name"`
	Hostile                   *bool             `json:"hostile"`
	Recipe                    string            `json:"recipe"`
	Parameters                map[string]any    `json:"parameters"`
	ParameterDomains          map[string]any    `json:"parameter_domains"`
	Dependencies              []string          `json:"dependencies"`
	Exclusions                []string          `json:"exclusions"`
	HumanCompletionContract   any               `json:"human_completion_contract"`
	HumanCompletion           any               `json:"human_completion"`
	DegradationContract       any               `json:"degradation_contract"`
	ExposureEventKinds        []string          `json:"exposure_event_kinds"`
	ActivationEventKinds      []string          `json:"activation_event_kinds"`
	ExpectedFailureSignatures []string          `json:"expected_failure_signatures"`
	RegressionCases           []string          `json:"regression_cases"`
	AssetDigests              map[string]string `json:"asset_digests"`
	SchemaDigests             map[string]string `json:"schema_digests"`
}

type taskConfig struct {
	Kind                         string   `json:"kind"`
	RequiredControls             []string `json:"required_controls"`
	HiddenControls               []string `json:"hidden_controls"`
	HumanPath                    any      `json:"human_path"`
	RequiresObservationalMock    bool     `json:"requires_observational_mock"`
	RequiresMock                 bool     `json:"requires_mock"`
	RequiredVerifiers            []string `json:"required_verifiers"`
	PermanentlyRejectedVerifiers []string `json:"permanently_rejected_verifiers"`
	PermanentRejection           bool     `json:"permanent_rejection"`
	RequiresRecovery             bool     `json:"requires_recovery"`
	RecoveryPaths                []string `json:"recovery_paths"`
	RecoveryRemoved              bool     `json:"recovery_removed"`
	RequiredBrowserCapabilities  []string `json:"required_browser_capabilities"`
	AvailableBrowserCapabilities []string `json:"available_browser_capabilities"`
}

type budgetConfig struct {
	TaskMs              *float64 `json:"task_ms"`
	RequiredMs          *float64 `json:"required_ms"`
	ObservationMs       *float64 `json:"observation_ms"`
	ControlMs           *float64 `json:"control_ms"`
	ArtificialDelayMs   *float64 `json:"artificial_delay_ms"`
	SoakProfileDeclared bool     `json:"soak_profile_declared"`
	SoakProfile         string   `json:"soak_profile"`
}

type degradationConfig struct {
	Declared     bool   `json:"declared"`
	Commissioned bool   `json:"commissioned"`
	Objective    string `json:"objective"`
	Graceful     bool   `json:"graceful"`
}

type fixProposal struct {
	RuleClassAuthority string `json:"rule_class_authority"`
	Authority          string `json:"authority"`
	Reviewed           bool   `json:"reviewed"`
	ReviewStatus       string `json:"review_status"`
	SupportingEvidence any    `json:"supporting_evidence"`
	Evidence           any    `json:"evidence"`
}

type curriculumConfig struct {
	MutatesActiveManifest  bool        `json:"mutates_active_manifest"`
	MutateActiveManifest   bool        `json:"mutate_active_manifest"`
	EditsManifestInPlace   bool        `json:"edits_manifest_in_place"`
	CreatesNewManifest     bool        `json:"creates_new_manifest"`
	NewManifest            bool        `json:"new_manifest"`
	SubjectLineages        []any       `json:"subject_lineages"`
	SharesLineages         bool        `json:"shares_lineages"`
	SharedLineage          bool        `json:"shared_lineage"`
	AutoPatchSubject       bool        `json:"auto_patch_subject"`
	AutoPatch              bool        `json:"auto_patch"`
	ActivatesExecutionFix  bool        `json:"activates_execution_fix"`
	ActivatesFix           bool        `json:"activates_fix"`
	InnerVariantProposal   any         `json:"inner_variant_proposal"`
	OuterFixProposal       *fixProposal `json:"outer_fix_proposal"`
	FixProposal            *fixProposal `json:"fix_proposal"`
}

type effectiveConfig struct {
	HostileTreatments
	ExecutableSignals
	Profile                   string             `json:"profile"`
	ExpectedOutcome           string             `json:"expected_outcome"`
	Hostile                   *bool              `json:"hostile"`
	Recipe                    string             `json:"recipe"`
	Features                  []featureConfig    `json:"features"`
	Task                      *taskConfig        `json:"task"`
	Budgets                   *budgetConfig      `json:"budgets"`
	Browser                   map[string]any     `json:"browser"`
	GracefulDegradation       *degradationConfig `json:"graceful_degradation"`
	Curriculum                *curriculumConfig  `json:"curriculum"`
	Readiness                 string             `json:"readiness"`
	AutosaveDisplacesReducer  bool               `json:"autosave_displaces_reducer"`
	WebsocketDisplacesReducer bool               `json:"websocket_displaces_reducer"`
}

var configNullReasons = map[string]bool{
	"not_enabled":          true,
	"not_applicable":       true,
	"not_observed":         true,
	"observation_lost":     true,
	"unsupported_by_subject": true,
	"manual_override":      true,
}

// ValidateFixture validates a laboratory manifest against its effective
// fixture configuration. It returns nil when the fixture is admissible and
// a descriptive error otherwise.
func ValidateFixture(manifest Manifest, configuration []byte) error {
	recordType, schemaVersion, err := checkManifestIdentity(manifest)
	if err != nil {
		return err
	}
	if err := checkActivity(manifest); err != nil {
		return err
	}
	if err := checkAttemptScope(manifest); err != nil {
		return err
	}
	if err := checkLineage(manifest); err != nil {
		return err
	}
	if err := checkTaskSemanticHash(manifest); err != nil {
		return err
	}
	manifestJSON, err := buildEKProjection(manifest, recordType, schemaVersion)
	if err != nil {
		return err
	}
	if err := evidence_codec.ValidateRecord(schemaVersion, recordType, manifestJSON); err != nil {
		return fmt.Errorf("fixture_policy: manifest violates EK structural gates: %w", err)
	}
	if len(bytes.TrimSpace(configuration)) == 0 {
		return fmt.Errorf("fixture_policy: missing effective_configuration")
	}
	canonical, err := evidence_codec.CanonicalJSON(configuration, "application/json")
	if err != nil {
		return fmt.Errorf("fixture_policy: effective_configuration is not canonicalizable JSON: %w", err)
	}
	var generic any
	if err := json.Unmarshal(canonical, &generic); err != nil {
		return fmt.Errorf("fixture_policy: cannot decode effective_configuration: %w", err)
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		return fmt.Errorf("fixture_policy: effective_configuration must be a JSON object")
	}
	if err := rejectBareNulls(obj, "$"); err != nil {
		return err
	}
	if err := scanExecutableGeneric(obj, "$"); err != nil {
		return err
	}
	var cfg effectiveConfig
	if err := json.Unmarshal(canonical, &cfg); err != nil {
		return fmt.Errorf("fixture_policy: cannot decode effective_configuration: %w", err)
	}
	profile := strings.TrimSpace(manifest.Profile)
	if profile == "" {
		profile = strings.TrimSpace(cfg.Profile)
	}
	if profile == "" {
		profile = "M1"
	}
	isM1 := strings.EqualFold(profile, "M1")
	if err := checkExecutableCodeTyped(&cfg); err != nil {
		return err
	}
	if err := checkM1Hostile(isM1, &cfg); err != nil {
		return err
	}
	if err := checkReadinessAndReducerAuthority(&cfg); err != nil {
		return err
	}
	if err := checkFeaturePackContracts(isM1, &cfg); err != nil {
		return err
	}
	if err := checkCompletionHumanPaths(&cfg); err != nil {
		return err
	}
	if err := checkImpossibleBudgetsAndRecovery(&cfg); err != nil {
		return err
	}
	if err := checkPermanentRejection(&cfg); err != nil {
		return err
	}
	if err := checkCurriculum(manifest, &cfg); err != nil {
		return err
	}
	return nil
}

func checkManifestIdentity(m Manifest) (string, string, error) {
	recordType := strings.TrimSpace(m.RecordType)
	if recordType == "" {
		recordType = "manifest"
	}
	schemaVersion := strings.TrimSpace(m.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = "1.0.0"
	}
	if recordType != "manifest" {
		return "", "", fmt.Errorf("fixture_policy: manifest record_type must be %q, got %q", "manifest", m.RecordType)
	}
	if strings.TrimSpace(m.ManifestID) == "" {
		return "", "", fmt.Errorf("fixture_policy: manifest is missing required field %q", "manifest_id")
	}
	if strings.TrimSpace(m.RunID) == "" {
		return "", "", fmt.Errorf("fixture_policy: manifest is missing required field %q", "run_id")
	}
	if strings.TrimSpace(m.JournalID) == "" {
		return "", "", fmt.Errorf("fixture_policy: manifest is missing required field %q", "journal_id")
	}
	if strings.TrimSpace(m.OwnerDomain) == "" {
		return "", "", fmt.Errorf("fixture_policy: manifest is missing required field %q", "owner_domain")
	}
	return recordType, schemaVersion, nil
}

func checkActivity(m Manifest) error {
	if strings.TrimSpace(m.Activity) == "" {
		return nil
	}
	if m.Activity != "application_attempt" && m.Activity != "kernel_conformance" {
		return fmt.Errorf("fixture_policy: activity must be application_attempt or kernel_conformance, got %q", m.Activity)
	}
	return nil
}

func checkAttemptScope(m Manifest) error {
	if strings.TrimSpace(m.Attempt.Kind) == "" || strings.TrimSpace(m.Attempt.Context) == "" || strings.TrimSpace(m.Attempt.Scope) == "" {
		return fmt.Errorf("fixture_policy: attempt must declare kind, context, and scope (practice, laboratory_fixture, held_in)")
	}
	if m.Attempt.Kind != "practice" {
		return fmt.Errorf("fixture_policy: Hellscape attempts outside practice are not admitted (got kind %q); production requires an employer origin", m.Attempt.Kind)
	}
	if m.Attempt.Context != "laboratory_fixture" {
		return fmt.Errorf("fixture_policy: Hellscape attempts outside laboratory_fixture are not admitted (got context %q)", m.Attempt.Context)
	}
	if m.Attempt.Scope != "held_in" {
		return fmt.Errorf("fixture_policy: Hellscape attempts outside held_in are not admitted (got scope %q)", m.Attempt.Scope)
	}
	return nil
}

func checkLineage(m Manifest) error {
	if strings.TrimSpace(m.Lineage.Kind) != "" && strings.TrimSpace(m.Attempt.Kind) != "" && m.Lineage.Kind != m.Attempt.Kind {
		return fmt.Errorf("fixture_policy: kind is immutable (attempt %q vs lineage %q)", m.Attempt.Kind, m.Lineage.Kind)
	}
	seen := make(map[string]bool, len(m.Lineage.DerivedFrom))
	for _, d := range m.Lineage.DerivedFrom {
		if strings.TrimSpace(d) == "" {
			return fmt.Errorf("fixture_policy: derived_from contains an empty identity")
		}
		if d == m.ManifestID {
			return fmt.Errorf("fixture_policy: derived_from is acyclic (self-reference %q)", d)
		}
		if seen[d] {
			return fmt.Errorf("fixture_policy: derived_from contains duplicate identity %q", d)
		}
		seen[d] = true
		lower := strings.ToLower(d)
		if m.Attempt.Kind == "practice" && strings.Contains(lower, "production") {
			return fmt.Errorf("fixture_policy: derived_from references only the same kind (practice attempt derives from %q)", d)
		}
	}
	kind := strings.TrimSpace(m.Attempt.Kind)
	if kind == "" {
		kind = strings.TrimSpace(m.Lineage.Kind)
	}
	if kind == "" || kind == "practice" {
		if strings.TrimSpace(m.Lineage.PerformanceOf) != "" {
			return fmt.Errorf("fixture_policy: performance_of links production to practice; a practice attempt must not declare performance_of")
		}
		if strings.TrimSpace(m.Lineage.RehearsalOf) != "" && m.Lineage.RehearsalOf == m.ManifestID {
			return fmt.Errorf("fixture_policy: rehearsal_of must reference an already commissioned production identity distinct from self")
		}
	} else if kind == "production" {
		if strings.TrimSpace(m.Lineage.RehearsalOf) != "" {
			return fmt.Errorf("fixture_policy: rehearsal_of links practice to production; a production attempt must not declare rehearsal_of")
		}
		if strings.TrimSpace(m.Lineage.PerformanceOf) != "" && m.Lineage.PerformanceOf == m.ManifestID {
			return fmt.Errorf("fixture_policy: performance_of must reference an already commissioned practice identity distinct from self")
		}
	}
	if strings.TrimSpace(m.Attempt.SubjectVersion) != "" && strings.TrimSpace(m.Subject.Version) != "" && m.Attempt.SubjectVersion != m.Subject.Version {
		return fmt.Errorf("fixture_policy: subject version is an attribution boundary (attempt %q vs subject %q); changing the subject version creates a new attempt", m.Attempt.SubjectVersion, m.Subject.Version)
	}
	return nil
}

func checkTaskSemanticHash(m Manifest) error {
	if strings.TrimSpace(m.TaskSemanticHash) == "" {
		return nil
	}
	if !validDigest(m.TaskSemanticHash) {
		return fmt.Errorf("fixture_policy: task_semantic_hash %q must match sha256:<64 lowercase hex>", m.TaskSemanticHash)
	}
	return nil
}

func buildEKProjection(m Manifest, recordType, schemaVersion string) ([]byte, error) {
	proj := map[string]any{
		"record_type":  recordType,
		"schema_version": schemaVersion,
		"manifest_id":  m.ManifestID,
		"run_id":       m.RunID,
		"journal_id":   m.JournalID,
		"owner_domain": m.OwnerDomain,
	}
	if strings.TrimSpace(m.CommissionerID) != "" {
		proj["commissioner_id"] = m.CommissionerID
	}
	if strings.TrimSpace(m.Activity) != "" {
		proj["activity"] = m.Activity
	}
	attempt := map[string]any{}
	if strings.TrimSpace(m.Attempt.Kind) != "" {
		attempt["kind"] = m.Attempt.Kind
	}
	if strings.TrimSpace(m.Attempt.Context) != "" {
		attempt["context"] = m.Attempt.Context
	}
	if strings.TrimSpace(m.Attempt.Scope) != "" {
		attempt["scope"] = m.Attempt.Scope
	}
	if strings.TrimSpace(m.Attempt.SubjectVersion) != "" {
		attempt["subject_version"] = m.Attempt.SubjectVersion
	}
	if strings.TrimSpace(m.Attempt.Assistance) != "" {
		attempt["assistance"] = m.Attempt.Assistance
	}
	if len(attempt) > 0 {
		proj["attempt"] = attempt
	}
	if len(m.Execution) > 0 {
		proj["execution"] = m.Execution
	}
	if len(m.Task) > 0 {
		proj["task"] = m.Task
	}
	if strings.TrimSpace(m.TaskSemanticHash) != "" {
		proj["task_semantic_hash"] = m.TaskSemanticHash
	}
	if len(m.Environment) > 0 {
		proj["environment"] = m.Environment
	}
	if m.Seed != nil {
		proj["seed"] = m.Seed
	}
	if len(m.BuildPins) > 0 {
		proj["build_pins"] = m.BuildPins
	}
	if len(m.EventRegistry) > 0 {
		proj["event_registry"] = m.EventRegistry
	}
	if len(m.Producers) > 0 {
		proj["producers"] = m.Producers
	}
	if len(m.Clocks) > 0 {
		proj["clocks"] = m.Clocks
	}
	out, err := json.Marshal(proj)
	if err != nil {
		return nil, fmt.Errorf("fixture_policy: cannot encode manifest projection: %w", err)
	}
	return out, nil
}

func validDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	hexPart := strings.TrimPrefix(s, prefix)
	if len(hexPart) != 64 {
		return false
	}
	for _, c := range hexPart {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func rejectBareNulls(v any, path string) error {
	switch t := v.(type) {
	case nil:
		return fmt.Errorf("fixture_policy: bare null at %s: missing fields must use typed Missing envelopes with value null and a reason", path)
	case map[string]any:
		if raw, ok := t["value"]; ok && raw == nil {
			for k := range t {
				if k != "value" && k != "reason" && k != "detail" {
					return fmt.Errorf("fixture_policy: unknown field %q in Missing envelope at %s", k, path)
				}
			}
			r, _ := t["reason"].(string)
			if !configNullReasons[r] {
				return fmt.Errorf("fixture_policy: invalid NullReason %q at %s", r, path)
			}
			if d, ok := t["detail"]; ok {
				s, ok := d.(string)
				if !ok || strings.TrimSpace(s) == "" {
					return fmt.Errorf("fixture_policy: Missing detail at %s must be a nonempty string", path)
				}
			}
			return nil
		}
		for k, e := range t {
			if err := rejectBareNulls(e, path+"."+k); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for i, e := range t {
			if err := rejectBareNulls(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

var executableStringKeys = map[string]bool{
	"javascript": true, "js": true, "inline_js": true, "feature_js": true,
	"script": true, "inline_script": true, "recipe_body": true,
	"downloaded_code_url": true, "downloaded_executable": true, "downloaded_code": true,
	"native_plugin": true,
}

var executableBoolKeys = map[string]bool{
	"runtime_eval": true, "eval": true, "native_plugin_loading": true,
}

func scanExecutableGeneric(v any, path string) error {
	switch t := v.(type) {
	case map[string]any:
		if raw, ok := t["value"]; ok && raw == nil {
			return nil
		}
		for k, e := range t {
			lk := strings.ToLower(k)
			if executableStringKeys[lk] {
				switch ev := e.(type) {
				case string:
					if strings.TrimSpace(ev) != "" {
						return fmt.Errorf("fixture_policy: executable code rejected at %s: manifests contain parameters and registered recipes, not executable JavaScript", path+"."+k)
					}
				case bool:
					if ev {
						return fmt.Errorf("fixture_policy: executable code rejected at %s: manifests contain parameters and registered recipes, not executable JavaScript", path+"."+k)
					}
				case map[string]any:
					if len(ev) > 0 {
						return fmt.Errorf("fixture_policy: executable code rejected at %s: manifests contain parameters and registered recipes, not executable JavaScript", path+"."+k)
					}
				case []any:
					if len(ev) > 0 {
						return fmt.Errorf("fixture_policy: executable code rejected at %s: manifests contain parameters and registered recipes, not executable JavaScript", path+"."+k)
					}
				}
			}
			if executableBoolKeys[lk] {
				switch ev := e.(type) {
				case bool:
					if ev {
						return fmt.Errorf("fixture_policy: executable code rejected at %s: no runtime eval, downloaded executable feature code, or native plugin loading is admitted", path+"."+k)
					}
				case string:
					if strings.TrimSpace(ev) != "" {
						return fmt.Errorf("fixture_policy: executable code rejected at %s: no runtime eval, downloaded executable feature code, or native plugin loading is admitted", path+"."+k)
					}
				}
			}
			if lk == "recipe" {
				if s, ok := e.(string); ok && isCodeLikeRecipe(s) {
					return fmt.Errorf("fixture_policy: recipe %q at %s is not a registered primitive recipe: manifests contain parameters and registered recipes, not executable JavaScript", s, path+"."+k)
				}
			}
			if err := scanExecutableGeneric(e, path+"."+k); err != nil {
				return err
			}
		}
		return nil
	case []any:
		for i, e := range t {
			if err := scanExecutableGeneric(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// isCodeLikeRecipe reports whether s is executable code rather than a
// registered primitive recipe name. Registered names use only letters,
// digits, and the separators : / . - _ @ + (for example
// "primitive:cooperative-form/1.0").
func isCodeLikeRecipe(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	for _, token := range []string{"function", "eval", "script", "javascript:", "import ", "import(", "require(", "window.", "document.", "process.", "global.", "=>"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == ':' || r == '/' || r == '.' || r == '-' || r == '_' || r == '@' || r == '+':
		default:
			return true
		}
	}
	return false
}

func checkExecutableCodeTyped(cfg *effectiveConfig) error {
	if err := checkExecutableSignals(cfg.ExecutableSignals, "effective_configuration"); err != nil {
		return err
	}
	if cfg.Recipe != "" && isCodeLikeRecipe(cfg.Recipe) {
		return fmt.Errorf("fixture_policy: top-level recipe %q is not a registered primitive recipe: manifests contain parameters and registered recipes, not executable JavaScript", cfg.Recipe)
	}
	for i, f := range cfg.Features {
		where := fmt.Sprintf("features[%d] (%q)", i, f.Name)
		if err := checkExecutableSignals(f.ExecutableSignals, where); err != nil {
			return err
		}
		if f.Recipe != "" && isCodeLikeRecipe(f.Recipe) {
			return fmt.Errorf("fixture_policy: feature %s recipe %q is not a registered primitive recipe: manifests contain parameters and registered recipes, not executable JavaScript", where, f.Recipe)
		}
	}
	return nil
}

func checkExecutableSignals(s ExecutableSignals, where string) error {
	if strings.TrimSpace(s.Javascript) != "" || strings.TrimSpace(s.JavascriptCamel) != "" || strings.TrimSpace(s.Script) != "" {
		return fmt.Errorf("fixture_policy: %s declares executable JavaScript: manifests contain parameters and registered recipes, not executable JavaScript", where)
	}
	if strings.TrimSpace(s.RecipeBody) != "" {
		return fmt.Errorf("fixture_policy: %s declares an inline recipe body: manifests contain parameters and registered recipes, not executable JavaScript", where)
	}
	if s.RuntimeEval || s.Eval {
		return fmt.Errorf("fixture_policy: %s enables runtime eval: no runtime eval is admitted", where)
	}
	if strings.TrimSpace(s.DownloadedCodeURL) != "" || strings.TrimSpace(s.DownloadedExecutable) != "" {
		return fmt.Errorf("fixture_policy: %s declares downloaded executable feature code: no downloaded executable feature code is admitted", where)
	}
	if strings.TrimSpace(s.NativePlugin) != "" || s.NativePluginLoading {
		return fmt.Errorf("fixture_policy: %s declares native plugin loading: no native plugin loading is admitted", where)
	}
	return nil
}

func checkM1Hostile(isM1 bool, cfg *effectiveConfig) error {
	if !isM1 {
		return nil
	}
	if cfg.Hostile != nil && *cfg.Hostile {
		return fmt.Errorf("fixture_policy: M1 cooperative profile admits zero hostile features: top-level is marked hostile")
	}
	if reasons := cfg.HostileTreatments.reasons(); len(reasons) > 0 {
		return fmt.Errorf("fixture_policy: M1 cooperative profile admits zero hostile features: top-level declares %s", strings.Join(reasons, ", "))
	}
	for i, f := range cfg.Features {
		where := fmt.Sprintf("features[%d] (%q)", i, f.Name)
		if f.Hostile != nil && *f.Hostile {
			return fmt.Errorf("fixture_policy: M1 cooperative profile admits zero hostile features: %s is marked hostile", where)
		}
		if reasons := f.HostileTreatments.reasons(); len(reasons) > 0 {
			return fmt.Errorf("fixture_policy: M1 cooperative profile admits zero hostile features: %s declares hostile treatments: %s", where, strings.Join(reasons, ", "))
		}
	}
	return nil
}

func checkReadinessAndReducerAuthority(cfg *effectiveConfig) error {
	normalized := strings.ToLower(strings.TrimSpace(cfg.Readiness))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	if normalized == "network_silence" {
		return fmt.Errorf("fixture_policy: readiness occurs after relevant controls render and enable; network silence is not readiness")
	}
	if cfg.AutosaveDisplacesReducer {
		return fmt.Errorf("fixture_policy: later autosave behavior cannot displace reducer authority")
	}
	if cfg.WebsocketDisplacesReducer {
		return fmt.Errorf("fixture_policy: later WebSocket behavior cannot displace reducer authority")
	}
	return nil
}

func checkFeaturePackContracts(isM1 bool, cfg *effectiveConfig) error {
	if isM1 {
		return nil
	}
	for i, f := range cfg.Features {
		hostile := (f.Hostile != nil && *f.Hostile) || len(f.HostileTreatments.reasons()) > 0
		if !hostile {
			continue
		}
		where := fmt.Sprintf("features[%d] (%q)", i, f.Name)
		if f.ParameterDomains == nil {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin typed parameter domains", where)
		}
		if f.Dependencies == nil || f.Exclusions == nil {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin dependencies and exclusions", where)
		}
		if strings.TrimSpace(f.Recipe) == "" {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin a registered primitive recipe", where)
		}
		hasHuman := !isEmptyEvidence(f.HumanCompletionContract) || !isEmptyEvidence(f.HumanCompletion)
		hasDegradation := !isEmptyEvidence(f.DegradationContract)
		if !hasHuman && !hasDegradation {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin a human-completion or degradation contract", where)
		}
		if len(f.ExposureEventKinds) == 0 && len(f.ActivationEventKinds) == 0 {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin exposure/activation event kinds", where)
		}
		if len(f.ExpectedFailureSignatures) == 0 {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin expected failure signatures", where)
		}
		if len(f.RegressionCases) == 0 {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin regression cases", where)
		}
		if len(f.AssetDigests) == 0 && len(f.SchemaDigests) == 0 {
			return fmt.Errorf("fixture_policy: later feature pack %s must pin asset and schema digests", where)
		}
		for k, v := range f.AssetDigests {
			if !validDigest(v) {
				return fmt.Errorf("fixture_policy: later feature pack %s asset digest %q (%q) must match sha256:<64 lowercase hex>", where, k, v)
			}
		}
		for k, v := range f.SchemaDigests {
			if !validDigest(v) {
				return fmt.Errorf("fixture_policy: later feature pack %s schema digest %q (%q) must match sha256:<64 lowercase hex>", where, k, v)
			}
		}
	}
	return nil
}

func isCompletionTask(t *taskConfig) bool {
	if t == nil {
		return false
	}
	if strings.TrimSpace(t.Kind) != "" {
		return t.Kind == "completion"
	}
	return len(t.RequiredControls) > 0 || len(t.HiddenControls) > 0 || len(t.RequiredVerifiers) > 0 ||
		t.RequiresRecovery || t.PermanentRejection || len(t.PermanentlyRejectedVerifiers) > 0
}

func hasHumanPath(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return strings.TrimSpace(t) != ""
	case []any:
		return len(t) > 0
	case []string:
		return len(t) > 0
	case map[string]any:
		if raw, ok := t["value"]; ok && raw == nil {
			return false
		}
		for _, key := range []string{"enabled", "exists", "available", "present"} {
			if b, ok := t[key].(bool); ok {
				return b
			}
		}
		return len(t) > 0
	case float64:
		return t != 0
	case json.Number:
		return t.String() != "0"
	default:
		return false
	}
}

func checkCompletionHumanPaths(cfg *effectiveConfig) error {
	t := cfg.Task
	if t == nil || !isCompletionTask(t) {
		return nil
	}
	if len(t.HiddenControls) > 0 && !hasHumanPath(t.HumanPath) {
		if len(t.RequiredControls) == 0 {
			return fmt.Errorf("fixture_policy: completion task hides required controls %v without a human path", t.HiddenControls)
		}
		required := make(map[string]bool, len(t.RequiredControls))
		for _, c := range t.RequiredControls {
			required[c] = true
		}
		var hiddenRequired []string
		for _, h := range t.HiddenControls {
			if required[h] {
				hiddenRequired = append(hiddenRequired, h)
			}
		}
		if len(hiddenRequired) > 0 {
			return fmt.Errorf("fixture_policy: completion task hides required controls %v without a human path", hiddenRequired)
		}
	}
	if t.RequiresObservationalMock || t.RequiresMock {
		return fmt.Errorf("fixture_policy: completion task requires an observational mock to satisfy verification")
	}
	return nil
}

func checkImpossibleBudgetsAndRecovery(cfg *effectiveConfig) error {
	if cfg.Budgets != nil {
		b := cfg.Budgets
		if b.TaskMs != nil && b.RequiredMs != nil && *b.RequiredMs > *b.TaskMs {
			return fmt.Errorf("fixture_policy: completion task exceeds budget by construction (required %.0fms exceeds task budget %.0fms)", *b.RequiredMs, *b.TaskMs)
		}
		for name, v := range map[string]*float64{
			"task_ms": b.TaskMs, "required_ms": b.RequiredMs,
			"observation_ms": b.ObservationMs, "control_ms": b.ControlMs,
			"artificial_delay_ms": b.ArtificialDelayMs,
		} {
			if v != nil && *v < 0 {
				return fmt.Errorf("fixture_policy: impossible %s budget %.0fms (budgets must not be negative)", name, *v)
			}
		}
		if b.ArtificialDelayMs != nil && *b.ArtificialDelayMs > MaxFastCampaignDelayMs {
			if !b.SoakProfileDeclared && strings.TrimSpace(b.SoakProfile) == "" {
				return fmt.Errorf("fixture_policy: fast-campaign artificial delay %.0fms exceeds %dms without a separately declared soak profile", *b.ArtificialDelayMs, MaxFastCampaignDelayMs)
			}
		}
	}
	t := cfg.Task
	if t == nil || !isCompletionTask(t) {
		return nil
	}
	if t.RequiresRecovery {
		if t.RecoveryRemoved {
			return fmt.Errorf("fixture_policy: completion task removes all recovery while requiring recovery")
		}
		if len(t.RecoveryPaths) == 0 {
			return fmt.Errorf("fixture_policy: completion task requires recovery but declares no recovery paths")
		}
	}
	if len(t.RequiredBrowserCapabilities) > 0 {
		available := make(map[string]bool)
		for _, c := range t.AvailableBrowserCapabilities {
			available[c] = true
		}
		if cfg.Browser != nil {
			for _, key := range []string{"capabilities", "available_capabilities", "browser_capabilities"} {
				if caps, ok := cfg.Browser[key]; ok {
					switch v := caps.(type) {
					case []any:
						for _, e := range v {
							if s, ok := e.(string); ok {
								available[s] = true
							}
						}
					case []string:
						for _, s := range v {
							available[s] = true
						}
					}
				}
			}
		}
		var missing []string
		for _, r := range t.RequiredBrowserCapabilities {
			if !available[r] {
				missing = append(missing, r)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("fixture_policy: completion task requires unavailable fixture browser capabilities %v", missing)
		}
	}
	return nil
}

func checkPermanentRejection(cfg *effectiveConfig) error {
	t := cfg.Task
	if t == nil {
		return nil
	}
	hasRejection := t.PermanentRejection || len(t.PermanentlyRejectedVerifiers) > 0
	if !hasRejection {
		return nil
	}
	d := cfg.GracefulDegradation
	if d == nil {
		return fmt.Errorf("fixture_policy: permanent rejection requires explicitly commissioned graceful degradation (no graceful_degradation declared)")
	}
	if !d.Declared {
		return fmt.Errorf("fixture_policy: permanent rejection requires declared graceful degradation (declared=false)")
	}
	if !d.Commissioned {
		return fmt.Errorf("fixture_policy: permanent rejection requires explicitly commissioned graceful degradation (commissioned=false)")
	}
	if strings.TrimSpace(d.Objective) == "" {
		return fmt.Errorf("fixture_policy: permanent rejection requires a declared graceful-degradation objective")
	}
	return nil
}

func isEmptyEvidence(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case bool:
		return !t
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	case map[string]any:
		if raw, ok := t["value"]; ok && raw == nil {
			return true
		}
		return len(t) == 0
	case map[string]string:
		return len(t) == 0
	default:
		return false
	}
}

func validateFixProposal(f *fixProposal, path string) error {
	if f == nil {
		return nil
	}
	authority := strings.TrimSpace(f.RuleClassAuthority)
	if authority == "" {
		authority = strings.TrimSpace(f.Authority)
	}
	if authority == "" {
		return fmt.Errorf("fixture_policy: %s requires reviewed rule-class authority", path)
	}
	reviewed := f.Reviewed
	status := strings.ToLower(strings.TrimSpace(f.ReviewStatus))
	if status == "reviewed" || status == "approved" {
		reviewed = true
	}
	if !reviewed {
		return fmt.Errorf("fixture_policy: %s requires reviewed rule-class authority and supporting evidence (proposal is not reviewed)", path)
	}
	evidence := f.SupportingEvidence
	if isEmptyEvidence(evidence) {
		evidence = f.Evidence
	}
	if isEmptyEvidence(evidence) {
		return fmt.Errorf("fixture_policy: %s requires supporting evidence", path)
	}
	return nil
}

func distinctSubjects(lineages []any) ([]string, error) {
	var distinct []string
	seen := map[string]bool{}
	for i, entry := range lineages {
		var subject string
		switch v := entry.(type) {
		case string:
			s := strings.TrimSpace(v)
			if s == "" {
				return nil, fmt.Errorf("fixture_policy: curriculum subject_lineages[%d] is empty", i)
			}
			subject = s
			for _, sep := range []string{":", "/", "@", "#"} {
				if idx := strings.Index(subject, sep); idx > 0 {
					subject = strings.TrimSpace(subject[:idx])
					break
				}
			}
		case map[string]any:
			if raw, ok := v["value"]; ok && raw == nil {
				return nil, fmt.Errorf("fixture_policy: curriculum subject_lineages[%d] must identify a subject, not a Missing envelope", i)
			}
			if s, ok := v["subject"].(string); ok && strings.TrimSpace(s) != "" {
				subject = strings.TrimSpace(s)
			} else if s, ok := v["name"].(string); ok && strings.TrimSpace(s) != "" {
				subject = strings.TrimSpace(s)
			} else {
				raw, _ := json.Marshal(v)
				subject = string(raw)
			}
		default:
			raw, _ := json.Marshal(entry)
			subject = string(raw)
		}
		if strings.TrimSpace(subject) == "" {
			return nil, fmt.Errorf("fixture_policy: curriculum subject_lineages[%d] must identify a subject", i)
		}
		if !seen[subject] {
			seen[subject] = true
			distinct = append(distinct, subject)
		}
	}
	return distinct, nil
}

func checkCurriculum(manifest Manifest, cfg *effectiveConfig) error {
	c := cfg.Curriculum
	if c == nil {
		return nil
	}
	if c.MutatesActiveManifest || c.MutateActiveManifest || c.EditsManifestInPlace {
		return fmt.Errorf("fixture_policy: curriculum creates new manifests only; mutating the active manifest is rejected")
	}
	if !c.CreatesNewManifest && !c.NewManifest {
		return fmt.Errorf("fixture_policy: curriculum changes must create new subject-scoped manifests (creates_new_manifest=false)")
	}
	if c.SharesLineages || c.SharedLineage {
		return fmt.Errorf("fixture_policy: per-subject lineages must remain parallel and non-alternating; shared curriculum lineages are rejected")
	}
	if len(c.SubjectLineages) > 0 {
		distinct, err := distinctSubjects(c.SubjectLineages)
		if err != nil {
			return err
		}
		if len(distinct) > 1 {
			return fmt.Errorf("fixture_policy: per-subject lineages must remain parallel and non-alternating; curriculum spans multiple subjects %v", distinct)
		}
		if len(distinct) == 1 && strings.TrimSpace(manifest.Subject.Name) != "" && distinct[0] != strings.TrimSpace(manifest.Subject.Name) {
			return fmt.Errorf("fixture_policy: curriculum subject %q does not match manifest subject %q; subject version, assistance, context policy, and feature exposure remain attribution boundaries", distinct[0], manifest.Subject.Name)
		}
	}
	if c.AutoPatchSubject || c.AutoPatch || c.ActivatesExecutionFix || c.ActivatesFix {
		return fmt.Errorf("fixture_policy: no automatic subject patching is introduced; curriculum must not activate execution-layer fixes")
	}
	if err := validateFixProposal(c.OuterFixProposal, "curriculum.outer_fix_proposal"); err != nil {
		return err
	}
	if err := validateFixProposal(c.FixProposal, "curriculum.fix_proposal"); err != nil {
		return err
	}
	outer := c.OuterFixProposal
	if outer == nil {
		outer = c.FixProposal
	}
	if c.InnerVariantProposal != nil && outer != nil {
		if fixCoreEqual(c.InnerVariantProposal, outer) {
			return fmt.Errorf("fixture_policy: inner variant proposals and outer reviewed fix proposals are separate features")
		}
	}
	return nil
}

// fixCoreEqual reports whether an inner variant proposal duplicates the core
// of an outer reviewed fix proposal. Inner variants (for example
// {"variant":"layout-b"}) carry no fix identity and are always separate;
// an inner proposal that carries the same rule-class authority, review
// state, and supporting evidence as the outer fix is not a separate
// feature.
func fixCoreEqual(inner any, outer *fixProposal) bool {
	if outer == nil {
		return false
	}
	innerMap, ok := inner.(map[string]any)
	if !ok {
		raw, err := json.Marshal(inner)
		if err != nil {
			return false
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			outerRaw, _ := json.Marshal(outer)
			return string(raw) == string(outerRaw)
		}
		innerMap = decoded
	}
	_, hasAuthority := innerMap["rule_class_authority"]
	_, hasAuthorityAlias := innerMap["authority"]
	_, hasReviewed := innerMap["reviewed"]
	_, hasReviewStatus := innerMap["review_status"]
	_, hasEvidence := innerMap["supporting_evidence"]
	_, hasEvidenceAlias := innerMap["evidence"]
	if !hasAuthority && !hasAuthorityAlias && !hasReviewed && !hasReviewStatus && !hasEvidence && !hasEvidenceAlias {
		return false
	}
	innerAuthority := firstNonEmptyString(innerMap, "rule_class_authority", "authority")
	outerAuthority := strings.TrimSpace(outer.RuleClassAuthority)
	if outerAuthority == "" {
		outerAuthority = strings.TrimSpace(outer.Authority)
	}
	if innerAuthority != outerAuthority {
		return false
	}
	innerReviewed := fixReviewed(innerMap["reviewed"], innerMap["review_status"])
	outerReviewed := outer.Reviewed
	status := strings.ToLower(strings.TrimSpace(outer.ReviewStatus))
	if status == "reviewed" || status == "approved" {
		outerReviewed = true
	}
	if innerReviewed != outerReviewed {
		return false
	}
	innerEvidence := innerMap["supporting_evidence"]
	if isEmptyEvidence(innerEvidence) {
		innerEvidence = innerMap["evidence"]
	}
	outerEvidence := outer.SupportingEvidence
	if isEmptyEvidence(outerEvidence) {
		outerEvidence = outer.Evidence
	}
	innerRaw, _ := json.Marshal(innerEvidence)
	outerRaw, _ := json.Marshal(outerEvidence)
	return string(innerRaw) == string(outerRaw)
}

func firstNonEmptyString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func fixReviewed(reviewedAny any, statusAny any) bool {
	if b, ok := reviewedAny.(bool); ok && b {
		return true
	}
	if s, ok := statusAny.(string); ok {
		lower := strings.ToLower(strings.TrimSpace(s))
		return lower == "reviewed" || lower == "approved"
	}
	return false
}
