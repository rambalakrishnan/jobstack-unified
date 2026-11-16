package fixture_policy

import (
	"encoding/json"
	"strings"
	"testing"
)

const testDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func validTestManifest() Manifest {
	return Manifest{
		RecordType:     "manifest",
		SchemaVersion:  "1.0.0",
		ManifestID:     "m1",
		RunID:          "r1",
		JournalID:      "j1",
		OwnerDomain:    "laboratory",
		CommissionerID: "commissioner-1",
		Activity:       "application_attempt",
		Attempt: AttemptContext{
			Kind:           "practice",
			Context:        "laboratory_fixture",
			Scope:          "held_in",
			SubjectVersion: "subject-1.0",
			Assistance:     "none",
		},
		Execution:       map[string]any{"mode": "manual"},
		Task:            map[string]any{"task_id": "task-1"},
		TaskSemanticHash: testDigestA,
		Environment:     map[string]any{"deployment": "laboratory"},
		Seed:            "seed-1",
		BuildPins:       map[string]string{"fixture": "1.0.0"},
		EventRegistry:   map[string]string{"kind1": "v1"},
		Producers:       []map[string]any{{"producer_id": "p1"}},
		Clocks:          []map[string]any{{"clock_id": "c1"}},
		Profile:         "M1",
		Subject:         SubjectDescriptor{Name: "subject-A", Version: "subject-1.0"},
		Lineage:         LineageLinks{Kind: "practice"},
	}
}

func validTestConfig(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{
		"profile": "M1",
		"features": []any{
			map[string]any{"name": "cooperative-form", "recipe": "primitive:cooperative-form/1.0"},
		},
		"task": map[string]any{
			"kind":                             "completion",
			"required_controls":                []any{"contact-name"},
			"hidden_controls":                  []any{},
			"human_path":                       true,
			"required_verifiers":               []any{"v1"},
			"permanently_rejected_verifiers":   []any{},
			"requires_recovery":                false,
			"recovery_paths":                   []any{"retry"},
			"required_browser_capabilities":    []any{},
			"available_browser_capabilities":   []any{"dom"},
		},
		"budgets": map[string]any{
			"task_ms":           60000.0,
			"required_ms":       5000.0,
			"artificial_delay_ms": 100.0,
		},
	}
}

func encodeConfig(t *testing.T, cfg map[string]any) []byte {
	t.Helper()
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("cannot encode config: %v", err)
	}
	return out
}

func mustPass(t *testing.T, m Manifest, cfg []byte, label string) {
	t.Helper()
	if err := ValidateFixture(m, cfg); err != nil {
		t.Fatalf("%s: expected pass, got error: %v", label, err)
	}
}

func mustFail(t *testing.T, m Manifest, cfg []byte, label string, wantSubstr ...string) {
	t.Helper()
	err := ValidateFixture(m, cfg)
	if err == nil {
		t.Fatalf("%s: expected rejection, got pass", label)
	}
	msg := strings.ToLower(err.Error())
	for _, want := range wantSubstr {
		if !strings.Contains(msg, strings.ToLower(want)) {
			t.Fatalf("%s: error %q does not mention %q", label, err.Error(), want)
		}
	}
}

func setFeatureFlag(cfg map[string]any, flag string, value any) {
	features := cfg["features"].([]any)
	f := features[0].(map[string]any)
	f[flag] = value
}

func taskOf(cfg map[string]any) map[string]any {
	return cfg["task"].(map[string]any)
}

func budgetsOf(cfg map[string]any) map[string]any {
	return cfg["budgets"].(map[string]any)
}

func TestM1ConfigurationRejectsDeliberateHostileTreatments(t *testing.T) {
	m := validTestManifest()
	mustPass(t, m, encodeConfig(t, validTestConfig(t)), "cooperative M1 passes")

	// Zero-feature M1 also passes (zero hostile admitted, vacuously).
	empty := validTestConfig(t)
	empty["features"] = []any{}
	mustPass(t, m, encodeConfig(t, empty), "featureless M1 passes")

	hostileFlags := []string{
		"frame_challenge", "root_challenge", "class_churn", "decoys",
		"delayed_hydration", "idle_trap", "transport_failure_injected",
		"injected_transport_failure", "production_challenge_service",
		"artificial_timing_race", "shadow_dom_controls", "unstable_layout",
		"non_native_controls", "non_ordinary_labels",
		"abnormal_validation", "abnormal_upload", "abnormal_identity",
		"abnormal_state_transition", "abnormal_submission",
	}
	for _, flag := range hostileFlags {
		cfg := validTestConfig(t)
		setFeatureFlag(cfg, flag, true)
		mustFail(t, m, encodeConfig(t, cfg), "M1 hostile flag "+flag, "M1", "hostile")
	}
	cfg := validTestConfig(t)
	setFeatureFlag(cfg, "hostile", true)
	mustFail(t, m, encodeConfig(t, cfg), "M1 explicit hostile marker", "M1", "hostile")

	cfg = validTestConfig(t)
	cfg["frame_challenge"] = true
	mustFail(t, m, encodeConfig(t, cfg), "M1 top-level hostile treatment", "M1", "hostile")

	cfg = validTestConfig(t)
	cfg["readiness"] = "network_silence"
	mustFail(t, m, encodeConfig(t, cfg), "network silence is not readiness", "readiness", "network silence")

	cfg = validTestConfig(t)
	cfg["autosave_displaces_reducer"] = true
	mustFail(t, m, encodeConfig(t, cfg), "autosave cannot displace reducer", "reducer")

	cfg = validTestConfig(t)
	cfg["websocket_displaces_reducer"] = true
	mustFail(t, m, encodeConfig(t, cfg), "websocket cannot displace reducer", "reducer")

	// Attempt scope boundary: only practice / laboratory_fixture / held_in.
	for _, tc := range []struct {
		name   string
		mutate func(*Manifest)
		want   string
	}{
		{"production kind", func(mm *Manifest) { mm.Attempt.Kind = "production" }, "practice"},
		{"employer context", func(mm *Manifest) { mm.Attempt.Context = "employer_origin" }, "laboratory_fixture"},
		{"held-out scope", func(mm *Manifest) { mm.Attempt.Scope = "held_out" }, "held_in"},
		{"missing scope", func(mm *Manifest) { mm.Attempt = AttemptContext{} }, "kind, context, and scope"},
	} {
		mm := validTestManifest()
		tc.mutate(&mm)
		mustFail(t, mm, encodeConfig(t, validTestConfig(t)), tc.name, tc.want)
	}

	// Lineage: kind immutable, acyclic, direction-checked.
	mm := validTestManifest()
	mm.Lineage.Kind = "production"
	mustFail(t, mm, encodeConfig(t, validTestConfig(t)), "kind immutable", "immutable")

	mm = validTestManifest()
	mm.Lineage.DerivedFrom = []string{"m1"}
	mustFail(t, mm, encodeConfig(t, validTestConfig(t)), "derived_from acyclic", "acyclic")

	mm = validTestManifest()
	mm.Lineage.PerformanceOf = "m0"
	mustFail(t, mm, encodeConfig(t, validTestConfig(t)), "practice must not declare performance_of", "performance_of")

	// Manifest identity gates.
	mm = validTestManifest()
	mm.ManifestID = ""
	mustFail(t, mm, encodeConfig(t, validTestConfig(t)), "missing manifest_id", "manifest_id")

	mm = validTestManifest()
	mm.TaskSemanticHash = "not-a-digest"
	mustFail(t, mm, encodeConfig(t, validTestConfig(t)), "bad semantic hash", "sha256")

	// Structural gates via evidence_codec: duplicate keys and bare nulls.
	dup := []byte(`{"profile":"M1","profile":"M1","features":[],"task":{"kind":"completion"}}`)
	mustFail(t, m, dup, "duplicate keys rejected", "duplicate")

	bareNull := []byte(`{"profile":"M1","features":[],"task":{"kind":"completion","human_path":null}}`)
	mustFail(t, m, bareNull, "bare null rejected", "null")

	notObject := []byte(`[]`)
	mustFail(t, m, notObject, "configuration must be object", "object")

	mustFail(t, m, []byte(`   `), "missing configuration", "missing")

	// Later hostile packs are not an M1 prerequisite: M1 needs no full
	// feature-pack contract, but a later hostile pack with a full contract
	// is structurally admissible outside M1.
	later := validTestConfig(t)
	later["profile"] = "M3"
	mm = validTestManifest()
	mm.Profile = "M3"
	features := later["features"].([]any)
	features[0] = map[string]any{
		"name": "hostile-churn", "hostile": true,
		"class_churn": true,
		"recipe":      "primitive:class-churn/1.0",
		"parameters":  map[string]any{"rate": 3.0},
		"parameter_domains": map[string]any{"rate": "int[1,10]"},
		"dependencies":      []any{}, "exclusions": []any{},
		"human_completion_contract": "operator can disable churn",
		"exposure_event_kinds":       []any{"churn_exposed"},
		"activation_event_kinds":     []any{"churn_activated"},
		"expected_failure_signatures": []any{"selector-flake"},
		"regression_cases":            []any{"churn-baseline"},
		"asset_digests":               map[string]any{"pack": testDigestA},
		"schema_digests":              map[string]any{"task": testDigestB},
	}
	mustPass(t, mm, encodeConfig(t, later), "later hostile pack with full contract passes")

	// Same later pack without its contract is rejected.
	laterBare := validTestConfig(t)
	laterBare["profile"] = "M3"
	featuresB := laterBare["features"].([]any)
	featuresB[0] = map[string]any{"name": "hostile-churn", "hostile": true, "class_churn": true, "recipe": "primitive:class-churn/1.0"}
	mustFail(t, mm, encodeConfig(t, laterBare), "later hostile pack needs contract", "must pin")
}

func TestCompletionTasksWithoutHumanPathsAreRejected(t *testing.T) {
	m := validTestManifest()
	mustPass(t, m, encodeConfig(t, validTestConfig(t)), "baseline completion passes")

	cfg := validTestConfig(t)
	tk := taskOf(cfg)
	tk["hidden_controls"] = []any{"contact-name"}
	tk["human_path"] = false
	mustFail(t, m, encodeConfig(t, cfg), "hidden required without human path", "human path")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["hidden_controls"] = []any{"contact-name"}
	delete(tk, "human_path")
	mustFail(t, m, encodeConfig(t, cfg), "hidden required with omitted human path", "human path")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["hidden_controls"] = []any{"contact-name"}
	tk["human_path"] = ""
	mustFail(t, m, encodeConfig(t, cfg), "hidden required with empty human path", "human path")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["hidden_controls"] = []any{"contact-name"}
	tk["human_path"] = "open the details disclosure to reveal the field"
	mustPass(t, m, encodeConfig(t, cfg), "hidden required with documented human path passes")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["hidden_controls"] = []any{"optional-decoration"}
	tk["human_path"] = false
	mustPass(t, m, encodeConfig(t, cfg), "hidden non-required control without path passes")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["requires_observational_mock"] = true
	mustFail(t, m, encodeConfig(t, cfg), "observational mock rejected", "observational mock")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["requires_mock"] = true
	mustFail(t, m, encodeConfig(t, cfg), "mock alias rejected", "mock")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["kind"] = "diagnostic"
	tk["hidden_controls"] = []any{"contact-name"}
	tk["human_path"] = false
	mustPass(t, m, encodeConfig(t, cfg), "non-completion task skips completion rules")
}

func TestImpossibleCompletionBudgetsAndRecoveryContractsAreRejected(t *testing.T) {
	m := validTestManifest()
	mustPass(t, m, encodeConfig(t, validTestConfig(t)), "baseline budgets pass")

	cfg := validTestConfig(t)
	b := budgetsOf(cfg)
	b["task_ms"] = 1000.0
	b["required_ms"] = 5000.0
	mustFail(t, m, encodeConfig(t, cfg), "exceeds budget by construction", "budget")

	cfg = validTestConfig(t)
	b = budgetsOf(cfg)
	b["task_ms"] = -5.0
	mustFail(t, m, encodeConfig(t, cfg), "negative budget rejected", "budget")

	cfg = validTestConfig(t)
	b = budgetsOf(cfg)
	b["artificial_delay_ms"] = 6000.0
	mustFail(t, m, encodeConfig(t, cfg), "long delay without soak rejected", "soak")

	cfg = validTestConfig(t)
	b = budgetsOf(cfg)
	b["artificial_delay_ms"] = 6000.0
	b["soak_profile_declared"] = true
	mustPass(t, m, encodeConfig(t, cfg), "long delay with declared soak passes")

	cfg = validTestConfig(t)
	b = budgetsOf(cfg)
	b["artificial_delay_ms"] = 6000.0
	b["soak_profile"] = "soak-1"
	mustPass(t, m, encodeConfig(t, cfg), "long delay with named soak passes")

	cfg = validTestConfig(t)
	b = budgetsOf(cfg)
	b["artificial_delay_ms"] = 5000.0
	mustPass(t, m, encodeConfig(t, cfg), "5000ms boundary passes without soak")

	cfg = validTestConfig(t)
	tk := taskOf(cfg)
	tk["requires_recovery"] = true
	tk["recovery_paths"] = []any{}
	mustFail(t, m, encodeConfig(t, cfg), "recovery required but no paths", "recovery")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["requires_recovery"] = true
	tk["recovery_removed"] = true
	tk["recovery_paths"] = []any{"retry"}
	mustFail(t, m, encodeConfig(t, cfg), "recovery removed while required", "recovery")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["requires_recovery"] = true
	tk["recovery_paths"] = []any{"retry", "restore-draft"}
	mustPass(t, m, encodeConfig(t, cfg), "declared recovery passes")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["required_browser_capabilities"] = []any{"weird-capability"}
	tk["available_browser_capabilities"] = []any{"dom"}
	mustFail(t, m, encodeConfig(t, cfg), "unavailable browser capability", "browser")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["required_browser_capabilities"] = []any{"dom"}
	tk["available_browser_capabilities"] = []any{"dom", "fetch"}
	mustPass(t, m, encodeConfig(t, cfg), "available browser capability passes")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["required_browser_capabilities"] = []any{"fetch"}
	tk["available_browser_capabilities"] = []any{}
	cfg["browser"] = map[string]any{"capabilities": []any{"fetch"}}
	mustPass(t, m, encodeConfig(t, cfg), "top-level browser capabilities satisfy requirement")
}

func TestPermanentRejectionRequiresDeclaredGracefulDegradation(t *testing.T) {
	m := validTestManifest()
	mustPass(t, m, encodeConfig(t, validTestConfig(t)), "no rejection needs no degradation")

	cfg := validTestConfig(t)
	tk := taskOf(cfg)
	tk["permanent_rejection"] = true
	mustFail(t, m, encodeConfig(t, cfg), "flag rejection without degradation", "graceful")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["permanently_rejected_verifiers"] = []any{"v1"}
	mustFail(t, m, encodeConfig(t, cfg), "list rejection without degradation", "graceful")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["required_verifiers"] = []any{"v1", "v2"}
	tk["permanently_rejected_verifiers"] = []any{"v1"}
	mustFail(t, m, encodeConfig(t, cfg), "partial permanent rejection without degradation", "graceful")

	degraded := func(declared, commissioned bool, objective string) map[string]any {
		cfg := validTestConfig(t)
		tk := taskOf(cfg)
		tk["permanently_rejected_verifiers"] = []any{"v1"}
		cfg["graceful_degradation"] = map[string]any{
			"declared":     declared,
			"commissioned": commissioned,
			"objective":    objective,
		}
		return cfg
	}
	mustFail(t, m, encodeConfig(t, degraded(false, true, "degraded-submit")), "undeclared degradation", "declared")
	mustFail(t, m, encodeConfig(t, degraded(true, false, "degraded-submit")), "uncommissioned degradation", "commissioned")
	mustFail(t, m, encodeConfig(t, degraded(true, true, "")), "missing objective", "objective")
	mustPass(t, m, encodeConfig(t, degraded(true, true, "degraded-submit")), "commissioned degradation passes")

	cfg = validTestConfig(t)
	tk = taskOf(cfg)
	tk["permanent_rejection"] = true
	cfg["graceful_degradation"] = map[string]any{
		"declared": true, "commissioned": true, "objective": "read-only-review",
	}
	mustPass(t, m, encodeConfig(t, cfg), "flag rejection with degradation passes")
}

func TestFeatureRecipesCannotContainExecutableCode(t *testing.T) {
	m := validTestManifest()
	mustPass(t, m, encodeConfig(t, validTestConfig(t)), "registered recipe passes")

	for _, name := range []string{
		"primitive:cooperative-form/1.0", "label-stable",
		"namespace:feature@1.2", "a:b/c.d-e_f+g",
	} {
		cfg := validTestConfig(t)
		setFeatureFlag(cfg, "recipe", name)
		mustPass(t, m, encodeConfig(t, cfg), "registered name "+name)
	}

	codeRecipes := []string{
		"function evil() { steal(); }",
		"eval(alert(1))",
		"primitive:good(); drop",
		"<script>alert(1)</script>",
		"import evil from 'x'",
		"require('evil')",
		"window.location = evil",
		"document.cookie",
		"a => b",
		"recipe with spaces",
		"primitive:bad[0]",
		"primitive:bad;evil",
	}
	for _, recipe := range codeRecipes {
		cfg := validTestConfig(t)
		setFeatureFlag(cfg, "recipe", recipe)
		mustFail(t, m, encodeConfig(t, cfg), "code recipe "+recipe, "registered", "recipe")
	}

	cfg := validTestConfig(t)
	setFeatureFlag(cfg, "recipe_body", "function inline() {}")
	mustFail(t, m, encodeConfig(t, cfg), "inline recipe body", "recipe")

	cfg = validTestConfig(t)
	setFeatureFlag(cfg, "javascript", "alert(1)")
	mustFail(t, m, encodeConfig(t, cfg), "feature javascript", "javascript")

	cfg = validTestConfig(t)
	cfg["javascript"] = "alert(1)"
	mustFail(t, m, encodeConfig(t, cfg), "top-level javascript", "javascript")

	cfg = validTestConfig(t)
	setFeatureFlag(cfg, "script", "alert(1)")
	mustFail(t, m, encodeConfig(t, cfg), "feature script", "javascript")

	for _, flag := range []string{"runtime_eval", "eval", "native_plugin_loading"} {
		cfg := validTestConfig(t)
		setFeatureFlag(cfg, flag, true)
		mustFail(t, m, encodeConfig(t, cfg), "feature "+flag, "eval", "admitted")
	}
	// native_plugin_loading mentions plugin, not eval; check separately.
	cfg = validTestConfig(t)
	setFeatureFlag(cfg, "native_plugin_loading", true)
	if err := ValidateFixture(m, encodeConfig(t, cfg)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "plugin") {
		t.Fatalf("native plugin loading: expected plugin rejection, got %v", err)
	}

	cfg = validTestConfig(t)
	setFeatureFlag(cfg, "downloaded_code_url", "https://example.com/evil.js")
	mustFail(t, m, encodeConfig(t, cfg), "downloaded code", "downloaded")

	cfg = validTestConfig(t)
	setFeatureFlag(cfg, "downloaded_executable", "evil.wasm")
	mustFail(t, m, encodeConfig(t, cfg), "downloaded executable", "downloaded")

	cfg = validTestConfig(t)
	setFeatureFlag(cfg, "native_plugin", "evil.so")
	mustFail(t, m, encodeConfig(t, cfg), "native plugin", "plugin")

	// Nested executable smuggled inside parameters is still rejected.
	cfg = validTestConfig(t)
	features := cfg["features"].([]any)
	f := features[0].(map[string]any)
	f["parameters"] = map[string]any{"javascript": "alert(1)"}
	mustFail(t, m, encodeConfig(t, cfg), "nested javascript", "javascript")
}

func TestCurriculumChangesCreateNewSubjectScopedManifests(t *testing.T) {
	m := validTestManifest()
	mustPass(t, m, encodeConfig(t, validTestConfig(t)), "no curriculum passes")

	validCurriculum := func() map[string]any {
		cfg := validTestConfig(t)
		cfg["curriculum"] = map[string]any{
			"creates_new_manifest": true,
			"subject_lineages":     []any{"subject-A:1.0"},
		}
		return cfg
	}
	mustPass(t, m, encodeConfig(t, validCurriculum()), "new subject-scoped manifest passes")

	cfg := validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{map[string]any{"subject": "subject-A", "version": "1.0"}},
	}
	mustPass(t, m, encodeConfig(t, cfg), "object lineage passes")

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{"subject-A:1.0"},
		"outer_fix_proposal": map[string]any{
			"rule_class_authority": "rules-board",
			"reviewed":             true,
			"supporting_evidence":  []any{"evidence-1"},
		},
		"inner_variant_proposal": map[string]any{"variant": "layout-b"},
	}
	mustPass(t, m, encodeConfig(t, cfg), "reviewed fix with separate variant passes")

	cfg = validCurriculum()
	cfg["curriculum"].(map[string]any)["mutates_active_manifest"] = true
	mustFail(t, m, encodeConfig(t, cfg), "mutating active manifest", "new manifests only")

	cfg = validCurriculum()
	cfg["curriculum"].(map[string]any)["edits_manifest_in_place"] = true
	mustFail(t, m, encodeConfig(t, cfg), "in-place edit", "new manifests only")

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": false,
		"subject_lineages":     []any{"subject-A:1.0"},
	}
	mustFail(t, m, encodeConfig(t, cfg), "curriculum without new manifest", "new subject-scoped manifests")

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{"subject_lineages": []any{"subject-A:1.0"}}
	mustFail(t, m, encodeConfig(t, cfg), "curriculum missing new-manifest flag", "new subject-scoped manifests")

	cfg = validCurriculum()
	cfg["curriculum"].(map[string]any)["shares_lineages"] = true
	mustFail(t, m, encodeConfig(t, cfg), "shared lineages", "parallel")

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{"subject-A:1.0", "subject-B:1.0"},
	}
	mustFail(t, m, encodeConfig(t, cfg), "multi-subject lineage", "parallel")

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{"subject-B:1.0"},
	}
	mustFail(t, m, encodeConfig(t, cfg), "subject mismatch", "attribution boundaries")

	for _, flag := range []string{"auto_patch_subject", "auto_patch", "activates_execution_fix", "activates_fix"} {
		cfg = validCurriculum()
		cfg["curriculum"].(map[string]any)[flag] = true
		mustFail(t, m, encodeConfig(t, cfg), "curriculum "+flag, "automatic", "patch")
	}

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{"subject-A:1.0"},
		"outer_fix_proposal": map[string]any{
			"reviewed": true, "supporting_evidence": []any{"e1"},
		},
	}
	mustFail(t, m, encodeConfig(t, cfg), "fix without authority", "authority")

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{"subject-A:1.0"},
		"outer_fix_proposal": map[string]any{
			"rule_class_authority": "rules-board",
			"reviewed":             false,
			"supporting_evidence":  []any{"e1"},
		},
	}
	mustFail(t, m, encodeConfig(t, cfg), "unreviewed fix", "reviewed")

	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{"subject-A:1.0"},
		"outer_fix_proposal": map[string]any{
			"rule_class_authority": "rules-board",
			"reviewed":             true,
		},
	}
	mustFail(t, m, encodeConfig(t, cfg), "fix without evidence", "evidence")

	same := map[string]any{"rule_class_authority": "rules-board", "reviewed": true, "supporting_evidence": []any{"e1"}}
	cfg = validTestConfig(t)
	cfg["curriculum"] = map[string]any{
		"creates_new_manifest": true,
		"subject_lineages":     []any{"subject-A:1.0"},
		"inner_variant_proposal": same,
		"outer_fix_proposal":     same,
	}
	mustFail(t, m, encodeConfig(t, cfg), "inner and outer must differ", "separate")
}
