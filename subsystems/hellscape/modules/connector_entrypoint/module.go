// Package connector_entrypoint wires the reference external connector as an
// independently shipped authority outside the three laboratory databases.
//
// Seam references: seam-mappings/hellscape-seam-mapping.md sections 4.3
// (connector persistence boundary) and 16.8 (silo acceptance), plus
// contracts/02-external-connector.yaml invariants EXT-*.
//
// Semantic boundaries enforced here:
//
//   - The connector owns preparation, handle allocation, dispatch intent,
//     native transports, and native-message persistence. Hellscape invokes it
//     through EXT and stores verified imported copies.
//   - The reference binding and synthetic implementation ship with the source
//     distribution, but their authoritative execution service is never merged
//     into the laboratory engine process or its application/analyzer
//     authority. All wiring in this package stays private; there is no
//     exported entrypoint.
//   - Connector storage is a fourth owner boundary (connector.db plus a
//     connector-owned artifact root) outside application.db, observation.db,
//     and diagnostic.db. No attach, shared transaction, or shared writer
//     spans those boundaries.
//   - Silo acceptance needs no live circus-tent, Ringmaster, crawler,
//     orchestrator, dashboard, Firebase service, or production origin. The
//     default native transport is an in-memory synthetic backend that never
//     dials the network.
//
// An in-process synthetic test validates wire behavior. It cannot prove
// process or I/O isolation merely by separating tables; the failure test in
// this module therefore kills a real OS process holding the connector store.
package connector_entrypoint

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	reference_connector "reference_connector"
	owner_store "owner_store"
)

// ---------------------------------------------------------------------------
// Laboratory allocation (seam 4.1 names; connector storage must differ).
// ---------------------------------------------------------------------------

// laboratoryDatabaseNames returns exactly the three laboratory database file
// names. The connector authority must never write to any of them.
func laboratoryDatabaseNames() [3]string {
	return [3]string{"application.db", "observation.db", "diagnostic.db"}
}

// connectorDatabaseName is the connector-owned database file name. It lives
// beside the laboratory databases but is never one of them.
func connectorDatabaseName() string {
	return "connector.db"
}

// isLaboratoryDatabaseName reports whether base names a laboratory database.
func isLaboratoryDatabaseName(base string) bool {
	for _, name := range laboratoryDatabaseNames() {
		if base == name {
			return true
		}
	}
	return false
}

// laboratory is three independent owner stores, one per laboratory database.
type laboratory struct {
	root string

	applicationPath   string
	observationPath   string
	diagnosticPath    string
	applicationArt    string
	observationArt    string
	diagnosticArt     string
	application       *owner_store.OwnerStore
	observation       *owner_store.OwnerStore
	diagnostic        *owner_store.OwnerStore
}

// openLaboratory opens exactly the three laboratory databases under root, each
// with its own connection, artifact root, and owner domain.
func openLaboratory(root string) (*laboratory, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("connector_entrypoint: laboratory root is required")
	}
	names := laboratoryDatabaseNames()
	domains := [3]string{"application", "observation", "diagnostic"}
	paths := [3]string{
		filepath.Join(root, names[0]),
		filepath.Join(root, names[1]),
		filepath.Join(root, names[2]),
	}
	arts := [3]string{
		filepath.Join(root, "artifacts", domains[0]),
		filepath.Join(root, "artifacts", domains[1]),
		filepath.Join(root, "artifacts", domains[2]),
	}
	stores := [3]*owner_store.OwnerStore{}
	for i := range 3 {
		store, err := owner_store.OpenOwner(paths[i], arts[i], domains[i])
		if err != nil {
			for j := range i {
				_ = stores[j].Close()
			}
			return nil, fmt.Errorf("connector_entrypoint: open laboratory %s: %w", names[i], err)
		}
		stores[i] = store
	}
	return &laboratory{
		root:            root,
		applicationPath: paths[0], observationPath: paths[1], diagnosticPath: paths[2],
		applicationArt: arts[0], observationArt: arts[1], diagnosticArt: arts[2],
		application: stores[0], observation: stores[1], diagnostic: stores[2],
	}, nil
}

// close releases the three laboratory stores.
func (l *laboratory) close() error {
	if l == nil {
		return nil
	}
	var errs []error
	for _, s := range []*owner_store.OwnerStore{l.application, l.observation, l.diagnostic} {
		if s != nil {
			if err := s.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// databasePaths returns the three laboratory database paths.
func (l *laboratory) databasePaths() [3]string {
	return [3]string{l.applicationPath, l.observationPath, l.diagnosticPath}
}

// artifactRoots returns the three laboratory artifact roots.
func (l *laboratory) artifactRoots() [3]string {
	return [3]string{l.applicationArt, l.observationArt, l.diagnosticArt}
}

// ---------------------------------------------------------------------------
// Connector endpoint (seam 4.3): fourth owner boundary, never merged.
// ---------------------------------------------------------------------------

// connectorEndpoint is one wired reference connector: its own OwnerStore plus
// the EXT handler bound to that store. It is never launched inside the
// laboratory engine process as an authoritative service.
type connectorEndpoint struct {
	root         string
	storePath    string
	artifactRoot string
	store        *owner_store.OwnerStore
	handler      http.Handler
	descriptor   reference_connector.ConnectorDescriptor
}

// checkStorageOutsideLaboratory rejects any connector path that collides with
// the three laboratory databases or their artifact roots.
func checkStorageOutsideLaboratory(connectorPath, connectorArtifacts string, lab *laboratory) error {
	base := filepath.Base(connectorPath)
	if isLaboratoryDatabaseName(base) {
		return fmt.Errorf("connector_entrypoint: connector database name %q is a laboratory database; storage must be outside the three laboratory databases", base)
	}
	if strings.TrimSpace(connectorPath) == "" || strings.TrimSpace(connectorArtifacts) == "" {
		return fmt.Errorf("connector_entrypoint: connector storage paths are required")
	}
	absConn, err := filepath.Abs(connectorPath)
	if err != nil {
		return fmt.Errorf("connector_entrypoint: resolve connector path: %v", err)
	}
	absConnArt, err := filepath.Abs(connectorArtifacts)
	if err != nil {
		return fmt.Errorf("connector_entrypoint: resolve connector artifact root: %v", err)
	}
	if lab == nil {
		return nil
	}
	for _, labPath := range lab.databasePaths() {
		absLab, err := filepath.Abs(labPath)
		if err != nil {
			continue
		}
		if absConn == absLab {
			return fmt.Errorf("connector_entrypoint: connector storage %q collides with laboratory database %q", connectorPath, labPath)
		}
	}
	for _, labArt := range lab.artifactRoots() {
		absLabArt, err := filepath.Abs(labArt)
		if err != nil {
			continue
		}
		if absConnArt == absLabArt {
			return fmt.Errorf("connector_entrypoint: connector artifact root %q collides with laboratory artifact root %q", connectorArtifacts, labArt)
		}
	}
	return nil
}

// openConnector wires the reference connector against its own owner boundary.
// The store is connector.db with owner domain "connector"; its artifact root
// is a sibling of the laboratory roots, never one of them. A nil native
// transport selects the synthetic backend so silo acceptance never requires
// a live circus-tent or Ringmaster deployment.
func openConnector(root string, lab *laboratory, descriptor reference_connector.ConnectorDescriptor, native http.RoundTripper) (*connectorEndpoint, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("connector_entrypoint: connector root is required")
	}
	storePath := filepath.Join(root, connectorDatabaseName())
	artifactRoot := filepath.Join(root, "artifacts", "connector")
	if err := checkStorageOutsideLaboratory(storePath, artifactRoot, lab); err != nil {
		return nil, err
	}
	if native == nil {
		native = newSyntheticBackend()
	}
	store, err := owner_store.OpenOwner(storePath, artifactRoot, "connector")
	if err != nil {
		return nil, fmt.Errorf("connector_entrypoint: open connector store: %w", err)
	}
	handler, err := reference_connector.NewReferenceConnector(store, descriptor, native)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("connector_entrypoint: wire reference connector: %w", err)
	}
	return &connectorEndpoint{
		root: root, storePath: storePath, artifactRoot: artifactRoot,
		store: store, handler: handler, descriptor: descriptor,
	}, nil
}

// close releases the connector-owned store. The laboratory stores are never
// touched here.
func (c *connectorEndpoint) close() error {
	if c == nil || c.store == nil {
		return nil
	}
	return c.store.Close()
}

// ---------------------------------------------------------------------------
// Synthetic native backend: loopback only, never a live deployment.
// ---------------------------------------------------------------------------

// syntheticCall logs one native RoundTrip invocation.
type syntheticCall struct {
	method string
	url    string
	body   []byte
	at     time.Time
}

// syntheticBackend is an in-memory http.RoundTripper for silo acceptance. It
// records every invocation and answers from canned bytes without dialing any
// network. A nil handler returns terminal success.
type syntheticBackend struct {
	mu      sync.Mutex
	calls   []syntheticCall
	handler func(*http.Request) (*http.Response, error)
}

// newSyntheticBackend builds the loopback-only native transport.
func newSyntheticBackend() *syntheticBackend {
	return &syntheticBackend{}
}

// RoundTrip implements http.RoundTripper without any network I/O.
func (s *syntheticBackend) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	s.mu.Lock()
	s.calls = append(s.calls, syntheticCall{method: r.Method, url: r.URL.String(), body: append([]byte(nil), body...), at: time.Now()})
	h := s.handler
	s.mu.Unlock()
	if h != nil {
		return h(r)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"state":"completed","native_run_id":"synthetic-run-1","native_message_id":"synthetic-msg-1","timing":{"duration_ms":10}}`)),
	}, nil
}

// callCount returns the number of recorded native invocations.
func (s *syntheticBackend) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// urls returns the recorded native URLs in invocation order.
func (s *syntheticBackend) urls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	for i := range s.calls {
		out[i] = s.calls[i].url
	}
	return out
}

// ---------------------------------------------------------------------------
// Reference descriptor for silo acceptance.
// ---------------------------------------------------------------------------

const (
	digestBuild   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestBinding = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestSubject = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	digestMapping = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	digestBudget  = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	digestNative  = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// missingEnvelope returns a typed Missing envelope (never a bare null).
func missingEnvelope(reason string) map[string]any {
	return map[string]any{"value": nil, "reason": reason}
}

// defaultDescriptor returns a valid nine-verb reference descriptor for silo
// acceptance. All digests are well-formed sha256 identities; the mapping pin
// is accepted by the native-mapping serializer.
func defaultDescriptor() reference_connector.ConnectorDescriptor {
	capIDs := []string{
		"native_goal_task",
		"native_plan_execution",
		"native_cancel",
		"native_context_release",
		"native_artifact_retrieval",
		"native_revision",
		"native_dom_access",
		"browser_state_isolation",
		"browser_state_persistence",
		"learning_state_control",
	}
	caps := make([]reference_connector.Capability, 0, len(capIDs))
	for _, id := range capIDs {
		caps = append(caps, reference_connector.Capability{
			ID: id, Availability: "available",
			EvidenceRefs: []reference_connector.EvidenceRef{},
			Limitations:  []string{},
		})
	}
	ops := []reference_connector.OperationMapping{
		{Operation: reference_connector.OpDescribe, Implementation: "connector-local", NativeContract: missingEnvelope("not_applicable"), CapabilityRefs: []string{}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}},
		{Operation: reference_connector.OpPrepare, Implementation: "connector-local", NativeContract: missingEnvelope("not_applicable"), CapabilityRefs: []string{}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}},
		{Operation: reference_connector.OpStart, Implementation: "native-mapping", NativeContract: reference_connector.VersionPin{ID: "native-start", Version: "v1", ArtifactDigest: digestNative}, CapabilityRefs: []string{"native_goal_task"}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}, NativeEndpoint: "http://native.test/start"},
		{Operation: reference_connector.OpObserve, Implementation: "connector-local", NativeContract: missingEnvelope("not_applicable"), CapabilityRefs: []string{}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}},
		{Operation: reference_connector.OpRequestNativeCancel, Implementation: "native-mapping", NativeContract: reference_connector.VersionPin{ID: "native-cancel", Version: "v1", ArtifactDigest: digestNative}, CapabilityRefs: []string{"native_cancel"}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}, NativeEndpoint: "http://native.test/cancel"},
		{Operation: reference_connector.OpCloseObservationConnection, Implementation: "connector-local", NativeContract: missingEnvelope("not_applicable"), CapabilityRefs: []string{}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}},
		{Operation: reference_connector.OpCollectArtifacts, Implementation: "connector-local", NativeContract: missingEnvelope("not_applicable"), CapabilityRefs: []string{"native_artifact_retrieval"}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}},
		{Operation: reference_connector.OpReleaseNativeContext, Implementation: "native-mapping", NativeContract: reference_connector.VersionPin{ID: "native-release", Version: "v1", ArtifactDigest: digestNative}, CapabilityRefs: []string{"native_context_release"}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}, NativeEndpoint: "http://native.test/release"},
		{Operation: reference_connector.OpContain, Implementation: "connector-local", NativeContract: missingEnvelope("not_applicable"), CapabilityRefs: []string{}, EvidenceRefs: []reference_connector.EvidenceRef{}, Limitations: []string{}},
	}
	return reference_connector.ConnectorDescriptor{
		RecordType: reference_connector.RecordTypeDescriptor, SchemaVersion: reference_connector.SchemaVersion,
		ConnectorID: "test-connector", ConnectorVersion: "m1-test",
		Build:   reference_connector.VersionPin{ID: "test-build", Version: "m1", ArtifactDigest: digestBuild},
		Binding: reference_connector.VersionPin{ID: "test-binding", Version: "m1", ArtifactDigest: digestBinding},
		Subject: reference_connector.SubjectIdentity{
			SubjectID: "test-subject", SubjectVersion: "v1", RevisionBasis: "operator_attestation",
			NativeRevision:      missingEnvelope("not_applicable"),
			ConfiguredMode:      "cooperative",
			InterfaceSurface:    "browser",
			ConfigurationDigest: digestSubject,
			Stack:               []any{},
		},
		Capabilities: caps, Operations: ops,
		TaskMappings: []reference_connector.TaskMapping{
			{TaskType: "apply", InputForm: "task_envelope", Mapping: reference_connector.VersionPin{ID: "native-mapping", Version: "m1-1", ArtifactDigest: digestMapping}, PlanningOwner: "subject", RecoveryOwner: "connector", Limitations: []string{}},
			{TaskType: "extract", InputForm: "task_envelope", Mapping: reference_connector.VersionPin{ID: "native-mapping", Version: "m1-1", ArtifactDigest: digestMapping}, PlanningOwner: "subject", RecoveryOwner: "connector", Limitations: []string{}},
			{TaskType: "discover_jobs", InputForm: "task_envelope", Mapping: reference_connector.VersionPin{ID: "native-mapping", Version: "m1-1", ArtifactDigest: digestMapping}, PlanningOwner: "subject", RecoveryOwner: "connector", Limitations: []string{}},
		},
		ObservationChannels: []string{"terminal_response", "callback", "native_stream"},
		ActionGrounding:     map[string]any{"mode": "ordinary_browser"},
		ExecutionSubstrate:  "browser",
		Limits: reference_connector.DescriptorLimits{
			MaxCallWait:           reference_connector.DurationLimit{Kind: "exact", Unit: "ms", Value: 60000},
			MaxObservationItems:   1000,
			MaxRequestBytes:       4 << 20,
			MaxResponseBytes:      8 << 20,
			MaxArtifactChunkBytes: 1 << 20,
			MaxQueuedTasks:        10,
			MaxActiveTasks:        5,
		},
		BudgetAccounting: reference_connector.VersionPin{ID: "budget", Version: "v1", ArtifactDigest: digestBudget},
		EvidencePrefix:   missingEnvelope("not_applicable"),
	}
}
