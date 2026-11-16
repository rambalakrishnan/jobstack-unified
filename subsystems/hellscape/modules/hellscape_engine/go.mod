module hellscape_engine

go 1.26.0

require (
	application_owner v0.0.0
	authority v0.0.0
	control_http v0.0.0
	cooperative_assets v0.0.0
	modernc.org/sqlite v1.61.0
	observation_owner v0.0.0
	owner_store v0.0.0
	session_runtime v0.0.0
)

require (
	admission v0.0.0 // indirect
	analysis_owner v0.0.0 // indirect
	clock_rules v0.0.0 // indirect
	connector_transport v0.0.0 // indirect
	diagnostic_reducer v0.0.0 // indirect
	diagnostic_render v0.0.0 // indirect
	evidence_bundle v0.0.0 // indirect
	evidence_codec v0.0.0 // indirect
	evidence_import v0.0.0 // indirect
	fixture_policy v0.0.0 // indirect
	fixture_reducer v0.0.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.49.0 // indirect
	journal_rules v0.0.0 // indirect
	lifecycle_rules v0.0.0 // indirect
	manual_acceptance v0.0.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	publication v0.0.0 // indirect
	replay v0.0.0 // indirect
	source_verifier v0.0.0 // indirect
)

replace admission => ../admission

replace analysis_owner => ../analysis_owner

replace application_owner => ../application_owner

replace authority => ../authority

replace clock_rules => ../clock_rules

replace connector_entrypoint => ../connector_entrypoint

replace connector_queries => ../connector_queries

replace connector_transport => ../connector_transport

replace cooperative_assets => ../cooperative_assets

replace diagnostic_reducer => ../diagnostic_reducer

replace diagnostic_render => ../diagnostic_render

replace evidence_bundle => ../evidence_bundle

replace evidence_codec => ../evidence_codec

replace evidence_import => ../evidence_import

replace fixture_policy => ../fixture_policy

replace fixture_reducer => ../fixture_reducer

replace journal_rules => ../journal_rules

replace lifecycle_rules => ../lifecycle_rules

replace manual_acceptance => ../manual_acceptance

replace native_mapping => ../native_mapping

replace observation_owner => ../observation_owner

replace owner_store => ../owner_store

replace publication => ../publication

replace reference_connector => ../reference_connector

replace replay => ../replay

replace session_runtime => ../session_runtime

replace source_verifier => ../source_verifier

replace control_http => ../control_http
