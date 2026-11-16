module replay

go 1.26.0

require (
	authority v0.0.0
	diagnostic_reducer v0.0.0
	evidence_bundle v0.0.0
	evidence_codec v0.0.0
	fixture_reducer v0.0.0
	journal_rules v0.0.0
	owner_store v0.0.0
	publication v0.0.0
)

require (
	clock_rules v0.0.0 // indirect
	evidence_import v0.0.0 // indirect
	fixture_policy v0.0.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.49.0 // indirect
	lifecycle_rules v0.0.0 // indirect
	modernc.org/libc v1.79.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	modernc.org/sqlite v1.61.0 // indirect
	source_verifier v0.0.0 // indirect
)

replace authority => ../authority

replace clock_rules => ../clock_rules

replace diagnostic_reducer => ../diagnostic_reducer

replace evidence_bundle => ../evidence_bundle

replace evidence_codec => ../evidence_codec

replace evidence_import => ../evidence_import

replace fixture_policy => ../fixture_policy

replace fixture_reducer => ../fixture_reducer

replace journal_rules => ../journal_rules

replace lifecycle_rules => ../lifecycle_rules

replace owner_store => ../owner_store

replace publication => ../publication

replace source_verifier => ../source_verifier
