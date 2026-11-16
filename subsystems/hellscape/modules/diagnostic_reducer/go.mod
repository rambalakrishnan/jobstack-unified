module diagnostic_reducer

go 1.22

require (
	clock_rules v0.0.0
	evidence_codec v0.0.0
	fixture_policy v0.0.0
	journal_rules v0.0.0
	lifecycle_rules v0.0.0
)

replace clock_rules => ../clock_rules

replace evidence_codec => ../evidence_codec

replace fixture_policy => ../fixture_policy

replace journal_rules => ../journal_rules

replace lifecycle_rules => ../lifecycle_rules
