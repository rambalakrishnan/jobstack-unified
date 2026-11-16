module lifecycle_rules

go 1.22

require (
	clock_rules v0.0.0
	evidence_codec v0.0.0
	journal_rules v0.0.0
)

replace clock_rules => ../clock_rules

replace evidence_codec => ../evidence_codec

replace journal_rules => ../journal_rules
