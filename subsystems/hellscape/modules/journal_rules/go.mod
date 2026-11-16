module journal_rules

go 1.22

require (
	evidence_codec v0.0.0
	clock_rules v0.0.0
)

replace evidence_codec => ../evidence_codec

replace clock_rules => ../clock_rules
