module native_mapping

go 1.22

require (
	clock_rules v0.0.0
	evidence_codec v0.0.0
)

replace clock_rules => ../clock_rules

replace evidence_codec => ../evidence_codec
