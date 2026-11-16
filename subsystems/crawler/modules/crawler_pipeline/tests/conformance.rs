//! Conformance tests for `crawler_pipeline`.
//!
//! * **[C08]** Four surfaces: exact 3/4/3/2 stage participation and initial
//!   states (§16.2). Enrich is one logical stage; Finalize runs only on the
//!   full-description surface.
//! * **[C12]** Stage atomicity: no orphan downstream row or cursor beyond the
//!   durable packet (§16.5). Transactions held across forbidden boundaries,
//!   same-key failures reused as success, adapter commits, and Finalize
//!   synthesis outside the four-field mapping are rejected.

use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_pipeline::{route_surface, validate_stage_transaction, LocalPipeline, Pipeline};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use serde_json::{json, Value};

const PRODUCER: &str = "pipeline_worker";
const OWNER_DOMAIN: &str = "crawler_ingest";

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes"))
}

fn manifest() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-pipeline",
            "producer_registry": [
                {
                    "producer_id": PRODUCER,
                    "owner_domain": OWNER_DOMAIN,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "stage_commit", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn grant() -> Grant {
    let manifest = manifest();
    let principal = check(
        "audit_log",
        json!({
            "producer_id": PRODUCER,
            "manifest_digest": binding_of(&manifest),
        }),
    );
    let submission = check("audit_log", json!({"event_kind": "stage_commit"}));
    authorize_producer(&principal, &submission, &manifest).expect("grant must issue")
}

fn declaration(surface: &str) -> CheckedRecord {
    check("audit_log", json!({"surface": surface}))
}

fn listing(job_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({"job_id": job_id, "target": "target-1"}),
    )
}

fn before(value: Value) -> CheckedRecord {
    check("audit_log", value)
}

fn transaction(value: Value) -> CheckedRecord {
    check("audit_log", value)
}

fn expect_fault<T: std::fmt::Debug>(result: Result<T, Fault>, code: &str) -> Fault {
    match result {
        Ok(value) => panic!("expected fault {code:?}, got success: {value:?}"),
        Err(error) => {
            assert_eq!(error.code, code, "fault detail: {}", error.detail);
            error
        }
    }
}

// ---------------------------------------------------------------------------
// C08: four surfaces
// ---------------------------------------------------------------------------

#[test]
fn c08_four_surfaces_exact_stage_participation() {
    let cases: &[(&str, &str, &[&str])] = &[
        (
            "phase_a_full_description",
            "pending_description_classify",
            &["extract", "description_classify", "finalize"],
        ),
        (
            "phase_a_snippet_phase_b_description",
            "pending_snippet_classify",
            &[
                "extract",
                "snippet_classify",
                "enrich",
                "description_classify",
            ],
        ),
        (
            "phase_b_description_only",
            "pending_enrich",
            &["extract", "enrich", "description_classify"],
        ),
        ("none", "pending_enrich", &["extract", "enrich"]),
    ];
    let expected_counts = [3usize, 4, 3, 2];
    for (index, (surface, initial, stages)) in cases.iter().enumerate() {
        let routed = route_surface(&declaration(surface), &listing("job-1"))
            .unwrap_or_else(|e| panic!("surface {surface:?} must route: {e:?}"));
        let value = record_value(&routed);
        assert_eq!(value["surface"], json!(surface));
        assert_eq!(value["initial_state"], json!(initial));
        let got: Vec<&str> = value["stages"]
            .as_array()
            .expect("stages array")
            .iter()
            .map(|entry| entry.as_str().expect("stage string"))
            .collect();
        assert_eq!(got, *stages, "surface {surface:?} stage list");
        assert_eq!(
            value["stage_count"],
            json!(expected_counts[index]),
            "surface {surface:?} stage count"
        );
        assert_eq!(value["enrich_is_single_stage"], json!(true));
        // Enrich appears at most once: dispatcher+fetcher are boundaries,
        // not two logical stages.
        assert!(
            got.iter().copied().filter(|stage| *stage == "enrich").count() <= 1,
            "enrich must be a single logical stage on {surface:?}"
        );
        assert!(
            !got.contains(&"dispatch") && !got.contains(&"fetch"),
            "logical route exposes enrich, not dispatch/fetch, on {surface:?}"
        );
        // Finalize runs only on the full-description surface.
        let finalize = got.contains(&"finalize");
        assert_eq!(
            value["finalize_present"],
            json!(finalize),
            "finalize flag on {surface:?}"
        );
        if *surface == "phase_a_full_description" {
            assert!(finalize, "full surface must include finalize");
        } else {
            assert!(
                !finalize,
                "surface {surface:?} must not secretly execute finalize"
            );
        }
        assert_eq!(value["listing_ref"], json!("job-1"));
    }
}

#[test]
fn c08_rejects_unknown_surface_and_state() {
    // Unknown wire surface is rejected, never mapped to nearest.
    let error = expect_fault(
        route_surface(&declaration("phase_c_everything"), &listing("job-1")),
        "unknown_surface",
    );
    assert!(error.detail.contains("phase_c_everything"));

    // Missing surface is an invalid declaration.
    let bad = check("audit_log", json!({"surface": missing("not_observed")}));
    expect_fault(route_surface(&bad, &listing("job-1")), "invalid_declaration");

    // Unknown listing state is rejected, never mapped.
    let bad_listing = check(
        "audit_log",
        json!({"job_id": "job-1", "listing_state": "pending_magic"}),
    );
    expect_fault(
        route_surface(&declaration("none"), &bad_listing),
        "unknown_listing_state",
    );

    // Known listing states pass through routing.
    for state in [
        "pending_snippet_classify",
        "pending_enrich",
        "pending_description_classify",
        "pending_finalize",
        "enqueued",
        "finalized",
        "deduped",
        "vetoed",
        "render_failed",
        "failed",
    ] {
        let ok_listing = check(
            "audit_log",
            json!({"job_id": "job-1", "listing_state": state}),
        );
        route_surface(&declaration("none"), &ok_listing)
            .unwrap_or_else(|e| panic!("listing state {state:?} must route: {e:?}"));
    }
}

// ---------------------------------------------------------------------------
// C12: stage atomicity
// ---------------------------------------------------------------------------

fn durable_before() -> Value {
    json!({
        "durable_packet_id": "packet-1",
        "listings": ["job-1"],
        "works": ["work-1"],
        "details": ["Detail-1"],
        "cursor": {"certified_packet_id": "packet-1"},
    })
}

#[test]
fn c12_stage_atomicity_no_orphan_downstream() {
    // Extract creating listings inside the durable packet commits.
    validate_stage_transaction(
        &before(json!({
            "durable_packet_id": "packet-1",
            "listings": [],
            "works": [],
            "details": [],
        })),
        &transaction(json!({
            "stage": "extract",
            "packet_id": "packet-1",
            "creates_listings": ["job-1", "job-2"],
        })),
    )
    .expect("extract within durable packet must commit");

    // Dispatch creating work with durable listing delegation commits.
    validate_stage_transaction(
        &before(durable_before()),
        &transaction(json!({
            "stage": "dispatch",
            "packet_id": "packet-1",
            "creates_works": ["work-2"],
        })),
    )
    .expect("work with listing delegation must commit");

    // Same-effect listing delegation also satisfies the contract.
    validate_stage_transaction(
        &before(json!({
            "durable_packet_id": "packet-1",
            "listings": [],
            "works": [],
            "details": [],
        })),
        &transaction(json!({
            "stage": "enrich",
            "packet_id": "packet-1",
            "creates_listings": ["job-9"],
            "creates_works": ["work-9"],
        })),
    )
    .expect("same-effect listing delegation must commit");

    // Work without any listing is orphaned.
    expect_fault(
        validate_stage_transaction(
            &before(json!({
                "durable_packet_id": "packet-1",
                "listings": [],
                "works": [],
                "details": [],
            })),
            &transaction(json!({
                "stage": "dispatch",
                "packet_id": "packet-1",
                "creates_works": ["work-orphan"],
            })),
        ),
        "orphan_work",
    );

    // Fetch creating detail with work present commits.
    validate_stage_transaction(
        &before(durable_before()),
        &transaction(json!({
            "stage": "fetch",
            "packet_id": "packet-1",
            "creates_details": ["detail-2"],
            "completes_works": ["work-1"],
        })),
    )
    .expect("detail with work completion must commit");

    // Detail without any work is orphaned.
    expect_fault(
        validate_stage_transaction(
            &before(json!({
                "durable_packet_id": "packet-1",
                "listings": ["job-1"],
                "works": [],
                "details": [],
            })),
            &transaction(json!({
                "stage": "fetch",
                "packet_id": "packet-1",
                "creates_details": ["detail-orphan"],
            })),
        ),
        "orphan_detail",
    );

    // Reuse of an established ready detail commits (covered in
    // c12_reuse_never_invents_success); malformed reuse is rejected there.
}

#[test]
fn c12_reuse_never_invents_success() {
    // Ready reuse commits.
    validate_stage_transaction(
        &before(durable_before()),
        &transaction(json!({
            "stage": "fetch",
            "packet_id": "packet-1",
            "completes_works": ["work-1"],
            "reuses_detail": {"detail_id": "Detail-1", "detail_state": "ready"},
        })),
    )
    .expect("ready reuse must commit");

    // Vetoed reuse commits.
    validate_stage_transaction(
        &before(durable_before()),
        &transaction(json!({
            "stage": "fetch",
            "packet_id": "packet-1",
            "reuses_detail": {"detail_id": "Detail-1", "detail_state": "vetoed"},
        })),
    )
    .expect("vetoed reuse must commit");

    // A same-key failed render is never existing success.
    for state in ["render_failed", "failed", "pending_classification"] {
        expect_fault(
            validate_stage_transaction(
                &before(durable_before()),
                &transaction(json!({
                    "stage": "fetch",
                    "packet_id": "packet-1",
                    "completes_works": ["work-1"],
                    "reuses_detail": {"detail_id": "Detail-1", "detail_state": state},
                })),
            ),
            "invalid_reuse",
        );
    }

    // Reuse of a detail with no durable row invents success.
    expect_fault(
        validate_stage_transaction(
            &before(durable_before()),
            &transaction(json!({
                "stage": "fetch",
                "packet_id": "packet-1",
                "reuses_detail": {"detail_id": "Detail-ghost", "detail_state": "ready"},
            })),
        ),
        "orphan_detail",
    );
}

#[test]
fn c12_cursor_never_beyond_durable_packet() {
    // Packet beyond the durable boundary is orphaned.
    expect_fault(
        validate_stage_transaction(
            &before(durable_before()),
            &transaction(json!({
                "stage": "extract",
                "packet_id": "packet-2",
                "creates_listings": ["job-2"],
            })),
        ),
        "orphan_packet",
    );

    // Cursor advance within the durable packet commits.
    validate_stage_transaction(
        &before(durable_before()),
        &transaction(json!({
            "stage": "extract",
            "packet_id": "packet-1",
            "creates_listings": ["job-2"],
            "cursor_advance": {"certified_packet_id": "packet-1"},
        })),
    )
    .expect("cursor within durable packet must commit");

    // Cursor advance beyond the durable packet is rejected.
    expect_fault(
        validate_stage_transaction(
            &before(durable_before()),
            &transaction(json!({
                "stage": "extract",
                "packet_id": "packet-1",
                "creates_listings": ["job-2"],
                "cursor_advance": {"certified_packet_id": "packet-2"},
            })),
        ),
        "cursor_beyond_packet",
    );

    // A durable set admits any member but nothing beyond it.
    validate_stage_transaction(
        &before(json!({
            "durable_packet_id": "packet-1",
            "durable_packets": ["packet-1", "packet-2"],
            "listings": ["job-1"],
            "works": [],
            "details": [],
        })),
        &transaction(json!({
            "stage": "extract",
            "packet_id": "packet-2",
            "creates_listings": ["job-2"],
        })),
    )
    .expect("packet inside the durable set must commit");
    expect_fault(
        validate_stage_transaction(
            &before(json!({
                "durable_packet_id": "packet-1",
                "durable_packets": ["packet-1", "packet-2"],
                "listings": ["job-1"],
                "works": [],
                "details": [],
            })),
            &transaction(json!({
                "stage": "extract",
                "packet_id": "packet-3",
            })),
        ),
        "orphan_packet",
    );

    // Unknown stages are hidden stages, never admitted.
    expect_fault(
        validate_stage_transaction(
            &before(durable_before()),
            &transaction(json!({
                "stage": "shadow_rank",
                "packet_id": "packet-1",
            })),
        ),
        "unknown_stage",
    );
}

#[test]
fn c12_transaction_never_spans_forbidden_boundary() {
    for span in ["network", "inference", "signal_emission", "human_waiting"] {
        expect_fault(
            validate_stage_transaction(
                &before(durable_before()),
                &transaction(json!({
                    "stage": "fetch",
                    "packet_id": "packet-1",
                    "holds_across": [span],
                })),
            ),
            "spans_forbidden_boundary",
        );
    }
    for field in [
        "spans_network",
        "spans_inference",
        "spans_signal",
        "spans_human",
    ] {
        expect_fault(
            validate_stage_transaction(
                &before(durable_before()),
                &transaction(json!({
                    "stage": "fetch",
                    "packet_id": "packet-1",
                    field: true,
                })),
            ),
            "spans_forbidden_boundary",
        );
    }
    // Local-only holds commit.
    validate_stage_transaction(
        &before(durable_before()),
        &transaction(json!({
            "stage": "fetch",
            "packet_id": "packet-1",
            "holds_across": [],
        })),
    )
    .expect("local-only transaction must commit");

    // Adapters never commit tables, alter fencing, override proofs, or
    // perform cross-domain writes.
    for field in [
        "adapter_commit",
        "fencing_override",
        "proof_override",
        "cross_domain_write",
        "shared_write",
    ] {
        expect_fault(
            validate_stage_transaction(
                &before(durable_before()),
                &transaction(json!({
                    "stage": "fetch",
                    "packet_id": "packet-1",
                    field: true,
                })),
            ),
            "adapter_forbidden",
        );
    }
}

#[test]
fn c12_listing_transitions_and_finalize_synthesis() {
    // Absent -> initial commits.
    validate_stage_transaction(
        &before(json!({
            "durable_packet_id": "packet-1",
            "listings": [],
            "works": [],
            "details": [],
        })),
        &transaction(json!({
            "stage": "extract",
            "packet_id": "packet-1",
            "creates_listings": ["job-1"],
            "listing_transition": {"from": "absent", "to": "pending_enrich"},
        })),
    )
    .expect("absent -> initial must commit");

    // Snippet PASS delegates to enrich; VETO vetoes.
    for (to, ok) in [("pending_enrich", true), ("vetoed", true)] {
        let result = validate_stage_transaction(
            &before(json!({
                "durable_packet_id": "packet-1",
                "listings": ["job-1"],
                "works": [],
                "details": [],
                "listing_state": "pending_snippet_classify",
            })),
            &transaction(json!({
                "stage": "snippet_classify",
                "packet_id": "packet-1",
                "listing_transition": {"from": "pending_snippet_classify", "to": to},
            })),
        );
        assert!(ok && result.is_ok(), "transition to {to:?}: {result:?}");
    }

    // Enrich delegates to enqueued; short circuit dedupes.
    validate_stage_transaction(
        &before(json!({
            "durable_packet_id": "packet-1",
            "listings": ["job-1"],
            "works": [],
            "details": [],
            "listing_state": "pending_enrich",
        })),
        &transaction(json!({
            "stage": "dispatch",
            "packet_id": "packet-1",
            "creates_works": ["work-2"],
            "listing_transition": {"from": "pending_enrich", "to": "enqueued"},
        })),
    )
    .expect("enrich -> enqueued must commit");

    // Skipping stages is rejected.
    expect_fault(
        validate_stage_transaction(
            &before(json!({
                "durable_packet_id": "packet-1",
                "listings": ["job-1"],
                "works": [],
                "details": [],
                "listing_state": "pending_snippet_classify",
            })),
            &transaction(json!({
                "stage": "snippet_classify",
                "packet_id": "packet-1",
                "listing_transition": {"from": "pending_snippet_classify", "to": "finalized"},
            })),
        ),
        "invalid_transition",
    );

    // Reset without authorization is rejected; with authorization it commits.
    let reset_before = json!({
        "durable_packet_id": "packet-1",
        "listings": ["job-1"],
        "works": [],
        "details": [],
        "listing_state": "failed",
    });
    expect_fault(
        validate_stage_transaction(
            &before(reset_before.clone()),
            &transaction(json!({
                "stage": "failure_reclamation",
                "packet_id": "packet-1",
                "listing_transition": {"from": "failed", "to": "pending_enrich"},
            })),
        ),
        "invalid_transition",
    );
    validate_stage_transaction(
        &before(reset_before),
        &transaction(json!({
            "stage": "failure_reclamation",
            "packet_id": "packet-1",
            "reset_authorized": true,
            "listing_transition": {"from": "failed", "to": "pending_enrich"},
        })),
    )
    .expect("authorized reset must commit");

    // Finalize with four-field synthesis commits.
    validate_stage_transaction(
        &before(json!({
            "durable_packet_id": "packet-1",
            "listings": ["job-1"],
            "works": ["work-1"],
            "details": [],
            "listing_state": "pending_finalize",
        })),
        &transaction(json!({
            "stage": "finalize",
            "packet_id": "packet-1",
            "creates_details": ["detail-2"],
            "completes_works": ["work-1"],
            "synthesis": {
                "title": "Engineer",
                "employer": "Bank",
                "snippet": "Build things",
                "full_description": "Long text",
            },
            "listing_transition": {"from": "pending_finalize", "to": "finalized"},
        })),
    )
    .expect("four-field finalize must commit");

    // Invented synthesis outside the mapping is rejected.
    expect_fault(
        validate_stage_transaction(
            &before(json!({
                "durable_packet_id": "packet-1",
                "listings": ["job-1"],
                "works": ["work-1"],
                "details": [],
            })),
            &transaction(json!({
                "stage": "finalize",
                "packet_id": "packet-1",
                "creates_details": ["detail-2"],
                "completes_works": ["work-1"],
                "synthesis": {
                    "title": "Engineer",
                    "compensation": "1M",
                },
            })),
        ),
        "invalid_synthesis",
    );
}

#[test]
fn c12_advance_enforces_surface_and_atomicity() {
    let pipeline = LocalPipeline::new();
    let grant = grant();

    // Happy path: enrich dispatch on the none surface commits.
    let command = check(
        "audit_log",
        json!({
            "surface": "none",
            "before": durable_before(),
            "transaction": {
                "stage": "dispatch",
                "packet_id": "packet-1",
                "creates_works": ["work-2"],
            },
        }),
    );
    let committed = pipeline
        .advance(&grant, &command)
        .expect("surface-legal atomic stage must commit");
    let value = record_value(&committed);
    assert_eq!(value["record_type"], json!("stage_commit"));
    assert_eq!(value["stage"], json!("dispatch"));
    assert_eq!(value["surface"], json!("none"));
    assert_eq!(value["packet_id"], json!("packet-1"));
    assert_eq!(value["owner_domain"], json!(OWNER_DOMAIN));
    assert_eq!(value["applied"], json!(true));

    // Dispatch/fetch satisfy the single logical enrich stage.
    for stage in ["enrich", "dispatch", "fetch"] {
        let command = check(
            "audit_log",
            json!({
                "surface": "none",
                "before": durable_before(),
                "transaction": {
                    "stage": stage,
                    "packet_id": "packet-1",
                    "creates_works": ["work-x"],
                },
            }),
        );
        pipeline
            .advance(&grant, &command)
            .unwrap_or_else(|e| panic!("stage {stage:?} must satisfy enrich: {e:?}"));
    }

    // Finalize on a non-full surface is a hidden stage.
    expect_fault(
        pipeline.advance(
            &grant,
            &check(
                "audit_log",
                json!({
                    "surface": "none",
                    "before": durable_before(),
                    "transaction": {
                        "stage": "finalize",
                        "packet_id": "packet-1",
                    },
                }),
            ),
        ),
        "stage_not_in_surface",
    );

    // Snippet classification on the full surface is not a participant.
    expect_fault(
        pipeline.advance(
            &grant,
            &check(
                "audit_log",
                json!({
                    "surface": "phase_a_full_description",
                    "before": durable_before(),
                    "transaction": {
                        "stage": "snippet_classify",
                        "packet_id": "packet-1",
                    },
                }),
            ),
        ),
        "stage_not_in_surface",
    );

    // Atomicity still applies through advance: orphan work is rejected.
    expect_fault(
        pipeline.advance(
            &grant,
            &check(
                "audit_log",
                json!({
                    "surface": "none",
                    "before": {
                        "durable_packet_id": "packet-1",
                        "listings": [],
                        "works": [],
                        "details": [],
                    },
                    "transaction": {
                        "stage": "dispatch",
                        "packet_id": "packet-1",
                        "creates_works": ["work-orphan"],
                    },
                }),
            ),
        ),
        "orphan_work",
    );

    // Cursors beyond the durable packet are rejected through advance.
    expect_fault(
        pipeline.advance(
            &grant,
            &check(
                "audit_log",
                json!({
                    "surface": "none",
                    "before": durable_before(),
                    "transaction": {
                        "stage": "extract",
                        "packet_id": "packet-1",
                        "cursor_advance": {"certified_packet_id": "packet-9"},
                    },
                }),
            ),
        ),
        "cursor_beyond_packet",
    );
}
