# Pre-Phase-4 Triage: Module Complexity Classification

**Scope:** Phase 3 complete. 150 `.omp-spec.md` files staged across five subsystems. This task extracts signals and classifies complexity. Model assignment is out of scope.

---

## §1. Objective

Classify each of the 150 modules into one of six classes (S, H, I, A, B, U) by extracting signals from the existing artifacts. Report per-class distribution, uncertainty, and the specific modules where the heuristic is weakest.

The report is the deliverable. Model selection, cost estimation, consolidation decisions, and Phase 4 spec authoring are separate downstream tasks driven by the operator.

---

## §2. Inputs

Read and index:

- `subsystems/*/modules/*/.omp-spec.md` (150 files) — parse fully
- `subsystems/*/module-graph-0.1.0.dag` (5 files) — parse node headers for `deps`, `tier`, `lang`
- `seam-mappings/*-seam-mapping.md` (5 files) — extract section heading text only for anchor resolution; do not read the mapping bodies
- `contracts/*.yaml` — do not read; the spec's dereferenced invariants and cases are the signals

Bound total reading to the 150 spec files plus one pass over each DAG and one heading-only pass over each seam mapping. Do not read full seam mapping bodies.

---

## §3. Signal extraction

### §3.1 Signal reliability ranking

Use these signals in order of reliability. Higher-ranked signals carry more weight in the classification ladder (§4).

1. `invariant_ids` — extracted IDs from the spec's Invariants section
2. `module_name` — frontmatter `name:` and the semantic tokens it contains
3. `assertion_count`, `invariant_count` — density signals
4. `read_section_headings` — headings of the BLIND SPOT subsections
5. `expose_count + consume_count`, `consumer_count`
6. `forbidden_items`
7. `responsibility_text` — corroboration only; never a primary signal

The `description:` frontmatter field always matches `^Module implementing \S+ at tier -?\d+$` and contains no semantic signal. Log `is_boilerplate_responsibility: true` whenever the field matches this pattern and exclude the field from classification.

### §3.2 `count_interface_items(block)` — paren-aware

Count interface items in the fenced EXPOSES or CONSUMES block. If the block is line-oriented (each non-blank line begins with `fn `, `pub fn `, `def `, `async def `, `func `, `trait `, `type `, `struct `, `enum `, `class `, `interface `, `const `, `static `, or a `<dep_name>:` prefix), count the qualifying lines.

Otherwise treat the block as a single comma-separated list. Split on commas only at paren, bracket, and brace depth 0. Do not split on parameter commas inside `(...)`, `[...]`, or `{...}`.

If both paths produce zero items and the block is non-empty, log the spec to `triage-report.uncertain.json` and count as 0.

### §3.3 `forbidden_count` — exclusion list

Extract lines starting with `- ` from the "## Boundary Execution Constraints (FORBIDDEN)" section. Exclude these three template lines verbatim:

- `No in-band nulls; all missing fields must use typed Missing envelopes.`
- `No shared database writes or cross-domain transactions.`
- `No forbidden constraints specified.`

Any remaining line is a module-specific constraint.

### §3.4 `read_section_headings` — heading text, not anchor fragments

Extract both from each `#### Reference: \`file#anchor\`` block in the BLIND SPOT section:

- The `file#anchor` fragment (used for §4.5 anchor fallback)
- The first `#`–`######` heading text that appears immediately after the reference line

Use the heading text for term matching in §4.3 and §4.4. Use the anchor fragment only when the heading text is absent.

### §3.5 `invariant_ids` — extract from dereferenced bullets

Match `^- \*\*\[([A-Z0-9_\-]+)\]\*\*` in the "### Invariants" subsection. Invariant lines end either with resolved rule text or with `See contracts.` — both produce an extractable ID. Any invariant bullet without a bracketed ID logs `uncertainty_reason: "unresolved_invariant"` and demotes confidence to medium.

### §3.6 Module name suffix signals

Split `module_name` on `_` and check for these tokens:

| Class | Suffix tokens (token must appear anywhere in the name) |
|---|---|
| S | `schema`, `schemas`, `types`, `type`, `def`, `defs`, `definition`, `definitions`, `constant`, `constants`, `enum`, `enums`, `registry`, `catalog`, `atom`, `clock`, `identity`, `digest`, `struct`, `record`, `model`, `models`, `payload`, `error`, `errors` |
| H | `test`, `tests`, `harness`, `fixture`, `fixtures`, `golden`, `goldens`, `runner`, `benchmark`, `mock`, `stub` |
| I | `codec`, `protocol`, `adapter`, `serial`, `deserial`, `wire`, `client`, `transport`, `request`, `response`, `callback`, `handshake`, `translation`, `mapping`, `registration`, `state`, `transition`, `dispatch`, `router`, `routing`, `binding`, `compat`, `normalizer`, `connector`, `service` |
| A | `runtime`, `engine`, `handler`, `pipeline`, `state_machine`, `transpiler`, `reducer`, `evaluator`, `detector`, `classifier`, `minimizer`, `resolver`, `scheduler`, `matcher`, `ranker`, `scorer`, `healer` |
| B | `lease`, `lock`, `fence`, `atomic`, `session_epoch`, `shard`, `ownership`, `publication`, `replacement`, `archive` |

If the module name matches tokens from two classes, log the conflict to `triage-report.contradictions.json` (Check 5).

---

## §4. Classification ladder

Apply priorities in order. The first priority whose conditions are met determines the class.

### Priority 1 — Class B (boundary / concurrency-critical)

Class B if any condition holds:

- Any `invariant_id` matches: `^OWD-(REPLACE|ARCHIVE|RETENTION|LOCAL-COMMIT|PUBLISH)$`, `^BO-THREAD$`, `^EK-(LEASE|LEASE-RESTART|ATOMICITY|JOURNAL)$`, `^LIFE-(DISPATCH|IDEMPOTENCY)$`, or any ID containing `THREAD`, `LEASE`, `FENCE`, `ATOMIC`, `EPOCH`, `OWNERSHIP`, `CONCURREN`, or `TRANSACTION`.
- Module name has a B-suffix (§3.6).
- Any module-specific FORBIDDEN item contains: `atomic`, `concurren`, `fence`, `epoch`, `lease`, `thread`, `isolate`, `barrier`, `transaction`, `contention`, `mutex`, `lock`, `sweep`, `expiry`, `ownership`, `shard`.
- Any extracted section heading contains any of the same terms.

### Priority 2 — Class A (algorithmic)

Class A if any condition holds:

- Module name has an A-suffix.
- Any extracted section heading matches an algorithmic term for the module's subsystem (§4.3).
- `assertion_count >= 5 AND invariant_count >= 2`.
- `invariant_count >= 4`.
- `responsibility_text` is not boilerplate AND contains `proof`, `algebra`, `detector`, `coverage`, `reducer`, or `transpiler`.

### Priority 3 — Class I (integration / interface-heavy)

Class I if any condition holds:

- Module name has an I-suffix.
- Any extracted section heading matches an integration term for the module's subsystem (§4.4).
- `expose_count + consume_count >= 5`.

### Priority 4 — Class H (harness / test infrastructure)

Class H if any condition holds:

- Module name has an H-suffix.
- Any extracted section heading contains `conformance`, `test corpus`, `fixture`, or `golden`.

### Priority 5 — Class S (structural / pure data)

Class S if all conditions hold:

- Module name has an S-suffix.
- `assertion_count <= 3`.
- `invariant_count <= 1`.
- `expose_count + consume_count <= 4`.

### Priority 6 — Class U (uncertain)

If no priority 1–5 condition holds, the module is Class U. It requires operator review before Phase 4 begins. Do not auto-assign.

### §4.1 Promotions after ladder

Apply these promotions after the primary classification. Each promotion advances the class by at most one step in the order S → H → I → A → B. Stop at the first promotion that applies. Log every applied promotion.

- **Promotion 1 (blast radius):** `consumer_count >= 5` advances one step.
- **Promotion 2 (interface surface):** `expose_count + consume_count >= 8` advances one step.
- **Promotion 3 (invariant density):** `invariant_count >= 3` AND current class in {I, S} promotes to A.

### §4.2 Check-3 override

Any module with `assertion_count >= 8` that lands in S, H, or I is overridden to Class A. If Class B signals are also present, override to Class B. Log every override as `check3_override: true`.

### §4.3 Algorithmic section terms per subsystem

Match against extracted heading text.

| Subsystem | Terms |
|---|---|
| crawler | `coverage`, `proof`, `detector`, `drift`, `cursor`, `semantic state`, `pipeline`, `lease`, `classif`, `acquisition` |
| circus-tent | `tier`, `resolution`, `heal`, `extraction`, `reduction`, `scheduler` |
| ringmaster | `tier`, `resolution`, `reduction`, `breaker`, `extraction`, `observe`, `lifecycle`, `recovery` |
| hellscape | `assessment`, `three-way`, `diagnostic`, `replay`, `composition`, `reducer`, `pipeline` |
| job-hunter | `evaluation`, `candidate policy`, `pipeline`, `lifecycle`, `publication`, `transformation`, `scoring` |

### §4.4 Integration section terms per subsystem

Match against extracted heading text.

| Subsystem | Terms |
|---|---|
| crawler | `transport`, `connector`, `session`, `adapter`, `declaration`, `acquisition contract` |
| circus-tent | `transport`, `connector`, `session`, `profile`, `browser`, `route` |
| ringmaster | `transport`, `connector`, `session`, `profile`, `browser`, `binding`, `primitive` |
| hellscape | `application`, `connector`, `external`, `boundary`, `surface`, `authority` |
| job-hunter | `connector`, `protocol`, `boundary`, `topography`, `subsystem`, `interface` |

If a heading matches both an algorithmic and an integration term, the algorithmic match takes precedence.

### §4.5 Anchor fallback

If a section has no heading text (§3.4), fall back to matching the anchor fragment against the section number listed in the seam mapping's table of contents. Read only the TOC of the seam mapping for this fallback.

---

## §5. Script output

Produce five files at `subsystems/`:

- `triage-report.json` — per-module records plus aggregate
- `triage-report.md` — human-readable report
- `triage-report.warnings.json` — calibration warnings from §6
- `triage-report.contradictions.json` — Check 5 and Check 6 output
- `triage-report.uncertain.json` — extraction failures

Per-module JSON record:

```json
{
  "module": "crawler_runtime",
  "subsystem": "crawler",
  "lang": "rust",
  "tier": 4,
  "consumer_count": 2,
  "expose_count": 3,
  "consume_count": 5,
  "assertion_count": 7,
  "invariant_count": 3,
  "invariant_ids": ["EK-ATOMICITY", "LIFE-DISPATCH"],
  "forbidden_count": 2,
  "read_section_headings": ["Coverage Algebra and Equations", "Fetch-Key Replacement"],
  "read_section_anchors": ["#§17-coverage-algebra"],
  "responsibility_text": "Module implementing crawler_runtime at tier 4",
  "is_boilerplate_responsibility": true,
  "name_suffix_signals": {"S": [], "H": [], "I": [], "A": ["runtime"], "B": []},
  "section_signals": {"algorithmic": ["coverage"], "integration": []},
  "class": "A",
  "promotions": ["invariant_density"],
  "signals_matched": {"A": ["name_suffix:runtime", "section:algorithmic:coverage"]},
  "confidence": "medium",
  "uncertainty_reasons": ["boilerplate_responsibility"],
  "check3_override": false,
  "spec_path": "subsystems/crawler/modules/crawler_runtime/.omp-spec.md"
}
```

Sort modules by `(subsystem, module)`. Sort JSON keys alphabetically. No wall-clock fields except top-level `generated_at`.

Aggregate block contains `total_modules`, `distribution`, `pct`, and per-subsystem breakdown.

---

## §6. Calibration checks

Run all six checks before producing the report. Append any failing check to `triage-report.warnings.json`.

**Check 1 — Distribution bounds.** If any class (S/H/I/A/B) exceeds 60% of modules, warn. If Class U exceeds 5%, warn. Do not enforce target percentages.

**Check 2 — Class B floor and ceiling.** If Class B is below 2 across all subsystems, warn "boundary signals under-firing." If above 15, warn "boundary signals over-triggering."

**Check 3 — High-density override verification.** Confirm every `check3_override: true` module is correctly reclassified. Warn with module name and assertion count.

**Check 4 — Consumer-dense mid-or-above.** Any module with `consumer_count >= 8` that remains in S or H is a Promotion 1 failure. Warn with module name and consumer count.

**Check 5 — Name/signal contradiction.** Module name suffix class differs from final class. Log to `triage-report.contradictions.json` with the specific suffix tokens and the final class.

**Check 6 — Priority ambiguity.** Module matched signals at two or more classes at the same ladder priority. Log with the specific conflicting signals.

---

## §7. Constraints

- Classify strictly from extracted signals. Do not infer class from `responsibility_text` when it is boilerplate.
- Class U with reason is correct output when extraction fails. Never fabricate signals.
- Do not reference specific models, pricing, or allowances in any output file.
- Do not compute cost estimates.
- `triage-report.md` must be readable in under 15 minutes.
- `triage-report.json` must round-trip through `json.load` and `json.dumps` without loss.

---

## §8. Success criteria

- `triage-report.json` contains all 150 modules classified into S, H, I, A, B, or U.
- `triage-report.md` contains: distribution table, sample module per class, top 10 lowest-confidence modules with signal dumps, all warnings from §6, all contradictions from Check 5 and Check 6.
- All 6 calibration checks in §6 executed; results in warnings and contradictions files.
- Report explicitly names at least 3 modules where the heuristic is weakest, with full signal dumps.
- No file references models, pricing, or cost.

Failure conditions: any module without a class, any confidence claim stronger than the ladder supports, any model or pricing reference in output, `triage-report.md` over 20 pages.
