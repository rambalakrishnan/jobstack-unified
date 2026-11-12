# job-hunter — candidate-specific selection, application, and follow-up

**Status:** Step 0 review draft; requirements below describe intended behavior, not an implemented service, verified employer integration, or observed application result. [proposed: distinguish specification from operational evidence]

**Role:** job-hunter is the product layer for Ram Balakrishnan’s job search: consume opportunities, evaluate them against his capabilities and preferences, prepare truthful materials, commission authorized applications, and track each attempt through subsequent outcomes. [extracted: current request, Purpose; 6-get-a-job.xml.txt, AGENTS.md]

**Baseline:** the six shared contract drafts and their conformance suites govern evidence, attempts, connector calls, browser bindings, owner-separated publication, and suggested fixes; this PRD does not introduce another shared contract or redefine their fields. [inferred: 1-handoff-brief.txt, Step 0; prd/00-integration.md]

**Decisions:** retain the recorded provisionals, particularly P-07, P-13 through P-16, and amendment HA-03; no new handoff amendment is introduced here. [proposed: implement decisions/invariants-and-provisionals.md without silently changing its conclusions]

## 1. Outcome and operating priority

The first useful output is a suitable, real, tracked application—not a finished crawler, autonomous agent framework, dashboard, or laboratory curriculum. [inferred: current request, Purpose; 1-handoff-brief.txt, Roadmap and Anti-patterns]

From day one, the operator must be able to capture a job, evaluate it, prepare materials, apply manually, retain outcome evidence, and record the next action while automation develops independently. [inferred: decisions/invariants-and-provisionals.md, HA-03; prd/00-integration.md, Day-one production lane]

A commissioned attempt, submit action, executor completion claim, verified employer commitment, and eventual hiring outcome must remain distinguishable in the product view. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES and LIFE-CLAIMS; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md]

The handoff’s top-five application lane is an operating target, not a mandatory batch size, success metric divorced from suitability, or justification for submitting unsuitable applications. [inferred: 1-handoff-brief.txt, Roadmap; decisions/invariants-and-provisionals.md, §1]

### 1.1 Product responsibilities

| job-hunter owns | Boundary |
|---|---|
| Candidate policy, evaluation, prioritization, and selection | It does not let a crawler relevance label become the final application decision. [inferred: 1-handoff-brief.txt, component interface notes; 2-state-bank-crawler-blueprint.json, §14] |
| Tailored resumes, cover letters, supplemental answers, and their approval records | It cannot invent candidate qualifications or treat an LLM-generated answer as verified history. [inferred: 6-get-a-job.xml.txt, AGENTS.md, capability_profile.txt, and raw_job_history.txt] |
| Immutable commissioning and authorized scheduling | It requests work through the external connector rather than driving browser primitives. [extracted: 1-handoff-brief.txt, External connector and Orchestrator interface notes] |
| Product tracking, correspondence review, follow-up, and presentation | Its projections cannot overwrite source execution claims, origin facts, or reconciliation results. [inferred: contracts/01-application-attempt-lifecycle.yaml; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md] |
| Turning observed friction into evidence-backed work for the appropriate product owner | It does not automatically patch Circus Tent or Ringmaster, grant capability credit, or convert practice into production authorization. [inferred: contracts/05-suggested-fix-registry.yaml; decisions/invariants-and-provisionals.md, INV-29 and INV-30] |

Browser control belongs to Circus Tent or Ringmaster, discovery coverage belongs to the crawler, and controlled form experiments belong to Hellscape; these are collaborating products, not modules inside job-hunter’s runtime. [extracted: 1-handoff-brief.txt, seven semantic boundaries; current request, Products]

## 2. Candidate policy is the product’s center

### 2.1 Match problems, not career-title continuity

The candidate’s recurring value is absorbing ambiguous environments, extracting rules, building middleware or SOPs, improving human execution, and leaving auditable systems; title matching alone systematically loses that cross-domain evidence. [extracted: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt]

Evaluation must name which playbooks fit the actual work and cite the candidate evidence supporting that match, rather than merely labeling the candidate a “systems thinker.” [inferred: 6-get-a-job.xml.txt, capability_profile.txt]

| Playbook | Problem signatures to recognize | Supplied evidence anchors |
|---|---|---|
| **Recursive Structural Deconstruction & Isomorphic Mapping** | Undocumented interfaces, incompatible systems, legacy workflows, normalization, or translating a problem across domains. | Meridian telemetry-to-ArcView integration; Liberty CRM-to-document middleware; poultry sensing/control integration. [extracted: 6-get-a-job.xml.txt, capability_profile.txt] |
| **Human Asset Optimization & Reverse-Pyramid Leadership** | Training pipelines, coaching, delegation of local decisions, uneven team performance, or frontline-to-engineering coordination. | Minted’s five-role progression, curriculum work, coaching a remote team, and technical liaison responsibilities. [extracted: 6-get-a-job.xml.txt, capability_profile.txt and raw_job_history.txt] |
| **Compliance-to-Automation Pipeline** | Ambiguous regulation, inconsistent procedures, manual checks, audit preparation, or compliance evidence generation. | Liberty SEC/FINRA procedures; USPS chain-of-custody work; supplied DOT-related procedural experience. [extracted: 6-get-a-job.xml.txt, capability_profile.txt] |
| **High-Stakes De-escalation & Autonomous Field Triage** | Escalated customers, volatile field conditions, discretionary policy application, or resolving problems without immediate supervision. | Minted final escalations; Mid-Columbia passenger and route interventions; Liberty stakeholder triage. [extracted: 6-get-a-job.xml.txt, capability_profile.txt] |
| **Cross-Domain Hardware/Software Integration** | Sensors, firmware, edge devices, radio/telemetry, actuators, or integrating software with physical operating constraints. | Meridian SBC/MCU work; poultry ROS2/YOLO/actuators; inference infrastructure experimentation. [extracted: 6-get-a-job.xml.txt, capability_profile.txt] |
| **Latency-Aware Cognitive Offloading** | Local/cloud allocation, constrained inference, accessibility interfaces, or expensive reasoning behind inexpensive triage. | Local-SLM/cloud-reasoner architecture; serial/Braille/HID work; the job-search automation experiments. [extracted: 6-get-a-job.xml.txt, capability_profile.txt] |
| **Public/Community Governance & Parliamentary Procedure** | Community coordination, parliamentary process, stakeholder consensus, public communication, or accountable volunteer operations. | AA/NA motions, treasury/reporting, and large-group speaking experience. [extracted: 6-get-a-job.xml.txt, capability_profile.txt] |
| **Data-Driven Campaign Engineering** | Audience segmentation, conversion measurement, constrained budgets, outreach optimization, or operations informed by demographic data. | Liberty’s 34 mail campaigns and reported revenue improvement at flat budget; community BI models; prior listing analysis. [extracted: 6-get-a-job.xml.txt, capability_profile.txt] |

These anchors are evaluation evidence, not permission to disclose every personal detail in an application; external materials require candidate-approved selection and wording. [proposed: separate useful internal matching evidence from appropriate employer-facing disclosure]

### 2.2 Preserve negative space and uncertainty

The profile states no formal degree, limited deep ownership of AzureAD/Intune/PowerPlatform-style enterprise stacks, and no established multi-year, multi-time-zone delegation history at scale; evaluation and materials must not erase those gaps. [extracted: 6-get-a-job.xml.txt, capability_profile.txt]

A bachelor’s requirement is a review signal: read its actual substitution language and assess the barrier rather than assuming a waiver or excluding every posting containing the word “bachelor’s.” [extracted: 6-get-a-job.xml.txt, job_search_queries.txt]

Past transit work does not establish a current license, and broad equivalent experience does not establish that an employer accepts that equivalency. [inferred: 6-get-a-job.xml.txt, capability_profile.txt, job_search_queries.txt, and raw_job_history.txt]

Current salary floor, schedule limits, travel tolerance, location/address rules, credential status, and disclosure preferences are incomplete in the supplied sources; obtain and version owner decisions instead of filling those gaps with plausible defaults. [uncertain: complete current candidate policy and the referenced address/zone rules are absent; resolve them with the candidate before enforcing affected decisions]

### 2.3 Version the evaluation inputs

Each evaluation must pin the actual job snapshot, candidate profile, relevant policy, evaluation method, and supporting evidence; model or prompt identity and human assistance must be retained when used. [proposed: make candidate decisions reproducible and explainable using kernel evidence and owner-separated evaluation references]

New preferences or corrected history create new policy/profile inputs and, when needed, new evaluations; they must not rewrite the rationale under which an earlier application was commissioned. [inferred: contracts/04-owner-separated-write-domains.yaml, EvaluationReference; contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION]

The candidate remains the authority for preferences and approvals; a model may propose translations or questions but cannot silently change the policy to increase application volume. [inferred: 6-get-a-job.xml.txt, AGENTS.md, Rules of engagement]

## 3. Day-one operating workflow

The first operating interface may be a small local recorder with explicit artifact import and readable review output; a dashboard, scheduler, model service, and automated feed are not prerequisites. [proposed: implement HA-03 with the smallest durable workflow rather than a substitute platform project]

| Step | Minimum useful behavior | Evidence and boundary |
|---|---|---|
| Capture | Save the actual listing location, description, and observed employer/requisition information. | Mark the source as manual where appropriate; do not invent a crawler ID, coverage proof, or acquisition revision. [inferred: decisions/invariants-and-provisionals.md, HA-03; prd/00-integration.md, §2] |
| Evaluate | Compare the requirements with the profile, playbooks, blockers, and tolerances; ask the candidate about consequential unknowns. | Retain the decision inputs and rationale even if the evaluator is entirely human. [inferred: 6-get-a-job.xml.txt, job_search_queries.txt; decisions/invariants-and-provisionals.md, P-13] |
| Prepare | Produce truthful, job-specific materials and review the final values. | Preserve the exact approved artifacts and unresolved-answer questions rather than an untracked working document. [inferred: 6-get-a-job.xml.txt, AGENTS.md and docs/contracts/firestore-collections.md] |
| Commission | Record a production attempt targeting the employer origin before submission. | Pin the job, candidate, task, permissions, kind, and manual execution configuration; do not fabricate subject or connector identity. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION and LIFE-MANUAL] |
| Apply | The operator completes the form and performs final submission under the initial production policy. | Journal manual observations as manual; operator action is not unattended executor performance. [inferred: decisions/invariants-and-provisionals.md, P-14; 5-browser-qualification.md] |
| Establish outcome | Retain the actual receipt, confirmation, error, or absence of conclusive evidence. | A designated origin-fact recorder verifies source and candidate/job/attempt correlation; an operator’s assertion alone does not become an origin fact. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-ORIGIN] |
| Follow up | Record the next review or follow-up action and its owner. | Unknown submission outcome requires investigation, not an automatic repeat submission. [inferred: contracts/01-application-attempt-lifecycle.yaml, idempotency and origin rules; 6-get-a-job.xml.txt, AGENTS.md] |

A manual job snapshot can remain a registered evidence artifact until a source identity is established; later matching to a crawler record must preserve the original snapshot and the evidence for that match. [proposed: support manual discovery without counterfeiting the crawler’s `(target, job_id)` identity]

A tracked failed or unresolved attempt is useful, but it must not be counted as a verified application commitment merely to satisfy the operating target. [inferred: 1-handoff-brief.txt, evidence invariants; prd/00-integration.md, Product outcome]

## 4. Evaluation and selection requirements

### 4.1 Intake and recall

Automated intake consumes a named crawler publication, preserving source identity, source URL, content, render status, classifier provenance, and per-partition coverage references. [extracted: contracts/04-owner-separated-write-domains.yaml, JobCrawlerValue and EvaluationReference]

An individually usable posting may be evaluated even when its enumeration partition is incomplete, but job-hunter must display that limitation and cannot describe the search as complete. [inferred: 2-state-bank-crawler-blueprint.json, §§7–8]

A failed-render record or incomplete extraction is not a valid full description for an invented evaluation; request another legitimate source or manual capture while retaining the original failure evidence. [inferred: 2-state-bank-crawler-blueprint.json, §§3.7 and 11.4; 5-browser-qualification.md]

Search expansion should follow the supplied parallel problem-signature families—systems, compliance, human operations, business process, and accessibility—while titles remain secondary recall expanders. [extracted: 6-get-a-job.xml.txt, job_search_queries.txt]

Embeddings, cosine ranking, and a lightweight recall filter are optional throughput improvements, not prerequisites for useful selection or replacements for candidate-specific review. [inferred: 6-get-a-job.xml.txt, job_search_queries.txt; decisions/invariants-and-provisionals.md, P-13]

A crawler’s genuine/applied PASS or VETO is retained as its own classification evidence; it does not automatically authorize an application or erase job-hunter’s independent decision. [inferred: 2-state-bank-crawler-blueprint.json, §§6 and 14; contracts/04-owner-separated-write-domains.yaml]

### 4.2 Two distinct checks

Evaluation first checks actual hard requirements and then checks tolerability/desirability; lack of a known hard blocker does not imply that the candidate wants the work. [extracted: 6-get-a-job.xml.txt, job_search_queries.txt]

| Dimension | Required judgment |
|---|---|
| Ability | Identify central duties, relevant evidence, matched playbooks, and material gaps; preserve uncertainty where the description is too vague. [inferred: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt] |
| Hard requirements | Read requirements for licenses, clearance, education, location, and other mandatory conditions in context; distinguish a proven conflict from an unresolved question. [inferred: 6-get-a-job.xml.txt, job_search_queries.txt] |
| Tolerability | Assess schedule, work pattern, travel, commission exposure, physical demands, and culture against the current owner policy. [extracted: 6-get-a-job.xml.txt, job_search_queries.txt] |
| Compensation | Compare disclosed compensation with known policy; absent pay or absent candidate threshold remains unresolved rather than automatically acceptable. [inferred: 6-get-a-job.xml.txt, job_search_queries.txt] |
| Legibility | Explain where supported experience is relevant but unlikely to be recognized by conventional ATS/title matching, and propose truthful translations. [extracted: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt] |
| Practical opportunity | Preserve actual application location, observed deadline information, and whether further source verification is needed. [inferred: 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md; contracts/04-owner-separated-write-domains.yaml, JobContent] |

The source’s “can do 70 percent” question is an evaluator prompt, not an established mathematical rubric, fixed weighting scheme, or permission to fabricate a numeric confidence. [inferred: 6-get-a-job.xml.txt, job_search_queries.txt]

Keyword exclusions are recall aids and policy evidence, not a universal substring veto engine; for example, mentioning nursing stakeholders is not equivalent to requiring an RN license. [proposed: avoid false exclusions by grounding blockers in the posting’s actual requirement and candidate policy]

### 4.3 Evaluation artifact and decision

The supplied reranker vocabulary—`can_do_70_percent`, `hard_blockers`, `playbooks_matched`, `would_tolerate`, `pay_ok`, `legibility_gap`, `resume_translation`, and `score`—is the starting semantic inventory, not a complete executable schema with established types and defaults. [extracted: 6-get-a-job.xml.txt, job_search_queries.txt]

The product-owned evaluation artifact must preserve those distinctions, supporting job/candidate evidence, unresolved questions, evaluator identity, and input pins; its versioned representation must be defined before automated producers are admitted. [proposed: complete product-local evaluation semantics without adding an unreviewed shared contract]

Missing inputs must use the kernel’s explicit missingness discipline rather than false, zero, an empty blocker list, or a fabricated score; “no blockers found” must be distinguishable from “requirements not assessed.” [inferred: 1-handoff-brief.txt, null and evidence invariants]

The downstream selection uses the existing `go`, `no_go`, and `review` vocabulary: `go` records a supported decision to pursue, `no_go` records the policy/evidence reason not to pursue, and `review` exposes unresolved decisions requiring owner input. [inferred: contracts/04-owner-separated-write-domains.yaml, ProductSelection; 6-get-a-job.xml.txt, job_search_queries.txt]

A `go` decision is not dispatch permission: material approval, task authority, target identity, and prior-attempt ambiguity must still be checked before commissioning executable work. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION; contracts/02-external-connector.yaml, EXT-AUTHORITY]

No score weights, salary constants, rank thresholds, or automatic rejection cutoffs are established by this PRD; introduce them only as explicit, versioned candidate policy supported by review. [uncertain: the supplied sources provide scoring concepts but no complete current rubric; obtain owner-approved rules and evaluate them against labeled examples]

A reviewer must be able to inspect why a job ranked above another, identify the strongest evidence and largest uncertainty, and override the proposed selection with an attributed reason. [proposed: optimize for accountable candidate decisions rather than opaque ranking]

## 5. Truthful materials and human approval

Materials must translate supported experience into the employer’s vocabulary without inventing credentials, employers, dates, accomplishments, titles held, or numeric results. [inferred: 6-get-a-job.xml.txt, AGENTS.md, capability_profile.txt, and raw_job_history.txt]

A functional headline may explain relevance, but it must not silently replace an actual employment title in an employer’s work-history field. [proposed: reconcile the legacy functionalTitle concept with truthful employment-history submission]

For each submitted factual answer or substantive resume claim, retain the supporting source or explicit candidate confirmation; discrepancies and missing answers become review questions rather than model-completed facts. [proposed: make tailored content auditable and prevent plausible fabrication]

The legacy `fabricationLog` field is not authorization to fabricate; preserve any imported value as historical source material and require review rather than silently interpreting it as verified candidate evidence. [inferred: 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md; decisions/invariants-and-provisionals.md, §8.3]

The exact resume, cover letter, supplemental responses, and other submitted artifacts must be pinned to the commission; updating a working copy must not change the bytes authorized for an already prepared attempt. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION; contracts/02-external-connector.yaml, EXT-PREPARATION-PIN]

Initial production operation requires human review of selection, materials, and final submission; broader automation requires explicit authorization for a particular origin/task/subject scope with evidenced correlation and recovery behavior. [extracted: decisions/invariants-and-provisionals.md, P-14]

Job descriptions, employer pages, emails, and model outputs must be treated as untrusted content, not instructions that can change candidate facts, permissions, recipient addresses, or execution policy. [proposed: prevent externally supplied text from becoming authority over application actions]

## 6. Commissioning Circus Tent or Ringmaster

### 6.1 Product choice, not internal-driver choice

job-hunter selects an independently identified execution product and configuration through the shared asynchronous connector; it does not import Playwright, Camoufox, BrowserOxide, or a shared element abstraction to perform the application itself. [inferred: 1-handoff-brief.txt, external/internal protocol distinction; current request, Products]

Circus Tent and Ringmaster must remain separately identifiable in evaluation, assistance, browser-state policy, learning-state policy, cost, and outcome views; results from one do not certify the other. [inferred: 1-handoff-brief.txt, independent products and per-version capability rules]

Circus Tent’s compatibility route and intended Firefox-extension route likewise require separate descriptors and evidence; job-hunter must not treat a product name as proof of a particular internal route’s capability. [inferred: decisions/invariants-and-provisionals.md, P-04; prd/00-integration.md, Browser architecture]

### 6.2 Required commissioning sequence

| Stage | Product obligation |
|---|---|
| Check the work | Resolve selection/material approval, target scope, authorized actions, and any prior unresolved attempt before dispatch. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION and idempotency rules] |
| `Describe` | Pin the exact subject/version/mode/interface descriptor, mappings, capabilities, and limits; assess whether they are adequate for this task without converting declarations into qualification. [extracted: contracts/02-external-connector.yaml, EXT-DESCRIBE and EXT-DECLARE-NOT-ASSESS] |
| Plan, if required | Supply an explicit plan through a separately recorded planning step using permitted public inputs and disclosed cost; the documented Circus Tent `/run` surface accepts steps rather than goals. [extracted: 3-hellscape-blueprint.md, §5.4; contracts/02-external-connector.yaml, native reconciliation] |
| Commission | Freeze attempt identity, kind, candidate, job snapshot, target, task, subject configuration, assistance, permissions, and owner bindings. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION] |
| `Prepare` | Validate the supplied work and record limitations without target navigation, login probing, context reset, hidden planning, or plan improvement. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE] |
| `Start` | Use the pinned preparation and logical idempotency key; retain the returned local handle and distinguish local admission from native acceptance. [extracted: contracts/02-external-connector.yaml, EXT-START and EXT-IDEMPOTENCY] |
| `Observe` and `CollectArtifacts` | Consume journal-backed observations and available artifacts, retaining explicit missingness, raw-response references, mapping versions, and source/correlation checks. [extracted: contracts/02-external-connector.yaml, EXT-OBSERVE, EXT-NORMALIZE, and EXT-ARTIFACTS] |
| Close or intervene | Use `RequestNativeCancel`, `CloseObservationConnection`, `ReleaseNativeContext`, and `Contain` as separately authorized and evidenced operations; never collapse them into a successful “cancel.” [extracted: contracts/02-external-connector.yaml, EXT-CLOSE and EXT-CONTROLS] |

All nine verbs are recognized by the contract, but a particular subject may lack a native mapping; job-hunter must handle honest unsupported results without inventing endpoints or assuming native absence from a connector mapping gap. [extracted: contracts/02-external-connector.yaml, EXT-SURFACE and EXT-DESCRIBE]

Required unsupported context or budget policies block preparation; expressly permitted best-effort policies require visible acceptance of their limitations, not silent downgrading. [extracted: contracts/02-external-connector.yaml, EXT-STATE-POLICY and EXT-PREPARATION-PIN]

### 6.3 Recovery without duplicate applications

Durable product work records must be sufficient to recover the existing commission, preparation, command identity, idempotency key, and connector handle after restart; queue notifications alone cannot be the authority for whether a dispatch occurred. [proposed: apply the operational-outbox discipline to job-hunter scheduling without selecting a storage engine]

A timeout or crash around delivery does not authorize a new key, a new attempt, or a switch to the other executor; preserve dispatch uncertainty until stronger evidence or an explicitly authorized recovery path resolves it. [extracted: contracts/01-application-attempt-lifecycle.yaml, idempotency reconciliation; contracts/02-external-connector.yaml, EXT-FAILURE]

Authorized resume must use the existing logical execution and the evidenced native checkpoint/idempotency contract, with compatible context and explicit recovery authority; local lease expiry is not permission to repeat a side effect. [extracted: contracts/02-external-connector.yaml, EXT-RESUME]

Changing the task, target, subject version, or immutable execution configuration creates a new attempt, but that identity rule does not bypass review of an unresolved earlier submission. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION and idempotency rules]

A human takeover must retain assistance and context evidence; a mixed executor/human attempt cannot be relabeled as wholly manual or fully unattended to simplify reporting. [inferred: 5-browser-qualification.md, evidence discipline; prd/00-integration.md, Day-one production lane]

## 7. Tracking outcomes without manufacturing truth

### 7.1 The five axes remain visible

| Axis | Authority | Product interpretation |
|---|---|---|
| Dispatch | Connector | Delivery intent, local identity, acceptance evidence, rejection, or uncertainty. [extracted: contracts/01-application-attempt-lifecycle.yaml, ownership] |
| Observation | Connector, or the designated manual recorder | Observation window, local bounds, close-time knowledge, and late evidence. [extracted: contracts/01-application-attempt-lifecycle.yaml, ownership and LIFE-MANUAL] |
| Execution | Subject | Authenticated, correlated claims retained at their original scope. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-CLAIMS] |
| Application | Origin | Fixture transaction evidence for practice or verified employer-origin evidence for production. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-ORIGIN] |
| Report | Reconciler | Comparisons over pinned input revisions, never corrections to either source axis. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-RECONCILE] |

The product may offer a concise summary, but users must be able to inspect its source axes, evidence, and freshness; a summary cannot become a sixth authoritative attempt status. [inferred: 1-handoff-brief.txt, no-single-status invariant; contracts/04-owner-separated-write-domains.yaml]

A subject’s `/run completed`, a submit click, `None`, HTTP 200, or a callback signature is not by itself an application commitment; authentication, correlation, claim scope, and origin evidence are separate checks. [extracted: 3-hellscape-blueprint.md, §§1.3 and 4.6; 5-browser-qualification.md]

Wholly manual attempts have no fabricated subject claim or native run; their dispatch and execution slots remain explicitly inapplicable while the origin-fact path can still establish commitment. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-MANUAL]

### 7.2 Closure and late evidence

Closing observation stops the product’s active workflow commands within the commissioned bounds, but does not prove native termination or rollback of already dispatched employer work. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-CLOSE; contracts/02-external-connector.yaml, EXT-CLOSE]

A later correlated receipt creates new immutable source publications and reconciliation, preserving the close-time view; honest earlier outcome-unknown is not contradicted merely because commitment becomes known later. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LATE-EVIDENCE and reconciliation algorithm]

Receipt arrival time alone cannot prove when an employer operation occurred, and absence of a receipt cannot establish final non-commitment. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-TIME and LIFE-ORIGIN]

### 7.3 Correspondence, interviews, and eventual outcomes

The source product includes classified email, application tracking, interview scheduling, reminders, and preparation artifacts; these remain product capabilities, but they are not prerequisites for the first application. [inferred: 6-get-a-job.xml.txt, AGENTS.md and docs/contracts/firestore-collections.md]

Initially, the operator may import correspondence and record actions manually; later Gmail and calendar adapters must preserve original evidence and use separately authorized outbound operations. [proposed: incrementally automate follow-up without making external account integration a day-one dependency]

Employer responses such as interview invitations, rejection notices, or offers should be retained as evidence-backed product outcome history, separate from the submission-commitment fact. [proposed: track the application through its real outcome without overloading the lifecycle’s application axis]

A rejection after submission does not erase that the application was committed, and an interview invitation does not silently prove which of several similarly named attempts produced it. [inferred: contracts/01-application-attempt-lifecycle.yaml, source correlation and immutable fact rules]

Uncertain correspondence matching requires review rather than attachment by company/title alone; sending follow-up, accepting calendar changes, withdrawing, or reapplying requires authority for that action. [proposed: avoid miscorrelated outcomes and unauthorized external effects]

Follow-up cadence, outbound templates, and autonomous-send policy are not determined by the sources; obtain candidate preferences and actual API documentation before enabling those effects. [uncertain: the supplied collection summary and API index do not define follow-up business rules or executable integrations]

## 8. Data ownership and implementation boundaries

### 8.1 Logical records, not a shared mutable database

For a discovered job, the crawler owns acquisition, content, render, processing, classifier provenance, and coverage; job-hunter owns downstream evaluations, materials, selection, priority, work ownership, and attempt links. [extracted: contracts/04-owner-separated-write-domains.yaml, job domain layout]

job-hunter must never update crawler-owned content to make an evaluation pass, nor treat an attempt link or downstream selection as evidence that an application committed. [inferred: contracts/04-owner-separated-write-domains.yaml, job exclusions]

Each domain publishes complete immutable revisions asynchronously; readers consume a complete old-or-new logical row at a named version vector, not a cross-owner transaction or an unpinned merge. [extracted: contracts/04-owner-separated-write-domains.yaml]

On different-fetch-key replacement, the complete prior published logical row—including downstream data—is archived with immutable content addressing and transitive retention; evaluations and commissions remain pinned to their original inputs. [inferred: contracts/04-owner-separated-write-domains.yaml, archive rules and EvaluationReference]

The retained same-fetch-key rule remains a content-write no-op; job-hunter cannot request a fabricated nonce or overwrite crawler data as an undocumented freshness workaround. [extracted: decisions/invariants-and-provisionals.md, §5]

Work leases are fenced ownership records rather than application or pipeline outcomes; claiming a job for preparation does not make it submitted. [inferred: 2-state-bank-crawler-blueprint.json, lease discipline; contracts/04-owner-separated-write-domains.yaml, DownstreamOwnership]

### 8.2 Reconcile the legacy collections

| Legacy concept | Current disposition |
|---|---|
| `jobs` | Source-backed job data composes crawler and downstream domains; legacy `status` does not own the attempt’s outcome. [inferred: 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md; contracts/04-owner-separated-write-domains.yaml] |
| `evaluations`, `artifacts`, `noGoList` | Retain their product purposes using versioned evidence-backed artifacts and decisions; do not assume the summary table supplies complete types or business rules. [inferred: 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md] |
| `trackers` | A product projection over commissions, source axes, verified receipts, correspondence, and follow-up—not an alternative application authority. [inferred: contracts/01-application-attempt-lifecycle.yaml; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md] |
| `emails`, `schedules` | Product-owned correspondence and action projections with retained source evidence and explicit external-action authorization. [proposed: preserve the source purposes while applying the shared authority discipline] |
| `settings`, `vault`, `costs` | Candidate policy, secret custody, and cost accounting remain distinct concerns; the listed collections do not force Firestore as the storage engine. [inferred: 1-handoff-brief.txt, Firebase provisional; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md] |
| `tasks`, `logs` | Durable scheduling and operational diagnostics may support the product, but neither a task row nor ordinary logs replace the evidence journal. [inferred: 1-handoff-brief.txt, journal invariant; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md] |

The legacy job hash based on company/title/location and application key based on company/title may suggest duplicates; neither may automatically merge distinct requisitions, origins, or attempts. [inferred: decisions/invariants-and-provisionals.md, §5]

### 8.3 Language, storage, and UI

Production language and canonical storage remain undecided: the former TypeScript/Restate/Firebase direction is not binding after the Stagehand rationale changed. [extracted: 1-handoff-brief.txt, provisional decisions; decisions/invariants-and-provisionals.md, P-07 and P-15]

Choose at the durable scheduling/storage implementation boundary using maintenance cost, model/API library fit, contract validation, restart behavior, and independently owned publication; a small manual recorder does not settle the final service language. [proposed: make the deferred decision at its actual dependency boundary rather than reopening the job search around it]

The dashboard remains TypeScript/Angular over HTTP and may use Firebase only as a useful dashboard projection backend; it must not become canonical cross-component exchange or a second writer of source domains. [extracted: 1-handoff-brief.txt, semantic boundaries and Firebase provisional]

A receipt recorder or reconciler may be deployed alongside product services, but its authority and write grants remain separate; co-location does not let the product writer manufacture employer facts or edit execution claims. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES; contracts/04-owner-separated-write-domains.yaml]

Candidate artifacts and raw evidence containing personal data remain restricted, secrets stay out of repositories and ordinary logs, and runtime access uses authorized references rather than embedding control credentials in tasks. [inferred: 6-get-a-job.xml.txt, AGENTS.md; contracts/02-external-connector.yaml, EXT-AUTHORITY]

## 9. Learning that serves applications

Hellscape practice is a separate lane: it may reuse job text, but its forms remain laboratory fixtures and its commitments never enter the production count. [extracted: 1-handoff-brief.txt, Hellscape invariant; contracts/01-application-attempt-lifecycle.yaml, LIFE-LINEAGE]

`kind` is immutable; `derived_from` is same-kind, while rehearsal/performance links refer to already commissioned identities and do not transfer evidentiary credit. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LINEAGE]

The first automated product integration exercises the cooperative Hellscape fixture after silo conformance; subject non-completion is a diagnostic result, not a requirement to suspend manual production work or repair every executor first. [inferred: 1-handoff-brief.txt, Roadmap; 3-hellscape-blueprint.md, M1–M2; decisions/invariants-and-provisionals.md, HA-03]

Production and practice diagnostics may motivate product-specific suggested fixes when their evidence supports scope, attribution, required conditions, contraindications, and a verification plan; unsupported suggestions remain explicitly missing. [inferred: contracts/05-suggested-fix-registry.yaml; 1-handoff-brief.txt, fix-registry definition]

Human approval of a rule class does not prove an implementation improved, and a selector-cache update is not automatically a reviewed registry fix; new executor versions require their own evidence. [extracted: decisions/invariants-and-provisionals.md, INV-14 and INV-30]

Selection feedback should also be evidence-backed: use candidate review and observed outcomes to propose policy changes, without assuming that rejection proves inability or that silence identifies a particular scoring defect. [proposed: improve relevance without inventing causal explanations for employer behavior]

### 9.1 Operating view

The operating view must separately show opportunities captured, evaluations completed, decisions awaiting input, approved work, production attempts, verified origin commitments, unresolved outcomes, and next follow-up actions. [proposed: make actual job-search progress and unresolved work visible]

Manual assistance, model cost, and operator effort should remain attributable to the work they supported; missing cost or timing is not zero, and manual work is not hidden to inflate automation rates. [inferred: 5-browser-qualification.md, evidence discipline; 6-get-a-job.xml.txt, costs collection]

Practice throughput, browser benchmarks, fix proposals, and engineering milestones belong in separate views rather than the application funnel. [inferred: 1-handoff-brief.txt, practice/production and anti-avoidance invariants]

## 10. Delivery and acceptance

### 10.1 Incremental delivery

| Increment | Independently useful result | Explicit non-prerequisites |
|---|---|---|
| Manual product lane | Capture, evaluate, tailor, commission, apply, retain receipt/uncertainty, and identify the next action. | Automated discovery, LLM reranking, Hellscape, browser execution, registry deployment, or dashboard completion. [inferred: decisions/invariants-and-provisionals.md, HA-03] |
| Feed and evaluation automation | Consume pinned jobs and produce reviewable candidate-specific evaluations while manual application continues. | Ringmaster DOM work, every crawler state, or a deployed autonomous scheduler. [inferred: 1-handoff-brief.txt, minimal-slice and parallel delivery rules] |
| Commissioning automation | Durable preparations and connector calls against synthetic backends, including ambiguous-delivery recovery. | A live executor or employer in CI. [inferred: 1-handoff-brief.txt, silo gate; contracts/02-external-connector.yaml] |
| Cooperative practice integration | Correct commissioning, observation, reconciliation, and assistance disclosure against Hellscape. | Subject completion or production-qualification credit. [extracted: 3-hellscape-blueprint.md, M2; 1-handoff-brief.txt, Roadmap] |
| Scoped production automation | Candidate-authorized execution with evidenced origin correlation and recovery behavior. | Universal ATS support or elimination of manual takeover. [proposed: promote only demonstrated scopes under P-14] |
| Follow-up and learning automation | Reviewed correspondence, next-action scheduling, and supported policy/execution improvement. | It must not become a prerequisite for continuing application activity. [inferred: current request, Purpose; 1-handoff-brief.txt, Anti-patterns] |

There is no revived M0 qualification phase; retired qualification lessons are enforced through conformance and retained fixtures. [extracted: 1-handoff-brief.txt, m0 retirement; 3-hellscape-blueprint.md, Product sequence]

### 10.2 Silo acceptance scenarios

These proposed product acceptance scenarios run against retained local fixtures and synthetic peers before peer integration; they supplement the shared suites rather than replace them. [proposed: give job-hunter an independent, deterministic shipping gate]

| ID | Scenario | Required oracle |
|---|---|---|
| JH-01 | All automated peers absent | A manually sourced job can reach a recorded production attempt and evidence-backed outcome/uncertainty without fabricated crawler or subject fields. [proposed: acceptance for HA-03 and LIFE-MANUAL] |
| JH-02 | Cross-domain fit without title overlap | A synthetic posting is evaluated using named playbooks and concrete candidate evidence; the decision is explainable without relying on title equality. [proposed: acceptance for candidate-centered matching] |
| JH-03 | Missing pay, uncertain degree substitution, or license status | Uncertainty is visible and drives review where consequential; no fabricated threshold, credential, waiver, or zero-valued score appears. [proposed: acceptance for policy completeness and kernel missingness] |
| JH-04 | Material-generation overclaim | An unsupported degree, date, employment title, or numerical accomplishment cannot pass approval without source evidence or candidate correction. [proposed: acceptance for truthful material preparation] |
| JH-05 | Changed job/profile after evaluation | The original evaluation and commission retain their exact inputs; a new decision is a new version rather than silent reinterpretation. [proposed: acceptance for immutable decision inputs] |
| JH-06 | Incomplete crawler partition and valid posting | The posting remains evaluable with visible coverage limitations; search completeness is not claimed. [proposed: acceptance for honest discovery consumption] |
| JH-07 | Concurrent owner publication and replacement | Readers see complete pinned views, downstream writes do not modify crawler fields, and archived prior rows retain downstream evaluations and materials. [proposed: acceptance for owner-separated job records] |
| JH-08 | Lost response after Start | Existing identity and uncertainty survive restart; retry creates neither a second logical execution nor an automatic executor switch. [proposed: acceptance for EXT-IDEMPOTENCY and EXT-FAILURE] |
| JH-09 | Native completion without receipt | Execution claim is retained, application commitment remains unestablished, and the product does not increment verified commitment counts. [proposed: acceptance for LIFE-CLAIMS and LIFE-ORIGIN] |
| JH-10 | Close followed by late correlated commitment | Original closure remains intact, new facts and report revisions appear, and earlier honest uncertainty is not falsely contradicted. [proposed: acceptance for LIFE-LATE-EVIDENCE] |
| JH-11 | Real job text used in Hellscape | The attempt remains practice/held-in; its result cannot authorize production or enter production counts. [proposed: acceptance for LIFE-LINEAGE] |
| JH-12 | Ambiguous email match or follow-up authority | Correspondence remains unassigned/reviewable and no outbound action occurs without the required authorization. [proposed: acceptance for safe follow-up] |
| JH-13 | Missing or unsupported fix evidence | The product retains the finding and explicit missing recommendation without patching an executor or claiming improvement. [proposed: acceptance for the schema-only learning boundary] |

The applicable kernel, lifecycle, connector-consumer, owner-separated-write, and fix-record validations must pass independently; job-hunter consumes browser capability evidence but does not claim to have implemented either internal binding. [inferred: 1-handoff-brief.txt, silo discipline; current request, Products]

CI must not perform live employer writes; real applications are separately authorized operations, and their observed results must never be synthesized from fixture results. [extracted: 6-get-a-job.xml.txt, AGENTS.md; 5-browser-qualification.md]

Exact executable verification commands remain to be specified in the chosen implementation modules; the sources do not supply a current job-hunter codebase or command that this PRD can honestly claim has passed. [uncertain: implementation language, module manifests, and executable test runner are not supplied; define deterministic commands when those modules are specified]

## 11. Open decisions and evidence needed

| Question | Resolution and interim behavior |
|---|---|
| Current candidate policy | Obtain explicit pay, schedule, travel, geography/address, credential, and disclosure decisions; use review rather than invented defaults until resolved. [uncertain: current policy values are incomplete in 6-get-a-job.xml.txt] |
| Formal evaluation rubric | Review labeled candidate/job examples and choose a versioned rubric if numeric ranking adds value; retain qualitative human evaluation meanwhile. [uncertain: the supplied reranker prompt does not establish weights, calibration, or thresholds] |
| Production language and storage | Choose at the durable implementation boundary and prove restart, idempotency, owner publication, and operational maintainability; keep manual operation independent. [extracted: decisions/invariants-and-provisionals.md, P-07] |
| Employer receipt mappings | Establish source verification, candidate/job/attempt correlation, and temporal scope per origin; use a reviewed manual receipt policy before an automated adapter if necessary. [uncertain: current production origin mappings are absent; contracts/01-application-attempt-lifecycle.yaml, open evidence] |
| Autonomous production scope | Candidate authorization plus evidenced task/subject/origin behavior can change the initial human-controlled policy; practice completion alone cannot. [extracted: decisions/invariants-and-provisionals.md, P-14] |
| Existing Firestore migration | Inspect actual producers and executable schemas before importing values; the collection table is not sufficient to infer every type, timestamp, status, or authority. [uncertain: shared/firestore-contracts and actual legacy records are not supplied] |
| Email/calendar integration | Obtain current API documentation, account permissions, correlation rules, and outbound-action policy; manual follow-up remains available. [uncertain: docs/external/README.md lists integrations but does not supply their executable contracts] |
| Actual operating results | Collect real evaluation, attempt, receipt, follow-up, and effort evidence through the day-one lane; this draft contains no observed application throughput or hiring result. [uncertain: operational evidence is not supplied] |

The product must make applying easier before making automation impressive: replace one manual step at a time, preserve what actually happened, and keep pursuing suitable work while the machinery improves. [inferred: current request, Purpose; 1-handoff-brief.txt, Anti-patterns and Roadmap]
