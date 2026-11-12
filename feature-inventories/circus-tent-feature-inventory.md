# Circus Tent (`circus-tent`) — Lossless Technical Feature Inventory

Source Blueprint: `full-featured-blueprints/4-circus-tent-arch.md` (`ARCHITECTURE.md — circus-tent`, Version 1.0)

---

## 0. Architectural Principles, Purpose, Technology Stack & Global System Topology (§1, §2, §3, §4, §8, §9)

### 0.1 Purpose & Scope (§1)
- Production-grade web-automation framework for **high-concurrency, stateful interaction with heavily fortified enterprise portals**:
  - **Applicant Tracking Systems (ATS):** Workday, Greenhouse, Lever, NEOGOV (`governmentjobs`).
  - **Job Boards:** Indeed, LinkedIn.
- Core operational requirements:
  - Execute hundreds of concurrent automation tasks without saturating host CPU, memory, or sockets.
  - Mimic natural power-user traffic to avoid anti-bot detection.
  - Persist authenticated sessions across runs, including MFA state.
  - Extract structured content from SPAs without per-page LLM token costs.
  - Self-heal when targets change DOM structure.
  - Expose programmatic entry points (REST + MCP) usable by external orchestrators.
- Explicit non-goals: Not a general-purpose scraper; not for anonymous public crawling. It is a stateful, credentialed harness for a bounded set of high-value targets.

### 0.2 Binding Architectural Principles (§2)
1. **Domain isolation over single-browser multiplexing.** One isolated browser process per target domain family.
2. **Bounded parallelism over unbounded tab spawning.** Hard cap of concurrent tab contexts per shard; surge traffic is queued, never absorbed by flooding.
3. **Text-first intelligence.** Selection, navigation, recovery rely on semantic textual structure. Visual analysis is a late-stage fallback only.
4. **Local extraction over remote LLM extraction.** BM25 / cosine / markdown chunking first; LLMs only for self-healing and vision fallback.
5. **Fingerprint immutability per profile.** A profile's fingerprint never changes. Changing it requires a full profile reset and MFA re-handoff.
6. **Secrets live in the environment, never in git.** Config files reference env var names only. Dev convenience: `.env` at repo root (gitignored, `chmod 600`), loaded at startup when no richer source exists; production exports real env vars.
7. **Single-runtime implementation.** Python-native end-to-end. No cross-language serialization, no sidecar HTTP pipes, no dual-runtime state.
   - Rationale: Camoufox's stealth lives at the C++ engine level and its Python API is the reference implementation. Crawl4AI is Python-native. Single runtime eliminates cross-language silent-failure risk and serialization boundaries.

### 0.3 Technology Stack (§3)

| Layer | Technology | Role |
|---|---|---|
| Browser engine | Camoufox 0.5.7 (Python API) | Stealth Firefox, C++-level fingerprint injection |
| Browser driver | Playwright async API (bundled with Camoufox) | Tab/context lifecycle, navigation, evaluation |
| Extraction | Crawl4AI (in-process) | BM25 / pruning content filters, markdown generation |
| Text-healing model | Muse Spark 1.3 Contributor via OpenCode Go | Selector recovery from pruned DOM |
| Vision fallback model | DeepSeek V4 Flash Vision Exp via OpenCode Go | Bounding-box localization from screenshots |
| LLM conduit | LiteLLM | Token counting, budget enforcement, provider failover |
| API framework | FastAPI (ASGI / uvicorn) | REST endpoints + MCP server mounting |
| MCP server | mcp.server.fastmcp.FastMCP | Tools over Streamable HTTP (WebSocket transport forbidden) |
| Fairness / concurrency | asyncio primitives + custom fair-share semaphore | Tab slot distribution across sessions |
| Challenge resolution | CapSolver | Bot-wall bypass hooks; all task types ship enabled |
| Telemetry | OpenTelemetry (W3C traceparent) + prometheus-client + structlog-style JSON | Traces, metrics, structured logs |

### 0.4 System Architecture Diagram (§4)

```
                         External callers (MCP clients, REST consumers, orchestrators)
                                          │  HTTP / Streamable HTTP
┌─────────────────────────────────────────▼──────────────────────────────────────┐
│ API Layer (FastAPI + FastMCP, one ASGI app, 127.0.0.1:8000)                    │
│ /run /extract /health /shards /metrics   MCP at /mcp: run, extract, health,    │
│ list_shards                                bearer auth + per-caller scoping     │
│ idempotency_key on /run; optional callback_url; audit log per call             │
└─────────────────────────────────────────┬──────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────▼──────────────────────────────────────┐
│ Fairness & Concurrency Layer                                                    │
│  shard Semaphore(12)  •  per-account quota (default 3)  •  fair-share FIFO      │
│  back-pressure: Retry-After + X-Queue-Depth headers, 429 at depth > 1000        │
│  per-caller rate limit (independent of session quotas)                          │
└─────────────────────────────────────────┬──────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────▼──────────────────────────────────────┐
│ Cluster Manager                                                                 │
│  domain→shard routing (declaration order, misc="*" last)                        │
│  lifecycle: INITIALIZING→READY→DRAINING→TERMINATED                              │
│  recycle at pages_processed ≥ 500; same-profile boot AFTER old process exits    │
│  target-side rate limiter (RPM ceilings, 429/403/503/challenge backoff, cooldown)│
└──────┬────────────────────┬────────────────────┬───────────────────────────────┘
       │                    │                    │
┌──────▼─────┐      ┌───────▼──────┐      ┌──────▼────────┐
│ workday    │      │ greenhouse   │ ...  │ misc          │   (7 shards incl.
│ ≤12 tabs   │      │ ≤12 tabs     │      │ ≤12 tabs      │   governmentjobs,
│ pinned fp  │      │ pinned fp    │      │ pinned fp     │   indeed, linkedin)
└──────┬─────┘      └───────┬──────┘      └──────┬────────┘
       └────────────────────┼────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────────────────┐
│ Execution Engine                                                                 │
│  preflight (session validity) → Learn-Run-Heal state machine                     │
│  step types: navigate fill click select wait extract assert upload checkpoint   │
│  Tier 1 run (cached selectors, zero tokens) / Tier 2 heal (text model) /        │
│  Tier 3 vision (localized crop → perceptual-hash coordinate cache)              │
│  idempotency ledger, checkpoints keyed by idempotency_key                       │
└───────────────────────────┬─────────────────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────────────────────┐
│ Extraction Pipeline (in-process)                                                │
│  SPA stabilization (network idle 500ms / DOM quiet 300ms / text hydration)      │
│  in-browser pruning via page.evaluate() — EXTRACT ≤250KB, HEAL ≤50KB profiles   │
│  Shadow-DOM uncloaking + iframe frame flattening (recursive, cross-frame)       │
│  Crawl4AI AsyncWebCrawler.arun(html=...) → BM25/Pruning filters → markdown       │
│  deterministic schema-guided extraction (schema_incomplete flag, no LLM)        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. 7-Shard Topology & Resource Controls (§5.1, §5.3, §5.9, §6.2, §9)

### 1.1 7-Shard Registry & Domain Routing (`src/circus_tent/browser/cluster_manager.py`, `config/shards.yaml`)
- **Configuration File:** `config/shards.yaml` (`schema_version: 1`).
- **Shard Roster (7 Shards v1):**
  1. `workday` — Single shared Workday shard (all tenants routed through one profile).
  2. `greenhouse` — Greenhouse ATS domain family.
  3. `lever` — Lever ATS domain family.
  4. `governmentjobs` — NEOGOV (`governmentjobs`) ATS domain family (live account configured).
  5. `indeed` — Indeed job board domain family.
  6. `linkedin` — LinkedIn job board domain family (live account configured).
  7. `misc` — Catch-all shard declared last, matching pattern `"*"`.
- **Routing Algorithm:**
  - Routes incoming tasks to shards by domain pattern in **declaration order** (first match wins; `misc` is always last and matches `"*"`).
- **Persistent Profile Paths & Permissions:**
  - Each shard is bound to a domain family and an isolated persistent profile directory under:
    `~/.automation-wrapper/profiles/<name>/` with filesystem mode `0700` (`rwx------`).

### 1.2 Concurrency Layer 1 & Layer 2: Semaphore(12), Per-Account Quotas & Fair-Share FIFO (`src/circus_tent/api/fairness.py`, `src/circus_tent/browser/cluster_manager.py`)
- **Layer 1 — Per-Shard Tab Concurrency (`max_tabs`):**
  - Enforces `max_tabs` (default `12`) concurrent tab contexts per shard via `asyncio.Semaphore(12)` (`asyncio.Semaphore(max_tabs)`).
- **Layer 2 — Per-Account Session Quota:**
  - Enforces a per-account concurrent tab quota (default `3` concurrent tabs).
  - Keyed strictly on the **registered account** (`config/accounts.yaml`); caller-supplied `session_id` values are informational only and do not create extra quota buckets.
- **Fair-Share FIFO Permit Distribution:**
  - Distributes tab permits across waiting accounts/sessions using fair-share FIFO ordering so no session starves another under contention (~100 concurrent sessions expected; queueing is the intended design).
- **Independent Per-Caller Rate Limit:**
  - Enforced at the API layer (`config/callers.yaml`) independently of per-account session tab quotas.
- **Concurrency Telemetry Metrics:**
  - Tracks permit-acquisition wait time, queue depth, and per-session utilization.

### 1.3 Backpressure & Queue Depth Controls (`src/circus_tent/api/fairness.py`)
- Requests exceeding available shard/account permits are queued (never absorbed by unbounded tab spawning and never silently dropped).
- **Response Headers on Queued / Backpressured Traffic:**
  - `Retry-After`: indicates backoff delay for callers.
  - `X-Queue-Depth`: exposes current shard/fairness queue depth.
- **Hard Queue Ceiling:**
  - When queue depth exceeds `1000` (`depth > 1000`), requests are rejected explicitly with **HTTP `429 Too Many Requests`** carrying both `Retry-After` and `X-Queue-Depth` headers.
  - Zero silent drops: every request either succeeds or receives explicit HTTP 429 backpressure.

### 1.4 Target-Side Rate Limiter (B6) (`src/circus_tent/browser/cluster_manager.py`)
- Hosted inside the Browser Cluster Manager:
  - **Per-shard request-per-minute (RPM) ceiling.**
  - **Per-session step ceiling.**
  - **Per-shard automatic backoff** triggered on target HTTP `429`, `403`, `503`, or detected anti-bot challenge pages.
  - **Cooldown window** during which the shard's `pages_processed` counter is frozen.

### 1.5 500-Page Profile Recycling Loop with PID Exit Reaping (`src/circus_tent/browser/cluster_manager.py`, `src/circus_tent/browser/shard.py`, §6.2)
- **Trigger Condition:**
  - Cluster manager tracks `pages_processed` per shard and triggers recycling when `pages_processed >= recycle_after_pages` (default `500` pages).
- **7-Step Deterministic Recycle Sequence:**
  1. **Drain Routing (`DRAINING`):** Transition shard state to `DRAINING` and stop routing new work to the shard.
  2. **Grace Wait for In-Flight Contexts:** Wait for all in-flight tab contexts to complete, up to a configurable grace timeout (default `60s`).
  3. **Flush Sequence:** Close all contexts via the explicit **flush sequence** — persist session state explicitly before closing each context, then close the browser.
  4. **PID Exit Reaping (Critical Lock Safety):** **Wait for the old browser process to fully exit (PID reaped)** before starting the replacement. Firefox writes cookies and storage asynchronously on shutdown; spawning a replacement process against the same profile directory while the old process still holds profile locks corrupts the profile.
  5. **Same-Profile Replacement Launch:** Launch the replacement browser instance from the **exact same profile directory** with the **exact same pinned `fingerprint.json` manifest**. No snapshot or copy of `user_data/` is ever made while a browser process is alive. Recycling **never** rotates fingerprints.
  6. **Health Check & Atomic Swap:** Health-check the replacement browser (navigate `about:blank`, verify page responds, verify runtime fingerprint hash matches manifest); atomically swap the active shard reference in the cluster registry; transition shard state to `READY` and resume routing traffic.
  7. **Event Emission & Monitoring:** Emit a `shard_recycled` event logging old PID, new PID, `pages_processed` count, and elapsed recycle duration. A spike in `shard_recycled` frequency indicates a memory leak or target-side behavior change.

---

## 2. Fingerprint Persistence & Lifecycle (§5.2, §5.3, §6.1, §6.4)

### 2.1 Launch Options Manifest Generation & Pinned Identity (`src/circus_tent/browser/fingerprint.py`)
- **First Initialization of a Profile Directory (Bootstrap):**
  - Resolves the full Camoufox launch-options bundle — combining both the **launch flags** AND the **generated identity** via Camoufox's own generator:
    - Operating System (`OS`)
    - `navigator` properties
    - `screen` dimensions/metrics
    - `fonts` list
    - `WebGL` vendor and renderer
    - `canvas` surface fingerprint
    - `audio` surface fingerprint
  - Serializes the complete resolved bundle to `{profile_dir}/fingerprint.json`.
- **Subsequent Launches:**
  - Every subsequent launch loads `{profile_dir}/fingerprint.json` and passes the pinned options back to the Camoufox launcher:
    - `persistent_context=True`
    - `fingerprint=<bundle>`
    - `os=<pinned>`
    - `i_know_what_im_doing=True`
    - `humanize=True`
    - `headless=<configured_mode>` (`False` for bootstrap, `"virtual"` for production)
  - Without explicit pinning of `fingerprint=<bundle>`, `os=<pinned>`, and `i_know_what_im_doing=True`, Camoufox randomizes the OS and WebGL vendor/renderer on every launch, which triggers anti-bot "new device" detection.
- **Immutability Contract:**
  - `fingerprint.json` is strictly **immutable after first creation** (created only during `circus-tent bootstrap --shard <name>`).
  - Any launch-parameter change requires a **full profile reset**: purge the entire profile directory and manifest, then re-authenticate visually via MFA handoff. Changing a fingerprint without clearing cookies produces a "new device" signal and risks immediate account lockout on ATS platforms.
- **Verification Entry Point:**
  - `python3 <repo>/benchmarks/verify_browser.py` (or benchmark harness C1 with `--with-browser`), verifying identical canvas, WebGL, audio, navigator, screen, and fonts hashes plus an unchanged manifest hash across consecutive launches.

### 2.2 Profile Directory Structure (§5.2)
Located under `~/.automation-wrapper/profiles/<shard_name>/` (permissions `0700`):
```
profiles/<shard_name>/
├── fingerprint.json        # immutable launch-options manifest
├── user_data/              # Camoufox persistent context (cookies, storage)
├── manifest_created_at.txt
└── health.json
```

### 2.3 Shard Lifecycle State Machine & Xvfb Virtual Framebuffer Modes (`src/circus_tent/browser/shard.py`, §6.1)
- **Lifecycle States:**
  `INITIALIZING → READY → DRAINING → TERMINATED`
- **Initialization Sequence (`INITIALIZING → READY`):**
  1. Resolve profile directory and `fingerprint.json` manifest (create if absent on first init/bootstrap).
  2. Launch Camoufox with `persistent_context=True`, pinned manifest (`fingerprint=<bundle>`, `os=<pinned>`, `i_know_what_im_doing=True`), `humanize=True`, and configured headless mode.
  3. Execute startup health check:
     - Navigate to `about:blank`.
     - Verify page responds.
     - Compute live browser fingerprint hash and assert it matches the pinned `fingerprint.json` manifest.
  4. Transition state to `READY`.
- **Headless Execution Modes & MFA Handoff (§5.3, §6.1):**
  - **First-Run / MFA Bootstrap Mode (`headless=False`):**
    - Invoked via CLI: `circus-tent bootstrap --shard <name>`.
    - Launches the shard visually (`headless=False`).
    - Operator completes MFA and onboarding visually in the browser window and confirms completion.
    - Authenticated session state (cookies, IndexedDB, localStorage) persists to `user_data/`.
    - Immutable `fingerprint.json` manifest is written.
    - Browser terminates cleanly via flush sequence.
  - **Production Mode (`headless="virtual"`):**
    - Uses **Xvfb virtual framebuffer** (`headless="virtual"`), loading the pre-authenticated `user_data/` cache and pinned `fingerprint.json`.
    - Standard browser headless mode is detectable and is never used on anti-bot-heavy targets.

### 2.4 Graceful Shutdown Sequence (B7) (§6.4)
- **Signal Handling (`SIGTERM` / `SIGINT`):**
  1. Immediately stop accepting new incoming work.
  2. Drain all in-flight execution steps up to a configurable drain timeout.
  3. Close every active tab context via the profile-safe **flush sequence** (explicitly persisting session state prior to context closure).
  4. Close every shard browser process and wait for clean exit.
  5. Persist selector caches, coordinate caches, execution/idempotency ledger, and telemetry metrics to disk.
  6. Exit with deterministic process status code for the supervisor:
     - `0` = drain completed cleanly within timeout.
     - `1` = forced termination after drain timeout elapsed.
  - Every shutdown path executes the profile-safe flush sequence so deployments never corrupt persistent profiles.

---

## 3. 3-Tier Execution Engine & Model Conduit (§5.6, §5.7, §6.3, §9)

### 3.1 Supported Step Types & Preflight Verification (`src/circus_tent/engine/`)
- **Typed Action Step Vocabulary (9 Step Types):**
  1. `navigate`
  2. `fill`
  3. `click`
  4. `select`
  5. `wait`
  6. `extract`
  7. `assert`
  8. `upload` (B4)
  9. `checkpoint` (D4)
- **Preflight Session Validity Check (B3):**
  - Executed before every `/run` invocation.
  - Navigates to the target shard's configured preflight URL (defined per shard in `config/shards.yaml`) and asserts the presence of the configured authenticated DOM/text marker.
  - If the authenticated marker is absent:
    - Fails fast with error code `SESSION_EXPIRED`.
    - Emits a `session_expired` event so operators can subscribe for re-MFA bootstrap escalation.

### 3.2 Tier 1 — Run (Cached Selectors, Zero LLM Tokens)
- **Workflow:**
  1. Load domain selector cache from `config/selectors/{domain}.json`.
  2. Execute the cached selector for the current `step_id` using Playwright native operations wrapped in `try / except` catching:
     - `TimeoutError`
     - `ElementNotInteractableError`
     - `PlaywrightError`
  3. On execution success:
     - Increment `hit_count` (`hit_count += 1`).
     - Update `last_verified` timestamp (both step-level and file-level).
  4. On caught exception: escalate immediately to **Tier 2 (Heal)**.
- **Selector Cache Schema (`config/selectors/{domain}.json`, `schema_version: 1`):**
  ```json
  {
    "domain": "<domain>",
    "version": 1,
    "last_verified": "<ISO-8601 timestamp>",
    "steps": {
      "<step_id>": {
        "selector": "<CSS/Playwright selector string>",
        "strategy": "<selector strategy>",
        "confidence": 0.95,
        "hit_count": 42,
        "heal_count": 1,
        "fallback_text": "<semantic description / visible label of target element>",
        "last_verified": "<ISO-8601 timestamp>",
        "stale": false
      }
    }
  }
  ```
- **Background Cache Re-Validation & Operational Review (§5.6, §6.3):**
  - A low-priority background task periodically re-validates cached selectors against live pages on a rolling schedule; failing selectors are marked `stale: true` and demoted.
  - Operational review thresholds (§6.3):
    - Steps with `confidence < 0.5` indicate an active target site redesign.
    - Steps with `heal_count > 10` indicate chronic selector instability (requires reviewing `fallback_text` or updating step schema).

### 3.3 Tier 2 — Heal (Text Model Recovery from HEAL-Profile Pruned DOM)
- **Trigger:** Tier 1 cached selector throws `TimeoutError`, `ElementNotInteractableError`, or `PlaywrightError`.
- **DOM Capture:**
  - Execute in-browser pruning script (`page.evaluate()`) using the aggressive **`HEAL` profile (`<= 50KB`)**: layout `<div>`s stripped, wrapper chains collapsed, retaining only interactive elements and textual nodes, with open Shadow DOM uncloaked and nested iframes flattened.
- **Model Invocation & Prompt Inputs:**
  - **Primary Model:** `Muse Spark 1.3 Contributor` via OpenCode Go (`/zen/go/v1/responses`, OpenAI Responses-API format via `MUSE_API_BASE` / `MUSE_API_KEY`).
  - **Ordered Provider Fallback:** `Muse Spark 1.2 Contributor` on timeout or HTTP 5xx.
  - **Prompt Payload Inputs:**
    1. `HEAL`-profile pruned DOM (`<= 50KB`).
    2. Step `fallback_text` (semantic description/target label).
    3. Failed selector string from Tier 1.
- **Strict JSON Response Contract:**
  ```json
  {
    "selector": "<recovered selector string>",
    "strategy": "<css | xpath | text | role | testid>",
    "confidence": 0.85,
    "reason": "<explanation of DOM mutation and recovery logic>"
  }
  ```
- **Programmatic JSON Repair Layer:**
  - Before burning a retry on malformed LLM output, the raw model response is passed through a programmatic JSON repair pipeline using:
    - `partial-json-parser`
    - `llm-json-repair`
  - If parsing/repair still fails or the healed selector fails execution, perform **one retry**, then escalate to **Tier 3 (Vision)**.
- **Cache Write-Back on Heal Success:**
  - Immediately write the replacement selector back to `config/selectors/{domain}.json` with:
    - **Decremented `confidence`**
    - **Incremented `heal_count`** (`heal_count += 1`)
    - Updated `last_verified` timestamp
  - Retry the native Playwright operation with the healed selector.

### 3.4 Tier 3 — Vision (Localized Container Crop + Perceptual dHash Coordinate Cache)
- **Trigger:** Tier 2 text-model heal fails after programmatic JSON repair and one retry.
- **Localized Container Screenshot Crop (`+100px` Padding):**
  - Captures a **localized screenshot crop of the failing container element plus `+100px` padding** around its bounds.
  - **Never captures the full viewport** (full-viewport screenshots degrade both visual token cost and coordinate localization accuracy).
- **Perceptual Hash (`dHash`) Lookup:**
  - Computes the perceptual difference hash (**dHash**) of the localized cropped image.
  - Consults `config/coordinates/{domain}.json` (`phash → coordinates`).
  - **On Cache Hit:**
    - Increment `hit_count` and click the cached center coordinates `(x + width / 2, y + height / 2)` directly without invoking the vision LLM.
  - **On Cache Miss:**
    - Invoke the `vision_fallback` model: `DeepSeek V4 Flash Vision Exp` via OpenCode Go (`/zen/go/v1/chat/completions`, chat-completions format via `DEEPSEEK_API_BASE` / `DEEPSEEK_API_KEY`).
    - Parse the returned **bounding box** (`x`, `y`, `width`, `height`).
    - Click the **geometric center of the bounding box**:
      $$\text{click\_x} = x + \frac{\text{width}}{2}, \quad \text{click\_y} = y + \frac{\text{height}}{2}$$
    - Write the `phash → bounding box` mapping into `config/coordinates/{domain}.json`.
- **Coordinate Cache Schema (`config/coordinates/{domain}.json`, `schema_version: 1`):**
  ```json
  {
    "domain": "<domain>",
    "entries": {
      "<phash_hex>": {
        "x": 120,
        "y": 340,
        "width": 160,
        "height": 44,
        "viewport": {
          "width": 1280,
          "height": 720
        },
        "step_id": "<step_id>",
        "hit_count": 5,
        "created_at": "<ISO-8601 timestamp>"
      }
    }
  }
  ```

### 3.5 Model Registry, LiteLLM Conduit, Token Budgets & Circuit Breaker (`src/circus_tent/engine/models.py`, `src/circus_tent/engine/budgets.py`, `config/models.yaml`)
- **Model Configuration (`config/models.yaml`):**
  - Externalizes all model bindings using environment variable names only (`schema_version: 1`).
  - Roles:
    - `text_healing`: Muse Spark 1.3 Contributor (OpenAI Responses-API format at `/zen/go/v1/responses` via `MUSE_API_BASE`), fallback to Muse Spark 1.2 Contributor.
    - `vision_fallback`: DeepSeek V4 Flash Vision Exp (OpenAI chat-completions format at `/zen/go/v1/chat/completions` via `DEEPSEEK_API_BASE`).
  - Providers are configured as **ordered fallback lists**: a request timeout or HTTP 5xx automatically fails over to the next provider entry in the list.
- **LiteLLM Conduit (B9):**
  - Every LLM call (text healing and vision fallback) routes through **LiteLLM** for unified token counting, pre-call budget enforcement, and provider failover.
  - **Required HTTP Headers on Every Outbound LLM Request:**
    - `User-Agent: circus-tent/<version>`
    - `x-opencode-session: <stable_session_id>` (mandatory OpenCode Go requirement).
- **Token Budgets & Heal Circuit Breaker (B9):**
  - Enforces separate daily token caps **per-session** and **per-shard** for `text_healing` and `vision_fallback`.
  - **Per-Shard Heal Circuit Breaker:** Automatically trips and disables Tier 2/3 healing on a shard when the **heal rate exceeds 30% of steps in a rolling 1-hour window** (signals a major target site redesign requiring human review rather than burning LLM tokens).
  - Exposes Prometheus `/metrics` counters for tokens consumed per shard, per model, per day.

---

## 4. In-Browser Pruning & Extraction Pipeline (§5.4, §5.5)

### 4.1 SPA Stabilization Conditions (`src/circus_tent/parser/trimmer.py`)
Before DOM pruning or extraction runs, the page must satisfy three stabilization conditions:
1. **Network Idle:** Zero in-flight network requests for `500ms`.
2. **DOM Mutation Quiet:** Zero DOM mutations observed for `300ms` via an injected `MutationObserver`.
3. **Text Hydration Signatures:** Configured target text signatures are present in the rendered DOM.
- **Timeout Handling:** If stabilization times out before all three conditions settle, execution proceeds with a structured warning and sets the `stabilization_partial: true` flag on the result.

### 4.2 Full In-Browser `page.evaluate()` Pruning Script Specification (`src/circus_tent/parser/trimmer.py`)
Pruning executes directly inside the browser JS runtime via `page.evaluate()` so multi-megabyte raw SPA DOM strings never cross a process or IPC transport boundary.

The in-browser pruning script MUST perform the following transformations in order:
1. **Shallow-Clone & Tag Stripping:**
   - Shallow-clone the document tree and strip all non-content tags:
     `<script>`, `<style>`, `<noscript>`, `<iframe>`, `<link>`, `<meta>`.
2. **Semantic Icon & Graphic Marker Conversion:**
   - Convert `<img>` and `<svg>` elements into compact inline semantic text markers (e.g., `[ICON:calendar]`, `[BUTTON:submit]`) derived from their `aria-label`, `role`, `title`, or `alt` attributes.
3. **Recursive Open Shadow DOM Uncloaking (`.shadowRoot`):**
   - Explicitly inspect every element during tree traversal for a non-null `.shadowRoot` property.
   - Standard `cloneNode(true)` and `querySelectorAll()` cannot traverse inside Shadow DOM trees; the pruner recursively traverses every open `.shadowRoot` and inlines its rendered shadow children directly into the host element's pruned output.
4. **Nested Iframe / Frame Tree Flattening (`page.frames()`):**
   - Iterate across Playwright's `page.frames()` collection to prune and merge each nested frame's DOM into the unified pruned document string:
     - **Readable Same-Origin & Cross-Origin Frames (via Playwright frame handles):** Pruned content is merged inline at the frame's mount point.
     - **Unreadable Frames:** Emit an explicit placeholder marker `[FRAME:<src>]`.
5. **Accessibility Attribute Preservation:**
   - Retain `aria-label`, `role`, `title`, and `alt` attributes on all preserved elements.
6. **Whitespace Normalization & Minification:**
   - Collapse contiguous whitespace, remove empty text nodes, and minify the resulting HTML/DOM string.

### 4.3 Pruning Profiles: `EXTRACT` (`<= 250KB`) vs. `HEAL` (`<= 50KB`)
| Profile | Max Size Ceiling | Retention & Stripping Rules | Downstream Consumer |
|---|---|---|---|
| `EXTRACT` | `<= 250 KB` | Preserves structural containers, headings, tables, lists, semantic context, accessibility attributes, uncloaked Shadow DOM, and flattened frames. | In-process Crawl4AI BM25 / LXML content filtering and Markdown generation. |
| `HEAL` | `<= 50 KB` | Aggressive structural reduction: strips layout `<div>` wrappers, collapses single-child wrapper chains, and retains **only** interactive elements (`button`, `input`, `select`, `a`, `[role=...]`) and directly adjacent textual label nodes. | Tier 2 Text-Healing LLM (`Muse Spark 1.3 Contributor`). |

### 4.4 Crawl4AI In-Process LXML / BM25 Extraction Pipeline (`src/circus_tent/parser/extraction.py`)
- **In-Process Architecture:**
  - Uses Crawl4AI in-process inside the single Python 3.14 runtime — no sidecar container, no HTTP pipe, no cross-process serialization boundary.
- **Direct Synchronous Filter + Markdown Invocation (Fast Path):**
  - Invokes Crawl4AI's synchronous pure-Python content filters and markdown generator **directly** without spawning a Crawl4AI browser instance:
    - **Query Supplied:** `BM25ContentFilter` ranks and filters DOM blocks against the caller's `query`.
    - **No Query Supplied:** `PruningContentFilterLXML` (lxml-backed structural pruner) removes boilerplate/noise blocks.
    - **Markdown Generation:** Feeds filtered HTML directly into `DefaultMarkdownGenerator`.
  - **Performance Profile:** Runs at **`~106 ms` p50 / `~165 ms` p95** for `150 KB` HTML documents (satisfying Acceptance Benchmark #2: `p95 < 200ms`, `peak RSS < 2GB`).
  - **Raw HTML vs. Live-Page Pruner Routing:**
    - When processing raw HTML strings directly, raw HTML is fed to the Crawl4AI filter **unpruned** because the semantic pruner's `[ICON:...]` / `[BUTTON:...]` marker-annotated output is 7x slower through `DefaultMarkdownGenerator`.
    - The in-browser semantic pruner (`EXTRACT` profile) is applied on the **live-page path**, where in-browser `.shadowRoot` uncloaking and `page.frames()` flattening are required.
- **`AsyncWebCrawler` Fallback Route:**
  - `AsyncWebCrawler.arun(html=...)` is retained strictly as a compatibility fallback for Crawl4AI API drift (since `AsyncWebCrawler` spawns a browser per call and costs `~3 s` per document).
- **Batch Processing:**
  - Uses bounded-concurrency `asyncio.gather` (since `crawl4ai 0.9.4` does not provide `MemoryAdaptiveDispatcher`).
- **Deterministic Schema-Guided Extraction (Zero LLM Tokens):**
  - When a caller supplies an extraction JSON `schema` on `/extract`, extraction runs as a **deterministic post-processing step** applying `jsonschema`-validated heuristics over the generated Markdown — **never an LLM call**.
  - If the document cannot satisfy all required schema fields, the pipeline returns a best-effort partial object alongside the flag `schema_incomplete: true`.

---

## 5. Dual Upload & Checkpoint Engines (§5.6)

### 5.1 Dual Upload Engine (`upload` Step Type, B4) (`src/circus_tent/engine/`)
Supports two distinct file upload execution modes to handle both standard HTML `<input type="file">` controls and custom JavaScript drop zones (such as Workday's resume/cover-letter drop zones):

1. **Mode 1 — Direct Input (`set_input_files`):**
   - Uses Playwright's native `page.set_input_files(selector, file_payload)` on standard file input elements.
2. **Mode 2 — Synthetic Drag-and-Drop Emulation (`DataTransfer` Event Recipe):**
   - Required for enterprise ATS portals like **Workday**, which implement custom JS drop zones that are not addressable via `page.set_input_files()` alone.
   - **In-Browser Execution Recipe:**
     1. Read file bytes from the caller-supplied reference.
     2. Inside the page context, construct an in-memory `File` / `Blob` and attach it to a synthetic `DataTransfer` instance (`dataTransfer.items.add(file)`).
     3. Resolve the target drop-zone DOM element.
     4. Sequentially construct and dispatch synthetic `DragEvent`s carrying `{ bubbles: true, cancelable: true, dataTransfer }` on the drop-zone element in exact order:
        - `dragenter`
        - `dragover`
        - `drop`
- **File Sourcing & Security Controls:**
  - File bytes are read strictly from **caller-supplied references** (local filesystem paths or object-store URIs) at step execution time; the framework never stores uploaded files in its own persistent storage.
  - Enforces a configurable **per-upload byte size limit** and a strict **MIME type allowlist** prior to loading or injecting file bytes.

### 5.2 Idempotency Ledger & Multi-Page Wizard Checkpoint Engine (`checkpoint` Step Type, B2, D4) (`src/circus_tent/engine/`)
- **Mandatory `idempotency_key` (B2):**
  - Every `POST /run` and MCP `run(...)` call requires a mandatory `idempotency_key`.
  - A persistent per-key execution ledger records step progress and terminal run state.
- **At-Most-Once Semantics for Side-Effecting Steps (`side_effecting: true`):**
  - Any step marked `side_effecting: true` (e.g., final application submission, payment, account creation, offer acceptance) is governed by strict **at-most-once** execution semantics.
  - Retrying a `/run` request with an existing `idempotency_key` is guaranteed **never** to re-execute a completed `side_effecting: true` step.
- **Checkpoint Step Recording & Mid-Wizard Resumption (`checkpoint`, D4):**
  - Executing a `checkpoint` step writes a resumable state snapshot into the execution ledger keyed by `idempotency_key`:
    - `step_index`: index of the last completed step in the task list.
    - `extracted_form_values`: dictionary of form values extracted/populated up to this checkpoint.
    - `url`: current page URL at the checkpoint boundary.
    - `shard` and `profile`: bound shard and persistent profile identity.
  - When `/run` is invoked with an `idempotency_key` that has a recorded checkpoint:
    - Execution routes to the **same shard and persistent profile**.
    - Skips already-completed steps (`0 .. step_index`) and resumes execution mid-list from `step_index + 1` at the checkpointed URL/state.
    - Designed specifically for long multi-page enterprise ATS wizards (e.g., Workday 10+ page "Save and Continue" application flows).

---

## 6. CapSolver Bot-Wall Bypass, API/MCP Interface & Secret Config (§5.8, §5.10, §5.11, §9)

### 6.1 CapSolver Challenge Resolution Engine (`src/circus_tent/security/challenge_resolver.py`)
- **API Integration:**
  - Integrates with the CapSolver REST API (`createTask` / `getTaskResult` polling loop) authenticated via the `CAPSOLVER_API_KEY` environment variable.
  - All solve calls are token/cost-budgeted and recorded in the security audit log.
- **All 9 Challenge Task Types Ship Enabled by Default:**
  1. `reCAPTCHA v2` & `reCAPTCHA v3`
  2. `hCaptcha` (standard + Enterprise)
  3. `FunCaptcha` / `Arkose Labs`
  4. `Cloudflare Turnstile`
  5. `DataDome`
  6. `GeeTest` (v3 / v4)
  7. `Imperva` / `Incapsula`
  8. `Akamai Bot Manager`
  9. `PerimeterX` (`HUMAN Security`)
- **Navigation Challenge Detection Hooks:**
  - On every page navigation and step transition, DOM and network response signatures are inspected against per-challenge-type detectors (matching challenge iframes, script tags, sitekeys, challenge form containers, and HTTP 403/429/503 challenge payloads).
- **Per-Type Solved Token Injection Recipes:**
  - When a challenge signature is detected, `challenge_resolver.py` dispatches `createTask` to CapSolver, polls `getTaskResult` until solved, and injects the returned token/cookie directly into the live page context according to challenge type:
    - **reCAPTCHA v2 / v3:** Inject solved token string into `#g-recaptcha-response` / `textarea[name="g-recaptcha-response"]` and invoke the registered `___grecaptcha_cfg` callback.
    - **hCaptcha (+Enterprise):** Inject solved token into `textarea[name="h-captcha-response"]` and `textarea[name="g-recaptcha-response"]` and dispatch the hCaptcha submit/callback event.
    - **Cloudflare Turnstile:** Inject solved token into `input[name="cf-turnstile-response"]` and invoke the Turnstile widget callback registered on `window.turnstile`.
    - **DataDome:** Set the solved `datadome` cookie into the browser context (`context.add_cookies(...)`) and reload/continue navigation.
    - **FunCaptcha / GeeTest / Imperva / Akamai / PerimeterX:** Inject the respective verification token, session cookie (`_px3`, `reese84`, `_abck`), or callback payload into the page context and resume the blocked navigation/step.

### 6.2 Configuration Loader & Secret Management (`src/circus_tent/config/loader.py`)
- **Managed Configuration Files (all require top-level `schema_version`):**
  1. `config/shards.yaml` (`schema_version: 1`) — 7-shard definitions, domain patterns, `max_tabs: 12`, `recycle_after_pages: 500`, preflight URLs and authenticated markers, target-side rate limit ceilings.
  2. `config/models.yaml` (`schema_version: 1`) — `text_healing` and `vision_fallback` ordered provider lists, env var bindings, daily token budgets, 30% rolling-hour heal circuit breaker threshold.
  3. `config/accounts.yaml` (`schema_version: 1`) — registered portal accounts (NEOGOV, LinkedIn, etc.), per-account concurrency quotas (default `3`), credential env var references.
  4. `config/callers.yaml` (`schema_version: 1`) — bearer token env var bindings, per-caller shard allowlists, tool allowlists, account impersonation scopes, and independent per-caller rate limits.
  5. Auto-managed JSON caches: `config/selectors/{domain}.json` (`schema_version: 1`) and `config/coordinates/{domain}.json` (`schema_version: 1`).
- **Environment Variable Interpolation Syntax:**
  - Supports `${VAR}` (required env var) and `${VAR:-default}` (env var with fallback default), resolved strictly from `os.environ` at configuration load time.
- **`.env` Dev Fallback Semantics:**
  - `.env` at repository root (gitignored, file permissions `chmod 600`) is loaded at startup **only as a development fallback** when the process environment lacks the required variables (standard `dotenv` semantics with `override=False` — real exported process environment variables always win).
- **Mandatory Environment Variables:**
  - `MUSE_API_KEY` — API key for Muse Spark 1.3 / 1.2 Contributor (OpenCode Go).
  - `MUSE_API_BASE` — Base URL for Muse Spark OpenAI Responses API (`/zen/go/v1/responses`).
  - `DEEPSEEK_API_KEY` — API key for DeepSeek V4 Flash Vision Exp (OpenCode Go).
  - `DEEPSEEK_API_BASE` — Base URL for DeepSeek Vision chat-completions API (`/zen/go/v1/chat/completions`).
  - `CAPSOLVER_API_KEY` — API key for CapSolver challenge resolution service.
  - `AUTOMATION_WRAPPER_API_KEY` — Master/caller bearer API key for authenticating requests to the Circus Tent server.
  - Plus any account-specific credential variables referenced in `config/accounts.yaml`.
- **Zero Disk Secret Leakage Guarantee (B8):**
  - No secret value is ever written to any file (configs, selector/coordinate caches, profiles, ledgers, or logs) by the framework.
  - Structured JSON logs (`structlog`-style) run an automatic secret-pattern redaction filter scrubbing known API keys, bearer tokens, cookies, and credential values before emission.

### 6.3 Unified ASGI API & MCP Server Layer (`src/circus_tent/api/`)
- **Single ASGI Process:**
  - Hosted on `uvicorn` bound to `127.0.0.1:8000`.
  - Mounts both the FastAPI REST routes and the `FastMCP` server at `/mcp` via `mcp.streamable_http_app()` (**Streamable HTTP transport only**; WebSocket transport is strictly forbidden/deprecated).
- **REST Endpoints:**
  - `POST /run` — Execute a typed step workflow on a target domain shard (requires `idempotency_key`, supports optional `callback_url`).
  - `POST /extract` — Stabilize, prune, and extract Markdown or deterministic schema-guided data from a URL/HTML payload (supports optional `callback_url`).
  - `GET /health` — Shard health, callback delivery failure summary, circuit breaker status.
  - `GET /shards` — Live status, active tab count, queue depth, `pages_processed`, and PID for all 7 shards.
  - `GET /metrics` — Prometheus text format metrics (`circus_tent_*` prefix).
- **MCP Tools (mounted at `/mcp`):**
  - `run(domain, steps, session_id|account, idempotency_key, callback_url?)`
  - `extract(domain, url, query, schema?)`
  - `health()`
  - `list_shards()`
- **Bearer Auth, Per-Caller Scoping & Audit Log (B1):**
  - Every REST and MCP request authenticates via a bearer token verified using **constant-time comparison** (`hmac.compare_digest`).
  - Enforces per-caller scoping from `config/callers.yaml`: allowed shards, allowed tools, allowed accounts, and per-caller rate limit.
  - Every `/run` and `/extract` invocation writes an immutable audit log entry binding the request parameters, `idempotency_key`, target shard, and outcome to the authenticated caller identity.
- **Signed Webhook Callbacks (C):**
  - When `callback_url` is supplied on `/run` or `/extract`, reaching a terminal state triggers a signed HTTP `POST` summary (overall success, per-step status, error details) with best-effort retry; persistent callback delivery failures surface in `GET /health`.
- **OpenTelemetry & Prometheus Telemetry (C):**
  - Propagates W3C `traceparent` headers across REST/MCP calls, shard acquisitions, browser steps, and LiteLLM requests.
  - Exports `circus_tent_*` Prometheus metrics (permit wait times, queue depths, per-session tab utilization, pages processed, recycle counts, heal rates, token usage per shard/model/day).

---

## 7. The 8 Binding Acceptance Benchmarks (§7)

All 8 acceptance criteria in §7 are binding contract requirements and may not be relaxed:

| # | Benchmark | Exact Workload & Test Specification | Binding Target Criteria | CI Execution Mode |
|---|---|---|---|---|
| **1** | **Fingerprint stability** | Launch a shard **100 consecutive times** with a pinned `fingerprint.json` manifest; extract and compare runtime hashes for `canvas`, `WebGL` (vendor/renderer/parameters), `audio`, `navigator`, `screen`, and `fonts` across all launches (`benchmarks/verify_browser.py`). | **Identical on all 100 launches** (single unchanged manifest hash and 100% identical surface hashes). | Runs in CI (short form against local browser harness). |
| **2** | **Extraction throughput** | Process **500 × 150KB HTML strings** through the in-process Crawl4AI extraction pipeline (`BM25ContentFilter` / `PruningContentFilterLXML` + `DefaultMarkdownGenerator`); measure latency percentiles (`p50`, `p95`) and peak process RSS memory. | **`p95 < 200ms`**, **`peak RSS < 2GB`** (verified baseline: `~106ms` p50 / `~165ms` p95). | Runs in CI against captured HTML fixtures. |
| **3** | **Heal success** | Mutate **20% of an ATS DOM fixture** (CSS class renames, sibling/child element reorders, injected wrapper `<div>`s); execute Tier 2 text-model selector recovery (`HEAL` profile `<= 50KB` + `fallback_text` + failed selector + JSON repair layer). | **`> 85%` first-attempt recovery**. | Runs in CI (with mocked model responses against synthetic mutant fixtures). |
| **4** | **Concurrency fairness** | Drive **100 concurrent sessions × 20 tasks** (2,000 total tasks) against a single shard (`Semaphore(12)`, per-account quota `3`, fair-share FIFO queue). | **Zero quota violations** (no account ever exceeds 3 concurrent tabs; shard never exceeds 12 tabs); **`max wait < 3× median wait`**. | Runs in CI against local fixture harness. |
| **5** | **Recycle correctness** | Run a shard continuously to **500 `pages_processed`**, triggering the automatic recycle sequence (`INITIALIZING → READY → DRAINING → TERMINATED`, grace drain, flush sequence, PID exit reaping, same-profile relaunch). | **Zero orphan browser processes**; **replacement inherits the exact unchanged pinned fingerprint**; in-flight work on old browser drains cleanly before exit. | Full browser lifecycle benchmark. |
| **6** | **MFA persistence** | Complete interactive visual MFA handoff (`circus-tent bootstrap --shard <name>`, `headless=False`) on a fresh profile, then execute **20 consecutive automated sessions** in production mode (`headless="virtual"`). | **Zero re-authentication / MFA prompts** across all 20 automated sessions. | Operator/staging verification (never touches live ATS in CI). |
| **7** | **Back-pressure** | Flood a shard with concurrent requests exceeding **2× shard cap** (and beyond queue depth 1000 ceiling); inspect all HTTP responses and headers. | **Every request either succeeds or receives explicit HTTP `429` back-pressure** carrying both `Retry-After` and `X-Queue-Depth` headers (zero silent drops). | Runs in CI. |
| **8** | **Secret leakage** | Seed known test secret values into environment variables; run workloads (including errors and heals); recursively `grep` all emitted logs, configuration files, caches, and profile directories for the test secret strings. | **Zero matches** across all logs, configs, caches, and profile files. | Runs in CI. |

### 7.1 Locked Operator Design Decisions & Quality Gates (§9)
1. **Repository:** `rambalakrishnan/circus-tent`, public, **no license file**, no CI workflow running against live targets, branch `main`.
2. **Runtime & Packaging:** Python `3.14` system interpreter; managed via `uv` with committed `uv.lock`; system-wide install, no virtualenv. Package name `circus_tent`, CLI entry point `circus-tent` (`serve`, `bootstrap` subcommands).
3. **Host Binding:** Runs directly on host at `127.0.0.1:8000` with MCP mounted at `/mcp`.
4. **Live Accounts:** NEOGOV (`governmentjobs`) and LinkedIn configured first; interactive bootstrap is operator-run.
5. **Documentation & Quality Gates:** Mirrors `job-hunter` conventions (`AGENTS.md`, per-module `.omp-spec.md`, `docs/contracts/`, `docs/external/` including per-service rate-limit research). Enforces `ruff`, `mypy --strict`, and full `pytest` suite with per-module git commits.
6. **Fixtures & Drift Checks:** Captured real logged-out pages of all six target portals (`workday`, `greenhouse`, `lever`, `governmentjobs`, `indeed`, `linkedin`) plus synthetic DOM mutants; nightly live drift check runs outside CI; CI never touches live ATS endpoints.
