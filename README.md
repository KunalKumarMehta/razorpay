# IntentLock

**Zero-Trust Policy Gate for High-Risk Payouts**  
*Razorpay AI Buildathon 2026 • Track 2: AI Risk Manager*

---

## Executive Summary

**IntentLock** intercepts deepfake voice notes, urgent social engineering, and unauthorized recipient tampering before payment instructions reach RazorpayX rails.

Emerging autonomous AI agents are being granted raw financial execution credentials—a catastrophic design flaw in real-time settlement rails (IMPS/UPI) where there is no recall or "Ctrl-Z". IntentLock enforces our core design thesis:

> **Never let an LLM touch the financial trigger.**

IntentLock divides the entire payment lifecycle into three hard-bounded authority lanes:
1. **Lane 1: Trust Agent (Read-Only LLM)**: Ingests multimodal voice notes, screenshots, and invoices under DPDP admission rules. Transcribes audio, extracts candidate entities, and grounds every field to verbatim evidence spans. Crucially, Lane 1 holds **zero financial execution permissions**.
2. **Lane 2: Deterministic Policy Gate**: The operator reviews the extracted intent and clicks Confirm, freezing an immutable **SHA-256 Intent Hash**. A 100% deterministic Python rule engine verifies the counterparty against an approved bank registry. Unapproved beneficiaries immediately halt execution at `STEP_UP_REQUIRED`, mandating independent out-of-band callback and dual controller approval.
3. **Lane 3: Maker-Checker Rail**: Once approved, IntentLock issues a single-use, 15-minute **HMAC-SHA256 Handoff Grant**. An idempotent action adapter submits exactly one pending item to RazorpayX's Maker-Checker queue. Final execution authority rests solely with RazorpayX.

---

## System Architecture

```
[ Ingested Voice / WhatsApp / Evidence ]
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Lane 1: DPDP Admission & Privacy Gate       │ ─── (Invalid) ──► Admission Rejection (No Disk Leak)
└──────────────────────────────────────────────┘
                   │ (Admitted)
                   ▼
┌──────────────────────────────────────────────┐
│  Lane 1: Trust Agent (Extraction & Grounding)│ ───► Verbatim Evidence Spans (Zero Money Authority)
└──────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Human Confirmation & Intent Hash Freeze     │ ───► Immutable SHA-256 Intent Hash
└──────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Lane 2: Deterministic Policy Gate Core      │ ───► BLOCKED | HOLD | STEP_UP_REQUIRED
└──────────────────────────────────────────────┘
                   │ (ELIGIBLE_FOR_HANDOFF)
                   ▼
┌──────────────────────────────────────────────┐
│  Lane 3: Single-Use HMAC-SHA256 Grant        │ ───► 15-Minute TTL (Bound to Intent Hash)
└──────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Lane 3: Idempotent Action Adapter           │ ───► Pending Item in RazorpayX Maker-Checker Queue
└──────────────────────────────────────────────┘
```

> [!NOTE]
> **Durable Replay & Atomic Handoff Slice**: Handoff attempts execute within an explicit SQLite `BEGIN IMMEDIATE` transaction. Grants are conditionally claimed (`used = 0 AND status = 'ACTIVE'`). Server-owned idempotency keys are deterministically derived from tenant/case/version/grant data. Attempts and pending maker-checker approval items are durably recorded in SQLite, surviving restarts while refusing duplicate submissions and blind ambiguity retries.

> [!NOTE]
> **Authenticated Authoritative Audit Checkpoints**: The `audit_events` table is the sole authoritative audit store. `risk_cases.state_json` never stores or trusts audit data (`state_json["audit"] = []`), and `load_case` hydrates strictly from verified `audit_events` rows against authenticated checkpoints in `case_audit_checkpoints`. Checkpoints verify tip hash, event count, and sequence continuity via HMAC-SHA256 (`PAYOUTPROOF_AUDIT_CHECKPOINT_V1`). Any tail deletion, event truncation, row tampering, sequence reordering, or cross-case event fails closed immediately with `AuditLedgerIntegrityError`.

---

## Configuration & Secret Composition

IntentLock enforces strict secret composition with immutable, redacted configuration (`AppConfig`).

### Environment Variables

| Variable | Description | Required | Constraints |
| :--- | :--- | :--- | :--- |
| `PAYOUTPROOF_GRANT_SECRET` | Secret key for HMAC-SHA256 signing and verification of single-use Handoff Grants. | Yes (production/staging) | ≥ 32 characters, distinct from checkpoint secret. |
| `PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET` | Secret key for signing audit chain checkpoints. | Yes (production/staging) | ≥ 32 characters, distinct from grant secret. |
| `PAYOUTPROOF_ENV` | Environment identifier (`production`, `staging`, `development`, `test`). | No (default: `production`) | Fails closed unless set to `development`. |
| `PAYOUTPROOF_DB_PATH` | File path for SQLite database. | No (default: `payoutproof.db`) | Valid filesystem path. |
| `PAYOUTPROOF_ENABLE_DEMO_ADAPTER_MODES` | Enable local demo adapter simulation modes. | No (default: `0`) | `1` or `true` to enable. |

### Setup Instructions

Configure high-entropy secrets using placeholders (never commit real secrets):

```bash
export PAYOUTPROOF_ENV="production"
export PAYOUTPROOF_GRANT_SECRET="<generate_at_least_32_character_random_grant_secret>"
export PAYOUTPROOF_AUDIT_CHECKPOINT_SECRET="<generate_distinct_32_character_random_checkpoint_secret>"
export PAYOUTPROOF_DB_PATH="payoutproof.db"
```

> [!CAUTION]
> If any required secret is missing, shorter than 32 characters, or identical to another secret, the system fails closed immediately with an actionable safe `ConfigurationError`. Secrets are redacted in `repr`/`str` as `[REDACTED]` and never exposed in logs, exceptions, or API endpoints.

### Ephemeral Development Mode

For local evaluation and interactive UI inspection, you can enable development mode:

```bash
export PAYOUTPROOF_ENV="development"
```

---

## Quick Start & Verification

### 1. Run Automated Test Suite (403 Tests)

```bash
uv run pytest
```

### 2. Run Synthetic Policy Evaluation Harnesses

> [!NOTE]
> The evaluation harness runner exercises deterministic policy plumbing and boundary invariants against synthetic structured test cases (45 dev, 90 sealed, and 81 repeated safety executions: 27 synthetic base cases × 3 repetitions). All dev, sealed, and safety corpora are deterministic synthetic structured policy-plumbing harnesses—not held-out data, real media/models, human validation, real-world performance, or product proof. Real multilingual ASR and AASIST runs, separated sealed media, an immutable Evaluation Version, raw outputs, and a release manifest are not yet evidenced.

```bash
# 45-case development policy harness (synthetic cases)
uv run intentlock eval --suite dev

# 90-case synthetic policy plumbing harness
uv run intentlock eval --suite sealed

# 81-execution critical safety invariant harness (27 synthetic base cases × 3 repetitions)
uv run intentlock eval --suite safety
```

### 3. Start Local Control Plane & Web Presentation

```bash
# In terminal 1: Start FastAPI control plane API
uv run intentlock serve --port 8000

# In terminal 2: Start Vite React Frontend Operator Console
cd web && npm run dev
```

Visit `http://localhost:3000` to interact with the IntentLock Operator Console.

### 4. Interactive Diagrams & Presentation Deck

- **Interactive Pitch Presenter**: Open [`build/IntentLock_Interactive_Pitch.html`](build/IntentLock_Interactive_Pitch.html) in any web browser.
- **3-Lane Architecture Diagram**: Open [`build/diagrams/IntentLock_Architecture.html`](build/diagrams/IntentLock_Architecture.html).
- **Sequence & Safe Failure Flow**: Open [`build/diagrams/IntentLock_SequenceFlow.html`](build/diagrams/IntentLock_SequenceFlow.html).
- **Pitch Deck (PowerPoint)**: [`build/IntentLock_Pitch_Deck.pptx`](build/IntentLock_Pitch_Deck.pptx).
- **Spoken Teleprompter Script**: [`Pitch_Script.md`](Pitch_Script.md) (formatted for Obsidian).

---

## Predeclared Acceptance Gates (Targets)

> [!WARNING]
> **Status: NOT RUN / NOT YET EVIDENCED**
> The table below records **predeclared target gates only**. The repository currently contains deterministic policy plumbing and unit-level invariant checks on synthetic structured cases. Full held-out product evaluation—including real multilingual voice models (ASR), anti-spoof diagnostics (AASIST), separated sealed media, and human-in-the-loop validation—has **not** been executed. Unearned passing claims have been reset.

| Metric | Target Gate (Target Only) | Current Observed Value | Evaluation Status |
| :--- | :--- | :--- | :--- |
| **Unsafe Handoffs** | **0 (Zero Tolerance)** | Not evaluated on held-out corpus | **NOT RUN** |
| **3-Action Correctness** | **≥ 90.0%** | Not evaluated on held-out corpus | **NOT RUN** |
| **Protective Intervention Recall** | **≥ 95.0%** | Not evaluated on held-out corpus | **NOT RUN** |
| **Intent Binding Correctness** | **≥ 95.0%** | Not evaluated on held-out corpus | **NOT RUN** |
| **Operator Interaction Reduction** | **≥ 30.0%** | Not evaluated with human reviewers | **NOT RUN** |
| **Tamper-Evident Audit Verification** | Cryptographic SHA-256 Chain | Partial unit checks with known gaps | **NOT YET EVIDENCED** |
| **Replay & Concurrency Protection** | Single-use HMAC nonces & idempotency | Partial unit checks with known gaps | **NOT YET EVIDENCED** |

See [handoff_ledger.json](./handoff_ledger.json) for the machine-readable development ledger.

---

## Reproducible Supply Chain & Build Verification

```bash
# 1. Verify dependency lockfile integrity (both Python and Node)
uv lock --check
npm --prefix web ci --dry-run

# 2. Run static analysis and formatting checks
uv run ruff check src tests scripts

# 3. Generate CycloneDX 1.5 JSON SBOM
uv run python scripts/generate_sbom.py --format cyclonedx --output build/sbom.cdx.json

# 4. Generate SPDX 2.3 JSON SBOM
uv run python scripts/generate_sbom.py --format spdx --output build/sbom.spdx.json

# 5. Build pinned production container
docker build -t intentlock:pilot .
```

---

## License

This project is open source and licensed under the [MIT License](LICENSE).
