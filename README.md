# PayoutProof

**Trust Agent & Deterministic Policy Gate for Payment Risk**  
*Razorpay Buildathon MVP Implementation*

---

## Architecture Overview

PayoutProof converts urgent, out-of-band payout instructions into auditable Risk Cases and submits the exact Payment Intent to a deterministic Policy Gate before it can enter an existing maker-checker approval rail.

```
[ Ingested Voice / Message / Evidence ]
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Admission Control (Processing Authority)    │ ─── (Invalid) ──► Admission Rejection (No Case)
└──────────────────────────────────────────────┘
                   │ (Valid)
                   ▼
┌──────────────────────────────────────────────┐
│  Trust Agent (Extraction & Candidate Spans)  │
└──────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Human Confirmation & Intent Hash Freeze     │
└──────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Deterministic Policy Gate Evaluator         │ ───► BLOCKED | HOLD | STEP_UP_REQUIRED
└──────────────────────────────────────────────┘
                   │ (ELIGIBLE_FOR_HANDOFF)
                   ▼
┌──────────────────────────────────────────────┐
│  Single-Use Expiring HMAC Handoff Grant      │
└──────────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────┐
│  Action Adapter (Idempotent Rail Submission) │ ───► Pending Item in Maker-Checker Rail
└──────────────────────────────────────────────┘
```

> [!NOTE]
> **Durable Replay & Atomic Handoff Slice**: Handoff attempts execute within an explicit SQLite `BEGIN IMMEDIATE` transaction. Grants are conditionally claimed (`used = 0 AND status = 'ACTIVE'`). Server-owned idempotency keys are deterministically derived from tenant/case/version/grant data. Attempts and pending maker-checker approval items are durably recorded in SQLite, surviving restarts while refusing duplicate submissions and blind ambiguity retries.

> [!NOTE]
> **Authenticated Authoritative Audit Checkpoints (P0-3C)**: The `audit_events` table is the sole authoritative audit store. `risk_cases.state_json` never stores or trusts audit data (`state_json["audit"] = []`), and `load_case` hydrates strictly from verified `audit_events` rows against authenticated checkpoints in `case_audit_checkpoints`. Checkpoints verify tip hash, event count, and sequence continuity via HMAC-SHA256 (`PAYOUTPROOF_AUDIT_CHECKPOINT_V1`). Any tail deletion, event truncation, row tampering, sequence reordering, or cross-case event fails closed immediately with `AuditLedgerIntegrityError`. Legacy uncheckpointed cases are quarantined as `LEGACY_UNTRUSTED` on database migration.

---

## Configuration & Secret Composition

PayoutProof enforces strict secret composition with immutable, redacted configuration (`AppConfig`).

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

> [!WARNING]
> In development mode, missing secrets are generated as process-ephemeral secure random strings. A one-time warning is printed to `stderr`:
> `WARNING: PAYOUTPROOF_ENV=development generated process-ephemeral secrets; restarting the process will invalidate active grants and audit checkpoints.`
> Because ephemeral secrets reside in memory, restarting the process invalidates all previously issued grants and audit checkpoints. Explicitly supplied secrets still validate strictly.

---

## Quick Start & Verification

### 1. Run Automated Test Suite (Unit & Boundary Invariants)

```bash
UV_CACHE_DIR=/private/tmp/payoutproof-uv-cache PYTHONDONTWRITEBYTECODE=1 uv run pytest -q -p no:cacheprovider
```

### 2. Run Development Policy Harness (Synthetic Structured Cases)

> [!NOTE]
> The evaluation harness runner exercises deterministic policy plumbing and boundary invariants against synthetic structured test cases (45 dev, 90 sealed, and 81 repeated safety executions: 27 synthetic base cases × 3 repetitions). All dev, sealed, and safety corpora are deterministic synthetic structured policy-plumbing harnesses—not held-out data, real media/models, human validation, real-world performance, or product proof. Real multilingual ASR and AASIST runs, separated sealed media, an immutable Evaluation Version, raw outputs, and a release manifest are not yet evidenced.

```bash
# 45-case development policy harness (synthetic cases)
uv run payoutproof eval --suite dev

# 90-case synthetic policy plumbing harness
uv run payoutproof eval --suite sealed

# 81-execution critical safety invariant harness (27 synthetic base cases × 3 repetitions)
uv run payoutproof eval --suite safety
```

### 3. Start Local Control Plane & Web Presentation

```bash
# In terminal 1: Start FastAPI control plane API
uv run payoutproof serve --port 8000

# In terminal 2: Start Vite React Frontend
cd web && npm run dev
```

Visit `http://localhost:3000` to interact with the Operator Console and development policy harness runner.

### 4. Verify Authenticated Audit Chain Integrity

```bash
uv run payoutproof verify-audit --case-id <case-id>
```

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

## Reproducible Pilot Baseline & Supply Chain

### 1. Clean-Checkout Verification Commands

Every pilot baseline artifact is reproducible from a clean checkout without ad-hoc network access:

```bash
# 1. Verify dependency lockfile integrity (both Python and Node)
uv lock --check
npm --prefix web ci --dry-run

# 2. Run static analysis and formatting checks
uv run ruff check src tests scripts

# 3. Execute unit and integration tests (281 tests)
uv run pytest -q -p no:cacheprovider

# 4. Run synthetic evaluation harnesses across all suites
uv run payoutproof eval --suite dev
uv run payoutproof eval --suite sealed
uv run payoutproof eval --suite safety

# 5. Build frontend production assets
npm --prefix web run build
```

### 2. Secret-Free Release Metadata Endpoints

PayoutProof exposes stable release and provenance identifiers across public boundaries without leaking secrets, credentials, or machine paths:

- **`GET /api/health`**: Returns service liveness, capability status, database WAL status, and the `release` block.
- **`GET /api/release`**: Returns the secret-free release identity payload:
  - `application_version`: Mirrored from `pyproject.toml` (`0.1.0`).
  - `policy_version`: Deterministic Policy Gate identifier (`PP-POLICY-V1`).
  - `schema_version`: Authoritative persistence schema version (`PP-SCHEMA-V1`).
  - `audit_checkpoint_version`: Audit checkpoint domain separator (`PAYOUTPROOF_AUDIT_CHECKPOINT_V1`).
  - `model_configuration_version`: Bound model configuration (`PP-MODEL-CONFIG-V1-SYNTHETIC-STRUCTURED`).
  - `evaluation_version`: Immutable Evaluation Version (`PP-EVAL-V1-SYNTHETIC-STRUCTURED`).
  - `evidence_scope`: Scope declaration (`SYNTHETIC_INVARIANT_HARNESS_ONLY_NOT_HELD_OUT`).
  - `maturity`: Pipeline maturity (`IN_DEVELOPMENT`).

### 3. Automated Software Bill of Materials (SBOM)

An offline, reproducible SBOM generator parses `uv.lock` and `web/package-lock.json` to produce CycloneDX 1.5 and SPDX 2.3 JSON documents:

```bash
# Generate CycloneDX 1.5 JSON SBOM
uv run python scripts/generate_sbom.py --format cyclonedx --output build/sbom.cdx.json

# Generate SPDX 2.3 JSON SBOM
uv run python scripts/generate_sbom.py --format spdx --output build/sbom.spdx.json
```

### 4. Pinned Container Build

The application container is defined in a multi-stage `Dockerfile` with pinned base images (`python:3.11.9-slim-bookworm` and `node:20.15.1-bookworm-slim`), unprivileged execution user (`appuser:10001`), and healthcheck probes:

```bash
docker build -t payoutproof:pilot .
```

### 5. Branch Protection & Promotion Discipline

- The protected `main` branch remains untouched (`aa3bd57`).
- Branch protection discipline ensures all development proceeds through dedicated review.
- Evaluation results honestly declare synthetic scope; no held-out claims or unverified pilot certifications are published.

---

## License

This project is licensed under the [MIT License](LICENSE).

