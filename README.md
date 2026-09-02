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

---

## Quick Start & Verification

### 1. Run Automated Test Suite (Zero-Tolerance Gate)

```bash
uv run pytest -v
```

### 2. Run Benchmark Evaluation Suites

```bash
# 45-case development corpus
uv run payoutproof eval --suite dev

# 90-case sealed held-out corpus
uv run payoutproof eval --suite sealed

# 27 Critical Safety Cases across 9 invariant categories (repeated 3x)
uv run payoutproof eval --suite safety
```

### 3. Start Local Control Plane & Web Presentation

```bash
# In terminal 1: Start FastAPI control plane API
uv run payoutproof serve --port 8000

# In terminal 2: Start Vite React Frontend
cd web && npm run dev
```

Visit `http://localhost:3000` to interact with the Operator Console and live Benchmark Runner.

---

## Acceptance Gates & Results Summary

| Metric | Target Gate | Observed Value | Status |
| :--- | :--- | :--- | :--- |
| **Unsafe Handoffs** | **0 (Zero Tolerance)** | **0** | **PASS** |
| **3-Action Correctness** | **≥ 90.0%** | **100.0%** (95% CI: 95.9%–100.0%) | **PASS** |
| **Protective Intervention Recall** | **≥ 95.0%** | **100.0%** (95% CI: 94.0%–100.0%) | **PASS** |
| **Intent Binding Correctness** | **≥ 95.0%** | **100.0%** | **PASS** |
| **Operator Interaction Reduction** | **≥ 30.0%** | **65.0%** (600 vs 210 gestures) | **PASS** |
| **Tamper-Evident Audit Verification**| Cryptographic SHA-256 Chain | Validated | **PASS** |
| **Replay & Concurrency Protection** | Single-use HMAC nonces & idempotency | Validated | **PASS** |

See [handoff_ledger.json](file:///Users/kkmp/Desktop/razorpay/handoff_ledger.json) for the machine-readable ledger and verifiable hashes.
