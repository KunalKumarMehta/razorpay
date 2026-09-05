# ADR 0014: Trust Agent Extraction Jobs and Explicit Failure States

## Status

Accepted

## Context

GitHub Issue #14 requires moving Trust Agent extraction across a bounded asynchronous job boundary with explicit lifecycle states, strict failure modeling, deterministic test doubles, provenance preservation, and a non-negotiable safety invariant: **failures, timeouts, missing signals, or low confidence must never convert into affirmative evidence or confirmed payment intent**.

In automated payout risk evaluation:
1. **Asynchronous Provider Boundary**:
   - Model extraction and NLP parsing are variable-latency operations and subject to external provider downtime, rate limits, or network timeouts.
   - Jobs must transition through explicit lifecycle states (`QUEUED`, `PROCESSING`, `SUCCEEDED`, `FAILED`, `TIMED_OUT`, `QUARANTINED`).
2. **Explicit Failure States**:
   - Failure modes must be distinguished and explicitly represented: `TIMEOUT`, `MALFORMED_SCHEMA`, `LOW_CONFIDENCE`, `MISSING_SIGNAL`, `PROVIDER_OUTAGE`, `SECURITY_QUARANTINE`, and `INTERNAL_ERROR`.
   - Silent failures, empty responses, or low-quality inferences must not be treated as success or neutral approvals.
3. **Non-Affirmative Failure Invariant**:
   - If an extraction times out or fails with provider outage, `TruthState` must remain `NOT_EVALUATED`.
   - If extraction finds no signal (missing counterparty, missing amount), `TruthState` must be `NOT_OBSERVED`.
   - If confidence is below threshold (< 0.80), `TruthState` must be `INSUFFICIENT_QUALITY` and the `PaymentIntent` status must NOT be set to `CONFIRMED`.
   - No failure condition may ever set `TruthState.SUPPORTED` or authorize a payout.
4. **Cryptographic Provenance and Auditability**:
   - Every job must record provider identity, model version, confidence, processing timing, raw output reference (`raw-ref://{hash}`), and source provenance (source channel, content hash, authority ref, tenant ID, organization ID).
   - All completed and failed jobs must be committed to the append-only `AuditChain` and the transactional database ledger.

## Decision

1. **Job Data Models & Explicit Failure Taxonomy (`src/payoutproof/agent/models.py`)**:
   - `JobStatus`: `QUEUED`, `PROCESSING`, `SUCCEEDED`, `FAILED`, `TIMED_OUT`, `QUARANTINED`.
   - `ExtractionFailureReason`: `TIMEOUT`, `MALFORMED_SCHEMA`, `LOW_CONFIDENCE`, `MISSING_SIGNAL`, `PROVIDER_OUTAGE`, `SECURITY_QUARANTINE`, `INTERNAL_ERROR`.
   - `ProviderProvenance` and `ProviderResult`: Strongly-typed dataclasses capturing metadata, raw output hash references, and structured signals without leaking internal secrets.
   - `ExtractionJobRecord`: Comprehensive job entity with `to_public_dict()` for safe, redaction-complete API serialization.

2. **Provider Boundary Protocol & Deterministic Test Doubles (`src/payoutproof/agent/provider.py`)**:
   - `ExtractionProvider` protocol defines `extract(raw_content, mime_type, source_provenance, simulation_mode) -> ProviderResult`.
   - `DeterministicFakeProvider` provides 100% reproducible, fast execution of all extraction behaviors:
     - `SimulationMode.SUCCESS`: Generates high-confidence (0.95) extraction matching document contents.
     - `SimulationMode.TIMEOUT`: Simulates provider-side execution timeout.
     - `SimulationMode.MALFORMED_SCHEMA`: Simulates unparseable or schema-violating provider response.
     - `SimulationMode.LOW_CONFIDENCE`: Generates low-confidence (0.45) inference to test quality gating.
     - `SimulationMode.MISSING_SIGNAL`: Simulates valid document without actionable payment instructions.
     - `SimulationMode.PROVIDER_OUTAGE`: Simulates 503 / upstream service unavailable.
     - `SimulationMode.SECURITY_QUARANTINE`: Simulates immediate quarantine trigger.

3. **Trust Agent Orchestration Service (`src/payoutproof/agent/service.py`)**:
   - `TrustAgentService` manages job lifecycle (`enqueue_job`, `process_job`, `run_extraction_job`, `get_job`, `list_case_jobs`).
   - Terminal jobs are immutable; attempts to reprocess completed jobs return the recorded result idempotently.
   - Content is safely retrieved from `EncryptedObjectStore` before invocation.
   - Strictly enforces non-affirmative mappings:
     - `SUCCESS` (confidence >= 0.80) -> updates `PaymentIntent` and sets findings to `TruthState.SUPPORTED`.
     - `LOW_CONFIDENCE` (< 0.80) -> records `TruthState.INSUFFICIENT_QUALITY`, does not confirm intent.
     - `MISSING_SIGNAL` -> records `TruthState.NOT_OBSERVED`, does not confirm intent.
     - `TIMEOUT`, `PROVIDER_OUTAGE`, `MALFORMED_SCHEMA` -> records `TruthState.NOT_EVALUATED`.
     - `SECURITY_QUARANTINE` -> halts processing immediately, marks job `QUARANTINED`.
   - Cryptographically linked audit records (`TRUST_AGENT_EXTRACTION_COMPLETED` or `TRUST_AGENT_EXTRACTION_FAILED`) are appended to the case's `AuditChain`.

4. **Database Persistence & API Endpoints (`src/payoutproof/storage/db.py`, `src/payoutproof/api/app.py`)**:
   - `CREATE TABLE IF NOT EXISTS extraction_jobs` with dialect-specific schema for PostgreSQL and SQLite.
   - Endpoints:
     - `POST /api/cases/{case_id}/jobs/extract`: Enqueues and executes job with optional simulation mode.
     - `GET /api/jobs/{job_id}`: Retrieves safe public job record with provenance.
     - `GET /api/cases/{case_id}/jobs`: Lists all extraction jobs bound to a case.

## Consequences

- **Safety**: Automated payout policies cannot be tricked by timeouts, provider outages, or ambiguous evidence.
- **Reproducibility**: `DeterministicFakeProvider` ensures test suites and pilot demos run predictably without external dependencies.
- **Traceability**: Raw outputs are content-hashed and linked to source evidence, guaranteeing audit defensibility.
