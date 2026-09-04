# ADR 0013: Authorized Real Evidence Admission and Encrypted Preservation

## Status

Accepted

## Context

In production payment operations, operators handle representative evidence (invoices, identity documents, bank confirmation letters, authorization call recordings, transaction receipts) to corroborate high-value payouts or investigate risk flags.

Handling real external evidence introduces critical security, regulatory, and architectural challenges:
1. **Unauthorized Evidence Processing**:
   - Processing data without verifiable legal or regulatory authority violates data protection standards (GDPR, SOC2, PCI-DSS).
   - If evidence lacks a valid `ProcessingAuthorityRecord`, processing must halt before any case is created, preventing liability and capacity consumption.
2. **Untrusted Input and Malware Exploitation**:
   - Attackers may spoof client MIME types (e.g. declaring a shell script or Windows executable as `audio/wav`).
   - Archive formats (ZIP, TAR, GZ, 7Z) pose decompression bomb hazards and path traversal risks.
   - Malicious files (executables, injection payloads, malware signatures) must be quarantined immediately rather than parsed or stored in downstream pipelines.
3. **Data Protection and Confidentiality at Rest**:
   - Storing raw evidence in plaintext exposes sensitive financial details, bank accounts, and PII.
   - Raw evidence must be encrypted at rest using authenticated symmetric AEAD (AES-256-GCM) with cryptographic binding to tenant, organization, case, and evidence IDs in Additional Authenticated Data (AAD).
4. **Audit Integrity and Operational Transparency**:
   - The authoritative `content_hash` must be computed over the plaintext bytes to maintain verifiable hash links with `PaymentIntent` and `EvidenceItem` models.
   - Upload progress must be transparent to operators while never leaking encryption keys, raw bytes, or filesystem paths in logs, error messages, or telemetry.

## Decision

1. **Pre-Admission Processing Authority Gate (`src/payoutproof/admission/validator.py`)**:
   - Every upload requires a valid `ProcessingAuthorityRecord` specifying lawful basis, data classification, purpose, retention window, and authority reference.
   - Missing or invalid processing authority immediately halts admission with an explicit rejection (`ADMISSION_AUTHORITY_INCOMPLETE` or `ADMISSION_AUTHORITY_INVALID`).
   - Rejection occurs *before* any Risk Case is opened, ensuring unadmitted evidence consumes zero case capacity or tenant quota.

2. **Deep Server-Side Content Detection & Threat Quarantine (`src/payoutproof/admission/detector.py`)**:
   - Server-side magic byte inspection determines true media type across supported formats (`audio/wav`, `audio/mpeg`, `audio/ogg`, `application/pdf`, `image/png`, `image/jpeg`, `application/json`, `text/plain`).
   - Client MIME declarations are validated against inspected types; discrepancies fail closed as `MALFORMED_INPUT`.
   - Strict archive protection rejects `.zip`, `.tar`, `.gz`, `.7z`, `.rar`, `.bz2` as `PROHIBITED_INPUT`.
   - Malware and binary inspection detects PE, ELF, Mach-O executables, EICAR test signatures, and script injection strings, immediately routing payloads to `QUARANTINED` status with safe threat descriptors.

3. **AES-256-GCM Encrypted Object Store (`src/payoutproof/storage/encrypted_store.py`)**:
   - Raw bytes are encrypted prior to disk storage using AES-256-GCM with a 12-byte cryptographically secure random nonce.
   - Additional Authenticated Data (AAD) binds the ciphertext to `{tenant_id}|{organization_id}|{case_id}|{evidence_id}`.
   - The stored format is `0x01 (version byte) + nonce (12B) + ciphertext + tag (16B)`.
   - Content hash (SHA-256) is computed over the plaintext bytes, providing a permanent, tamper-evident hash for audit verification.
   - Storage paths follow a strict tenant-isolated hierarchy: `{base_dir}/{tenant_id}/{organization_id}/{case_id}/{evidence_id}.enc`.
   - Encryption keys are strictly redacted (`[REDACTED]`) in all string representations and logs.

4. **Transactional Evidence Ledger & API Surface (`src/payoutproof/storage/db.py`, `src/payoutproof/api/app.py`)**:
   - Durable evidence metadata is recorded in the `admitted_evidence` table in both SQLite and PostgreSQL.
   - Upload progress is observable across stages (`INITIALIZED`, `VALIDATING_AUTHORITY`, `INSPECTING_CONTENT`, `SCANNING_SECURITY`, `ENCRYPTING_PAYLOAD`, `PERSISTING_LEDGER`, `COMPLETED`, `REJECTED`, `QUARANTINED`).
   - REST API endpoints:
     - `POST /api/evidence/admit`: Safely uploads evidence, returning `AdmissionResult`.
     - `GET /api/evidence/{evidence_id}/status`: Provides public metadata and lifecycle status with zero secret exposure.
     - `GET /api/cases/{case_id}/evidence`: Lists all admitted evidence items bound to a case.

## Consequences

- **Security**: Raw evidence is never stored unencrypted. Untrusted files cannot spoof media types or bypass malware filters.
- **Compliance**: Proof of lawful processing authority is established and immutably recorded before ingestion.
- **Reliability**: Dual-dialect database support guarantees seamless transition from local development (SQLite) to production (PostgreSQL).
- **Auditability**: Plaintext SHA-256 hashes ensure end-to-end cryptographic verifiability from evidence ingestion to final settlement.
