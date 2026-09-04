# ADR 0016: Representative Document and Image Intent Extraction, OCR Diagnostics, and Location Provenance

## Status

Accepted

## Context

GitHub Issue #16 requires turning authorized document and image evidence into the same provenance-rich Payment Intent contract used by the audio workflow.

In commercial payout operations:
1. **Diverse Media Formats**:
   - Evidence comprises digital PDF invoices, purchase orders, contracts, scanned receipts (PNG/JPEG), and structured vendor transmissions (JSON/TXT).
2. **Fine-Grained Location Provenance**:
   - Reviewers and auditors must not merely see an extracted string; they must be able to trace each field (`counterparty`, `destination`, `amount`, `purpose`, `instruction_reference`) back to its exact document page and normalized bounding box coordinates (`[ymin, xmin, ymax, xmax]`), along with the content hash.
3. **Auditable OCR Diagnostics**:
   - Extraction provider identity, model/version (e.g. `layoutlm-in-v2.1`), confidence scores, timing, and raw OCR representations must be preserved without leaking secrets.
4. **Protective Fail-Closed States**:
   - Documents with internal contradictions (e.g. remittance total differing from line-item sum, or multiple conflicting bank accounts in invoice body), low OCR confidence (< 0.80), corrupted headers, unsupported binary types, or timeouts must fail closed, preventing false confirmations.

## Decision

1. **Document & Image Container Validation (`src/payoutproof/agent/document.py`)**:
   - `parse_document_metadata` inspects magic bytes for PDF, PNG (IHDR dimensions), JPEG (SOF dimensions), JSON, and UTF-8 plain text.
   - Truncated or malformed headers raise `DocumentCorruptedError` -> `ExtractionFailureReason.DOCUMENT_CORRUPTED`.
   - Unsupported types raise `DocumentFormatError` -> `ExtractionFailureReason.UNSUPPORTED_DOCUMENT_FORMAT`.

2. **Fine-Grained Bounding Box Location Provenance (`src/payoutproof/agent/document.py`)**:
   - Bounding boxes are normalized to `[0.0, 1.0]` coordinates: `BoundingBox(ymin, xmin, ymax, xmax)`.
   - Each intent field receives a `FieldDocumentProvenance` linked to page and bounding box, formatted as canonical audit strings:
     `doc:field={field_name}:page={page}:box={ymin},{xmin},{ymax},{xmax}:hash={hash[:12]}:snippet={text_snippet}`.

3. **Contradiction Detection & Quality Gating (`src/payoutproof/agent/document.py`)**:
   - Internal contradictions trigger `ExtractionFailureReason.MATERIAL_AMBIGUITY`, setting `FindingName.INSTRUCTION_CONSISTENCY` to `TruthState.INSUFFICIENT_QUALITY`.
   - Low OCR confidence (< 0.80) triggers `ExtractionFailureReason.LOW_CONFIDENCE`, setting `FindingName.INSTRUCTION_CONSISTENCY` to `TruthState.INSUFFICIENT_QUALITY`.
   - In all failure modes, the Payment Intent is NOT confirmed (`NOT_EXTRACTED`).

4. **Audit and Investigation Integration (`src/payoutproof/agent/service.py`)**:
   - `CaseInvestigation` updates `model_status` (`COMPLETED`, `AMBIGUOUS`, `FAILED`, `TIMED_OUT`), `extraction_latency_ms`, and increments `attempt`.
   - The case `AuditChain` receives document format, page count, OCR provider, model version, and contradiction flags.

## Consequences

- **Uniformity**: Documents, images, and audio all produce identically structured `PaymentIntent` records with field-level provenance strings.
- **Audit Defensibility**: Operators and regulators can visually verify extracted fields on the exact page and coordinates of the source document.
- **Risk Mitigation**: Invoices with conflicting payment destinations or amounts cannot slip through automated approval gates.
