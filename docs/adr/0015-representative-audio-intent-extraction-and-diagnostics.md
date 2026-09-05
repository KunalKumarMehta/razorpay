# ADR 0015: Representative Audio Intent Extraction, Diagnostics, and Provenance

## Status

Accepted

## Context

GitHub Issue #15 requires turning authorized voice evidence into a provenance-rich, reviewable Payment Intent using a real ASR provider contract and explicit diagnostic uncertainty.

Audio evidence introduces distinct challenges:
1. **Acoustic Container & Header Integrity**:
   - Voice evidence items must be parsed at the container level (WAV RIFF, MP3, OGG) to extract duration, sample rate, and channel geometry. Corrupted headers or unsupported formats must fail closed without crashing background workers.
2. **Representative Language Strata**:
   - Payout operations in India require support for Indian English (`en-IN`), Hindi (`hi-IN`), and standard English (`en-US`), with verbatim transcripts and time-aligned token segments.
3. **Fine-Grained Field Provenance**:
   - Rather than treating an entire audio file as a black box, each extracted Payment Intent field (`counterparty`, `destination`, `amount`, `purpose`, `instruction_reference`) must bind to specific audio timestamps `[start_ms, end_ms]`, a text snippet, and the evidence content hash.
4. **ASR & Anti-Spoof Diagnostics**:
   - Deepfake, synthetic voice, and replay attacks pose critical payout risk. The pipeline must execute AASIST synthetic speech detection, exposing model version, anti-spoof score, and typed states (`GENUINE`, `SYNTHETIC_DETECTED`, `SUSPECTED_SPOOF`, `UNCERTAIN`, `NOT_EVALUATED`).
5. **Protective Fail-Closed Workflow Behavior**:
   - Timeouts, malformed output, unsupported formats, low ASR confidence (< 0.80), detected synthetic speech, and unresolved material ambiguity (contradictory spoken amounts or destinations) must halt the pipeline in a protective failure state and never promote the Payment Intent to `CONFIRMED` or `EXTRACTED`.

## Decision

1. **Audio Metadata Parser (`src/payoutproof/agent/audio.py`)**:
   - `parse_audio_metadata(data, declared_mime)` validates RIFF/WAVE chunks, sample rate, channels, bit depth, and duration in milliseconds.
   - Raises `AudioCorruptedError` or `AudioFormatError` on truncated or invalid payloads.

2. **Language Strata & Field-Level Audio Provenance (`src/payoutproof/agent/audio.py`)**:
   - Predeclared language strata (`en-IN`, `hi-IN`, `en-US`) generate verbatim transcripts and segment timestamps.
   - Each intent field receives a `FieldAudioProvenance` descriptor formatted into canonical audit strings:
     `audio:field={field_name}:t={start_ms}-{end_ms}:hash={hash[:12]}:snippet={text_snippet}`.

3. **AASIST Anti-Spoof & ASR Diagnostics (`src/payoutproof/agent/audio.py`)**:
   - `AntiSpoofDiagnostic` records synthetic speech scores and typed status.
   - Genuine speech records `FindingName.AASIST_SYNTHETIC_SCORE` as `TruthState.SUPPORTED`.
   - Synthetic speech or spoof records `FindingName.AASIST_SYNTHETIC_SCORE` as `TruthState.CONTRADICTED` and halts extraction as `ExtractionFailureReason.SPOOF_DETECTED`.
   - Ambiguity and low SNR record `TruthState.INSUFFICIENT_QUALITY`.

4. **CaseInvestigation & Audit Integration (`src/payoutproof/agent/service.py`)**:
   - Updates `case_state.investigation` with `model_status` (`COMPLETED`, `AMBIGUOUS`, `SPOOF_DETECTED`, `FAILED`, `TIMED_OUT`), `asr_confidence`, `extraction_latency_ms`, `language_stratum`, and increments `attempt`.
   - Binds audio duration, language stratum, anti-spoof status, and ambiguity flags to the append-only `AuditChain`.

5. **Protective Fail-Closed Invariant**:
   - If an extraction fails, times out, detects spoof, encounters ambiguity, or exhibits low confidence, `intent.status` remains `NOT_EXTRACTED` and no affirmative finding is recorded.

## Consequences

- **Security**: Voice cloning and synthetic audio attacks are stopped before any payout grant or rail handoff can occur.
- **Explainability**: Reviewing operators see exact audio time offsets and verbatim snippets for each extracted payment field.
- **Audit Defensibility**: Cryptographic binding from raw audio bytes to field segments to policy gates ensures complete regulatory auditability.
