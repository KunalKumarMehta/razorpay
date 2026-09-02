# Technical Feasibility and Cost-Aware Resource Inventory

**Research date:** 2026-09-02  
**Question:** Which open datasets, open-weight models, deterministic methods, local runtimes, Razorpay test-mode APIs, free tiers, credits, and paid fallbacks can credibly support the candidate ventures, and what latency, accuracy, multilingual, privacy, integration, and solo-build feasibility limits do they impose?

## Conclusion

The leading venture is technically feasible as a **local-first, recorded-audio Trust Agent** for an urgent payout or beneficiary-change request. The smallest credible build is: upload a voice note (and optionally a synthetic document/screenshot), transcribe locally, run an open audio anti-spoofing model as one signal, extract structured facts, apply deterministic quality and policy rules, and produce an auditable Risk Case. The Money Action remains behind a separate Policy Gate and a human approval; the buildathon integration can safely use RazorpayX Test Mode.

Do not make “detect a deepfake” the product claim. Public detectors and datasets are research benchmarks, not a universal voice-clone oracle. The durable, reproducible value is conservative evidence fusion: audio authenticity, transcript/request consistency, beneficiary history, document field checks, and missing/low-quality evidence become explicit findings and a hold/step-up recommendation.

The MVP can be built for **zero required API spend** using local models, Docker, SQLite/Postgres, OpenTelemetry, and Razorpay test credentials. Optional hosted inference or deployment should be treated as a bounded convenience or paid fallback, never as the source of truth or as a place to send real customer audio/documents without a reviewed data agreement.

## Recommended stack by capability

| Capability | Free/open first choice | What it can credibly do | Hard limit / implication | Paid fallback and trigger |
|---|---|---|---|---|
| Speech-to-text and language ID | [Whisper](https://github.com/openai/whisper) (MIT weights/code); [AI4Bharat IndicConformer](https://github.com/AI4Bharat/IndicConformerASR) (MIT); [Mozilla Common Voice](https://commonvoice.mozilla.org/en/datasets) for ASR evaluation/augmentation | Whisper is multilingual ASR, translation, language ID, and VAD. IndicConformer covers all 22 official Indian languages and publishes a 600M multilingual checkpoint plus monolingual checkpoints. | Whisper’s reference `transcribe()` reads the whole file in sliding 30-second windows; its published speed numbers are A100 measurements and vary widely by language, speaking rate, and hardware. IndicConformer requires the AI4Bharat NeMo stack and a 600M model, so benchmark memory/latency on the founder’s laptop. Common Voice is ASR data, not deepfake or identity evidence; its dataset terms prohibit attempting to determine speaker identity. | [AssemblyAI pricing](https://www.assemblyai.com/pricing) advertises a $50 free offer and streaming/pre-recorded STT; [Google Cloud Speech-to-Text](https://cloud.google.com/speech-to-text/pricing) is pay-as-you-go. Use only if local transcription misses a required language or the demo needs streaming latency. |
| Voice/deepfake signal | [AASIST](https://github.com/clovaai/aasist) (official PyTorch implementation, MIT; official [checkpoint card](https://huggingface.co/SpeechAntiSpoofingBenchmarks/AASIST)); RawNet2 and LFCC-GMM/LFCC-LCNN baselines in the [ASVspoof 2021 repository](https://github.com/asvspoof-challenge/2021) | Scores whether an audio segment resembles bona-fide or spoofed speech under a research protocol; AASIST has an official ASVspoof-trained implementation and pretrained model distribution. | ASVspoof explicitly evaluates channel variation and separate LA/PA/DF conditions; ASVspoof 2021 released new evaluation data without new train/development data. [WaveFake](https://zenodo.org/records/5642694) is 104,885 generated clips (~175 hours) but only two reference languages and synthetic generator families; it is 28.9 GB and its data license is CC-BY-SA 4.0. [ASVspoof 5](https://zenodo.org/records/14498691) is a valuable newer benchmark (around 2,000 speakers, >20 attacks) but the download is 142.3 GB and the repository identifies the language as English. A high benchmark score is not field accuracy on Indian PSTN/VoIP audio. | A specialist commercial voice-risk detector may be evaluated later against a held-out local set. There is no safe paid replacement for missing in-domain labels; procurement cannot remove the need for calibration and human review. |
| Speaker turns / comparison | [pyannote.audio](https://github.com/pyannote/pyannote-audio) (MIT code; community pipeline); [SpeechBrain](https://github.com/speechbrain/speechbrain) (Apache-2.0, ECAPA-TDNN recipes) | Diarizes speaker turns and provides speaker-embedding/verification building blocks. The community pipeline runs locally; pyannote’s README documents optional hosted premium inference. | Open pipeline use requires accepting the Hugging Face model conditions and an access token. Diarization says “who spoke when,” not “this is the CFO”; speaker verification requires consented enrollment data and has quality/demographic risks. Never enroll or identify Common Voice contributors. | pyannoteAI’s premium pipeline is a practical hosted fallback (the project documents free credits), but it moves audio off-device and needs a privacy/retention review. |
| OCR/document field extraction | [PaddleOCR](https://github.com/PaddlePaddle/PaddleOCR) (Apache-2.0; 100+ languages and local/ONNX serving paths); [Tesseract](https://tesseract-ocr.github.io/tessdoc/Installation.html) (Apache-2.0); [OpenCV](https://opencv.org/license/) (Apache-2.0) | Local OCR, document crop/quality checks, barcode/number normalization, and deterministic comparison of name/account/amount fields against the request. | [MIDV-500](https://arxiv.org/abs/1807.05786) has 500 videos/50 document types and public or publicly licensed source images; [MIDV-2020](https://arxiv.org/abs/2107.00396) uses 1,000 mock identity documents with artificial faces. Neither is an Indian KYC corpus, and OCR success does not establish authenticity, ownership, or live identity. [InsightFace](https://pypi.org/project/insightface/) code is MIT, but its provided pretrained models are non-commercial research-only; do not ship those weights in a startup MVP without a license review. | [Google Document AI](https://cloud.google.com/document-ai/pricing) can be purchased per processed page when production OCR/parser quality justifies it. A regulated KYC/face provider is a separate procurement and compliance decision, not a buildathon dependency. |
| LLM extraction/explanation | Deterministic parser first; local [llama.cpp](https://github.com/ggml-org/llama.cpp) (MIT server, quantization and OpenAI-compatible API) or [Ollama](https://docs.ollama.com/) local API; Qwen3 open weights (the official [Qwen repository](https://github.com/QwenLM/Qwen3) documents 0.6B–4B options, multilingual support, and local Ollama/llama.cpp paths); Gemma 4 2B/4B open weights under [Google’s terms](https://ai.google.dev/gemma/terms) | Use the model to summarize evidence into a fixed schema, never to decide authorization. Small quantized local models are enough for extraction and plain-language explanation when the parser and policy rules are authoritative. | Model output can hallucinate, omit fields, or vary by quantization; free hosted prompts may be retained/used for product improvement. Gemma is open-weight but has use/distribution terms rather than a simple MIT/Apache license. Model-specific cards and notices must travel with any distribution. | [Gemini API pricing](https://ai.google.dev/gemini-api/docs/pricing) gives a free tier for eligible models and pay-as-you-go tiers. Google says new accounts begin on the free tier, but free-tier data may be used to improve products; paid projects receive different data handling, and the Google Cloud $300 welcome credit cannot be used for Gemini API/AI Studio. Use only redacted/synthetic evidence in the free tier. |
| Policy gate and score fusion | Plain Python/TypeScript rules, JSON Schema/Pydantic validation, exact amount/payee normalization, beneficiary allowlist, cooldown, idempotency key, and an append-only case log; [scikit-learn calibration docs](https://scikit-learn.org/stable/modules/calibration.html) for held-out calibration | A deterministic state machine can enforce missing-evidence holds, maximum amount, new-beneficiary step-up, dual-control approval, and “no model can call a Money Action directly.” A weighted or conservative max-risk fusion can combine available signal scores after quality gating. | It is not a statistically valid probability until calibrated on disjoint, representative data. Unknown/low-quality inputs must be `insufficient_evidence`, not zero risk. Thresholds chosen on synthetic benchmarks must be shown as demo thresholds, not production fraud rates. | No paid service is required. A rules engine or policy-management product may be considered only after policy volume and audit requirements justify the operational cost. |
| Local runtime and deployment | Docker Compose; local SQLite for demo case storage, Postgres when multi-user; [llama.cpp](https://github.com/ggml-org/llama.cpp) or Ollama; [OpenTelemetry](https://opentelemetry.io/docs/) | Reproducible CPU/GPU service boundaries, local inference, structured logs/metrics/traces, and a laptop demo. OpenTelemetry is vendor-neutral and covers traces, metrics, and logs. | Model downloads are large; cold starts and CPU inference can dominate latency. Never persist raw audio/documents in logs. Use content hashes, redacted transcripts, model version, quality scores, policy version, and timings. | [Google Cloud Run pricing](https://cloud.google.com/run/pricing) is pay-per-use with monthly free usage and Mumbai/Delhi regions listed, but billing, network, registry, and inference-resource costs can still occur. [Render free services](https://render.com/docs/free) are suitable for a demo UI only: idle services spin down, take about a minute to wake, local files are ephemeral, free Postgres expires after 30 days, and Render says not to use free instances for production. |
| Razorpay integration | [Razorpay Payments Test/Live Modes](https://razorpay.com/docs/payments/dashboard/test-live-modes/), [test cards](https://razorpay.com/docs/payments/payments/test-card-details/), and [RazorpayX Test Mode](https://razorpay.com/docs/x/dashboard/test-mode/) | Test keys and test cards simulate payment flows without real-money settlement. RazorpayX Test Mode supports dummy balance, contacts, fund accounts, payouts, and webhooks; with a local Policy Gate and fake-adapter hold, the candidate can show a gated test payout and a Risk Case around it. | Razorpay Payment Test Mode cannot accept real payments. RazorpayX Test Mode has no real money and its Approval Workflow is unavailable, so `pending`/`rejected` states cannot be demonstrated through that workflow. Live API keys require activation/KYC and must not be used for this buildathon. | No fallback is needed for the MVP; use a local fake adapter for policy tests and RazorpayX Test Mode for the integration demo. |

## Voice feasibility and limits

### ASR and language coverage

Whisper’s official model table gives a useful solo-build envelope: `tiny`/`base` are approximately 1 GB VRAM, `small` ~2 GB, `medium` ~5 GB, `large` ~10 GB, and `turbo` ~6 GB; the published relative speeds are measured on an A100 and explicitly may vary significantly in the real world. The reference implementation processes the entire input through sliding 30-second windows. Therefore:

* Demo input should be a recorded voice note or uploaded call excerpt, not a carrier-level real-time call. Start with Whisper `base` or `turbo` according to laptop memory; pin the exact model and record runtime/model version in the Risk Case.
* If Hindi or other Indic languages are central, benchmark Whisper against AI4Bharat IndicConformer. IndicConformer covers the 22 official languages and is MIT, but its NeMo/600M setup is heavier than a tiny/base Whisper path. Do not promise language parity until the target-language test set is measured.
* A browser microphone can be chunked into short windows for a “near-real-time” visual demo, but chunk boundaries, partial transcripts, code-switching, and endpointing are additional failure modes. Treat the result as provisional evidence until the full audio is available.
* Common Voice is useful for language/ASR smoke tests and accent coverage, and current release listings show CC0-1.0 datasets across many locales including Bengali. It is not evidence that the voice is real or that the speaker is an authorized person; its terms prohibit attempting to determine contributor identity.

### Anti-spoofing, replay, and voice identity

AASIST and RawNet2 are credible open research starting points. The ASVspoof organizers publish baselines, evaluation scripts, and challenge metrics; ASVspoof 2021 explicitly separated logical access, physical access, and speech-deepfake tracks and focused one track on channel variation. WaveFake broadens generator families, while ASVspoof 5 broadens speakers, attack families, and crowdsourced acoustic conditions.

These resources impose three non-negotiable limits:

1. **Domain shift:** clean benchmark speech is not an Indian phone/VoIP recording, WhatsApp forward, noisy room, or replay from a speaker. A detector score must be shown with the codec/channel/quality metadata and treated as a clue.
2. **No universal calibration:** score distributions vary by model, attack family, microphone, language, and preprocessing. Calibrate on held-out files that were not used for fitting, and publish false-accept/false-reject trade-offs rather than a single “deepfake probability.”
3. **Identity is distinct:** diarization and speaker embeddings cannot prove that a caller is the claimed executive. Enrollment requires an authorized reference sample, consent, retention policy, and demographic/quality testing. A voice-clone score must never authorize a Money Action.

The buildathon acceptance test should seed a small, disclosed matrix of bona-fide and synthetic/replayed clips, then report detection score, transcript quality, processing time, and the final Policy Gate outcome. The score is a Risk Case finding; the gate’s conservative hold/step-up rule is the safety control.

## Documents and identity: feasible narrow slice, unsafe broad claim

PaddleOCR, Tesseract, and OpenCV make local document preprocessing and OCR straightforward. For a synthetic demo, generate mock IDs/invoices and test:

* crop/blur/glare/rotation quality checks;
* field extraction and normalization (name, account/VPA, amount, date);
* cross-field consistency (e.g., requested beneficiary and document beneficiary disagree);
* template/issuer allowlists and checksum-style format checks where the format is known;
* redaction of raw images after creating a content hash and structured findings.

MIDV-500 and MIDV-2020 are appropriate privacy-conscious benchmarks because they use public/licensed source images or artificial mock documents, but their document types and capture conditions are not an Indian KYC validation set. The startup claim should therefore be **“document evidence consistency and quality triage,”** not “authenticates Aadhaar/PAN/passports.” [UIDAI’s handbook](https://mndc.uidai.gov.in/images/LR_Aadhaar_Handbook_2026.pdf) says the Authority does not reveal personal information from the Aadhaar database; a buildathon prototype should use synthetic documents and no real Aadhaar data.

Do not include InsightFace’s automatically downloaded pretrained model packages in a commercial artifact without resolving their non-commercial-research restriction. A document branch is optional for the initial voice/payout wedge; it becomes a follow-on only when customer consent, document formats, and a licensed identity provider are available.

## Degraded-signal fusion and deterministic policy gating

The fusion layer is the most feasible differentiator because it is testable without training a production fraud model. For each input, compute a bounded finding with provenance:

* audio quality: duration, sample rate, clipping, silence/noise proxy, codec/container, and whether the anti-spoof model had enough speech;
* transcript: language, extraction confidence, amount/payee/VPA candidates, conflicting numbers, and whether a human can inspect the source segment;
* request context: urgency, changed beneficiary, amount delta, first-seen beneficiary, duplicate request, and mismatch with the known allowlist;
* document: OCR confidence, field agreement, template/format checks, and synthetic/test-data marker;
* system state: model/version, policy version, case hash, timestamps, and any missing signal.

Use quality gates before score fusion. If audio is too short or clipped, mark voice evidence missing. If OCR is unreadable, mark document evidence missing. Never map missing to “safe.” A practical rule set for the prototype is:

```text
if prohibited_or_malformed_request: BLOCK
elif unknown_or_changed_beneficiary: HOLD_FOR_HUMAN
elif any_high_severity_signal and evidence_quality_is_adequate: HOLD_FOR_HUMAN
elif insufficient_evidence: STEP_UP_SECOND_CHANNEL
else: ALLOW_TEST_ONLY
```

The LLM may explain this outcome in a fixed JSON schema, but only the deterministic Policy Gate can emit an `ALLOW_TEST_ONLY`, `HOLD_FOR_HUMAN`, `STEP_UP`, or `BLOCK` decision. The agent has no credential or tool route to a live Money Action.

For evaluation, use a held-out set and report precision/recall or PR-AUC for seeded risk cases, EER/minDCF where comparing with ASVspoof, calibration curve/Brier score for any probability-like output, median/p95 processing time, missing-evidence rate, and human reviewer agreement. Scikit-learn documents cross-validated `CalibratedClassifierCV`, sigmoid/isotonic calibration, and Brier/log loss; these are methods, not proof that the resulting score is production-calibrated.

## Razorpay test-mode integration contract

Razorpay documents separate Test and Live modes and separate API keys. Payments Test Mode is a sandbox with no real-money acceptance; test cards drive a mock-bank success/failure flow. RazorpayX Test Mode is more relevant to the urgent-payout wedge: it has a dummy balance, supports creating test Contacts, Fund Accounts, Payouts, and webhooks, and keeps test entities out of Live Mode. The test account can use dummy or real-world-shaped data without moving funds.

The integration should use an adapter with two implementations:

1. `razorpayx_test`: create a test contact/fund account/payout only after the local Policy Gate returns `ALLOW_TEST_ONLY` and a human clicks the demo approval.
2. `fake`: deterministic in-memory or SQLite state machine for unit tests, including blocked/held/released/error paths that Test Mode cannot show.

Razorpay’s webhook guidance requires validating the `X-Razorpay-Signature` HMAC-SHA256 over the **raw** request body, deduplicating with `x-razorpay-event-id`, and designing for retries/event ordering. Store the raw event hash and parsed event metadata, but do not log secrets or unredacted PII. The RazorpayX Test Mode limitation is material: Approval Workflow is not available, so pending/rejected approval states need the fake adapter for the demo.

## Privacy, hosting, and observability

Local inference is the default privacy boundary: audio/docs remain on the laptop or a controlled container; the Risk Case stores redacted text, hashes, quality features, model identifiers, and policy decisions. Retain raw media only when a reviewer explicitly asks for it, encrypt it if retained, and define deletion in the blueprint. Free hosted AI tiers are not automatically private. Google says free-tier Gemini content may be used to improve products, while paid API projects receive different data-handling terms; Hugging Face’s routed Inference Providers give free users monthly credits but provider/account billing and data paths vary. Use synthetic or redacted cases for hosted smoke tests.

For deployment:

* Docker Compose plus SQLite is the reproducible solo path. Add Postgres only when a multi-user demo requires it.
* Cloud Run can host a stateless API, and the pricing page lists monthly free usage and Mumbai/Delhi regions; it still requires billing setup and charges beyond the free tier and for related services such as build/registry/network usage.
* Render can expose a polished demo cheaply, but free services sleep after 15 minutes, wake in about a minute, lose local files on restart, and free Postgres expires after 30 days. Do not store audio, docs, or authoritative case history only on a free instance.
* OpenTelemetry supplies vendor-neutral traces, metrics, and logs. Instrument `case_id`, `trace_id`, stage (`decode`, `asr`, `anti_spoof`, `ocr`, `extract`, `policy`, `razorpay`), model/policy version, duration, and outcome. Redact transcript text and all secrets; sample payloads by hash, not raw media.

## Cost and solo-build recommendation

The recommended cash-minimum path is:

1. Use synthetic voice notes and mock documents plus a small, legally usable slice of ASVspoof/WaveFake/MIDV for offline evaluation; do not download ASVspoof 5 or WaveFake wholesale unless storage and time are available.
2. Run Whisper base/turbo, AASIST, PaddleOCR/Tesseract, and a small local LLM on the target machine. Record actual latency and peak memory; do not substitute published A100 speeds for measurements.
3. Keep the Policy Gate and fake Razorpay adapter deterministic, then add RazorpayX Test Mode using test keys, dummy balance, and webhook signature verification.
4. Use Render or Cloud Run only for a stateless presentation layer if a public URL is required, with spend caps and no raw evidence persistence.
5. Spend on AssemblyAI/GCP STT, Gemini paid API, Document AI, or a specialist identity/voice service only when a measured MVP failure justifies the incremental value. Paid inference does not solve benchmark/domain mismatch or replace human approval.

This stack is feasible for a solo founder in buildathon time because the hard work is integration, redaction, deterministic policy, and evaluation—not training a new anti-spoofing or KYC model. A full carrier-level real-time voice deployment, production identity verification, and live payouts remain outside the MVP and require separate privacy, security, reliability, and regulatory work.

## Uncertainty and evidence limits

* No local founder Gemini Deep Research summary was present in this workspace; this inventory therefore uses first-party docs, source repositories, dataset-owner pages, and official API pricing/docs. The founder summary should be reconciled if ticket 05 surfaces it.
* Actual end-to-end latency, memory, WER, OCR accuracy, and anti-spoof EER on the founder’s machine and Indian phone audio are unmeasured here. They are acceptance-gate measurements, not assumptions.
* Dataset and model licenses are separate from code licenses and can change. Before publishing a commercial artifact, pin versions and retain each model/dataset card and license.
* Free-tier quotas, credits, prices, and hosted data-use terms change. The links above were checked on 2026-09-02 and should be rechecked immediately before implementation.

## Sources

1. [ASVspoof 2021 official release, datasets, metrics, and channel-variation scope](https://www.asvspoof.org/index2021.html)
2. [ASVspoof 5 official baseline repository](https://github.com/asvspoof-challenge/asvspoof5)
3. [ASVspoof 5 dataset owner page and size/attack/speaker metadata](https://zenodo.org/records/14498691)
4. [WaveFake dataset owner page, languages, size, and CC-BY-SA 4.0 license](https://zenodo.org/records/5642694)
5. [AASIST official implementation](https://github.com/clovaai/aasist)
6. [AASIST official checkpoint card](https://huggingface.co/SpeechAntiSpoofingBenchmarks/AASIST)
7. [OpenAI Whisper official repository/model table](https://github.com/openai/whisper)
8. [AI4Bharat IndicConformer official repository](https://github.com/AI4Bharat/IndicConformerASR)
9. [Mozilla Common Voice dataset catalog](https://commonvoice.mozilla.org/en/datasets)
10. [Mozilla Data Collective dataset terms example](https://datacollective.mozillafoundation.org/datasets/cmflnuzz3ivk743c0mb6yee4g)
11. [pyannote.audio official repository and local/community/premium pipelines](https://github.com/pyannote/pyannote-audio)
12. [SpeechBrain official repository](https://github.com/speechbrain/speechbrain)
13. [PaddleOCR official repository](https://github.com/PaddlePaddle/PaddleOCR)
14. [Tesseract official documentation](https://tesseract-ocr.github.io/tessdoc/Installation.html)
15. [OpenCV license](https://opencv.org/license/)
16. [MIDV-500 paper/dataset description](https://arxiv.org/abs/1807.05786)
17. [MIDV-2020 paper/dataset description](https://arxiv.org/abs/2107.00396)
18. [UIDAI Aadhaar Handbook 2026](https://mndc.uidai.gov.in/images/LR_Aadhaar_Handbook_2026.pdf)
19. [InsightFace Python package license/model restriction](https://pypi.org/project/insightface/)
20. [llama.cpp official repository](https://github.com/ggml-org/llama.cpp)
21. [Ollama official API documentation](https://docs.ollama.com/)
22. [Qwen3 official repository](https://github.com/QwenLM/Qwen3)
23. [Gemma model overview](https://ai.google.dev/gemma/docs/core)
24. [Gemma terms of use](https://ai.google.dev/gemma/terms)
25. [Gemini API pricing](https://ai.google.dev/gemini-api/docs/pricing)
26. [Gemini API billing/data handling and credit limitations](https://ai.google.dev/gemini-api/docs/billing)
27. [Hugging Face Inference Providers pricing/credits](https://huggingface.co/docs/inference-providers/pricing)
28. [AssemblyAI pricing and free offer](https://www.assemblyai.com/pricing)
29. [Google Cloud Speech-to-Text pricing](https://cloud.google.com/speech-to-text/pricing)
30. [Google Cloud Document AI pricing](https://cloud.google.com/document-ai/pricing)
31. [Google Cloud Run pricing/free tier](https://cloud.google.com/run/pricing)
32. [Render free deployment limitations](https://render.com/docs/free)
33. [OpenTelemetry documentation](https://opentelemetry.io/docs/)
34. [Razorpay Test and Live Modes](https://razorpay.com/docs/payments/dashboard/test-live-modes/)
35. [Razorpay test card details](https://razorpay.com/docs/payments/payments/test-card-details/)
36. [RazorpayX Test Mode](https://razorpay.com/docs/x/dashboard/test-mode/)
37. [RazorpayX Payout APIs](https://razorpay.com/docs/api/x/)
38. [Razorpay webhook validation/testing](https://razorpay.com/docs/webhooks/validate-test/)
39. [Razorpay API authentication and test/live key guidance](https://razorpay.com/docs/api/authentication/)
40. [scikit-learn probability calibration](https://scikit-learn.org/stable/modules/calibration.html)
