# Venture Selection Scorecard — Decision Support

**Prepared:** 2026-09-02 (Asia/Kolkata)  
**Status:** recommendation only; the founder has not selected the venture or runners-up  
**Decision ticket:** [Select the Venture and Two Runners-Up](../issues/06-select-venture-and-runners-up.md)

## Recommendation

Recommend this podium for founder approval:

1. **Winner — PayoutProof: Urgent Payout Trust Agent.** Convert a recorded call or voice note, optional message/invoice evidence, beneficiary history, and a candidate payout into an exact payment intent and auditable Risk Case. A deterministic Policy Gate—not the agent—decides whether the exact intent may proceed to test-only human approval, must be held, or needs step-up verification.
2. **Runner-up — ChangeGuard: Beneficiary-Change Verification Agent.** Narrow the workflow to vendor bank-detail or beneficiary changes in accounts payable. Compare the request, invoice, known beneficiary record, and independent callback evidence before a human can approve the changed payment destination.
3. **Runner-up — RecallReady: Payment-Fraud Recovery Triage Agent.** After a suspected fraudulent payment, assemble a time-critical evidence bundle, recommend the recall/reporting route, track unresolved handoffs, and keep every external action human-controlled.

The winner has the best combined Buildathon and startup profile. ChangeGuard is the simplest credible fallback but gives up agentic depth and differentiated scope. RecallReady addresses severe pain and has a larger coordination thesis, but actual recovery proof and institutional access are not credible within the Buildathon window.

## Method

Scores are 1–5, where 5 is favorable. For **regulatory exposure**, 5 means lower exposure and a cleaner safety boundary. The weighted total is `sum(weight × score / 5)`. Weights implement the map's approximate **60% Buildathon signal / 40% durable startup value** preference:

- Buildathon signal (60): Buildathon fit 12, measurable proof 10, differentiation 6, agentic depth 8, solo feasibility 10, resource availability 8, regulatory exposure 6.
- Startup value (40): severity of customer pain 9, market potential 9, defensibility 12, future expansion 10.

The numbers are comparative decision aids, not validated market measurements. Public evidence does not establish India-specific impersonation prevalence, buyer willingness to pay, or the absence of equivalent private incumbent features.

## Weighted scorecard

| Criterion | Weight | PayoutProof | ChangeGuard | RecallReady |
|---|---:|---:|---:|---:|
| Buildathon fit | 12 | 5 | 4 | 3 |
| Measurable proof | 10 | 4 | 5 | 2 |
| Severity of customer pain | 9 | 5 | 4 | 5 |
| Market potential | 9 | 4 | 3 | 4 |
| Differentiation | 6 | 4 | 2 | 3 |
| Agentic depth | 8 | 5 | 2 | 4 |
| Solo feasibility | 10 | 4 | 5 | 3 |
| Resource availability | 8 | 5 | 5 | 4 |
| Defensibility | 12 | 4 | 2 | 3 |
| Regulatory exposure (5 = lower) | 6 | 3 | 4 | 2 |
| Future expansion | 10 | 5 | 3 | 4 |
| **Weighted total / 100** | **100** | **88.2** | **71.4** | **67.4** |
| **Buildathon subtotal / 60** | **60** | **52.4** | **48.0** | **36.0** |
| **Startup subtotal / 40** | **40** | **35.8** | **23.4** | **31.4** |

## Evidence-based interpretation

### PayoutProof

- **Why it wins:** It fits the AI Risk Manager contract; produces held-out precision/recall, false-positive-cost, latency, evidence-completeness, and abstention measurements; demonstrates meaningful multi-stage agent work; and has a visible deterministic/human safety boundary.
- **Why it is feasible:** A local-first recorded-audio path can use Whisper or IndicConformer, AASIST as one non-authoritative signal, OCR for optional document fields, deterministic rules, a fake payout adapter, and RazorpayX Test Mode with zero required API spend.
- **Why it can become a startup:** It owns a specific request-level evidence and authorization contract instead of competing as a generic detector, KYC tool, fraud score, case manager, or maker-checker system.
- **Why it is not a certainty:** Direct risk platforms may support similar private workflows; audio models generalize poorly across real channels; India-specific prevalence and paid demand remain unvalidated; and production privacy, security, and regulatory work is substantial.

### ChangeGuard

- **Why it is the first runner-up:** Changed bank details and invoice fraud have direct support in official BEC guidance. Structured document/history comparisons are easy to reproduce, and the product can show a clean legitimate-versus-mismatch batch with low implementation risk.
- **Why it does not win:** OCR proves field consistency, not authenticity or authorization; identity/document verification is crowded; the workflow can collapse into deterministic AP rules with modest agentic depth; and the research does not establish an India-specific dataset or a durable moat.

### RecallReady

- **Why it remains on the podium:** FBI and Indian government guidance both establish that recall/reporting speed matters, while I4C's intervention scale supports a real coordination problem. A Risk Case and bounded routing agent could expand across banks, payment providers, and incident operations.
- **Why it does not win:** The build cannot honestly demonstrate money recovered, privileged institution access, or real external execution using synthetic data. That weakens both the AI Revenue Recovery track bar and the MVP's core value proof, while increasing compliance and operational dependence.

## Rejected as core ventures

- **Standalone voice-clone detector:** easy to demo and benchmark, but crowded, vulnerable to channel/domain shift, and incapable of establishing payment authorization.
- **Generic identity/document authenticator:** crowded by mature providers; available open data do not support a credible Indian KYC claim, and OCR is extraction rather than authenticity.
- **Generic fraud orchestration or case-management platform:** directly confronts Feedzai, Alloy, Unit21, Sardine, and ComplyAdvantage without a narrow workflow advantage.
- **New payout approval dashboard:** existing rails already provide maker-checker and hold/review primitives; the venture should feed evidence into them rather than rebuild them.

## Current grilling frontier

There is one founder decision whose prerequisites are settled. Buyer, job, exact evaluation contract, trust boundaries, prototype behavior, architecture, business model, and MVP sequencing depend on this selection and belong to later tickets.

❓ **Q1** - **Venture podium**: Which venture should the Buildathon Blueprint commit to as the winner, and which two should it preserve as runners-up?

Choose one complete podium or state an explicit reorder:

1. **Recommended podium:** PayoutProof wins; ChangeGuard is runner-up #1; RecallReady is runner-up #2.
2. **Simplicity-first reorder:** ChangeGuard wins; PayoutProof is runner-up #1; RecallReady is runner-up #2.
3. **Recovery-first reorder:** RecallReady wins; PayoutProof is runner-up #1; ChangeGuard is runner-up #2.

➡️ Choose option 1. PayoutProof is the only candidate that combines a strong five-minute demo, the AI Risk Manager's measurable defense-only contract, meaningful agentic work, a credible local/test-mode build, and a startup wedge differentiated at the request-to-authorization boundary. Preserve ChangeGuard as the lower-risk build fallback and RecallReady as the higher-dependency expansion alternative.
