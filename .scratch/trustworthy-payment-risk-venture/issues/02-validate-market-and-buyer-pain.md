# Validate the Market and Buyer Pain for Payment-Authorization Impersonation

Type: research
Status: resolved

## Question

How frequent and costly are voice-, identity-, document-, and context-based impersonation attacks around payment authorization; which organizations feel the pain most acutely; who owns the budget; what controls fail today; and what evidence supports an India-first startup wedge?

## Answer

The market evidence supports an India-first wedge, with an important boundary: build **pre-authorization investigation for urgent or changed payout instructions**, not a standalone voice/deepfake detector. The FBI recorded 24,768 BEC complaints and $3.0466B in reported losses in 2025, while its latest AI analysis records 135 AI-referenced BEC complaints/$30.26M and describes cloned voice, video, and synthetic identity documents used to elicit payments or obtain bank access. RBI reports 13,516 card/internet frauds involving ₹520 crore in FY2024-25 (the broadest India proxy, not an impersonation-only measure), and NPCI reports 22,716.07M UPI transactions worth ₹28,92,138.67 crore in June 2026. I4C's CFCFRMS had saved more than ₹8,690 crore across 24.65 lakh complaints by 31 January 2026, showing substantial live intervention demand.

The most credible first buyers are inferred to be Indian banks, non-bank PSOs/payment aggregators, and fintech payment/fraud-operations teams; a secondary segment is corporate treasury/finance teams approving high-value or urgent payouts. RBI assigns fraud governance to the Board, Risk Management Committee, senior management, and a GM-equivalent in banks, and assigns Board/CISO oversight, real-time monitoring, auditability, and rapid response to PSOs. The economic buyer is therefore likely Head of Fraud/Financial Crime or Payments Risk, CISO/security, or Payments Operations, with CFO/treasury as the enterprise sponsor; titles and willingness to pay remain unvalidated.

The control gap is that MFA/OTP, caller ID, sender identity, familiar voice, document matching, or transaction rules can be manipulated or can authenticate a deceived user without proving beneficiary, purpose, or request context. Current response also becomes fragmented and after-the-fact; FBI and MHA both emphasize immediate recall/reporting and speed. The recommended MVP is a Trust Agent that assembles the call/voice note, email/chat/invoice, identity/document, beneficiary, and transaction context into an auditable Risk Case, then hands a deterministic Policy Gate a hold/step-up/human-approval decision. No autonomous Money Action.

See the cited research asset: [Market and Buyer Pain: Payment-Authorization Impersonation](../research/02-market-and-buyer-pain.md).

Uncertainty: no primary public dataset isolates India-specific voice-clone, forged-document, or context-impersonation payment attacks; FBI data are complaint-based and RBI's amount-involved figures are not loss. Buyer budget and willingness to pay require customer discovery.
