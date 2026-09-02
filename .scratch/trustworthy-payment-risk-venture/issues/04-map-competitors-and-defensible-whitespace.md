# Map Competitors and Defensible Whitespace

Type: research
Status: resolved

## Question

Which vendors and open-source projects already address voice deepfake detection, identity/document verification, payment approval controls, fraud case management, or transaction-risk orchestration, and where is there a defensible unmet workflow rather than a thin feature?

## Answer

See [Competitors and Defensible Whitespace](../research/04-competitors-and-defensible-whitespace.md). The category is crowded at the feature level: Feedzai, Alloy, Unit21, Sardine, and ComplyAdvantage cover major risk/orchestration/case workflows; Pindrop, Reality Defender, and Resemble cover synthetic-media signals; Persona, Jumio, and Trulioo cover identity/document checks; and RazorpayX, Modern Treasury, and Stripe provide approval/hold primitives. The defensible opening is therefore a narrow evidence-to-authorization workflow for urgent payout or beneficiary-change requests: bind unstructured request evidence and cross-channel/context checks to an exact payment intent, produce an explainable Risk Case, and let a deterministic Policy Gate hand a hold/approval decision to the existing payout rail. This is an inference from public product surfaces; no public docs prove incumbents lack an unadvertised version, and willingness to pay remains unvalidated.
