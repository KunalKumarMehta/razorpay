# Prototype the Operator and Demo Journey

Type: prototype
Status: resolved
Blocked by: 08, 09

## Question

What should the five-minute experience look and feel like from the triggering risk event through investigation, explanation, policy decision, human intervention, graceful failure, and measurable outcome, and which concrete prototype best exposes flaws before architecture is fixed?

## Answer

The validated journey is embodied in [the self-contained PayoutProof operator-journey logic prototype](../prototypes/payoutproof-operator-journey-throwaway.html). It exposes the full readable state, keeps every transition available for free play, and provides guided walkthroughs for the happy path, step-up, contradiction/Hold, canonical-snapshot `BLOCKED`, Admission Rejection, material-edit invalidation, model failure, and replay/ambiguous handoff.

The five-minute pitch should auto-advance evidence admission and Trust Agent extraction, then reserve visible operator gestures for confirming the exact Payment Intent, providing the specified step-up evidence, and initiating handoff. The detailed prototype remains click-by-click so reviewers can challenge hidden preconditions. The explanation should keep three state tracks visibly separate: provenance-linked investigation, deterministic evaluation of a frozen snapshot, and human/adapter handoff. The measurable ending is a pending item in the existing approval rail, never payout approval or execution.

Independent callback confirms an instruction but cannot approve an unapproved destination. Eligibility requires both the specified callback and separate policy-governed destination-approval evidence; otherwise the outcome remains `STEP_UP_REQUIRED`. A material intent edit invalidates the evaluation, active grant, and any exact-intent callback finding; destination approval may remain valid when it is separately bound only to the counterparty and destination. Model or required-signal failure produces a fail-closed `HOLD` with a specific recovery action.

Incomplete processing authority produces an **Admission Rejection** before evidence enters the investigation: no Risk Case opens and no Policy Outcome exists. `BLOCKED` is reserved for an admitted canonical snapshot that fails gate checks because it is unauthorized, tampered, prohibited, or structurally invalid. Admission Rejections still belong in the audit trail and Critical Safety Suite.

An eligible result and a Handoff Grant remain distinct visible transitions. If adapter status becomes ambiguous, the historical `ELIGIBLE_FOR_HANDOFF` result remains intact while the operational state becomes **Reconciliation Required**; the grant becomes unavailable for reuse and the adapter rejects blind replay. Reevaluation occurs only if intent, evidence, or policy validity changes.
