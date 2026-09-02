# Razorpay Buildathon Venture

This context defines the business language for selecting and planning an agent-based Razorpay Buildathon submission that can become a real startup.

## Language

**Buildathon Blueprint**:
The decision-ready plan for one selected venture, covering its MVP, agent boundaries, architecture, evidence, evaluation, demo, free-resource stack, business model, and post-Buildathon roadmap.
_Avoid_: Idea list, generic project plan

**Startup Wedge**:
The first narrow, measurable payment-risk workflow through which the broader venture enters the market.
_Avoid_: Full platform, all-in-one solution

**Trust Agent**:
An agent that investigates payment-risk evidence and produces an explainable recommendation without independently authorizing a sensitive action.
_Avoid_: Autonomous payment agent, fraud oracle

**Policy Gate**:
A deterministic control that validates a Trust Agent's proposal against explicit permissions, limits, stopping rules, and human-approval requirements.
_Avoid_: Agent judgment, LLM guardrail

**Money Action**:
Any operation that can create, approve, alter, recover, refund, or otherwise affect a payment or financial obligation.
_Avoid_: Tool call, agent action

**Risk Case**:
The auditable bundle of signals, findings, confidence, recommended response, policy outcome, and unresolved exceptions for one suspected payment-risk event.
_Avoid_: Prediction, alert

**Payment Intent**:
The exact proposed payout, binding its counterparty, destination, amount, purpose, and originating instruction into one reviewable business object.
_Avoid_: Transaction, payment request

**Payment Operator**:
The finance-team member who receives a payout instruction and prepares its Payment Intent for review.
_Avoid_: User, fraud analyst

**Finance Control Owner**:
The business owner accountable for payout-process integrity, exception handling, and maker-checker effectiveness; commonly a Controller or Head of Finance.
_Avoid_: Approver, CISO

**Design Partner**:
An early customer that commits accountable stakeholders, representative workflow access, baseline measurement, and structured feedback to evaluate PayoutProof before production adoption.
_Avoid_: Beta tester, free pilot customer

**Approved Destination**:
A bank account, VPA, or equivalent payout endpoint whose association with a counterparty was accepted under the organization's finance policy before the current instruction.
_Avoid_: New beneficiary, verified identity

**Evaluation Case**:
A representative payout-instruction scenario with a known Payment Intent and expected Policy Outcome, used to evaluate PayoutProof.
_Avoid_: Test row, fraud sample

**Evaluation Version**:
An immutable sealed evaluation attempt binding one corpus, policy, model configuration, scorer, and complete set of outputs; a material change requires a fresh version and full rerun.
_Avoid_: Patched run, best run

**Operator Interaction**:
One predeclared observable human task in a payout-exception workflow, counted independently of automated model or policy work for paired workflow comparison.
_Avoid_: Click, time saved

**Protective Intervention Required**:
The headline evaluation condition in which policy requires Hold or Step Up Required rather than Eligible for Handoff; Blocked cases are reported separately as protective non-handoffs.
_Avoid_: Fraud detected, positive prediction

**Intent Binding Correct**:
An evaluation result in which every material Payment Intent field matches the available evidence, unresolved ambiguity remains explicit, and provenance is preserved.
_Avoid_: Mostly correct extraction, semantic match

**Unsafe Handoff**:
An outcome that marks a Payment Intent Eligible for Handoff despite a required protective outcome or an incorrect, unresolved, unsupported, or invalidated material field.
_Avoid_: False negative, model error

**Processing Authority Record**:
The case-scoped declaration of why a submitted evidence item may be processed, including its permitted purposes, restrictions, and lifecycle.
_Avoid_: Consent flag, legal approval

**Admission Rejection**:
The pre-investigation refusal of submitted evidence whose required Processing Authority Record is incomplete; no Risk Case is opened and no Policy Outcome exists.
_Avoid_: Blocked case, policy denial

**Policy Outcome**:
The deterministic workflow state assigned by the Policy Gate: Blocked, Hold, Step Up Required, or Eligible for Handoff; it is not a fraud verdict.
_Avoid_: Fraud score, model decision

**Handoff Grant**:
A single-use, expiring authorization that binds one eligible Risk Case and its exact Payment Intent to a fresh human-initiated handoff.
_Avoid_: Payment approval, agent permission

**Reconciliation Required**:
The operational state entered when a handoff attempt may have affected the downstream approval rail but its result is unknown; the grant cannot be reused and the attempt must not be blindly retried.
_Avoid_: Retry pending, policy hold

## Venture Concepts

**PayoutProof**:
The selected venture: a Trust Agent that converts an urgent payout instruction into an auditable Risk Case and submits the exact payment intent to a Policy Gate before it can enter an existing approval rail.
_Avoid_: Deepfake detector, payout approval dashboard

**ChangeGuard**:
The first runner-up: a narrower agent that verifies beneficiary or account-detail changes before an existing payment workflow accepts them.
_Avoid_: PayoutProof Lite, generic maker-checker

**RecallReady**:
The second runner-up: an agent that assembles and coordinates evidence for rapid payment-fraud recovery after a suspicious transfer has been initiated.
_Avoid_: Autonomous recovery agent, chargeback bot
