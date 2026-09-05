# IntentLock — 5-Minute Pitch & Live Demo Script

> [!abstract] Overview
> - **Product:** IntentLock (Zero-Trust Policy Gate for High-Risk Payouts)
> - **Track:** Razorpay AI Buildathon 2026 • Track 2: AI Risk Manager
> - **Target Pitch Duration:** ~3:15 spoken + ~1:30 live interaction (Under 5:00 total limit)
> - **Presenter:** Kunal Kumar Mehta

---

## Stage 1: The Hook & Core Vulnerability (0:00 – 0:45)

> [!note] Screen Action
> Show the **Hero view** or **Interactive Threat Landscape**. Highlight the tension between real-time payments (UPI/IMPS) and emerging generative threats.

### Spoken Script

"Hey everyone! I'm Kunal, and this is **IntentLock**: a zero-trust policy gate intercepting deepfake voice notes, urgent social engineering, and unauthorized payouts before money moves on RazorpayX.

Over the last few months, everyone's been hyping up autonomous AI agents that browse the web, execute actions, and call APIs. But when you look at how real-time payments work in India—especially **IMPS and UPI**—there is no *Ctrl-Z*. Once money leaves your account, it is gone forever.

At the same time, generative voice cloning has gotten terrifyingly accessible. An attacker can scrape a CEO's voice from a YouTube talk in thirty seconds, and drop an urgent WhatsApp voice note to an accounts operator:

> *'Hey, need you to clear an urgent payment of 4 lakh 25 thousand rupees to a new vendor right now.'*

Under pressure, the operator panics, drafts a payout on RazorpayX, and a busy manager approves it.

That led to our core design thesis: **Never let an LLM touch the financial trigger!**"

---

## Stage 2: The 3 Hard Authority Lanes (0:45 – 1:35)

> [!note] Screen Action
> Switch to **IntentLock Architecture Diagram** (`build/diagrams/IntentLock_Architecture.html`). Use Arrow keys or the Step button to trace the flow from left to right.

### Spoken Script

"So we built **IntentLock**. We split the entire system into three hard authority lanes.

- **Lane 1 is the Trust Agent.** It ingests the raw evidence—whether that's an audio voice note, WhatsApp screenshot, or PDF invoice—under strict DPDP privacy rules. It transcribes the audio, extracts the counterparty, bank account, amount, and purpose, and grounds every single field to an exact evidence span. But crucially: **Lane 1 has zero authority to move money.**

- **Lane 2 is the Deterministic Policy Gate.** The operator reviews the extracted intent and clicks Confirm. This freezes an immutable **SHA-256 intent hash**. At this exact moment, the AI is completely removed from the loop. A 100% deterministic Python rule engine takes over. It verifies the intent against approved bank registries. If the bank account is unapproved, policy immediately returns **Step-Up Required**. It refuses to move forward until two independent controls are verified: an out-of-band callback and a separate finance controller sign-off.

- **Lane 3 is the Maker-Checker Rail.** Once the controller approves the new destination, the case transitions to **Eligible for Handoff**. IntentLock issues a single-use, 15-minute **HMAC-SHA256 grant**. An idempotent action adapter submits exactly one pending item into RazorpayX's Maker-Checker queue, leaving final execution to RazorpayX."

---

## Stage 3: Real-World Fault Tolerance & Safe Failure (1:35 – 2:20)

> [!note] Screen Action
> Switch to **Operational Flow Diagram** (`build/diagrams/IntentLock_SequenceFlow.html`). Highlight the timeout branch and the red *Reconciliation Required* state.

### Spoken Script

"Now, what happens when things break in the real world? Say the network drops or the bank gateway times out mid-transfer. 

Naive systems blindly retry, risking double payouts. In IntentLock, **uncertainty never becomes permission.**

The system enters **Reconciliation Required**, permanently burns the single-use HMAC grant, and deterministically rejects any blind retry. If anyone tampers with the amount or bank account, the intent hash breaks and the grant is instantly voided."

---

## Stage 4: Engineering Rigor & Disclosed Invariants (2:20 – 3:00)

> [!note] Screen Action
> Show the **Verification Spine & Terminal / UI** (`uv run pytest` or the Operator Console Benchmark tab showing 403 passing tests).

### Spoken Script

"In payments, honesty is everything. I refused the hackathon temptation to fake 99% accuracy. 

We built a testing spine with **403 passing tests** across three suites: 
1. 45 dev cases,
2. 90 sealed policy cases, and
3. An 81-execution critical safety suite.

Over all 81 safety runs, IntentLock achieved **zero unsafe handoffs**.

The entire codebase is open source under the MIT license, with clean Docker builds and passing GitHub Actions CI. Our startup wedge is urgent payout exception gating for Indian mid-market companies on RazorpayX."

---

## Stage 5: The Closing Ask (3:00 – 3:15)

> [!note] Screen Action
> Show repo GitHub page (`github.com/KunalKumarMehta/razorpay`) and concluding contact details.

### Spoken Script

"Our next step is taking IntentLock to three design partners to stress-test this in live shadowing.

I'd love the panel's questions and architectural grilling. Thank you!"

---

## Quick Reference / Delivery Notes

> [!tip] Pacing & Demeanor
> - **Tone:** Grounded, technical, and confident. Not salesy.
> - **Key Catchphrase:** *"Never let an LLM touch the financial trigger!"* (Hit this with conviction at 0:40).
> - **Rule of Thumb:** Speak at a calm, deliberate pace (~130 words/minute). The script has 520 words, taking ~3 minutes and 40 seconds, leaving over a minute for UI interaction.
