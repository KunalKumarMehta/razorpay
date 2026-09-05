import asyncio
import os
import edge_tts

# Andrew Multilingual is exceptionally natural, conversational, and energetic
VOICE = "en-US-AndrewMultilingualNeural"
RATE = "+10%"
PITCH = "+0Hz"

SCRIPT_TEXT = """
Hey everyone! I'm Kunal, and this is IntentLock: a zero-trust policy gate intercepting deepfake voice notes, urgent social engineering, and unauthorized payouts before money moves on RazorpayX.

Over the last few months, everyone's been hyping up autonomous AI agents that browse the web, execute actions, and call APIs. But when you look at how real-time payments work in India—especially IMPS and UPI—there is no Ctrl-Z. Once money leaves your account, it is gone forever.

At the same time, generative voice cloning has gotten terrifyingly accessible. An attacker can scrape a CEO's voice from a YouTube talk in thirty seconds, and drop an urgent WhatsApp voice note to an accounts operator: "Hey, need you to clear an urgent payment of four lakh twenty-five thousand rupees to a new vendor right now." Under pressure, the operator panics, drafts a payout on RazorpayX, and a busy manager approves it.

That led to our core design thesis: Never let an LLM touch the financial trigger!

So we built IntentLock. We split the entire system into three hard authority lanes.

Lane 1 is the Trust Agent. It ingests the raw evidence—whether that's an audio voice note, WhatsApp screenshot, or PDF invoice—under strict DPDP privacy rules. It transcribes the audio, extracts the counterparty, bank account, amount, and purpose, and grounds every single field to an exact evidence span. But crucially: Lane 1 has zero authority to move money.

Lane 2 is the Deterministic Policy Gate. The operator reviews the extracted intent and clicks Confirm. This freezes an immutable SHA-256 intent hash. At this exact moment, the AI is completely removed from the loop. A 100% deterministic Python rule engine takes over. It verifies the intent against approved bank registries. If the bank account is unapproved, policy immediately returns Step-Up Required. It refuses to move forward until two independent controls are verified: an out-of-band callback and a separate finance controller sign-off.

Lane 3 is the Maker-Checker Rail. Once the controller approves the new destination, the case transitions to Eligible for Handoff. IntentLock issues a single-use, 15-minute HMAC-SHA256 grant. An idempotent action adapter submits exactly one pending item into RazorpayX's Maker-Checker queue, leaving final execution to RazorpayX.

Now, what happens when things break in the real world? Say the network drops or the bank gateway times out mid-transfer. Naive systems blindly retry, risking double payouts. In IntentLock, uncertainty never becomes permission. The system enters Reconciliation Required, permanently burns the single-use HMAC grant, and deterministically rejects any blind retry. If anyone tampers with the amount or bank account, the intent hash breaks and the grant is instantly voided.

In payments, honesty is everything. I refused the hackathon temptation to fake 99% accuracy. We built a testing spine with 403 passing tests across three suites: 45 dev cases, 90 sealed policy cases, and an 81-execution critical safety suite. Over all 81 safety runs, IntentLock achieved zero unsafe handoffs.

The entire codebase is open source under the MIT license, with clean Docker builds and passing GitHub Actions CI. Our startup wedge is urgent payout exception gating for Indian mid-market companies on RazorpayX.

I'd love the panel's questions and architectural grilling. Thank you!
"""

async def generate():
    output_dir = "build"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "IntentLock_Pitch_Voiceover.mp3")

    print(f"Generating voiceover using voice: {VOICE} at rate: {RATE}...")
    communicate = edge_tts.Communicate(SCRIPT_TEXT.strip(), VOICE, rate=RATE, pitch=PITCH)
    await communicate.save(output_path)
    print(f"Voiceover successfully generated: {output_path}")

if __name__ == "__main__":
    asyncio.run(generate())
