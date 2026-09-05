import asyncio
import os
import edge_tts

VOICE = "en-IN-PrabhatNeural"  # Natural Indian English male voice, friendly & confident
# Alternative: "en-US-AndrewMultilingualNeural" or "en-US-BrianMultilingualNeural"

SCRIPT_TEXT = """
Hey everyone! I'm Kunal, a 2nd year CS undergrad, and this is IntentLock.

Over the last few months, I saw everyone on Twitter hyping up autonomous AI agents that can browse the web and make API calls. But when you look at how payments actually work in India—especially real-time rails like UPI and IMPS—there is no Ctrl-Z. Once money leaves your account, it is gone forever.

At the same time, generative voice cloning has made executive impersonation crazy easy. Imagine an attacker clones a CEO's voice from a YouTube talk, and drops an urgent WhatsApp voice note to an accounts intern at 4:30 PM: "Hey, need you to clear an urgent payment of 4 lakh 25 thousand rupees for a tooling deposit right now." The operator panics, drafts a payout on RazorpayX, and a busy finance manager clicks approve.

I realized: autonomous payment agents are a critical vulnerability. You should never let an LLM touch the financial trigger!

So I built IntentLock. We split the entire system into three hard authority lanes.

Lane 1 is the Trust Agent. It ingests the noisy audio or WhatsApp screenshot under strict DPDP privacy rules. It transcribes the voice note, extracts the exact counterparty, bank account, amount, and purpose, and links every field to the exact evidence span. Crucially, the AI has zero permission to move money.

Lane 2 is the Deterministic Policy Gate. The operator reviews the extracted intent and clicks Confirm. This freezes a cryptographic SHA-256 intent hash. Now the LLM is completely out of the loop. A 100 percent deterministic Python rule engine verifies the intent against approved bank registries. If the bank account is unapproved, policy immediately returns Step Up Required. It refuses to proceed until two independent controls are verified: an out-of-band callback and a separate finance controller approval.

Lane 3 is the Maker-Checker Rail. Once the controller approves the new destination, policy transitions to Eligible for Handoff. IntentLock signs a single-use, 15-minute HMAC-SHA256 Handoff Grant. An idempotent action adapter submits exactly one pending item to RazorpayX's Maker-Checker queue. RazorpayX retains final approval authority.

Now, what happens when the real world fails? Suppose the network drops or the bank gateway times out during handoff. Naive systems retry blindly, which can cause double payouts! In IntentLock, uncertainty never becomes permission. The system enters Reconciliation Required, permanently burns the single-use HMAC grant, and deterministically rejects any blind retry. Furthermore, if anyone tries to tamper with the amount or bank account, the intent hash breaks and the grant is immediately invalidated.

In payments, honesty is everything. I refused the hackathon temptation to fake 99 percent accuracy. We built a testing spine with 403 passing unit tests and ran three evaluation suites: 45 dev cases, 90 sealed policy cases, and an 81-execution critical safety suite. Over all 81 safety runs, IntentLock achieved zero unsafe handoffs.

The entire codebase is open source under the MIT license, with clean Docker builds and passing GitHub Actions CI.

Our startup wedge is urgent payout exception gating for Indian mid-market businesses running on RazorpayX. My next step is taking IntentLock to three design partners to stress-test this in live shadowing.

I'd love the panel's feedback and guidance. Thank you!
"""

async def generate():
    output_dir = "build"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "IntentLock_Pitch_Voiceover.mp3")

    print(f"Generating voiceover using voice: {VOICE}...")
    communicate = edge_tts.Communicate(SCRIPT_TEXT.strip(), VOICE, rate="+3%", pitch="+0Hz")
    await communicate.save(output_path)
    print(f"Voiceover successfully generated: {output_path}")

if __name__ == "__main__":
    asyncio.run(generate())
