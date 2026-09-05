import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_deck(output_path="build/PayoutProof_Pitch_Deck.pptx"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    blank_layout = prs.slide_layouts[6]

    # Palette
    BG_DARK = RGBColor(11, 23, 42)       # #0B172A
    CARD_BG = RGBColor(19, 35, 64)       # #132340
    CARD_BORDER = RGBColor(37, 65, 110)  # #25416E
    TEXT_MAIN = RGBColor(248, 250, 252)  # #F8FAFC
    TEXT_MUTED = RGBColor(148, 163, 184) # #94A3B8
    BLUE_ACCENT = RGBColor(43, 132, 234) # #2B84EA
    CYAN_ACCENT = RGBColor(0, 186, 242)  # #00BAF2
    GREEN_ACC = RGBColor(16, 185, 129)   # #10B981
    AMBER_ACC = RGBColor(245, 158, 11)   # #F59E0B
    RED_ACC = RGBColor(239, 68, 68)      # #EF4444

    def add_header(slide, title_text, category_text="RAZORPAY AI BUILDATHON 2026 • TRACK 2: AI RISK MANAGER"):
        # Category
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.5), Inches(0.4))
        tf_c = cat_box.text_frame
        tf_c.word_wrap = True
        tf_c.margin_left = tf_c.margin_top = tf_c.margin_right = tf_c.margin_bottom = 0
        p_c = tf_c.paragraphs[0]
        p_c.text = category_text.upper()
        p_c.font.size = Pt(11)
        p_c.font.bold = True
        p_c.font.color.rgb = CYAN_ACCENT

        # Title
        t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.9), Inches(11.5), Inches(0.8))
        tf_t = t_box.text_frame
        tf_t.word_wrap = True
        tf_t.margin_left = tf_t.margin_top = tf_t.margin_right = tf_t.margin_bottom = 0
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.size = Pt(26)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_MAIN

    def set_slide_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_DARK
        bg.line.fill.background()
        return bg

    def add_card(slide, left, top, width, height, title, body_lines, accent_color=BLUE_ACCENT, badge=None):
        shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        shape.fill.solid()
        shape.fill.fore_color.rgb = CARD_BG
        shape.line.color.rgb = CARD_BORDER
        shape.line.width = Pt(1.2)

        # Content in text frame
        tf = shape.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.3)
        tf.margin_right = Inches(0.3)
        tf.margin_top = Inches(0.3)
        tf.margin_bottom = Inches(0.3)

        p0 = tf.paragraphs[0]
        if badge:
            p0.text = f"[{badge}]  {title}"
        else:
            p0.text = title
        p0.font.size = Pt(18)
        p0.font.bold = True
        p0.font.color.rgb = accent_color
        p0.space_after = Pt(12)

        for line in body_lines:
            p = tf.add_paragraph()
            p.text = line
            p.font.size = Pt(13)
            p.font.color.rgb = TEXT_MAIN
            p.space_after = Pt(6)

        return shape

    # ==========================================
    # SLIDE 1: Title Slide
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s1)

    tbox = s1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.3), Inches(3.8))
    tf1 = tbox.text_frame
    tf1.word_wrap = True

    p_badge = tf1.paragraphs[0]
    p_badge.text = "RAZORPAY AI BUILDATHON 2026  |  TRACK 2: AI RISK MANAGER"
    p_badge.font.size = Pt(13)
    p_badge.font.bold = True
    p_badge.font.color.rgb = CYAN_ACCENT
    p_badge.space_after = Pt(14)

    p_title = tf1.add_paragraph()
    p_title.text = "PayoutProof"
    p_title.font.size = Pt(50)
    p_title.font.bold = True
    p_title.font.color.rgb = TEXT_MAIN
    p_title.space_after = Pt(10)

    p_sub = tf1.add_paragraph()
    p_sub.text = "Trust Agent & Deterministic Policy Gate for Payment Risk"
    p_sub.font.size = Pt(22)
    p_sub.font.color.rgb = BLUE_ACCENT
    p_sub.space_after = Pt(18)

    p_desc = tf1.add_paragraph()
    p_desc.text = "A zero-trust gatekeeper intercepting deepfake voice notes, urgent social engineering, and rogue beneficiary tampering before money moves on RazorpayX rails."
    p_desc.font.size = Pt(15)
    p_desc.font.color.rgb = TEXT_MUTED
    p_desc.space_after = Pt(24)

    p_meta = tf1.add_paragraph()
    p_meta.text = "Builder: Kunal Kumar Mehta  •  Repository: github.com/KunalKumarMehta/razorpay  •  License: MIT"
    p_meta.font.size = Pt(12)
    p_meta.font.color.rgb = CYAN_ACCENT

    # ==========================================
    # SLIDE 2: The Urgent Problem
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s2)
    add_header(s2, "The Problem: Deepfakes & Out-of-Band Payout Hijacking")

    add_card(s2, Inches(0.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "1. AI Voice Clones & Urgency",
             [
                 "• CEOs & directors impersonated via cloned voice notes on WhatsApp/Signal.",
                 "• Urgent requests: 'Transfer ₹4,25,000 to new tooling vendor before 5 PM.'",
                 "• Pressure induces payment operators to bypass slow manual verification.",
                 "• Real-time Indian payment rails (IMPS/UPI) mean money is gone instantly."
             ], RED_ACC, "THREAT")

    add_card(s2, Inches(4.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "2. The 'Autonomous Agent' Trap",
             [
                 "• Emerging commerce agents are given raw API keys to payout rails.",
                 "• Prompt injection, ambiguity, or hallucinations trigger unauthorized transfers.",
                 "• No mathematical guarantee: an LLM can never be a financial oracle.",
                 "• Fatal industry flaw: connecting generative models directly to money triggers."
             ], AMBER_ACC, "VULNERABILITY")

    add_card(s2, Inches(8.8), Inches(1.9), Inches(3.7), Inches(4.8),
             "3. The Maker-Checker Gap",
             [
                 "• RazorpayX provides solid maker-checker workflows, BUT...",
                 "• Dirty, spoofed, or unverified instructions easily enter the queue as 'Maker drafts.'",
                 "• Weary approvers click 'Approve' assuming the operator verified origin.",
                 "• Missing link: A verifiable zero-trust gate *before* instruction entry."
             ], BLUE_ACCENT, "BLIND SPOT")

    # ==========================================
    # SLIDE 3: The Architectural Solution
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s3)
    add_header(s3, "Architecture: 3 Hard-Bounded Authority Lanes")

    add_card(s3, Inches(0.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "Lane 1: Trust Agent",
             [
                 "• Multimodal ingestion (voice note, message, invoice).",
                 "• Mandatory Processing Authority Record admission check (Zero PII leak).",
                 "• Extracts Counterparty, Destination, Amount, Purpose.",
                 "• Strict candidate span binding & evidence provenance.",
                 "• STRICT RULE: Never decides policy, never touches money."
             ], CYAN_ACCENT, "EXTRACT & INVESTIGATE")

    add_card(s3, Inches(4.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "Lane 2: Deterministic Policy Gate",
             [
                 "• Human Operator freezes cryptographic Intent Hash (SHA-256).",
                 "• 100% Deterministic Python policy rules (Zero LLM judgment).",
                 "• Checks Approved Destination registry & tenant limits.",
                 "• Emits: BLOCKED, HOLD, STEP_UP_REQUIRED, or ELIGIBLE.",
                 "• Signs single-use, expiring HMAC-SHA256 Handoff Grant."
             ], GREEN_ACC, "GATE & SIGN")

    add_card(s3, Inches(8.8), Inches(1.9), Inches(3.7), Inches(4.8),
             "Lane 3: Maker-Checker Rail",
             [
                 "• Action Adapter consumes HMAC Grant atomically via SQLite BEGIN IMMEDIATE.",
                 "• Server-derived deterministic idempotency key.",
                 "• Submits pending item to RazorpayX Maker-Checker approval rail.",
                 "• Existing finance hierarchy retains final approval & release.",
                 "• Ambiguity halts into RECONCILIATION_REQUIRED (No blind retries)."
             ], BLUE_ACCENT, "IDEMPOTENT HANDOFF")

    # ==========================================
    # SLIDE 4: Live Demo Journey
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s4)
    add_header(s4, "The 85-Second Demo: Step-Up Earns Eligibility")

    add_card(s4, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.8),
             "Primary Workflow: 3 Explicit Human Gestures",
             [
                 "1. Gesture 1: Confirm Intent & Freeze Hash",
                 "   Operator inspects extracted spans (₹4.25L to Kaveri Components, HDFC 4821). Freezes immutable intent hash.",
                 "",
                 "2. Policy Evaluation: STEP_UP_REQUIRED",
                 "   Destination is unapproved! Deterministic gate refuses handoff. Enforces two requirements: independent callback + separate destination governance.",
                 "",
                 "3. Gesture 2: Record Verified Destination",
                 "   Finance Controller records verified bank approval. Policy re-evaluates -> transitions to ELIGIBLE_FOR_HANDOFF.",
                 "",
                 "4. Gesture 3: Fresh Human Initiation",
                 "   Operator triggers handoff. System consumes HMAC grant and dispatches exactly 1 pending item to RazorpayX."
             ], BLUE_ACCENT, "HAPPY PATH")

    add_card(s4, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8),
             "Graceful Failure: 'Uncertainty Never Becomes Permission'",
             [
                 "• The Scenario: Network drops or timeout occurs while submitting to downstream rail adapter.",
                 "",
                 "• Flawed systems: Blindly retry (causing double payouts!) or fail open.",
                 "",
                 "• PayoutProof Response:",
                 "   - Consumes the single-use grant immediately.",
                 "   - Preserves historical eligibility while flagging RECONCILIATION_REQUIRED.",
                 "   - Refuses retry: second click is deterministically REJECTED.",
                 "   - Guarantees pending rail items <= 1 at all times.",
                 "",
                 "• Invariant: Any edit to amount/account invalidates intent hash and cancels grant."
             ], AMBER_ACC, "RESILIENCE")

    # ==========================================
    # SLIDE 5: Cryptographic Audit Ledger & Invariants
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s5)
    add_header(s5, "Tamper-Evident Audit Ledger & Defense Invariants")

    add_card(s5, Inches(0.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "Authoritative Hash Chain",
             [
                 "• Every event is recorded in dedicated audit_events table.",
                 "• Chained with SHA-256: prev_hash -> current_hash.",
                 "• Verified tip checkpoints signed with HMAC-SHA256.",
                 "• Any row tampering, deletion, or truncation causes immediate AuditLedgerIntegrityError.",
                 "• Zero audit storage in mutable state JSON."
             ], CYAN_ACCENT, "P0-3C AUDIT")

    add_card(s5, Inches(4.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "Admission & Privacy Gate",
             [
                 "• Processing Authority Record required before case creation.",
                 "• Validates data classification, submitter role, and retention.",
                 "• Invalid/unauthorized evidence triggers Admission Rejection.",
                 "• Zero PII leakage: unadmitted data never touches models or disk.",
                 "• Defense-only: strictly zero offense-capable tools."
             ], GREEN_ACC, "PRIVACY FIRST")

    add_card(s5, Inches(8.8), Inches(1.9), Inches(3.7), Inches(4.8),
             "Cryptographic Grants",
             [
                 "• Single-use HMAC-SHA256 Handoff Grants.",
                 "• Enforces strict 15-minute Time-To-Live (TTL).",
                 "• Bound strictly to case_id, case_version, and exact intent_hash.",
                 "• Claimed atomically with SQLite BEGIN IMMEDIATE.",
                 "• Prevents replay, race conditions, and out-of-order execution."
             ], BLUE_ACCENT, "ZERO-TRUST")

    # ==========================================
    # SLIDE 6: Rigorous Evaluation & Benchmarks
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s6)
    add_header(s6, "Evaluation Rigor: Disclosed Invariant Harnesses")

    add_card(s6, Inches(0.8), Inches(1.9), Inches(5.6), Inches(4.8),
             "Synthetic Policy Benchmark Suites",
             [
                 "• 45-Case Development Policy Harness:",
                 "   Validates extraction spans, intent freezing, and basic policy gates.",
                 "",
                 "• 90-Case Sealed Policy Plumbing Suite:",
                 "   Covers edge cases: multi-currency, unapproved vendors, split amounts, ambiguous notes, and timeout forks.",
                 "",
                 "• 81-Execution Critical Safety Harness (27 base x 3 repetitions):",
                 "   Rigorous verification of zero Unsafe Handoffs, replay rejections, and grant expiration.",
                 "",
                 "• 403 Automated Unit & Integration Tests passing cleanly."
             ], BLUE_ACCENT, "EVALUATION HARNESS")

    add_card(s6, Inches(6.8), Inches(1.9), Inches(5.7), Inches(4.8),
             "Honest Engineering Disclosure",
             [
                 "• The Golden Rule of Hackathons: Never fake production metrics.",
                 "",
                 "• We explicitly declare: current benchmarks verify deterministic policy plumbing and safety boundary invariants against synthetic cases.",
                 "",
                 "• Held-out production targets are declared as TARGETS ONLY:",
                 "   - Unsafe Handoffs: 0 (Zero Tolerance - Verified in Invariant Suite)",
                 "   - 3-Action Correctness Target: >= 90.0%",
                 "   - Protective Intervention Recall Target: >= 95.0%",
                 "   - Operator Interaction Reduction Target: >= 30.0%",
                 "",
                 "• Full ASR voice models & human-in-the-loop pilot are staged for Design Partner phase."
             ], GREEN_ACC, "INTEGRITY")

    # ==========================================
    # SLIDE 7: Startup Wedge & Business Model
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s7)
    add_header(s7, "Startup Thesis: The Wedge into Enterprise Payout Security")

    add_card(s7, Inches(0.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "1. Target Buyer & Beachhead",
             [
                 "• Buyer: Finance Control Owners, CFOs, & Treasury Heads.",
                 "• Market: Indian growth & mid-market enterprises running RazorpayX Payouts.",
                 "• Beachhead Wedge: Urgent out-of-band payout exception gating.",
                 "• Solves the #1 nightmare: CEO deepfake fraud inducing unauthorized wire transfers."
             ], CYAN_ACCENT, "ICP & WEDGE")

    add_card(s7, Inches(4.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "2. 3 Bounded Design Partners",
             [
                 "• Staged 90-day pilot with 3 design partners.",
                 "• Success criteria:",
                 "   - 0 Unsafe Handoffs under live shadowing.",
                 "   - >= 30% reduction in manual operator triage time.",
                 "   - Zero false approvals on modified bank details.",
                 "• Gated expansion: only expand to vendor onboarding if 2/3 commit."
             ], BLUE_ACCENT, "PILOT DISCIPLINE")

    add_card(s7, Inches(8.8), Inches(1.9), Inches(3.7), Inches(4.8),
             "3. Defensible Moat",
             [
                 "• Models are commodities (Whisper, Gemini, Llama get swapped).",
                 "• The True Moat:",
                 "   - Counterparty approval graph & trust history.",
                 "   - Tamper-evident cryptographic audit ledger.",
                 "   - Deep integration into RazorpayX maker-checker rails.",
                 "   - Provable safety invariant compliance."
             ], GREEN_ACC, "DEFENSIBILITY")

    # ==========================================
    # SLIDE 8: Summary & Final Ask
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s8)
    add_header(s8, "Why PayoutProof Wins Razorpay Buildathon", "SUMMARY & NEXT STEPS")

    add_card(s8, Inches(0.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "Production-Grade Codebase",
             [
                 "• 403 passing unit & integration tests.",
                 "• Zero lint errors (clean Ruff checks).",
                 "• Reproducible CycloneDX & SPDX SBOM generator.",
                 "• Pinned multi-stage Docker build.",
                 "• Full FastAPI backend + Vite React Operator Console."
             ], GREEN_ACC, "EXECUTION")

    add_card(s8, Inches(4.8), Inches(1.9), Inches(3.6), Inches(4.8),
             "Razorpay AI Synergy",
             [
                 "• Native extension for RazorpayX Payouts & Vendor Payments.",
                 "• Protects Razorpay merchants from modern deepfake threats.",
                 "• Embeds seamlessly into existing Maker-Checker approval flows.",
                 "• Strictly defense-only: 100% compliant with Track 2 rules."
             ], BLUE_ACCENT, "STRATEGIC FIT")

    add_card(s8, Inches(8.8), Inches(1.9), Inches(3.7), Inches(4.8),
             "The Ask to Judges",
             [
                 "• Evaluate PayoutProof on its disclosed safety invariants, code architecture, and honest metrics.",
                 "• Invite to panel review for deep architectural grilling.",
                 "• Aspirational: introductions to 3 RazorpayX design partners to validate in live shadowing.",
                 "",
                 "Repository: github.com/KunalKumarMehta/razorpay"
             ], CYAN_ACCENT, "THE ASK")

    prs.save(output_path)
    print(f"Presentation saved successfully to: {output_path}")

if __name__ == "__main__":
    create_deck()
