import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def create_deck(output_path="build/IntentLock_Pitch_Deck.pptx"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    blank_layout = prs.slide_layouts[6]

    # Razorpay palette
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
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.5), Inches(0.35))
        tf_c = cat_box.text_frame
        tf_c.word_wrap = True
        tf_c.margin_left = tf_c.margin_top = tf_c.margin_right = tf_c.margin_bottom = 0
        p_c = tf_c.paragraphs[0]
        p_c.text = category_text.upper()
        p_c.font.size = Pt(11)
        p_c.font.bold = True
        p_c.font.color.rgb = CYAN_ACCENT

        t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(11.5), Inches(0.75))
        tf_t = t_box.text_frame
        tf_t.word_wrap = True
        tf_t.margin_left = tf_t.margin_top = tf_t.margin_right = tf_t.margin_bottom = 0
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.size = Pt(24)
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

        tf = shape.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.25)
        tf.margin_right = Inches(0.25)
        tf.margin_top = Inches(0.25)
        tf.margin_bottom = Inches(0.25)

        p0 = tf.paragraphs[0]
        p0.text = f"[{badge}]  {title}" if badge else title
        p0.font.size = Pt(16)
        p0.font.bold = True
        p0.font.color.rgb = accent_color
        p0.space_after = Pt(8)

        for line in body_lines:
            p = tf.add_paragraph()
            p.text = line
            p.font.size = Pt(12)
            p.font.color.rgb = TEXT_MAIN
            p.space_after = Pt(4)

        return shape

    # SLIDE 1: Title
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s1)

    tbox = s1.shapes.add_textbox(Inches(1.0), Inches(1.6), Inches(11.3), Inches(4.5))
    tf1 = tbox.text_frame
    tf1.word_wrap = True

    p_badge = tf1.paragraphs[0]
    p_badge.text = "RAZORPAY AI BUILDATHON 2026  |  TRACK 2: AI RISK MANAGER"
    p_badge.font.size = Pt(13)
    p_badge.font.bold = True
    p_badge.font.color.rgb = CYAN_ACCENT
    p_badge.space_after = Pt(14)

    p_title = tf1.add_paragraph()
    p_title.text = "IntentLock"
    p_title.font.size = Pt(56)
    p_title.font.bold = True
    p_title.font.color.rgb = TEXT_MAIN
    p_title.space_after = Pt(10)

    p_sub = tf1.add_paragraph()
    p_sub.text = "Zero-Trust Policy Gate for High-Risk Payouts"
    p_sub.font.size = Pt(22)
    p_sub.font.color.rgb = BLUE_ACCENT
    p_sub.space_after = Pt(16)

    p_desc = tf1.add_paragraph()
    p_desc.text = "A student-built defense system intercepting deepfake voice notes, urgent social engineering, and rogue beneficiary tampering before money moves on RazorpayX rails."
    p_desc.font.size = Pt(15)
    p_desc.font.color.rgb = TEXT_MUTED
    p_desc.space_after = Pt(22)

    p_meta = tf1.add_paragraph()
    p_meta.text = "Builder: Kunal Kumar Mehta  •  Repository: github.com/KunalKumarMehta/razorpay  •  License: MIT"
    p_meta.font.size = Pt(12)
    p_meta.font.color.rgb = CYAN_ACCENT

    # SLIDE 2: Problem
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s2)
    add_header(s2, "The Problem: Deepfakes, Urgency & Autonomous LLM Blindness")

    add_card(s2, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "1. AI Voice Clones & Urgency",
             [
                 "• CEOs & executives cloned via off-the-shelf TTS in 30 seconds.",
                 "• Urgent WhatsApp voice notes: 'Transfer ₹4.25L to new vendor before 5 PM.'",
                 "• Pressure induces operators to bypass slow manual verification.",
                 "• Real-time Indian payment rails (IMPS/UPI) mean money is gone instantly."
             ], RED_ACC, "THREAT")

    add_card(s2, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "2. The 'Autonomous Agent' Trap",
             [
                 "• Trend of giving LLMs raw API keys to payout rails.",
                 "• Fatal flaw: In payments, there is NO Ctrl+Z.",
                 "• Hallucinations, prompt injections, or ambiguity cause catastrophic loss.",
                 "• Core realization: Never let an LLM touch the financial trigger."
             ], AMBER_ACC, "VULNERABILITY")

    add_card(s2, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0),
             "3. The Maker-Checker Gap",
             [
                 "• RazorpayX provides solid maker-checker workflows.",
                 "• BUT dirty or spoofed instructions easily enter as 'Maker drafts.'",
                 "• Fatigued checkers click 'Approve' assuming origin was verified.",
                 "• Missing link: A verifiable zero-trust gate BEFORE instruction entry."
             ], BLUE_ACCENT, "BLIND SPOT")

    # SLIDE 3: Architecture with Eraser Diagram
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s3)
    add_header(s3, "Architecture: 3 Hard-Bounded Authority Lanes")

    arch_img = "build/diagrams/IntentLock_Architecture.png"
    if os.path.exists(arch_img):
        # Embed diagram on left, bullet points on right
        s3.shapes.add_picture(arch_img, Inches(0.8), Inches(1.8), width=Inches(7.2))
        add_card(s3, Inches(8.3), Inches(1.8), Inches(4.2), Inches(5.0),
                 "Core Authority Lanes",
                 [
                     "• Lane 1: Trust Agent",
                     "  Extracts intent spans with zero money authority under DPDP admission.",
                     "",
                     "• Lane 2: Deterministic Policy Gate",
                     "  Freezes SHA-256 intent hash. Enforces rules & approved beneficiary registry.",
                     "",
                     "• Lane 3: Maker-Checker Rail",
                     "  Signs single-use HMAC grant. Dispatches exactly 1 pending item to RazorpayX.",
                     "",
                     "• Live Eraser.io Diagram:",
                     "  app.eraser.io/workspace/Rrf7ddUOQTF02vngHxui"
                 ], CYAN_ACCENT, "DIAGRAM BREAKDOWN")
    else:
        add_card(s3, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0), "Lane 1: Trust Agent", ["Extraction with zero money authority."], CYAN_ACCENT)
        add_card(s3, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0), "Lane 2: Policy Gate", ["100% Deterministic Python math."], GREEN_ACC)
        add_card(s3, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0), "Lane 3: Action Rail", ["Single-use HMAC handoff."], BLUE_ACCENT)

    # SLIDE 4: Demo Sequence with Eraser Flow Diagram
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s4)
    add_header(s4, "Interactive Demo: 3 Human Gestures & Safe Failure")

    seq_img = "build/diagrams/IntentLock_SequenceFlow.png"
    if os.path.exists(seq_img):
        s4.shapes.add_picture(seq_img, Inches(0.8), Inches(1.8), width=Inches(7.2))
        add_card(s4, Inches(8.3), Inches(1.8), Inches(4.2), Inches(5.0),
                 "Execution Steps",
                 [
                     "1. Gesture 1: Freeze Intent",
                     "   Operator confirms extracted spans. Generates immutable SHA-256 hash.",
                     "",
                     "2. Policy Gate: STEP_UP_REQUIRED",
                     "   Destination unapproved! Demands callback + controller approval.",
                     "",
                     "3. Gesture 2: Controller Approval",
                     "   Controller approves bank -> Case becomes ELIGIBLE_FOR_HANDOFF.",
                     "",
                     "4. Gesture 3: Single-Use Handoff",
                     "   Consumes HMAC grant -> 1 pending item on RazorpayX.",
                     "",
                     "• Uncertainty Never Becomes Permission:",
                     "   Timeouts enter RECONCILIATION_REQUIRED. No double payouts!"
                 ], BLUE_ACCENT, "WORKFLOW STEPS")
    else:
        add_card(s4, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0), "Happy Path", ["3 gestures."], BLUE_ACCENT)
        add_card(s4, Inches(6.8), Inches(1.8), Inches(5.7), Inches(5.0), "Fault Tolerance", ["No retries."], AMBER_ACC)

    # SLIDE 5: Crypto Audit
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s5)
    add_header(s5, "Tamper-Evident Audit Ledger & Cryptographic Gating")

    add_card(s5, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "Authoritative Hash Chain",
             [
                 "• Every event recorded in dedicated audit_events table.",
                 "• Chained with SHA-256: prev_hash -> current_hash.",
                 "• Verified tip checkpoints signed with HMAC-SHA256.",
                 "• Tampering causes immediate AuditLedgerIntegrityError.",
                 "• Zero audit storage in mutable state JSON."
             ], CYAN_ACCENT, "CRYPTO AUDIT")

    add_card(s5, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "Admission & Privacy Gate",
             [
                 "• Processing Authority Record required before case creation.",
                 "• Validates data classification, submitter role, and retention.",
                 "• Invalid/unauthorized evidence triggers Admission Rejection.",
                 "• Zero PII leakage: unadmitted data never touches models or disk.",
                 "• Defense-only: strictly zero offense-capable tools."
             ], GREEN_ACC, "PRIVACY FIRST")

    add_card(s5, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0),
             "Single-Use HMAC Grants",
             [
                 "• Single-use HMAC-SHA256 Handoff Grants.",
                 "• Enforces strict 15-minute Time-To-Live (TTL).",
                 "• Bound strictly to case_id, case_version, and exact intent_hash.",
                 "• Claimed atomically with SQLite BEGIN IMMEDIATE.",
                 "• Prevents replay, race conditions, and out-of-order execution."
             ], BLUE_ACCENT, "ZERO-TRUST")

    # SLIDE 6: Honest Evaluation
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s6)
    add_header(s6, "Evaluation Rigor: 403 Tests & Disclosed Invariants")

    add_card(s6, Inches(0.8), Inches(1.8), Inches(5.6), Inches(5.0),
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
                 "• 403 Automated Unit & Integration Tests passing cleanly in CI."
             ], BLUE_ACCENT, "EVALUATION HARNESS")

    add_card(s6, Inches(6.8), Inches(1.8), Inches(5.7), Inches(5.0),
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
                 "• Real ASR voice models staged for live Design Partner phase."
             ], GREEN_ACC, "HONEST DISCLOSURE")

    # SLIDE 7: Startup Wedge
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s7)
    add_header(s7, "Startup Thesis: The Wedge into Enterprise Payout Security")

    add_card(s7, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "1. Target Buyer & Beachhead",
             [
                 "• Buyer: Finance Control Owners, CFOs, & Treasury Heads.",
                 "• Market: Indian growth & mid-market enterprises running RazorpayX Payouts.",
                 "• Beachhead Wedge: Urgent out-of-band payout exception gating.",
                 "• Solves the #1 nightmare: CEO deepfake fraud inducing unauthorized wire transfers."
             ], CYAN_ACCENT, "ICP & WEDGE")

    add_card(s7, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "2. 3 Bounded Design Partners",
             [
                 "• Staged 90-day pilot with 3 design partners.",
                 "• Success criteria:",
                 "   - 0 Unsafe Handoffs under live shadowing.",
                 "   - >= 30% reduction in manual operator triage time.",
                 "   - Zero false approvals on modified bank details.",
                 "• Gated expansion: only expand to vendor onboarding if 2/3 commit."
             ], BLUE_ACCENT, "PILOT DISCIPLINE")

    add_card(s7, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0),
             "3. Defensible Moat",
             [
                 "• Models are commodities (Whisper, Gemini, Llama get swapped).",
                 "• The True Moat:",
                 "   - Counterparty approval graph & trust history.",
                 "   - Tamper-evident cryptographic audit ledger.",
                 "   - Deep integration into RazorpayX maker-checker rails.",
                 "   - Provable safety invariant compliance."
             ], GREEN_ACC, "DEFENSIBILITY")

    # SLIDE 8: Summary & Final Ask
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s8)
    add_header(s8, "Why IntentLock Wins Razorpay Buildathon", "SUMMARY & NEXT STEPS")

    add_card(s8, Inches(0.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "Production-Grade Codebase",
             [
                 "• 403 passing unit & integration tests.",
                 "• GitHub Actions CI 100% Green (lint, tests, evals, Docker).",
                 "• Reproducible CycloneDX & SPDX SBOM generator.",
                 "• Pinned multi-stage Docker build.",
                 "• Full FastAPI backend + Vite React Operator Console."
             ], GREEN_ACC, "EXECUTION")

    add_card(s8, Inches(4.8), Inches(1.8), Inches(3.6), Inches(5.0),
             "Architecture & Media Assets",
             [
                 "• Live Eraser.io Architecture Diagram:",
                 "  app.eraser.io/workspace/Rrf7ddUOQTF02vngHxui",
                 "",
                 "• Live Eraser.io Sequence Diagram:",
                 "  app.eraser.io/workspace/3YKVq7LqK2R7Ps24TTYv",
                 "",
                 "• Generated AI Voiceover: build/IntentLock_Pitch_Voiceover.mp3"
             ], CYAN_ACCENT, "DIAGRAMS & AUDIO")

    add_card(s8, Inches(8.8), Inches(1.8), Inches(3.7), Inches(5.0),
             "The Ask to Judges",
             [
                 "• Evaluate IntentLock on its disclosed safety invariants, code architecture, and honest metrics.",
                 "• Invite to panel review for deep architectural grilling.",
                 "• Aspirational: introductions to 3 RazorpayX design partners to validate in live shadowing.",
                 "",
                 "Repository: github.com/KunalKumarMehta/razorpay"
             ], BLUE_ACCENT, "THE ASK")

    prs.save(output_path)
    print(f"Presentation saved successfully to: {output_path}")

if __name__ == "__main__":
    create_deck()
