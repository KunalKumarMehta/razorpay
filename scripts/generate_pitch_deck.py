import os
from PIL import Image
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

    # Executive Modern Palette
    TEXT_MAIN = RGBColor(255, 255, 255)       # Pure White
    TEXT_MUTED = RGBColor(156, 175, 203)     # Slate Blue
    BLUE_ACCENT = RGBColor(56, 140, 255)     # Royal Blue
    CYAN_ACCENT = RGBColor(0, 229, 255)      # Electric Cyan
    GREEN_ACC = RGBColor(16, 217, 144)       # Emerald Green
    AMBER_ACC = RGBColor(255, 179, 0)        # Amber Warning
    RED_ACC = RGBColor(255, 77, 77)          # Red Alert
    CARD_BG = RGBColor(14, 25, 48)           # Dark Slate Navy
    CARD_BORDER = RGBColor(38, 68, 115)      # Border
    CARD_BORDER_ACCENT = RGBColor(0, 186, 242)

    bg_hero_path = "build/assets/slide_bg_hero.png"
    bg_content_path = "build/assets/slide_bg_content.png"

    def set_slide_background(slide, is_hero=False):
        bg_file = bg_hero_path if is_hero else bg_content_path
        if os.path.exists(bg_file):
            slide.shapes.add_picture(bg_file, Inches(0), Inches(0), width=Inches(13.333), height=Inches(7.5))
        else:
            bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
            bg.fill.solid()
            bg.fill.fore_color.rgb = RGBColor(7, 13, 26)
            bg.line.fill.background()

    def add_header(slide, title_text, category_text="RAZORPAY AI BUILDATHON 2026 • TRACK 2: AI RISK MANAGER"):
        # Category pill badge
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.42), Inches(11.5), Inches(0.32))
        tf_c = cat_box.text_frame
        tf_c.word_wrap = True
        tf_c.margin_left = tf_c.margin_top = tf_c.margin_right = tf_c.margin_bottom = 0
        p_c = tf_c.paragraphs[0]
        p_c.text = f"  {category_text.upper()}  "
        p_c.font.size = Pt(10.5)
        p_c.font.bold = True
        p_c.font.color.rgb = CYAN_ACCENT

        # Title
        t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.78), Inches(11.5), Inches(0.75))
        tf_t = t_box.text_frame
        tf_t.word_wrap = True
        tf_t.margin_left = tf_t.margin_top = tf_t.margin_right = tf_t.margin_bottom = 0
        p_t = tf_t.paragraphs[0]
        p_t.text = title_text
        p_t.font.size = Pt(25)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_MAIN

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
        tf.margin_top = Inches(0.22)
        tf.margin_bottom = Inches(0.22)

        p0 = tf.paragraphs[0]
        p0.text = f"[{badge}]  {title}" if badge else title
        p0.font.size = Pt(15.5)
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

    def add_fitted_image(slide, img_path, left, top, max_w, max_h):
        """Fit image cleanly within bounding box without distortion or overflow."""
        if not os.path.exists(img_path):
            return None

        # Container card behind the image
        container = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, max_w, max_h)
        container.fill.solid()
        container.fill.fore_color.rgb = RGBColor(9, 17, 34)
        container.line.color.rgb = CARD_BORDER_ACCENT
        container.line.width = Pt(1.2)

        with Image.open(img_path) as im:
            orig_w, orig_h = im.size

        pad = Inches(0.15)
        inner_w = max_w - (pad * 2)
        inner_h = max_h - (pad * 2)

        img_aspect = orig_w / orig_h
        inner_aspect = inner_w / inner_h

        if img_aspect > inner_aspect:
            # Image is wider than container
            final_w = inner_w
            final_h = inner_w / img_aspect
        else:
            # Image is taller than container
            final_h = inner_h
            final_w = inner_h * img_aspect

        # Center inside container
        final_left = left + pad + (inner_w - final_w) / 2
        final_top = top + pad + (inner_h - final_h) / 2

        return slide.shapes.add_picture(img_path, final_left, final_top, width=final_w, height=final_h)

    # ==========================================
    # SLIDE 1: Hero / Title Slide
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1, is_hero=True)

    tbox = s1.shapes.add_textbox(Inches(1.0), Inches(1.5), Inches(11.3), Inches(4.5))
    tf1 = tbox.text_frame
    tf1.word_wrap = True

    p_badge = tf1.paragraphs[0]
    p_badge.text = "RAZORPAY AI BUILDATHON 2026  •  TRACK 2: AI RISK MANAGER"
    p_badge.font.size = Pt(13)
    p_badge.font.bold = True
    p_badge.font.color.rgb = CYAN_ACCENT
    p_badge.space_after = Pt(14)

    p_title = tf1.add_paragraph()
    p_title.text = "IntentLock"
    p_title.font.size = Pt(56)
    p_title.font.bold = True
    p_title.font.color.rgb = TEXT_MAIN
    p_title.space_after = Pt(8)

    p_sub = tf1.add_paragraph()
    p_sub.text = "Zero-Trust Policy Gate for High-Risk Payouts"
    p_sub.font.size = Pt(23)
    p_sub.font.bold = True
    p_sub.font.color.rgb = BLUE_ACCENT
    p_sub.space_after = Pt(16)

    p_desc = tf1.add_paragraph()
    p_desc.text = "A defense-grade policy gate intercepting deepfake voice notes, urgent social engineering, and rogue beneficiary tampering before money moves on RazorpayX rails."
    p_desc.font.size = Pt(15)
    p_desc.font.color.rgb = TEXT_MUTED
    p_desc.space_after = Pt(24)

    p_meta = tf1.add_paragraph()
    p_meta.text = "Builder: Kunal Kumar Mehta   •   Repository: github.com/KunalKumarMehta/razorpay   •   License: MIT"
    p_meta.font.size = Pt(12.5)
    p_meta.font.bold = True
    p_meta.font.color.rgb = CYAN_ACCENT

    # ==========================================
    # SLIDE 2: The Urgent Problem
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "The Vulnerability: Deepfakes, Urgency & Autonomous LLM Risks")

    add_card(s2, Inches(0.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "1. AI Voice Clones & Urgency",
             [
                 "• Executives cloned in 30 seconds via generative speech tools.",
                 "• Urgent WhatsApp voice notes: 'Transfer ₹4.25L to new vendor before 5 PM.'",
                 "• Psychological pressure induces operators to bypass slow verification.",
                 "• Real-time Indian payment rails (IMPS/UPI) make unauthorized transfers irreversible."
             ], RED_ACC, "THE THREAT")

    add_card(s2, Inches(4.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "2. The 'Autonomous Agent' Trap",
             [
                 "• Emerging commerce agents given raw API keys to payout rails.",
                 "• In financial systems, there is NO Ctrl+Z.",
                 "• Hallucinations, prompt injections, or ambiguity cause catastrophic loss.",
                 "• Core thesis: Never let an LLM touch the financial trigger."
             ], AMBER_ACC, "VULNERABILITY")

    add_card(s2, Inches(8.8), Inches(1.75), Inches(3.7), Inches(5.1),
             "3. The Maker-Checker Gap",
             [
                 "• RazorpayX provides solid maker-checker workflows.",
                 "• BUT dirty or spoofed instructions easily enter as 'Maker drafts.'",
                 "• Fatigued checkers click 'Approve' assuming origin was verified.",
                 "• Missing link: A verifiable zero-trust gate BEFORE instruction entry."
             ], BLUE_ACCENT, "BLIND SPOT")

    # ==========================================
    # SLIDE 3: Architecture & Authority Lanes (With Dark Diagram)
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Architecture: 3 Hard-Bounded Authority Lanes")

    arch_img = "build/diagrams/IntentLock_Architecture_Dark.png"
    if not os.path.exists(arch_img):
        arch_img = "build/diagrams/IntentLock_Architecture.png"

    # Add fitted diagram on left side
    add_fitted_image(s3, arch_img, Inches(0.8), Inches(1.75), Inches(6.8), Inches(5.1))

    # Add descriptive card on right side
    add_card(s3, Inches(7.9), Inches(1.75), Inches(4.6), Inches(5.1),
             "Authority Separation",
             [
                 "• Lane 1: Trust Agent (Investigator)",
                 "  Multimodal extraction under DPDP admission rules. Links evidence spans with strict provenance. Zero money authority.",
                 "",
                 "• Lane 2: Deterministic Policy Gate",
                 "  Operator freezes SHA-256 intent hash. Deterministic Python engine evaluates limits & approved destination registry.",
                 "",
                 "• Lane 3: Maker-Checker Rail",
                 "  Issues single-use 15-minute HMAC-SHA256 grant. Dispatches 1 pending item into RazorpayX.",
                 "",
                 "• Provable Invariant:",
                 "  Any edit to amount or account breaks hash and cancels grant."
             ], CYAN_ACCENT, "LANES")

    # ==========================================
    # SLIDE 4: Interactive Demo & Safe Failure (With Sequence Diagram)
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Interactive Workflow: 3 Human Gestures & Fault Tolerance")

    seq_img = "build/diagrams/IntentLock_SequenceFlow_Dark.png"
    if not os.path.exists(seq_img):
        seq_img = "build/diagrams/IntentLock_SequenceFlow.png"

    # Add fitted diagram on left side
    add_fitted_image(s4, seq_img, Inches(0.8), Inches(1.75), Inches(6.8), Inches(5.1))

    # Add descriptive card on right side
    add_card(s4, Inches(7.9), Inches(1.75), Inches(4.6), Inches(5.1),
             "Live Workflow & Safe Failure",
             [
                 "• Gesture 1: Freeze Intent",
                 "  Operator verifies extracted spans. Freezes immutable SHA-256 Intent Hash.",
                 "",
                 "• Policy Step-Up: STEP_UP_REQUIRED",
                 "  Destination unapproved! Gate demands independent callback + separate destination approval.",
                 "",
                 "• Gesture 2 & 3: Approval & Handoff",
                 "  Controller approves destination -> Case becomes ELIGIBLE. Operator freshly initiates handoff to RazorpayX.",
                 "",
                 "• Uncertainty Never Becomes Permission:",
                 "  Gateway timeouts enter RECONCILIATION_REQUIRED. Blind retries rejected; no duplicate payouts!"
             ], BLUE_ACCENT, "GESTURES & FAULT")

    # ==========================================
    # SLIDE 5: Cryptographic Audit Ledger
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Tamper-Evident Cryptographic Audit Ledger & Gating")

    add_card(s5, Inches(0.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "Authoritative Hash Chain",
             [
                 "• Dedicated audit_events table is the sole authoritative audit store.",
                 "• Chained with SHA-256: prev_hash -> current_hash.",
                 "• Verified tip checkpoints signed with HMAC-SHA256.",
                 "• Any row tampering, deletion, or truncation causes immediate AuditLedgerIntegrityError.",
                 "• Zero audit storage in mutable state JSON."
             ], CYAN_ACCENT, "CRYPTO AUDIT")

    add_card(s5, Inches(4.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "Admission & Privacy Gate",
             [
                 "• Processing Authority Record required before case creation.",
                 "• Validates data classification, submitter role, and retention.",
                 "• Invalid/unauthorized evidence triggers Admission Rejection.",
                 "• Zero PII leakage: unadmitted data never touches models or disk.",
                 "• Defense-only: strictly zero offense-capable tools."
             ], GREEN_ACC, "PRIVACY FIRST")

    add_card(s5, Inches(8.8), Inches(1.75), Inches(3.7), Inches(5.1),
             "Single-Use HMAC Grants",
             [
                 "• Single-use HMAC-SHA256 Handoff Grants.",
                 "• Enforces strict 15-minute Time-To-Live (TTL).",
                 "• Bound strictly to case_id, case_version, and exact intent_hash.",
                 "• Claimed atomically with SQLite BEGIN IMMEDIATE.",
                 "• Prevents replay, race conditions, and out-of-order execution."
             ], BLUE_ACCENT, "ZERO-TRUST")

    # ==========================================
    # SLIDE 6: Honest Evaluation Rigor
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Evaluation Rigor: 403 Tests & Disclosed Invariants")

    add_card(s6, Inches(0.8), Inches(1.75), Inches(5.6), Inches(5.1),
             "Policy Benchmark Suites",
             [
                 "• 45-Case Development Policy Harness:",
                 "  Validates extraction spans, intent freezing, and basic policy gates.",
                 "",
                 "• 90-Case Sealed Policy Plumbing Suite:",
                 "  Covers edge cases: multi-currency, unapproved vendors, split amounts, ambiguous notes, and timeout forks.",
                 "",
                 "• 81-Execution Critical Safety Harness (27 base x 3 repetitions):",
                 "  Rigorous verification of zero Unsafe Handoffs, replay rejections, and grant expiration.",
                 "",
                 "• 403 Automated Unit & Integration Tests passing in GitHub Actions CI."
             ], BLUE_ACCENT, "EVALUATION HARNESS")

    add_card(s6, Inches(6.8), Inches(1.75), Inches(5.7), Inches(5.1),
             "Honest Engineering Disclosure",
             [
                 "• The Golden Rule of Hackathons: Never fake production metrics.",
                 "",
                 "• We explicitly declare: current benchmarks verify deterministic policy plumbing and safety boundary invariants against synthetic cases.",
                 "",
                 "• Held-out production targets are declared as TARGETS ONLY:",
                 "  - Unsafe Handoffs: 0 (Zero Tolerance - Verified in Invariant Suite)",
                 "  - 3-Action Correctness Target: >= 90.0%",
                 "  - Protective Intervention Recall Target: >= 95.0%",
                 "  - Operator Interaction Reduction Target: >= 30.0%",
                 "",
                 "• Real ASR voice models staged for live Design Partner phase."
             ], GREEN_ACC, "HONEST DISCLOSURE")

    # ==========================================
    # SLIDE 7: Startup Wedge & Business Model
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Startup Thesis: Defensible Wedge for RazorpayX Payouts")

    add_card(s7, Inches(0.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "1. Target Buyer & Beachhead",
             [
                 "• Buyer: Finance Control Owners, CFOs, & Treasury Heads.",
                 "• Market: Indian growth & mid-market enterprises running RazorpayX Payouts.",
                 "• Beachhead Wedge: Urgent out-of-band payout exception gating.",
                 "• Solves the #1 nightmare: CEO deepfake fraud inducing wire transfers."
             ], CYAN_ACCENT, "ICP & WEDGE")

    add_card(s7, Inches(4.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "2. 3 Bounded Design Partners",
             [
                 "• Staged 90-day pilot with 3 design partners.",
                 "• Success criteria:",
                 "  - 0 Unsafe Handoffs under live shadowing.",
                 "  - >= 30% reduction in manual operator triage time.",
                 "  - Zero false approvals on modified bank details.",
                 "• Gated expansion: only expand to vendor onboarding if 2/3 commit."
             ], BLUE_ACCENT, "PILOT DISCIPLINE")

    add_card(s7, Inches(8.8), Inches(1.75), Inches(3.7), Inches(5.1),
             "3. Defensible Moat",
             [
                 "• Models are commodities (Whisper, Gemini, Llama get swapped).",
                 "• The True Moat:",
                 "  - Counterparty approval graph & trust history.",
                 "  - Tamper-evident cryptographic audit ledger.",
                 "  - Deep integration into RazorpayX maker-checker rails.",
                 "  - Provable safety invariant compliance."
             ], GREEN_ACC, "DEFENSIBILITY")

    # ==========================================
    # SLIDE 8: Summary & The Ask
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Why IntentLock Wins Razorpay Buildathon", "SUMMARY & NEXT STEPS")

    add_card(s8, Inches(0.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "Production-Grade Codebase",
             [
                 "• 403 passing unit & integration tests.",
                 "• GitHub Actions CI 100% Green (lint, tests, evals, Docker).",
                 "• Reproducible CycloneDX & SPDX SBOM generator.",
                 "• Pinned multi-stage Docker build.",
                 "• Full FastAPI backend + Vite React Operator Console."
             ], GREEN_ACC, "EXECUTION")

    add_card(s8, Inches(4.8), Inches(1.75), Inches(3.6), Inches(5.1),
             "Strategic Alignment",
             [
                 "• Native extension for RazorpayX Payouts & Vendor Payments.",
                 "• Protects Razorpay merchants from modern deepfake threats.",
                 "• Embeds seamlessly into existing Maker-Checker approval flows.",
                 "• Strictly defense-only: 100% compliant with Track 2 rules."
             ], CYAN_ACCENT, "RAZORPAY FIT")

    add_card(s8, Inches(8.8), Inches(1.75), Inches(3.7), Inches(5.1),
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
