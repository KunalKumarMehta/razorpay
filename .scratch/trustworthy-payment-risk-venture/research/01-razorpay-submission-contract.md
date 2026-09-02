# Razorpay AI Buildathon 2026 — submission contract

Checked 2026-09-02 (Asia/Kolkata). This note uses the official Buildathon page, its linked application form, the official Razorpay Careers LinkedIn channel, and Razorpay’s API documentation. It separates published requirements from inferences and unresolved points.

## Decision

Treat the submission as a student-only, build-first application for one of five tracks. The safe contract for the Blueprint is: submit a public repository, a five-minute pitch video, and an architecture explanation; complete the official form with the applicant and project fields; demonstrate a working, measurable, reliable, AI-meaningful system; and keep any payment integration in Razorpay Test Mode. For this venture, the AI Risk Manager track is the cleanest fit: prove a defense-only detector/verifier/auto-responder for one loss class with held-out precision/recall and false-positive cost.

## Eligibility, participation, and timing

- The program is explicitly “students only.” The official Razorpay Careers post also describes it as hiring AI Builder Interns, with no aptitude test or group discussion, and says to apply by **5 September**. The 2026 form title and the current program context make the year **2026**. Sources: [Razorpay AI Buildathon](https://razorpay.com/buildathon/), [Razorpay Careers official channel](https://www.linkedin.com/showcase/razorpay-careers/).
- The live form requires a graduation-year choice of **2027, 2028, or 2029** and asks whether the applicant is available for an **in-person internship starting September**. This is the most specific current eligibility signal; the public page does not state a degree branch, CGPA, age, nationality, or year-of-study rule. Source: [official application form](https://docs.google.com/forms/d/e/1FAIpQLScJ9XSqVCB2oaPwEMH0Zk3I1OpILFW1WpWdWweQ2950jdRzlg/viewform).
- The official page says the application is a build-first process (“pick a track, build something real, show your work”), not a conventional resume screen. The current form is an individual applicant form: it asks for email, full name, college, graduation year, and individual availability, and has no team-member or team-size field. Therefore, team participation is **not specified/authorized by the current materials**; plan and submit as one builder unless Razorpay confirms otherwise. This last sentence is an inference from the form, not an explicit “solo only” rule. Sources: [Buildathon page](https://razorpay.com/buildathon/), [official form](https://docs.google.com/forms/d/e/1FAIpQLScJ9XSqVCB2oaPwEMH0Zk3I1OpILFW1WpWdWweQ2950jdRzlg/viewform).
- The official Careers channel gives the deadline as **5 September 2026**, but neither that post, the Buildathon page, nor the form publishes a cutoff time or timezone. This is an unresolved contract detail. Use an internal safety cutoff of 2026-09-04 23:59 IST and verify the live page/form immediately before submission; do not claim “11:59 PM IST” as an official rule. Source: [Razorpay Careers official channel](https://www.linkedin.com/showcase/razorpay-careers/).

## Tracks and their published bars

The official page lists five tracks; a submission chooses one.

1. **AI Growth & Agentic Commerce:** build an agent that grows merchant revenue on Razorpay test-mode APIs, or makes a merchant transactable by an AI buyer end-to-end. Every money action must be explainable, bounded, and gated; show an audit trail and one graceful failure.
2. **AI Risk Manager:** build a working detector, verifier, or auto-responder for one class of fraud, returns, or chargeback loss. Report precision and recall on a held-out test set, include false-positive cost, and stay strictly defense-only; anything offense-capable is disqualified.
3. **AI Revenue Recovery:** detect revenue at risk, determine an intervention, and execute a bounded recovery workflow. Show measured money recovered across a batch, compliant escalation, stopping rules, and an audit trail.
4. **AI Finance Controller:** close one finance-ops loop across a **50+ record synthetic-data batch**. Report throughput/match rate and the exceptions the system could not resolve; one cherry-picked match is insufficient.
5. **Open Track:** any domain, workflow, or user is allowed, but the project must show a real problem, working product, meaningful AI use, value evidence, execution, reliability, and depth.

Source for all track definitions and bars: [Razorpay AI Buildathon](https://razorpay.com/buildathon/).

## Required submission artifacts and form fields

The official page explicitly asks the builder to show: **a public repository, a five-minute pitch video, and the architecture**. The Careers post independently repeats the public-repo and five-minute-pitch requirements. The page does not require a slide deck. Sources: [Buildathon page](https://razorpay.com/buildathon/), [Razorpay Careers official channel](https://www.linkedin.com/showcase/razorpay-careers/).

The current official form (all questions are required unless noted by the form UI) collects:

- email address (Google Forms required email field);
- full name and college name;
- graduation year: 2027, 2028, or 2029;
- in-person internship availability starting September: Yes/No;
- preferred internship duration: 6-month or 12-month;
- selected track: the five tracks above;
- project name/title;
- project objectives (“What does it solve?”);
- GitHub repository URL;
- five-minute pitch video link;
- build challenges and technical obstacles (“What issues did you face while building, and how did you solve them?”); and
- a final-submission checkbox confirming this is the official final submission and that no further changes or edits can be made after submitting.

There is **no separate architecture URL/upload field, demo URL field, resume field, or team field** in the current form. This does not remove the page’s architecture/working-product expectation: put architecture, run instructions, and the demo path in the public repository and pitch. Source: [official application form](https://docs.google.com/forms/d/e/1FAIpQLScJ9XSqVCB2oaPwEMH0Zk3I1OpILFW1WpWdWweQ2950jdRzlg/viewform).

## API and Test Mode expectations

Only the AI Growth & Agentic Commerce track explicitly requires Razorpay test-mode APIs. The other four track descriptions do not state a Razorpay API requirement; they describe the evidence/data bar instead. Source: [Buildathon page](https://razorpay.com/buildathon/).

If the build integrates Razorpay, use Test Mode keys and simulated transactions. Razorpay defines Test Mode as a simulation in which customers cannot make payments; its Sandbox Setup says to use test API keys and that no real money is used. Never put a key secret in the public repository or pitch. Sources: [Razorpay API authentication](https://razorpay.com/docs/api/authentication/), [Razorpay API Sandbox Setup](https://razorpay.com/docs/api/sandbox-setup/).

For this Trust Agent, a Razorpay API integration is optional rather than a submission prerequisite under AI Risk Manager. A reproducible synthetic event set plus held-out evaluation is sufficient to meet the published Risk Manager bar, provided the system is clearly defense-only and the evidence is honest.

## Judging signals and safety constraints

There is no public numeric scorecard or weighting on the current official page. The observable signals are track-specific:

- real problem and value evidence (especially Open Track);
- a working system, not only an idea;
- measured outcomes: held-out precision/recall and false-positive cost (Risk), recovered money across a batch (Revenue), or throughput/match rate plus honest exceptions (Finance);
- explainability, bounded actions, explicit gates, escalation/stopping rules, and audit trails where money or recovery actions are involved; and
- reliability and graceful failure handling, including the form’s required account of what broke and how it was fixed.

The explicit safety floor is strongest for this venture: Risk Manager is **strictly defense-only**, and an offense-capable build is disqualified. Any money-affecting behavior should remain explainable, bounded, gated, logged, and in Test Mode; the Trust Agent should recommend and route rather than autonomously authorize a sensitive Money Action. The last sentence is the Blueprint’s safety interpretation of the published bars, not an additional Razorpay rule.

## Internship conditions

The offer published on the Buildathon page is **₹75,000 monthly stipend**, with a choice of **6 or 12 months**, **in-person in Bangalore from September**. Shortlisted builders go directly to a panel; there is no aptitude test or group discussion, and the page says there is no resume screening. No public official condition promises a PPO, full-time conversion, remote work, a prize, or a particular September start date. Source: [Razorpay AI Buildathon](https://razorpay.com/buildathon/).

## Blueprint acceptance checklist

Before submitting, verify:

1. A single selected track is named (recommended: AI Risk Manager).
2. The public repo is cloneable and documents architecture, setup, model/tool choices, synthetic data provenance, evaluation code, held-out results, limitations, and failure recovery.
3. The five-minute pitch demonstrates the working path, the measured metric, one failure/abstention path, and the human/policy boundary.
4. The form answers match the repo and pitch; the final checkbox is only selected after all links are final because the form says no edits are possible afterward.
5. No live Razorpay secrets, live-money operation, offensive capability, or unsupported claims appear anywhere in the submission.
6. Submission is complete before 5 September 2026; the official cutoff time/timezone remains unknown.

## Uncertainty register

- **Deadline time/timezone:** not published; only the official date “5 Sep” is visible.
- **Team format:** no explicit solo/team rule; the form is individual and has no team fields.
- **Numerical judging weights:** not published; use the track bars as the acceptance contract.
- **Razorpay API requirement outside Track 1:** not stated; do not add an API dependency to Risk Manager without a product reason.
- **Resume/PPO/remote or post-internship terms:** not stated in the current official page/form.
