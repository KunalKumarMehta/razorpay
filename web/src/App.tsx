import { useState, useEffect } from 'react';
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Lock,
  FileCheck,
  RefreshCw,
  ArrowRight,
  Database,
  Key,
  Layers,
  Sparkles,
  BarChart3,
} from 'lucide-react';
import { RiskCaseState, BenchmarkReport, ProcessingAuthorityRecord } from './types';

const SYNTHETIC_AUTHORITY_RECORD: ProcessingAuthorityRecord = {
  data_class: 'SYNTHETIC_VOICE_AND_TEXT',
  source: 'DEMO_COMMUNICATION_CHANNEL',
  subject_category: 'VENDOR',
  submitter: 'Payment Operator (Demo)',
  purpose: 'Synthetic payment intent extraction and deterministic policy verification',
  asserted_authority_ref: 'POLICY-DEMO-AUTH-2026',
  permitted_uses: ['PAYMENT_INTENT_EXTRACTION', 'POLICY_GATE_EVALUATION'],
  processing_route: 'LOCAL_ONLY_SYNTHETIC_PIPELINE',
  redaction_declaration: 'SYNTHETIC_DISCLOSED_NO_PII',
  retention_days: 7,
  legal_hold: false,
  restrictions: ['NO_MODEL_TRAINING', 'LOCAL_STORAGE_ONLY'],
  is_valid: true,
};

const SYNTHETIC_EVIDENCE_INPUT = {
  content: 'SYNTHETIC DEMO EVIDENCE: Urgent payment of INR 4,25,000 to Kaveri Components account HDFC 4821 for tooling deposit.',
  mime_type: 'text/plain',
  filename: 'synthetic_instruction.txt',
  title: 'Synthetic urgent voice note + message bundle',
};

const INITIAL_STATE: RiskCaseState = {
  case_id: null,
  case_version: 0,
  tenant_id: 'tenant_default',
  phase: 'EVIDENCE_ADMISSION',
  processing_authority: 'NOT_CHECKED',
  authority_record: null,
  request_bundle_status: 'NOT_ADMITTED',
  intent: {
    counterparty: null,
    destination: null,
    destination_status: 'UNAPPROVED',
    amount: null,
    currency: 'INR',
    purpose: null,
    instruction_reference: null,
    provenance: [],
    status: 'NOT_EXTRACTED',
    intent_hash: null,
  },
  evidence: [],
  findings: [],
  investigation: {
    model_status: 'NOT_RUN',
    attempt: 0,
  },
  policy: {
    outcome: null,
    reasons: [],
    next_steps: ['Admit an authorized request bundle'],
    evaluated_intent_hash: null,
    policy_version: 'PP-POLICY-V1',
  },
  grant: null,
  handoff: {
    status: 'NOT_STARTED',
    idempotency_key: null,
    attempts: 0,
    last_adapter_decision: null,
    pending_item_id: null,
  },
  last_change: 'Urgent instruction submitted for authority checks; no Risk Case exists yet.',
  audit: [
    {
      seq: 1,
      event_type: 'EVIDENCE_ADMISSION_STARTED',
      summary: 'Urgent out-of-band instruction submitted',
      actor: 'Payment Operator',
      prev_hash: '0000000000000000000000000000000000000000000000000000000000000000',
      current_hash: 'a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890',
      timestamp: new Date().toISOString(),
      details: {},
    },
  ],
};

const ACTION_CATALOG: [string, string][] = [
  ['Start over', 'RESET'],
  ['Admit authorized request', 'ADMIT_AUTHORIZED_BUNDLE'],
  ['Submit incomplete processing authority', 'SUBMIT_UNAUTHORIZED_BUNDLE'],
  ['Extract Payment Intent', 'EXTRACT_INTENT'],
  ['Simulate unusable audio / model failure', 'FAIL_MODEL'],
  ['Confirm exact Payment Intent', 'CONFIRM_INTENT'],
  ['Record independent callback', 'ADD_CALLBACK_EVIDENCE'],
  ['Record destination-approval evidence', 'ADD_DESTINATION_APPROVAL'],
  ['Add contradictory invoice', 'ADD_CONTRADICTION'],
  ['Submit tampered canonical snapshot', 'SUBMIT_TAMPERED_SNAPSHOT'],
  ['Run deterministic Policy Gate', 'EVALUATE_POLICY'],
  ['Issue single-use Handoff Grant', 'ISSUE_GRANT'],
  ['Materially edit amount (₹4.25L ➔ ₹4.75L)', 'EDIT_AMOUNT'],
  ['Operator initiates handoff', 'INITIATE_HANDOFF'],
];

const SCENARIOS = [
  {
    name: 'Happy path',
    description: 'A legitimate urgent exception earns eligibility only after exact intent confirmation, independent callback, and separate policy-governed destination approval. IntentLock creates a pending approval item—not payout approval or execution.',
    steps: [
      'ADMIT_AUTHORIZED_BUNDLE',
      'EXTRACT_INTENT',
      'CONFIRM_INTENT',
      'ADD_CALLBACK_EVIDENCE',
      'ADD_DESTINATION_APPROVAL',
      'EVALUATE_POLICY',
      'ISSUE_GRANT',
      'INITIATE_HANDOFF',
    ],
  },
  {
    name: 'Step-up',
    description: 'Callback confirms the instruction but cannot approve an unapproved destination. The case remains Step Up Required until separate destination-approval evidence is recorded.',
    steps: [
      'ADMIT_AUTHORIZED_BUNDLE',
      'EXTRACT_INTENT',
      'CONFIRM_INTENT',
      'EVALUATE_POLICY',
      'ADD_CALLBACK_EVIDENCE',
      'EVALUATE_POLICY',
      'ADD_DESTINATION_APPROVAL',
      'EVALUATE_POLICY',
    ],
  },
  {
    name: 'Contradiction / Hold',
    description: 'A supplier invoice disagrees with the destination in the instruction. The contradiction remains explicit and forces Policy Gate to Hold.',
    steps: [
      'ADMIT_AUTHORIZED_BUNDLE',
      'EXTRACT_INTENT',
      'CONFIRM_INTENT',
      'ADD_CONTRADICTION',
      'EVALUATE_POLICY',
    ],
  },
  {
    name: 'Blocked input',
    description: 'Evidence was admitted, but the canonical snapshot fails an integrity check. This is a real Policy Outcome of Blocked, with stable reasons and no handoff path.',
    steps: [
      'ADMIT_AUTHORIZED_BUNDLE',
      'EXTRACT_INTENT',
      'CONFIRM_INTENT',
      'SUBMIT_TAMPERED_SNAPSHOT',
      'ISSUE_GRANT',
    ],
  },
  {
    name: 'Admission rejection',
    description: 'The request lacks a complete Processing Authority Record. Evidence is rejected before investigation: no Risk Case opens and no Policy Outcome exists.',
    steps: ['SUBMIT_UNAUTHORIZED_BUNDLE', 'EXTRACT_INTENT'],
  },
  {
    name: 'Material edit',
    description: 'After eligibility and grant issuance, changing ₹4.25L to ₹4.75L immediately invalidates both evaluation and active grant. Old eligibility cannot travel with new money details.',
    steps: [
      'ADMIT_AUTHORIZED_BUNDLE',
      'EXTRACT_INTENT',
      'CONFIRM_INTENT',
      'ADD_CALLBACK_EVIDENCE',
      'ADD_DESTINATION_APPROVAL',
      'EVALUATE_POLICY',
      'ISSUE_GRANT',
      'EDIT_AMOUNT',
      'INITIATE_HANDOFF',
    ],
  },
  {
    name: 'Model failure',
    description: 'Unusable audio or a failed model extraction fails closed, forcing Hold and asking for a safer text recording.',
    steps: ['ADMIT_AUTHORIZED_BUNDLE', 'FAIL_MODEL', 'ISSUE_GRANT'],
  },
  {
    name: 'Replay / ambiguity',
    description: 'The adapter cannot confirm downstream status. Historical eligibility remains, the grant is suspended/consumed, the case enters Reconciliation Required, and blind replays are rejected.',
    steps: [
      'ADMIT_AUTHORIZED_BUNDLE',
      'EXTRACT_INTENT',
      'CONFIRM_INTENT',
      'ADD_CALLBACK_EVIDENCE',
      'ADD_DESTINATION_APPROVAL',
      'EVALUATE_POLICY',
      'ISSUE_GRANT',
      'INITIATE_HANDOFF',
      'INITIATE_HANDOFF',
    ],
  },
];

export function App() {
  const [activeTab, setActiveTab] = useState<'console' | 'benchmark' | 'architecture'>('console');
  const [caseState, setCaseState] = useState<RiskCaseState>(INITIAL_STATE);
  const [activeScenario, setActiveScenario] = useState<number>(0);
  const [scenarioStep, setScenarioStep] = useState<number>(0);
  const [apiOnline, setApiOnline] = useState<boolean>(true);
  const [benchmarkSuite, setBenchmarkSuite] = useState<'dev' | 'sealed' | 'safety'>('dev');
  const [benchmarkReport, setBenchmarkReport] = useState<BenchmarkReport | null>(null);
  const [benchmarkLoading, setBenchmarkLoading] = useState<boolean>(false);
  const [auditValid, setAuditValid] = useState<boolean>(true);

  // Fetch initial case from API or create if absent
  useEffect(() => {
    fetchCase('RC-DEMO-042');
  }, []);

  const createFreshCase = async (prefix = 'RC-SCENARIO') => {
    try {
      const newCaseId = `${prefix}-${Date.now().toString(36).toUpperCase()}`;
      const res = await fetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: newCaseId, tenant_id: 'tenant_default' }),
      });
      if (res.ok) {
        const data = await res.json();
        setCaseState(data);
        setApiOnline(true);
        return data;
      }
    } catch {
      setApiOnline(false);
    }
    return null;
  };

  const fetchCase = async (caseId: string) => {
    try {
      let res = await fetch(`/api/cases/${caseId}`);
      if (res.status === 404) {
        // Missing case returns 404; explicitly create initial case via POST /api/cases
        res = await fetch('/api/cases', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ case_id: caseId, tenant_id: 'tenant_default' }),
        });
      }
      if (res.ok) {
        const data = await res.json();
        setCaseState(data);
        setApiOnline(true);
      }
    } catch {
      setApiOnline(false);
    }
  };

  const dispatchAction = async (actionType: string, isFromScenario = false) => {
    try {
      const caseId = caseState.case_id || 'RC-DEMO-042';
      let payload: Record<string, any> = {};

      if (actionType === 'ADMIT_AUTHORIZED_BUNDLE') {
        payload = {
          case_id: caseId,
          processing_authority: SYNTHETIC_AUTHORITY_RECORD,
          evidence: SYNTHETIC_EVIDENCE_INPUT,
          title: SYNTHETIC_EVIDENCE_INPUT.title,
        };
      } else if (actionType === 'SUBMIT_UNAUTHORIZED_BUNDLE') {
        payload = {
          case_id: caseId,
          // Incomplete / omitted authority demonstrates Admission Rejection
        };
      } else if (
        actionType === 'INITIATE_HANDOFF' &&
        isFromScenario &&
        SCENARIOS[activeScenario]?.name === 'Replay / ambiguity' &&
        scenarioStep === 7
      ) {
        payload = {
          fake_adapter_mode: 'SIMULATE_AMBIGUITY',
        };
      }

      const res = await fetch(`/api/cases/${caseId}/dispatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: actionType, payload }),
      });

      if (res.ok) {
        const nextState = await res.json();
        setCaseState(nextState);
        setApiOnline(true);
        if (isFromScenario && actionType !== 'RESET') {
          setScenarioStep((s) => s + 1);
        }

        // Verify audit chain
        const auditRes = await fetch(`/api/audit/verify/${caseId}`);
        if (auditRes.ok) {
          const auditData = await auditRes.json();
          setAuditValid(auditData.is_valid);
        }
      }
    } catch (e) {
      console.error('API call failed', e);
      setApiOnline(false);
    }
  };

  const runBenchmarkSuite = async (suite: 'dev' | 'sealed' | 'safety') => {
    setBenchmarkSuite(suite);
    setBenchmarkLoading(true);
    try {
      const res = await fetch(`/api/evaluate/run?suite=${suite}`, { method: 'POST' });
      if (res.ok) {
        const report = await res.json();
        setBenchmarkReport(report);
      }
    } catch (e) {
      console.error('Benchmark failed', e);
    } finally {
      setBenchmarkLoading(false);
    }
  };

  const startScenario = async (index: number) => {
    setActiveScenario(index);
    setScenarioStep(0);
    await createFreshCase(`RC-SCENARIO-${index + 1}`);
  };

  const formatAmount = (amt: string | null, curr = 'INR') => {
    if (!amt) return 'Not extracted';
    const num = Number(amt);
    return `₹${num.toLocaleString('en-IN')} ${curr}`;
  };

  const getOutcomeBadge = (outcome: string | null) => {
    if (!outcome) {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 12px', borderRadius: 999, background: '#28362f', color: '#8e9e95', fontSize: 13, fontWeight: 700 }}>
          NOT EVALUATED
        </span>
      );
    }
    if (outcome === 'ELIGIBLE_FOR_HANDOFF') {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 12px', borderRadius: 999, background: 'var(--accent-soft)', color: '#10b981', border: '1px solid #10b981', fontSize: 13, fontWeight: 700 }}>
          <CheckCircle2 size={16} /> ELIGIBLE FOR HANDOFF
        </span>
      );
    }
    if (outcome === 'STEP_UP_REQUIRED') {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 12px', borderRadius: 999, background: 'var(--warn-soft)', color: '#f59e0b', border: '1px solid #f59e0b', fontSize: 13, fontWeight: 700 }}>
          <AlertTriangle size={16} /> STEP UP REQUIRED
        </span>
      );
    }
    if (outcome === 'HOLD') {
      return (
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 12px', borderRadius: 999, background: 'var(--danger-soft)', color: '#ef4444', border: '1px solid #ef4444', fontSize: 13, fontWeight: 700 }}>
          <XCircle size={16} /> HOLD
        </span>
      );
    }
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '4px 12px', borderRadius: 999, background: 'var(--danger-soft)', color: '#ef4444', border: '1px solid #ef4444', fontSize: 13, fontWeight: 700 }}>
        <Lock size={16} /> BLOCKED
      </span>
    );
  };

  const actionLabels = Object.fromEntries(ACTION_CATALOG.map(([lbl, val]) => [val, lbl]));

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', padding: '24px 20px 80px' }}>
      {/* Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, borderBottom: '1px solid var(--surface-border)', paddingBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 34, height: 34, borderRadius: 8, background: 'var(--accent)', display: 'grid', placeItems: 'center', color: '#000' }}>
              <ShieldCheck size={22} strokeWidth={2.5} />
            </div>
            <h1 style={{ fontSize: 24, fontWeight: 800, letterSpacing: '-0.03em' }}>IntentLock</h1>
            <span style={{ fontSize: 12, fontWeight: 700, padding: '2px 8px', borderRadius: 6, background: 'var(--surface-raised)', border: '1px solid var(--surface-border)', color: 'var(--text-muted)' }}>
              LOCAL MODULAR MONOLITH
            </span>
          </div>
          <p style={{ fontSize: 14, color: 'var(--text-muted)', marginTop: 4 }}>
            Trust Agent & Deterministic Policy Gate for Payment Risk · Razorpay Buildathon
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: apiOnline ? '#10b981' : '#ef4444', background: 'var(--surface)', padding: '6px 12px', borderRadius: 8, border: '1px solid var(--surface-border)' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: apiOnline ? '#10b981' : '#ef4444' }} />
            {apiOnline ? 'Control Plane Online' : 'API Offline'}
          </div>

          <button
            onClick={() => createFreshCase('RC-DEMO')}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', borderRadius: 8, background: 'var(--surface-raised)', border: '1px solid var(--surface-border)', color: 'var(--text-main)', fontSize: 13, fontWeight: 600 }}
          >
            <RefreshCw size={14} /> Reset State
          </button>
        </div>
      </header>

      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        <button
          onClick={() => setActiveTab('console')}
          style={{
            padding: '10px 18px',
            borderRadius: 10,
            fontSize: 14,
            fontWeight: 700,
            background: activeTab === 'console' ? 'var(--accent)' : 'var(--surface)',
            color: activeTab === 'console' ? '#000' : 'var(--text-muted)',
            border: '1px solid ' + (activeTab === 'console' ? 'var(--accent)' : 'var(--surface-border)'),
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <Layers size={16} /> Operator Console
        </button>

        <button
          onClick={() => {
            setActiveTab('benchmark');
            if (!benchmarkReport) runBenchmarkSuite('dev');
          }}
          style={{
            padding: '10px 18px',
            borderRadius: 10,
            fontSize: 14,
            fontWeight: 700,
            background: activeTab === 'benchmark' ? 'var(--accent)' : 'var(--surface)',
            color: activeTab === 'benchmark' ? '#000' : 'var(--text-muted)',
            border: '1px solid ' + (activeTab === 'benchmark' ? 'var(--accent)' : 'var(--surface-border)'),
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <BarChart3 size={16} /> Policy Harness & Acceptance Gates
        </button>
      </div>

      {activeTab === 'console' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 360px) minmax(0, 1fr) minmax(320px, 360px)', gap: 20 }}>
          {/* Column 1: Walkthroughs & Free Play */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Guided Walkthroughs */}
            <section style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <Sparkles size={18} color="var(--accent)" />
                <h2 style={{ fontSize: 16, fontWeight: 700 }}>Guided Walkthroughs</h2>
              </div>
              <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 12 }}>
                Select a scenario and execute each step in order:
              </p>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
                {SCENARIOS.map((s, idx) => (
                  <button
                    key={idx}
                    onClick={() => startScenario(idx)}
                    style={{
                      padding: '6px 10px',
                      borderRadius: 6,
                      fontSize: 12,
                      fontWeight: 600,
                      background: activeScenario === idx ? 'var(--accent)' : 'var(--surface-raised)',
                      color: activeScenario === idx ? '#000' : 'var(--text-main)',
                      border: '1px solid var(--surface-border)',
                    }}
                  >
                    {s.name}
                  </button>
                ))}
              </div>

              <div style={{ padding: 12, background: 'var(--surface-raised)', borderRadius: 8, fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.4 }}>
                {SCENARIOS[activeScenario].description}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {SCENARIOS[activeScenario].steps.map((stepType, idx) => {
                  const isDone = idx < scenarioStep;
                  const isNext = idx === scenarioStep;
                  return (
                    <button
                      key={idx}
                      onClick={() => isNext && dispatchAction(stepType, true)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        padding: '10px 12px',
                        borderRadius: 8,
                        fontSize: 13,
                        fontWeight: 600,
                        textAlign: 'left',
                        background: isDone ? 'var(--surface-raised)' : isNext ? 'var(--accent-soft)' : 'var(--surface)',
                        color: isDone ? 'var(--text-dim)' : isNext ? 'var(--accent)' : 'var(--text-muted)',
                        border: '1px solid ' + (isNext ? 'var(--accent)' : 'var(--surface-border)'),
                        cursor: isNext ? 'pointer' : 'default',
                      }}
                    >
                      <span style={{ width: 20, height: 20, borderRadius: '50%', background: isDone ? 'var(--accent)' : isNext ? 'var(--accent)' : 'var(--surface-border)', color: isDone || isNext ? '#000' : '#888', display: 'grid', placeItems: 'center', fontSize: 11, fontWeight: 800 }}>
                        {isDone ? '✓' : idx + 1}
                      </span>
                      <span style={{ flex: 1 }}>
                        {SCENARIOS[activeScenario]?.name === 'Replay / ambiguity' && idx === 7
                          ? 'Operator initiates handoff (simulate ambiguity mode)'
                          : SCENARIOS[activeScenario]?.name === 'Replay / ambiguity' && idx === 8
                          ? 'Second handoff gesture (demonstrates safe replay rejection)'
                          : actionLabels[stepType] || stepType}
                      </span>
                      {isNext && <ArrowRight size={14} />}
                    </button>
                  );
                })}
              </div>
            </section>

            {/* Free Play */}
            <section style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
              <h2 style={{ fontSize: 16, fontWeight: 700, marginBottom: 8 }}>Free Play Controls</h2>
              <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
                Trigger any transition at any time to verify boundary invariants:
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 6, maxHeight: 300, overflowY: 'auto' }}>
                {ACTION_CATALOG.map(([label, type]) => (
                  <button
                    key={type}
                    onClick={() => dispatchAction(type)}
                    style={{
                      padding: '8px 10px',
                      borderRadius: 6,
                      fontSize: 12,
                      fontWeight: 600,
                      textAlign: 'left',
                      background: 'var(--surface-raised)',
                      color: 'var(--text-main)',
                      border: '1px solid var(--surface-border)',
                    }}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </section>
          </div>

          {/* Column 2: Live State Inspection */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Status Bar */}
            <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Phase:
                  </span>
                  <span style={{ fontSize: 13, fontWeight: 700, padding: '3px 8px', borderRadius: 6, background: 'var(--surface-raised)', border: '1px solid var(--surface-border)' }}>
                    {caseState.phase.replace(/_/g, ' ')}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Policy Outcome:
                  </span>
                  {getOutcomeBadge(caseState.policy.outcome)}
                </div>

                <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>
                  Case v{caseState.case_version} · ID: {caseState.case_id || 'None'}
                </span>
              </div>

              {/* What Just Changed Banner */}
              <div style={{ background: 'var(--accent-soft)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: 10, padding: '12px 14px', fontSize: 13, color: '#d1fae5', display: 'flex', alignItems: 'center', gap: 10 }}>
                <CheckCircle2 size={16} color="var(--accent)" style={{ flexShrink: 0 }} />
                <span><strong>What just changed:</strong> {caseState.last_change}</span>
              </div>
            </div>

            {/* Payment Intent Card */}
            <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                <h3 style={{ fontSize: 15, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <FileCheck size={18} color="var(--accent)" /> Authoritative Payment Intent
                </h3>
                <span style={{ fontSize: 12, fontWeight: 700, padding: '2px 8px', borderRadius: 4, background: caseState.intent.status === 'CONFIRMED' ? 'var(--accent-soft)' : 'var(--surface-raised)', color: caseState.intent.status === 'CONFIRMED' ? 'var(--accent)' : 'var(--text-muted)' }}>
                  {caseState.intent.status}
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
                <div style={{ background: 'var(--surface-raised)', padding: 12, borderRadius: 8 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, display: 'block', marginBottom: 4 }}>
                    Counterparty
                  </span>
                  <span style={{ fontSize: 14, fontWeight: 700 }}>
                    {caseState.intent.counterparty || <span style={{ color: 'var(--text-dim)' }}>Not extracted</span>}
                  </span>
                </div>

                <div style={{ background: 'var(--surface-raised)', padding: 12, borderRadius: 8 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, display: 'block', marginBottom: 4 }}>
                    Amount
                  </span>
                  <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent)' }}>
                    {formatAmount(caseState.intent.amount, caseState.intent.currency)}
                  </span>
                </div>

                <div style={{ background: 'var(--surface-raised)', padding: 12, borderRadius: 8 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, display: 'block', marginBottom: 4 }}>
                    Destination Account
                  </span>
                  <span style={{ fontSize: 14, fontWeight: 700 }}>
                    {caseState.intent.destination || <span style={{ color: 'var(--text-dim)' }}>Not extracted</span>}
                  </span>
                  <span style={{ display: 'block', fontSize: 11, color: caseState.intent.destination_status === 'APPROVED_FOR_COUNTERPARTY' ? 'var(--accent)' : 'var(--warn)', marginTop: 2, fontWeight: 600 }}>
                    Status: {caseState.intent.destination_status.replace(/_/g, ' ')}
                  </span>
                </div>

                <div style={{ background: 'var(--surface-raised)', padding: 12, borderRadius: 8 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, display: 'block', marginBottom: 4 }}>
                    Purpose
                  </span>
                  <span style={{ fontSize: 14, fontWeight: 700 }}>
                    {caseState.intent.purpose || <span style={{ color: 'var(--text-dim)' }}>Not extracted</span>}
                  </span>
                </div>
              </div>

              {/* SHA-256 Intent Hash */}
              <div style={{ background: 'var(--bg)', padding: 10, borderRadius: 8, border: '1px solid var(--surface-border)', fontSize: 12 }}>
                <span style={{ color: 'var(--text-muted)', fontWeight: 700, display: 'block', marginBottom: 2 }}>
                  Frozen Intent SHA-256 Hash:
                </span>
                <span className="mono" style={{ color: caseState.intent.intent_hash ? 'var(--accent)' : 'var(--text-dim)', wordBreak: 'break-all' }}>
                  {caseState.intent.intent_hash || 'Unfrozen / Intent not confirmed'}
                </span>
              </div>
            </div>

            {/* Policy & Findings Subgrid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              {/* Policy Reasons & Next Steps */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 16 }}>
                <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                  Policy Reasons ({caseState.policy.reasons.length})
                </h4>
                {caseState.policy.reasons.length > 0 ? (
                  <ul style={{ paddingLeft: 18, fontSize: 12, color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {caseState.policy.reasons.map((r, i) => (
                      <li key={i}>{r.replace(/_/g, ' ')}</li>
                    ))}
                  </ul>
                ) : (
                  <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>No active policy reasons</span>
                )}

                <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: 14, marginBottom: 8 }}>
                  Required Next Steps
                </h4>
                <ul style={{ paddingLeft: 18, fontSize: 12, color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {caseState.policy.next_steps.map((s, i) => (
                    <li key={i}>{s}</li>
                  ))}
                </ul>
              </div>

              {/* Findings & Evidence */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 16 }}>
                <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                  Provenance Findings ({caseState.findings.length})
                </h4>
                {caseState.findings.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {caseState.findings.map((f, i) => (
                      <div key={i} style={{ fontSize: 12, background: 'var(--surface-raised)', padding: 8, borderRadius: 6 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                          <strong>{f.name}</strong>
                          <span style={{ fontSize: 10, fontWeight: 800, padding: '1px 6px', borderRadius: 4, background: f.truth_state === 'supported' ? 'var(--accent-soft)' : f.truth_state === 'contradicted' ? 'var(--danger-soft)' : 'var(--surface-border)', color: f.truth_state === 'supported' ? 'var(--accent)' : f.truth_state === 'contradicted' ? 'var(--danger)' : 'var(--text-muted)' }}>
                            {f.truth_state.toUpperCase()}
                          </span>
                        </div>
                        <div style={{ color: 'var(--text-muted)' }}>{f.detail}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>No findings recorded yet</span>
                )}
              </div>
            </div>

            {/* Handoff Grant & Adapter State */}
            <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 16, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div>
                <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Key size={14} color="var(--accent)" /> Single-Use Handoff Grant
                </h4>
                <div style={{ fontSize: 12 }}>
                  <div><strong>Status:</strong> {caseState.grant ? caseState.grant.status : 'NOT_ISSUED'}</div>
                  {caseState.grant && (
                    <div style={{ marginTop: 4 }}>
                      <div><strong>Grant ID:</strong> {caseState.grant.grant_id}</div>
                      <div style={{ wordBreak: 'break-all', color: 'var(--text-dim)', fontSize: 11, marginTop: 2 }}>
                        Nonce: {caseState.grant.nonce}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div>
                <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Database size={14} color="var(--accent)" /> Downstream Approval Rail
                </h4>
                <div style={{ fontSize: 12 }}>
                  <div><strong>Adapter State:</strong> {caseState.handoff.status.replace(/_/g, ' ')}</div>
                  <div><strong>Last Decision:</strong> {caseState.handoff.last_adapter_decision?.replace(/_/g, ' ') || 'No attempt'}</div>
                  {caseState.handoff.pending_item_id && (
                    <div style={{ color: 'var(--accent)', fontWeight: 700, marginTop: 2 }}>
                      Pending Item: {caseState.handoff.pending_item_id}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Column 3: Audit Hash Chain */}
          <div>
            <section style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18, height: '100%', display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h2 style={{ fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Shield size={18} color="var(--accent)" /> Audit Chain
                </h2>
                <span style={{ fontSize: 11, fontWeight: 800, padding: '2px 8px', borderRadius: 4, background: auditValid ? 'var(--accent-soft)' : 'var(--danger-soft)', color: auditValid ? 'var(--accent)' : 'var(--danger)' }}>
                  {auditValid ? 'CRYPTOGRAPHICALLY VALID' : 'TAMPER DETECTED'}
                </span>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
                Tamper-evident per-case SHA-256 append-only chain ({caseState.audit.length} events):
              </p>

              <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 600 }}>
                {[...caseState.audit].reverse().map((ev) => (
                  <div key={ev.seq} style={{ background: 'var(--surface-raised)', padding: 12, borderRadius: 8, borderLeft: '3px solid var(--accent)', fontSize: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <span style={{ fontWeight: 800, color: 'var(--accent)' }}>#{ev.seq} {ev.event_type}</span>
                      <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>{ev.actor}</span>
                    </div>
                    <div style={{ color: 'var(--text-main)', marginBottom: 6 }}>{ev.summary}</div>
                    <div className="mono" style={{ fontSize: 10, color: 'var(--text-dim)', wordBreak: 'break-all' }}>
                      Hash: {ev.current_hash.slice(0, 24)}...
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      )}

      {activeTab === 'benchmark' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 20 }}>
            <div style={{ display: 'inline-block', padding: '4px 10px', borderRadius: 6, background: '#fef3c7', color: '#92400e', fontSize: 12, fontWeight: 800, letterSpacing: '0.05em', marginBottom: 12 }}>
              DEVELOPMENT POLICY HARNESS / SYNTHETIC STRUCTURED CASES / NOT A SEALED EVALUATION
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 800, marginBottom: 8 }}>Development Policy Harness</h2>
            <p style={{ fontSize: 14, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.5 }}>
              This harness exercises deterministic policy plumbing and boundary invariants on synthetic structured cases. It does <strong>not</strong> represent a sealed evaluation, held-out benchmark, product accuracy, or proof of real-world performance. Predeclared gates are targets only.
            </p>

            <div style={{ display: 'flex', gap: 12 }}>
              <button
                onClick={() => runBenchmarkSuite('dev')}
                disabled={benchmarkLoading}
                style={{
                  padding: '10px 18px',
                  borderRadius: 8,
                  fontSize: 13,
                  fontWeight: 700,
                  background: benchmarkSuite === 'dev' ? 'var(--accent)' : 'var(--surface-raised)',
                  color: benchmarkSuite === 'dev' ? '#000' : 'var(--text-main)',
                  border: '1px solid var(--surface-border)',
                }}
              >
                Run 45-Case Development Harness
              </button>

              <button
                onClick={() => runBenchmarkSuite('sealed')}
                disabled={benchmarkLoading}
                style={{
                  padding: '10px 18px',
                  borderRadius: 8,
                  fontSize: 13,
                  fontWeight: 700,
                  background: benchmarkSuite === 'sealed' ? 'var(--accent)' : 'var(--surface-raised)',
                  color: benchmarkSuite === 'sealed' ? '#000' : 'var(--text-main)',
                  border: '1px solid var(--surface-border)',
                }}
              >
                Run 90-Case Synthetic Policy Harness
              </button>

              <button
                onClick={() => runBenchmarkSuite('safety')}
                disabled={benchmarkLoading}
                style={{
                  padding: '10px 18px',
                  borderRadius: 8,
                  fontSize: 13,
                  fontWeight: 700,
                  background: benchmarkSuite === 'safety' ? 'var(--accent)' : 'var(--surface-raised)',
                  color: benchmarkSuite === 'safety' ? '#000' : 'var(--text-main)',
                  border: '1px solid var(--surface-border)',
                }}
              >
                Run 27-Case Critical Safety Invariant Harness
              </button>
            </div>
          </div>

          {benchmarkReport && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
              {/* Hard Safety Gate Card */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
                <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Zero Tolerance Gate
                </span>
                <div style={{ fontSize: 28, fontWeight: 800, color: benchmarkReport.passed_safety_gate ? 'var(--accent)' : 'var(--danger)', marginTop: 6 }}>
                  {benchmarkReport.unsafe_handoffs_count} Unsafe Handoffs
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
                  Target: 0 unsafe handoffs ({benchmarkReport.passed_safety_gate ? 'Target Met in Harness' : 'Target Failed'})
                </div>
              </div>

              {/* 3-Action Accuracy Card */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
                <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  3-Action Correctness (Harness)
                </span>
                <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent)', marginTop: 6 }}>
                  {(benchmarkReport.three_action_accuracy * 100).toFixed(1)}%
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
                  95% CI: {(benchmarkReport.three_action_wilson[0] * 100).toFixed(1)}%–{(benchmarkReport.three_action_wilson[1] * 100).toFixed(1)}% (Target: ≥ 90.0% · {benchmarkReport.three_action_accuracy >= 0.90 ? 'Target Met in Harness' : 'Below Target'})
                </div>
              </div>

              {/* Protective Recall Card */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
                <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Protective Intervention Recall (Harness)
                </span>
                <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent)', marginTop: 6 }}>
                  {(benchmarkReport.protective_recall * 100).toFixed(1)}%
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
                  TP: {benchmarkReport.protective_tp} | FN: {benchmarkReport.protective_fn} (Target: ≥ 95.0% · {benchmarkReport.protective_recall >= 0.95 ? 'Target Met in Harness' : 'Below Target'})
                </div>
              </div>

              {/* Interaction Reduction Card */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--surface-border)', borderRadius: 14, padding: 18 }}>
                <span style={{ fontSize: 12, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Simulated Interaction Reduction
                </span>
                <div style={{ fontSize: 28, fontWeight: 800, color: 'var(--accent)', marginTop: 6 }}>
                  {benchmarkReport.interaction_reduction_pct.toFixed(1)}%
                </div>
                <div style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
                  {benchmarkReport.total_no_tool_interactions} baseline ➔ {benchmarkReport.total_tool_interactions} gestures (Target: ≥ 30.0% · {benchmarkReport.passed_interaction_gate ? 'Target Met in Harness' : 'Below Target'})
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
