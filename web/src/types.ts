export type TruthState =
  | 'supported'
  | 'contradicted'
  | 'not_observed'
  | 'insufficient_quality'
  | 'not_evaluated';

export type PolicyOutcome =
  | 'BLOCKED'
  | 'HOLD'
  | 'STEP_UP_REQUIRED'
  | 'ELIGIBLE_FOR_HANDOFF';

export type CasePhase =
  | 'EVIDENCE_ADMISSION'
  | 'ADMISSION_REJECTED'
  | 'INVESTIGATION'
  | 'OPERATOR_INTERVENTION'
  | 'READY_FOR_HUMAN_HANDOFF'
  | 'HANDOFF_IN_PROGRESS'
  | 'COMPLETE'
  | 'RECONCILIATION_REQUIRED';

export type IntentStatus =
  | 'NOT_EXTRACTED'
  | 'EXTRACTED'
  | 'CONFIRMED'
  | 'INVALIDATED';

export type DestinationStatus =
  | 'UNAPPROVED'
  | 'APPROVED_FOR_COUNTERPARTY'
  | 'SUSPICIOUS_OR_CHANGED';

export type GrantStatus =
  | 'NOT_ISSUED'
  | 'ACTIVE'
  | 'CONSUMED'
  | 'INVALIDATED'
  | 'EXPIRED'
  | 'SUSPENDED_FOR_RECONCILIATION';

export type HandoffStatus =
  | 'NOT_STARTED'
  | 'PENDING'
  | 'PENDING_IN_APPROVAL_RAIL'
  | 'RECONCILIATION_REQUIRED'
  | 'FAILED';

export interface PaymentIntent {
  counterparty: string | null;
  destination: string | null;
  destination_status: DestinationStatus;
  amount: string | null;
  currency: string;
  purpose: string | null;
  instruction_reference: string | null;
  provenance: string[];
  status: IntentStatus;
  intent_hash: string | null;
}

export interface EvidenceItem {
  id: string;
  item_type: string;
  title: string;
  content_hash: string;
  finding: string;
  truth_state: TruthState;
  admitted_at: string;
}

export interface Finding {
  name: string;
  truth_state: TruthState;
  detail: string;
  evidence_ref?: string;
}

export interface PolicyEvaluationResult {
  outcome: PolicyOutcome | null;
  reasons: string[];
  next_steps: string[];
  evaluated_intent_hash: string | null;
  evaluated_snapshot_hash?: string | null;
  policy_version: string;
  evaluated_at?: string;
  expires_at?: string;
}

export interface HandoffGrant {
  grant_id: string;
  tenant_id: string;
  case_id: string;
  bound_intent_hash: string;
  bound_snapshot_hash: string;
  policy_version: string;
  outcome: PolicyOutcome;
  nonce: string;
  issued_at: string;
  expires_at: string;
  signature: string;
  status: GrantStatus;
  used: boolean;
}

export interface HandoffRecord {
  status: HandoffStatus;
  idempotency_key: string | null;
  attempts: number;
  last_adapter_decision: string | null;
  pending_item_id?: string | null;
}

export interface AuditEvent {
  seq: number;
  case_id?: string;
  event_type: string;
  summary: string;
  actor: string;
  prev_hash: string;
  current_hash: string;
  timestamp: string;
  details: Record<string, any>;
}

export interface ProcessingAuthorityRecord {
  data_class: string;
  source: string;
  subject_category: string;
  submitter: string;
  purpose: string;
  asserted_authority_ref: string;
  permitted_uses: string[];
  processing_route: string;
  redaction_declaration: string;
  retention_days: number;
  legal_hold: boolean;
  restrictions: string[];
  is_valid: boolean;
}

export interface RiskCaseState {
  case_id: string | null;
  case_version: number;
  tenant_id: string;
  phase: CasePhase;
  processing_authority: string;
  authority_record?: ProcessingAuthorityRecord | null;
  request_bundle_status: string;
  intent: PaymentIntent;
  evidence: EvidenceItem[];
  findings: Finding[];
  investigation: {
    model_status: string;
    attempt: number;
  };
  policy: PolicyEvaluationResult;
  grant: HandoffGrant | null;
  handoff: HandoffRecord;
  last_change: string;
  audit: AuditEvent[];
}

export interface BenchmarkReport {
  total_cases: number;
  unsafe_handoffs_count: number;
  passed_safety_gate: boolean;
  three_action_accuracy: number;
  three_action_correct: number;
  three_action_total: number;
  three_action_wilson: [number, number];
  protective_tp: number;
  protective_fp: number;
  protective_fn: number;
  protective_tn: number;
  protective_recall: number;
  protective_recall_wilson: [number, number];
  protective_precision: number;
  protective_precision_wilson: [number, number];
  intent_binding_accuracy: number;
  intent_binding_wilson: [number, number];
  abstention_accuracy: number;
  abstention_wilson: [number, number];
  strata_metrics: Record<string, any>;
  total_no_tool_interactions: number;
  total_tool_interactions: number;
  interaction_reduction_pct: number;
  passed_interaction_gate: boolean;
  confusion_matrix: Record<string, Record<string, number>>;
}
