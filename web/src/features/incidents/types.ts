export interface TriggerItem {
  id: string
  incident_id: string
  trigger_type: string
  occurred_at: string
  recorded_at: string
  asserted_by_id: string
  evidence_summary: string
  rationale: string
  is_disputed: boolean
  dispute_reason?: string | null
  disputed_by_id?: string | null
  counter_occurred_at?: string | null
}

export interface ObligationItem {
  id: string
  incident_id: string
  pack_id: string
  regulator: string
  status: string
  deadline_at: string | null
  disputed_deadline_at: string | null
  active_deadline_at: string | null
  next_due_at: string | null
  escalation_level: number
  locked_until?: string | null
  filed_at?: string | null
  acknowledgement_id?: string | null
  applicability_status?: "assumed_applicable" | "exempt_pending_approval" | "exempt_confirmed" | "not_in_force" | string
  applicability_assessed_at?: string | null
  applicability_assessed_by_id?: string | null
  applicability_rationale?: string | null
  applicability_answers?: Record<string, any> | null
  applicability_pending_rationale?: string | null
}

export interface IncidentItem {
  id: string
  incident_number: string
  title: string
  summary: string
  severity: "low" | "medium" | "high" | "critical"
  status: "new" | "triaged" | "confirmed" | "false_positive" | "contained" | "closed"
  created_at: string
  updated_at: string
  created_by_id: string
  is_major?: boolean
  major_declared_at?: string | null
  major_declared_by_id?: string | null
  major_reason?: string | null
  closed_by_id?: string | null
  closed_at?: string | null
  closure_notes?: string | null
  triggers: TriggerItem[]
  obligations: ObligationItem[]
}
