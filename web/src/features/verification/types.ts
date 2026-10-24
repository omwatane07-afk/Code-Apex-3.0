export interface CommandStatus {
  status: string
  current_timestamp: string
  active_investigations_count: number
  total_evidence_records: number
  unresolved_disagreements_count: number
  team_evidence_grounding_average: number
  connector_health_ratio: string
  all_connectors_healthy: boolean
  active_review_iteration: number
  latest_investigation: any
  disclaimer: string
}

export interface AgentItem {
  agent_id: string
  role: string
  level: string
  display_name: string
  department: string
  supervisor_role: string | null
  responsibilities: string[]
  benchmarked_precision: number
  benchmarked_recall: number
  evidence_grounding_score: number
  tasks_assigned: number
  tasks_completed: number
  rejections_count: number
  status: string
}

export interface TimelineEventItem {
  id: string
  investigation_id: string
  phase: string
  timestamp: string
  actor_role: string
  actor_name: string
  action: string
  details: string
}

export interface EvidenceRecordItem {
  evidence_id: string
  investigation_id: string
  finding_id: string | null
  task_id: string
  claim: string
  product_name: string
  product_version: string
  test_environment: string
  source_or_test_case: string
  timestamp: string
  raw_observation: Record<string, any>
  sanitized_event: Record<string, any>
  expected_behavior: string
  actual_behavior: string
  evidence_provenance: string
  validation_status: "VERIFIED" | "CONTRADICTED" | "UNVERIFIED" | "TAMPERED"
  related_findings: string[]
  reviewer_comments: { reviewer: string; comment: string }[]
  tamper_hash: string
}

export interface SecurityConnectorItem {
  connector_id: string
  tool_name: string
  category: string
  status: "CONNECTED_HEALTHY" | "DEGRADED" | "DISCONNECTED" | "MAINTENANCE"
  endpoint_url: string
  authenticated_version: string
  last_heartbeat: string
  ingested_events: number
  dropped_events: number
  health_diagnostic: string
  supported_events: string[]
}

export interface ToolCompliancePassportItem {
  tool_id: string
  tool_name: string
  vendor: string
  category: string
  stqc_certificate_ref: string
  auditor_name: string
  vapt_valid_until: string
  pades_signature_hash: string
  cyclonedx_sbom_digest: string
  trust_status: string
  para59_exception_ref: string | null
}

export interface CrashTestScenarioItem {
  test_id: string
  name: string
  category: string
  mitre_attack_id: string
  nist_csf_id: string
  rbi_clause: string
  certin_clause: string
  description: string
  is_mandatory: boolean
  repeat_count: number
}

export interface VerificationResultsData {
  testbed_profile: string
  total_scenarios_evaluated: number
  mandatory_scenarios_count: number
  metrics: {
    overall_detection_rate: number
    precision: number
    recall: number
    false_positive_rate: number
    reproducibility_rate: number
  }
  confusion_matrix: {
    true_positives: number
    false_positives: number
    false_negatives: number
    true_negatives: number
  }
  scenarios: CrashTestScenarioItem[]
}

export interface DisagreementItem {
  id: string
  investigation_id: string
  disputed_claim: string
  agent_a_id: string
  agent_a_role: string
  agent_a_position: string
  agent_a_evidence_id: string
  agent_b_id: string
  agent_b_role: string
  agent_b_position: string
  agent_b_evidence_id: string
  resolution_method: string
  resolution_outcome: string | null
  resolved_at: string | null
}

export interface PrimarySourceItem {
  key: string
  authority: string
  title: string
  document_reference: string
  publication_date: string
  canonical_url: string
  clauses: Record<string, string>
  is_verified: boolean
  notes: string
}
