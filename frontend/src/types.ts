export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type AlertStatus =
  | "NEW"
  | "TRIAGED"
  | "AUTO_RESOLVED"
  | "ESCALATED"
  | "CLOSED";

export interface EvidenceLog {
  timestamp: string;
  source: string;
  event_type: string;
  source_ip: string | null;
  destination_ip: string | null;
  username: string | null;
  command: string | null;
  url: string | null;
  status: string | null;
  raw_message: string;
}

export interface Alert {
  alert_id: string;
  timestamp: string;
  severity: Severity;
  rule_id: string;
  rule_name: string;
  description: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  event_type: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_technique_id: string | null;
  evidence: EvidenceLog[];
  status: AlertStatus;
  confidence: number | null;
  created_at: string;
}

export interface AuditEntry {
  timestamp: string;
  event: string;
  detail: Record<string, unknown>;
}

export interface Incident {
  incident_id: string;
  alert_id: string;
  severity: Severity;
  status: AlertStatus;
  title: string;
  description: string | null;
  affected_asset: string | null;
  source_ip: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  mitre_technique_id: string | null;
  evidence: EvidenceLog[];
  historical_matches: Array<Record<string, unknown>>;
  rag_status: "ok" | "no_matches" | "unavailable" | "error" | null;
  confidence: number | null;
  agent_decision: string | null;
  recommended_response: string | null;
  response_action: string | null;
  response_status: string | null;
  escalation_reason: string | null;
  created_at: string;
  updated_at: string;
  timeline: AuditEntry[];
}

export interface Metrics {
  total_logs: number;
  malicious_logs: number;
  detected_malicious_logs: number;
  total_detections: number;
  detection_rate: number | null;
  total_alerts: number;
  alerts_by_severity: Record<Severity, number>;
  alerts_by_status: Record<AlertStatus, number>;
  total_incidents: number;
  incidents_by_status: Record<string, number>;
  incidents_by_technique: Record<string, number>;
  auto_resolved: number;
  escalated: number;
}

export interface Health {
  status: string;
  service: string;
  version: string;
  environment: string;
  llm_configured: boolean;
  rag: { ready: boolean; error: string | null };
}

export interface SimulateResult {
  scenario: string;
  log_count: number;
  detection_count: number;
  alert_count: number;
  incident_count: number;
  alerts: string[];
  incidents: string[];
  decisions: Record<string, string | null>;
}