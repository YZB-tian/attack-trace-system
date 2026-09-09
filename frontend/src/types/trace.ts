/** Frontend view type for the TraceResult contract absent from the starter types file. */
export interface AttackStage {
  order: number;
  tactic: string;
  technique_id?: string | null;
  technique_name?: string | null;
  title: string;
  description: string;
  entity_ids: string[];
  evidence_event_ids: string[];
  evidence_alert_ids: string[];
  confidence: number;
}

export interface TraceResult {
  schema_version: "1.0";
  trace_id: string;
  task_id: string;
  generated_at: string;
  status: string;
  summary: string;
  initial_access_entity_id?: string | null;
  suspected_c2_entity_ids: string[];
  attack_chain: AttackStage[];
  attribution: Record<string, unknown>;
  evidence_event_ids: string[];
  evidence_alert_ids: string[];
}
