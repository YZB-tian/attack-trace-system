export type SourceType =
  | "host_log"
  | "host_behavior"
  | "network_flow"
  | "boundary_log";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type TaskState = "pending" | "running" | "completed" | "failed";

export interface ProcessInfo {
  pid?: number | null;
  ppid?: number | null;
  name?: string | null;
  path?: string | null;
  hash_sha256?: string | null;
}

export interface NormalizedEvent {
  schema_version: "1.0";
  event_id: string;
  task_id: string;
  timestamp: string;
  source_type: SourceType;
  source: string;
  host_id?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  user?: string | null;
  action: string;
  process?: ProcessInfo | null;
  object?: { type?: string | null; name?: string | null; path?: string | null } | null;
  network?: {
    protocol?: string | null;
    direction?: string | null;
    bytes_in?: number | null;
    bytes_out?: number | null;
    session_id?: string | null;
  } | null;
  raw_event?: unknown;
  labels: string[];
  metadata: Record<string, unknown>;
}

export interface Alert {
  schema_version: "1.0";
  alert_id: string;
  task_id: string;
  timestamp_start: string;
  timestamp_end?: string | null;
  event_ids: string[];
  host_ids: string[];
  severity: Severity;
  rule_id: string;
  rule_name: string;
  description: string;
  mitre?: {
    tactic: string;
    technique_id: string;
    technique_name: string;
    subtechnique_id?: string | null;
  } | null;
  confidence: number;
  evidence_summary: string;
  detector: string;
  status: "open" | "reviewed" | "false_positive" | "confirmed";
}

export interface GraphNode {
  id: string;
  type: "host" | "user" | "process" | "file" | "ip" | "domain" | "session" | "c2" | "technique" | "other";
  label: string;
  attributes: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relation:
    | "login"
    | "process_spawn"
    | "file_access"
    | "network_connect"
    | "initial_access"
    | "lateral_movement"
    | "privilege_escalation"
    | "c2_communication"
    | "data_access"
    | "data_exfiltration"
    | "related_to";
  timestamp?: string | null;
  technique_id?: string | null;
  evidence_event_ids: string[];
  evidence_alert_ids: string[];
  confidence: number;
  attributes: Record<string, unknown>;
}

export interface AttackGraph {
  schema_version: "1.0";
  graph_id: string;
  task_id: string;
  generated_at: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TaskStatus {
  schema_version: "1.0";
  task_id: string;
  status: TaskState;
  stage: string;
  progress: number;
  message: string;
  created_at: string;
  updated_at: string;
}
