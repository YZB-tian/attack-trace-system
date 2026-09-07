from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from .enums import (
    AlertStatus,
    EdgeRelation,
    NodeType,
    Severity,
    SourceType,
    TaskState,
)

SCHEMA_VERSION = "1.0"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProcessInfo(StrictModel):
    pid: Optional[int] = None
    ppid: Optional[int] = None
    name: Optional[str] = None
    path: Optional[str] = None
    hash_sha256: Optional[str] = None


class EventObject(StrictModel):
    type: Optional[str] = None
    name: Optional[str] = None
    path: Optional[str] = None


class NetworkInfo(StrictModel):
    protocol: Optional[str] = None
    direction: Optional[str] = None
    bytes_in: Optional[int] = None
    bytes_out: Optional[int] = None
    session_id: Optional[str] = None


class NormalizedEvent(StrictModel):
    schema_version: str = SCHEMA_VERSION
    event_id: str
    task_id: str
    timestamp: str

    source_type: SourceType
    source: str
    host_id: Optional[str] = None

    src_ip: Optional[str] = None
    src_port: Optional[int] = Field(default=None, ge=0, le=65535)
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = Field(default=None, ge=0, le=65535)

    user: Optional[str] = None
    action: str

    process: Optional[ProcessInfo] = None
    object: Optional[EventObject] = None
    network: Optional[NetworkInfo] = None

    raw_event: Any = None
    labels: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MitreMapping(StrictModel):
    tactic: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str] = None


class Alert(StrictModel):
    schema_version: str = SCHEMA_VERSION
    alert_id: str
    task_id: str

    timestamp_start: str
    timestamp_end: Optional[str] = None

    event_ids: List[str] = Field(min_length=1)
    host_ids: List[str] = Field(default_factory=list)

    severity: Severity
    rule_id: str
    rule_name: str
    description: str

    mitre: Optional[MitreMapping] = None
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_summary: str = ""
    detector: str
    status: AlertStatus = AlertStatus.OPEN


class GraphNode(StrictModel):
    id: str
    type: NodeType
    label: str
    attributes: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(StrictModel):
    id: str
    source: str
    target: str
    relation: EdgeRelation

    timestamp: Optional[str] = None
    technique_id: Optional[str] = None

    evidence_event_ids: List[str] = Field(default_factory=list)
    evidence_alert_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class AttackGraph(StrictModel):
    schema_version: str = SCHEMA_VERSION
    graph_id: str
    task_id: str
    generated_at: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)


class AttackStage(StrictModel):
    order: int = Field(ge=1)
    tactic: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    title: str
    description: str
    entity_ids: List[str] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    evidence_alert_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class TraceResult(StrictModel):
    schema_version: str = SCHEMA_VERSION
    trace_id: str
    task_id: str
    generated_at: str

    status: str
    summary: str

    initial_access_entity_id: Optional[str] = None
    suspected_c2_entity_ids: List[str] = Field(default_factory=list)
    attack_chain: List[AttackStage] = Field(default_factory=list)

    attribution: Dict[str, Any] = Field(default_factory=dict)
    evidence_event_ids: List[str] = Field(default_factory=list)
    evidence_alert_ids: List[str] = Field(default_factory=list)


class TaskStatus(StrictModel):
    schema_version: str = SCHEMA_VERSION
    task_id: str
    status: TaskState
    stage: str
    progress: int = Field(ge=0, le=100)
    message: str
    created_at: str
    updated_at: str
