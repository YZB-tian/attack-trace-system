import { FileWarning } from "lucide-react";
import type { Alert } from "../types/contracts";
import { dataTime, parseEvidenceSummary, type ParsedEvidence } from "./data-panel-format";
import "./data-panels.css";

const severityLabels = { info: "信息", low: "低", medium: "中", high: "高", critical: "严重" };

export function AlertsView({ alerts }: { alerts: Alert[] }) {
  return <div className="alert-cards alert-data-view">{alerts.map((alert) => <AlertCard key={alert.alert_id} alert={alert} />)}</div>;
}

function AlertCard({ alert }: { alert: Alert }) {
  const evidence = parseEvidenceSummary(alert.evidence_summary);
  const score = Math.round(alert.confidence * 100);
  return <article className="alert-card">
    <div className="alert-card-top"><span className={`severity-pill ${alert.severity}`}>{severityLabels[alert.severity]}</span><time dateTime={alert.timestamp_start} title={alert.timestamp_start}>{dataTime(alert.timestamp_start)}</time><span className="alert-status">{alert.status}</span></div>
    <h3>{alert.rule_name}</h3><p>{alert.description}</p>
    <dl className="alert-facts">
      <div><dt>规则</dt><dd>{alert.rule_id}</dd></div>
      <div><dt>{evidence.heuristic ? "启发式分数" : "告警置信度"}</dt><dd>{evidence.heuristic ? `${score} / 100` : `${score}%`}</dd></div>
      <div><dt>主机</dt><dd>{alert.host_ids.join(", ") || "未提供"}</dd></div>
      <div><dt>检测器</dt><dd>{alert.detector}</dd></div>
      {alert.mitre && <div className="alert-fact-wide"><dt>MITRE</dt><dd>{alert.mitre.technique_id} · {alert.mitre.technique_name}<span className="alert-fact-sub">{alert.mitre.tactic}{alert.mitre.subtechnique_id ? ` · ${alert.mitre.subtechnique_id}` : ""}</span></dd></div>}
      {alert.timestamp_end && <div><dt>结束时间</dt><dd><time dateTime={alert.timestamp_end} title={alert.timestamp_end}>{dataTime(alert.timestamp_end)}</time></dd></div>}
    </dl>
    {evidence.heuristic && <p className="alert-score-note">启发式分数衡量规则匹配程度，不代表攻击概率。</p>}
    <EvidenceSummary evidence={evidence} />
    <details className="data-disclosure alert-index"><summary>告警与事件索引 · {alert.event_ids.length} 条证据事件</summary><dl className="alert-facts"><div className="alert-fact-wide"><dt>告警 ID</dt><dd>{alert.alert_id}</dd></div><div className="alert-fact-wide"><dt>任务 ID</dt><dd>{alert.task_id}</dd></div><div className="alert-fact-wide"><dt>证据事件</dt><dd className="alert-event-ids">{alert.event_ids.length ? alert.event_ids.map((id, index) => <code key={`${id}-${index}`}>{id}</code>) : "无"}</dd></div></dl></details>
  </article>;
}

function EvidenceSummary({ evidence }: { evidence: ParsedEvidence }) {
  return <section className="alert-evidence"><h4><FileWarning size={14} aria-hidden="true" />证据摘要</h4>
    {evidence.structured ? <>
      {evidence.fields.length > 0 && <dl className="beacon-evidence-grid">{evidence.fields.map((field) => <div key={field.key}><dt>{field.label}</dt><dd>{field.value}</dd></div>)}</dl>}
      {evidence.otherFields.length > 0 && <dl className="additional-evidence">{evidence.otherFields.map((field) => <div key={field.key}><dt>{field.label}</dt><dd>{field.value}</dd></div>)}</dl>}
      {evidence.fields.length === 0 && evidence.otherFields.length === 0 && <p className="data-muted">证据摘要为空对象</p>}
      <details className="data-disclosure"><summary>原始证据</summary><pre className="data-json">{evidence.original}</pre></details>
    </> : <p className="evidence-text">{evidence.original.trim() ? evidence.original : "暂无证据摘要"}</p>}
  </section>;
}
