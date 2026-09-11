import { FileWarning } from "lucide-react";
import type { Alert } from "../types/contracts";
import { dataTime, dataTimeExact, parseEvidenceSummary, type ParsedEvidence } from "./data-panel-format";
import { descriptionNoteLabel, detectorLabel, ruleLabel, scoreKindLabel, scoreLabel, statusLabel, tacticLabel, techniqueLabel } from "../labels";
import "./data-panels.css";

const severityLabels = { info: "信息", low: "低", medium: "中", high: "高", critical: "严重" };

export function AlertsView({ alerts }: { alerts: Alert[] }) {
  return <div className="alert-cards alert-data-view">{alerts.map((alert) => <AlertCard key={alert.alert_id} alert={alert} />)}</div>;
}

/** The detector writes "<title>; requires analyst verification"; show it once. */
function alertNotes(alert: Alert) {
  const name = alert.rule_name ?? "";
  let text = (alert.description ?? "").trim();
  if (name && text.toLowerCase().startsWith(name.toLowerCase())) {
    text = text.slice(name.length).replace(/^[;；,，.\s]+/, "");
  }
  const marker = text.match(/requires analyst verification/i);
  const prefix = marker ? "需人工复核" : "";
  let note = marker ? text.slice(marker.index! + marker[0].length).trim() : text;
  if (!marker) text = "";
  note = note.replace(/^[;；,，.\s]+/, "");
  return { prefix, note, noteOriginal: note, text: note ? descriptionNoteLabel(note) : "" };
}

function AlertCard({ alert }: { alert: Alert }) {
  const evidence = parseEvidenceSummary(alert.evidence_summary);
  const notes = alertNotes(alert);
  const scoreKind = evidence.structured ? scoreKindLabel("heuristic_not_probability") : "";
  const scoreIsHeuristic = evidence.heuristic;

  return <article className="alert-card">
    <div className="alert-card-top">
      <span className={`severity-pill ${alert.severity}`}>{severityLabels[alert.severity]}</span>
      <time dateTime={alert.timestamp_start} title={dataTimeExact(alert.timestamp_start)}>{dataTime(alert.timestamp_start)}</time>
      <span className="alert-status">{statusLabel(alert.status)}</span>
    </div>
    <h3>{ruleLabel(alert.rule_id, alert.rule_name)}</h3>
    <p className="alert-rule-id"><code title={alert.rule_name ? `规则原始名称：${alert.rule_name}` : undefined}>{alert.rule_id}</code></p>
    {(notes.prefix || notes.note) && <p className="alert-notes" title={notes.noteOriginal || undefined}>
      {[notes.prefix, notes.text].filter(Boolean).join(" · ")}
    </p>}
    <dl className="alert-facts">
      <div><dt>{scoreIsHeuristic ? "启发式评分" : "告警置信度"}</dt><dd>{scoreLabel(alert.confidence, scoreIsHeuristic)}</dd></div>
      <div><dt>主机</dt><dd>{alert.host_ids.join("、") || "未关联主机"}</dd></div>
      <div><dt>检测器</dt><dd>{detectorLabel(alert.detector)}</dd></div>
      {alert.timestamp_end && <div><dt>结束时间</dt><dd><time dateTime={alert.timestamp_end} title={dataTimeExact(alert.timestamp_end)}>{dataTime(alert.timestamp_end)}</time></dd></div>}
      {alert.mitre && <div className="alert-fact-wide"><dt>ATT&amp;CK</dt><dd>
        {tacticLabel(alert.mitre.tactic)} · {techniqueLabel(alert.mitre.subtechnique_id ?? alert.mitre.technique_id, alert.mitre.technique_name)}
        {alert.mitre.subtechnique_id && <span className="alert-fact-sub">技术编号 {alert.mitre.subtechnique_id}</span>}
      </dd></div>}
    </dl>
    {scoreIsHeuristic && <p className="alert-score-note">{scoreKind || "启发式评分（非概率）"}：0 到 1 的匹配程度，不代表攻击概率，也不是校准后的置信度。</p>}
    <EvidenceSummary evidence={evidence} />
    <details className="data-disclosure alert-index">
      <summary>告警与事件索引 · {alert.event_ids.length} 条证据事件</summary>
      <dl className="alert-facts">
        <div className="alert-fact-wide"><dt>告警 ID</dt><dd><code>{alert.alert_id}</code></dd></div>
        <div className="alert-fact-wide"><dt>任务 ID</dt><dd><code>{alert.task_id}</code></dd></div>
        <div className="alert-fact-wide"><dt>证据事件</dt><dd className="alert-event-ids">{alert.event_ids.length ? alert.event_ids.map((id, index) => <code key={`${id}-${index}`}>{id}</code>) : "无"}</dd></div>
      </dl>
    </details>
  </article>;
}

function EvidenceSummary({ evidence }: { evidence: ParsedEvidence }) {
  return <section className="alert-evidence">
    <h4><FileWarning size={14} aria-hidden="true" />证据摘要</h4>
    {evidence.structured ? <>
      {evidence.fields.length > 0 && <dl className="beacon-evidence-grid">{evidence.fields.map((field) => <div key={field.key}><dt>{field.label}</dt><dd>{field.value}</dd></div>)}</dl>}
      {evidence.otherFields.length > 0 && <dl className="additional-evidence">{evidence.otherFields.map((field) => <div key={field.key}><dt title={field.key}>{field.label}</dt><dd>{field.value}</dd></div>)}</dl>}
      {evidence.fields.length === 0 && evidence.otherFields.length === 0 && <p className="data-muted">证据摘要为空对象</p>}
      <details className="data-disclosure"><summary>原始证据 JSON</summary><pre className="data-json">{evidence.original}</pre></details>
    </> : <p className="evidence-text">{evidence.original.trim() ? evidence.original : "暂无证据摘要"}</p>}
  </section>;
}
