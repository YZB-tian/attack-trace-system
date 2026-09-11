import { useState } from "react";
import { ChevronRight, GitBranch, ShieldAlert } from "lucide-react";
import type { NormalizedEvent } from "../types/contracts";
import {
  actionLabel,
  attributionMethodLabel,
  compactTime,
  dataClassificationLabel,
  exactTime,
  limitationLabel,
  valueLabel,
} from "../labels";
import "./attribution.css";

type AnyRecord = Record<string, unknown>;

const isRecord = (value: unknown): value is AnyRecord =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const asText = (value: unknown): string =>
  value === null || value === undefined ? "" : typeof value === "string" ? value : String(value);

const PATH_STAGES = [
  ["lateral_movement", "横向移动"],
  ["privilege_escalation", "权限提升"],
  ["data_access", "数据访问"],
  ["data_exfiltration", "数据外传"],
] as const;

const SCOPES: Record<string, string> = {
  primary_candidate_path_only: "仅主候选路径",
};

export function AttributionPanel({ attribution, eventsById }: {
  attribution: AnyRecord;
  eventsById: Map<string, NormalizedEvent>;
}) {
  const classifications = asArray(attribution.data_classification).map(asText);
  const method = asText(attribution.method);
  const llmUsed = attribution.llm_used === true;
  const stixSource = asText(attribution.stix_source);
  const candidatePaths = asArray(attribution.candidate_paths).filter(Array.isArray) as string[][];
  const aptMatches = asArray(attribution.apt_similarity).filter(isRecord);
  const scope = asText(attribution.apt_similarity_scope);
  const pathAnalysis = isRecord(attribution.path_analysis) ? attribution.path_analysis : {};
  const dataPaths = asArray(attribution.data_access_to_network_candidates).filter(isRecord);
  const limitations = asArray(attribution.limitations).map(asText);
  const llmReview = isRecord(attribution.llm_review) ? attribution.llm_review : null;

  return <div className="attribution-panel">
    <dl className="attribution-facts">
      <div>
        <dt>数据分类</dt>
        <dd>{classifications.length
          ? classifications.map((value) => <span className="attribution-chip" key={value} title={value}>{dataClassificationLabel(value)}</span>)
          : "未标注"}</dd>
      </div>
      <div><dt>分析方法</dt><dd>{method ? attributionMethodLabel(method) : "未提供"}</dd></div>
      <div><dt>是否使用大模型</dt><dd>{llmUsed ? "是（仅补充意见）" : "否，全部为确定性结果"}</dd></div>
      <div><dt>ATT&CK 数据源</dt><dd title={stixSource}>{stixSource ? stixSource.split(/[\\/]/).pop() : "未配置官方 STIX bundle，技术名称保持未解析"}</dd></div>
    </dl>

    <section className="attribution-section">
      <h5><GitBranch size={14} aria-hidden="true" />候选路径 · {candidatePaths.length} 条</h5>
      {candidatePaths.length === 0
        ? <p className="attribution-muted">没有形成候选路径：需要至少一条告警参与关联，当前任务没有满足条件的证据链。</p>
        : <ol className="path-list">
          {candidatePaths.slice(0, 3).map((path, index) => <li key={`path-${index}`}>
            <span className="path-index">路径 {index + 1}</span>
            <div className="path-events">{path.map((eventId) => <EventChip key={eventId} eventId={eventId} eventsById={eventsById} />)}</div>
          </li>)}
        </ol>}
      {candidatePaths.length > 3 && <details className="attribution-disclosure">
        <summary>展开其余 {candidatePaths.length - 3} 条候选路径</summary>
        <ol className="path-list">{candidatePaths.slice(3).map((path, index) => <li key={`rest-${index}`}>
          <span className="path-index">路径 {index + 4}</span>
          <div className="path-events">{path.map((eventId) => <EventChip key={eventId} eventId={eventId} eventsById={eventsById} />)}</div>
        </li>)}</ol>
      </details>}
    </section>

    <section className="attribution-section">
      <h5><ShieldAlert size={14} aria-hidden="true" />APT 行为相似度 · {aptMatches.length} 个组织</h5>
      <p className="attribution-muted">比较范围：{SCOPES[scope] ?? (scope || "未说明")}。相似度是行为层面的技术 ID 重合度，不能作为归因结论。</p>
      {aptMatches.length === 0
        ? <p className="attribution-muted">未匹配到已知组织：当前观测到的技术组合与内置知识库没有重合。</p>
        : <table className="attribution-table">
          <thead><tr><th scope="col">组织</th><th scope="col">相似度</th><th scope="col">匹配技术</th><th scope="col">说明</th></tr></thead>
          <tbody>{aptMatches.map((match, index) => <tr key={String(match.group_id ?? index)}>
            <td>{asText(match.group_name)}<small>{asText(match.group_id)}</small></td>
            <td>{typeof match.similarity === "number" ? match.similarity.toFixed(2) : "-"}</td>
            <td>{(asArray(match.matched_techniques).map(asText).join("、")) || "-"}</td>
            <td title={asText(match.interpretation)}>{valueLabel(asText(match.interpretation))}</td>
          </tr>)}</tbody>
        </table>}
    </section>

    <section className="attribution-section">
      <h5>阶段路径分析</h5>
      <div className="stage-path-grid">
        {PATH_STAGES.map(([key, label]) => {
          const rows = asArray((pathAnalysis as AnyRecord)[key]).filter(isRecord);
          return <div className="stage-path-card" key={key}>
            <div className="stage-path-head"><span>{label}</span><strong>{rows.length} 条候选</strong></div>
            {rows.length === 0
              ? <p className="attribution-muted">没有该阶段的证据告警，未做推断。</p>
              : <ul className="stage-path-list">{rows.slice(0, 4).map((row, index) => <li key={`${key}-${index}`}>
                <code title={`${asText(row.source)} → ${asText(row.target)}`}>{asText(row.source)} → {asText(row.target)}</code>
                <small>证据事件 {asArray(row.evidence_event_ids).length} · 告警 {asArray(row.evidence_alert_ids).length}</small>
              </li>)}</ul>}
            {rows.length > 4 && <p className="attribution-muted">另有 {rows.length - 4} 条同类候选。</p>}
          </div>;
        })}
      </div>
    </section>

    <section className="attribution-section">
      <h5>存储到外传候选路径 · {dataPaths.length} 条</h5>
      {dataPaths.length === 0
        ? <p className="attribution-muted">没有同时包含文件读取与后续网络通信的候选路径；这不代表没有外传，只说明当前证据不足以建立该路径。</p>
        : <ul className="data-path-list">{dataPaths.slice(0, 4).map((row, index) => <li key={`data-${index}`}>
          <div className="data-path-head">
            <span>读取事件 {asArray(row.read_event_ids).length}</span>
            <span>写入事件 {asArray(row.written_file_event_ids).length}</span>
            <span>网络事件 {asArray(row.network_event_ids).length}</span>
          </div>
          <div className="data-path-destinations">目标地址：{(asArray(row.destinations).map(asText).join("、")) || "未提供"}</div>
          <small>内容是否真正外传：{row.content_transfer_proven === true ? "已证明" : "未证明"}</small>
        </li>)}</ul>}
      {dataPaths.length > 4 && <p className="attribution-muted">另有 {dataPaths.length - 4} 条同类候选。</p>}
    </section>

    {limitations.length > 0 && <section className="attribution-section">
      <h5>结论边界</h5>
      <ul className="limitation-list">{limitations.map((text, index) => <li key={index} title={text}>{limitationLabel(text)}</li>)}</ul>
    </section>}

    {llmReview && <section className="attribution-section">
      <h5>大模型复核 · 仅作补充，不改变检测结论</h5>
      <dl className="attribution-facts">
        <div><dt>模型</dt><dd>{asText(llmReview.provider)} / {asText(llmReview.model)}</dd></div>
        <div><dt>角色</dt><dd>{asArray(llmReview.roles).map(asText).map((role) => role === "analyst" ? "分析师" : role === "reviewer" ? "审核员" : role).join(" → ")}</dd></div>
        <div><dt>抽样事件</dt><dd>{asText(llmReview.sampled_events)} / {asText(llmReview.total_events)}（优先级抽样，不代表全部事件）</dd></div>
      </dl>
      <ul className="llm-finding-list">{asArray(llmReview.findings).filter(isRecord).map((finding, index) => <li key={index}>
        <p>{asText(finding.text)}</p>
        {asArray(finding.event_ids).length > 0 && <div className="llm-finding-evidence">
          {asArray(finding.event_ids).map(asText).map((eventId) => <EventChip key={eventId} eventId={eventId} eventsById={eventsById} />)}
        </div>}
      </li>)}</ul>
    </section>}
  </div>;
}

export function EventChip({ eventId, eventsById }: { eventId: string; eventsById: Map<string, NormalizedEvent> }) {
  const event = eventsById.get(eventId);
  if (!event) {
    return <span className="event-chip is-unknown" title={`未在当前任务事件集中找到 ${eventId}`}>
      <code>{eventId.slice(0, 20)}…</code><small>事件未在当前任务中</small>
    </span>;
  }
  return <span className="event-chip" title={exactTime(event.timestamp)}>
    <span className="event-chip-time">{compactTime(event.timestamp)}</span>
    <strong>{actionLabel(event.action)}</strong>
    <small>{event.host_id ?? event.source}</small>
  </span>;
}

export function EvidenceIndex({ eventIds, alertIds }: { eventIds: string[]; alertIds: string[] }) {
  const [showAllEvents, setShowAllEvents] = useState(false);
  const visible = showAllEvents ? eventIds : eventIds.slice(0, 12);
  return <div className="evidence-index">
    <div className="evidence-index-head">
      <div><span>事件</span><strong>{eventIds.length}</strong></div>
      <div><span>告警</span><strong>{alertIds.length}</strong></div>
    </div>
    <ul className="evidence-id-list">{visible.map((id) => <li key={id}><code>{id}</code></li>)}</ul>
    {eventIds.length > visible.length && <button type="button" className="text-button" onClick={() => setShowAllEvents(true)}>
      展开全部 {eventIds.length} 个事件 ID<ChevronRight size={15} aria-hidden="true" />
    </button>}
    {showAllEvents && eventIds.length > 12 && <button type="button" className="text-button" onClick={() => setShowAllEvents(false)}>
      收起
    </button>}
    {alertIds.length > 0 && <ul className="evidence-id-list evidence-id-alerts">{alertIds.map((id) => <li key={id}><code>{id}</code></li>)}</ul>}
    <p className="attribution-muted">证据 ID 与原始日志一一对应，用于人工复核。</p>
  </div>;
}
