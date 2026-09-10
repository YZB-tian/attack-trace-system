import { useEffect, useId, useRef, useState } from "react";
import { FileSearch, X } from "lucide-react";
import type { NormalizedEvent } from "../types/contracts";
import { dataTime, detailValue, endpointLabel, eventSourceLabel } from "./data-panel-format";
import "./data-panels.css";

export function EventsView({ events }: { events: NormalizedEvent[] }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const openerRef = useRef<HTMLButtonElement | null>(null);
  const selected = events.find((event) => event.event_id === selectedId);

  return <div className="events-view">
    <p className="data-panel-hint">点击事件行或“详情”，查看完整字段与原始证据。</p>
    <table className="events-table">
      <caption className="data-sr-only">标准化事件：时间、主机、来源、行为和网络摘要</caption>
      <colgroup><col className="event-time-column" /><col className="event-host-column" /><col className="event-source-column" /><col className="event-action-column" /><col className="event-network-column" /></colgroup>
      <thead><tr><th scope="col">时间</th><th scope="col">主机</th><th scope="col">来源</th><th scope="col">行为</th><th scope="col">网络摘要</th></tr></thead>
      <tbody>{events.map((event) => <tr key={event.event_id} onClick={(click) => {
        openerRef.current = click.currentTarget.querySelector("button");
        setSelectedId(event.event_id);
      }}>
        <td data-label="时间"><time dateTime={event.timestamp} title={event.timestamp}>{dataTime(event.timestamp)}</time></td>
        <td data-label="主机"><code>{event.host_id ?? "未提供"}</code></td>
        <td data-label="来源"><span className="source-tag">{eventSourceLabel(event.source_type)}</span><span className="event-source-name">{event.source}</span></td>
        <td data-label="行为"><strong>{event.action}</strong><button type="button" className="event-detail-button" aria-label={`查看事件 ${event.event_id} 详情`} aria-haspopup="dialog"><FileSearch size={13} aria-hidden="true" />详情</button></td>
        <td data-label="网络摘要"><NetworkSummary event={event} /></td>
      </tr>)}</tbody>
    </table>
    {selected && <EventDetails event={selected} onClose={() => setSelectedId(null)} returnFocus={openerRef.current} />}
  </div>;
}

function NetworkSummary({ event }: { event: NormalizedEvent }) {
  const hasEndpoints = event.src_ip != null || event.dst_ip != null || event.src_port != null || event.dst_port != null;
  if (!hasEndpoints && !event.network) return <span className="data-muted">无网络信息</span>;
  if (!hasEndpoints && !event.network?.protocol && !event.network?.direction) return <span className="data-muted">网络字段见详情</span>;
  return <div className="event-network-summary">
    {hasEndpoints && <><span><small>源</small><code>{endpointLabel(event.src_ip, event.src_port)}</code></span><span><small>目的</small><code>{endpointLabel(event.dst_ip, event.dst_port)}</code></span></>}
    {(event.network?.protocol || event.network?.direction) && <span className="event-network-meta">{[event.network.protocol, event.network.direction].filter(Boolean).join(" · ")}</span>}
  </div>;
}

function EventDetails({ event, onClose, returnFocus }: { event: NormalizedEvent; onClose: () => void; returnFocus: HTMLButtonElement | null }) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const headingId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    dialog.showModal();
    closeRef.current?.focus();
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      dialog.close();
      document.body.style.overflow = previousOverflow;
      if (returnFocus?.isConnected) returnFocus.focus();
    };
  }, [returnFocus]);

  const fields = [
    ["事件 ID", event.event_id], ["任务 ID", event.task_id], ["时间", event.timestamp],
    ["主机", event.host_id], ["来源类型", event.source_type], ["采集来源", event.source],
    ["行为", event.action], ["用户", event.user], ["源 IP", event.src_ip], ["源端口", event.src_port],
    ["目的 IP", event.dst_ip], ["目的端口", event.dst_port], ["Schema 版本", event.schema_version],
  ] as const;

  return <dialog ref={dialogRef} className="event-detail-dialog" aria-labelledby={headingId} aria-describedby={descriptionId} onCancel={(cancel) => { cancel.preventDefault(); onClose(); }}>
    <header className="event-dialog-header"><div><h2 id={headingId}>事件详情</h2><p id={descriptionId}>{event.event_id}</p></div><button ref={closeRef} type="button" className="data-close-button" onClick={onClose} aria-label="关闭事件详情"><X size={19} aria-hidden="true" /></button></header>
    <div className="event-dialog-body">
      <dl className="event-detail-fields">{fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value == null ? "未提供" : String(value)}</dd></div>)}</dl>
      <EventDetailBlock label="网络" field="network" value={event.network} />
      <EventDetailBlock label="进程" field="process" value={event.process} />
      <EventDetailBlock label="对象" field="object" value={event.object} />
      <EventDetailBlock label="标签" field="labels" value={event.labels} />
      <EventDetailBlock label="元数据" field="metadata" value={event.metadata} />
      <EventDetailBlock label="原始事件" field="raw_event" value={event.raw_event} />
      <details className="data-disclosure"><summary>完整事件 JSON</summary><pre className="data-json">{JSON.stringify(event, null, 2)}</pre></details>
    </div>
  </dialog>;
}

function EventDetailBlock({ label, field, value }: { label: string; field: string; value: unknown }) {
  return <section className="event-detail-block"><h3>{label}<code>{field}</code></h3><pre className="data-json">{detailValue(value)}</pre></section>;
}
