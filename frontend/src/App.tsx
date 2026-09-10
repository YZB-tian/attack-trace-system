import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ChevronRight,
  CircleCheck,
  CircleX,
  Clock3,
  Database,
  FileWarning,
  GitBranch,
  LoaderCircle,
  Network,
  RefreshCw,
  Search,
  Shield,
  TerminalSquare,
  Wifi,
  X,
} from "lucide-react";
import { client } from "./api/client";
import type {
  Alert,
  AttackGraph,
  GraphNode,
  NormalizedEvent,
  TaskStatus,
} from "./types/contracts";
import type { TraceResult } from "./types/trace";

const DEFAULT_TASK = "task_demo_001";

type LoadState<T> = { data: T | null; loading: boolean; error: string | null };
type Section = "overview" | "events" | "alerts" | "graph" | "trace";

const emptyState = <T,>(): LoadState<T> => ({ data: null, loading: true, error: null });

function useEndpoint<T>(loader: () => Promise<T>, dependencies: string[]): LoadState<T> & { reload: () => void } {
  const [state, setState] = useState<LoadState<T>>(emptyState);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    setState({ data: null, loading: true, error: null });
    loader()
      .then((data) => active && setState({ data, loading: false, error: null }))
      .catch((error: unknown) => {
        if (active) setState({ data: null, loading: false, error: error instanceof Error ? error.message : "请求失败" });
      });
    return () => {
      active = false;
    };
    // Loader is intentionally supplied by each endpoint and dependencies identify its inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, String(revision)]);

  return { ...state, reload };
}

function formatTime(value?: string | null) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}

function percent(value: number) {
  return `${Math.max(0, Math.min(100, value))}%`;
}

function confidence(value: number) {
  return `${Math.round(value * 100)}%`;
}

function statusLabel(status: TaskStatus["status"]) {
  return { pending: "等待中", running: "运行中", completed: "已完成", failed: "失败" }[status];
}

function severityLabel(value: Alert["severity"]) {
  return { info: "信息", low: "低", medium: "中", high: "高", critical: "严重" }[value];
}

function sourceLabel(value: NormalizedEvent["source_type"]) {
  return { host_log: "主机日志", host_behavior: "主机行为", network_flow: "网络流量", boundary_log: "边界日志" }[value];
}

function EmptyState({ icon: Icon = Database, title, detail }: { icon?: typeof Database; title: string; detail?: string }) {
  return <div className="empty-state"><Icon size={22} /><strong>{title}</strong>{detail && <span>{detail}</span>}</div>;
}

function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="error-state"><CircleX size={22} /><div><strong>接口请求失败</strong><span>{message}</span></div>{retry && <button className="icon-button" title="重试" onClick={retry}><RefreshCw size={16} /></button>}</div>;
}

function LoadingState() {
  return <div className="loading-state"><LoaderCircle className="spin" size={22} /><span>正在读取分析数据…</span></div>;
}

function App() {
  const [taskId, setTaskId] = useState(DEFAULT_TASK);
  const [taskInput, setTaskInput] = useState(DEFAULT_TASK);
  const [section, setSection] = useState<Section>("overview");
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const health = useEndpoint(client.health, []);
  const events = useEndpoint(client.events, []);
  const alerts = useEndpoint(client.alerts, []);
  const task = useEndpoint(() => client.task(taskId), [taskId]);
  const graph = useEndpoint(() => client.graph(taskId), [taskId]);
  const trace = useEndpoint(() => client.trace(taskId), [taskId]);

  const reloadAll = () => {
    health.reload(); events.reload(); alerts.reload(); task.reload(); graph.reload(); trace.reload();
  };

  const displayedEvents = useMemo(() => (events.data ?? []).filter((event) => event.task_id === taskId), [events.data, taskId]);
  const displayedAlerts = useMemo(() => (alerts.data ?? []).filter((alert) => alert.task_id === taskId), [alerts.data, taskId]);

  const chooseTask = (event: React.FormEvent) => {
    event.preventDefault();
    const next = taskInput.trim();
    if (next) { setTaskId(next); setSection("overview"); setSelectedNode(null); }
  };

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={20} /></div><div><strong>Attack Trace</strong><span>行为溯源分析台</span></div></div>
      <div className="side-caption">WORKSPACE</div>
      <nav className="nav-list" aria-label="主导航">
        <NavItem icon={Activity} label="任务概览" active={section === "overview"} onClick={() => setSection("overview")} />
        <NavItem icon={Database} label="事件流" count={displayedEvents.length} active={section === "events"} onClick={() => setSection("events")} />
        <NavItem icon={AlertTriangle} label="检测告警" count={displayedAlerts.length} active={section === "alerts"} onClick={() => setSection("alerts")} />
        <NavItem icon={GitBranch} label="攻击图" active={section === "graph"} onClick={() => setSection("graph")} />
        <NavItem icon={Shield} label="溯源结果" active={section === "trace"} onClick={() => setSection("trace")} />
      </nav>
      <div className="sidebar-bottom"><div className="side-caption">SYSTEM</div><div className="system-status"><span className={`status-dot ${health.data ? "online" : health.error ? "offline" : "pending"}`} /><span>API {health.data ? "在线" : health.error ? "离线" : "检测中"}</span><span className="status-url">:8000</span></div><button className="refresh-button" onClick={reloadAll}><RefreshCw size={15} />刷新全部数据</button></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><div className="eyebrow">SECURITY OPERATIONS / TRACE WORKSPACE</div><h1>{sectionTitle(section)}</h1></div><form className="task-picker" onSubmit={chooseTask}><label htmlFor="task-id">分析任务</label><Search size={15} /><input id="task-id" value={taskInput} onChange={(event) => setTaskInput(event.target.value)} spellCheck={false} /><button type="submit" title="加载任务"><ChevronRight size={17} /></button></form></header>
      <div className="content-wrap">
        {section === "overview" && <Overview task={task} events={displayedEvents} alerts={displayedAlerts} graph={graph} trace={trace} onNavigate={setSection} />}
        {section === "events" && <EventsPanel state={{ ...events, data: displayedEvents }} />}
        {section === "alerts" && <AlertsPanel state={{ ...alerts, data: displayedAlerts }} />}
        {section === "graph" && <GraphPanel state={graph} selectedNode={selectedNode} onSelectNode={setSelectedNode} />}
        {section === "trace" && <TracePanel state={trace} />}
      </div>
    </main>
  </div>;
}

function sectionTitle(section: Section) { return { overview: "任务概览", events: "事件流", alerts: "检测告警", graph: "攻击图", trace: "溯源结果" }[section]; }

function NavItem({ icon: Icon, label, count, active, onClick }: { icon: typeof Activity; label: string; count?: number; active: boolean; onClick: () => void }) {
  return <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}><Icon size={17} /><span>{label}</span>{typeof count === "number" && <small>{count}</small>}</button>;
}

function Overview({ task, events, alerts, graph, trace, onNavigate }: { task: LoadState<TaskStatus> & { reload: () => void }; events: NormalizedEvent[]; alerts: Alert[]; graph: LoadState<AttackGraph> & { reload: () => void }; trace: LoadState<TraceResult> & { reload: () => void }; onNavigate: (section: Section) => void }) {
  const graphData = graph.data;
  return <div className="overview-grid">
    <section className="hero-panel"><div className="hero-copy"><span className="section-kicker"><Activity size={14} /> LIVE INVESTIGATION</span><h2>{task.data ? task.data.message : "正在载入任务状态"}</h2><p>{task.data ? `任务 ${task.data.task_id} · 最近更新 ${formatTime(task.data.updated_at)}` : "连接后端接口，加载当前攻击调查上下文。"}</p></div>{task.data && <div className="progress-block"><div className="progress-heading"><span>溯源进度</span><strong>{percent(task.data.progress)}</strong></div><div className="progress-track"><span style={{ width: percent(task.data.progress) }} /></div><div className="progress-meta"><span>阶段：{task.data.stage}</span><span className={`state-pill ${task.data.status}`}>{statusLabel(task.data.status)}</span></div></div>}{task.error && <ErrorState message={task.error} retry={task.reload} />}</section>
    <div className="metric-row"><Metric icon={Database} label="标准化事件" value={events.length} accent="cyan" onClick={() => onNavigate("events")} /><Metric icon={AlertTriangle} label="检测告警" value={alerts.length} accent="amber" onClick={() => onNavigate("alerts")} /><Metric icon={GitBranch} label="攻击图节点" value={graph.data?.nodes.length ?? 0} accent="violet" onClick={() => onNavigate("graph")} /><Metric icon={Shield} label="证据置信度" value={trace.data ? confidence(Math.max(...trace.data.attack_chain.map((stage) => stage.confidence), 0)) : "-"} accent="green" onClick={() => onNavigate("trace")} /></div>
    <section className="panel event-preview"><PanelHeading icon={Database} title="最近事件" action="查看全部" onAction={() => onNavigate("events")} />{events.length === 0 ? <EmptyState title="暂无事件" detail="接口返回空数据" /> : <div className="mini-list">{events.slice(0, 3).map((event) => <div className="mini-row" key={event.event_id}><span className="event-time">{formatTime(event.timestamp)}</span><span className="event-action">{event.action}</span><span className="event-host">{event.host_id ?? event.source}</span><span className="source-tag">{sourceLabel(event.source_type)}</span></div>)}</div>}</section>
    <section className="panel alert-preview"><PanelHeading icon={AlertTriangle} title="告警摘要" action="查看全部" onAction={() => onNavigate("alerts")} />{alerts.length === 0 ? <EmptyState title="暂无告警" detail="当前任务没有检测结果" /> : <div className="alert-stack">{alerts.slice(0, 3).map((alert) => <div className="alert-row" key={alert.alert_id}><span className={`severity-dot ${alert.severity}`} /><div><strong>{alert.rule_name}</strong><span>{alert.rule_id} · {formatTime(alert.timestamp_start)}</span></div><b>{severityLabel(alert.severity)}</b></div>)}</div>}</section>
    <section className="panel chain-preview"><PanelHeading icon={GitBranch} title="攻击链路" action="展开攻击图" onAction={() => onNavigate("graph")} />{graph.loading ? <LoadingState /> : graph.error ? <ErrorState message={graph.error} retry={graph.reload} /> : graphData ? <div className="chain-flow">{graphData.nodes.slice(0, 4).map((node, index) => <div className="chain-node" key={node.id}><NodeGlyph type={node.type} /><span>{node.label}</span>{index < Math.min(graphData.nodes.length, 4) - 1 && <ChevronRight size={14} />}</div>)}</div> : <EmptyState title="暂无攻击图" />}</section>
  </div>;
}

function Metric({ icon: Icon, label, value, accent, onClick }: { icon: typeof Database; label: string; value: string | number; accent: string; onClick: () => void }) { return <button className="metric-card" onClick={onClick}><span className={`metric-icon ${accent}`}><Icon size={18} /></span><span className="metric-label">{label}</span><strong>{value}</strong><ChevronRight className="metric-arrow" size={16} /></button>; }

function PanelHeading({ icon: Icon, title, action, onAction }: { icon: typeof Database; title: string; action?: string; onAction?: () => void }) { return <div className="panel-heading"><div><Icon size={17} /><h3>{title}</h3></div>{action && <button className="text-button" onClick={onAction}>{action}<ChevronRight size={15} /></button>}</div>; }

function EventsPanel({ state }: { state: LoadState<NormalizedEvent[]> & { reload?: () => void } }) { return <section className="panel table-panel"><PanelHeading icon={Database} title="标准化事件" action={`${state.data?.length ?? 0} 条`} />{state.loading ? <LoadingState /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : state.data?.length ? <div className="table-scroll"><table><thead><tr><th>时间</th><th>主机</th><th>来源</th><th>行为</th><th>进程</th><th>网络</th><th>标签</th></tr></thead><tbody>{state.data.map((event) => <tr key={event.event_id}><td className="nowrap">{formatTime(event.timestamp)}</td><td><code>{event.host_id ?? "-"}</code></td><td><span className="source-tag">{sourceLabel(event.source_type)}</span><small className="table-sub">{event.source}</small></td><td><strong>{event.action}</strong><small className="table-sub">{event.event_id}</small></td><td>{event.process?.name ?? "-"}</td><td>{event.src_ip || event.dst_ip ? <span className="network-cell"><Wifi size={14} /><span>{event.src_ip ?? "-"}:{event.src_port ?? "-"}<small>到 {event.dst_ip ?? "-"}:{event.dst_port ?? "-"}</small></span></span> : "-"}</td><td><div className="tag-list">{event.labels.map((label) => <span key={label}>{label}</span>)}</div></td></tr>)}</tbody></table></div> : <EmptyState title="暂无事件" detail="当前任务没有标准化事件" />}</section>; }

function AlertsPanel({ state }: { state: LoadState<Alert[]> & { reload?: () => void } }) { return <section className="panel table-panel"><PanelHeading icon={AlertTriangle} title="检测告警" action={`${state.data?.length ?? 0} 条`} />{state.loading ? <LoadingState /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : state.data?.length ? <div className="alert-cards">{state.data.map((alert) => <article className="alert-card" key={alert.alert_id}><div className="alert-card-top"><span className={`severity-pill ${alert.severity}`}>{severityLabel(alert.severity)}</span><span>{formatTime(alert.timestamp_start)}</span><span className="alert-status">{alert.status}</span></div><h3>{alert.rule_name}</h3><p>{alert.description}</p><div className="alert-detail-grid"><span><small>规则</small><strong>{alert.rule_id}</strong></span><span><small>置信度</small><strong>{confidence(alert.confidence)}</strong></span><span><small>主机</small><strong>{alert.host_ids.join(", ") || "-"}</strong></span>{alert.mitre && <span><small>MITRE</small><strong>{alert.mitre.technique_id} · {alert.mitre.technique_name}</strong></span>}</div><div className="evidence-line"><FileWarning size={14} />{alert.evidence_summary}</div></article>)}</div> : <EmptyState title="暂无告警" detail="当前任务没有检测结果" />}</section>; }

function GraphPanel({ state, selectedNode, onSelectNode }: { state: LoadState<AttackGraph> & { reload: () => void }; selectedNode: GraphNode | null; onSelectNode: (node: GraphNode | null) => void }) {
  return <section className="panel graph-panel"><PanelHeading icon={GitBranch} title="攻击图" action={state.data ? `${state.data.nodes.length} 节点 · ${state.data.edges.length} 关系` : undefined} />{state.loading ? <LoadingState /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : state.data ? <div className="graph-layout"><GraphCanvas graph={state.data} onSelectNode={onSelectNode} /><aside className={`node-inspector ${selectedNode ? "visible" : ""}`}>{selectedNode ? <><div className="inspector-heading"><div><NodeGlyph type={selectedNode.type} /><div><span>节点属性</span><strong>{selectedNode.label}</strong></div></div><button className="icon-button" title="关闭" onClick={() => onSelectNode(null)}><X size={16} /></button></div><div className="inspector-type">{selectedNode.type}</div><dl>{Object.entries(selectedNode.attributes).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd></div>)}</dl></> : <EmptyState icon={GitBranch} title="选择图节点" detail="查看节点属性和证据上下文" />}</aside></div> : <EmptyState title="暂无攻击图" />}</section>;
}

function GraphCanvas({ graph, onSelectNode }: { graph: AttackGraph; onSelectNode: (node: GraphNode) => void }) {
  const width = 780; const height = 390; const positions = useMemo(() => graph.nodes.reduce<Record<string, { x: number; y: number }>>((map, node, index) => { const columns = Math.max(1, Math.ceil(Math.sqrt(graph.nodes.length))); map[node.id] = { x: 100 + (index % columns) * ((width - 200) / Math.max(1, columns - 1)), y: 90 + Math.floor(index / columns) * 145 }; return map; }, {}), [graph.nodes]);
  return <div className="graph-canvas"><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="攻击关系图"><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#7b8ba7" /></marker></defs><g className="edge-layer">{graph.edges.map((edge) => { const from = positions[edge.source]; const to = positions[edge.target]; if (!from || !to) return null; const midX = (from.x + to.x) / 2; const midY = (from.y + to.y) / 2; return <g key={edge.id}><line x1={from.x} y1={from.y} x2={to.x} y2={to.y} markerEnd="url(#arrow)" /><text x={midX} y={midY - 8}>{edge.relation}</text></g>; })}</g><g className="node-layer">{graph.nodes.map((node) => { const point = positions[node.id]; return <g className="graph-node" key={node.id} transform={`translate(${point.x},${point.y})`} onClick={() => onSelectNode(node)} tabIndex={0} role="button" aria-label={`查看 ${node.label}`}><circle r="31" className={`node-circle ${node.type}`} /><text className="node-type" y="-4">{node.type.toUpperCase()}</text><text className="node-label" y="51">{node.label}</text></g>; })}</g></svg><div className="graph-legend">{["host", "process", "ip", "file", "c2"].map((type) => <span key={type}><i className={`legend-dot ${type}`} />{type}</span>)}</div></div>;
}

function TracePanel({ state }: { state: LoadState<TraceResult> & { reload: () => void } }) {
  return <section className="trace-stack">
    {state.loading ? <section className="panel"><LoadingState /></section> : state.error ? <section className="panel"><ErrorState message={state.error} retry={state.reload} /></section> : state.data ? <>
      <section className="trace-hero"><div><span className="section-kicker"><CircleCheck size={14} /> TRACE COMPLETE</span><h2>{state.data.summary}</h2><p>{state.data.trace_id} · 生成于 {formatTime(state.data.generated_at)}</p></div><div className="trace-score"><span>证据覆盖</span><strong>{state.data.evidence_event_ids.length + state.data.evidence_alert_ids.length}</strong><small>条证据</small></div></section>
      <section className="panel"><PanelHeading icon={GitBranch} title="攻击阶段" action={`${state.data.attack_chain.length} 个阶段`} /><div className="stage-list">{state.data.attack_chain.map((stage) => <article className="stage-row" key={stage.order}><div className="stage-number">{String(stage.order).padStart(2, "0")}</div><div className="stage-main"><div className="stage-top"><span>{stage.tactic}</span>{stage.technique_id && <code>{stage.technique_id}</code>}<b>{confidence(stage.confidence)}</b></div><h3>{stage.title}</h3><p>{stage.description}</p><div className="stage-evidence"><span><FileWarning size={14} />事件 {stage.evidence_event_ids.length}</span><span><AlertTriangle size={14} />告警 {stage.evidence_alert_ids.length}</span></div></div></article>)}</div></section>
      <section className="trace-bottom"><section className="panel attribution"><PanelHeading icon={Shield} title="归因分析" />{Object.entries(state.data.attribution).map(([key, value]) => <div className="attribute-row" key={key}><span>{key}</span><strong>{typeof value === "object" ? JSON.stringify(value) : String(value)}</strong></div>)}</section><section className="panel evidence"><PanelHeading icon={FileWarning} title="证据索引" /><div className="evidence-columns"><div><span>事件</span><strong>{state.data.evidence_event_ids.length}</strong><code>{state.data.evidence_event_ids.join("\n") || "-"}</code></div><div><span>告警</span><strong>{state.data.evidence_alert_ids.length}</strong><code>{state.data.evidence_alert_ids.join("\n") || "-"}</code></div></div></section></section>
    </> : <section className="panel"><EmptyState title="暂无溯源结果" /></section>}
  </section>;
}

function NodeGlyph({ type }: { type: GraphNode["type"] }) { return <span className={`node-glyph ${type}`}>{type === "host" ? <TerminalSquare size={15} /> : type === "process" ? <Activity size={15} /> : type === "ip" || type === "c2" ? <Network size={15} /> : <Database size={15} />}</span>; }

export default App;
