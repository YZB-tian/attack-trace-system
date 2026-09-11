import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ChevronRight,
  CircleCheck,
  CircleX,
  Database,
  FileWarning,
  GitBranch,
  LoaderCircle,
  Network,
  RefreshCw,
  Search,
  Shield,
  TerminalSquare,
} from "lucide-react";
import { client } from "./api/client";
import { selectTask } from "./task-selection";
import { EventsView } from "./components/EventsView";
import { AlertsView } from "./components/AlertsView";
import { AttributionPanel, EvidenceIndex, EventChip } from "./components/AttributionPanel";
import { parseEvidenceSummary } from "./components/data-panel-format";
import {
  actionLabel,
  compactTime,
  exactTime,
  nodeTypeLabel,
  ruleLabel,
  scoreShort,
  sourceTypeLabel,
  statusLabel,
  tacticLabel,
  techniqueLabel,
} from "./labels";
import type {
  Alert,
  AttackGraph,
  GraphNode,
  NormalizedEvent,
  TaskStatus,
} from "./types/contracts";
import type { AttackStage, TraceResult } from "./types/trace";

const AttackGraphView = lazy(() => import("./components/AttackGraphView"));

const DEFAULT_TASK = new URLSearchParams(window.location.search).get("task") ?? "";

type LoadState<T> = { data: T | null; loading: boolean; error: string | null };
type Section = "overview" | "events" | "alerts" | "graph" | "trace";

const emptyState = <T,>(): LoadState<T> => ({ data: null, loading: true, error: null });

function useEndpoint<T>(loader: () => Promise<T>, dependencies: string[], enabled = true): LoadState<T> & { reload: () => void } {
  const [state, setState] = useState<LoadState<T>>(emptyState);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    if (!enabled) {
      setState({ data: null, loading: false, error: null });
      return;
    }
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
  }, [...dependencies, String(revision), enabled]);

  return { ...state, reload };
}

function percent(value: number) {
  return `${Math.max(0, Math.min(100, value))}%`;
}

function severityLabel(value: Alert["severity"]) {
  return { info: "信息", low: "低", medium: "中", high: "高", critical: "严重" }[value];
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

function RawSummary({ text }: { text: string }) {
  if (!text) return null;
  return <details className="raw-summary">
    <summary>接口返回的分析摘要（原文，未翻译）</summary>
    <p>{text}</p>
  </details>;
}

function App() {
  const [taskId, setTaskId] = useState(DEFAULT_TASK);
  const [taskInput, setTaskInput] = useState(DEFAULT_TASK);
  const [section, setSection] = useState<Section>("overview");

  const health = useEndpoint(client.health, []);
  const events = useEndpoint(client.events, []);
  const alerts = useEndpoint(client.alerts, []);
  useEffect(() => {
    const next = selectTask(taskId, events.data ?? []);
    if (next !== taskId) { setTaskId(next); setTaskInput(next); }
  }, [events.data, taskId]);
  const task = useEndpoint(() => client.task(taskId), [taskId], Boolean(taskId));
  const graph = useEndpoint(() => client.graph(taskId), [taskId], Boolean(taskId));
  const trace = useEndpoint(() => client.trace(taskId), [taskId], Boolean(taskId));

  const reloadAll = () => {
    health.reload(); events.reload(); alerts.reload(); task.reload(); graph.reload(); trace.reload();
  };

  const displayedEvents = useMemo(() => (events.data ?? []).filter((event) => event.task_id === taskId), [events.data, taskId]);
  const displayedAlerts = useMemo(() => (alerts.data ?? []).filter((alert) => alert.task_id === taskId), [alerts.data, taskId]);
  const eventsById = useMemo(() => new Map(displayedEvents.map((event) => [event.event_id, event])), [displayedEvents]);

  const chooseTask = (event: React.FormEvent) => {
    event.preventDefault();
    const next = taskInput.trim();
    if (next) { setTaskId(next); setSection("overview"); }
  };

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={20} /></div><div><strong>Attack Trace</strong><span>行为溯源分析台</span></div></div>
      <div className="side-caption">工作区</div>
      <nav className="nav-list" aria-label="主导航">
        <NavItem icon={Activity} label="任务概览" active={section === "overview"} onClick={() => setSection("overview")} />
        <NavItem icon={Database} label="事件流" count={displayedEvents.length} active={section === "events"} onClick={() => setSection("events")} />
        <NavItem icon={AlertTriangle} label="检测告警" count={displayedAlerts.length} active={section === "alerts"} onClick={() => setSection("alerts")} />
        <NavItem icon={GitBranch} label="攻击图" active={section === "graph"} onClick={() => setSection("graph")} />
        <NavItem icon={Shield} label="溯源结果" active={section === "trace"} onClick={() => setSection("trace")} />
      </nav>
      <div className="sidebar-bottom"><div className="side-caption">系统状态</div><div className="system-status"><span className={`status-dot ${health.data ? "online" : health.error ? "offline" : "pending"}`} /><span>接口{health.data ? "在线" : health.error ? "离线" : "检测中"}</span><span className="status-url">/api</span></div><button className="refresh-button" onClick={reloadAll}><RefreshCw size={15} />刷新全部数据</button></div>
    </aside>
    <main className="main-content">
      <header className="topbar"><div><div className="eyebrow">安全运营 · 溯源工作台</div><h1>{sectionTitle(section)}</h1></div><form className="task-picker" onSubmit={chooseTask}><label htmlFor="task-id">分析任务</label><Search size={15} /><input id="task-id" value={taskInput} onChange={(event) => setTaskInput(event.target.value)} spellCheck={false} title={taskInput} /><button type="submit" title="加载任务" aria-label="加载任务"><ChevronRight size={17} /></button></form></header>
      <div className="content-wrap">
        {displayedEvents.some((event) => event.metadata?.classification === "controlled_emulation") && <p className="data-notice" role="status">受控实验数据 · 含真实日志与通信记录 · 不代表完整入侵链已验证</p>}
        {section === "overview" && <Overview task={task} trace={trace} events={displayedEvents} alerts={displayedAlerts} graph={graph} onNavigate={setSection} />}
        {section === "events" && <EventsPanel state={{ ...events, data: displayedEvents }} />}
        {section === "alerts" && <AlertsPanel state={{ ...alerts, data: displayedAlerts }} />}
        {section === "graph" && <GraphPanel state={graph} alerts={displayedAlerts} />}
        {section === "trace" && <TracePanel state={trace} eventsById={eventsById} />}
      </div>
    </main>
  </div>;
}

function sectionTitle(section: Section) { return { overview: "任务概览", events: "事件流", alerts: "检测告警", graph: "攻击图", trace: "溯源结果" }[section]; }

function NavItem({ icon: Icon, label, count, active, onClick }: { icon: typeof Activity; label: string; count?: number; active: boolean; onClick: () => void }) {
  return <button className={`nav-item ${active ? "active" : ""}`} aria-label={label} aria-current={active ? "page" : undefined} onClick={onClick}><Icon size={17} /><span>{label}</span>{typeof count === "number" && <small>{count}</small>}</button>;
}

function Overview({ task, trace, events, alerts, graph, onNavigate }: {
  task: LoadState<TaskStatus> & { reload: () => void };
  trace: LoadState<TraceResult> & { reload: () => void };
  events: NormalizedEvent[];
  alerts: Alert[];
  graph: LoadState<AttackGraph> & { reload: () => void };
  onNavigate: (section: Section) => void;
}) {
  const topAlert = alerts.reduce<Alert | null>((best, alert) => {
    if (!Number.isFinite(alert.confidence) || alert.confidence < 0 || alert.confidence > 1) return best;
    return !best || alert.confidence > best.confidence ? alert : best;
  }, null);
  const heuristicScore = topAlert ? parseEvidenceSummary(topAlert.evidence_summary).heuristic : false;
  const stages = trace.data?.attack_chain ?? [];

  const headline = task.data
    ? task.data.status === "completed"
      ? `分析完成：${events.length} 个标准化事件，${alerts.length} 条候选告警`
      : task.data.status === "failed"
        ? "分析失败"
        : task.data.status === "running"
          ? `分析进行中：${percent(task.data.progress)}`
          : "等待开始分析"
    : "正在载入任务状态";

  return <div className="overview-grid">
    <section className="hero-panel">
      <div className="hero-copy">
        <span className="section-kicker"><Activity size={14} /> 实时调查</span>
        <h2>{headline}</h2>
        <p>{task.data ? `任务 ${task.data.task_id} · 最近更新 ${compactTime(task.data.updated_at)}` : "连接后端接口，加载当前攻击调查上下文。"}</p>
        <RawSummary text={task.data?.message ?? ""} />
      </div>
      {task.data && <div className="progress-block">
        <div className="progress-heading"><span>溯源进度</span><strong>{percent(task.data.progress)}</strong></div>
        <div className="progress-track"><span style={{ width: percent(task.data.progress) }} /></div>
        <div className="progress-meta"><span>阶段：{statusLabel(task.data.status)}</span><span className={`state-pill ${task.data.status}`}>{statusLabel(task.data.status)}</span></div>
      </div>}
      {task.error && <ErrorState message={task.error} retry={task.reload} />}
    </section>
    <div className="metric-row">
      <Metric icon={Database} label="标准化事件" value={events.length} accent="cyan" onClick={() => onNavigate("events")} />
      <Metric icon={AlertTriangle} label="检测告警" value={alerts.length} accent="amber" onClick={() => onNavigate("alerts")} />
      <Metric icon={GitBranch} label="攻击图节点" value={graph.data?.nodes.length ?? 0} accent="violet" onClick={() => onNavigate("graph")} />
      <Metric
        icon={Shield}
        label={topAlert ? (heuristicScore ? "最高告警评分" : "最高告警置信度") : "最高告警评分"}
        value={topAlert ? scoreShort(topAlert.confidence, heuristicScore) : "—"}
        accent="green"
        hint={topAlert
          ? `当前任务最高的${heuristicScore ? "启发式评分（0～1，非攻击概率）" : "告警置信度"}。`
          : "当前任务没有告警，因此没有可展示的分值。"}
        onClick={() => onNavigate("alerts")}
      />
    </div>
    <section className="panel event-preview">
      <PanelHeading icon={Database} title="最近事件" action="查看全部" onAction={() => onNavigate("events")} />
      {events.length === 0
        ? <EmptyState title="暂无事件" detail="当前任务没有标准化事件" />
        : <div className="mini-list">{events.slice(0, 3).map((event) => <div className="mini-row" key={event.event_id}>
          <span className="event-time" title={exactTime(event.timestamp)}>{compactTime(event.timestamp)}</span>
          <span className="event-action" title={event.action}>{actionLabel(event.action)}</span>
          <span className="event-host">{event.host_id ?? event.source}</span>
          <span className="source-tag">{sourceTypeLabel(event.source_type)}</span>
        </div>)}</div>}
    </section>
    <section className="panel alert-preview">
      <PanelHeading icon={AlertTriangle} title="告警摘要" action="查看全部" onAction={() => onNavigate("alerts")} />
      {alerts.length === 0
        ? <EmptyState title="暂无告警" detail="当前任务没有触发任何检测规则" />
        : <div className="alert-stack">{alerts.slice(0, 3).map((alert) => <div className="alert-row" key={alert.alert_id}>
          <span className={`severity-dot ${alert.severity}`} />
          <div>
            <strong title={alert.rule_name}>{ruleLabel(alert.rule_id, alert.rule_name)}</strong>
            <span>{alert.rule_id} · {compactTime(alert.timestamp_start)}</span>
          </div>
          <b>{severityLabel(alert.severity)}</b>
        </div>)}</div>}
    </section>
    <section className="panel chain-preview">
      <PanelHeading icon={GitBranch} title="攻击链路" action="展开攻击图" onAction={() => onNavigate("graph")} />
      {trace.loading ? <LoadingState /> : trace.error ? <ErrorState message={trace.error} retry={trace.reload} />
        : stages.length > 0
          ? <div className="chain-flow">{stages.slice(0, 6).map((stage, index) => <div className="chain-node" key={stage.order}>
            <NodeGlyph type="other" />
            <span>{tacticLabel(stage.tactic)}{stage.technique_id ? ` · ${stage.technique_id}` : ""}</span>
            {index < Math.min(stages.length, 6) - 1 && <ChevronRight size={14} />}
          </div>)}</div>
          : <EmptyState title="尚未形成攻击阶段" detail="溯源结果中没有带 ATT&CK 映射的告警阶段；可能任务没有命中检测规则，或未配置官方 ATT&CK 数据。" />}
    </section>
  </div>;
}

function Metric({ icon: Icon, label, value, accent, hint, onClick }: { icon: typeof Database; label: string; value: string | number; accent: string; hint?: string; onClick: () => void }) {
  return <button className="metric-card" title={hint} aria-label={`${label} ${value}`} onClick={onClick}><span className={`metric-icon ${accent}`}><Icon size={18} /></span><span className="metric-label">{label}</span><strong>{value}</strong><ChevronRight className="metric-arrow" size={16} /></button>;
}

function PanelHeading({ icon: Icon, title, action, onAction }: { icon: typeof Database; title: string; action?: string; onAction?: () => void }) {
  return <div className="panel-heading"><div><Icon size={17} /><h3>{title}</h3></div>{action && (onAction
    ? <button className="text-button" onClick={onAction}>{action}<ChevronRight size={15} /></button>
    : <span className="panel-heading-note">{action}</span>)}</div>;
}

function EventsPanel({ state }: { state: LoadState<NormalizedEvent[]> & { reload?: () => void } }) {
  return <section className="panel table-panel">
    <PanelHeading icon={Database} title="标准化事件" action={`${state.data?.length ?? 0} 条`} />
    {state.loading ? <LoadingState /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : state.data?.length ? <EventsView events={state.data} /> : <EmptyState title="暂无事件" detail="当前任务没有标准化事件" />}
  </section>;
}

function AlertsPanel({ state }: { state: LoadState<Alert[]> & { reload?: () => void } }) {
  return <section className="panel table-panel">
    <PanelHeading icon={AlertTriangle} title="检测告警" action={`${state.data?.length ?? 0} 条`} />
    {state.loading ? <LoadingState /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : state.data?.length ? <AlertsView alerts={state.data} /> : <EmptyState title="暂无告警" detail="当前任务没有触发任何检测规则" />}
  </section>;
}

function GraphPanel({ state, alerts }: { state: LoadState<AttackGraph> & { reload: () => void }; alerts: Alert[] }) {
  return <section className="panel graph-panel">
    <PanelHeading icon={GitBranch} title="攻击图" action={state.data ? `${state.data.nodes.length} 节点 · ${state.data.edges.length} 关系` : undefined} />
    {state.loading ? <LoadingState /> : state.error ? <ErrorState message={state.error} retry={state.reload} /> : state.data ? <Suspense fallback={<LoadingState />}><AttackGraphView graph={state.data} alerts={alerts} /></Suspense> : <EmptyState title="暂无攻击图" />}
  </section>;
}

function stageText(stage: AttackStage, eventsById: Map<string, NormalizedEvent>) {
  const raw = (stage.description ?? "").trim();
  const observed = raw.match(/^Observed at ([^.]+(?:\.[0-9]+)?(?:[+-]\d{2}:\d{2}|Z)?)\.\s*/);
  let text = observed ? raw.slice(observed[0].length) : raw;
  const title = (stage.title ?? "").trim();
  if (title && text.toLowerCase().startsWith(title.toLowerCase())) {
    text = text.slice(title.length).replace(/^[;；,，.\s]+/, "");
  }
  text = text.replace(/requires analyst verification/gi, "需人工复核");
  return { observedAt: observed ? observed[1] : null, text: text.trim() };
}

function TracePanel({ state, eventsById }: { state: LoadState<TraceResult> & { reload: () => void }; eventsById: Map<string, NormalizedEvent> }) {
  if (state.loading) return <section className="trace-stack"><section className="panel"><LoadingState /></section></section>;
  if (state.error) return <section className="trace-stack"><section className="panel"><ErrorState message={state.error} retry={state.reload} /></section></section>;
  if (!state.data) return <section className="trace-stack"><section className="panel"><EmptyState title="暂无溯源结果" /></section></section>;

  const trace = state.data;
  const paths = Array.isArray(trace.attribution?.candidate_paths) ? (trace.attribution.candidate_paths as unknown[]).length : 0;
  const headline = `溯源完成：${trace.evidence_event_ids.length} 个事件，${trace.evidence_alert_ids.length} 条告警，${paths} 条候选路径`;

  return <section className="trace-stack">
    <section className="trace-hero">
      <div>
        <span className="section-kicker"><CircleCheck size={14} /> 溯源完成</span>
        <h2>{headline}</h2>
        <p>溯源编号 {trace.trace_id} · 生成于 {compactTime(trace.generated_at)}</p>
        {trace.initial_access_entity_id && <p>初始入侵实体：{trace.initial_access_entity_id}</p>}
        <RawSummary text={trace.summary} />
      </div>
      <div className="trace-score">
        <span>证据条目</span>
        <strong>{trace.evidence_event_ids.length + trace.evidence_alert_ids.length}</strong>
        <small>事件 + 告警</small>
      </div>
    </section>

    <section className="panel">
      <PanelHeading icon={GitBranch} title="攻击阶段" action={`${trace.attack_chain.length} 个阶段`} />
      {trace.attack_chain.length === 0
        ? <EmptyState title="没有形成攻击阶段" detail="阶段来自带 ATT&CK 映射的告警；当前任务可能未命中规则，或未配置官方 ATT&CK 数据。" />
        : <div className="stage-list">{trace.attack_chain.map((stage) => {
          const parsed = stageText(stage, eventsById);
          return <article className="stage-row" key={stage.order}>
            <div className="stage-number">{String(stage.order).padStart(2, "0")}</div>
            <div className="stage-main">
              <div className="stage-top">
                <span>{tacticLabel(stage.tactic)}</span>
                {stage.technique_id && <code title={stage.technique_name ?? undefined}>{techniqueLabel(stage.technique_id, stage.technique_name)}</code>}
                <b>{scoreShort(stage.confidence, true)}</b>
              </div>
              <h3 title={stage.title !== ruleLabel(stage.title, stage.title) ? stage.title : undefined}>{ruleLabel(stage.title, stage.title)}</h3>
              {parsed.text && <p>{parsed.text}</p>}
              <div className="stage-evidence">
                {parsed.observedAt && <span title={exactTime(parsed.observedAt)}>观测时间 {compactTime(parsed.observedAt)}</span>}
                <span><FileWarning size={14} />证据事件 {stage.evidence_event_ids.length}</span>
                <span><AlertTriangle size={14} />告警 {stage.evidence_alert_ids.length}</span>
              </div>
              {stage.evidence_event_ids.length > 0 && <div className="stage-event-chips">
                {stage.evidence_event_ids.slice(0, 6).map((eventId) => <EventChip key={eventId} eventId={eventId} eventsById={eventsById} />)}
              </div>}
            </div>
          </article>;
        })}</div>}
    </section>

    <section className="trace-bottom">
      <section className="panel attribution">
        <PanelHeading icon={Shield} title="归因分析" />
        <AttributionPanel attribution={trace.attribution ?? {}} eventsById={eventsById} />
      </section>
      <section className="panel evidence">
        <PanelHeading icon={FileWarning} title="证据索引" />
        <EvidenceIndex eventIds={trace.evidence_event_ids} alertIds={trace.evidence_alert_ids} />
      </section>
    </section>
  </section>;
}

function NodeGlyph({ type }: { type: GraphNode["type"] }) {
  const label = nodeTypeLabel(type);
  return <span className={`node-glyph ${type}`} title={label} aria-label={label}>
    {type === "host" ? <TerminalSquare size={15} /> : type === "process" ? <Activity size={15} /> : type === "ip" || type === "c2" ? <Network size={15} /> : <Database size={15} />}
  </span>;
}

export default App;
