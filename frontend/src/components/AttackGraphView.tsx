import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import cytoscape from "cytoscape";
import type { Core, EventObject } from "cytoscape";
import dagre from "cytoscape-dagre";
import { Expand, Focus, GitBranch, HelpCircle, Minus, Plus, RotateCcw, Search, X } from "lucide-react";
import type { Alert, AttackGraph, GraphEdge, GraphNode } from "../types/contracts";
import { createGraphElements, edgeElementId, fitGraph, graphStyles, nodeColors, nodeElementId, runGraphLayout } from "./graphModel";
import type { GraphLayout, GraphSelection } from "./graphModel";
import { nodeTypeLabel, compactTime, relationLabel } from "../labels";
import "./graph.css";

cytoscape.use(dagre);

const RELATION_LABEL_BUDGET = 120;
const SUGGESTION_LIMIT = 200;

export default function AttackGraphView({ graph, alerts = [] }: { graph: AttackGraph; alerts?: Alert[] }) {
  const canvasRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Core | null>(null);
  const [selection, setSelection] = useState<GraphSelection>(null);
  const [layout, setLayout] = useState<GraphLayout>("cose");
  const [allRelations, setAllRelations] = useState(false);
  const [zoom, setZoom] = useState(100);
  const [expanded, setExpanded] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [hiddenTypes, setHiddenTypes] = useState<string[]>([]);
  const [onlyAlertRelated, setOnlyAlertRelated] = useState(false);
  const [nodeQuery, setNodeQuery] = useState("");
  const [edgeQuery, setEdgeQuery] = useState("");
  const hintId = useId();

  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const node of graph.nodes) counts.set(node.type, (counts.get(node.type) ?? 0) + 1);
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [graph.nodes]);

  const alertNodeIds = useMemo(() => {
    const ids = new Set<string>();
    const alertEventIds = new Set(alerts.flatMap((alert) => alert.event_ids));
    for (const node of graph.nodes) {
      const attribute = node.attributes?.alert_ids;
      if (Array.isArray(attribute) && attribute.length > 0) ids.add(node.id);
      if (node.type === "c2") ids.add(node.id);
      const eventId = node.attributes?.event_id;
      if (typeof eventId === "string" && alertEventIds.has(eventId)) ids.add(node.id);
    }
    for (const alert of alerts) for (const host of alert.host_ids) ids.add(host);
    // Entities that an alert edge directly implicates, without pulling in every
    // neighbour of a hub host (which would keep the whole graph visible).
    for (const edge of graph.edges) {
      if (edge.evidence_alert_ids?.length) { ids.add(edge.source); ids.add(edge.target); }
    }
    return ids;
  }, [graph.nodes, alerts]);

  // A graph with hundreds of nodes is unreadable at fit zoom, so a task whose
  // graph is that large starts focused on alert-backed evidence. The user can
  // switch back with one click, and the summary line always states the ratio.
  useEffect(() => {
    const hasAlertEvidence = graph.nodes.some((node) => Array.isArray(node.attributes?.alert_ids)
      && (node.attributes.alert_ids as unknown[]).length > 0);
    setHiddenTypes([]);
    setOnlyAlertRelated(graph.nodes.length > 150 && hasAlertEvidence);
    setNodeQuery("");
    setEdgeQuery("");
  }, [graph.graph_id, graph.nodes]);

  const filtered = useMemo(() => {
    const visibleNodes = graph.nodes.filter((node) => !hiddenTypes.includes(node.type));
    let keep = visibleNodes;
    if (onlyAlertRelated && alertNodeIds.size > 0) {
      keep = visibleNodes.filter((node) => alertNodeIds.has(node.id));
    }
    const ids = new Set(keep.map((node) => node.id));
    const edges = graph.edges.filter((edge) => ids.has(edge.source) && ids.has(edge.target));
    return { nodes: keep, edges };
  }, [graph, hiddenTypes, onlyAlertRelated, alertNodeIds]);

  const model = useMemo(
    () => createGraphElements({ ...graph, nodes: filtered.nodes, edges: filtered.edges }),
    [graph, filtered],
  );
  const nodesById = useMemo(() => new Map(filtered.nodes.map((node) => [node.id, node])), [filtered.nodes]);
  const selectedNode = selection?.kind === "node" ? nodesById.get(selection.id) : undefined;
  const selectedEdge = selection?.kind === "edge" ? filtered.edges.find((edge) => edge.id === selection.id) : undefined;
  const filtering = hiddenTypes.length > 0 || onlyAlertRelated;
  const nodeMatches = useMemo(() => matchNodes(filtered.nodes, nodeQuery), [filtered.nodes, nodeQuery]);
  const edgeMatches = useMemo(() => matchEdges(filtered.edges, nodesById, edgeQuery), [filtered.edges, nodesById, edgeQuery]);

  const fitView = useCallback(() => {
    const instance = graphRef.current;
    if (instance) fitGraph(instance);
  }, []);

  const changeZoom = useCallback((factor: number) => {
    const instance = graphRef.current;
    if (!instance) return;
    instance.zoom({
      level: Math.max(instance.minZoom(), Math.min(instance.maxZoom(), instance.zoom() * factor)),
      renderedPosition: { x: instance.width() / 2, y: instance.height() / 2 },
    });
  }, []);

  const chooseElement = useCallback((next: GraphSelection, focus = false) => {
    setSelection(next);
    const instance = graphRef.current;
    if (!instance) return;
    instance.elements().unselect().removeClass("neighbor");
    if (!next) return;
    const element = instance.getElementById(next.kind === "node" ? nodeElementId(next.id) : edgeElementId(next.id));
    if (!element.length) return;
    element.select();
    if (next.kind === "node") element.neighborhood("node").addClass("neighbor");
    if (focus) {
      const focused = next.kind === "edge" ? element.union(element.connectedNodes()) : element;
      instance.fit(focused, 110);
      if (instance.zoom() > 1.2) { instance.zoom(1.2); instance.center(focused); }
    }
  }, []);

  useEffect(() => {
    if (!canvasRef.current || !model.elements.length) return;
    const instance = cytoscape({
      container: canvasRef.current, elements: model.elements, style: graphStyles,
      layout: { name: "preset" }, minZoom: 0.08, maxZoom: 3,
      selectionType: "single", boxSelectionEnabled: false,
      autoungrabify: false, userPanningEnabled: true, userZoomingEnabled: true,
    });
    graphRef.current = instance;
    setSelection(null);
    const select = (event: EventObject) => {
      const element = event.target;
      chooseElement({ kind: element.isNode() ? "node" : "edge", id: String(element.data("contractId")) });
    };
    instance.on("tap", "node, edge", select);
    instance.on("tap", (event) => { if (event.target === instance) chooseElement(null); });
    instance.on("mouseover", "edge", (event) => event.target.addClass("hovered"));
    instance.on("mouseout", "edge", (event) => event.target.removeClass("hovered"));
    instance.on("zoom", () => setZoom(Math.round(instance.zoom() * 1000) / 10));
    const observer = new ResizeObserver(() => instance.resize());
    observer.observe(canvasRef.current);
    return () => {
      observer.disconnect();
      instance.destroy();
      if (graphRef.current === instance) graphRef.current = null;
    };
  }, [model, chooseElement]);

  useEffect(() => {
    if (graphRef.current && model.elements.length) runGraphLayout(graphRef.current, layout);
  }, [model, layout]);

  useEffect(() => {
    graphRef.current?.edges().toggleClass("show-relation", allRelations);
  }, [model, allRelations]);

  useEffect(() => {
    const frame = requestAnimationFrame(fitView);
    return () => cancelAnimationFrame(frame);
  }, [expanded, fitView, filtered]);

  const handleCanvasKey = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.target !== event.currentTarget) return;
    const pan: Record<string, { x: number; y: number }> = {
      ArrowLeft: { x: 60, y: 0 }, ArrowRight: { x: -60, y: 0 },
      ArrowUp: { x: 0, y: 60 }, ArrowDown: { x: 0, y: -60 },
    };
    if (pan[event.key]) { event.preventDefault(); graphRef.current?.panBy(pan[event.key]); }
    else if (event.key === "+" || event.key === "=") { event.preventDefault(); changeZoom(1.25); }
    else if (event.key === "-") { event.preventDefault(); changeZoom(0.8); }
    else if (event.key === "0") { event.preventDefault(); fitView(); }
    else if (event.key === "Escape") { chooseElement(null); setExpanded(false); }
  };

  const toggleType = (type: string) => {
    setHiddenTypes((current) => current.includes(type) ? current.filter((item) => item !== type) : [...current, type]);
  };

  const relationLabelsDisabled = filtered.edges.length > RELATION_LABEL_BUDGET;

  return <section className={`attack-graph-view ${expanded ? "is-expanded" : ""}`} aria-label="交互攻击图" onKeyDown={(event) => { if (event.key === "Escape" && expanded) setExpanded(false); }}>
    <div className="attack-graph-toolbar">
      <div className="attack-graph-controls" role="group" aria-label="画布控制">
        <button type="button" onClick={() => changeZoom(1.25)} aria-label="放大" title="放大"><Plus size={16} /></button>
        <output aria-label="当前缩放比例">{zoom}%</output>
        <button type="button" onClick={() => changeZoom(0.8)} aria-label="缩小" title="缩小"><Minus size={16} /></button>
        <button type="button" onClick={fitView} title="缩放到全部可见节点"><Focus size={15} />适配全图</button>
        <button type="button" onClick={() => { if (graphRef.current) runGraphLayout(graphRef.current, layout); }} title="重新计算节点位置"><RotateCcw size={14} />重新布局</button>
        <button type="button" onClick={() => setExpanded((value) => !value)} aria-pressed={expanded}><Expand size={14} />{expanded ? "收起画布" : "全屏画布"}</button>
        <button type="button" onClick={() => setShowHelp((value) => !value)} aria-pressed={showHelp} aria-label="画布操作说明" title="操作说明"><HelpCircle size={15} /></button>
      </div>
      <label className="attack-graph-layout-picker">排列方式<select aria-label="攻击图排列方式" value={layout} onChange={(event) => setLayout(event.target.value === "dagre" ? "dagre" : "cose")}><option value="cose">力导向</option><option value="dagre">分层</option></select></label>
      <label className="attack-graph-label-toggle" title={relationLabelsDisabled ? `关系超过 ${RELATION_LABEL_BUDGET} 条，全部显示会互相遮挡；请先筛选用节点，或在图上悬停单条关系查看标签。` : "在每条关系上显示名称"}>
        <input type="checkbox" checked={allRelations} disabled={relationLabelsDisabled} onChange={(event) => setAllRelations(event.target.checked)} />显示全部关系标签
      </label>
    </div>

    <p id={hintId} className="data-sr-only">可拖动节点、滚轮缩放、拖动空白处平移；方向键平移，加号与减号缩放，数字 0 适配全图。</p>
    {showHelp && <div className="attack-graph-help" role="note">
      <p>拖动节点调整位置，滚轮缩放，拖动空白处平移。</p>
      <p>点击节点或关系查看属性与证据；悬停关系可临时显示名称。</p>
      <p>键盘：方向键平移，+ / − 缩放，0 适配全图，Esc 取消选中。</p>
    </div>}

    <div className="attack-graph-filters">
      <div className="attack-graph-type-filter" role="group" aria-label="按节点类型筛选">
        <span className="attack-graph-filter-caption">节点类型</span>
        {typeCounts.map(([type, count]) => <button type="button" key={type} className={`type-chip ${hiddenTypes.includes(type) ? "is-off" : ""}`} aria-pressed={!hiddenTypes.includes(type)} onClick={() => toggleType(type)} title={`${nodeTypeLabel(type)}（${type}）`}>
          <i style={{ backgroundColor: nodeColors[type as GraphNode["type"]] ?? "#a0b4c9" }} />{nodeTypeLabel(type)}<small>{count}</small>
        </button>)}
      </div>
      <label className="attack-graph-toggle">
        <input type="checkbox" checked={onlyAlertRelated} onChange={(event) => setOnlyAlertRelated(event.target.checked)} />只看与告警相关的节点
      </label>
      {(filtering || hiddenTypes.length > 0) && <button type="button" className="attack-graph-reset" onClick={() => { setHiddenTypes([]); setOnlyAlertRelated(false); }}>
        重置筛选
      </button>}
    </div>

    <div className="attack-graph-selectors">
      <label>
        <span>节点</span>
        <span className="attack-graph-search">
          <Search size={14} aria-hidden="true" />
          <input value={nodeQuery} placeholder={`按名称或 ID 搜索（${filtered.nodes.length} 个节点）`} onChange={(event) => setNodeQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter" && nodeMatches[0]) { event.preventDefault(); chooseElement({ kind: "node", id: nodeMatches[0].id }, true); } }} />
        </span>
        {nodeQuery && <span className="attack-graph-search-note">{nodeMatches.length ? `匹配 ${nodeMatches.length} 个，回车定位第一个` : "没有匹配的节点"}</span>}
      </label>
      <label>
        <span>关系</span>
        <span className="attack-graph-search">
          <Search size={14} aria-hidden="true" />
          <input value={edgeQuery} placeholder={`按关系或端点搜索（${filtered.edges.length} 条关系）`} onChange={(event) => setEdgeQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter" && edgeMatches[0]) { event.preventDefault(); chooseElement({ kind: "edge", id: edgeMatches[0].id }, true); } }} />
        </span>
        {edgeQuery && <span className="attack-graph-search-note">{edgeMatches.length ? `匹配 ${edgeMatches.length} 条，回车定位第一条` : "没有匹配的关系"}</span>}
      </label>
    </div>

    {graph.nodes.length !== filtered.nodes.length && <p className="attack-graph-filter-summary" role="status">
      正在显示 {filtered.nodes.length} / {graph.nodes.length} 个节点、{filtered.edges.length} / {graph.edges.length} 条关系。
    </p>}
    {model.unresolvedEdges.length > 0 && <p className="attack-graph-warning" role="status">
      {model.unresolvedEdges.length} 条关系引用的节点缺失，无法绘制；这些关系的证据仍保留在溯源结果中。
    </p>}

    <div className="attack-graph-body">
      <div className="attack-graph-stage">
        {filtered.nodes.length
          ? <div ref={canvasRef} className="attack-graph-canvas" tabIndex={0} role="region" aria-label={`攻击关系图，${filtered.nodes.length} 个节点，${filtered.edges.length} 条关系`} aria-describedby={hintId} onKeyDown={handleCanvasKey} />
          : <div className="attack-graph-empty"><GitBranch size={24} /><strong>{graph.nodes.length ? "当前筛选没有可见节点" : "暂无攻击图节点"}</strong><span>{graph.nodes.length ? "调整节点类型筛选或关闭“只看与告警相关的节点”。" : "当前任务没有产生攻击图。"}</span></div>}
        <div className="attack-graph-legend" aria-label="节点类型图例">
          {typeCounts.map(([type]) => <span key={type}><i style={{ backgroundColor: nodeColors[type as GraphNode["type"]] ?? "#a0b4c9" }} />{nodeTypeLabel(type)}</span>)}
        </div>
      </div>
      <aside className="attack-graph-inspector" aria-label="图元素详情" aria-live="polite">
        {(selectedNode || selectedEdge) && <button className="attack-graph-close" type="button" aria-label="关闭图元素详情" onClick={() => chooseElement(null)}><X size={16} /></button>}
        {selectedNode
          ? <NodeDetails node={selectedNode} edges={filtered.edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)} onSelectEdge={(id) => chooseElement({ kind: "edge", id }, true)} />
          : selectedEdge
            ? <EdgeDetails edge={selectedEdge} nodesById={nodesById} onSelectNode={(id) => chooseElement({ kind: "node", id }, true)} />
            : <div className="attack-graph-empty"><GitBranch size={22} /><strong>未选中图元素</strong><span>点击画布中的节点或关系，或使用上方搜索框定位。</span></div>}
      </aside>
    </div>
  </section>;
}

function matchNodes(nodes: GraphNode[], query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  return nodes.filter((node) => node.label.toLowerCase().includes(needle) || node.id.toLowerCase().includes(needle)).slice(0, SUGGESTION_LIMIT);
}

function matchEdges(edges: GraphEdge[], nodesById: Map<string, GraphNode>, query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  return edges.filter((edge) => {
    const source = nodesById.get(edge.source)?.label ?? edge.source;
    const target = nodesById.get(edge.target)?.label ?? edge.target;
    return [edge.relation, edge.id, source, target].some((value) => value.toLowerCase().includes(needle));
  }).slice(0, SUGGESTION_LIMIT);
}

function NodeDetails({ node, edges, onSelectEdge }: { node: GraphNode; edges: GraphEdge[]; onSelectEdge: (id: string) => void }) {
  return <>
    <span className="attack-graph-detail-kicker">节点详情 · {nodeTypeLabel(node.type)}</span>
    <h4>{node.label}</h4>
    <dl>
      <Detail label="节点 ID" value={node.id} />
      <Detail label="节点类型" value={`${nodeTypeLabel(node.type)}（${node.type}）`} />
    </dl>
    <Attributes attributes={node.attributes} />
    <h5>关联关系 · {edges.length}</h5>
    <div className="attack-graph-related">{edges.length
      ? edges.map((edge) => <button type="button" key={edge.id} onClick={() => onSelectEdge(edge.id)}>
        <strong>{relationLabel(edge.relation)}</strong>
        <span>{(edge.source === node.id ? "指向" : "来自")} {edge.source === node.id ? edge.target : edge.source}</span>
        <small>置信度 {Math.round(edge.confidence * 100)}% · 证据 {edge.evidence_event_ids.length} 条</small>
      </button>)
      : <p>没有关联关系</p>}</div>
  </>;
}

function EdgeDetails({ edge, nodesById, onSelectNode }: { edge: GraphEdge; nodesById: Map<string, GraphNode>; onSelectNode: (id: string) => void }) {
  return <>
    <span className="attack-graph-detail-kicker">关系详情</span>
    <h4>{relationLabel(edge.relation)}</h4>
    <dl>
      <Detail label="关系 ID" value={edge.id} />
      <Detail label="关系类型" value={`${relationLabel(edge.relation)}（${edge.relation}）`} />
      <Detail label="关系置信度" value={`${Math.round(edge.confidence * 100)}%`} />
      <Detail label="时间" value={compactTime(edge.timestamp)} hint={edge.timestamp ?? undefined} />
      <Detail label="ATT&CK 技术" value={edge.technique_id ?? "未标注"} />
    </dl>
    <div className="attack-graph-endpoints">
      {(["source", "target"] as const).map((key) => <div key={key}>
        <span>{key === "source" ? "起点" : "终点"}</span>
        {nodesById.has(edge[key])
          ? <button type="button" onClick={() => onSelectNode(edge[key])}>{nodesById.get(edge[key])?.label}</button>
          : <strong>节点缺失</strong>}
        <code>{edge[key]}</code>
      </div>)}
    </div>
    <EvidenceIds title="事件证据" ids={edge.evidence_event_ids} />
    <EvidenceIds title="告警证据" ids={edge.evidence_alert_ids} />
    <Attributes attributes={edge.attributes} />
  </>;
}

function Detail({ label, value, hint }: { label: string; value: unknown; hint?: string }) {
  const text = value === null || value === undefined || value === ""
    ? "未提供"
    : typeof value === "object"
      ? JSON.stringify(value, null, 2)
      : String(value);
  return <div><dt>{label}</dt><dd title={hint}>{text}</dd></div>;
}

function Attributes({ attributes }: { attributes: Record<string, unknown> }) {
  const entries = Object.entries(attributes ?? {});
  if (!entries.length) return <><h5>完整属性</h5><p className="attack-graph-muted">无附加属性</p></>;
  return <><h5>完整属性</h5><dl>{entries.map(([key, value]) => <Detail key={key} label={attributeLabel(key)} value={value} hint={key} />)}</dl></>;
}

const ATTRIBUTE_LABELS: Record<string, string> = {
  kind: "属性种类",
  event_id: "事件 ID",
  timestamp: "时间",
  alert_ids: "关联告警",
  technique_ids: "ATT&CK 技术",
  action: "行为",
  ip: "IP 地址",
  host_id: "主机",
  pid: "进程号",
  ppid: "父进程号",
  identity_resolved: "进程身份已解析",
  zone: "区域",
  role: "角色",
  event_observations: "事件观测",
  observations: "多条观测",
  reasons: "关联依据",
  time_delta_seconds: "时间差（秒）",
  relation: "关系",
  confidence: "置信度",
  first_seen: "首次出现",
  last_seen: "最后出现",
  connected_hosts: "关联主机",
  domains: "关联域名",
  risk_score: "风险分",
  tactic: "战术",
};

function attributeLabel(key: string) {
  return ATTRIBUTE_LABELS[key] ?? key;
}

function EvidenceIds({ title, ids }: { title: string; ids: string[] }) {
  return <section className="attack-graph-evidence"><h5>{title} · {ids.length}</h5>{ids.length
    ? <ul>{ids.map((id, index) => <li key={`${id}:${index}`}><code>{id}</code></li>)}</ul>
    : <p>未提供{title}</p>}</section>;
}
