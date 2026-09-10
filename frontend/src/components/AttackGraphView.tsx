import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import cytoscape from "cytoscape";
import type { Core, EventObject } from "cytoscape";
import dagre from "cytoscape-dagre";
import { Expand, Focus, GitBranch, Minus, Plus, RotateCcw, X } from "lucide-react";
import type { AttackGraph, GraphEdge, GraphNode } from "../types/contracts";
import { createGraphElements, edgeElementId, fitGraph, graphStyles, nodeColors, nodeElementId, runGraphLayout } from "./graphModel";
import type { GraphLayout, GraphSelection } from "./graphModel";
import "./graph.css";

cytoscape.use(dagre);

export default function AttackGraphView({ graph }: { graph: AttackGraph }) {
  const canvasRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<Core | null>(null);
  const [selection, setSelection] = useState<GraphSelection>(null);
  const [layout, setLayout] = useState<GraphLayout>("cose");
  const [allRelations, setAllRelations] = useState(false);
  const [zoom, setZoom] = useState(100);
  const [expanded, setExpanded] = useState(false);
  const hintId = useId();
  const model = useMemo(() => createGraphElements(graph), [graph]);
  const nodesById = useMemo(() => new Map(graph.nodes.map((node) => [node.id, node])), [graph.nodes]);
  const selectedNode = selection?.kind === "node" ? nodesById.get(selection.id) : undefined;
  const selectedEdge = selection?.kind === "edge" ? graph.edges.find((edge) => edge.id === selection.id) : undefined;

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
    if (!canvasRef.current || !graph.nodes.length) return;
    const instance = cytoscape({
      container: canvasRef.current, elements: model.elements, style: graphStyles,
      layout: { name: "preset" }, minZoom: 0.08, maxZoom: 3,
      wheelSensitivity: 0.2, selectionType: "single", boxSelectionEnabled: false,
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
  }, [model, graph.nodes.length, chooseElement]);

  useEffect(() => {
    if (graphRef.current) runGraphLayout(graphRef.current, layout);
  }, [model, layout]);

  useEffect(() => {
    graphRef.current?.edges().toggleClass("show-relation", allRelations);
  }, [model, allRelations]);

  useEffect(() => {
    const frame = requestAnimationFrame(fitView);
    return () => cancelAnimationFrame(frame);
  }, [expanded, fitView]);

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

  return <section className={`attack-graph-view ${expanded ? "is-expanded" : ""}`} aria-label="交互攻击图" onKeyDown={(event) => { if (event.key === "Escape" && expanded) setExpanded(false); }}>
    <div className="attack-graph-toolbar">
      <div className="attack-graph-controls" role="group" aria-label="画布控制">
        <button type="button" onClick={() => changeZoom(1.25)} aria-label="放大攻击图" title="放大"><Plus size={16} /></button>
        <output aria-label="当前缩放比例">{zoom}%</output>
        <button type="button" onClick={() => changeZoom(0.8)} aria-label="缩小攻击图" title="缩小"><Minus size={16} /></button>
        <button type="button" onClick={fitView}><Focus size={15} />Fit View</button>
        <button type="button" onClick={() => { if (graphRef.current) runGraphLayout(graphRef.current, layout); }}><RotateCcw size={14} />重新布局</button>
        <button type="button" onClick={() => setExpanded((value) => !value)} aria-pressed={expanded}><Expand size={14} />{expanded ? "收起画布" : "展开画布"}</button>
      </div>
      <label className="attack-graph-layout-picker">布局<select aria-label="攻击图布局" value={layout} onChange={(event) => setLayout(event.target.value === "dagre" ? "dagre" : "cose")}><option value="cose">结构布局</option><option value="dagre">分层布局</option></select></label>
      <label className="attack-graph-label-toggle"><input type="checkbox" checked={allRelations} onChange={(event) => setAllRelations(event.target.checked)} />显示全部关系标签</label>
    </div>
    <p id={hintId} className="attack-graph-hint">滚轮缩放，拖动空白处平移，拖动节点调整位置。关系标签在悬停或选中时显示；所有关系始终保留。键盘可用下方选择器，画布内方向键平移，+ / − 缩放，0 适配全图。</p>
    <div className="attack-graph-selectors">
      <label>节点<select aria-label="选择图节点" value={selectedNode?.id ?? ""} onChange={(event) => chooseElement(event.target.value ? { kind: "node", id: event.target.value } : null, true)}><option value="">选择节点查看属性（{graph.nodes.length}）</option>{graph.nodes.map((node) => <option key={node.id} value={node.id}>{node.label} · {node.type} · {node.id}</option>)}</select></label>
      <label>关系<select aria-label="选择图关系" value={selectedEdge?.id ?? ""} onChange={(event) => chooseElement(event.target.value ? { kind: "edge", id: event.target.value } : null, true)}><option value="">选择关系查看证据（{graph.edges.length}）</option>{graph.edges.map((edge) => <option key={edge.id} value={edge.id}>{nodesById.get(edge.source)?.label ?? edge.source} 到 {nodesById.get(edge.target)?.label ?? edge.target} · {edge.relation} · {edge.id}</option>)}</select></label>
    </div>
    {model.unresolvedEdges.length > 0 && <p className="attack-graph-warning" role="status">{model.unresolvedEdges.length} 条关系引用的节点缺失，无法绘制。全部关系仍可在选择器查看证据。</p>}
    <div className="attack-graph-body">
      <div className="attack-graph-stage">
        {graph.nodes.length ? <div ref={canvasRef} className="attack-graph-canvas" tabIndex={0} role="region" aria-label={`攻击关系图，${graph.nodes.length} 个节点，${graph.edges.length} 条关系`} aria-describedby={hintId} onKeyDown={handleCanvasKey} /> : <div className="attack-graph-empty"><GitBranch size={24} /><strong>暂无攻击图节点</strong><span>当前任务返回空图</span></div>}
        <div className="attack-graph-legend">{[...new Set(graph.nodes.map((node) => node.type))].map((type) => <span key={type}><i style={{ backgroundColor: nodeColors[type] }} />{type}</span>)}</div>
      </div>
      <aside className="attack-graph-inspector" aria-label="图元素详情" aria-live="polite">
        {(selectedNode || selectedEdge) && <button className="attack-graph-close" type="button" aria-label="关闭图元素详情" onClick={() => chooseElement(null)}><X size={16} /></button>}
        {selectedNode ? <NodeDetails node={selectedNode} edges={graph.edges.filter((edge) => edge.source === selectedNode.id || edge.target === selectedNode.id)} onSelectEdge={(id) => chooseElement({ kind: "edge", id }, true)} /> : selectedEdge ? <EdgeDetails edge={selectedEdge} nodesById={nodesById} onSelectNode={(id) => chooseElement({ kind: "node", id }, true)} /> : <div className="attack-graph-empty"><GitBranch size={22} /><strong>查看节点或关系</strong><span>点击节点查看完整属性；点击连线查看关系和证据。也可用上方选择器定位。</span></div>}
      </aside>
    </div>
  </section>;
}

function NodeDetails({ node, edges, onSelectEdge }: { node: GraphNode; edges: GraphEdge[]; onSelectEdge: (id: string) => void }) {
  return <><span className="attack-graph-detail-kicker">节点详情 · {node.type}</span><h4>{node.label}</h4><dl><Detail label="节点 ID" value={node.id} /><Detail label="节点类型" value={node.type} /></dl><Attributes attributes={node.attributes} /><h5>关联关系 · {edges.length}</h5><div className="attack-graph-related">{edges.length ? edges.map((edge) => <button type="button" key={edge.id} onClick={() => onSelectEdge(edge.id)}><strong>{edge.relation}</strong><span>{edge.source} 到 {edge.target}</span><small>{edge.id}</small></button>) : <p>没有关联关系</p>}</div></>;
}

function EdgeDetails({ edge, nodesById, onSelectNode }: { edge: GraphEdge; nodesById: Map<string, GraphNode>; onSelectNode: (id: string) => void }) {
  return <><span className="attack-graph-detail-kicker">关系详情</span><h4>{edge.relation}</h4><dl><Detail label="关系 ID" value={edge.id} /><Detail label="关系类型" value={edge.relation} /><Detail label="关系置信度" value={`${Math.round(edge.confidence * 100)}%`} /><Detail label="时间" value={edge.timestamp} /><Detail label="ATT&CK 技术" value={edge.technique_id} /></dl><div className="attack-graph-endpoints">{(["source", "target"] as const).map((key) => <div key={key}><span>{key === "source" ? "起点" : "终点"}</span>{nodesById.has(edge[key]) ? <button type="button" onClick={() => onSelectNode(edge[key])}>{nodesById.get(edge[key])?.label}</button> : <strong>节点缺失</strong>}<code>{edge[key]}</code></div>)}</div><EvidenceIds title="事件证据" ids={edge.evidence_event_ids} /><EvidenceIds title="告警证据" ids={edge.evidence_alert_ids} /><Attributes attributes={edge.attributes} /></>;
}

function Detail({ label, value }: { label: string; value: unknown }) {
  const text = value === null || value === undefined ? "未提供" : typeof value === "object" ? JSON.stringify(value, null, 2) : String(value);
  return <div><dt>{label}</dt><dd>{text}</dd></div>;
}

function Attributes({ attributes }: { attributes: Record<string, unknown> }) {
  return <><h5>完整属性</h5>{Object.keys(attributes).length ? <dl>{Object.entries(attributes).map(([key, value]) => <Detail key={key} label={key} value={value} />)}</dl> : <p className="attack-graph-muted">无附加属性</p>}</>;
}

function EvidenceIds({ title, ids }: { title: string; ids: string[] }) {
  return <section className="attack-graph-evidence"><h5>{title} · {ids.length}</h5>{ids.length ? <ul>{ids.map((id, index) => <li key={`${id}:${index}`}><code>{id}</code></li>)}</ul> : <p>未提供{title}</p>}</section>;
}
