import type { Core, ElementDefinition, LayoutOptions, StylesheetJson } from "cytoscape";
import type { AttackGraph, GraphEdge, GraphNode } from "../types/contracts";
import { formatNodeDisplay } from "./node-display.ts";

export type GraphLayout = "cose" | "dagre";
export type GraphSelection = { kind: "node" | "edge"; id: string } | null;

export const nodeElementId = (id: string) => `node:${id}`;
export const edgeElementId = (id: string) => `edge:${id}`;

export const nodeColors: Record<GraphNode["type"], string> = {
  host: "#2de1c2", user: "#87d8cf", process: "#b59cff", file: "#80aff3",
  ip: "#ffbf60", domain: "#f3c589", session: "#82c9e5", c2: "#ff9775",
  technique: "#e1a0da", other: "#a0b4c9",
};

function compactLabel(label: string, maxLines = 2) {
  const characters = Array.from(label.replace(/\s+/g, " "));
  const lines: string[] = [];
  let offset = 0;
  for (let line = 0; line < maxLines && offset < characters.length; line += 1) {
    let width = 0;
    let text = "";
    while (offset < characters.length) {
      const character = characters[offset];
      const nextWidth = (character.codePointAt(0) ?? 0) > 255 ? 2 : 1;
      if (width + nextWidth > 18) break;
      text += character;
      width += nextWidth;
      offset += 1;
    }
    if (line === maxLines - 1 && offset < characters.length) text = `${Array.from(text).slice(0, -1).join("")}…`;
    lines.push(text);
  }
  return lines.join("\n");
}

/** Contract IDs stay untouched; only renderer IDs get separate namespaces. */
export function createGraphElements(graph: AttackGraph): { elements: ElementDefinition[]; unresolvedEdges: GraphEdge[] } {
  const nodeIds = new Set(graph.nodes.map((node) => node.id));
  const radius = Math.max(160, Math.sqrt(graph.nodes.length) * 80);
  const elements: ElementDefinition[] = graph.nodes.map((node, index) => {
    const angle = index * Math.PI * 2 / Math.max(graph.nodes.length, 1);
    const display = formatNodeDisplay(node);
    const typeLine = `[${display.typeLabel}]${display.port !== null ? ` :${display.port}` : ""}${display.protocol ? ` ${display.protocol}` : ""}`;
    return {
      group: "nodes",
      data: { id: nodeElementId(node.id), contractId: node.id, label: `${compactLabel(display.address ?? display.title)}\n${compactLabel(typeLine, 1)}`, color: nodeColors[node.type] },
      position: { x: radius * Math.cos(angle), y: radius * Math.sin(angle) },
    };
  });
  const unresolvedEdges: GraphEdge[] = [];
  const loopCounts = new Map<string, number>();
  // Parallel edges between the same ordered pair would otherwise be drawn on top
  // of each other with identical control points.
  const parallelCounts = new Map<string, number>();
  for (const edge of graph.edges) {
    if (!nodeIds.has(edge.source) || !nodeIds.has(edge.target)) {
      unresolvedEdges.push(edge);
      continue;
    }
    const loopIndex = edge.source === edge.target ? (loopCounts.get(edge.source) ?? 0) : 0;
    if (edge.source === edge.target) loopCounts.set(edge.source, loopIndex + 1);
    const pairKey = `${edge.source}\u0000${edge.target}`;
    const parallelIndex = parallelCounts.get(pairKey) ?? 0;
    parallelCounts.set(pairKey, parallelIndex + 1);
    const curveDistance = parallelIndex === 0 ? 0 : 34 * Math.ceil(parallelIndex / 2) * (parallelIndex % 2 ? 1 : -1);
    elements.push({
      group: "edges",
      data: {
        id: edgeElementId(edge.id), contractId: edge.id,
        source: nodeElementId(edge.source), target: nodeElementId(edge.target),
        relation: edge.relation, loopDirection: `${-45 + loopIndex * 65}deg`,
        curveDistance,
      },
    });
  }
  return { elements, unresolvedEdges };
}

/** A fixed minimum zoom can clip a long chain even when Fit View is requested. */
export function fitMinimumZoom(viewWidth: number, viewHeight: number, boundsWidth: number, boundsHeight: number, padding = 42) {
  const scale = Math.min(Math.max(1, viewWidth - 2 * padding) / Math.max(1, boundsWidth), Math.max(1, viewHeight - 2 * padding) / Math.max(1, boundsHeight));
  return Math.max(0.000001, Math.min(0.08, scale * 0.9));
}

export function fitGraph(instance: Core) {
  if (!instance.nodes().length) return;
  instance.resize();
  const bounds = instance.elements().boundingBox();
  instance.minZoom(fitMinimumZoom(instance.width(), instance.height(), bounds.w, bounds.h));
  instance.fit(instance.elements(), 42);
}

export function graphLayoutOptions(name: GraphLayout): LayoutOptions {
  if (name === "dagre") {
    return {
      name: "dagre", rankDir: "LR", ranker: "network-simplex", nodeSep: 32,
      edgeSep: 24, rankSep: 96, nodeDimensionsIncludeLabels: true, fit: true,
      padding: 42, animate: false,
    } as LayoutOptions;
  }
  return {
    name: "cose", randomize: false, animate: false, fit: true, padding: 42,
    nodeDimensionsIncludeLabels: true, componentSpacing: 100,
    nodeRepulsion: () => 14000, nodeOverlap: 20, idealEdgeLength: () => 90,
    edgeElasticity: () => 90, gravity: 0.7, numIter: 1400,
    initialTemp: 200, coolingFactor: 0.97, minTemp: 0.5,
  };
}

/** Force layouts can leave rectangular cards touching around hubs; separate only colliding cards. */
export function runGraphLayout(instance: Core, name: GraphLayout) {
  instance.layout({ ...graphLayoutOptions(name), fit: false } as LayoutOptions).run();
  if (name === "cose") {
    const nodes = instance.nodes().toArray();
    const positions = nodes.map((node) => ({ ...node.position() }));
    const sizes = nodes.map((node) => ({ width: node.outerWidth() + 26, height: node.outerHeight() + 26 }));
    // Rotate the positions, not the cards, when a tall force layout wastes a wide viewport.
    // Do this before collision separation because the cards retain their original width and height.
    if (nodes.length > 1 && instance.width() > 84 && instance.height() > 84) {
      const minX = Math.min(...positions.map((point) => point.x));
      const maxX = Math.max(...positions.map((point) => point.x));
      const minY = Math.min(...positions.map((point) => point.y));
      const maxY = Math.max(...positions.map((point) => point.y));
      const cardWidth = Math.max(...sizes.map((size) => size.width));
      const cardHeight = Math.max(...sizes.map((size) => size.height));
      const availableWidth = instance.width() - 84;
      const availableHeight = instance.height() - 84;
      const normalScale = Math.min(availableWidth / (maxX - minX + cardWidth), availableHeight / (maxY - minY + cardHeight));
      const rotatedScale = Math.min(availableWidth / (maxY - minY + cardWidth), availableHeight / (maxX - minX + cardHeight));
      if (rotatedScale > normalScale * 1.1) {
        const centerX = (minX + maxX) / 2;
        const centerY = (minY + maxY) / 2;
        for (const point of positions) {
          const x = point.x - centerX;
          point.x = centerX - (point.y - centerY);
          point.y = centerY + x;
        }
      }
    }
    for (let pass = 0; pass < 200; pass += 1) {
      let collisions = 0;
      for (let left = 0; left < nodes.length; left += 1) {
        for (let right = left + 1; right < nodes.length; right += 1) {
          const dx = positions[right].x - positions[left].x;
          const dy = positions[right].y - positions[left].y;
          const overlapX = (sizes[left].width + sizes[right].width) / 2 - Math.abs(dx);
          const overlapY = (sizes[left].height + sizes[right].height) / 2 - Math.abs(dy);
          if (overlapX <= 0 || overlapY <= 0) continue;
          collisions += 1;
          if (overlapX < overlapY) {
            const shift = (overlapX / 2 + 0.5) * (dx < 0 ? -1 : 1);
            positions[left].x -= shift;
            positions[right].x += shift;
          } else {
            const shift = (overlapY / 2 + 0.5) * (dy < 0 ? -1 : 1);
            positions[left].y -= shift;
            positions[right].y += shift;
          }
        }
      }
      if (collisions === 0) break;
    }
    instance.batch(() => nodes.forEach((node, index) => node.position(positions[index])));
  }
  fitGraph(instance);
}

export const graphStyles: StylesheetJson = [
  { selector: "node", style: {
    "shape": "round-rectangle", "width": 142, "height": 62,
    "background-color": "#102438", "border-color": "data(color)", "border-width": 1.8,
    "label": "data(label)", "color": "#dce9f7", "font-size": 12,
    "font-family": "system-ui, sans-serif", "text-wrap": "wrap", "text-max-width": "128px",
    "text-valign": "center", "text-halign": "center", "line-height": 1.35,
    "overlay-padding": 7, "overlay-opacity": 0,
  } },
  { selector: "edge", style: {
    "curve-style": "bezier", "control-point-step-size": 54,
    "control-point-distances": "data(curveDistance)", "control-point-weights": 0.5,
    "loop-direction": "data(loopDirection)", "loop-sweep": "-75deg",
    "width": 1.5, "line-color": "#6685a3", "target-arrow-color": "#88a7c6",
    "target-arrow-shape": "triangle", "arrow-scale": 1.1, "opacity": 0.72,
    "label": "", "font-size": 11, "color": "#e4eefb", "text-rotation": "autorotate",
    "text-background-color": "#0a1727", "text-background-opacity": 0.95,
    "text-background-padding": "4px", "text-border-color": "#42607c", "text-border-width": 1,
    "text-border-opacity": 0.8, "text-margin-y": -8,
    "text-events": "yes", "overlay-padding": 9,
  } },
  { selector: "edge.show-relation, edge.hovered, edge:selected", style: { "label": "data(relation)" } },
  { selector: "edge.hovered, edge:selected", style: {
    "line-color": "#6cf7d8", "target-arrow-color": "#6cf7d8", "width": 3,
    "opacity": 1, "z-index": 20, "text-border-color": "#50c9b4",
  } },
  { selector: "node:selected", style: {
    "border-width": 3.5, "background-color": "#17384a", "overlay-color": "#2de1c2", "overlay-opacity": 0.08,
  } },
  { selector: ".neighbor", style: { "border-width": 3 } },
];
