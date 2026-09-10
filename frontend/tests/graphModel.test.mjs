import assert from "node:assert/strict";
import test from "node:test";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import { createGraphElements, edgeElementId, fitMinimumZoom, graphStyles, nodeElementId, runGraphLayout } from "../src/components/graphModel.ts";

cytoscape.use(dagre);

// Explicitly synthetic stress data; never used as a backend task or production fallback.
function stressGraph(count) {
  const nodes = Array.from({ length: count }, (_, index) => ({
    id: `synthetic_node_${index}`, type: index === 0 ? "host" : "process",
    label: index === 0 ? "Synthetic hub" : `Synthetic process ${index}`, attributes: {},
  }));
  const edges = [];
  const add = (source, target, relation = "network_connect") => edges.push({
    id: `edge_synthetic_${edges.length}`, source: nodes[source].id, target: nodes[target].id,
    relation, confidence: 0.5, attributes: { synthetic: true },
    evidence_event_ids: [`evt_synthetic_${edges.length}`], evidence_alert_ids: [],
  });
  for (let index = 1; index < count; index += 1) add(0, index);
  for (let index = 1; index < count - 1; index += 1) add(index, index + 1, "process_spawn");
  add(0, 1, "related_to");
  add(1, 0, "related_to");
  add(0, 0, "related_to");
  add(0, 0, "file_access");
  add(count - 1, 1, "related_to");
  return { schema_version: "1.0", graph_id: "graph_synthetic_stress", task_id: `task_synthetic_stress_${count}`, generated_at: "2026-09-10T00:00:00+00:00", nodes, edges };
}

test("renderer conversion preserves every parallel, reverse, and self-loop edge without changing evidence", () => {
  const graph = stressGraph(14);
  const before = JSON.stringify(graph);
  const model = createGraphElements(graph);
  assert.equal(graph.edges.length, 30);
  assert.equal(model.elements.filter((element) => element.group === "nodes").length, 14);
  assert.equal(model.elements.filter((element) => element.group === "edges").length, 30);
  assert.equal(model.unresolvedEdges.length, 0);
  assert.equal(new Set(model.elements.map((element) => element.data.id)).size, 44);
  const loops = model.elements.filter((element) => element.group === "edges" && element.data.source === element.data.target);
  assert.equal(new Set(loops.map((element) => element.data.loopDirection)).size, 2);
  assert.equal(JSON.stringify(graph), before);
});

test("node and edge contract IDs cannot collide in the renderer; dangling edges remain available for inspection", () => {
  const graph = stressGraph(2);
  graph.nodes[0].id = graph.edges[0].id;
  graph.edges[0].source = graph.nodes[0].id;
  const model = createGraphElements(graph);
  assert.notEqual(nodeElementId(graph.nodes[0].id), edgeElementId(graph.edges[0].id));
  assert.ok(model.elements.some((element) => element.data.id === nodeElementId(graph.nodes[0].id)));
  assert.ok(model.elements.some((element) => element.data.id === edgeElementId(graph.edges[0].id)));
  assert.equal(model.elements.filter((element) => element.group === "edges").length + model.unresolvedEdges.length, graph.edges.length);
  assert.ok(model.unresolvedEdges.every((edge) => graph.edges.includes(edge)));
});

test("long CJK labels stay within two display lines plus type while original labels stay intact", () => {
  const graph = stressGraph(2);
  const label = "这是一段很长的中文网络连接节点标签用于确认图中的标签不会溢出卡片";
  graph.nodes[0].label = label;
  const model = createGraphElements(graph);
  const displayed = model.elements[0].data.label;
  assert.equal(displayed.split("\n").length, 3);
  assert.ok(displayed.includes("…"));
  assert.equal(graph.nodes[0].label, label);
});

for (const count of [20, 50]) {
  test(`Fit View permits the zoom required by a ${count}-node linear chain on narrow and wide canvases`, () => {
    const graph = stressGraph(count);
    graph.edges = graph.nodes.slice(1).map((node, index) => ({ ...graph.edges[index], source: graph.nodes[index].id, target: node.id }));
    const instance = cytoscape({ headless: true, styleEnabled: true, elements: createGraphElements(graph).elements, style: graphStyles, layout: { name: "preset" } });
    try {
      runGraphLayout(instance, "dagre");
      const bounds = instance.elements().boundingBox();
      for (const width of [280, 600, 1200]) {
        const needed = Math.min((width - 84) / bounds.w, (600 - 84) / bounds.h);
        const minimum = fitMinimumZoom(width, 600, bounds.w, bounds.h);
        assert.ok(minimum > 0 && Number.isFinite(minimum));
        assert.ok(minimum < needed, `minimum ${minimum} must allow fit ${needed} at width ${width}`);
        if (width === 280) assert.ok(minimum < 0.08, "long narrow chains must be able to zoom below the old hard limit");
      }
    } finally { instance.destroy(); }
  });
}

for (const count of [14, 20, 50]) {
  for (const layout of ["cose", "dagre"]) {
    test(`${layout} lays out ${count} synthetic hub nodes without node overlap or lost edges`, () => {
      const graph = stressGraph(count);
      const model = createGraphElements(graph);
      const instance = cytoscape({ headless: true, styleEnabled: true, elements: model.elements, style: graphStyles, layout: { name: "preset" } });
      try {
        runGraphLayout(instance, layout);
        assert.equal(instance.nodes().length, count);
        assert.equal(instance.edges().length, graph.edges.length);
        const nodes = instance.nodes().toArray();
        for (let index = 0; index < nodes.length; index += 1) {
          const point = nodes[index].position();
          assert.ok(Number.isFinite(point.x) && Number.isFinite(point.y));
          const bounds = nodes[index].boundingBox({ includeLabels: false, includeOverlays: false });
          for (let next = index + 1; next < nodes.length; next += 1) {
            const other = nodes[next].boundingBox({ includeLabels: false, includeOverlays: false });
            const overlap = Math.min(bounds.x2, other.x2) - Math.max(bounds.x1, other.x1) > 1 && Math.min(bounds.y2, other.y2) - Math.max(bounds.y1, other.y1) > 1;
            assert.equal(overlap, false, `overlap: ${nodes[index].id()} and ${nodes[next].id()}`);
          }
        }
      } finally {
        instance.destroy();
      }
    });
  }
}
