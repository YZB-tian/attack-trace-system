import assert from "node:assert/strict";
import test from "node:test";
import { formatNodeDisplay } from "../src/components/node-display.ts";
import { createGraphElements } from "../src/components/graphModel.ts";

const node = (type = "c2", label = "198.51.100.20", attributes = {}) => ({ id: `node_${type}`, type, label, attributes });

test("IP and C2 entities at the same address have distinct type, endpoint, and candidate metadata", () => {
  const ip = formatNodeDisplay(node("ip"));
  const c2 = formatNodeDisplay(node("c2", "198.51.100.20", { ip: "198.51.100.20", port: 443, protocol: "tcp", status: "candidate" }));
  assert.equal(ip.title, "198.51.100.20");
  assert.equal(ip.fullLabel, "[IP] 198.51.100.20 · IP 地址实体");
  assert.equal(c2.title, "198.51.100.20:443");
  assert.equal(c2.fullLabel, "[C2] 198.51.100.20:443 · 候选 C2 · TCP");
});

test("port zero and numeric metadata strings remain valid; protocol is displayed consistently", () => {
  const display = formatNodeDisplay(node("c2", "198.51.100.20", { ip: "198.51.100.20", port: 0, protocol: " udp " }));
  assert.equal(display.title, "198.51.100.20:0");
  assert.equal(display.protocol, "UDP");
  assert.equal(formatNodeDisplay(node("c2", "198.51.100.20", { port: "00443" })).port, "443");
});

test("existing IPv4 and bracketed IPv6 endpoint labels never receive a duplicate port", () => {
  assert.equal(formatNodeDisplay(node("c2", "198.51.100.20:443", { port: 443 })).title, "198.51.100.20:443");
  assert.equal(formatNodeDisplay(node("c2", "[2001:db8::20]:443", { port: 443 })).title, "[2001:db8::20]:443");
  assert.equal(formatNodeDisplay(node("c2", "ignored", { ip: "[2001:db8::20]:443", port: 443 })).title, "[2001:db8::20]:443");
});

test("IPv6 ports use brackets; an unbracketed suffix is never guessed to be a port", () => {
  assert.equal(formatNodeDisplay(node("c2", "2001:db8::20", { port: 443 })).title, "[2001:db8::20]:443");
  const withoutPort = formatNodeDisplay(node("c2", "2001:db8::443"));
  assert.equal(withoutPort.title, "2001:db8::443");
  assert.equal(withoutPort.port, null);
  assert.match(withoutPort.summary, /端口未提供/);
  assert.equal(formatNodeDisplay(node("c2", "fe80::20%en0", { port: 0 })).title, "[fe80::20%en0]:0");
});

test("missing or invalid attributes remain explicit and never stringify objects into an endpoint", () => {
  for (const port of [null, undefined, false, -1, 65536, "443tcp", Number.NaN, 4.5]) {
    const display = formatNodeDisplay(node("c2", "198.51.100.20", { ip: {}, port, protocol: [] }));
    assert.equal(display.title, "198.51.100.20");
    assert.equal(display.port, null);
    assert.equal(display.summary, "C2 实体 · 端口未提供 · 协议未提供");
  }
});

test("structured endpoint attributes take precedence over a legacy label without changing the input", () => {
  const original = node("c2", "Legacy label 198.51.100.20:80", { ip: "198.51.100.20", port: 443, protocol: "tcp", status: "candidate" });
  const before = JSON.stringify(original);
  assert.equal(formatNodeDisplay(original).title, "198.51.100.20:443");
  assert.equal(JSON.stringify(original), before);
});

test("long custom labels remain complete and empty labels fall back to the stable node ID", () => {
  const label = "这是保留完整含义的长候选节点标签".repeat(12);
  const display = formatNodeDisplay(node("c2", label, { port: 443, protocol: "tcp" }));
  assert.equal(display.title, label);
  assert.equal(display.address, null);
  assert.match(display.summary, /端口 443/);
  assert.equal(formatNodeDisplay(node("host", "  ")).title, "node_host");
});

test("canvas labels preserve C2 type, port and protocol even when a long IPv6 address is abbreviated", () => {
  const graph = { nodes: [node("ip"), node("c2", "2001:db8:1234:5678:90ab:cdef:1234:5678", { port: 443, protocol: "tcp" })], edges: [] };
  const elements = createGraphElements(graph).elements;
  assert.match(elements[0].data.label, /\[IP\]/);
  assert.match(elements[1].data.label, /\[C2\] :443 TCP/);
  assert.equal(elements[1].data.label.split("\n").length, 3);
});
