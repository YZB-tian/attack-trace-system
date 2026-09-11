import type { GraphNode } from "../types/contracts";

export interface NodeDisplay {
  typeLabel: string;
  title: string;
  address: string | null;
  port: string | null;
  protocol: string | null;
  summary: string;
  fullLabel: string;
}

function nonemptyText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function portText(value: unknown): string | null {
  if (typeof value !== "number" && (typeof value !== "string" || !/^\d+$/.test(value.trim()))) return null;
  const number = typeof value === "number" ? value : Number(value.trim());
  return Number.isInteger(number) && number >= 0 && number <= 65535 ? String(number) : null;
}

function splitEndpoint(value: string): { address: string; port: string | null } {
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
  if (bracketed) return { address: bracketed[1], port: portText(bracketed[2]) };
  // An unbracketed IPv6 suffix is part of the address, never an inferred port.
  const singleColon = /^([^:\s]+):(\d+)$/.exec(value);
  if (singleColon && portText(singleColon[2]) !== null) return { address: singleColon[1], port: portText(singleColon[2]) };
  return { address: value, port: null };
}

function addressFromLabel(label: string): string | null {
  if (/^\[[^\]]+\](?::\d+)?$/.test(label)) return label;
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(label)) return label;
  if (label.includes(":") && /^[\da-fA-F:.]+(?:%[\w.-]+)?$/.test(label)) return label;
  return null;
}

export function formatNodeDisplay(node: GraphNode): NodeDisplay {
  const typeLabel = node.type.toUpperCase();
  const originalLabel = nonemptyText(node.label) ?? nonemptyText(node.id) ?? "未命名实体";
  const networkEntity = node.type === "ip" || node.type === "c2";
  const source = networkEntity ? nonemptyText(node.attributes.ip) ?? addressFromLabel(originalLabel) : null;
  const parsed = source ? splitEndpoint(source) : null;
  const address = parsed?.address ?? null;
  const port = networkEntity ? portText(node.attributes.port) ?? parsed?.port ?? null : null;
  const protocol = networkEntity ? nonemptyText(node.attributes.protocol)?.toUpperCase() ?? null : null;
  const title = address ? port !== null ? `${address.includes(":") ? `[${address}]` : address}:${port}` : address : originalLabel;
  const details: string[] = [];
  if (node.type === "c2") {
    details.push(node.attributes.status === "candidate" ? "候选 C2" : "C2 实体");
    if (port === null) details.push("端口未提供");
    else if (!address) details.push(`端口 ${port}`);
    details.push(protocol ?? "协议未提供");
  } else if (node.type === "ip") {
    details.push("IP 地址实体");
    if (port !== null && !address) details.push(`端口 ${port}`);
    if (protocol) details.push(protocol);
  }
  const summary = details.join(" · ");
  return { typeLabel, title, address, port, protocol, summary, fullLabel: `[${typeLabel}] ${title}${summary ? ` · ${summary}` : ""}` };
}
