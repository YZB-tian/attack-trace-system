import type { NormalizedEvent } from "../types/contracts";

export function eventSourceLabel(value: NormalizedEvent["source_type"]) {
  return { host_log: "主机日志", host_behavior: "主机行为", network_flow: "网络流量", boundary_log: "边界日志" }[value] ?? value;
}

export function dataTime(value?: string | null) {
  if (!value) return "未提供";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  }).format(date);
}

export function endpointLabel(ip?: string | null, port?: number | null) {
  const address = ip || "地址未提供";
  if (port == null) return address;
  return `${ip?.includes(":") ? `[${address}]` : address}:${port}`;
}

export function detailValue(value: unknown): string {
  if (value === undefined) return "未提供";
  if (typeof value === "string") return value || "（空字符串）";
  return JSON.stringify(value, null, 2) ?? String(value);
}

export interface EvidenceField {
  key: string;
  label: string;
  value: string;
}

export interface ParsedEvidence {
  original: string;
  structured: boolean;
  heuristic: boolean;
  fields: EvidenceField[];
  otherFields: EvidenceField[];
}

const evidenceLabels = {
  sample_count: "样本数",
  span: "持续时间",
  median_interval: "中位间隔",
  regularity: "规律度",
  stable_size: "大小稳定",
  score_kind: "评分类型",
};

function evidenceValue(key: string, value: unknown) {
  if ((key === "span" || key === "median_interval") && typeof value === "number" && Number.isFinite(value)) return `${value} s`;
  if (key === "regularity" && typeof value === "number" && Number.isFinite(value)) return value.toFixed(2);
  if (key === "stable_size" && typeof value === "boolean") return value ? "是" : "否";
  if (key === "score_kind" && value === "heuristic_not_probability") return "启发式评分（非概率）";
  return detailValue(value);
}

export function parseEvidenceSummary(original: string): ParsedEvidence {
  const result: ParsedEvidence = { original, structured: false, heuristic: false, fields: [], otherFields: [] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(original);
  } catch {
    return result;
  }
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") return result;
  const record = parsed as Record<string, unknown>;
  result.structured = true;
  result.heuristic = record.score_kind === "heuristic_not_probability";
  for (const [key, label] of Object.entries(evidenceLabels)) {
    if (Object.prototype.hasOwnProperty.call(record, key)) result.fields.push({ key, label, value: evidenceValue(key, record[key]) });
  }
  for (const [key, value] of Object.entries(record)) {
    if (!Object.prototype.hasOwnProperty.call(evidenceLabels, key)) result.otherFields.push({ key, label: key, value: detailValue(value) });
  }
  return result;
}
