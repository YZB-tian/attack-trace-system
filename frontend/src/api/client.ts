import { API } from "../api/endpoints";
import type {
  Alert,
  AttackGraph,
  NormalizedEvent,
  TaskStatus,
} from "../types/contracts";
import type { TraceResult } from "../types/trace";

interface ApiEnvelope<T> {
  code: number;
  message: string;
  data: T;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: "application/json", ...(init?.headers ?? {}) },
  });
  let payload: ApiEnvelope<T> | { detail?: string };
  try {
    payload = (await response.json()) as ApiEnvelope<T> | { detail?: string };
  } catch {
    throw new Error(`API 返回无效 JSON（${response.status}）`);
  }
  if (!response.ok) {
    const detail = "detail" in payload ? payload.detail : undefined;
    throw new Error(detail ?? `API 请求失败（${response.status}）`);
  }
  if (!("data" in payload) || payload.code !== 0) {
    throw new Error("API 返回错误");
  }
  return payload.data;
}

export const client = {
  health: () => request<{ status: string }>(API.health),
  events: () => request<NormalizedEvent[]>(API.events),
  ingestEvents: (events: NormalizedEvent[]) => request<{ accepted: number; total: number }>(API.events, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(events),
  }),
  alerts: () => request<Alert[]>(API.alerts),
  graph: (taskId: string) => request<AttackGraph>(API.attackGraph(taskId)),
  trace: (taskId: string) => request<TraceResult>(API.trace(taskId)),
  task: (taskId: string) => request<TaskStatus>(API.task(taskId)),
};
