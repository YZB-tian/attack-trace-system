export const API = {
  health: "/api/health",
  events: "/api/events",
  alerts: "/api/alerts",
  attackGraph: (taskId: string) => `/api/attack-graph/${taskId}`,
  trace: (taskId: string) => `/api/trace/${taskId}`,
  task: (taskId: string) => `/api/tasks/${taskId}`,
} as const;
