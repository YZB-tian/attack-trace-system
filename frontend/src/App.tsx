import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

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
  RefreshCw,
  Search,
  Shield,
} from "lucide-react";

import { client } from "./api/client";
import { selectTask } from "./task-selection";

import { EventsView } from "./components/EventsView";
import { AlertsView } from "./components/AlertsView";
import ChainPreview from "./components/ChainPreview";
import { parseEvidenceSummary } from "./components/data-panel-format";

import type {
  Alert,
  AttackGraph,
  NormalizedEvent,
  TaskStatus,
} from "./types/contracts";

import type { TraceResult } from "./types/trace";

const AttackGraphView = lazy(
  () => import("./components/AttackGraphView"),
);

const DEFAULT_TASK =
  new URLSearchParams(window.location.search).get("task") ?? "";

type LoadState<T> = {
  data: T | null;
  loading: boolean;
  error: string | null;
};

type Section =
  | "overview"
  | "events"
  | "alerts"
  | "graph"
  | "trace";

const emptyState = <T,>(): LoadState<T> => ({
  data: null,
  loading: true,
  error: null,
});

function useEndpoint<T>(
  loader: () => Promise<T>,
  dependencies: string[],
  enabled = true,
): LoadState<T> & { reload: () => void } {
  const [revision, setRevision] = useState(0);

  /*
   * requestKey 同时包含：
   * 1. 当前 task / query 输入
   * 2. 手动 reload revision
   * 3. endpoint 是否启用
   *
   * 这样可以避免旧任务的迟到响应覆盖新任务。
   */
  const requestKey = JSON.stringify([
    ...dependencies,
    revision,
    enabled,
  ]);

  const [state, setState] = useState<
    LoadState<T> & { requestKey: string }
  >(() => ({
    ...emptyState<T>(),
    requestKey,
  }));

  const reload = useCallback(() => {
    setRevision((value) => value + 1);
  }, []);

  useEffect(() => {
    let active = true;

    /*
     * task / graph / trace 在 taskId 为空时禁止请求，
     * 避免产生 /api/tasks/、/api/trace/ 之类的空任务请求。
     */
    if (!enabled) {
      setState({
        data: null,
        loading: false,
        error: null,
        requestKey,
      });

      return;
    }

    setState({
      data: null,
      loading: true,
      error: null,
      requestKey,
    });

    loader()
      .then((data) => {
        if (!active) return;

        setState({
          data,
          loading: false,
          error: null,
          requestKey,
        });
      })
      .catch((error: unknown) => {
        if (!active) return;

        setState({
          data: null,
          loading: false,
          error:
            error instanceof Error
              ? error.message
              : "请求失败",
          requestKey,
        });
      });

    return () => {
      /*
       * 新请求启动以后，旧请求即使后返回，
       * 也不能再写入 state。
       */
      active = false;
    };

    // requestKey 已包含 loader 的输入、reload revision 与 enabled。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestKey]);

  /*
   * React effect 尚未来得及运行时，
   * 不把上一个 task / revision 的旧数据暴露给界面。
   */
  return {
    ...(state.requestKey === requestKey
      ? state
      : emptyState<T>()),
    reload,
  };
}

function formatTime(value?: string | null) {
  if (!value) return "-";

  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function percent(value: number) {
  return `${Math.max(0, Math.min(100, value))}%`;
}

function confidence(value: number) {
  return `${Math.round(value * 100)}%`;
}

function statusLabel(status: TaskStatus["status"]) {
  return {
    pending: "等待中",
    running: "运行中",
    completed: "已完成",
    failed: "失败",
  }[status];
}

function severityLabel(value: Alert["severity"]) {
  return {
    info: "信息",
    low: "低",
    medium: "中",
    high: "高",
    critical: "严重",
  }[value];
}

function sourceLabel(
  value: NormalizedEvent["source_type"],
) {
  return {
    host_log: "主机日志",
    host_behavior: "主机行为",
    network_flow: "网络流量",
    boundary_log: "边界日志",
  }[value];
}

function EmptyState({
  icon: Icon = Database,
  title,
  detail,
}: {
  icon?: typeof Database;
  title: string;
  detail?: string;
}) {
  return (
    <div className="empty-state">
      <Icon size={22} />
      <strong>{title}</strong>
      {detail && <span>{detail}</span>}
    </div>
  );
}

function ErrorState({
  message,
  retry,
}: {
  message: string;
  retry?: () => void;
}) {
  return (
    <div className="error-state">
      <CircleX size={22} />

      <div>
        <strong>接口请求失败</strong>
        <span>{message}</span>
      </div>

      {retry && (
        <button
          className="icon-button"
          title="重试"
          onClick={retry}
        >
          <RefreshCw size={16} />
        </button>
      )}
    </div>
  );
}

function LoadingState() {
  return (
    <div className="loading-state">
      <LoaderCircle
        className="spin"
        size={22}
      />
      <span>正在读取分析数据…</span>
    </div>
  );
}

function App() {
  const [query, setQuery] = useState({
    taskId: DEFAULT_TASK,
    revision: 0,
  });

  const { taskId } = query;

  const [taskInput, setTaskInput] =
    useState(DEFAULT_TASK);

  const [section, setSection] =
    useState<Section>("overview");

  /*
   * health 与 task 无关。
   */
  const health = useEndpoint(
    client.health,
    [],
  );

  /*
   * revision 非常重要：
   * 即使用户重新查询相同 taskId，
   * 也要求 Events / Alerts / Task / Graph / Trace
   * 全部重新请求。
   */
  const queryDependencies = [
    taskId,
    String(query.revision),
  ];

  /*
   * Events / Alerts 必须跟随 query revision 更新，
   * 这是之前 P1 自动刷新问题的核心修复。
   */
  const events = useEndpoint(
    client.events,
    queryDependencies,
  );

  const alerts = useEndpoint(
    client.alerts,
    queryDependencies,
  );

  /*
   * 如果 URL 没有 task 参数，
   * 等 Events 返回后自动选择第一个真实 task。
   *
   * 不再回退到 task_demo_001。
   */
  useEffect(() => {
    const next = selectTask(
      taskId,
      events.data ?? [],
    );

    if (next !== taskId) {
      setTaskInput(next);

      setQuery((previous) => ({
        taskId: next,
        revision:
          previous.revision + 1,
      }));
    }
  }, [events.data, taskId]);

  /*
   * taskId 为空时禁止这三个 endpoint 请求。
   */
  const task = useEndpoint(
    () => client.task(taskId),
    queryDependencies,
    Boolean(taskId),
  );

  const graph = useEndpoint(
    () => client.graph(taskId),
    queryDependencies,
    Boolean(taskId),
  );

  const trace = useEndpoint(
    () => client.trace(taskId),
    queryDependencies,
    Boolean(taskId),
  );

  /*
   * 手动“刷新全部数据”仍然保留。
   *
   * 修改 query revision 会触发：
   * Events
   * Alerts
   * Task
   * Graph
   * Trace
   *
   * 全部重新请求。
   */
  const reloadAll = () => {
    health.reload();

    setQuery((previous) => ({
      ...previous,
      revision:
        previous.revision + 1,
    }));
  };

  const displayedEvents = useMemo(
    () =>
      (events.data ?? []).filter(
        (event) =>
          event.task_id === taskId,
      ),
    [events.data, taskId],
  );

  const displayedAlerts = useMemo(
    () =>
      (alerts.data ?? []).filter(
        (alert) =>
          alert.task_id === taskId,
      ),
    [alerts.data, taskId],
  );

  const chooseTask = (
    event: React.FormEvent,
  ) => {
    event.preventDefault();

    const next =
      taskInput.trim();

    if (!next) return;

    setTaskInput(next);

    /*
     * 即使 next 与当前 taskId 相同，
     * revision 仍然 +1。
     *
     * 因此重新查询相同任务也会刷新所有资源。
     */
    setQuery((previous) => ({
      taskId: next,
      revision:
        previous.revision + 1,
    }));

    setSection("overview");
  };

  const isControlledEmulation =
    displayedEvents.some(
      (event) =>
        event.metadata
          ?.classification ===
        "controlled_emulation",
    );

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={20} />
          </div>

          <div>
            <strong>Attack Trace</strong>
            <span>行为溯源分析台</span>
          </div>
        </div>

        <div className="side-caption">
          WORKSPACE
        </div>

        <nav
          className="nav-list"
          aria-label="主导航"
        >
          <NavItem
            icon={Activity}
            label="任务概览"
            active={
              section === "overview"
            }
            onClick={() =>
              setSection("overview")
            }
          />

          <NavItem
            icon={Database}
            label="事件流"
            count={
              events.loading ||
              events.error
                ? undefined
                : displayedEvents.length
            }
            active={
              section === "events"
            }
            onClick={() =>
              setSection("events")
            }
          />

          <NavItem
            icon={AlertTriangle}
            label="检测告警"
            count={
              alerts.loading ||
              alerts.error
                ? undefined
                : displayedAlerts.length
            }
            active={
              section === "alerts"
            }
            onClick={() =>
              setSection("alerts")
            }
          />

          <NavItem
            icon={GitBranch}
            label="攻击图"
            active={
              section === "graph"
            }
            onClick={() =>
              setSection("graph")
            }
          />

          <NavItem
            icon={Shield}
            label="溯源结果"
            active={
              section === "trace"
            }
            onClick={() =>
              setSection("trace")
            }
          />
        </nav>

        <div className="sidebar-bottom">
          <div className="side-caption">
            SYSTEM
          </div>

          <div className="system-status">
            <span
              className={`status-dot ${
                health.data
                  ? "online"
                  : health.error
                    ? "offline"
                    : "pending"
              }`}
            />

            <span>
              API{" "}
              {health.data
                ? "在线"
                : health.error
                  ? "离线"
                  : "检测中"}
            </span>

            <span className="status-url">
              :8000
            </span>
          </div>

          <button
            className="refresh-button"
            onClick={reloadAll}
          >
            <RefreshCw size={15} />
            刷新全部数据
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">
              SECURITY OPERATIONS / TRACE
              WORKSPACE
            </div>

            <h1>
              {sectionTitle(section)}
            </h1>
          </div>

          <form
            className="task-picker"
            onSubmit={chooseTask}
          >
            <label htmlFor="task-id">
              分析任务
            </label>

            <Search size={15} />

            <input
              id="task-id"
              value={taskInput}
              onChange={(event) =>
                setTaskInput(
                  event.target.value,
                )
              }
              spellCheck={false}
            />

            <button
              type="submit"
              title="加载任务"
              aria-label="加载任务"
            >
              <ChevronRight size={17} />
            </button>
          </form>
        </header>

        <div className="content-wrap">
          {isControlledEmulation && (
            <p role="status">
              受控实验数据 ·
              真实日志与通信记录 ·
              不代表完整入侵链已验证
            </p>
          )}

          {section === "overview" && (
            <Overview
              task={task}
              events={{
                ...events,
                data: displayedEvents,
              }}
              alerts={{
                ...alerts,
                data: displayedAlerts,
              }}
              graph={graph}
              onNavigate={setSection}
            />
          )}

          {section === "events" && (
            <EventsPanel
              state={{
                ...events,
                data: displayedEvents,
              }}
            />
          )}

          {section === "alerts" && (
            <AlertsPanel
              state={{
                ...alerts,
                data: displayedAlerts,
              }}
            />
          )}

          {section === "graph" && (
            <GraphPanel state={graph} />
          )}

          {section === "trace" && (
            <TracePanel state={trace} />
          )}
        </div>
      </main>
    </div>
  );
}

function sectionTitle(
  section: Section,
) {
  return {
    overview: "任务概览",
    events: "事件流",
    alerts: "检测告警",
    graph: "攻击图",
    trace: "溯源结果",
  }[section];
}

function NavItem({
  icon: Icon,
  label,
  count,
  active,
  onClick,
}: {
  icon: typeof Activity;
  label: string;
  count?: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      className={`nav-item ${
        active ? "active" : ""
      }`}
      aria-label={label}
      aria-current={
        active ? "page" : undefined
      }
      onClick={onClick}
    >
      <Icon size={17} />

      <span>{label}</span>

      {typeof count === "number" && (
        <small>{count}</small>
      )}
    </button>
  );
}

function Overview({
  task,
  events: eventState,
  alerts: alertState,
  graph,
  onNavigate,
}: {
  task: LoadState<TaskStatus> & {
    reload: () => void;
  };

  events: LoadState<
    NormalizedEvent[]
  > & {
    reload: () => void;
  };

  alerts: LoadState<Alert[]> & {
    reload: () => void;
  };

  graph: LoadState<AttackGraph> & {
    reload: () => void;
  };

  onNavigate: (
    section: Section,
  ) => void;
}) {
  const events =
    eventState.data ?? [];

  const alerts =
    alertState.data ?? [];

  const graphData =
    graph.data;

  const topAlert =
    alerts.reduce<Alert | null>(
      (best, alert) => {
        if (
          !Number.isFinite(
            alert.confidence,
          ) ||
          alert.confidence < 0 ||
          alert.confidence > 1
        ) {
          return best;
        }

        return !best ||
          alert.confidence >
            best.confidence
          ? alert
          : best;
      },
      null,
    );

  const heuristicScore =
    topAlert
      ? parseEvidenceSummary(
          topAlert.evidence_summary,
        ).heuristic
      : false;

  const highestAlertConfidence =
    topAlert
      ? heuristicScore
        ? `${Math.round(
            topAlert.confidence *
              100,
          )} / 100`
        : confidence(
            topAlert.confidence,
          )
      : "-";

  return (
    <div className="overview-grid">
      <section className="hero-panel">
        <div className="hero-copy">
          <span className="section-kicker">
            <Activity size={14} />
            LIVE INVESTIGATION
          </span>

          <h2>
            {task.data
              ? task.data.message
              : "正在载入任务状态"}
          </h2>

          <p>
            {task.data
              ? `任务 ${task.data.task_id} · 最近更新 ${formatTime(
                  task.data
                    .updated_at,
                )}`
              : "连接后端接口，加载当前攻击调查上下文。"}
          </p>
        </div>

        {task.data && (
          <div className="progress-block">
            <div className="progress-heading">
              <span>溯源进度</span>

              <strong>
                {percent(
                  task.data.progress,
                )}
              </strong>
            </div>

            <div className="progress-track">
              <span
                style={{
                  width: percent(
                    task.data
                      .progress,
                  ),
                }}
              />
            </div>

            <div className="progress-meta">
              <span>
                阶段：
                {task.data.stage}
              </span>

              <span
                className={`state-pill ${task.data.status}`}
              >
                {statusLabel(
                  task.data
                    .status,
                )}
              </span>
            </div>
          </div>
        )}

        {task.error && (
          <ErrorState
            message={task.error}
            retry={task.reload}
          />
        )}
      </section>

      <div className="metric-row">
        <Metric
          icon={Database}
          label="标准化事件"
          value={
            eventState.loading
              ? "…"
              : eventState.error
                ? "-"
                : events.length
          }
          accent="cyan"
          onClick={() =>
            onNavigate("events")
          }
        />

        <Metric
          icon={AlertTriangle}
          label="检测告警"
          value={
            alertState.loading
              ? "…"
              : alertState.error
                ? "-"
                : alerts.length
          }
          accent="amber"
          onClick={() =>
            onNavigate("alerts")
          }
        />

        <Metric
          icon={GitBranch}
          label="攻击图节点"
          value={
            graph.loading
              ? "…"
              : graph.error
                ? "-"
                : graph.data
                    ?.nodes
                    .length ?? 0
          }
          accent="violet"
          onClick={() =>
            onNavigate("graph")
          }
        />

        <Metric
          icon={Shield}
          label={
            heuristicScore
              ? "最高告警评分"
              : "最高告警置信度"
          }
          value={
            alertState.loading
              ? "…"
              : alertState.error
                ? "-"
                : highestAlertConfidence
          }
          accent="green"
          hint="当前任务告警的最高 confidence 分数。启发式检测分数不代表经过校准的攻击概率。"
          onClick={() =>
            onNavigate("alerts")
          }
        />
      </div>

      <section className="panel event-preview">
        <PanelHeading
          icon={Database}
          title="最近事件"
          action="查看全部"
          onAction={() =>
            onNavigate("events")
          }
        />

        {eventState.loading ? (
          <LoadingState />
        ) : eventState.error ? (
          <ErrorState
            message={
              eventState.error
            }
            retry={
              eventState.reload
            }
          />
        ) : events.length === 0 ? (
          <EmptyState
            title="暂无事件"
            detail="接口返回空数据"
          />
        ) : (
          <div className="mini-list">
            {events
              .slice(0, 3)
              .map((event) => (
                <div
                  className="mini-row"
                  key={
                    event.event_id
                  }
                >
                  <span className="event-time">
                    {formatTime(
                      event.timestamp,
                    )}
                  </span>

                  <span className="event-action">
                    {event.action}
                  </span>

                  <span className="event-host">
                    {event.host_id ??
                      event.source}
                  </span>

                  <span className="source-tag">
                    {sourceLabel(
                      event.source_type,
                    )}
                  </span>
                </div>
              ))}
          </div>
        )}
      </section>

      <section className="panel alert-preview">
        <PanelHeading
          icon={AlertTriangle}
          title="告警摘要"
          action="查看全部"
          onAction={() =>
            onNavigate("alerts")
          }
        />

        {alertState.loading ? (
          <LoadingState />
        ) : alertState.error ? (
          <ErrorState
            message={
              alertState.error
            }
            retry={
              alertState.reload
            }
          />
        ) : alerts.length === 0 ? (
          <EmptyState
            title="暂无告警"
            detail="当前任务没有检测结果"
          />
        ) : (
          <div className="alert-stack">
            {alerts
              .slice(0, 3)
              .map((alert) => (
                <div
                  className="alert-row"
                  key={
                    alert.alert_id
                  }
                >
                  <span
                    className={`severity-dot ${alert.severity}`}
                  />

                  <div>
                    <strong>
                      {
                        alert.rule_name
                      }
                    </strong>

                    <span>
                      {
                        alert.rule_id
                      }{" "}
                      ·{" "}
                      {formatTime(
                        alert.timestamp_start,
                      )}
                    </span>
                  </div>

                  <b>
                    {severityLabel(
                      alert.severity,
                    )}
                  </b>
                </div>
              ))}
          </div>
        )}
      </section>

      <section className="panel chain-preview">
        <PanelHeading
          icon={GitBranch}
          title="攻击链路"
          action="展开攻击图"
          onAction={() =>
            onNavigate("graph")
          }
        />

        {graph.loading ? (
          <LoadingState />
        ) : graph.error ? (
          <ErrorState
            message={graph.error}
            retry={graph.reload}
          />
        ) : graphData ? (
          <ChainPreview
            nodes={
              graphData.nodes
            }
          />
        ) : (
          <EmptyState title="暂无攻击图" />
        )}
      </section>
    </div>
  );
}

function Metric({
  icon: Icon,
  label,
  value,
  accent,
  hint,
  onClick,
}: {
  icon: typeof Database;
  label: string;
  value: string | number;
  accent: string;
  hint?: string;
  onClick: () => void;
}) {
  return (
    <button
      className="metric-card"
      title={hint}
      aria-label={`${label} ${value}`}
      onClick={onClick}
    >
      <span
        className={`metric-icon ${accent}`}
      >
        <Icon size={18} />
      </span>

      <span className="metric-label">
        {label}
      </span>

      <strong>{value}</strong>

      <ChevronRight
        className="metric-arrow"
        size={16}
      />
    </button>
  );
}

function PanelHeading({
  icon: Icon,
  title,
  action,
  onAction,
}: {
  icon: typeof Database;
  title: string;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <div className="panel-heading">
      <div>
        <Icon size={17} />
        <h3>{title}</h3>
      </div>

      {action && (
        <button
          className="text-button"
          onClick={onAction}
        >
          {action}
          <ChevronRight size={15} />
        </button>
      )}
    </div>
  );
}

function EventsPanel({
  state,
}: {
  state: LoadState<
    NormalizedEvent[]
  > & {
    reload?: () => void;
  };
}) {
  return (
    <section className="panel table-panel">
      <PanelHeading
        icon={Database}
        title="标准化事件"
        action={
          state.loading
            ? "读取中"
            : state.error
              ? "读取失败"
              : `${state.data?.length ?? 0} 条`
        }
      />

      {state.loading ? (
        <LoadingState />
      ) : state.error ? (
        <ErrorState
          message={state.error}
          retry={state.reload}
        />
      ) : state.data?.length ? (
        <EventsView
          events={state.data}
        />
      ) : (
        <EmptyState
          title="暂无事件"
          detail="当前任务没有标准化事件"
        />
      )}
    </section>
  );
}

function AlertsPanel({
  state,
}: {
  state: LoadState<Alert[]> & {
    reload?: () => void;
  };
}) {
  return (
    <section className="panel table-panel">
      <PanelHeading
        icon={AlertTriangle}
        title="检测告警"
        action={
          state.loading
            ? "读取中"
            : state.error
              ? "读取失败"
              : `${state.data?.length ?? 0} 条`
        }
      />

      {state.loading ? (
        <LoadingState />
      ) : state.error ? (
        <ErrorState
          message={state.error}
          retry={state.reload}
        />
      ) : state.data?.length ? (
        <AlertsView
          alerts={state.data}
        />
      ) : (
        <EmptyState
          title="暂无告警"
          detail="当前任务没有检测结果"
        />
      )}
    </section>
  );
}

function GraphPanel({
  state,
}: {
  state: LoadState<AttackGraph> & {
    reload: () => void;
  };
}) {
  return (
    <section className="panel graph-panel">
      <PanelHeading
        icon={GitBranch}
        title="攻击图"
        action={
          state.data
            ? `${state.data.nodes.length} 节点 · ${state.data.edges.length} 关系`
            : undefined
        }
      />

      {state.loading ? (
        <LoadingState />
      ) : state.error ? (
        <ErrorState
          message={state.error}
          retry={state.reload}
        />
      ) : state.data ? (
        <Suspense
          fallback={
            <LoadingState />
          }
        >
          <AttackGraphView
            graph={state.data}
          />
        </Suspense>
      ) : (
        <EmptyState title="暂无攻击图" />
      )}
    </section>
  );
}

function TracePanel({
  state,
}: {
  state: LoadState<TraceResult> & {
    reload: () => void;
  };
}) {
  return (
    <section className="trace-stack">
      {state.loading ? (
        <section className="panel">
          <LoadingState />
        </section>
      ) : state.error ? (
        <section className="panel">
          <ErrorState
            message={state.error}
            retry={state.reload}
          />
        </section>
      ) : state.data ? (
        <>
          <section className="trace-hero">
            <div>
              <span className="section-kicker">
                <CircleCheck
                  size={14}
                />
                TRACE COMPLETE
              </span>

              <h2>
                {
                  state.data
                    .summary
                }
              </h2>

              <p>
                {
                  state.data
                    .trace_id
                }{" "}
                · 生成于{" "}
                {formatTime(
                  state.data
                    .generated_at,
                )}
              </p>
            </div>

            <div className="trace-score">
              <span>
                证据覆盖
              </span>

              <strong>
                {state.data
                  .evidence_event_ids
                  .length +
                  state.data
                    .evidence_alert_ids
                    .length}
              </strong>

              <small>条证据</small>
            </div>
          </section>

          <section className="panel">
            <PanelHeading
              icon={GitBranch}
              title="攻击阶段"
              action={`${state.data.attack_chain.length} 个阶段`}
            />

            <div className="stage-list">
              {state.data.attack_chain.map(
                (stage) => (
                  <article
                    className="stage-row"
                    key={
                      stage.order
                    }
                  >
                    <div className="stage-number">
                      {String(
                        stage.order,
                      ).padStart(
                        2,
                        "0",
                      )}
                    </div>

                    <div className="stage-main">
                      <div className="stage-top">
                        <span>
                          {
                            stage.tactic
                          }
                        </span>

                        {stage.technique_id && (
                          <code>
                            {
                              stage.technique_id
                            }
                          </code>
                        )}

                        <b>
                          {confidence(
                            stage.confidence,
                          )}
                        </b>
                      </div>

                      <h3>
                        {
                          stage.title
                        }
                      </h3>

                      <p>
                        {
                          stage.description
                        }
                      </p>

                      <div className="stage-evidence">
                        <span>
                          <FileWarning
                            size={
                              14
                            }
                          />
                          事件{" "}
                          {
                            stage
                              .evidence_event_ids
                              .length
                          }
                        </span>

                        <span>
                          <AlertTriangle
                            size={
                              14
                            }
                          />
                          告警{" "}
                          {
                            stage
                              .evidence_alert_ids
                              .length
                          }
                        </span>
                      </div>
                    </div>
                  </article>
                ),
              )}
            </div>
          </section>

          <section className="trace-bottom">
            <section className="panel attribution">
              <PanelHeading
                icon={Shield}
                title="归因分析"
              />

              {Object.entries(
                state.data
                  .attribution,
              ).map(
                ([key, value]) => (
                  <div
                    className="attribute-row"
                    key={key}
                  >
                    <span>
                      {key}
                    </span>

                    <strong>
                      {typeof value ===
                      "object"
                        ? JSON.stringify(
                            value,
                          )
                        : String(
                            value,
                          )}
                    </strong>
                  </div>
                ),
              )}
            </section>

            <section className="panel evidence">
              <PanelHeading
                icon={FileWarning}
                title="证据索引"
              />

              <div className="evidence-columns">
                <div>
                  <span>事件</span>

                  <strong>
                    {
                      state.data
                        .evidence_event_ids
                        .length
                    }
                  </strong>

                  <code>
                    {state.data
                      .evidence_event_ids
                      .join(
                        "\n",
                      ) || "-"}
                  </code>
                </div>

                <div>
                  <span>告警</span>

                  <strong>
                    {
                      state.data
                        .evidence_alert_ids
                        .length
                    }
                  </strong>

                  <code>
                    {state.data
                      .evidence_alert_ids
                      .join(
                        "\n",
                      ) || "-"}
                  </code>
                </div>
              </div>
            </section>
          </section>
        </>
      ) : (
        <section className="panel">
          <EmptyState title="暂无溯源结果" />
        </section>
      )}
    </section>
  );
}

export default App;