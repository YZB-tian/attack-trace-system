/**
 * Human-readable Chinese labels for contract values.
 *
 * The API keeps English identifiers (actions, tactics, relations, detector ids)
 * because they are part of the data contract. The interface translates them and
 * always keeps the original value available through `title`/details so the
 * evidence stays traceable.
 */

const TACTICS: Record<string, string> = {
  "initial-access": "初始入侵",
  "execution": "执行",
  "persistence": "持久化",
  "privilege-escalation": "权限提升",
  "defense-evasion": "防御规避",
  "stealth": "隐蔽",
  "credential-access": "凭据访问",
  "discovery": "发现",
  "lateral-movement": "横向移动",
  "collection": "收集",
  "command-and-control": "命令与控制",
  "exfiltration": "数据外传",
  "impact": "影响",
  "resource-development": "资源准备",
  "reconnaissance": "侦察",
};

const ACTIONS: Record<string, string> = {
  network_connect: "网络连接",
  network_write: "网络发送",
  network_observed: "网络观测",
  port_scan_observed: "端口扫描",
  dns_query: "DNS 查询",
  http_request: "HTTP 请求",
  irc_command: "IRC 命令",
  icmp_echo: "ICMP 回显",
  c2_beacon: "C2 心跳",
  data_transfer_received: "接收数据",
  login_success: "登录成功",
  login_failure: "登录失败",
  login: "登录",
  logout: "注销",
  session_open: "会话建立",
  session_close: "会话关闭",
  sudo_exec: "sudo 执行",
  user_switch: "切换用户",
  auth_log: "认证日志",
  disconnect: "断开连接",
  process_create: "进程创建",
  process_exec: "进程执行",
  process_exit: "进程退出",
  process_event: "进程事件",
  process_access: "进程访问",
  remote_thread_create: "远程线程创建",
  file_access: "文件访问",
  file_read: "文件读取",
  file_write: "文件写入",
  file_open: "打开文件",
  file_create: "创建文件",
  object_access: "对象访问",
  firewall_pass: "防火墙放行",
  firewall_block: "防火墙拦截",
  exploit_delivery: "漏洞利用投递",
  vulnerability_confirmed: "漏洞确认",
  remote_session_opened: "远程会话建立",
  remote_command: "远程命令",
  network_scan_target: "扫描目标",
  network_scan_service: "扫描服务",
  host_behavior: "主机行为",
  syscall: "系统调用",
  audit_event: "审计事件",
  config_change: "配置变更",
};

const RELATIONS: Record<string, string> = {
  related_to: "时间关联",
  network_connect: "网络连接",
  file_access: "文件访问",
  login: "登录",
  process_spawn: "派生进程",
  initial_access: "初始入侵",
  lateral_movement: "横向移动",
  privilege_escalation: "权限提升",
  data_access: "数据访问",
  data_exfiltration: "数据外传",
};

const NODE_TYPES: Record<string, string> = {
  host: "主机",
  user: "账户",
  process: "进程",
  file: "文件",
  ip: "IP 地址",
  domain: "域名",
  session: "会话",
  c2: "C2 服务器",
  technique: "ATT&CK 技术",
  other: "事件",
};

const DETECTORS: Record<string, string> = {
  network_heuristic_v1: "网络启发式规则",
  host_heuristic_v1: "主机启发式规则",
};

const DETECTION_SOURCES: Record<string, string> = {
  zeek: "Zeek 网络日志",
  "auth.log": "Linux 认证日志",
  auditd: "auditd 审计日志",
  sysmon: "Sysmon",
  syslog: "syslog",
  bpftrace: "bpftrace 内核跟踪",
  proc_sampler: "进程采样",
  c2_receiver: "C2 接收端",
  attack_tooling: "攻击工具输出",
  lab_service: "靶场服务",
  opnsense: "OPNsense 防火墙",
  windows_security: "Windows 安全日志",
  pcap_scapy: "PCAP 解析",
  strace: "strace 系统调用",
};

const SOURCE_TYPES: Record<string, string> = {
  host_log: "主机日志",
  host_behavior: "主机行为",
  network_flow: "网络流量",
  boundary_log: "边界日志",
};

const STATUSES: Record<string, string> = {
  pending: "等待中",
  running: "运行中",
  completed: "已完成",
  failed: "失败",
  open: "待处理",
  reviewed: "已复核",
  false_positive: "误报",
  confirmed: "已确认",
  closed: "已关闭",
};

const ATTRIBUTION_KEYS: Record<string, string> = {
  data_classification: "数据分类",
  method: "分析方法",
  llm_used: "是否使用大模型",
  candidate_paths: "候选路径",
  apt_similarity: "APT 行为相似度",
  apt_similarity_scope: "相似度比较范围",
  path_analysis: "阶段路径分析",
  data_access_to_network_candidates: "存储到外传候选路径",
  stix_source: "ATT&CK 数据源",
  limitations: "结论边界",
  llm_review: "大模型复核",
};

const ATTRIBUTION_METHODS: Record<string, string> = {
  deterministic_evidence_correlation: "确定性证据关联",
};

const DATA_CLASSIFICATIONS: Record<string, string> = {
  controlled_emulation: "受控实验数据",
  real_observation: "真实观测数据",
  real_exploitation: "真实漏洞利用数据",
};

const SCORE_KINDS: Record<string, string> = {
  heuristic_not_probability: "启发式评分（非概率）",
};

/** Rule titles shipped by the detector modules, keyed by their stable rule id. */
const RULES: Record<string, string> = {
  "NET-BEACON": "周期性通信候选（可能是正常业务）",
  "NET-DNS-TUNNEL": "疑似 DNS 隐蔽信道",
  "NET-HTTP-COVERT": "疑似 HTTP 隐蔽信道",
  "NET-ICMP-TUNNEL": "疑似 ICMP 隐蔽信道",
  "NET-INTERNAL-SENSITIVE-UPLOAD": "内网主机向外部大量上传数据",
  "NET-IRC-BACKDOOR-EXPLOIT": "IRC 服务后门利用尝试",
  "HOST-LINUX-SUDO-TO-ROOT": "非 root 账户执行 sudo 提权",
  "HOST-LINUX-INTERNAL-SSH-LOGIN": "内网主机之间的远程登录",
  "HOST-LINUX-SENSITIVE-FILE-ACCESS": "敏感凭据文件被访问",
  "HOST-LINUX-AUDIT-DISABLE": "审计功能被关闭或规则被删除",
  "HOST-WIN-POWERSHELL-ENCODED": "PowerShell 编码命令执行",
  "HOST-WIN-PROCESS-INJECTION": "进程内存注入",
  "HOST-WIN-LSASS-MEMORY-ACCESS": "LSASS 内存访问（凭据转储候选）",
  "HOST-WIN-LOLBIN-EXECUTION": "系统自带程序被用于加载远程载荷",
};

/** Technical evidence keys that would otherwise surface as raw identifiers. */
const EVIDENCE_KEYS: Record<string, string> = {
  reason: "判定依据",
  source_ip: "源地址",
  destination_ip: "目的地址",
  source_zone: "源区域",
  destination_port: "目的端口",
  bytes_out: "发送字节",
  bytes_in: "接收字节",
  connections: "连接数",
  out_in_multiple: "收发比",
  threshold_bytes: "阈值字节",
  content_bytes_proven: "内容外传已证明",
  hosts: "涉及主机",
  processes: "涉及进程",
  callers: "调用账户",
  sudo_events: "sudo 次数",
  login_events: "登录次数",
  success_proven: "成功已证明",
  execution_success_proven: "执行成功已证明",
  matched_condition: "命中条件",
  command_field: "命令字段",
  executable: "可执行文件",
  host_id: "主机",
  source_image: "来源进程",
  target_image: "目标进程",
  remote_thread_events: "远程线程事件",
  write_capable_access_events: "可写访问事件",
  unbacked_thread_events: "非模块内存线程事件",
  reflective_or_injected_code_indicator: "含反射加载或注入特征",
  code_execution_proven: "代码执行已证明",
  dump_created_proven: "转储文件已证明",
  access_events: "访问次数",
  irc_server: "IRC 服务端",
  irc_client: "IRC 客户端",
  reverse_connection_observed: "已观察反向连接",
  distinct_nicknames: "不同昵称数",
  irc_events: "IRC 事件数",
  probes: "探测包数",
  distinct_ports: "不同端口数",
  sample_ports: "端口样例",
  aggregation: "聚合方式",
  derived_from: "数据来源",
  minute: "分钟",
  encoded_parameter_or_path_ratio: "编码参数占比",
  encoded_value_churn: "编码值变化率",
  long_uri_ratio: "长 URI 占比",
  large_upload_ratio: "大体积上传占比",
  request_body_bytes: "请求体字节",
  response_body_bytes: "响应体字节",
  request_byte_fraction: "请求字节占比",
  body_sample_count: "请求体样本数",
  body_entropy_available: "请求体熵可用",
  high_entropy_body_ratio: "高熵请求体占比",
  body_sample_churn: "请求体变化率",
  malformed_uri_count: "异常 URI 数",
  matched_patterns: "命中模式",
  limitation: "适用边界",
  payload_entropy_available: "载荷熵可用",
  sampled_packets: "采样包数",
  high_entropy_payload_ratio: "高熵载荷占比",
  payload_sample_churn: "载荷变化率",
  packet_count: "包数",
  total_payload_bytes: "载荷总字节",
  evidence_level: "证据级别",
  unique_label_ratio: "不同标签占比",
  suffix_concentration: "后缀集中度",
  txt_ratio: "TXT 占比",
  long_label_ratio: "长标签占比",
  high_entropy_ratio: "高熵占比",
  hex_label_ratio: "十六进制标签占比",
  short_hex_txt_pattern: "短十六进制 TXT 模式",
  ip_bytes: "IP 字节数",
  observation_seconds: "观测时长",
  average_ip_packet_bytes: "平均包字节",
  packets_per_second: "包速率",
  score_kind: "评分类型",
};

export function ruleLabel(ruleId?: string | null, fallback?: string | null) {
  if (ruleId && RULES[ruleId]) return RULES[ruleId];
  if (fallback && RULE_NAMES[fallback]) return RULE_NAMES[fallback];
  if (ruleId && RULE_NAMES[ruleId]) return RULE_NAMES[ruleId];
  return fallback ?? ruleId ?? "未命名规则";
}

/** Detector titles arrive in English; the interface renders them in Chinese. */
const RULE_NAMES: Record<string, string> = {
  "Periodic communication candidate (may be benign)": "周期性通信候选（可能是正常业务）",
  "Suspected DNS covert communication": "疑似 DNS 隐蔽信道",
  "Suspected HTTP covert communication": "疑似 HTTP 隐蔽信道",
  "Suspected ICMP covert communication": "疑似 ICMP 隐蔽信道",
  "Internal host uploaded a large volume to an external destination": "内网主机向外部大量上传数据",
  "Automated IRC registrations followed by a reverse connection from the IRC service": "IRC 服务出现自动化注册并随后产生反向连接",
  "Remote login from another internal host (lateral movement candidate)": "来自内网其它主机的远程登录（横向移动候选）",
  "Sudo command targeting root from a non-root account": "非 root 账户执行 sudo 提权",
  "Sensitive credential file accessed on a monitored host": "监控主机上的敏感凭据文件被访问",
  "Process requested write access to LSASS memory (credential dumping candidate)": "进程请求写入 LSASS 内存（凭据转储候选）",
  "Remote thread created inside another process (memory injection candidate)": "在其它进程中创建远程线程（内存注入候选）",
  "System binary used to launch a remote or scripted payload": "系统自带程序被用于加载远程或脚本载荷",
  "PowerShell encoded command execution candidate": "PowerShell 编码命令执行候选",
  "Linux audit disabling or rule removal candidate": "Linux 审计被关闭或规则被删除",
};

/** Boundary statements produced by the correlation layer. */
const LIMITATIONS: Record<string, string> = {
  "Candidate relations do not prove common attacker identity.": "候选关联不等于同一攻击者身份。",
  "Only the strongest candidate path populates attack_chain; other paths remain separate.": "只有证据最强的候选路径会进入攻击链，其余路径单独保留。",
  "No live multi-agent LLM analysis is performed by this module.": "本模块不执行在线多智能体大模型分析。",
  "TTP similarity is not attribution; unobserved stages are not reconstructed.": "TTP 相似度不是归因；未观测到的阶段不会被补造。",
  "Time-window membership is not proof of attack causality.": "落在同一时间窗口不等于存在攻击因果关系。",
  "Office actions were separately orchestrated; no Web-to-Office compromise proven.": "办公区动作是独立编排的，未证明 Web 到办公区的实际攻陷。",
  "No real privilege escalation, memory injection or live LLM verified.": "未验证真实提权、内存注入或在线大模型分析。",
  "Citation existence is validated, not semantic truth: human review remains required.": "只校验引用是否存在，不保证语义正确，仍需人工复核。",
};

export function limitationLabel(value: string) {
  return LIMITATIONS[value] ?? value;
}

/** ATT&CK article titles are canonical English; the interface adds a Chinese gloss. */
const TECHNIQUES: Record<string, string> = {
  T1190: "利用面向公众的应用",
  T1059: "命令与脚本解释器",
  "T1059.001": "PowerShell",
  T1685: "削弱防御",
  "T1685.004": "禁用或修改 Linux 审计日志",
  T1021: "远程服务",
  "T1021.004": "SSH",
  T1548: "滥用提权控制机制",
  "T1548.003": "Sudo 与 sudo 缓存",
  T1005: "本地系统数据",
  T1041: "通过 C2 通道外传",
  T1071: "应用层协议",
  "T1071.001": "Web 协议",
  "T1071.004": "DNS 协议",
  T1095: "非应用层协议",
  T1055: "进程注入",
  T1003: "操作系统凭据转储",
  "T1003.001": "LSASS 内存",
  T1218: "系统二进制代理执行",
};

export function techniqueLabel(techniqueId?: string | null, techniqueName?: string | null) {
  const gloss = techniqueId ? TECHNIQUES[techniqueId] : undefined;
  if (gloss && techniqueName) return `${gloss}（${techniqueName}）`;
  if (gloss) return gloss;
  return techniqueName ?? techniqueId ?? "未标注";
}

/** Extra explanatory sentences appended by the detector modules. */
const DESCRIPTION_NOTES: Record<string, string> = {
  "Authorized administration also looks like this; review the caller and command.": "合法的运维操作也会呈现同样形态，请核对调用账户与命令。",
  "Source host is an internal asset, not the external attacker segment.": "来源主机属于内网资产，不是外部攻击段。",
  "Debuggers, EDR products and accessibility tools also create remote threads.": "调试器、EDR 与辅助工具也会创建远程线程。",
  "The thread start address is outside every loaded module, which is consistent with injected or reflectively loaded code.": "线程起始地址不在任何已加载模块内，符合代码注入或反射加载特征。",
  "Backup, EDR and password-filter components also request LSASS access.": "备份、EDR 与密码过滤组件也会请求 LSASS 访问。",
  "Backups and configuration management also read these files.": "备份与配置管理工具也会读取这些文件。",
  "Review original event and authorized administration context; success is not proven.": "请结合原始事件与授权运维背景复核，不证明已成功执行。",
};

export function descriptionNoteLabel(value: string) {
  return DESCRIPTION_NOTES[value] ?? value;
}

export function evidenceKeyLabel(key: string) {
  return EVIDENCE_KEYS[key] ?? key;
}

/** Enumerated values that would otherwise render as bare English identifiers. */
const FIXED_VALUES: Record<string, string> = {
  sudo_command_targets_root: "命令目标为 root",
  remote_login_from_another_lab_host: "来自内网其它主机",
  create_remote_thread_into_another_process: "在他人进程中创建远程线程",
  lsass_process_memory_write_access: "请求 LSASS 内存写权限",
  credential_or_privilege_file_accessed: "访问凭据或权限文件",
  encoded_command_argument: "编码命令参数",
  lolbin_remote_or_scripted_argument: "远程或脚本化参数",
  auditctl_disable_or_delete_rules: "关闭审计或删除规则",
  external: "外部区",
  boundary: "边界区",
  dmz: "DMZ 区",
  office: "办公区",
  server: "服务器区",
  internal: "内网",
  lab_vmnet2: "实验网段 VMnet2",
  inbound: "入站",
  outbound: "出站",
  unknown: "未知",
  inet: "IPv4",
  "TTP similarity only; not confirmed attribution": "仅为 TTP 相似度，不构成归因",
};

export function valueLabel(value: string) {
  return FIXED_VALUES[value] ?? value;
}

const withOriginal = (label: string, original: string) => (label === original ? label : `${label}（${original}）`);

export function tacticLabel(value?: string | null) {
  if (!value) return "未标注";
  return TACTICS[value] ?? value;
}

export function actionLabel(value?: string | null) {
  if (!value) return "未提供";
  return ACTIONS[value] ?? value;
}

export function relationLabel(value?: string | null) {
  if (!value) return "未提供";
  return RELATIONS[value] ?? value;
}

export function nodeTypeLabel(value?: string | null) {
  if (!value) return "未提供";
  return NODE_TYPES[value] ?? value;
}

export function detectorLabel(value?: string | null) {
  if (!value) return "未提供";
  return withOriginal(DETECTORS[value] ?? value, value);
}

export function detectionSourceLabel(value?: string | null) {
  if (!value) return "未提供";
  return DETECTION_SOURCES[value] ?? value;
}

export function sourceTypeLabel(value?: string | null) {
  if (!value) return "未提供";
  return SOURCE_TYPES[value] ?? value;
}

export function statusLabel(value?: string | null) {
  if (!value) return "未知";
  return STATUSES[value] ?? value;
}

export function attributionKeyLabel(value: string) {
  return ATTRIBUTION_KEYS[value] ?? value;
}

export function attributionMethodLabel(value: string) {
  return ATTRIBUTION_METHODS[value] ?? value;
}

export function dataClassificationLabel(value: string) {
  return DATA_CLASSIFICATIONS[value] ?? value;
}

export function scoreKindLabel(value: string) {
  return SCORE_KINDS[value] ?? value;
}

/** Heuristic scores are 0..1 fractions; never present them as a percentage. */
export function scoreLabel(value: number, heuristic: boolean) {
  if (!Number.isFinite(value)) return "未提供";
  return heuristic ? `${value.toFixed(2)} / 1.00（启发式）` : `${Math.round(value * 100)}%`;
}

export function scoreShort(value: number, heuristic: boolean) {
  return heuristic ? value.toFixed(2) : `${Math.round(value * 100)}%`;
}

export function ratioLabel(value: number) {
  return Number.isFinite(value) ? value.toFixed(2) : "未提供";
}

export function secondsLabel(value: number) {
  if (!Number.isFinite(value)) return "未提供";
  return `${value.toFixed(2)} 秒`;
}

export function bytesLabel(value: number) {
  if (!Number.isFinite(value) || value < 0) return "未提供";
  if (value < 1024) return `${value} 字节`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

export function compactTime(value?: string | null) {
  if (!value) return "未提供";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** Timezone-aware rendering for tooltips so the raw instant is never lost. */
export function exactTime(value?: string | null) {
  if (!value) return "未提供";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${compactTime(value)}（${Intl.DateTimeFormat().resolvedOptions().timeZone}，原始值 ${value}）`;
}

export function shortId(value?: string | null) {
  if (!value) return "未提供";
  const text = String(value);
  return text.length > 22 ? `${text.slice(0, 18)}…` : text;
}
