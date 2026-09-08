"""
攻击者身份溯源服务（主入口）

功能：
1. 从攻击图、告警、事件中提取攻击者指纹
2. 分析 C2 基础设施关联
3. 行为模式匹配已知 APT 组织
4. 生成完整的 TraceResult

输入：AttackGraph + list[Alert] + list[NormalizedEvent]
输出：TraceResult

遵守项目规范：
- 只修改 agents/ 目录
- 输出必须为公共模型 TraceResult
- 时间必须为带时区 ISO 8601
- ID 使用统一前缀
"""

from __future__ import annotations
from typing import List, Optional, Dict, Set
from collections import defaultdict

from common.models import (
    NormalizedEvent,
    Alert,
    AttackGraph,
    TraceResult,
    AttackStage,
)
from common.id_utils import new_id
from common.time_utils import now_iso

from agents.fingerprint_extractor import (
    AttackerFingerprint,
    extract_fingerprint_from_events,
    extract_fingerprint_from_alerts,
    extract_fingerprint_from_graph,
    merge_fingerprints,
)
from agents.c2_analyzer import (
    analyze_c2_infrastructure,
    InfrastructureAnalysis,
)
from agents.behavior_matcher import (
    match_apt_groups,
    AttributionResult,
)
from agents.apt_knowledge_base import tactic_order


# 关系到战术的映射（模块级常量，避免重复创建）
RELATION_TO_TACTIC = {
    "initial_access": "Initial Access",
    "process_spawn": "Execution",
    "file_access": "Collection",
    "file_create": "Persistence",
    "network_connect": "Command and Control",
    "lateral_movement": "Lateral Movement",
    "privilege_escalation": "Privilege Escalation",
    "c2_communication": "Command and Control",
    "data_access": "Collection",
    "data_exfiltration": "Exfiltration",
    "login": "Credential Access",
    "related_to": "Discovery",
}

# ATT&CK 技术名称（模块级缓存）
TECHNIQUE_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1195.002": "Supply Chain Compromise: Software Supply Chain",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1059.005": "Visual Basic",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1068": "Exploitation for Privilege Escalation",
    "T1070.004": "File Deletion",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1100": "Web Shell",
    "T1105": "Ingress Tool Transfer",
    "T1132.001": "Data Encoding: Standard Encoding",
    "T1136.001": "Create Account: Local Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1218.011": "Rundll32",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1505.003": "Web Shell",
    "T1529": "System Shutdown/Reboot",
    "T1542.003": "Pre-OS Boot: Bootkit",
    "T1547.001": "Registry Run Keys",
    "T1552.004": "Unsecured Credentials: Private Keys",
    "T1003": "OS Credential Dumping",
    "T1003.008": "/etc/passwd and /etc/shadow",
    "T1005": "Data from Local System",
    "T1014": "Rootkit",
    "T1016": "System Network Configuration Discovery",
    "T1021": "Remote Services",
    "T1021.004": "SSH",
    "T1027": "Obfuscated Files or Information",
    "T1029": "Scheduled Transfer",
    "T1033": "System Owner/User Discovery",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1098": "Account Manipulation",
}


def analyze_trace(
    graph: AttackGraph,
    alerts: Optional[List[Alert]] = None,
    events: Optional[List[NormalizedEvent]] = None,
) -> TraceResult:
    """
    攻击者身份溯源主函数。

    Args:
        graph: 攻击图（关联模块输出）
        alerts: 告警列表（检测模块输出）
        events: 归一化事件列表（采集模块输出）

    Returns:
        TraceResult: 完整的溯源结果
    """
    alerts = alerts or []
    events = events or []

    # ============================================================
    # 阶段 1: 提取攻击者指纹
    # ============================================================
    fp_from_graph = extract_fingerprint_from_graph(graph)
    fp_from_alerts = extract_fingerprint_from_alerts(alerts)
    fp_from_events = extract_fingerprint_from_events(events)
    fingerprint = merge_fingerprints([fp_from_graph, fp_from_alerts, fp_from_events])

    # ============================================================
    # 阶段 2: 分析 C2 基础设施
    # ============================================================
    c2_analysis = analyze_c2_infrastructure(events, alerts, graph)

    # ============================================================
    # 阶段 3: APT 组织匹配
    # ============================================================
    attribution = match_apt_groups(fingerprint, graph, alerts)

    # ============================================================
    # 阶段 4: 构建攻击链（增强版：聚合证据）
    # ============================================================
    attack_chain = _build_attack_chain(graph, alerts, fingerprint, attribution)

    # ============================================================
    # 阶段 5: 识别初始入侵点和 C2
    # ============================================================
    initial_access_id = _identify_initial_access(graph, fingerprint, events)
    suspected_c2_ids = [p.entity_id for p in c2_analysis.c2_profiles if p.confidence >= 0.3]

    # ============================================================
    # 阶段 6: 汇总证据
    # ============================================================
    evidence_event_ids = sorted(fingerprint.evidence_event_ids)
    evidence_alert_ids = sorted(fingerprint.evidence_alert_ids)

    # ============================================================
    # 阶段 7: 构建归因信息（含评分细目）
    # ============================================================
    attribution_dict = _build_attribution_dict(attribution, c2_analysis, fingerprint)

    # ============================================================
    # 阶段 8: 生成摘要
    # ============================================================
    summary = _generate_summary(
        fingerprint, c2_analysis, attribution, attack_chain, graph
    )

    return TraceResult(
        trace_id=new_id("trace"),
        task_id=graph.task_id,
        generated_at=now_iso(),
        status="completed",
        summary=summary,
        initial_access_entity_id=initial_access_id,
        suspected_c2_entity_ids=suspected_c2_ids,
        attack_chain=attack_chain,
        attribution=attribution_dict,
        evidence_event_ids=evidence_event_ids,
        evidence_alert_ids=evidence_alert_ids,
    )


# ============================================================
# 攻击链构建（增强版）
# ============================================================

def _build_attack_chain(
    graph: AttackGraph,
    alerts: List[Alert],
    fingerprint: AttackerFingerprint,
    attribution: AttributionResult,
) -> List[AttackStage]:
    """
    从攻击图构建攻击链。
    增强点：
    - 同一战术的多条边聚合为一个阶段，合并实体和证据
    - 从告警中补充缺失的战术阶段
    - 按 ATT&CK kill chain 顺序排列
    """
    # 按战术聚合边
    tactic_edges: Dict[str, list] = defaultdict(list)
    for edge in graph.edges:
        relation = edge.relation.value if hasattr(edge.relation, 'value') else str(edge.relation)
        tactic = RELATION_TO_TACTIC.get(relation, "Unknown")
        tactic_edges[tactic].append(edge)

    # 从告警中提取战术
    alert_tactics: Dict[str, List[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.mitre and alert.mitre.tactic:
            alert_tactics[alert.mitre.tactic].append(alert)

    # 合并所有战术
    all_tactics = set(tactic_edges.keys()) | set(alert_tactics.keys())
    if "Unknown" in all_tactics:
        all_tactics.discard("Unknown")

    # 构建阶段
    stages = []
    stage_counter = 0
    for tactic in all_tactics:
        edges = tactic_edges.get(tactic, [])
        tactic_alerts = alert_tactics.get(tactic, [])

        if edges:
            # 聚合同战术的所有边
            entity_ids: Set[str] = set()
            evidence_event_ids: Set[str] = set()
            evidence_alert_ids: Set[str] = set()
            technique_ids: Set[str] = set()
            max_confidence = 0.0
            earliest_ts = None

            for edge in edges:
                entity_ids.add(edge.source)
                entity_ids.add(edge.target)
                evidence_event_ids.update(edge.evidence_event_ids)
                evidence_alert_ids.update(edge.evidence_alert_ids)
                if edge.technique_id:
                    technique_ids.add(edge.technique_id)
                max_confidence = max(max_confidence, edge.confidence)
                if edge.timestamp:
                    if earliest_ts is None or edge.timestamp < earliest_ts:
                        earliest_ts = edge.timestamp

            # 补充告警证据
            for alert in tactic_alerts:
                evidence_alert_ids.add(alert.alert_id)
                evidence_event_ids.update(alert.event_ids)
                if alert.mitre and alert.mitre.technique_id:
                    technique_ids.add(alert.mitre.technique_id)
                max_confidence = max(max_confidence, alert.confidence)

            # 选择最主要的技术
            primary_tech = sorted(technique_ids)[0] if technique_ids else None

            stage_counter += 1
            stage = AttackStage(
                order=stage_counter,
                tactic=tactic,
                technique_id=primary_tech,
                technique_name=_get_technique_name(primary_tech),
                title=_build_stage_title(tactic, technique_ids),
                description=_build_stage_description(tactic, entity_ids, edges, len(tactic_alerts)),
                entity_ids=sorted(entity_ids),
                evidence_event_ids=sorted(evidence_event_ids),
                evidence_alert_ids=sorted(evidence_alert_ids),
                confidence=max_confidence,
            )
            stages.append(stage)

        elif tactic_alerts:
            # 仅从告警推断的阶段
            entity_ids: Set[str] = set()
            evidence_event_ids: Set[str] = set()
            evidence_alert_ids: Set[str] = set()
            technique_ids: Set[str] = set()
            max_confidence = 0.0

            for alert in tactic_alerts:
                entity_ids.update(alert.host_ids)
                evidence_event_ids.update(alert.event_ids)
                evidence_alert_ids.add(alert.alert_id)
                if alert.mitre:
                    if alert.mitre.technique_id:
                        technique_ids.add(alert.mitre.technique_id)
                max_confidence = max(max_confidence, alert.confidence)

            primary_tech = sorted(technique_ids)[0] if technique_ids else None

            stage_counter += 1
            stage = AttackStage(
                order=stage_counter,
                tactic=tactic,
                technique_id=primary_tech,
                technique_name=_get_technique_name(primary_tech),
                title=_build_stage_title(tactic, technique_ids),
                description=f"从 {len(tactic_alerts)} 条告警推断的 {tactic} 阶段。",
                entity_ids=sorted(entity_ids),
                evidence_event_ids=sorted(evidence_event_ids),
                evidence_alert_ids=sorted(evidence_alert_ids),
                confidence=max_confidence,
            )
            stages.append(stage)

    # 按 ATT&CK kill chain 顺序排序
    stages.sort(key=lambda s: tactic_order(s.tactic))

    # 重新编号（排序后）
    for i, stage in enumerate(stages):
        stage.order = i + 1

    # 如果没有任何阶段，从指纹中构建最小阶段
    if not stages and fingerprint.tactics:
        for tactic in sorted(fingerprint.tactics, key=tactic_order):
            stages.append(AttackStage(
                order=len(stages) + 1,
                tactic=tactic,
                title=tactic,
                description=f"从告警 MITRE 映射推断的 {tactic} 阶段。",
                entity_ids=sorted(fingerprint.host_ids)[:3],
                evidence_event_ids=[],
                evidence_alert_ids=sorted(fingerprint.evidence_alert_ids)[:3],
                confidence=0.4,
            ))

    return stages


def _build_stage_title(tactic: str, technique_ids: Set[str]) -> str:
    """构建阶段标题。"""
    if not technique_ids:
        return tactic

    if len(technique_ids) == 1:
        tech = list(technique_ids)[0]
        name = _get_technique_name(tech)
        return f"{tactic}: {name}" if name else f"{tactic} ({tech})"

    names = []
    for tech in sorted(technique_ids)[:3]:
        name = _get_technique_name(tech)
        names.append(name or tech)
    return f"{tactic}: {', '.join(names)}"


def _build_stage_description(
    tactic: str,
    entity_ids: Set[str],
    edges: list,
    num_alerts: int,
) -> str:
    """构建阶段详细描述。"""
    parts = [f"涉及 {len(entity_ids)} 个实体，{len(edges)} 条攻击关系。"]
    if num_alerts > 0:
        parts.append(f"关联 {num_alerts} 条告警。")

    # 列出主要实体（最多 5 个）
    if len(entity_ids) > 0:
        sample = sorted(entity_ids)[:5]
        parts.append(f"实体: {', '.join(sample)}。")

    return " ".join(parts)


# ============================================================
# 初始入侵点识别（增强版：多信号评分）
# ============================================================

def _identify_initial_access(
    graph: AttackGraph,
    fingerprint: AttackerFingerprint,
    events: Optional[List[NormalizedEvent]] = None,
) -> Optional[str]:
    """
    识别初始入侵点。
    使用多信号评分：
    1. 攻击图中的 initial_access 边（最高权重）
    2. DMZ/外部区域的主机
    3. 最早事件涉及的主机
    """
    candidates: Dict[str, float] = defaultdict(float)

    # 信号 1: 攻击图 initial_access 边
    for edge in graph.edges:
        relation = edge.relation.value if hasattr(edge.relation, 'value') else str(edge.relation)
        if relation == "initial_access":
            candidates[edge.target] += 1.0

    # 信号 2: 节点属性
    for node in graph.nodes:
        node_type = node.type.value if hasattr(node.type, 'value') else str(node.type)
        if node_type != "host":
            continue
        attrs = node.attributes
        zone = attrs.get("zone", "")
        role = attrs.get("role", "")

        if zone == "dmz":
            candidates[node.id] += 0.6
        elif zone == "boundary":
            candidates[node.id] += 0.3
        if role in ("web_server", "email_server"):
            candidates[node.id] += 0.4

    # 信号 3: 最早事件的 host_id
    if events:
        earliest_host = None
        earliest_ts = None
        for evt in events:
            if evt.host_id and (earliest_ts is None or evt.timestamp < earliest_ts):
                earliest_ts = evt.timestamp
                earliest_host = evt.host_id
        if earliest_host:
            candidates[earliest_host] += 0.3

    if candidates:
        return max(candidates, key=candidates.get)

    # 回退
    if graph.nodes:
        return graph.nodes[0].id
    return None


# ============================================================
# 归因字典构建（增强版：含评分细目）
# ============================================================

def _build_attribution_dict(
    attribution: AttributionResult,
    c2_analysis: InfrastructureAnalysis,
    fingerprint: AttackerFingerprint,
) -> dict:
    """构建归因字典，含评分细目（rubric）。"""
    result = {
        "matched_group": None,
        "confidence": 0.0,
        "all_matches": [],
        "scoring_rubric": {},
        "c2_infrastructure": c2_analysis.to_dict(),
        "fingerprint_summary": {
            "total_ips": len(fingerprint.ip_addresses),
            "total_domains": len(fingerprint.domains),
            "total_techniques": len(fingerprint.techniques),
            "total_tools": len(fingerprint.tools_detected),
            "total_hosts": len(fingerprint.host_ids),
            "total_commands": len(fingerprint.command_patterns),
        },
    }

    if attribution.best_match:
        best = attribution.best_match
        result["matched_group"] = best.group_name
        result["confidence"] = best.overall_score
        result["all_matches"] = [m.to_dict() for m in attribution.matches[:5]]

        # 评分细目
        result["scoring_rubric"] = {
            "technique_match": {
                "score": round(best.technique_score, 3),
                "weight": 0.35,
                "weighted": round(best.technique_score * 0.35, 3),
                "matched": best.matched_techniques,
                "count": len(best.matched_techniques),
            },
            "tool_match": {
                "score": round(best.tool_score, 3),
                "weight": 0.20,
                "weighted": round(best.tool_score * 0.20, 3),
                "matched": best.matched_tools,
                "count": len(best.matched_tools),
            },
            "kill_chain_match": {
                "score": round(best.kill_chain_score, 3),
                "weight": 0.15,
                "weighted": round(best.kill_chain_score * 0.15, 3),
            },
            "behavior_match": {
                "score": round(best.behavior_score, 3),
                "weight": 0.15,
                "weighted": round(best.behavior_score * 0.15, 3),
                "matched": best.matched_behaviors,
                "count": len(best.matched_behaviors),
            },
            "infrastructure_match": {
                "score": round(best.infrastructure_score, 3),
                "weight": 0.15,
                "weighted": round(best.infrastructure_score * 0.15, 3),
            },
            "total": round(best.overall_score, 3),
            "confidence": round(best.confidence, 3),
            "notes": best.notes,
        }

    return result


# ============================================================
# 辅助函数
# ============================================================

def _get_technique_name(technique_id: Optional[str]) -> Optional[str]:
    """获取 ATT&CK 技术名称。"""
    if not technique_id:
        return None
    return TECHNIQUE_NAMES.get(technique_id)


def _generate_summary(
    fingerprint: AttackerFingerprint,
    c2_analysis: InfrastructureAnalysis,
    attribution: AttributionResult,
    attack_chain: List[AttackStage],
    graph: AttackGraph,
) -> str:
    """生成溯源摘要。"""
    parts = []

    # 攻击链概述
    parts.append(
        f"基于 {len(graph.nodes)} 个实体和 {len(graph.edges)} 条关系的攻击图分析，"
        f"识别出 {len(attack_chain)} 个攻击阶段。"
    )

    # 指纹概述
    if fingerprint.ip_addresses:
        parts.append(f"涉及 {len(fingerprint.ip_addresses)} 个 IP 地址。")
    if fingerprint.host_ids:
        parts.append(f"影响 {len(fingerprint.host_ids)} 个主机。")
    if fingerprint.techniques:
        parts.append(f"使用 {len(fingerprint.techniques)} 种 ATT&CK 技术。")
    if fingerprint.tools_detected:
        parts.append(f"检测到工具: {', '.join(sorted(fingerprint.tools_detected))}。")

    # C2 概述
    if c2_analysis.c2_profiles:
        parts.append(c2_analysis.summary)

    # 归因概述
    if attribution.best_match:
        best = attribution.best_match
        parts.append(
            f"归因分析指向 {best.group_name}（置信度 {best.overall_score:.0%}），"
            f"匹配 {len(best.matched_techniques)} 个技术特征。"
        )
    else:
        parts.append("未能匹配到已知 APT 组织，可能为未知攻击者或数据不足。")

    return " ".join(parts)
