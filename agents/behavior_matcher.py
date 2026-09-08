"""
行为模式匹配器
将提取的攻击者指纹与已知 APT 组织的 TTP 进行匹配分析。

匹配维度：
1. 技术匹配：ATT&CK 技术 ID 重叠度
2. 工具匹配：已知工具使用重叠
3. 战术链匹配：攻击阶段顺序相似度
4. 行为特征匹配：命令模式、IOC 特征
5. 基础设施匹配：C2 通信模式
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from common.models import AttackGraph, Alert
from agents.apt_knowledge_base import APTGroup, APT_GROUPS, get_groups_by_technique, tactic_order
from agents.fingerprint_extractor import AttackerFingerprint


@dataclass
class MatchResult:
    """单个 APT 组织的匹配结果。"""
    group_name: str
    group_id: str
    overall_score: float  # 0.0 ~ 1.0

    # 各维度分数
    technique_score: float = 0.0
    tool_score: float = 0.0
    kill_chain_score: float = 0.0
    behavior_score: float = 0.0
    infrastructure_score: float = 0.0

    # 匹配详情
    matched_techniques: List[str] = field(default_factory=list)
    missing_techniques: List[str] = field(default_factory=list)
    matched_tools: List[str] = field(default_factory=list)
    matched_behaviors: List[str] = field(default_factory=list)

    confidence: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_name": self.group_name,
            "group_id": self.group_id,
            "overall_score": round(self.overall_score, 3),
            "technique_score": round(self.technique_score, 3),
            "tool_score": round(self.tool_score, 3),
            "kill_chain_score": round(self.kill_chain_score, 3),
            "behavior_score": round(self.behavior_score, 3),
            "infrastructure_score": round(self.infrastructure_score, 3),
            "matched_techniques": self.matched_techniques,
            "missing_techniques": self.missing_techniques[:10],  # 限制输出
            "matched_tools": self.matched_tools,
            "matched_behaviors": self.matched_behaviors,
            "confidence": round(self.confidence, 3),
            "notes": self.notes,
        }


@dataclass
class AttributionResult:
    """完整的归因分析结果。"""
    matches: List[MatchResult] = field(default_factory=list)
    best_match: Optional[MatchResult] = None
    analysis_summary: str = ""
    fingerprint_used: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matches": [m.to_dict() for m in self.matches],
            "best_match": self.best_match.to_dict() if self.best_match else None,
            "analysis_summary": self.analysis_summary,
            "fingerprint_used": self.fingerprint_used,
        }


# 权重配置
MATCH_WEIGHTS = {
    "technique": 0.35,
    "tool": 0.20,
    "kill_chain": 0.15,
    "behavior": 0.15,
    "infrastructure": 0.15,
}

# 最低匹配阈值
MIN_TECHNIQUE_MATCH_RATIO = 0.15  # 至少匹配 15% 的技术


def match_apt_groups(
    fingerprint: AttackerFingerprint,
    graph: AttackGraph,
    alerts: List[Alert],
) -> AttributionResult:
    """将攻击者指纹与所有已知 APT 组织进行匹配。"""
    results = AttributionResult()
    results.fingerprint_used = fingerprint.to_dict()

    for group_name, group in APT_GROUPS.items():
        match = _match_single_group(fingerprint, group, graph, alerts)
        if match.overall_score > 0:
            results.matches.append(match)

    # 按分数排序
    results.matches.sort(key=lambda m: m.overall_score, reverse=True)

    # 设置最佳匹配
    if results.matches and results.matches[0].overall_score >= 0.2:
        results.best_match = results.matches[0]

    # 生成摘要
    results.analysis_summary = _generate_attribution_summary(results)

    return results


def _match_single_group(
    fingerprint: AttackerFingerprint,
    group: APTGroup,
    graph: AttackGraph,
    alerts: List[Alert],
) -> MatchResult:
    """与单个 APT 组织进行匹配。"""
    result = MatchResult(
        group_name=group.name,
        group_id=group.group_id,
        overall_score=0.0,
    )

    # 1. 技术匹配
    result.technique_score, result.matched_techniques, result.missing_techniques = \
        _match_techniques(fingerprint, group)

    # 2. 工具匹配
    result.tool_score, result.matched_tools = _match_tools(fingerprint, group)

    # 3. 战术链匹配
    result.kill_chain_score = _match_kill_chain(fingerprint, group, graph, alerts)

    # 4. 行为特征匹配
    result.behavior_score, result.matched_behaviors = _match_behaviors(fingerprint, group)

    # 5. 基础设施匹配
    result.infrastructure_score = _match_infrastructure(fingerprint, group)

    # 计算总分
    result.overall_score = (
        result.technique_score * MATCH_WEIGHTS["technique"] +
        result.tool_score * MATCH_WEIGHTS["tool"] +
        result.kill_chain_score * MATCH_WEIGHTS["kill_chain"] +
        result.behavior_score * MATCH_WEIGHTS["behavior"] +
        result.infrastructure_score * MATCH_WEIGHTS["infrastructure"]
    )

    # 计算置信度
    result.confidence = _calculate_match_confidence(result, fingerprint)

    # 添加备注
    if result.overall_score >= 0.5:
        result.notes.append("高置信度匹配")
    elif result.overall_score >= 0.3:
        result.notes.append("中等置信度匹配")
    elif result.overall_score >= 0.15:
        result.notes.append("低置信度匹配")

    return result


def _match_techniques(
    fp: AttackerFingerprint,
    group: APTGroup,
) -> tuple[float, List[str], List[str]]:
    """匹配 ATT&CK 技术。"""
    if not fp.techniques or not group.techniques:
        return 0.0, [], []

    fp_set = set(fp.techniques)
    group_set = set(group.techniques)

    # 精确匹配
    exact_matches = fp_set & group_set

    # 部分匹配（父技术匹配子技术）
    partial_matches = set()
    for fp_tech in fp_set:
        for group_tech in group_set:
            # T1059 匹配 T1059.001
            if fp_tech.startswith(group_tech) or group_tech.startswith(fp_tech):
                partial_matches.add(fp_tech)
                partial_matches.add(group_tech)

    all_matches = exact_matches | partial_matches
    matched = sorted(all_matches & group_set)
    missing = sorted(group_set - all_matches)

    if not group_set:
        return 0.0, [], []

    # 匹配比例
    match_ratio = len(all_matches) / len(group_set)

    # 如果观察到的技术太少，降低权重
    if len(fp.techniques) < 3:
        match_ratio *= 0.5

    return match_ratio, matched, missing


def _match_tools(
    fp: AttackerFingerprint,
    group: APTGroup,
) -> tuple[float, List[str]]:
    """匹配已知工具（支持模糊匹配）。"""
    if not fp.tools_detected and not group.known_tools:
        return 0.0, []

    matched = []
    for tool in fp.tools_detected:
        tool_lower = tool.lower().replace("_", " ").replace("-", " ")
        tool_words = set(w for w in tool_lower.split() if len(w) > 2)

        for known in group.known_tools:
            known_lower = known.lower().replace("_", " ").replace("-", " ")
            known_words = set(w for w in known_lower.split() if len(w) > 2)

            # 精确包含匹配
            if tool_lower in known_lower or known_lower in tool_lower:
                matched.append(tool)
                break

            # 单词级模糊匹配
            if tool_words and known_words:
                overlap = tool_words & known_words
                if overlap and len(overlap) / min(len(tool_words), len(known_words)) >= 0.5:
                    matched.append(tool)
                    break

            # 字符串相似度匹配（简单版：公共子串比例）
            common_len = _longest_common_substr_len(tool_lower, known_lower)
            if common_len >= min(len(tool_lower), len(known_lower)) * 0.6:
                matched.append(tool)
                break

    if not group.known_tools:
        return 0.0, []

    score = len(matched) / max(len(group.known_tools), 1)
    return min(score, 1.0), sorted(set(matched))


def _longest_common_substr_len(s1: str, s2: str) -> int:
    """计算两个字符串的最长公共子串长度。"""
    m, n = len(s1), len(s2)
    if m == 0 or n == 0:
        return 0
    max_len = 0
    dp = [0] * (n + 1)
    for i in range(1, m + 1):
        prev = 0
        for j in range(1, n + 1):
            temp = dp[j]
            if s1[i-1] == s2[j-1]:
                dp[j] = prev + 1
                max_len = max(max_len, dp[j])
            else:
                dp[j] = 0
            prev = temp
    return max_len


def _match_kill_chain(
    fp: AttackerFingerprint,
    group: APTGroup,
    graph: AttackGraph,
    alerts: list | None = None,
) -> float:
    """匹配攻击链阶段顺序。"""
    if not group.typical_kill_chain:
        return 0.0

    # 从攻击图中提取实际攻击链
    observed_tactics = set()
    for edge in graph.edges:
        relation = edge.relation.value if hasattr(edge.relation, 'value') else str(edge.relation)
        # 映射关系到战术
        tactic = _relation_to_tactic(relation)
        if tactic:
            observed_tactics.add(tactic)

    # 从告警中提取战术
    if alerts:
        for alert in alerts:
            if alert.mitre and alert.mitre.tactic:
                observed_tactics.add(alert.mitre.tactic)

    if not observed_tactics:
        return 0.0

    # 计算战术覆盖度
    group_tactics = set(group.typical_kill_chain)
    overlap = observed_tactics & group_tactics
    coverage = len(overlap) / len(group_tactics) if group_tactics else 0.0

    # 计算顺序相似度（简化版）
    observed_ordered = sorted(observed_tactics, key=tactic_order)
    group_ordered = group.typical_kill_chain

    # 计算最长公共子序列比例
    lcs_len = _lcs_length(observed_ordered, group_ordered)
    order_similarity = lcs_len / max(len(group_ordered), 1)

    return (coverage * 0.6 + order_similarity * 0.4)


def _match_behaviors(
    fp: AttackerFingerprint,
    group: APTGroup,
) -> tuple[float, List[str]]:
    """匹配行为特征关键词。"""
    if not group.behavior_keywords:
        return 0.0, []

    # 合并搜索文本
    search_parts = []
    search_parts.extend(fp.command_patterns)
    search_parts.extend(fp.process_names)
    search_parts.extend(fp.actions)
    search_text = " ".join(search_parts).lower()

    matched = []
    for keyword in group.behavior_keywords:
        if keyword.lower() in search_text:
            matched.append(keyword)

    if not group.behavior_keywords:
        return 0.0, []

    score = len(matched) / len(group.behavior_keywords)
    return min(score, 1.0), sorted(matched)


def _match_infrastructure(
    fp: AttackerFingerprint,
    group: APTGroup,
) -> float:
    """匹配基础设施特征。"""
    score = 0.0
    checks = 0

    c2 = group.c2_patterns
    if not c2:
        return 0.0

    # 端口匹配
    if "port_preferences" in c2 and fp.ports:
        checks += 1
        preferred = set(c2["port_preferences"])
        overlap = fp.ports & preferred
        if overlap:
            score += len(overlap) / len(preferred)

    # 协议匹配
    if "protocols" in c2 and fp.protocols:
        checks += 1
        preferred = set(c2["protocols"])
        overlap = fp.protocols & preferred
        if overlap:
            score += len(overlap) / len(preferred)

    # 动态 DNS 检测
    if c2.get("uses_dynamic_dns") and fp.domains:
        checks += 1
        ddns_providers = ["no-ip", "duckdns", "dynu", "freedns", "hopto", "ngrok"]
        for domain in fp.domains:
            if any(provider in domain.lower() for provider in ddns_providers):
                score += 1.0
                break

    return score / max(checks, 1)


def _calculate_match_confidence(result: MatchResult, fp: AttackerFingerprint) -> float:
    """计算匹配置信度。"""
    base = result.overall_score

    # 数据量调整
    data_points = len(fp.techniques) + len(fp.tools_detected) + len(fp.actions)
    if data_points < 3:
        base *= 0.5  # 数据太少，降低置信度
    elif data_points >= 10:
        base *= 1.1  # 数据充分，略微提升

    return min(base, 1.0)


def _relation_to_tactic(relation: str) -> Optional[str]:
    """将攻击图边关系映射到 ATT&CK 战术。"""
    mapping = {
        "initial_access": "Initial Access",
        "process_spawn": "Execution",
        "file_access": "Collection",
        "network_connect": "Command and Control",
        "lateral_movement": "Lateral Movement",
        "privilege_escalation": "Privilege Escalation",
        "c2_communication": "Command and Control",
        "data_access": "Collection",
        "data_exfiltration": "Exfiltration",
        "login": "Credential Access",
    }
    return mapping.get(relation)


def _lcs_length(seq1: List[str], seq2: List[str]) -> int:
    """计算最长公共子序列长度。"""
    m, n = len(seq1), len(seq2)
    if m == 0 or n == 0:
        return 0

    # 简化版，只计算长度
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq1[i-1].lower() == seq2[j-1].lower():
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    return dp[m][n]


def _generate_attribution_summary(result: AttributionResult) -> str:
    """生成归因分析摘要。"""
    if not result.matches:
        return "未找到与已知 APT 组织的匹配。攻击者可能使用了未知的 TTP，或者数据不足以进行归因。"

    best = result.matches[0]
    parts = []

    if best.overall_score >= 0.5:
        parts.append(f"高置信度匹配到 {best.group_name}（{best.group_id}）。")
    elif best.overall_score >= 0.3:
        parts.append(f"中等置信度匹配到 {best.group_name}（{best.group_id}）。")
    elif best.overall_score >= 0.15:
        parts.append(f"低置信度匹配到 {best.group_name}（{best.group_id}）。")
    else:
        parts.append(f"微弱匹配到 {best.group_name}（{best.group_id}），仅供参考。")

    if best.matched_techniques:
        parts.append(f"匹配 {len(best.matched_techniques)} 个 ATT&CK 技术。")
    if best.matched_tools:
        parts.append(f"使用工具: {', '.join(best.matched_tools)}。")

    # 列出前 3 个匹配
    if len(result.matches) > 1:
        others = result.matches[1:3]
        other_names = [f"{m.group_name}({m.overall_score:.2f})" for m in others]
        parts.append(f"其他候选: {', '.join(other_names)}。")

    return " ".join(parts)
