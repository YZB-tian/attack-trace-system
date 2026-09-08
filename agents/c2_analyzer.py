"""
C2 基础设施分析器
分析攻击者与 C2 服务器的关联信息，包括：
- C2 服务器识别
- 域名/IP 基础设施关联
- 通信模式分析
- 注册信息模拟分析
"""

from __future__ import annotations
import re
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from collections import Counter

from common.models import NormalizedEvent, Alert, AttackGraph, GraphNode, GraphEdge


@dataclass
class C2Profile:
    """C2 服务器画像。"""
    entity_id: str
    ip_addresses: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)

    # 通信模式
    beacon_intervals: List[float] = field(default_factory=list)  # 秒
    session_count: int = 0
    total_bytes_in: int = 0
    total_bytes_out: int = 0

    # 关联主机
    connected_hosts: Set[str] = field(default_factory=set)

    # 证据
    evidence_event_ids: Set[str] = field(default_factory=set)
    evidence_alert_ids: Set[str] = field(default_factory=set)

    # 置信度
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "ip_addresses": sorted(self.ip_addresses),
            "domains": sorted(self.domains),
            "ports": sorted(self.ports),
            "protocols": sorted(self.protocols),
            "beacon_intervals": self.beacon_intervals,
            "session_count": self.session_count,
            "total_bytes_in": self.total_bytes_in,
            "total_bytes_out": self.total_bytes_out,
            "connected_hosts": sorted(self.connected_hosts),
            "evidence_event_ids": sorted(self.evidence_event_ids),
            "evidence_alert_ids": sorted(self.evidence_alert_ids),
            "confidence": self.confidence,
        }


@dataclass
class InfrastructureAnalysis:
    """C2 基础设施分析结果。"""
    c2_profiles: List[C2Profile] = field(default_factory=list)
    domain_infrastructure: Dict[str, Any] = field(default_factory=dict)
    ip_correlation: Dict[str, Any] = field(default_factory=dict)
    communication_patterns: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "c2_profiles": [p.to_dict() for p in self.c2_profiles],
            "domain_infrastructure": self.domain_infrastructure,
            "ip_correlation": self.ip_correlation,
            "communication_patterns": self.communication_patterns,
            "summary": self.summary,
        }


# C2 通信特征检测模式
C2_INDICATORS = {
    "high_frequency_beacon": {
        "description": "Regular periodic connections suggesting beaconing",
        "min_sessions": 5,
        "max_interval_variance": 0.3,  # 30% 变异系数
    },
    "data_exfiltration": {
        "description": "Large outbound data transfers",
        "min_bytes_out": 1_000_000,  # 1MB
        "out_in_ratio": 10.0,
    },
    "encrypted_channel": {
        "description": "Encrypted communication on non-standard ports",
        "suspicious_ports": [443, 8443, 4443, 8080, 9999, 53],
    },
    "dns_tunneling": {
        "description": "DNS-based covert channel",
        "port": 53,
        "min_queries": 100,
    },
}


def analyze_c2_infrastructure(
    events: List[NormalizedEvent],
    alerts: List[Alert],
    graph: AttackGraph,
) -> InfrastructureAnalysis:
    """分析 C2 基础设施。"""
    analysis = InfrastructureAnalysis()

    # 1. 从攻击图中识别 C2 节点
    c2_nodes = _identify_c2_nodes(graph)
    c2_entity_ids = {n.id for n in c2_nodes}

    # 2. 从事件中提取 C2 通信
    c2_comms = _extract_c2_communications(events, c2_entity_ids, graph)

    # 3. 构建 C2 画像
    c2_profiles = _build_c2_profiles(c2_comms, graph, alerts)

    # 4. 分析基础设施关联
    domain_infra = _analyze_domain_infrastructure(events, c2_profiles)
    ip_corr = _analyze_ip_correlation(events, c2_profiles)
    comm_patterns = _analyze_communication_patterns(events, c2_profiles)

    # 5. 为每个 C2 画像计算置信度
    for profile in c2_profiles:
        profile.confidence = _calculate_c2_confidence(profile, alerts)

    analysis.c2_profiles = c2_profiles
    analysis.domain_infrastructure = domain_infra
    analysis.ip_correlation = ip_corr
    analysis.communication_patterns = comm_patterns
    analysis.summary = _generate_c2_summary(c2_profiles, domain_infra, comm_patterns)

    return analysis


def _identify_c2_nodes(graph: AttackGraph) -> List[GraphNode]:
    """从攻击图中识别 C2 节点。"""
    c2_nodes = []

    for node in graph.nodes:
        node_type = node.type.value if hasattr(node.type, 'value') else str(node.type)

        # 直接标记为 C2 的节点
        if node_type == "c2":
            c2_nodes.append(node)
            continue

        # 通过边关系推断 C2
        for edge in graph.edges:
            relation = edge.relation.value if hasattr(edge.relation, 'value') else str(edge.relation)
            if relation == "c2_communication" and edge.target == node.id:
                c2_nodes.append(node)
                break

        # 通过属性推断
        if node_type == "domain" or node_type == "ip":
            attrs = node.attributes
            if attrs.get("c2") or attrs.get("malicious") or attrs.get("suspicious"):
                c2_nodes.append(node)

    return c2_nodes


def _extract_c2_communications(
    events: List[NormalizedEvent],
    c2_entity_ids: Set[str],
    graph: AttackGraph,
) -> List[NormalizedEvent]:
    """提取与 C2 相关的通信事件。"""
    c2_ips: Set[str] = set()
    c2_domains: Set[str] = set()

    # 从攻击图中获取 C2 的 IP 和域名
    for node in graph.nodes:
        if node.id in c2_entity_ids:
            node_type = node.type.value if hasattr(node.type, 'value') else str(node.type)
            if node_type in ("c2", "ip"):
                if "ip" in node.attributes:
                    c2_ips.add(node.attributes["ip"])
            elif node_type == "domain":
                c2_domains.add(node.label)

    # 从事件中匹配 C2 通信
    c2_events = []
    for evt in events:
        # 匹配 IP
        if evt.src_ip in c2_ips or evt.dst_ip in c2_ips:
            c2_events.append(evt)
            continue

        # 匹配域名（从 raw_event）
        if isinstance(evt.raw_event, dict):
            for key in ["domain", "hostname", "server_name", "sni"]:
                if key in evt.raw_event and evt.raw_event[key] in c2_domains:
                    c2_events.append(evt)
                    break

        # 匹配 C2 相关边
        for edge in graph.edges:
            relation = edge.relation.value if hasattr(edge.relation, 'value') else str(edge.relation)
            if relation == "c2_communication":
                if edge.source == evt.host_id or edge.target == evt.host_id:
                    if evt.event_id in edge.evidence_event_ids:
                        c2_events.append(evt)
                        break

    return c2_events


def _build_c2_profiles(
    c2_events: List[NormalizedEvent],
    graph: AttackGraph,
    alerts: List[Alert],
) -> List[C2Profile]:
    """构建 C2 服务器画像。"""
    # 按目标 IP/主机分组
    profiles: Dict[str, C2Profile] = {}

    for evt in c2_events:
        # 确定 C2 端
        c2_key = evt.dst_ip or "unknown"

        if c2_key not in profiles:
            profiles[c2_key] = C2Profile(entity_id=f"c2_{c2_key}")

        profile = profiles[c2_key]
        profile.evidence_event_ids.add(evt.event_id)

        if evt.src_ip:
            profile.connected_hosts.add(evt.src_ip)
        if evt.host_id:
            profile.connected_hosts.add(evt.host_id)
        if evt.dst_ip:
            profile.ip_addresses.add(evt.dst_ip)
        if evt.dst_port:
            profile.ports.add(evt.dst_port)
        if evt.network:
            if evt.network.protocol:
                profile.protocols.add(evt.network.protocol)
            if evt.network.bytes_in:
                profile.total_bytes_in += evt.network.bytes_in
            if evt.network.bytes_out:
                profile.total_bytes_out += evt.network.bytes_out
            profile.session_count += 1

    # 从攻击图中补充 C2 信息
    for node in graph.nodes:
        node_type = node.type.value if hasattr(node.type, 'value') else str(node.type)
        if node_type == "c2":
            c2_key = node.attributes.get("ip", node.id)
            if c2_key not in profiles:
                profiles[c2_key] = C2Profile(entity_id=node.id)
            profile = profiles[c2_key]
            if "ip" in node.attributes:
                profile.ip_addresses.add(node.attributes["ip"])
            if "domain" in node.attributes:
                profile.domains.add(node.attributes["domain"])

    # 关联告警
    for alert in alerts:
        for profile in profiles.values():
            if any(h in profile.connected_hosts for h in alert.host_ids):
                profile.evidence_alert_ids.add(alert.alert_id)

    return list(profiles.values())


def _analyze_domain_infrastructure(
    events: List[NormalizedEvent],
    c2_profiles: List[C2Profile],
) -> Dict[str, Any]:
    """分析域名基础设施。"""
    all_domains: Set[str] = set()

    for profile in c2_profiles:
        all_domains.update(profile.domains)

    for evt in events:
        if isinstance(evt.raw_event, dict):
            for key in ["domain", "hostname", "server_name", "sni"]:
                if key in evt.raw_event and isinstance(evt.raw_event[key], str):
                    all_domains.add(evt.raw_event[key])

    # 域名分析
    domain_analysis = {}
    for domain in all_domains:
        parts = domain.split(".")
        domain_info = {
            "domain": domain,
            "tld": parts[-1] if len(parts) > 1 else "",
            "sld": parts[-2] if len(parts) > 1 else parts[0],
            "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else "",
            "is_ip": _is_ip_address(domain),
            "suspicious_indicators": [],
        }

        # 可疑指标
        if len(parts[0]) > 20:
            domain_info["suspicious_indicators"].append("long_subdomain")
        if any(c.isdigit() for c in parts[0]) and len(parts[0]) > 10:
            domain_info["suspicious_indicators"].append("random-looking_subdomain")
        if domain_info["tld"] in ("tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw"):
            domain_info["suspicious_indicators"].append("suspicious_tld")

        domain_analysis[domain] = domain_info

    return {
        "domains": domain_analysis,
        "total_domains": len(all_domains),
    }


def _analyze_ip_correlation(
    events: List[NormalizedEvent],
    c2_profiles: List[C2Profile],
) -> Dict[str, Any]:
    """分析 IP 基础设施关联。"""
    # 收集所有外部 IP
    internal_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168.")

    external_ips: Set[str] = set()
    c2_ips: Set[str] = set()

    for profile in c2_profiles:
        c2_ips.update(profile.ip_addresses)

    for evt in events:
        for ip in [evt.src_ip, evt.dst_ip]:
            if ip and not any(ip.startswith(p) for p in internal_prefixes):
                external_ips.add(ip)

    # IP 段分析
    ip_subnets: Dict[str, Set[str]] = {}
    for ip in external_ips | c2_ips:
        parts = ip.split(".")
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            ip_subnets.setdefault(subnet, set()).add(ip)

    return {
        "external_ips": sorted(external_ips),
        "c2_ips": sorted(c2_ips),
        "ip_subnets": {k: sorted(v) for k, v in ip_subnets.items()},
        "shared_subnets": {
            k: sorted(v) for k, v in ip_subnets.items()
            if len(v) > 1
        },
    }


def _analyze_communication_patterns(
    events: List[NormalizedEvent],
    c2_profiles: List[C2Profile],
) -> Dict[str, Any]:
    """分析通信模式。"""
    # 按时间统计通信
    hourly_comms: Counter = Counter()
    protocol_dist: Counter = Counter()
    port_dist: Counter = Counter()

    for evt in events:
        try:
            hour = int(evt.timestamp[11:13])
            hourly_comms[hour] += 1
        except (ValueError, IndexError):
            pass

        if evt.network:
            if evt.network.protocol:
                protocol_dist[evt.network.protocol] += 1
        if evt.dst_port:
            port_dist[evt.dst_port] += 1

    # 实际 beacon 间隔分析
    beacon_result = _analyze_beacon_timing(events, c2_profiles)

    # 数据外传检测
    exfil_result = _detect_data_exfiltration(events, c2_profiles)

    return {
        "hourly_distribution": dict(hourly_comms),
        "protocol_distribution": dict(protocol_dist),
        "port_distribution": dict(port_dist),
        "beacon_analysis": beacon_result,
        "exfiltration_analysis": exfil_result,
        "beacon_detected": beacon_result.get("detected", False),
        "total_sessions": sum(p.session_count for p in c2_profiles),
    }


def _analyze_beacon_timing(
    events: List[NormalizedEvent],
    c2_profiles: List[C2Profile],
) -> Dict[str, Any]:
    """分析 C2 通信的时间间隔，检测 beacon 模式。"""
    # 收集每个 C2 目标的通信时间戳
    c2_ips: Set[str] = set()
    for p in c2_profiles:
        c2_ips.update(p.ip_addresses)

    timestamps_by_target: Dict[str, List[float]] = {}

    for evt in events:
        target = evt.dst_ip or ""
        if target not in c2_ips:
            continue

        # 解析时间戳为 epoch 秒
        try:
            ts_str = evt.timestamp[:19]  # 取到秒
            from datetime import datetime
            dt = datetime.fromisoformat(ts_str)
            ts = dt.timestamp()
            timestamps_by_target.setdefault(target, []).append(ts)
        except (ValueError, IndexError):
            continue

    beacon_results = {}
    for target, timestamps in timestamps_by_target.items():
        if len(timestamps) < 3:
            beacon_results[target] = {"detected": False, "reason": "insufficient_data"}
            continue

        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        if not intervals:
            beacon_results[target] = {"detected": False, "reason": "no_intervals"}
            continue

        avg_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)

        # 计算变异系数 (CV = std / mean)
        if avg_interval > 0:
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            cv = std_dev / avg_interval
        else:
            cv = 1.0

        # beacon 判定：间隔相对稳定 (CV < 0.5) 且至少 3 个间隔
        detected = cv < 0.5 and len(intervals) >= 3 and avg_interval > 0

        # 如果 profile 存在，更新 beacon 间隔
        for profile in c2_profiles:
            if target in profile.ip_addresses:
                profile.beacon_intervals = intervals[:10]  # 保留前 10 个

        beacon_results[target] = {
            "detected": detected,
            "avg_interval_sec": round(avg_interval, 2),
            "min_interval_sec": round(min_interval, 2),
            "max_interval_sec": round(max_interval, 2),
            "coefficient_of_variation": round(cv, 3),
            "num_intervals": len(intervals),
            "regularity": "high" if cv < 0.2 else "medium" if cv < 0.5 else "low",
        }

    any_detected = any(r.get("detected") for r in beacon_results.values())
    return {
        "detected": any_detected,
        "targets": beacon_results,
    }


def _detect_data_exfiltration(
    events: List[NormalizedEvent],
    c2_profiles: List[C2Profile],
) -> Dict[str, Any]:
    """检测数据外传模式。"""
    c2_ips: Set[str] = set()
    for p in c2_profiles:
        c2_ips.update(p.ip_addresses)

    suspicious_transfers = []
    total_outbound_bytes = 0

    for evt in events:
        if evt.dst_ip not in c2_ips:
            continue
        if not evt.network:
            continue

        bytes_out = evt.network.bytes_out or 0
        bytes_in = evt.network.bytes_in or 0
        total_outbound_bytes += bytes_out

        # 大量出站数据
        if bytes_out > 100_000:  # > 100KB
            ratio = bytes_out / max(bytes_in, 1)
            suspicious_transfers.append({
                "event_id": evt.event_id,
                "timestamp": evt.timestamp,
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "ratio": round(ratio, 2),
                "host_id": evt.host_id,
                "severity": "high" if bytes_out > 1_000_000 else "medium",
            })

    return {
        "suspicious_transfers": suspicious_transfers,
        "total_outbound_bytes": total_outbound_bytes,
        "exfiltration_detected": len(suspicious_transfers) > 0,
    }


def _calculate_c2_confidence(profile: C2Profile, alerts: List[Alert]) -> float:
    """计算 C2 置信度。"""
    score = 0.0

    # 有多个主机连接 → 更可能是 C2
    if len(profile.connected_hosts) >= 3:
        score += 0.25
    elif len(profile.connected_hosts) >= 2:
        score += 0.15
    elif len(profile.connected_hosts) >= 1:
        score += 0.08

    # 有关联告警 → 增加置信度
    if len(profile.evidence_alert_ids) >= 3:
        score += 0.25
    elif len(profile.evidence_alert_ids) >= 1:
        score += 0.15

    # 使用非标准端口
    standard_ports = {80, 443, 8080}
    non_standard = profile.ports - standard_ports
    if non_standard:
        score += 0.08

    # 大量数据传输
    if profile.total_bytes_out > 5_000_000:
        score += 0.15
    elif profile.total_bytes_out > 1_000_000:
        score += 0.10
    elif profile.total_bytes_out > 100_000:
        score += 0.05

    # 多次会话
    if profile.session_count >= 10:
        score += 0.10
    elif profile.session_count >= 5:
        score += 0.05

    # Beacon 规则性（如果有间隔数据）
    if profile.beacon_intervals and len(profile.beacon_intervals) >= 2:
        intervals = profile.beacon_intervals
        avg = sum(intervals) / len(intervals)
        if avg > 0:
            variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
            cv = (variance ** 0.5) / avg
            if cv < 0.2:  # 高度规则
                score += 0.15
            elif cv < 0.5:  # 中度规则
                score += 0.08

    return min(score, 1.0)


def _is_ip_address(s: str) -> bool:
    """检查字符串是否为 IP 地址。"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, s))


def _generate_c2_summary(
    profiles: List[C2Profile],
    domain_infra: Dict[str, Any],
    comm_patterns: Dict[str, Any],
) -> str:
    """生成 C2 分析摘要。"""
    if not profiles:
        return "未发现 C2 基础设施。"

    parts = []
    parts.append(f"发现 {len(profiles)} 个可疑 C2 服务器。")

    high_conf = [p for p in profiles if p.confidence >= 0.5]
    if high_conf:
        parts.append(f"其中 {len(high_conf)} 个高置信度。")

    all_hosts = set()
    for p in profiles:
        all_hosts.update(p.connected_hosts)
    if all_hosts:
        parts.append(f"共 {len(all_hosts)} 个主机与 C2 通信。")

    # beacon 分析
    beacon = comm_patterns.get("beacon_analysis", {})
    if beacon.get("detected"):
        targets = beacon.get("targets", {})
        regular_targets = [t for t, r in targets.items() if r.get("detected")]
        if regular_targets:
            avg_intervals = [targets[t].get("avg_interval_sec", 0) for t in regular_targets]
            parts.append(
                f"检测到 {len(regular_targets)} 个目标的周期性 beacon 通信，"
                f"平均间隔 {sum(avg_intervals)/len(avg_intervals):.1f} 秒。"
            )
    elif comm_patterns.get("beacon_detected"):
        parts.append("检测到周期性通信模式（beacon）。")

    # 数据外传
    exfil = comm_patterns.get("exfiltration_analysis", {})
    if exfil.get("exfiltration_detected"):
        total_bytes = exfil.get("total_outbound_bytes", 0)
        transfers = exfil.get("suspicious_transfers", [])
        parts.append(f"检测到 {len(transfers)} 笔可疑数据外传，总出站 {total_bytes:,} 字节。")
    else:
        total_bytes = sum(p.total_bytes_out for p in profiles)
        if total_bytes > 0:
            parts.append(f"总出站数据量: {total_bytes:,} 字节。")

    return " ".join(parts)
