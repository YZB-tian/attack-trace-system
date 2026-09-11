"""
agents 模块单元测试

测试内容：
1. 指纹提取器
2. C2 基础设施分析
3. 行为模式匹配
4. 主服务 (analyze_trace)
5. APT 知识库
"""

import pytest
from typing import List

from common.models import (
    NormalizedEvent,
    Alert,
    AttackGraph,
    GraphNode,
    GraphEdge,
    TraceResult,
    ProcessInfo,
    EventObject,
    NetworkInfo,
    MitreMapping,
)
from common.enums import SourceType, Severity, AlertStatus, NodeType, EdgeRelation
from common.id_utils import new_id
from common.time_utils import now_iso

from agents.fingerprint_extractor import (
    AttackerFingerprint,
    extract_fingerprint_from_events,
    extract_fingerprint_from_alerts,
    extract_fingerprint_from_graph,
    merge_fingerprints,
    TOOL_SIGNATURES,
)
from agents.c2_analyzer import (
    analyze_c2_infrastructure,
    C2Profile,
)
from agents.behavior_matcher import (
    match_apt_groups,
    AttributionResult,
)
from agents.apt_knowledge_base import (
    APT_GROUPS,
    get_apt_group,
    get_groups_by_technique,
    get_all_techniques,
    ATTACK_TACTIC_ORDER,
    tactic_order,
)
from agents.service import analyze_trace


# ============================================================
# 测试数据 fixtures
# ============================================================

@pytest.fixture
def sample_events() -> List[NormalizedEvent]:
    """创建测试用事件列表。"""
    return [
        NormalizedEvent(
            event_id="evt_test_001",
            task_id="task_test_001",
            timestamp="2024-03-06T11:20:15+08:00",
            source_type=SourceType.BOUNDARY_LOG,
            source="firewall",
            host_id="firewall01",
            src_ip="10.10.0.10",
            src_port=49832,
            dst_ip="10.10.1.10",
            dst_port=80,
            action="network_connect",
            network=NetworkInfo(
                protocol="tcp",
                direction="inbound",
                bytes_in=2048,
                bytes_out=512,
                session_id="sess_001",
            ),
            labels=["initial_access", "exploit"],
        ),
        NormalizedEvent(
            event_id="evt_test_002",
            task_id="task_test_001",
            timestamp="2024-03-06T11:20:18+08:00",
            source_type=SourceType.HOST_BEHAVIOR,
            source="auditd",
            host_id="webserver01",
            user="www-data",
            action="process_create",
            process=ProcessInfo(
                pid=12341,
                ppid=1200,
                name="sh",
                path="/bin/sh",
            ),
            object=EventObject(type="process", name="sh", path="/bin/sh"),
            labels=["shell", "post_exploit"],
            raw_event={"command_line": "sh -c id"},
        ),
        NormalizedEvent(
            event_id="evt_test_003",
            task_id="task_test_001",
            timestamp="2024-03-06T11:25:00+08:00",
            source_type=SourceType.HOST_BEHAVIOR,
            source="auditd",
            host_id="webserver01",
            src_ip="10.10.1.10",
            dst_ip="10.10.0.20",
            dst_port=443,
            action="network_connect",
            process=ProcessInfo(pid=12410, name="curl", path="/usr/bin/curl"),
            network=NetworkInfo(
                protocol="tcp",
                direction="outbound",
                bytes_in=1024,
                bytes_out=256,
                session_id="sess_c2_001",
            ),
            labels=["c2_communication", "beacon"],
            raw_event={"command_line": "curl -k https://10.10.0.20/beacon", "domain": "c2server01.local"},
        ),
    ]


@pytest.fixture
def sample_alerts() -> List[Alert]:
    """创建测试用告警列表。"""
    return [
        Alert(
            alert_id="alert_test_001",
            task_id="task_test_001",
            timestamp_start="2024-03-06T11:20:15+08:00",
            event_ids=["evt_test_001", "evt_test_002"],
            host_ids=["firewall01", "webserver01"],
            severity=Severity.CRITICAL,
            rule_id="DET-INIT-001",
            rule_name="Nginx Exploit Detected",
            description="Detected exploitation of Nginx vulnerability",
            mitre=MitreMapping(
                tactic="Initial Access",
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
            ),
            confidence=0.95,
            detector="rule-engine",
            status=AlertStatus.CONFIRMED,
        ),
        Alert(
            alert_id="alert_test_002",
            task_id="task_test_001",
            timestamp_start="2024-03-06T11:25:00+08:00",
            event_ids=["evt_test_003"],
            host_ids=["webserver01"],
            severity=Severity.HIGH,
            rule_id="DET-C2-001",
            rule_name="C2 Beacon Communication",
            description="Periodic HTTPS connections to C2 server detected",
            mitre=MitreMapping(
                tactic="Command and Control",
                technique_id="T1071.001",
                technique_name="Web Protocols",
            ),
            confidence=0.88,
            detector="network-anomaly",
            status=AlertStatus.CONFIRMED,
        ),
    ]


@pytest.fixture
def sample_graph() -> AttackGraph:
    """创建测试用攻击图。"""
    return AttackGraph(
        graph_id="graph_test_001",
        task_id="task_test_001",
        generated_at=now_iso(),
        nodes=[
            GraphNode(
                id="attacker01",
                type=NodeType.HOST,
                label="External Attacker",
                attributes={"ip": "10.10.0.10", "zone": "external"},
            ),
            GraphNode(
                id="c2server01",
                type=NodeType.C2,
                label="C2 Server",
                attributes={"ip": "10.10.0.20", "domain": "c2server01.local"},
            ),
            GraphNode(
                id="webserver01",
                type=NodeType.HOST,
                label="Web Server",
                attributes={"ip": "10.10.1.10", "zone": "dmz"},
            ),
            GraphNode(
                id="coreserver01",
                type=NodeType.HOST,
                label="Core Server",
                attributes={"ip": "10.10.3.10", "zone": "server"},
            ),
        ],
        edges=[
            GraphEdge(
                id="edge_001",
                source="attacker01",
                target="webserver01",
                relation=EdgeRelation.INITIAL_ACCESS,
                timestamp="2024-03-06T11:20:15+08:00",
                technique_id="T1190",
                evidence_event_ids=["evt_test_001"],
                evidence_alert_ids=["alert_test_001"],
                confidence=0.95,
            ),
            GraphEdge(
                id="edge_002",
                source="webserver01",
                target="c2server01",
                relation=EdgeRelation.C2_COMMUNICATION,
                timestamp="2024-03-06T11:25:00+08:00",
                technique_id="T1071.001",
                evidence_event_ids=["evt_test_003"],
                evidence_alert_ids=["alert_test_002"],
                confidence=0.88,
            ),
            GraphEdge(
                id="edge_003",
                source="webserver01",
                target="coreserver01",
                relation=EdgeRelation.LATERAL_MOVEMENT,
                timestamp="2024-03-06T11:35:00+08:00",
                technique_id="T1021.004",
                evidence_event_ids=["evt_test_004"],
                evidence_alert_ids=[],
                confidence=0.93,
            ),
        ],
    )


# ============================================================
# 指纹提取器测试
# ============================================================

class TestFingerprintExtractor:

    def test_extract_from_events_basic(self, sample_events):
        """测试从事件中提取基本 IOC。"""
        fp = extract_fingerprint_from_events(sample_events)

        assert "10.10.0.10" in fp.ip_addresses
        assert "10.10.1.10" in fp.ip_addresses
        assert "10.10.0.20" in fp.ip_addresses
        assert 80 in fp.ports
        assert 443 in fp.ports
        assert "tcp" in fp.protocols
        assert "www-data" in fp.usernames
        assert "webserver01" in fp.host_ids
        assert "firewall01" in fp.host_ids

    def test_extract_from_events_process(self, sample_events):
        """测试从事件中提取进程信息。"""
        fp = extract_fingerprint_from_events(sample_events)

        assert "sh" in fp.process_names
        assert "curl" in fp.process_names
        assert "/bin/sh" in fp.process_paths
        assert "/usr/bin/curl" in fp.process_paths

    def test_extract_from_events_time(self, sample_events):
        """测试时间提取。"""
        fp = extract_fingerprint_from_events(sample_events)

        assert fp.first_seen == "2024-03-06T11:20:15+08:00"
        assert fp.last_seen == "2024-03-06T11:25:00+08:00"
        assert 11 in fp.active_hours

    def test_extract_from_events_raw_event(self, sample_events):
        """测试从 raw_event 中提取信息。"""
        fp = extract_fingerprint_from_events(sample_events)

        # curl 事件的 raw_event 包含 domain
        assert "c2server01.local" in fp.domains

    def test_extract_from_alerts(self, sample_alerts):
        """测试从告警中提取信息。"""
        fp = extract_fingerprint_from_alerts(sample_alerts)

        assert "alert_test_001" in fp.evidence_alert_ids
        assert "alert_test_002" in fp.evidence_alert_ids
        assert "T1190" in fp.techniques
        assert "T1071.001" in fp.techniques
        assert "Initial Access" in fp.tactics
        assert "Command and Control" in fp.tactics

    def test_extract_from_graph(self, sample_graph):
        """测试从攻击图中提取信息。"""
        fp = extract_fingerprint_from_graph(sample_graph)

        assert "attacker01" in fp.host_ids
        assert "webserver01" in fp.host_ids
        assert "10.10.0.10" in fp.ip_addresses
        assert "10.10.0.20" in fp.ip_addresses
        assert "c2server01.local" in fp.domains
        assert "T1190" in fp.techniques
        assert "T1071.001" in fp.techniques

    def test_merge_fingerprints(self, sample_events, sample_alerts, sample_graph):
        """测试指纹合并。"""
        fp1 = extract_fingerprint_from_events(sample_events)
        fp2 = extract_fingerprint_from_alerts(sample_alerts)
        fp3 = extract_fingerprint_from_graph(sample_graph)

        merged = merge_fingerprints([fp1, fp2, fp3])

        # 应包含所有来源的数据
        assert len(merged.ip_addresses) >= 3
        assert len(merged.techniques) >= 3
        assert len(merged.host_ids) >= 4
        assert len(merged.evidence_event_ids) >= 3
        assert len(merged.evidence_alert_ids) >= 2

    def test_tool_detection_web_shell(self):
        """测试 Web Shell 工具检测。"""
        events = [
            NormalizedEvent(
                event_id="evt_ws_001",
                task_id="task_001",
                timestamp="2024-01-01T00:00:00+08:00",
                source_type=SourceType.HOST_BEHAVIOR,
                source="auditd",
                host_id="web01",
                user="www-data",
                action="process_create",
                process=ProcessInfo(pid=100, ppid=1, name="w3wp.exe", path="C:\\Windows\\System32\\inetsrv\\w3wp.exe"),
                raw_event={"command_line": "cmd.exe /c whoami"},
            ),
        ]
        fp = extract_fingerprint_from_events(events)
        assert "web_shell" in fp.tools_detected

    def test_fingerprint_to_dict(self, sample_events):
        """测试指纹转字典。"""
        fp = extract_fingerprint_from_events(sample_events)
        d = fp.to_dict()

        assert "network_ioc" in d
        assert "host_ioc" in d
        assert "behavior" in d
        assert "temporal" in d
        assert isinstance(d["network_ioc"]["ip_addresses"], list)


# ============================================================
# C2 分析器测试
# ============================================================

class TestC2Analyzer:

    def test_c2_analysis_basic(self, sample_events, sample_alerts, sample_graph):
        """测试基本 C2 分析。"""
        analysis = analyze_c2_infrastructure(sample_events, sample_alerts, sample_graph)

        # 应该检测到 C2
        assert len(analysis.c2_profiles) > 0
        assert analysis.summary != ""

    def test_c2_profile_confidence(self, sample_events, sample_alerts, sample_graph):
        """测试 C2 置信度计算。"""
        analysis = analyze_c2_infrastructure(sample_events, sample_alerts, sample_graph)

        for profile in analysis.c2_profiles:
            assert 0.0 <= profile.confidence <= 1.0

    def test_c2_communication_patterns(self, sample_events, sample_alerts, sample_graph):
        """测试通信模式分析。"""
        analysis = analyze_c2_infrastructure(sample_events, sample_alerts, sample_graph)

        assert "hourly_distribution" in analysis.communication_patterns
        assert "protocol_distribution" in analysis.communication_patterns


# ============================================================
# 行为匹配器测试
# ============================================================

class TestBehaviorMatcher:

    def test_match_apt_groups(self, sample_events, sample_alerts, sample_graph):
        """测试 APT 组织匹配。"""
        fp = extract_fingerprint_from_events(sample_events)
        fp_alerts = extract_fingerprint_from_alerts(sample_alerts)
        fp_graph = extract_fingerprint_from_graph(sample_graph)
        merged = merge_fingerprints([fp, fp_alerts, fp_graph])

        result = match_apt_groups(merged, sample_graph, sample_alerts)

        assert isinstance(result, AttributionResult)
        assert len(result.matches) > 0
        assert result.analysis_summary != ""

    def test_match_result_structure(self, sample_events, sample_alerts, sample_graph):
        """测试匹配结果结构。"""
        fp = extract_fingerprint_from_events(sample_events)
        result = match_apt_groups(fp, sample_graph, sample_alerts)

        for match in result.matches:
            assert 0.0 <= match.overall_score <= 1.0
            assert 0.0 <= match.technique_score <= 1.0
            assert 0.0 <= match.tool_score <= 1.0
            assert match.group_name in [g.name for g in APT_GROUPS.values()]

    def test_attribution_dict_serializable(self, sample_events, sample_alerts, sample_graph):
        """测试归因结果可序列化。"""
        fp = merge_fingerprints([
            extract_fingerprint_from_events(sample_events),
            extract_fingerprint_from_alerts(sample_alerts),
            extract_fingerprint_from_graph(sample_graph),
        ])
        result = match_apt_groups(fp, sample_graph, sample_alerts)

        d = result.to_dict()
        assert "matches" in d
        assert "best_match" in d
        assert "analysis_summary" in d


# ============================================================
# APT 知识库测试
# ============================================================

class TestAPTKnowledgeBase:

    def test_apt_groups_exist(self):
        """测试 APT 组织数据存在。"""
        assert len(APT_GROUPS) >= 5
        assert "APT28" in APT_GROUPS
        assert "APT29" in APT_GROUPS

    def test_get_apt_group_by_name(self):
        """测试按名称查找 APT 组织。"""
        group = get_apt_group("APT28")
        assert group is not None
        assert group.name == "APT28"

    def test_get_apt_group_by_alias(self):
        """测试按别名查找 APT 组织。"""
        group = get_apt_group("Fancy Bear")
        assert group is not None
        assert group.name == "APT28"

    def test_get_groups_by_technique(self):
        """测试按技术查找 APT 组织。"""
        groups = get_groups_by_technique("T1059.001")  # PowerShell
        assert len(groups) >= 3  # APT28, APT29, APT41 等都用 PowerShell

    def test_technique_mapping(self):
        """测试技术映射完整性。"""
        tech_map = get_all_techniques()
        assert len(tech_map) > 0
        assert "T1190" in tech_map  # Exploit Public-Facing Application

    def test_tactic_order(self):
        """测试战术顺序。"""
        assert tactic_order("Initial Access") < tactic_order("Execution")
        assert tactic_order("Execution") < tactic_order("Exfiltration")
        assert tactic_order("Unknown") == 999


# ============================================================
# 主服务测试
# ============================================================

class TestAnalyzeTrace:

    def test_analyze_trace_returns_trace_result(self, sample_events, sample_alerts, sample_graph):
        """测试 analyze_trace 返回 TraceResult。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)

        assert isinstance(result, TraceResult)
        assert result.trace_id.startswith("trace_")
        assert result.task_id == "task_test_001"
        assert result.status == "completed"
        assert result.generated_at is not None

    def test_analyze_trace_attack_chain(self, sample_events, sample_alerts, sample_graph):
        """测试攻击链构建。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)

        assert len(result.attack_chain) > 0
        for stage in result.attack_chain:
            assert stage.order >= 1
            assert stage.tactic != ""
            assert stage.confidence >= 0.0

    def test_analyze_trace_attribution(self, sample_events, sample_alerts, sample_graph):
        """测试归因信息。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)

        assert "matched_group" in result.attribution
        assert "confidence" in result.attribution

    def test_analyze_trace_c2(self, sample_events, sample_alerts, sample_graph):
        """测试 C2 识别。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)

        assert len(result.suspected_c2_entity_ids) > 0

    def test_analyze_trace_evidence(self, sample_events, sample_alerts, sample_graph):
        """测试证据保留。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)

        assert len(result.evidence_event_ids) > 0
        assert len(result.evidence_alert_ids) > 0

    def test_analyze_trace_schema_compliance(self, sample_events, sample_alerts, sample_graph):
        """测试 TraceResult 符合 schema。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)
        d = result.model_dump(mode="json")

        assert d["schema_version"] == "1.0"
        assert d["trace_id"].startswith("trace_")
        assert d["task_id"].startswith("task_")
        assert isinstance(d["attack_chain"], list)
        assert isinstance(d["suspected_c2_entity_ids"], list)
        assert isinstance(d["attribution"], dict)

    def test_analyze_trace_with_empty_inputs(self):
        """测试空输入处理。"""
        graph = AttackGraph(
            graph_id="graph_empty",
            task_id="task_empty",
            generated_at=now_iso(),
        )
        result = analyze_trace(graph)

        assert isinstance(result, TraceResult)
        assert result.status == "completed"

    def test_analyze_trace_summary_not_empty(self, sample_events, sample_alerts, sample_graph):
        """测试摘要非空。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)
        assert len(result.summary) > 10


# ============================================================
# DARPA E3 集成测试
# ============================================================

class TestDarpaE3Integration:

    @pytest.fixture
    def darpa_data(self):
        """加载 DARPA E3 测试数据。"""
        from testdata.darpa_e3_dataset import (
            get_darpa_e3_events,
            get_darpa_e3_alerts,
            get_darpa_e3_attack_graph,
        )

        events_raw = get_darpa_e3_events()
        alerts_raw = get_darpa_e3_alerts()
        graph_raw = get_darpa_e3_attack_graph()

        events = [NormalizedEvent.model_validate(e) for e in events_raw]
        alerts = [Alert.model_validate(a) for a in alerts_raw]
        graph = AttackGraph.model_validate(graph_raw)

        return events, alerts, graph

    def test_darpa_e3_full_pipeline(self, darpa_data):
        """测试 DARPA E3 数据的完整溯源流程。"""
        events, alerts, graph = darpa_data

        result = analyze_trace(graph, alerts, events)

        assert isinstance(result, TraceResult)
        assert result.status == "completed"
        assert len(result.attack_chain) >= 3  # 至少 3 个攻击阶段
        assert len(result.evidence_event_ids) >= 10
        assert len(result.evidence_alert_ids) >= 5

    def test_darpa_e3_c2_detection(self, darpa_data):
        """测试 C2 服务器检测。"""
        events, alerts, graph = darpa_data

        result = analyze_trace(graph, alerts, events)

        # 应该检测到 c2server01
        c2_ids = result.suspected_c2_entity_ids
        assert any("c2" in c2.lower() for c2 in c2_ids) or len(c2_ids) > 0

    def test_darpa_e3_attribution(self, darpa_data):
        """测试 APT 归因。"""
        events, alerts, graph = darpa_data

        result = analyze_trace(graph, alerts, events)

        assert "matched_group" in result.attribution
        # DARPA E3 CADETS 攻击模拟了 Nginx 漏洞利用 + 横向移动 + 数据外传
        # 应该能匹配到某些 APT 组织

    def test_darpa_e3_initial_access(self, darpa_data):
        """测试初始入侵点识别。"""
        events, alerts, graph = darpa_data

        result = analyze_trace(graph, alerts, events)

        # 初始入侵点应该是 webserver01（通过 Nginx 漏洞）
        assert result.initial_access_entity_id is not None

    def test_darpa_e3_schema_validation(self, darpa_data):
        """测试 DARPA E3 结果符合 schema。"""
        events, alerts, graph = darpa_data

        result = analyze_trace(graph, alerts, events)
        d = result.model_dump(mode="json")

        # 验证必需字段
        assert "schema_version" in d
        assert "trace_id" in d
        assert "task_id" in d
        assert "generated_at" in d
        assert "status" in d
        assert "summary" in d
        assert "attack_chain" in d
        assert "attribution" in d
        assert "evidence_event_ids" in d
        assert "evidence_alert_ids" in d

        # 验证 trace_id 格式
        assert d["trace_id"].startswith("trace_")

        # 验证 attack_chain 中每个 stage 的必需字段
        for stage in d["attack_chain"]:
            assert "order" in stage
            assert "tactic" in stage
            assert "title" in stage
            assert "description" in stage
            assert "entity_ids" in stage
            assert "evidence_event_ids" in stage
            assert "evidence_alert_ids" in stage
            assert "confidence" in stage

    def test_darpa_e3_scoring_rubric(self, darpa_data):
        """测试归因评分细目。"""
        events, alerts, graph = darpa_data
        result = analyze_trace(graph, alerts, events)

        rubric = result.attribution.get("scoring_rubric", {})
        if result.attribution.get("matched_group"):
            # 有匹配时应有评分细目
            assert "technique_match" in rubric
            assert "tool_match" in rubric
            assert "kill_chain_match" in rubric
            assert "behavior_match" in rubric
            assert "infrastructure_match" in rubric
            assert "total" in rubric
            assert "confidence" in rubric

            # 验证加权分数计算
            tech = rubric["technique_match"]
            assert tech["weight"] == 0.35
            assert abs(tech["weighted"] - tech["score"] * 0.35) < 0.001

    def test_darpa_e3_attack_chain_stages(self, darpa_data):
        """测试攻击链阶段质量。"""
        events, alerts, graph = darpa_data
        result = analyze_trace(graph, alerts, events)

        # 应该有多个阶段
        assert len(result.attack_chain) >= 4

        # 阶段应该按顺序编号
        for i, stage in enumerate(result.attack_chain):
            assert stage.order == i + 1

        # 每个阶段应该有证据
        for stage in result.attack_chain:
            assert len(stage.evidence_event_ids) > 0 or len(stage.evidence_alert_ids) > 0

        # 每个阶段应该有实体
        for stage in result.attack_chain:
            assert len(stage.entity_ids) > 0

    def test_darpa_e3_c2_beacon_analysis(self, darpa_data):
        """测试 C2 beacon 分析。"""
        events, alerts, graph = darpa_data
        result = analyze_trace(graph, alerts, events)

        c2_infra = result.attribution.get("c2_infrastructure", {})
        comm_patterns = c2_infra.get("communication_patterns", {})
        beacon = comm_patterns.get("beacon_analysis", {})

        # 应该有 beacon 分析结果
        assert "detected" in beacon

    def test_darpa_e3_fingerprint_summary(self, darpa_data):
        """测试指纹摘要。"""
        events, alerts, graph = darpa_data
        result = analyze_trace(graph, alerts, events)

        summary = result.attribution.get("fingerprint_summary", {})
        assert summary.get("total_ips", 0) >= 3
        assert summary.get("total_techniques", 0) >= 5
        assert summary.get("total_hosts", 0) >= 2

    def test_darpa_e3_multi_tactic_aggregation(self, darpa_data):
        """测试同一战术多条边的聚合。"""
        events, alerts, graph = darpa_data
        result = analyze_trace(graph, alerts, events)

        # 同一战术内的多条边应该被聚合
        # 检查每个阶段内有证据
        for stage in result.attack_chain:
            total_evidence = len(stage.evidence_event_ids) + len(stage.evidence_alert_ids)
            assert total_evidence > 0, f"Stage {stage.tactic} should have evidence"

        # 阶段应该按 kill chain 排序
        from agents.apt_knowledge_base import tactic_order
        for i in range(len(result.attack_chain) - 1):
            curr_order = tactic_order(result.attack_chain[i].tactic)
            next_order = tactic_order(result.attack_chain[i + 1].tactic)
            assert curr_order <= next_order, "Stages should be in kill chain order"

    def test_analyze_trace_attribution_rubric(self, sample_events, sample_alerts, sample_graph):
        """测试归因评分细目结构。"""
        result = analyze_trace(sample_graph, sample_alerts, sample_events)

        if result.attribution.get("matched_group"):
            rubric = result.attribution["scoring_rubric"]
            # 所有维度权重应加起来约为 1.0
            total_weight = sum(
                rubric[k]["weight"]
                for k in ["technique_match", "tool_match", "kill_chain_match",
                          "behavior_match", "infrastructure_match"]
            )
            assert abs(total_weight - 1.0) < 0.001
