"""
攻击者指纹提取器
从事件、告警、攻击图中提取 IOC 和攻击者指纹特征。

提取内容：
- 网络 IOC：IP、域名、URL、端口
- 主机 IOC：文件哈希、进程路径、注册表键、互斥量
- 行为特征：使用的工具、命令模式、TTP 技术
- 用户代理：用户名、会话
"""

from __future__ import annotations
import re
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field

from common.models import NormalizedEvent, Alert, AttackGraph


@dataclass
class AttackerFingerprint:
    """攻击者指纹特征集合。"""
    # 网络 IOC
    ip_addresses: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=set)

    # 主机 IOC
    file_hashes: Set[str] = field(default_factory=set)
    file_paths: Set[str] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    process_paths: Set[str] = field(default_factory=set)
    registry_keys: Set[str] = field(default_factory=set)
    mutexes: Set[str] = field(default_factory=set)

    # 用户信息
    usernames: Set[str] = field(default_factory=set)
    host_ids: Set[str] = field(default_factory=set)

    # 行为特征
    techniques: Set[str] = field(default_factory=set)
    tactics: Set[str] = field(default_factory=set)
    actions: Set[str] = field(default_factory=set)
    tools_detected: Set[str] = field(default_factory=set)
    command_patterns: Set[str] = field(default_factory=set)

    # 时间特征
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    active_hours: Set[int] = field(default_factory=set)

    # 关联 ID
    evidence_event_ids: Set[str] = field(default_factory=set)
    evidence_alert_ids: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        """转为可序列化字典。"""
        return {
            "network_ioc": {
                "ip_addresses": sorted(self.ip_addresses),
                "domains": sorted(self.domains),
                "ports": sorted(self.ports),
                "urls": sorted(self.urls),
                "protocols": sorted(self.protocols),
            },
            "host_ioc": {
                "file_hashes": sorted(self.file_hashes),
                "file_paths": sorted(self.file_paths),
                "process_names": sorted(self.process_names),
                "process_paths": sorted(self.process_paths),
                "registry_keys": sorted(self.registry_keys),
                "mutexes": sorted(self.mutexes),
            },
            "user_info": {
                "usernames": sorted(self.usernames),
                "host_ids": sorted(self.host_ids),
            },
            "behavior": {
                "techniques": sorted(self.techniques),
                "tactics": sorted(self.tactics),
                "actions": sorted(self.actions),
                "tools_detected": sorted(self.tools_detected),
                "command_patterns": sorted(self.command_patterns),
            },
            "temporal": {
                "first_seen": self.first_seen,
                "last_seen": self.last_seen,
                "active_hours": sorted(self.active_hours),
            },
            "evidence": {
                "event_ids": sorted(self.evidence_event_ids),
                "alert_ids": sorted(self.evidence_alert_ids),
            },
        }


# 已知攻击工具特征
TOOL_SIGNATURES = {
    "mimikatz": {
        "process_names": ["mimikatz.exe", "mimi32.exe", "mimi64.exe"],
        "process_paths": [r"\\mimikatz", r"\\mimi"],
        "command_patterns": ["sekurlsa", "kerberos", "lsadump", "privilege::debug", "dpapi::"],
        "description": "Credential dumping tool",
    },
    "cobalt_strike": {
        "process_names": ["beacon.exe", "cobaltstrike.exe"],
        "process_paths": [r"\\beacon", r"\\cobalt"],
        "command_patterns": ["beacon", "cobaltstrike", "sleep 0", "inject", "spawn"],
        "description": "Commercial penetration testing tool (abused by attackers)",
    },
    "powershell_empire": {
        "process_names": ["powershell.exe"],
        "process_paths": [],
        "command_patterns": [
            "Invoke-Empire", "Invoke-Mimikatz", "Invoke-Shellcode",
            "Invoke-TokenManipulation", "Set-MasterBootRecord",
            "Invoke-Kerberoast", "Invoke-WebRequest",
        ],
        "description": "PowerShell post-exploitation framework",
    },
    "metasploit": {
        "process_names": ["msfconsole", "msfvenom", "meterpreter"],
        "process_paths": [r"\\meterpreter", r"\\msf"],
        "command_patterns": ["meterpreter", "reverse_tcp", "reverse_https", "payload", "exploit"],
        "description": "Penetration testing framework",
    },
    "certutil_download": {
        "process_names": ["certutil.exe"],
        "process_paths": [r"\\certutil"],
        "command_patterns": ["certutil -urlcache", "certutil -decode", "-split -f"],
        "description": "Living-off-the-land binary for download/decode",
    },
    "bitsadmin_download": {
        "process_names": ["bitsadmin.exe"],
        "process_paths": [r"\\bitsadmin"],
        "command_patterns": ["bitsadmin /transfer", "bitsadmin /create"],
        "description": "Background Intelligent Transfer abuse",
    },
    "rundll32_abuse": {
        "process_names": ["rundll32.exe"],
        "process_paths": [r"\\rundll32"],
        "command_patterns": ["rundll32 javascript:", "rundll32 mshtml", "DllRegisterServer"],
        "description": "DLL execution via rundll32",
    },
    "wmi_execution": {
        "process_names": ["wmic.exe", "wmiprvse.exe"],
        "process_paths": [r"\\wmic", r"\\wmiprvse"],
        "command_patterns": ["wmic process call create", "wmic /node:"],
        "description": "WMI-based execution and lateral movement",
    },
    "psexec": {
        "process_names": ["psexec.exe", "psexesvc.exe"],
        "process_paths": [r"\\psexec"],
        "command_patterns": ["psexec", "psexesvc"],
        "description": "PsExec remote execution tool",
    },
    "web_shell": {
        "process_names": ["w3wp.exe", "httpd.exe", "nginx", "java", "tomcat"],
        "process_paths": [],
        "command_patterns": [
            "cmd.exe /c", "whoami", "ipconfig", "net user",
            "systeminfo", "tasklist", "type ",
        ],
        "description": "Web shell command execution",
    },
    # 新增工具签名
    "linpeas": {
        "process_names": ["linpeas.sh", "linpeas"],
        "process_paths": [r"\\linpeas", r"/tmp/.hidden/linpeas"],
        "command_patterns": ["linpeas", "./linpeas", "bash linpeas"],
        "description": "Linux privilege escalation enumeration script",
    },
    "winpeas": {
        "process_names": ["winpeas.exe", "winpeas"],
        "process_paths": [r"\\winpeas"],
        "command_patterns": ["winpeas", ".\\winpeas"],
        "description": "Windows privilege escalation enumeration script",
    },
    "bloodhound": {
        "process_names": ["sharphound.exe", "bloodhound.exe", "invoke-bloodhound"],
        "process_paths": [r"\\sharphound", r"\\bloodhound"],
        "command_patterns": ["bloodhound", "sharphound", "invoke-bloodhound", "neo4j"],
        "description": "Active Directory reconnaissance tool",
    },
    "chisel": {
        "process_names": ["chisel", "chisel.exe"],
        "process_paths": [r"\\chisel"],
        "command_patterns": ["chisel client", "chisel server", "socks", "reverse"],
        "description": "Tunneling tool for port forwarding and SOCKS proxy",
    },
    "ligolo": {
        "process_names": ["ligolo", "ligolo-ng", "agent"],
        "process_paths": [r"\\ligolo"],
        "command_patterns": ["ligolo", "proxy", "listener_start"],
        "description": "Tunneling tool for penetration testing",
    },
    "nmap": {
        "process_names": ["nmap", "nmap.exe", "ncat", "nping"],
        "process_paths": [r"\\nmap"],
        "command_patterns": ["nmap ", "-sS", "-sT", "-sU", "-sV", "-O", "--script"],
        "description": "Network scanning tool",
    },
    "netcat": {
        "process_names": ["nc", "ncat", "netcat", "nc.exe", "ncat.exe"],
        "process_paths": [r"\\nc", r"\\ncat"],
        "command_patterns": ["nc -e", "ncat -e", "-e /bin/sh", "-e cmd.exe", "-lp", "-lv"],
        "description": "Network utility often used for reverse shells",
    },
    "ssh_tunnel": {
        "process_names": ["ssh", "ssh.exe", "sshd"],
        "process_paths": [r"\\ssh"],
        "command_patterns": ["ssh -L", "ssh -R", "ssh -D", "-N -f", "-o StrictHostKeyChecking=no"],
        "description": "SSH tunneling for port forwarding",
    },
}

# 可疑命令模式
SUSPICIOUS_COMMAND_PATTERNS = {
    "reconnaissance": [
        "whoami", "whoami /all", "hostname", "ipconfig", "ipconfig /all",
        "systeminfo", "tasklist", "net user", "net group", "net localgroup",
        "net share", "net use", "netstat", "arp -a", "route print",
        "nltest", "nltest /dclist:", "dsquery",
        # Linux
        "id", "uname -a", "cat /etc/passwd", "cat /etc/shadow",
        "cat /etc/hosts", "ifconfig", "ip addr", "ip route",
        "ss -tuln", "ps aux", "ls -la /etc", "find / -perm",
        "cat /proc/version", "env", "printenv", "w", "last",
    ],
    "credential_access": [
        "sekurlsa", "kerberos::list", "lsadump", "vault::cred",
        "reg save HKLM\\SAM", "reg save HKLM\\SYSTEM",
        "esentutl /y /vss", "mimikatz",
        # Linux
        "cat /etc/shadow", "cat /etc/gshadow", "find / -name '*.key'",
        "find / -name '*.pem'", "find / -name 'id_rsa'",
        "grep -r password", "history", "cat ~/.bash_history",
    ],
    "defense_evasion": [
        "powershell -enc", "powershell -e ", "powershell -w hidden",
        "powershell -nop", "powershell -noni", "powershell -ep bypass",
        "certutil -decode", "certutil -urlcache",
        "bitsadmin /transfer", "mshta", "regsvr32 /s /n /u",
        "rundll32 javascript:", "vssadmin delete shadows",
        "bcdedit /set {default} recoveryenabled no",
        "wevtutil cl", "wevtutil clear-log",
        # Linux
        "unset HISTFILE", "export HISTSIZE=0", "ln -sf /dev/null",
        "shred ", "wipe ", "echo '' > ",
        "base64 -d", "openssl enc",
    ],
    "lateral_movement": [
        "psexec", "wmic /node:", "net use \\\\",
        "enter-pssession", "invoke-command",
        "schtasks /create", "schtasks /run",
        # Linux
        "ssh ", "scp ", "rsync ", "ssh -L", "ssh -R",
        "ssh-keygen", "ssh-copy-id",
    ],
    "privilege_escalation": [
        "sudo ", "su -", "chmod u+s", "chmod +s",
        "find / -perm -4000", "find / -perm -2000",
        "pkexec", "crontab -e", "echo '* * * * *'",
    ],
    "persistence": [
        "crontab", "systemctl enable", "systemctl start",
        ".bashrc", ".bash_profile", ".profile",
        "/etc/init.d/", "/etc/systemd/",
        "chattr +i",
    ],
    "data_staging": [
        "rar a", "7z a", "zip ", "tar -czf",
        "copy /b", "type ", "findstr",
        "compress-archive",
        # Linux
        "tar czf", "gzip ", "bzip2 ", "xz ",
        "split -b", "dd if=", "cat /dev/",
    ],
    "exfiltration": [
        "ftp ", "scp ", "sftp ", "curl ", "wget ",
        "bitsadmin /transfer", "certutil -urlcache",
        "nslookup", "dig ",
        # Linux
        "curl -X POST", "curl -d @", "curl -F",
        "wget --post-file", "nc -e", "ncat -e",
        "python -c 'import socket'", "python3 -c 'import socket'",
    ],
}


def extract_fingerprint_from_events(events: List[NormalizedEvent]) -> AttackerFingerprint:
    """从事件列表中提取攻击者指纹。"""
    fp = AttackerFingerprint()

    for evt in events:
        fp.evidence_event_ids.add(evt.event_id)
        fp.host_ids.add(evt.host_id or "unknown")
        fp.actions.add(evt.action)

        # 时间
        if fp.first_seen is None or evt.timestamp < fp.first_seen:
            fp.first_seen = evt.timestamp
        if fp.last_seen is None or evt.timestamp > fp.last_seen:
            fp.last_seen = evt.timestamp

        # 提取小时（时区感知）
        try:
            hour_str = evt.timestamp[11:13]
            fp.active_hours.add(int(hour_str))
        except (ValueError, IndexError):
            pass

        # 网络信息
        if evt.src_ip:
            fp.ip_addresses.add(evt.src_ip)
        if evt.dst_ip:
            fp.ip_addresses.add(evt.dst_ip)
        if evt.src_port:
            fp.ports.add(evt.src_port)
        if evt.dst_port:
            fp.ports.add(evt.dst_port)
        if evt.network:
            if evt.network.protocol:
                fp.protocols.add(evt.network.protocol)
            if evt.network.session_id:
                fp.urls.add(f"session:{evt.network.session_id}")

        # 用户
        if evt.user:
            fp.usernames.add(evt.user)

        # 进程信息
        if evt.process:
            if evt.process.name:
                fp.process_names.add(evt.process.name.lower())
            if evt.process.path:
                fp.process_paths.add(evt.process.path)
            if evt.process.hash_sha256:
                fp.file_hashes.add(evt.process.hash_sha256)

        # 对象信息
        if evt.object:
            if evt.object.path:
                fp.file_paths.add(evt.object.path)
            if evt.object.name:
                fp.process_names.add(evt.object.name.lower())

        # 标签
        for label in evt.labels:
            if label.startswith("technique:"):
                fp.techniques.add(label.split(":", 1)[1])

        # 从 raw_event 提取更多信息
        if isinstance(evt.raw_event, dict):
            _extract_from_raw_event(fp, evt.raw_event)

        # 检测工具使用
        _detect_tool_usage(fp, evt)

    return fp


def extract_fingerprint_from_alerts(alerts: List[Alert]) -> AttackerFingerprint:
    """从告警列表中提取攻击者指纹。"""
    fp = AttackerFingerprint()

    for alert in alerts:
        fp.evidence_alert_ids.add(alert.alert_id)
        fp.host_ids.update(alert.host_ids)

        # MITRE 映射
        if alert.mitre:
            if alert.mitre.technique_id:
                fp.techniques.add(alert.mitre.technique_id)
            if alert.mitre.tactic:
                fp.tactics.add(alert.mitre.tactic)

        # 从描述和规则名提取关键词
        desc_lower = alert.description.lower()
        rule_lower = alert.rule_name.lower()
        combined = f"{desc_lower} {rule_lower}"

        for tool_name, sig in TOOL_SIGNATURES.items():
            for pattern in sig["command_patterns"]:
                if pattern.lower() in combined:
                    fp.tools_detected.add(tool_name)

    return fp


def extract_fingerprint_from_graph(graph: AttackGraph) -> AttackerFingerprint:
    """从攻击图中提取攻击者指纹。"""
    fp = AttackerFingerprint()

    for node in graph.nodes:
        node_type = node.type.value if hasattr(node.type, 'value') else str(node.type)

        if node_type == "host":
            fp.host_ids.add(node.id)
            if "ip" in node.attributes:
                fp.ip_addresses.add(node.attributes["ip"])
        elif node_type == "ip":
            fp.ip_addresses.add(node.id)
        elif node_type == "user":
            fp.usernames.add(node.label)
        elif node_type == "process":
            fp.process_names.add(node.label.lower())
        elif node_type == "file":
            fp.file_paths.add(node.label)
        elif node_type == "domain":
            fp.domains.add(node.label)
        elif node_type == "c2":
            # C2 节点：提取域名和 IP
            if "domain" in node.attributes:
                fp.domains.add(node.attributes["domain"])
            if "ip" in node.attributes:
                fp.ip_addresses.add(node.attributes["ip"])
            # label 也可能是域名
            if "." in node.label and not node.label.replace(".", "").isdigit():
                fp.domains.add(node.label)
    for edge in graph.edges:
        if edge.technique_id:
            fp.techniques.add(edge.technique_id)
        fp.evidence_event_ids.update(edge.evidence_event_ids)
        fp.evidence_alert_ids.update(edge.evidence_alert_ids)

        relation = edge.relation.value if hasattr(edge.relation, 'value') else str(edge.relation)
        fp.actions.add(relation)

    return fp


def _extract_from_raw_event(fp: AttackerFingerprint, raw: Dict[str, Any]) -> None:
    """从原始事件数据中提取额外 IOC。"""
    # 尝试提取域名
    for key in ["domain", "hostname", "server_name", "sni"]:
        if key in raw and isinstance(raw[key], str):
            val = raw[key]
            if "." in val and not val.replace(".", "").replace(":", "").isdigit():
                fp.domains.add(val)

    # 尝试提取 URL
    for key in ["url", "uri", "request_uri"]:
        if key in raw and isinstance(raw[key], str):
            fp.urls.add(raw[key])

    # 尝试提取文件哈希
    for key in ["hash", "sha256", "md5", "file_hash"]:
        if key in raw and isinstance(raw[key], str) and len(raw[key]) >= 32:
            fp.file_hashes.add(raw[key])

    # 尝试提取注册表键
    for key in ["registry_key", "reg_key", "target_object"]:
        if key in raw and isinstance(raw[key], str):
            if "HKEY" in raw[key].upper() or "HK" in raw[key].upper():
                fp.registry_keys.add(raw[key])

    # 尝试提取命令行
    for key in ["command_line", "cmdline", "cmd", "command"]:
        if key in raw and isinstance(raw[key], str):
            fp.command_patterns.add(raw[key])
            _extract_command_ioc(fp, raw[key])


def _extract_command_ioc(fp: AttackerFingerprint, cmd: str) -> None:
    """从命令行中提取 IOC。"""
    cmd_lower = cmd.lower()

    # 提取 IP 地址
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    for ip in re.findall(ip_pattern, cmd):
        fp.ip_addresses.add(ip)

    # 提取域名
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    for domain in re.findall(domain_pattern, cmd):
        if domain not in ("Windows.System32", "Microsoft.Windows", "Program Files"):
            fp.domains.add(domain)

    # 提取文件路径
    path_pattern = r'[A-Za-z]:\\[^\s"\'<>|*?]+'
    for path in re.findall(path_pattern, cmd):
        fp.file_paths.add(path)

    # 检测可疑命令
    for category, patterns in SUSPICIOUS_COMMAND_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in cmd_lower:
                fp.command_patterns.add(f"[{category}] {pattern}")


def _detect_tool_usage(fp: AttackerFingerprint, evt: NormalizedEvent) -> None:
    """检测事件中的工具使用。"""
    # 检查进程名
    proc_name = ""
    if evt.process and evt.process.name:
        proc_name = evt.process.name.lower()
    if evt.object and evt.object.name:
        proc_name = evt.object.name.lower()

    proc_path = ""
    if evt.process and evt.process.path:
        proc_path = evt.process.path.lower()

    # 构建搜索文本
    search_parts = [proc_name, proc_path]
    if isinstance(evt.raw_event, dict):
        for key in ["command_line", "cmdline", "cmd"]:
            if key in evt.raw_event:
                search_parts.append(str(evt.raw_event[key]).lower())
    search_text = " ".join(search_parts)

    for tool_name, sig in TOOL_SIGNATURES.items():
        # 检查进程名
        for sig_proc in sig["process_names"]:
            if sig_proc.lower() in proc_name:
                fp.tools_detected.add(tool_name)
                return

        # 检查进程路径
        for sig_path in sig["process_paths"]:
            if sig_path.lower() in proc_path:
                fp.tools_detected.add(tool_name)
                return

        # 检查命令模式
        for pattern in sig["command_patterns"]:
            if pattern.lower() in search_text:
                fp.tools_detected.add(tool_name)
                return


def merge_fingerprints(fingerprints: List[AttackerFingerprint]) -> AttackerFingerprint:
    """合并多个指纹为一个。"""
    merged = AttackerFingerprint()

    for fp in fingerprints:
        merged.ip_addresses.update(fp.ip_addresses)
        merged.domains.update(fp.domains)
        merged.ports.update(fp.ports)
        merged.urls.update(fp.urls)
        merged.protocols.update(fp.protocols)
        merged.file_hashes.update(fp.file_hashes)
        merged.file_paths.update(fp.file_paths)
        merged.process_names.update(fp.process_names)
        merged.process_paths.update(fp.process_paths)
        merged.registry_keys.update(fp.registry_keys)
        merged.mutexes.update(fp.mutexes)
        merged.usernames.update(fp.usernames)
        merged.host_ids.update(fp.host_ids)
        merged.techniques.update(fp.techniques)
        merged.tactics.update(fp.tactics)
        merged.actions.update(fp.actions)
        merged.tools_detected.update(fp.tools_detected)
        merged.command_patterns.update(fp.command_patterns)
        merged.evidence_event_ids.update(fp.evidence_event_ids)
        merged.evidence_alert_ids.update(fp.evidence_alert_ids)
        merged.active_hours.update(fp.active_hours)

        if fp.first_seen and (merged.first_seen is None or fp.first_seen < merged.first_seen):
            merged.first_seen = fp.first_seen
        if fp.last_seen and (merged.last_seen is None or fp.last_seen > merged.last_seen):
            merged.last_seen = fp.last_seen

    return merged
