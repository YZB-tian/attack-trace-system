"""
APT 组织知识库
包含已知 APT 组织的 TTP 签名、IOC 模式、行为特征。
基于 MITRE ATT&CK 框架和公开威胁情报。

数据来源：
- MITRE ATT&CK (https://attack.mitre.org/)
- 公开 APT 报告
"""

from __future__ import annotations
from typing import Dict, List, Any
from dataclasses import dataclass, field


@dataclass
class APTGroup:
    """已知 APT 组织特征定义。"""
    group_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    country: str = ""
    description: str = ""

    # ATT&CK 技术 ID 列表
    techniques: List[str] = field(default_factory=list)

    # 典型战术阶段顺序（ATT&CK 战术）
    typical_kill_chain: List[str] = field(default_factory=list)

    # 已知工具
    known_tools: List[str] = field(default_factory=list)

    # 已知 C2 基础设施模式
    c2_patterns: Dict[str, Any] = field(default_factory=dict)

    # 已知 IOC 模式
    ioc_patterns: Dict[str, List[str]] = field(default_factory=dict)

    # 行为特征关键词
    behavior_keywords: List[str] = field(default_factory=list)


# ============================================================
# APT 知识库
# ============================================================

APT_GROUPS: Dict[str, APTGroup] = {
    "APT28": APTGroup(
        group_id="G0007",
        name="APT28",
        aliases=["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM"],
        country="Russia",
        description="Russian military intelligence (GRU) Unit 26165",
        techniques=[
            "T1566.001",  # Phishing: Spearphishing Attachment
            "T1059.001",  # Command and Scripting Interpreter: PowerShell
            "T1059.003",  # Command and Scripting Interpreter: Windows Command Shell
            "T1053.005",  # Scheduled Task/Job: Scheduled Task
            "T1055",      # Process Injection
            "T1070.004",  # Indicator Removal: File Deletion
            "T1071.001",  # Application Layer Protocol: Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1140",      # Deobfuscate/Decode Files or Information
            "T1218.011",  # System Binary Proxy Execution: Rundll32
            "T1547.001",  # Boot or Logon Autostart Execution: Registry Run Keys
            "T1027",      # Obfuscated Files or Information
            "T1082",      # System Information Discovery
            "T1083",      # File and Directory Discovery
            "T1005",      # Data from Local System
            "T1041",      # Exfiltration Over C2 Channel
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration"
        ],
        known_tools=[
            "X-Agent", "X-Tunnel", "Zebrocy", "CompuTrace",
            "Seduploader", "SkinnyBoy", "Graphite"
        ],
        c2_patterns={
            "protocols": ["https", "http", "dns"],
            "domain_patterns": [".com", ".net", ".org"],
            "port_preferences": [443, 80, 8080],
            "uses_dynamic_dns": True,
            "domain_age_days_typical": "<90",
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [r"Local\MSCTF.Shared.MUTEX", r"Global\SM0:.*:Windows"],
            "registry_keys": [
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ],
            "file_paths": [
                r"%APPDATA%\Microsoft\Windows\*",
                r"%TEMP%\*",
            ],
        },
        behavior_keywords=[
            "powershell", "rundll32", "regsvr32", "wscript", "cscript",
            "schtasks", "certutil", "bitsadmin",
        ],
    ),

    "APT29": APTGroup(
        group_id="G0016",
        name="APT29",
        aliases=["Cozy Bear", "The Dukes", "CozyDuke", "NOBELIUM"],
        country="Russia",
        description="Russian Foreign Intelligence Service (SVR)",
        techniques=[
            "T1566.002",  # Phishing: Spearphishing Link
            "T1195.002",  # Supply Chain Compromise: Software Supply Chain
            "T1059.001",  # PowerShell
            "T1055",      # Process Injection
            "T1070.004",  # File Deletion
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1132.001",  # Data Encoding: Standard Encoding
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1082",      # System Information Discovery
            "T1098",      # Account Manipulation
            "T1136.001",  # Create Account: Local Account
            "T1003",      # OS Credential Dumping
            "T1041",      # Exfiltration Over C2
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration"
        ],
        known_tools=[
            "SUNBURST", "TEARDROP", "Raindrop", "Cobalt Strike",
            "WellMess", "WellMail", "EnvyScout",
        ],
        c2_patterns={
            "protocols": ["https", "http"],
            "domain_patterns": [".com", ".cloudapp.net"],
            "port_preferences": [443, 8443],
            "uses_dynamic_dns": False,
            "uses_steganography": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [],
            "registry_keys": [r"HKCU\Software\Microsoft\Office\*"],
            "file_paths": [r"%LOCALAPPDATA%\*", r"%ProgramData%\*"],
        },
        behavior_keywords=[
            "powershell", "wmic", "net", "whoami", "ipconfig",
            "tasklist", "reg", "schtasks", "bitsadmin",
        ],
    ),

    "APT41": APTGroup(
        group_id="G0096",
        name="APT41",
        aliases=["Winnti Group", "Barium", "Wicked Panda", "Double Dragon"],
        country="China",
        description="Chinese state-sponsored with cybercrime side operations",
        techniques=[
            "T1190",      # Exploit Public-Facing Application
            "T1566.001",  # Spearphishing Attachment
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1053.005",  # Scheduled Task
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1218.011",  # Rundll32
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1082",      # System Information Discovery
            "T1100",      # Web Shell
            "T1005",      # Data from Local System
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration"
        ],
        known_tools=[
            "HIGHNOON", "HOMEUNIX", "PlugX", "ShadowPad",
            "Winnti", "Cobalt Strike", "MESSAGETAP",
        ],
        c2_patterns={
            "protocols": ["https", "http", "tcp"],
            "domain_patterns": [".com", ".net", ".org"],
            "port_preferences": [443, 80, 8443, 53],
            "uses_dynamic_dns": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [r"Global\Winnti"],
            "registry_keys": [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%SystemRoot%\Temp\*", r"%APPDATA%\*"],
        },
        behavior_keywords=[
            "powershell", "cmd", "wscript", "rundll32", "regsvr32",
            "net user", "net group", "whoami", "ipconfig",
        ],
    ),

    "Lazarus Group": APTGroup(
        group_id="G0032",
        name="Lazarus Group",
        aliases=["HIDDEN COBRA", "Zinc", "Labyrinth Chollima"],
        country="North Korea",
        description="North Korean state-sponsored, known for destructive attacks and cyber theft",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1053.005",  # Scheduled Task
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1218.011",  # Rundll32
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1486",      # Data Encrypted for Impact
            "T1489",      # Service Stop
            "T1005",      # Data from Local System
            "T1041",      # Exfiltration Over C2
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration", "Impact"
        ],
        known_tools=[
            "DARKCOMET", "HERMES", "HOPLIGHT", "Joanap",
            "Volgmer", "Manuscrypt", "Bankshot",
        ],
        c2_patterns={
            "protocols": ["https", "http", "tcp"],
            "domain_patterns": [".com", ".net", ".info"],
            "port_preferences": [443, 80, 8080],
            "uses_dynamic_dns": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [r"Global\PowerShell*", r"Local\SM0:*"],
            "registry_keys": [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%SystemRoot%\System32\*", r"%TEMP%\*"],
        },
        behavior_keywords=[
            "powershell", "cmd", "wscript", "rundll32", "regsvr32",
            "cipher", "vssadmin", "bcdedit", "taskkill",
        ],
    ),

    "Carbanak": APTGroup(
        group_id="G0008",
        name="Carbanak",
        aliases=["Anunak", "Cobalt Group", "FIN7"],
        country="Russia/Ukraine",
        description="Financially motivated threat group targeting financial institutions",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1059.001",  # PowerShell
            "T1059.005",  # Visual Basic
            "T1053.005",  # Scheduled Task
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1218.011",  # Rundll32
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1082",      # System Information Discovery
            "T1005",      # Data from Local System
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration"
        ],
        known_tools=[
            "Cobalt Strike", "Carbanak Backdoor", "ATMitch",
            "PowerShell Empire", "Mimikatz",
        ],
        c2_patterns={
            "protocols": ["https", "http"],
            "domain_patterns": [".com", ".net"],
            "port_preferences": [443, 80, 8443],
            "uses_dynamic_dns": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [],
            "registry_keys": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%APPDATA%\*", r"%TEMP%\*"],
        },
        behavior_keywords=[
            "powershell", "mimikatz", "cobalt", "rundll32", "wscript",
            "net user", "net group",
        ],
    ),

    # ================================================================
    # 新增 APT 组织
    # ================================================================

    "Equation Group": APTGroup(
        group_id="G0020",
        name="Equation Group",
        aliases=["EQGRP", "Tilded Team"],
        country="USA",
        description="Highly sophisticated threat actor linked to Tailored Access Operations (TAO)",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1059.001",  # PowerShell
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1014",      # Rootkit
            "T1542.003",  # Pre-OS Boot: Bootkit
            "T1082",      # System Information Discovery
            "T1083",      # File and Directory Discovery
            "T1005",      # Data from Local System
            "T1041",      # Exfiltration Over C2
            "T1029",      # Scheduled Transfer
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Collection", "Exfiltration"
        ],
        known_tools=[
            "EQUATIONDRUG", "DOUBLEPULSAR", "ETERNALBLUE", "FANNY",
            "GRAYFISH", "HIVE", "EQUATIONLASER", "COTTONMOUTH",
        ],
        c2_patterns={
            "protocols": ["https", "http", "tcp"],
            "domain_patterns": [".com", ".net"],
            "port_preferences": [443, 80, 4444],
            "uses_dynamic_dns": False,
            "uses_firmware_implant": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [r"Global\Mtx"],
            "registry_keys": [r"HKLM\SYSTEM\CurrentControlSet\Services\*"],
            "file_paths": [r"%SystemRoot%\System32\drivers\*"],
        },
        behavior_keywords=[
            "powershell", "rundll32", "rootkit", "bootkit", "firmware",
            "driver", "sys", "dll injection",
        ],
    ),

    "Turla": APTGroup(
        group_id="G0010",
        name="Turla",
        aliases=["Waterbug", "Venomous Bear", "Snake", "KRYPTON"],
        country="Russia",
        description="Russian FSB-linked group known for sophisticated espionage",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1059.001",  # PowerShell
            "T1059.004",  # Unix Shell
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1071.004",  # DNS
            "T1105",      # Ingress Tool Transfer
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1082",      # System Information Discovery
            "T1083",      # File and Directory Discovery
            "T1005",      # Data from Local System
            "T1041",      # Exfiltration Over C2
            "T1048",      # Exfiltration Over Alternative Protocol
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Collection", "Exfiltration"
        ],
        known_tools=[
            "Carbon", "KopiLuwak", "Gazer", "Skipper", "Mosquito",
            "LightNeuron", "Penguin", "WeakSteel", "Crutch",
        ],
        c2_patterns={
            "protocols": ["https", "http", "dns"],
            "domain_patterns": [".com", ".net", ".org"],
            "port_preferences": [443, 80, 53],
            "uses_dynamic_dns": True,
            "uses_satellite_c2": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [r"MutexPolessa"],
            "registry_keys": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%APPDATA%\*", r"%ProgramFiles%\*"],
        },
        behavior_keywords=[
            "powershell", "wscript", "cscript", "rundll32", "regsvr32",
            "schtasks", "certutil", "dns", "nslookup",
        ],
    ),

    "OceanLotus": APTGroup(
        group_id="G0050",
        name="OceanLotus",
        aliases=["APT32", "SeaLotus", "Cobalt Kitty", "Bismuth"],
        country="Vietnam",
        description="Vietnamese state-sponsored group targeting Southeast Asian entities",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1218.011",  # Rundll32
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1082",      # System Information Discovery
            "T1005",      # Data from Local System
            "T1041",      # Exfiltration Over C2
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Collection", "Exfiltration"
        ],
        known_tools=[
            "Cobalt Strike", "DenisRAT", "KerrDown", "Ratsnif",
            "BeaconLoader", "HyperBro",
        ],
        c2_patterns={
            "protocols": ["https", "http"],
            "domain_patterns": [".com", ".net", ".org"],
            "port_preferences": [443, 80, 8443],
            "uses_dynamic_dns": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [],
            "registry_keys": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%APPDATA%\*", r"%LOCALAPPDATA%\*"],
        },
        behavior_keywords=[
            "powershell", "cmd", "rundll32", "regsvr32", "wscript",
            "schtasks", "net user", "whoami",
        ],
    ),

    "Kimsuky": APTGroup(
        group_id="G0094",
        name="Kimsuky",
        aliases=["Velvet Chollima", "Black Banshee", "Thallium"],
        country="North Korea",
        description="North Korean group focused on intelligence gathering",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1059.001",  # PowerShell
            "T1059.005",  # Visual Basic
            "T1053.005",  # Scheduled Task
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1218.011",  # Rundll32
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1082",      # System Information Discovery
            "T1005",      # Data from Local System
            "T1041",      # Exfiltration Over C2
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Collection", "Exfiltration"
        ],
        known_tools=[
            "AppleSeed", "KghSpy", "BabyShark", "Grease",
            "RandomQuery", "Meterpreter",
        ],
        c2_patterns={
            "protocols": ["https", "http"],
            "domain_patterns": [".com", ".net", ".co.kr"],
            "port_preferences": [443, 80, 8080],
            "uses_dynamic_dns": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [],
            "registry_keys": [r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%APPDATA%\*", r"%TEMP%\*"],
        },
        behavior_keywords=[
            "powershell", "wscript", "cscript", "rundll32", "regsvr32",
            "schtasks", "keylogger", "screen capture",
        ],
    ),

    "Sandworm": APTGroup(
        group_id="G0034",
        name="Sandworm",
        aliases=["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "ELECTRUM"],
        country="Russia",
        description="Russian GRU Unit 74455, known for destructive attacks (NotPetya, Industroyer)",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1190",      # Exploit Public-Facing Application
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1053.005",  # Scheduled Task
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1218.011",  # Rundll32
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1486",      # Data Encrypted for Impact
            "T1489",      # Service Stop
            "T1529",      # System Shutdown/Reboot
            "T1005",      # Data from Local System
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Exfiltration", "Impact"
        ],
        known_tools=[
            "NotPetya", "Industroyer", "BlackEnergy", "KillDisk",
            "GreyEnergy", "Exaramel", "CaddyWiper", "WhisperGate",
        ],
        c2_patterns={
            "protocols": ["https", "http", "tcp"],
            "domain_patterns": [".com", ".net"],
            "port_preferences": [443, 80, 4444],
            "uses_dynamic_dns": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [],
            "registry_keys": [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%SystemRoot%\*", r"%TEMP%\*"],
        },
        behavior_keywords=[
            "powershell", "cmd", "rundll32", "vssadmin", "bcdedit",
            "cipher", "taskkill", "wscript", "schtasks",
        ],
    ),

    "DarkHotel": APTGroup(
        group_id="G0012",
        name="DarkHotel",
        aliases=["DUBNIUM", "Nemim", "Tapaoux", "Pioneer"],
        country="South Korea",
        description="Korean-speaking group targeting hospitality and business travelers",
        techniques=[
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1195.002",  # Supply Chain Compromise
            "T1059.001",  # PowerShell
            "T1059.003",  # Windows Command Shell
            "T1055",      # Process Injection
            "T1071.001",  # Web Protocols
            "T1105",      # Ingress Tool Transfer
            "T1218.011",  # Rundll32
            "T1547.001",  # Registry Run Keys
            "T1027",      # Obfuscated Files
            "T1082",      # System Information Discovery
            "T1005",      # Data from Local System
        ],
        typical_kill_chain=[
            "Initial Access", "Execution", "Persistence", "Defense Evasion",
            "Credential Access", "Discovery", "Collection", "Exfiltration"
        ],
        known_tools=[
            "Asruex", "Nemim", "Tapaoux", "Pioneer", "DUBNIUM",
            "Regin", "mstcp32", "soundmix",
        ],
        c2_patterns={
            "protocols": ["https", "http"],
            "domain_patterns": [".com", ".net", ".org"],
            "port_preferences": [443, 80, 8080],
            "uses_dynamic_dns": True,
            "targeted_wifi": True,
        },
        ioc_patterns={
            "file_hashes": [],
            "mutex_patterns": [],
            "registry_keys": [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"],
            "file_paths": [r"%ProgramFiles%\*", r"%TEMP%\*"],
        },
        behavior_keywords=[
            "powershell", "cmd", "rundll32", "regsvr32", "wscript",
            "wifi", "hotel", "certificate",
        ],
    ),
}


def get_apt_group(name: str) -> APTGroup | None:
    """按名称或别名查找 APT 组织。"""
    name_lower = name.lower()
    for group in APT_GROUPS.values():
        if group.name.lower() == name_lower:
            return group
        if any(alias.lower() == name_lower for alias in group.aliases):
            return group
    return None


def get_all_techniques() -> Dict[str, List[str]]:
    """返回 {technique_id: [group_names]} 映射。"""
    tech_to_groups: Dict[str, List[str]] = {}
    for group in APT_GROUPS.values():
        for tech in group.techniques:
            tech_to_groups.setdefault(tech, []).append(group.name)
    return tech_to_groups


def get_groups_by_technique(technique_id: str) -> List[APTGroup]:
    """返回包含指定技术的所有 APT 组织。"""
    return [g for g in APT_GROUPS.values() if technique_id in g.techniques]


# ATT&CK 战术顺序（用于攻击链对齐）
ATTACK_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def tactic_order(tactic: str) -> int:
    """返回战术在 kill chain 中的顺序索引，未匹配返回 999。"""
    try:
        return ATTACK_TACTIC_ORDER.index(tactic)
    except ValueError:
        return 999
