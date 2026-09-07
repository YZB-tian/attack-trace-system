from enum import Enum

class SourceType(str, Enum):
    HOST_LOG = "host_log"
    HOST_BEHAVIOR = "host_behavior"
    NETWORK_FLOW = "network_flow"
    BOUNDARY_LOG = "boundary_log"

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(str, Enum):
    OPEN = "open"
    REVIEWED = "reviewed"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"

class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class NodeType(str, Enum):
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    FILE = "file"
    IP = "ip"
    DOMAIN = "domain"
    SESSION = "session"
    C2 = "c2"
    TECHNIQUE = "technique"
    OTHER = "other"

class EdgeRelation(str, Enum):
    LOGIN = "login"
    PROCESS_SPAWN = "process_spawn"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECT = "network_connect"
    INITIAL_ACCESS = "initial_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    C2_COMMUNICATION = "c2_communication"
    DATA_ACCESS = "data_access"
    DATA_EXFILTRATION = "data_exfiltration"
    RELATED_TO = "related_to"
