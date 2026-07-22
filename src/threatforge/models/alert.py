from dataclasses import dataclass

@dataclass
class Alert:
    source_ip: str
    alert_type: str
    severity: str
    failed_attempts: int
