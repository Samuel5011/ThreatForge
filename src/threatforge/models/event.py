from dataclasses import dataclass

@dataclass
class Event:
    timestamp: str
    hostname: str
    service: str
    event_type: str
    username: str
    source_ip: str
    source_port: int
    protocol: str