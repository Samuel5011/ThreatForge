from dataclasses import dataclass

@dataclass
class DetectionResult:
    source_ip: str
    detection_type: str
    occurrence_count: int