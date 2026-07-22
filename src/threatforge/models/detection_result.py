from dataclass import dataclass

@dataclass
class DetectionResults:
    source_ip: str
    detection_type: str
    occurence_count: int