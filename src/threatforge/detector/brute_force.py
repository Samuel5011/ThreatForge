from collections import Counter

from threatforge.models.event import Event
from threatforge.models.alert import Alert
from threatforge.models.detection_result import DetectionResult


def detect_brute_force(
    events: list[Event],
    threshold: int = 3,
) -> list[Alert]:
    ip_counts = Counter(
        event.source_ip
        for event in events
        if event.event_type == "failed_login"
    )

    detections = [
        DetectionResult(
            source_ip=ip,
            detection_type="brute_force",
            occurrence_count=count,
        )
        for ip, count in ip_counts.items()
        if count >= threshold
    ]

    return detections