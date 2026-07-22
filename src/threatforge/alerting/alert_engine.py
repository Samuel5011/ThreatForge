from threatforge.models.alert import Alert
from threatforge.models.detection_result import DetectionResult


def determine_severity(occurrence_count: int) -> str:
    if occurrence_count >= 10:
        return "High"

    if occurrence_count >= 5:
        return "Medium"

    return "Low"


def create_alerts(
    detections: list[DetectionResult],
) -> list[Alert]:
    alerts = [
        Alert(
            source_ip=detection.source_ip,
            alert_type=detection.detection_type,
            severity=determine_severity(
                detection.occurrence_count
            ),
            failed_attempts=detection.occurrence_count,
        )
        for detection in detections
    ]

    return alerts