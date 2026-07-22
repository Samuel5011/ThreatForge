from collections import Counter

from threatforge.models.event import Event
from threatforge.models.alert import Alert


def detect_brute_force(
    events: list[Event],
    threshold: int = 3,
) -> list[Alert]:
    ip_counts = Counter(
        event.source_ip
        for event in events
        if event.event_type == "failed_login"
    )

    alerts = [
        Alert(
            source_ip=ip,
            alert_type="brute_force",
            severity="medium",
            failed_attempts=count,
        )
        for ip, count in ip_counts.items()
        if count >= threshold
    ]

    return alerts