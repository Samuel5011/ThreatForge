from collections import Counter

from threatforge.models.event import Event


def detect_brute_force(
    events: list[Event],
    threshold: int = 3,
) -> list[str]:
    ip_counts = Counter(
        event.source_ip
        for event in events
        if event.event_type == "failed_login"
    )

    suspicious_ips = [
        ip
        for ip, count in ip_counts.items()
        if count >= threshold
    ]

    return suspicious_ips