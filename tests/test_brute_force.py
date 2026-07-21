from threatforge.detector.brute_force import detect_brute_force
from threatforge.models.event import Event


def create_failed_login_event(source_ip: str) -> Event:
    return Event(
        timestamp="Jul 21 12:00:00",
        hostname="ubuntu-server",
        service="sshd",
        event_type="failed_login",
        username="admin",
        source_ip=source_ip,
        source_port=22,
        protocol="ssh2",
    )


def test_detects_ip_reaching_threshold():
    events = [
        create_failed_login_event("192.168.1.10"),
        create_failed_login_event("192.168.1.10"),
        create_failed_login_event("192.168.1.10"),
        create_failed_login_event("10.0.0.5"),
    ]

    suspicious_ips = detect_brute_force(events, threshold=3)

    assert suspicious_ips == ["192.168.1.10"]


def test_returns_empty_list_when_threshold_not_reached():
    events = [
        create_failed_login_event("192.168.1.10"),
        create_failed_login_event("192.168.1.10"),
    ]

    suspicious_ips = detect_brute_force(events, threshold=3)

    assert suspicious_ips == []