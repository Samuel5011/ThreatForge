from threatforge.parser.log_reader import read_auth_log


def test_read_auth_log_returns_valid_events() -> None:
    """Verify that valid authentication log entries are parsed from a file."""

    events = read_auth_log("sample_logs/auth.log")

    assert len(events) == 3
    assert events[0].username == "root"
    assert events[1].username == "admin"
    assert events[2].username == "ubuntu"

# Makes sure unsupported log lines are ignored safely
def test_read_auth_log_ignores_unsupported_lines() -> None:

    events = read_auth_log("sample_logs/auth.log")
    assert all(event.event_type == "failed_login" for event in events)