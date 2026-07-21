from threatforge.parser.auth_parser import parse_auth_line

# Verifies valid failed SSh login log is parsed correctly
def test_parse_failed_login() -> None:
    line = (
        "Jul 11 18:21:41 linux-lab sshd[2341]: "
        "Failed password for root from 192.168.64.10 port 51244 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event.event_type == "failed_login"
    assert event.username == "root"
    assert event.source_ip == "192.168.64.10"
    assert event.source_port == 51244
    assert event.hostname == "linux-lab"


# Verifies that invalid log lines return None
def test_returns_none_for_unsupported_line() -> None:
    line = "This is not an SSH authentication log"

    event = parse_auth_line(line)

    assert event is None




    