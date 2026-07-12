import re

from threatforge.models.event import Event

FAILED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\w+)\[\d+\]:\s+"
    r"Failed password for (?P<username>\w+) from "
    r"(?P<source_ip>[\d.]+) port "
    r"(?P<source_port>\d+) "
    r"(?P<protocol>\w+)"
)


def parse_auth_line(line: str) -> Event | None:
    match = FAILED_LOGIN_PATTERN.search(line)

    if not match:
        return None
    data = match.groupdict()

    return Event(

            timestamp=data["timestamp"],
            hostname=data["hostname"],
            service=data["service"],
            event_type="failed_login",
            username=data["username"],
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            protocol=data["protocol"],

        )