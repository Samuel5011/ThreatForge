from pathlib import Path

from threatforge.models.event import Event
from threatforge.parser.auth_parser import parse_auth_line


def read_auth_log(file_path: str) -> list[Event]:
    events: list[Event] = []

    path = Path(file_path)

    with path.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_auth_line(line)

            if event is not None:
                events.append(event)

    return events