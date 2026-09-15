from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address
from typing import Any

from pydantic import BaseModel, ConfigDict


class LogEventType(str, Enum):
    """Canonical normalized event types used across the simulator.

    Every raw log line is normalized into one of these. Individual fields in
    :class:`SecurityLog` stay optional because not every field is meaningful
    for every event type (e.g. a ``PROCESS_EXEC`` has no URL).
    """

    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    PROCESS_EXEC = "PROCESS_EXEC"
    POWERSHELL_EXEC = "POWERSHELL_EXEC"
    COMMAND_EXEC = "COMMAND_EXEC"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    URL_REQUEST = "URL_REQUEST"
    FILE_WRITE = "FILE_WRITE"


class SecurityLog(BaseModel):
    """Normalized security event.

    This is the single schema the rule engine will consume on Day 2, which is
    why it is deliberately generic: fields are optional per event type rather
    than forced into every record. Raw source messages are preserved in
    ``raw_message`` so the deterministic detectors and audit trail can always
    reference the original telemetry.
    """

    model_config = ConfigDict(use_enum_values=True)

    timestamp: datetime
    source: str  # hostname / component that produced the event
    event_type: LogEventType

    source_ip: IPv4Address | None = None
    destination_ip: IPv4Address | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    username: str | None = None
    command: str | None = None
    url: str | None = None
    status: str | None = None

    raw_message: str
    metadata: dict[str, Any] = {}