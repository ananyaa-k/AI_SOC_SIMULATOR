"""Simulated response actions (spec: responses are simulated only).

The L1 agent may only recommend actions from :data:`RESPONSE_ACTIONS`. Nothing
here touches real infrastructure: "executing" an action just produces a
record describing what *would* have happened, which goes into the audit
timeline.
"""

from __future__ import annotations

from dataclasses import dataclass

# action -> human-readable description of what a real SOC would do.
RESPONSE_ACTIONS: dict[str, str] = {
    "BLOCK_IP": "Block the source IP at the perimeter firewall",
    "DISABLE_ACCOUNT": "Disable the affected user account",
    "RESET_CREDENTIALS": "Force a credential reset for the affected account",
    "ISOLATE_HOST": "Isolate the affected host from the network",
    "KILL_PROCESS": "Terminate the offending process on the host",
    "QUARANTINE_FILE": "Quarantine the suspicious file",
    "MONITOR": "Add the indicator to a watchlist and keep monitoring",
    "NO_ACTION": "No response needed (benign / false positive)",
}

STATUS_SIMULATED = "SIMULATED"
STATUS_PENDING_APPROVAL = "PENDING_HUMAN_APPROVAL"


@dataclass(frozen=True)
class SimulatedResponse:
    action: str
    description: str
    target: str | None
    status: str

    def as_detail(self) -> dict:
        return {
            "action": self.action,
            "description": self.description,
            "target": self.target,
            "status": self.status,
            "simulated": True,
        }


def is_known_action(action: str | None) -> bool:
    return action is not None and action in RESPONSE_ACTIONS


def simulate_response(action: str, target: str | None, *, approved: bool) -> SimulatedResponse:
    """Record what the action would do.

    ``approved`` is True only for auto-resolved incidents; escalated ones keep
    the recommendation pending until a human analyst signs off.
    """
    if not is_known_action(action):
        raise ValueError(f"unknown response action {action!r}")
    return SimulatedResponse(
        action=action,
        description=RESPONSE_ACTIONS[action],
        target=target,
        status=STATUS_SIMULATED if approved else STATUS_PENDING_APPROVAL,
    )
