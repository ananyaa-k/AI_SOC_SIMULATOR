"""MITRE ATT&CK mapping registry (single source of truth for detection rules).

REVIEW REQUIRED (project owner): technique choices below are proposals with
written rationale. Verify each one before treating it as final -- the README
for this phase must be able to justify every ``mitre_technique_id``. No
technique is assigned arbitrarily.

Structure
---------
``RULES`` maps a rule ID to:

* human-readable metadata (name, description, severity)
* the MITRE attributes every Detection must reproduce exactly
* ``rationale`` -- why this technique applies
* ``scenario`` -- which :mod:`simulation.log_generator` scenario exercises it
  (used by the detection-rate evaluation)

Severity convention (normalized again by the alert manager on Day 3):
LOW < MEDIUM < HIGH < CRITICAL.

All technique references follow ATT&CK for Enterprise, MITRE.
"""

RULES: dict[str, dict] = {
    "RULE-001": {
        "name": "Brute-Force Detection",
        "description": (
            "Multiple authentication failures from the same source IP against "
            "the same destination within a configurable time window."
        ),
        "severity": "HIGH",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
        "scenario": "brute_force",
        "rationale": (
            "Repeated failed logins from one source to one target indicate "
            "password guessing or spraying against a single account/service, "
            "i.e. credential access via brute force (T1110)."
        ),
    },
    "RULE-002": {
        "name": "Known Malicious IP Communication",
        "description": "Connection established to an IP on the simulated known-malicious list.",
        "severity": "HIGH",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Application Layer Protocol",
        "mitre_technique_id": "T1071",
        "scenario": "malicious_ip",
        "rationale": (
            "Contacting infrastructure already flagged as malicious is "
            "consistent with beaconing/command-and-control over a common "
            "protocol (T1071). Tactic chosen is Command and Control for the "
            "established connection context."
        ),
    },
    "RULE-003": {
        "name": "Suspicious PowerShell",
        "description": "PowerShell execution using obfuscation/execution-bypass flags (-enc, -encodedcommand, -exec bypass, -nop).",
        "severity": "MEDIUM",
        "mitre_tactic": "Execution",
        "mitre_technique": "Command and Scripting Interpreter: PowerShell",
        "mitre_technique_id": "T1059.001",
        "scenario": "suspicious_powershell",
        "rationale": (
            "PowerShell launched with encoded command and script-block bypass "
            "flags is a common execution primitive for attackers (T1059.001); "
            "the encoded payload component also touches obfuscation (T1027)."
        ),
    },
    "RULE-004": {
        "name": "Suspicious Command Execution",
        "description": "Command execution matching known suspicious enumeration/privilege patterns.",
        "severity": "MEDIUM",
        "mitre_tactic": "Execution",
        "mitre_technique": "Command and Scripting Interpreter",
        "mitre_technique_id": "T1059",
        "scenario": "suspicious_command",
        "rationale": (
            "Commands such as whoami / net user / wmic / taskkill / reg add "
            "executed by a user span discovery and persistence primitives; "
            "they are surfaced here under the shared Execution technique "
            "(T1059). More specific techniques (T1033, T1087, T1047) are "
            "possible follow-ups."
        ),
    },
}


def get_rule_meta(rule_id: str) -> dict:
    """Return rule metadata for ``rule_id``; raises KeyError if unknown."""
    if rule_id not in RULES:
        raise KeyError(f"unknown rule id {rule_id!r}; known: {sorted(RULES)}")
    return {"rule_id": rule_id, **RULES[rule_id]}


def expected_rule_for_scenario(scenario: str) -> str | None:
    """Return the rule ID that should fire for a generator scenario, if any."""
    for rule_id, meta in RULES.items():
        if meta["scenario"] == scenario:
            return rule_id
    return None