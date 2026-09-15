"""Concrete detection rules -- CORE SECURITY LOGIC (owned by the project owner).

Files the owner must implement in this package:

* ``brute_force.py``          -> RULE-001 (T1110)
* ``malicious_ip.py``         -> RULE-002 (T1071)
* ``suspicious_powershell.py``-> RULE-003 (T1059.001)
* ``suspicious_command.py``   -> RULE-004 (T1059)

Each module exposes one :class:`~detection.rules.base.DetectionRule` subclass
with ``meta`` built from :func:`detection.mitre_mapping.get_rule_meta`, plus
an ``evaluate(logs)`` returning :class:`~detection.schemas.Detection` objects.

No rules are implemented here (reference only). See docs/detection-rules.md.
"""