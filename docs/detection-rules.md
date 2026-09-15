# Detection Layer — Design & Contract

## What it is

The deterministic detection layer turns normalized `SecurityLog` records into
structured `Detection` objects carrying MITRE ATT&CK metadata and evidencing
events. It is deliberately **not** LLM-powered: known attack patterns are
matched by explicit, readable rules (spec §11–§12, §42).

```
SecurityLog stream -> rule_engine.detect(logs) -> list[Detection]
```

## Component contract

### Output — `detection/schemas.py`

A `Detection` must contain:

| field              | meaning                                                    |
| ------------------ | ---------------------------------------------------------- |
| `rule_id`          | registry key, e.g. `RULE-001`                              |
| `rule_name`        | human name                                                  |
| `severity`         | normalized from the MITRE registry (LOW..CRITICAL)          |
| `mitre_tactic`     | from registry                                               |
| `mitre_technique`  | from registry                                               |
| `mitre_technique_id`| from registry                                              |
| `evidence`         | the **triggering** `SecurityLog` records (not everything)   |
| `detected_at`      | timestamp                                                   |
| `meta`             | optional supporting values (counts, matched flag/IP, …)     |

### Rule — `detection/rules/base.py`

```python
class BruteForceRule(DetectionRule):
    meta = RuleMeta(**get_rule_meta("RULE-001"))
    def evaluate(self, logs: Sequence[SecurityLog]) -> list[Detection]: ...
```

* One rule class per pattern; rules do their own window/sequence correlation
  inside `evaluate`. The engine doesn't correlate for them.
* MITRE fields must come from `mitre_mapping.get_rule_meta(...)`, never
  duplicated literals.

### Engine — `rule_engine.py` (YOUR implementation)

```python
def detect(logs: Sequence[SecurityLog], rules: Sequence[DetectionRule] | None = None) -> list[Detection]:
    ...
```

* `rules=None` means "built-in default set" (all four registered rules).
* Order-insensitive input; can sort internally.
* Returns `[]` on empty input. Never raises on benign traffic.

## Files for the owner to implement (core logic — not written for you)

| file                                  | rule      | pattern                   |
| ------------------------------------- | --------- | ------------------------- |
| `detection/rules/brute_force.py`      | RULE-001  | auth failures, same src→dst, in window |
| `detection/rules/malicious_ip.py`     | RULE-002  | connection to known-bad IP list         |
| `detection/rules/suspicious_powershell.py` | RULE-003 | PowerShell with `-enc`/`-encodedcommand`/bypass flags |
| `detection/rules/suspicious_command.py` | RULE-004 | command matches suspicious set          |
| `detection/rule_engine.py`            | —         | rule orchestration + dedup              |

## Design decisions to make while implementing

* **Window semantics** — brute force needs a threshold like "≥ N failures from
  the same source to the same destination within W seconds, same service".
  Put N and W in readable config constants on the rule, not scattered magic
  numbers.
* **Independent triggers / dedup** — a rule should emit *one* Detection per
  correlated cluster, not one per event. If the same source keeps failing
  after a window closes, that's a second Detection, not a flood.
* **Evidence fidelity** — `evidence` must be provable from the input batch.
  Slicing an unsorted batch can give misleading evidence; decide whether rules
  sort internally first.
* **Unknown/partial fields** — auth failures only exist for `AUTH_FAILURE`
  events with `source_ip`; guard accordingly (typing permits `None`).

## Edge cases (test coverage already written)

* empty logs → `[]`
* benign-only stream (any seed) → zero detections (false positives are worse
  than misses in an interview narrative)
* every scenario fires exactly its expected rule
* MITRE fields equal the registry (no drift)
* deterministic: same batch → same detections
* combined multi-scenario batch → no crash, all four rule types present

## False-positive considerations

* A system that auto-resolves on false positives is dangerous, not clever.
  Because RAG + agent phases (Day 5–6) key off `Detection`, rule thresholds
  should prefer *confident* matches. A missed one-off is salvageable by
  escalation policy; a flawed rule that fires on clean traffic is not.
* Rule confidence emerges later from historical similarity — detection itself
  must stay a hard gate.

## Acceptance gate (§16)

`backend/tests/test_detection_rate.py` injects every scenario × 8 seeds and
requires **≥ 80%** of cases to fire the expected rule:

```
pytest -s backend/tests/test_detection_rate.py   # prints the rate table
pytest backend/tests/test_detection_rate.py      # CI asserts the gate
```

Run the full suite with `pytest` (detection tests auto-skip until
`rule_engine.py` exists).