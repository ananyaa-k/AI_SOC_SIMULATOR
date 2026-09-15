# Security Log Schema

Every raw event produced by the simulator is normalized into a single
`SecurityLog` record (`backend/app/models/security_log.py`). The rule engine
(added Day 2) will consume this exact schema, so it is deliberately generic:
fields are optional per event type rather than forced into every record.

## Fields

| Field            | Type                 | Required | Notes                                                        |
| ---------------- | -------------------- | -------- | ------------------------------------------------------------ |
| `timestamp`      | `datetime` (UTC)     | yes      | Event time; generator emits monotonically increasing timestamps |
| `source`         | `str`                | yes      | Hostname/component that produced the event (e.g. `srv-auth-01`) |
| `event_type`     | `LogEventType` enum  | yes      | Canonical normalized type, see below                          |
| `source_ip`      | `IPv4Address?`       | no       | Validated; invalid IPs raise `ValidationError`               |
| `destination_ip` | `IPv4Address?`       | no       |                                                               |
| `source_port`    | `int?`               | no       |                                                               |
| `destination_port` | `int?`             | no       |                                                               |
| `protocol`       | `str?`               | no       | e.g. `ssh`, `tcp`, `https`                                    |
| `username`       | `str?`               | no       | Relevant for auth/command events                              |
| `command`        | `str?`               | no       | For `COMMAND_EXEC` / `POWERSHELL_EXEC` events                 |
| `url`            | `str?`               | no       | For `URL_REQUEST` events                                      |
| `status`         | `str?`               | no       | e.g. `ACCEPT`, `REJECTED`, HTTP status                        |
| `raw_message`    | `str`                | yes      | Original telemetry text; preserved for audit / evidence       |
| `metadata`       | `dict`               | no       | Arbitrary context; the generator stores `ground_truth`, `scenario`, `attack_category` |

## Event Types (`LogEventType`)

| Event               | Description                              |
| ------------------- | ---------------------------------------- |
| `AUTH_FAILURE`      | Failed authentication attempt            |
| `AUTH_SUCCESS`      | Successful authentication               |
| `PROCESS_EXEC`      | Process execution                        |
| `POWERSHELL_EXEC`   | PowerShell invocation                    |
| `COMMAND_EXEC`      | Shell/command execution                  |
| `NETWORK_CONNECTION`| Network connection attempt/establishment |
| `URL_REQUEST`       | HTTP/HTTPS request                       |
| `FILE_WRITE`        | File write activity                      |

## Design decisions

* **Enum `event_type`** keeps detection rules stable and avoids string drift.
* **`raw_message` is always present** so the deterministic detectors and the
  audit trail can always reference the original telemetry.
* **Optional fields, not sparse nulls everywhere**: logs only carry the fields
  that make sense for their event type (e.g. no `url` on `AUTH_FAILURE`).

## Ground-truth metadata

Generated events include:

```json
"metadata": {
  "source": "ai_soc_simulator",
  "scenario": "brute_force",
  "ground_truth": true,
  "attack_category": "brute_force"
}
```

`ground_truth` lets the Day 2 detection-evaluation suite measure detection
rate without manual labelling.

## IP address policy

All addresses use RFC 5737 documentation ranges, so nothing in the repo is
routable or claimable as real infrastructure:

* `192.0.2.0/24` – TEST-NET-1 (benign external endpoint)
* `198.51.100.0/24` – TEST-NET-2 (simulated malicious list)
* `203.0.113.0/24` – TEST-NET-3 (simulated attacker)
* `10.0.0.0/24` – internal network