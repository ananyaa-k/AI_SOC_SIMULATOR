"""Deterministic simulated attack log generator.

Generates normalized :class:`SecurityLog` records that mix benign baseline
events with malicious events for a given scenario. It is NOT real telemetry
and makes no claim to represent production data -- it exists so the SOC
pipeline can be exercised end to end.

Design goals
------------
* Deterministic: identical ``(scenario, seed)`` inputs produce identical
  output, which makes tests and detection evaluation reproducible.
* Labeled ground truth: every emitted event carries ``metadata.ground_truth``
  (bool) and ``metadata.scenario`` so later phases can measure detection rate
  and RAG retrieval accuracy without manual labelling.
* Safe addresses: all IPs come from RFC 5737 documentation ranges
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) -- never real hosts.
"""

from __future__ import annotations

import argparse
import json
import random
import zlib
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from pathlib import Path
from typing import Iterable

from app.models.security_log import LogEventType, SecurityLog

BASE_TS = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)

# RFC 5737 documentation ranges (never routable, safe to keep in the repo).
ATTACKER_IP = "203.0.113.10"  # TEST-NET-3
INTERNAL_IPS = ["10.0.0.12", "10.0.0.25", "10.0.0.60"]
INTERNAL_HOSTS = ["srv-web-01", "srv-auth-01", "srv-db-01", "ws-user-07"]
LEGIT_EXTERNAL = "192.0.2.40"  # TEST-NET-1, benign external endpoint

MALICIOUS_IPS: dict[str, str] = {
    "198.51.100.5": "c2_proxy",  # TEST-NET-2
    "198.51.100.9": "malware_download",
    "198.51.100.23": "known_phishing",
}

SUSPICIOUS_COMMANDS = [
    "whoami",
    "net user administrator",
    "net group \"Domain Admins\" /domain",
    "wmic process list full",
    "taskkill /F /IM svchost.exe",
    "reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinSock\\Parameters",
]

BENIGN_COMMANDS = [
    "dir C:\\Users\\jdoe\\Documents",
    "ipconfig /all",
    "type C:\\Users\\jdoe\\AppData\\Roaming\\app\\config.yml",
    "ping 10.0.0.1 -n 2",
    "Get-Process | Sort-Object Name",
]

POWERSHELL_FLAGS = ["-enc", "-encodedcommand", "-exec bypass", "-nop", "-w hidden"]


def _default_seed(scenario: str) -> int:
    """Stable default seed per scenario (str hashing is randomized per run)."""
    return zlib.crc32(scenario.encode("utf-8"))


def _event_meta(scenario: str, is_malicious: bool, category: str) -> dict:
    return {
        "source": "ai_soc_simulator",
        "scenario": scenario,
        "ground_truth": is_malicious,
        "attack_category": category,
    }


def _log(
    idx: int,
    event_type: LogEventType,
    source: str,
    meta: dict,
    *,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    protocol: str | None = None,
    username: str | None = None,
    command: str | None = None,
    url: str | None = None,
    status: str | None = None,
    raw_message: str | None = None,
) -> SecurityLog:
    return SecurityLog(
        timestamp=BASE_TS + timedelta(seconds=idx),
        source=source,
        event_type=event_type,
        source_ip=IPv4Address(source_ip) if source_ip else None,
        destination_ip=IPv4Address(destination_ip) if destination_ip else None,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        username=username,
        command=command,
        url=url,
        status=status,
        raw_message=raw_message or f"{source} {event_type.value}",
        metadata=meta,
    )


# --------------------------------------------------------------------------
# Benign building blocks
# --------------------------------------------------------------------------

def _benign_logins(rng: random.Random, start: int, count: int, meta: dict) -> list[SecurityLog]:
    users = ["jdoe", "asmith", "klane"]
    logs: list[SecurityLog] = []
    for i in range(count):
        idx = start + i
        user = rng.choice(users)
        logs.append(
            _log(
                idx,
                LogEventType.AUTH_SUCCESS,
                "srv-auth-01",
                meta,
                source_ip=rng.choice(INTERNAL_IPS),
                destination_ip="10.0.0.5",
                source_port=40000 + rng.randint(0, 9999),
                destination_port=22,
                protocol="ssh",
                username=user,
                status="ACCEPT",
                raw_message=f"Accepted password for {user} from {rng.choice(INTERNAL_IPS)} port {40000 + rng.randint(0, 9999)} ssh2",
            )
        )
    return logs


def _benign_web(rng: random.Random, start: int, count: int, meta: dict) -> list[SecurityLog]:
    urls = ["/index.html", "/assets/app.js", "/api/v1/health", "/login", "/docs"]
    logs: list[SecurityLog] = []
    for i in range(count):
        idx = start + i
        logs.append(
            _log(
                idx,
                LogEventType.URL_REQUEST,
                "srv-web-01",
                meta,
                source_ip=rng.choice(INTERNAL_IPS),
                destination_ip=LEGIT_EXTERNAL,
                source_port=50000 + rng.randint(0, 9999),
                destination_port=443,
                protocol="https",
                url=rng.choice(urls),
                status="200",
                raw_message=f"GET {rng.choice(urls)} -> 200",
            )
        )
    return logs


def _benign_commands(rng: random.Random, start: int, count: int, meta: dict) -> list[SecurityLog]:
    logs: list[SecurityLog] = []
    for i in range(count):
        idx = start + i
        host = "ws-user-07"
        cmd = rng.choice(BENIGN_COMMANDS)
        logs.append(
            _log(
                idx,
                LogEventType.COMMAND_EXEC,
                host,
                meta,
                source_ip=rng.choice(INTERNAL_IPS),
                username="jdoe",
                command=cmd,
                raw_message=f"user jdoe ran: {cmd}",
            )
        )
    return logs


def _benign_baseline(rng: random.Random, start: int, count: int, scenario: str) -> list[SecurityLog]:
    """Interleave benign logins, web traffic and commands for realistic context."""
    meta = _event_meta(scenario, is_malicious=False, category="benign")
    thirds = max(1, count // 3)
    return [
        *_benign_logins(rng, start, thirds, meta),
        *_benign_web(rng, start + thirds, thirds, meta),
        *_benign_commands(rng, start + (2 * thirds), count - (2 * thirds), meta),
    ]


# --------------------------------------------------------------------------
# Malicious scenarios
# --------------------------------------------------------------------------

def _scenario_brute_force(rng: random.Random, seed: int, fails: int = 25) -> list[SecurityLog]:
    scenario = "brute_force"
    benign = _benign_baseline(rng, 0, 8, scenario)
    base_idx = len(benign)
    meta = _event_meta(scenario, is_malicious=True, category="brute_force")
    target_user, target_host = "admin", "srv-auth-01"

    malicious: list[SecurityLog] = []
    for i in range(fails):
        idx = base_idx + i
        port = 35000 + rng.randint(0, 20000)
        malicious.append(
            _log(
                idx,
                LogEventType.AUTH_FAILURE,
                target_host,
                meta,
                source_ip=ATTACKER_IP,
                destination_ip="10.0.0.5",
                source_port=port,
                destination_port=22,
                protocol="ssh",
                username=target_user,
                status="REJECTED",
                raw_message=f"Failed password for {target_user} from {ATTACKER_IP} port {port} ssh2",
            )
        )
    return sorted([*benign, *malicious], key=lambda e: e.timestamp)


def _scenario_suspicious_powershell(rng: random.Random, seed: int, count: int = 6) -> list[SecurityLog]:
    scenario = "suspicious_powershell"
    benign = _benign_baseline(rng, 0, 6, scenario)
    base_idx = len(benign)
    meta = _event_meta(scenario, is_malicious=True, category="powershell_exec")

    malicious: list[SecurityLog] = []
    enc_cmds = [
        "SQBGACAoZ2V0LWNvbW1hbmQ..."
        "YWRtaW4gLSAt",
        "JGM9TmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50...",
        "SVBjb25maWcgLy1hbGw=...",
    ]
    for i in range(count):
        idx = base_idx + i
        flag = rng.choice(POWERSHELL_FLAGS)
        body = enc_cmds[i % len(enc_cmds)]
        cmd = f"powershell.exe {flag} {body}"
        malicious.append(
            _log(
                idx,
                LogEventType.POWERSHELL_EXEC,
                "ws-user-07",
                meta,
                source_ip="10.0.0.60",
                username="jdoe",
                command=cmd,
                raw_message=f"powershell: {cmd}",
            )
        )
    return sorted([*benign, *malicious], key=lambda e: e.timestamp)


def _scenario_malicious_ip(rng: random.Random, seed: int, targets: int = 3) -> list[SecurityLog]:
    scenario = "malicious_ip"
    benign = _benign_baseline(rng, 0, 6, scenario)
    base_idx = len(benign)
    same_cat_meta = _event_meta(scenario, is_malicious=True, category="malicious_communication")

    malicious: list[SecurityLog] = []
    chosen = list(MALICIOUS_IPS.keys())[:targets]
    for i, dst in enumerate(chosen):
        idx = base_idx + i
        cat = MALICIOUS_IPS[dst]
        meta = _event_meta(scenario, is_malicious=True, category=f"c2_{cat}")
        malicious.append(
            _log(
                idx,
                LogEventType.NETWORK_CONNECTION,
                "ws-user-07",
                meta,
                source_ip="10.0.0.60",
                destination_ip=dst,
                source_port=52000 + rng.randint(0, 999),
                destination_port=443 if rng.random() > 0.5 else 8443,
                protocol="tcp",
                url=None,
                status="ESTABLISHED",
                raw_message=f"TCP connection to {dst}:{443} established",
            )
        )
        same_cat_meta = meta
    return sorted([*benign, *malicious], key=lambda e: e.timestamp)


def _scenario_suspicious_command(rng: random.Random, seed: int, count: int = 5) -> list[SecurityLog]:
    scenario = "suspicious_command"
    benign = _benign_baseline(rng, 0, 6, scenario)
    base_idx = len(benign)
    meta = _event_meta(scenario, is_malicious=True, category="suspicious_command")

    malicious: list[SecurityLog] = []
    for i in range(count):
        idx = base_idx + i
        cmd = SUSPICIOUS_COMMANDS[i % len(SUSPICIOUS_COMMANDS)]
        malicious.append(
            _log(
                idx,
                LogEventType.COMMAND_EXEC,
                "ws-user-07",
                meta,
                source_ip="10.0.0.60",
                username="jdoe",
                command=cmd,
                raw_message=f"user jdoe ran: {cmd}",
            )
        )
    return sorted([*benign, *malicious], key=lambda e: e.timestamp)


SCENARIOS: dict[str, dict] = {
    "brute_force": {"desc": "repeated SSH auth failures", "fn": _scenario_brute_force},
    "suspicious_powershell": {"desc": "powershell with encoded/obfuscation flags", "fn": _scenario_suspicious_powershell},
    "malicious_ip": {"desc": "connections to known malicious IPs", "fn": _scenario_malicious_ip},
    "suspicious_command": {"desc": "command execution matching suspicious patterns", "fn": _scenario_suspicious_command},
}


def generate_scenario(scenario: str, seed: int | None = None) -> list[SecurityLog]:
    """Generate one deterministic scenario's log stream.

    :param scenario: one of :data:`SCENARIOS` keys.
    :param seed: RNG seed; defaults to a stable per-scenario value so repeated
        runs are identical unless a seed is given.
    :raises KeyError: unknown scenario name.
    """
    if scenario not in SCENARIOS:
        raise KeyError(f"unknown scenario '{scenario}'; choose from {sorted(SCENARIOS)}")
    rng = random.Random(seed if seed is not None else _default_seed(scenario))
    logs = SCENARIOS[scenario]["fn"](rng, seed if seed is not None else _default_seed(scenario))
    return sorted(logs, key=lambda e: e.timestamp)


def generate_benign(seed: int | None = None, count: int = 20) -> list[SecurityLog]:
    """Generate a fully benign log stream (no malicious events).

    Used by false-positive tests: a healthy detector must return zero
    detections for this stream.
    """
    rng = random.Random(seed if seed is not None else _default_seed("benign"))
    return sorted(_benign_baseline(rng, 0, count, "benign"), key=lambda e: e.timestamp)


def generate_all(seed: int | None = None) -> dict[str, list[SecurityLog]]:
    """Generate every scenario; useful for sample data / evaluation fixtures."""
    return {name: generate_scenario(name, seed=seed) for name in SCENARIOS}


def to_json_lines(logs: Iterable[SecurityLog]) -> str:
    return "\n".join(e.model_dump_json() for e in logs)


def _cli() -> None:
    parser = argparse.ArgumentParser(description="Generate simulated SOC log batches (JSON Lines).")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), help="single scenario (omit for all)")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed (default: stable per scenario)")
    parser.add_argument("--out", default=None, help="output file path; writes to stdout if omitted")
    args = parser.parse_args()

    batches = (
        {args.scenario: generate_scenario(args.scenario, seed=args.seed)}
        if args.scenario
        else generate_all(seed=args.seed)
    )

    lines: list[str] = []
    for name, logs in batches.items():
        for e in logs:
            lines.append(e.model_dump_json())
    payload = "\n".join(lines)

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload + "\n", encoding="utf-8")
        print(f"wrote {len(lines)} log lines to {out}", file=None)
    else:
        print(payload)


if __name__ == "__main__":
    _cli()