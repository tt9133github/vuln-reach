#!/usr/bin/env python3
"""Build repository evidence and obtain every verdict through OctoBus."""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(os.environ.get("VULN_REACH_ROOT", Path(__file__).resolve().parents[1]))
REPORT = ROOT / "report"
SERVICE = "vulnreach.v1.VulnReachService"


def grpc_call(method: str, payload: dict) -> dict:
    token = os.environ.get("CAP_TOKEN", "")
    if not token:
        raise RuntimeError("CAP_TOKEN is not injected into the Guest")
    target = os.environ.get("CAP_GRPC_TARGET", "agent-compose:7411")
    command = [
        "grpcurl", "-plaintext",
        "-H", f"x-capability-sandbox-token: {token}",
        "-H", "x-octobus-capset: vulnreach",
        "-H", "x-octobus-instance: reach-01",
        "-d", json.dumps(payload, separators=(",", ":")),
        target, f"{SERVICE}/{method}",
    ]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()[:1000]
        raise RuntimeError(f"OctoBus {method} failed: {detail}")
    return json.loads(completed.stdout)


def normalize_verdict(remote: dict) -> dict:
    checks = remote.get("checks") or {}
    level_checks = remote.get("levelChecks") or {}
    return {
        "cve_id": remote.get("cveId", ""),
        "ghsa_id": remote.get("ghsaId", ""),
        "alert_number": remote.get("alertNumber", 0),
        "state": remote.get("alertState", ""),
        "severity": remote.get("advisorySeverity", ""),
        "package": remote.get("package", ""),
        "installed_version": remote.get("installedVersion", ""),
        "affected_versions": remote.get("affectedVersions", ""),
        "fixed_version": remote.get("fixedVersion", ""),
        "rule_id": remote.get("ruleId", ""),
        "source_commit": remote.get("sourceCommit", ""),
        "snapshot_id": remote.get("snapshotId", ""),
        "scope": remote.get("scope", ""),
        "limitations": remote.get("limitations", []),
        "checks": {
            "version_match": checks.get("versionMatch", "unknown"),
            "sink_present": checks.get("sinkPresent", "unknown"),
            "preconditions": {
                item.get("id", ""): item.get("status", "unknown")
                for item in checks.get("preconditions", [])
                if item.get("id")
            },
        },
        "verdict": remote.get("verdict", "unknown"),
        "confidence": remote.get("confidence", "low"),
        "verdict_reason": remote.get("reason", ""),
        "reachability_level": remote.get("reachabilityLevel", "unknown"),
        "level_reason": remote.get("levelReason", ""),
        "governance_action": remote.get("governanceAction", ""),
        "level_checks": {
            "component_usage": level_checks.get("componentUsage", "unknown"),
            "dangerous_sink": level_checks.get("dangerousSink", "unknown"),
            "external_input_to_sink": level_checks.get("externalInputToSink", "unknown"),
            "complete_attack_path": level_checks.get("completeAttackPath", "unknown"),
        },
        "evidence": [
            {
                "rule_id": item.get("ruleId", ""),
                "check": item.get("check", ""),
                "status": item.get("status", "unknown"),
                "detail": item.get("detail", ""),
                "file": item.get("file", ""),
                "line": item.get("line", 0),
                "observed": item.get("observed", ""),
                "expected": item.get("expected", ""),
            }
            for item in remote.get("evidence", [])
        ],
        "fix": remote.get("fix", []),
    }


def build_markdown(verdicts: list[dict], snapshot: dict, generated_at: str) -> str:
    lines = [
        "# Vulnerability Reachability Report", "",
        f"- generated_at: {generated_at}",
        f"- snapshot_id: `{snapshot.get('snapshotId', '')}`",
        f"- source commit: `{snapshot.get('resolvedCommit', '')}`",
        f"- alerts analyzed: {len(verdicts)}", "",
    ]
    for value in sorted(verdicts, key=lambda item: item["alert_number"]):
        lines += [
            f"## #{value['alert_number']} {value['cve_id']} — {value['verdict'].upper()} ({value['confidence']})", "",
            f"- package: `{value['package']}:{value['installed_version'] or 'not found'}`",
            f"- alert state/severity: `{value['state'] or 'unknown'}` / `{value['severity'] or 'unknown'}`",
            f"- affected/fixed: `{value['affected_versions']}` / `{value['fixed_version'] or 'n/a'}`",
            f"- rule: `{value['rule_id'] or 'none'}`",
            f"- scope: {value['scope']}",
            f"- verdict reason: {value['verdict_reason']}", "", "### Checks", "",
            f"- version_match: {value['checks']['version_match'].upper()}",
            f"- sink_present: {value['checks']['sink_present'].upper()}",
        ]
        lines.extend(
            f"- precondition `{name}`: {status.upper()}"
            for name, status in value["checks"]["preconditions"].items()
        )
        lines += [
            "", "### Enterprise Reachability Level", "",
            f"- level: **{value['reachability_level']}**",
            f"- reason: {value['level_reason']}",
            f"- governance action: {value['governance_action']}",
            f"- component_usage: {value['level_checks']['component_usage'].upper()}",
            f"- dangerous_sink: {value['level_checks']['dangerous_sink'].upper()}",
            f"- external_input_to_sink: {value['level_checks']['external_input_to_sink'].upper()}",
            f"- complete_attack_path: {value['level_checks']['complete_attack_path'].upper()}",
        ]
        lines += ["", "### Evidence", ""]
        for item in value["evidence"]:
            location = f" ({item['file']}:{item['line']})" if item["file"] and item["line"] else ""
            lines.append(f"- [{item['status'].upper()}] `{item['rule_id']}` `{item['check']}`{location}: {item['detail']}")
        lines += ["", "### Limitations", ""]
        lines.extend(f"- {item}" for item in value["limitations"])
        lines += ["", "### Fix", ""]
        lines.extend(f"- {item}" for item in value["fix"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def snapshot_alerts(snapshot_id: str) -> list[dict]:
    if not re.fullmatch(r"[0-9A-Za-z._-]+", snapshot_id):
        raise RuntimeError("snapshot response returned an invalid snapshotId")
    alerts_dir = ROOT / "runtime" / "snapshots" / snapshot_id / "alerts"
    if not alerts_dir.is_dir():
        raise RuntimeError(f"snapshot alerts are not visible in the Guest: {alerts_dir}")
    alerts = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(alerts_dir.glob("*.json"))
        if path.name != "index.json"
    ]
    if not alerts:
        raise RuntimeError("snapshot contains no alerts")
    return alerts


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    for obsolete in ("verified-verdicts.json", "cross-check.json"):
        (REPORT / obsolete).unlink(missing_ok=True)

    snapshot = grpc_call("BuildRepositoryEvidence", {})
    snapshot_id = str(snapshot.get("snapshotId", ""))
    if not snapshot_id:
        raise RuntimeError("snapshot response did not contain snapshotId")
    (REPORT / "snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    verdicts = []
    for alert in snapshot_alerts(snapshot_id):
        selector = {"snapshotId": snapshot_id}
        if alert.get("advisory", {}).get("cve_id"):
            selector["cveId"] = alert["advisory"]["cve_id"]
        else:
            selector["alertNumber"] = alert["alert"]["number"]
        verdicts.append(normalize_verdict(grpc_call("CheckReachability", selector)))

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (REPORT / "verdicts.json").write_text(json.dumps({
        "schema_version": "verdict/4.1", "generated_at": generated_at,
        "snapshot_id": snapshot_id, "source": "octobus", "verdicts": verdicts,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (REPORT / "reachability-report.md").write_text(
        build_markdown(verdicts, snapshot, generated_at), encoding="utf-8"
    )
    print(f"pipeline complete: snapshot={snapshot_id}, alerts={len(verdicts)}, source=octobus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
