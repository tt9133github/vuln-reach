#!/usr/bin/env python3
"""Build evidence through OctoBus, run the local engine, and cross-check every verdict."""
from __future__ import annotations

import json
import os
import subprocess
import sys
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


def comparable(local: dict, remote: dict) -> dict:
    return {
        "verdict": (local.get("verdict"), remote.get("verdict")),
        "package": (local.get("package") or "", remote.get("package") or ""),
        "installed_version": (local.get("installed_version") or "", remote.get("installedVersion") or ""),
        "rule_id": (local.get("rule_id") or "", remote.get("ruleId") or ""),
        "source_commit": (local.get("source_commit") or "", remote.get("sourceCommit") or ""),
        "snapshot_id": (local.get("snapshot_id") or "", remote.get("snapshotId") or ""),
        "version_match": (
            {True: "pass", False: "fail", None: "unknown"}.get(local.get("checks", {}).get("version_match"), ""),
            remote.get("checks", {}).get("versionMatch", ""),
        ),
        "sink_present": (
            {True: "pass", False: "fail", None: "unknown"}.get(local.get("checks", {}).get("sink_present"), ""),
            remote.get("checks", {}).get("sinkPresent", ""),
        ),
        "preconditions": (
            sorted((name, {True: "pass", False: "fail", None: "unknown"}.get(value, "")) for name, value in local.get("checks", {}).get("preconditions", {}).items()),
            sorted((item.get("id", ""), item.get("status", "")) for item in remote.get("checks", {}).get("preconditions", [])),
        ),
    }


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    snapshot = grpc_call("BuildRepositoryEvidence", {})
    snapshot_id = str(snapshot.get("snapshotId", ""))
    if not snapshot_id:
        raise RuntimeError("snapshot response did not contain snapshotId")
    (REPORT / "snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "reachability.py"), "--snapshot-id", snapshot_id],
        check=True,
        cwd=ROOT,
    )
    local_doc = json.loads((REPORT / "verdicts.json").read_text(encoding="utf-8"))
    verified = []
    comparisons = []
    for local in local_doc.get("verdicts", []):
        selector = {"snapshotId": snapshot_id}
        if local.get("cve_id"):
            selector["cveId"] = local["cve_id"]
        else:
            selector["alertNumber"] = local["alert_number"]
        remote = grpc_call("CheckReachability", selector)
        fields = comparable(local, remote)
        mismatches = [name for name, values in fields.items() if values[0] != values[1]]
        final = dict(local)
        if mismatches:
            final["verdict"] = "unknown"
            final["confidence"] = "low"
            final["verdict_reason"] = f"Python/OctoBus mismatch: {', '.join(mismatches)}"
        verified.append(final)
        comparisons.append({
            "cve_id": local.get("cve_id", ""), "alert_number": local.get("alert_number", 0),
            "matched": not mismatches, "mismatches": mismatches, "fields": fields,
            "octobus": remote,
        })

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    (REPORT / "verified-verdicts.json").write_text(json.dumps({
        "schema_version": "verified-verdict/1.0", "generated_at": generated_at,
        "snapshot_id": snapshot_id, "verdicts": verified,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (REPORT / "cross-check.json").write_text(json.dumps({
        "schema_version": "cross-check/1.0", "generated_at": generated_at,
        "snapshot_id": snapshot_id, "all_matched": all(item["matched"] for item in comparisons),
        "comparisons": comparisons,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"pipeline complete: snapshot={snapshot_id}, alerts={len(verified)}, all_matched={all(item['matched'] for item in comparisons)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
