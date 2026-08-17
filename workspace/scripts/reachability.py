#!/usr/bin/env python3
"""Deterministic, fail-closed vulnerability reachability analysis."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("missing PyYAML, install with: pip install PyYAML")

STATUS = {True: "pass", False: "fail", None: "unknown"}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def project_root() -> Path:
    return Path(os.environ.get("VULN_REACH_ROOT", Path(__file__).resolve().parents[1]))


def version_tuple(version: object) -> tuple[int, ...] | None:
    text = str(version or "").strip()
    if not text or not re.fullmatch(r"\d+(?:\.\d+)*", text):
        return None
    return tuple(int(part) for part in re.match(r"\d+(?:\.\d+)*", text).group(0).split("."))


def compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    size = max(len(left), len(right))
    a = left + (0,) * (size - len(left))
    b = right + (0,) * (size - len(right))
    return (a > b) - (a < b)


def parse_constraint(text: str) -> tuple[str, tuple[int, ...]] | None:
    match = re.fullmatch(r"\s*(<=|>=|<|>|==|=)?\s*(\d+(?:\.\d+)*)\s*", text)
    if not match:
        return None
    parsed = version_tuple(match.group(2))
    return (match.group(1) or "=", parsed) if parsed else None


def version_in_range(version: object, spec: object) -> bool | None:
    current = version_tuple(version)
    constraints = [parse_constraint(part) for part in str(spec or "").split(",")]
    if current is None or not spec or any(item is None for item in constraints):
        return None
    for operator, target in constraints:
        comparison = compare_versions(current, target)
        if operator == "<" and comparison >= 0:
            return False
        if operator == "<=" and comparison > 0:
            return False
        if operator == ">" and comparison <= 0:
            return False
        if operator == ">=" and comparison < 0:
            return False
        if operator in ("=", "==") and comparison != 0:
            return False
    return True


def resolve_evidence_path(evidence: dict, dotted_path: str) -> list:
    current = [evidence]
    for segment in dotted_path.split("."):
        expand = segment.endswith("[*]")
        key = segment[:-3] if expand else segment
        next_values = []
        for item in current:
            if not isinstance(item, dict) or key not in item:
                continue
            value = item[key]
            if expand and isinstance(value, list):
                next_values.extend(value)
            elif not expand:
                next_values.append(value)
        current = next_values
    return current


def sink_patterns(rule_sinks: list) -> list[str]:
    return [str(item.get("api", "") if isinstance(item, dict) else item) for item in (rule_sinks or []) if item]


def evidence_item(rule_id: str, check: str, value: bool | None, detail: str, **fields) -> dict:
    item = {"rule_id": rule_id, "check": check, "status": STATUS[value], "detail": detail}
    item.update({key: val for key, val in fields.items() if val not in (None, "")})
    return item


def check_sink(evidence: dict | None, patterns: list[str]) -> tuple[bool | None, str, list[dict]]:
    if not patterns:
        return True, "rule has no fixed sink API; usage evidence is evaluated by preconditions", (evidence or {}).get("usage", [])
    if not evidence:
        return None, "package usage evidence is missing", []
    matches = [item for item in evidence.get("sinks", []) if item.get("api") in patterns]
    if matches:
        return True, f"matched {len(matches)} rule-defined sink call(s)", matches
    if evidence.get("sink_scan_complete") is True:
        return False, "complete sink scan found no rule-defined call", []
    return None, "no matching sink found, but sink scan completeness is not established", []


def judge(alert: dict, rule: dict, dep: dict | None, evidence: dict | None, source: dict | None = None, snapshot_id: str = "") -> dict:
    rule_id = rule["rule_id"]
    installed = dep.get("version", "") if dep else ""
    authoritative = bool((source or {}).get("authoritative"))
    if dep:
        version_match = version_in_range(installed, rule.get("affected_versions"))
        version_detail = f"{dep.get('package')} {installed} against {rule.get('affected_versions', '')}"
    elif authoritative:
        version_match = False
        version_detail = "package absent from authoritative dependency inventory"
    else:
        version_match = None
        version_detail = "package absent and dependency inventory is not authoritative"

    patterns = sink_patterns(rule.get("sinks", []))
    sink_present, sink_detail, matches = check_sink(evidence, patterns)
    checks = {"version_match": version_match, "sink_present": sink_present, "preconditions": {}}
    items = [
        evidence_item(rule_id, "version_match", version_match, version_detail, observed=installed, expected=rule.get("affected_versions")),
        evidence_item(rule_id, "sink_present", sink_present, sink_detail, expected=", ".join(patterns)),
    ]
    for match in matches:
        check_name = "sink_call" if patterns else "usage"
        items.append(evidence_item(rule_id, check_name, True, match.get("context", "matched code usage"), file=match.get("file"), line=match.get("line"), observed=match.get("api")))

    for precondition in rule.get("preconditions", []):
        values = resolve_evidence_path(evidence or {}, precondition["evidence_path"])
        result = None if not values else any(value == precondition["expect"] for value in values)
        checks["preconditions"][precondition["id"]] = result
        location = {}
        if precondition["evidence_path"].startswith("entry_points[*]."):
            key = precondition["evidence_path"].split(".", 1)[1]
            matched_entry = next((entry for entry in (evidence or {}).get("entry_points", []) if entry.get(key) == precondition["expect"]), {})
            location = {"file": matched_entry.get("file"), "line": matched_entry.get("line")}
        items.append(evidence_item(rule_id, f"precondition:{precondition['id']}", result, precondition["description"], observed=json.dumps(values, ensure_ascii=False), expected=json.dumps(precondition["expect"], ensure_ascii=False), **location))

    flat_checks = [version_match, sink_present, *checks["preconditions"].values()]
    if any(value is False for value in flat_checks):
        verdict, reason = "not_reachable", "at least one required condition is explicitly false"
    elif any(value is None for value in flat_checks):
        verdict, reason = "unknown", "one or more required conditions lack trustworthy evidence"
    else:
        verdict, reason = "reachable", "version, sink and all exploit preconditions are established"

    located = any(item.get("file") and item.get("line") for item in items)
    confidence = "high" if verdict != "unknown" and located else ("medium" if verdict != "unknown" else "low")
    source = source or {}
    return {
        "cve_id": alert["advisory"]["cve_id"], "ghsa_id": alert["advisory"]["ghsa_id"],
        "alert_number": alert["alert"]["number"], "state": alert["alert"]["state"],
        "severity": alert["advisory"]["severity"], "package": alert["vulnerability"]["package"],
        "installed_version": installed, "affected_versions": rule.get("affected_versions", ""),
        "fixed_version": rule.get("fixed_version", ""), "rule_id": rule_id,
        "source_commit": source.get("commit", ""), "snapshot_id": snapshot_id,
        "scope": rule.get("scope", "component API boundary"),
        "limitations": rule.get("limitations", []), "checks": checks, "verdict": verdict,
        "confidence": confidence, "verdict_reason": reason, "evidence": items,
        "fix": rule.get("fix", []), "exploit_notes": rule.get("exploit_notes", ""),
    }


def mark(value: bool | None) -> str:
    return {True: "PASS", False: "FAIL", None: "UNKNOWN"}[value]


def build_markdown(verdicts: list, policy: dict, generated_at: str, snapshot_id: str) -> str:
    lines = ["# Vulnerability Reachability Report", "", f"- generated_at: {generated_at}", f"- snapshot_id: `{snapshot_id}`", f"- alerts analyzed: {len(verdicts)}", f"- policy: {policy['verdicts']['unknown']['definition']}", ""]
    for value in sorted(verdicts, key=lambda item: item["alert_number"]):
        lines += [f"## #{value['alert_number']} {value['cve_id']} — {value['verdict'].upper()} ({value['confidence']})", "", f"- package: `{value['package']}:{value['installed_version'] or 'not found'}`", f"- affected/fixed: `{value.get('affected_versions', '')}` / `{value.get('fixed_version', '') or 'n/a'}`", f"- rule: `{value.get('rule_id') or 'none'}`", f"- source commit: `{value.get('source_commit') or 'unknown'}`", f"- scope: {value.get('scope', '')}", f"- verdict reason: {value['verdict_reason']}", "", "### Checks", ""]
        if value.get("checks"):
            lines.append(f"- version_match: {mark(value['checks']['version_match'])}")
            lines.append(f"- sink_present: {mark(value['checks']['sink_present'])}")
            for key, result in value["checks"].get("preconditions", {}).items():
                lines.append(f"- {key}: {mark(result)}")
        lines += ["", "### Evidence", ""]
        for item in value.get("evidence", []):
            location = f" `{item['file']}:{item['line']}`" if item.get("file") and item.get("line") else ""
            lines.append(f"- [{item['status']}] `{item['check']}`{location}: {item['detail']}")
        lines += ["", "### Fix", "", *[f"- {fix}" for fix in value.get("fix", [])]]
        if value.get("limitations"):
            lines += ["", "### Limitations", "", *[f"- {item}" for item in value["limitations"]]]
        lines.append("")
    return "\n".join(lines)


def load_rules(rules_dir: Path) -> dict:
    rules = {}
    for rule_file in sorted(rules_dir.glob("*.yaml")):
        if rule_file.name == "verdict.yaml":
            continue
        for rule in (load_yaml(rule_file) or {}).get("rules", []):
            cve = rule.get("cve")
            if not cve or cve in rules:
                raise ValueError(f"missing or duplicate CVE rule: {cve!r}")
            rules[cve] = rule
    return rules


def unknown_verdict(alert: dict, reason: str, snapshot_id: str = "") -> dict:
    return {"cve_id": alert["advisory"]["cve_id"], "ghsa_id": alert["advisory"]["ghsa_id"], "alert_number": alert["alert"]["number"], "state": alert["alert"]["state"], "severity": alert["advisory"]["severity"], "package": alert["vulnerability"]["package"], "installed_version": "", "affected_versions": "", "fixed_version": "", "rule_id": None, "source_commit": "", "snapshot_id": snapshot_id, "scope": "component API boundary", "limitations": [], "checks": {}, "verdict": "unknown", "confidence": "low", "verdict_reason": reason, "evidence": [], "fix": []}


def resolve_snapshot(root: Path, runtime: str, requested_id: str) -> tuple[str, Path]:
    runtime_root = root / runtime
    snapshot_id = requested_id.strip()
    if not snapshot_id:
        pointer = load_json(runtime_root / "current.json")
        snapshot_id = str(pointer.get("snapshot_id", ""))
    if not re.fullmatch(r"[0-9A-Za-z._-]+", snapshot_id):
        raise ValueError("invalid or missing snapshot id")
    snapshot_root = runtime_root / "snapshots" / snapshot_id
    if not (snapshot_root / "provenance.json").is_file():
        raise FileNotFoundError(f"snapshot not found: {snapshot_id}")
    return snapshot_id, snapshot_root


def main() -> int:
    parser = argparse.ArgumentParser(description="vulnerability reachability analysis")
    parser.add_argument("--runtime", default="runtime")
    parser.add_argument("--snapshot-id", default="")
    parser.add_argument("--rules", default="rules")
    parser.add_argument("--output", default="report")
    args = parser.parse_args()
    root = project_root()
    snapshot_id, snapshot_root = resolve_snapshot(root, args.runtime, args.snapshot_id)
    repo_doc = load_json(snapshot_root / "repo" / "dependencies.json")
    usage_doc = load_json(snapshot_root / "repo" / "usage.json")
    deps = {item["package"]: item for item in repo_doc.get("dependencies", [])}
    usage, source = usage_doc.get("evidence", {}), repo_doc.get("source", {})
    rules, policy = load_rules(root / args.rules), load_yaml(root / args.rules / "verdict.yaml")
    verdicts = []
    for alert_file in sorted((snapshot_root / "alerts").glob("*.json")):
        if alert_file.name == "index.json":
            continue
        alert = load_json(alert_file)
        cve, package = alert["advisory"]["cve_id"], alert["vulnerability"]["package"]
        rule = rules.get(cve)
        value = judge(alert, rule, deps.get(package), usage.get(package), source, snapshot_id) if rule else unknown_verdict(alert, "no rule for this CVE", snapshot_id)
        verdicts.append(value)
        print(f"[OK] {cve} -> {value['verdict']} ({value['confidence']})")
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    output = root / args.output
    output.mkdir(parents=True, exist_ok=True)
    (output / "verdicts.json").write_text(json.dumps({"schema_version": "verdict/2.0", "generated_at": generated_at, "snapshot_id": snapshot_id, "verdicts": verdicts}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "reachability-report.md").write_text(build_markdown(verdicts, policy, generated_at, snapshot_id) + "\n", encoding="utf-8")
    print(f"\n{len(verdicts)} alerts analyzed -> {output.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
