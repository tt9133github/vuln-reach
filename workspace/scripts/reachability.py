#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reachability.py - rule-driven vulnerability reachability analysis.

Inputs:
    alerts/*.json          normalized alert contracts (from normalize.py)
    repo/dependencies.json repository dependency inventory
    repo/usage.json        code usage evidence (file/line/sink/entry)
    rules/*.yaml           analysis rules + verdict policy

Outputs:
    report/verdicts.json          structured verdicts (machine readable)
    report/reachability-report.md evidence-backed human report

How rules are consumed by code:
    - version hit:   rule.affected_versions parsed and compared to inventory
    - sink hit:      rule.sinks[].api matched against usage.json call sites
    - preconditions: rule.preconditions[].evidence_path resolved from usage.json
    - verdict:       driven by verdict.yaml definitions
"""
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
    sys.exit("missing PyYAML, install with: pip install pyyaml")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def project_root() -> Path:
    """工作区根目录；沙箱内为 /workspace，本地为仓库下的 workspace。"""
    env = os.environ.get("VULN_REACH_ROOT")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[1]


def ws(root: Path, name: str) -> Path:
    return root / name


def version_tuple(version) -> tuple:
    """'1.2.31' -> (1,2,31); non-numeric suffixes are ignored."""
    parts = []
    for part in str(version).strip().lower().split("."):
        m = re.match(r"(\d+)", part)
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts)


def parse_constraint(text: str):
    text = text.strip()
    m = re.match(r"(<=|>=|<|>|==|=)?\s*([0-9][0-9a-zA-Z._-]*)", text)
    if not m:
        return None, None
    return (m.group(1) or "="), version_tuple(m.group(2))


def version_in_range(version, spec) -> bool:
    if not spec or not str(spec).strip():
        return True
    v = version_tuple(version)
    for part in str(spec).split(","):
        op, target = parse_constraint(part)
        if target is None:
            continue
        if op == "<" and not v < target:
            return False
        if op == "<=" and not v <= target:
            return False
        if op == ">" and not v > target:
            return False
        if op == ">=" and not v >= target:
            return False
        if op in ("=", "==") and not v == target:
            return False
    return True


def resolve_evidence_path(evidence: dict, path: str) -> list:
    """Resolve dot paths like entry_points[*].external_input or template_control."""
    current = [evidence]
    for seg in path.split("."):
        if seg.endswith("[*]"):
            key = seg[:-3]
            nxt = []
            for item in current:
                if isinstance(item, dict) and key in item and isinstance(item[key], list):
                    nxt.extend(item[key])
            current = nxt
        else:
            nxt = []
            for item in current:
                if isinstance(item, dict) and seg in item:
                    nxt.append(item[seg])
            current = nxt
    return current


def _sink_patterns(rule_sinks: list) -> list[str]:
    """规则 YAML 中 sinks 支持两种写法：["API"] 或 [{"api": "API"}]。"""
    patterns = []
    for s in rule_sinks or []:
        if isinstance(s, dict):
            patterns.append(str(s.get("api", "")))
        else:
            patterns.append(str(s))
    return [p for p in patterns if p]


def check_sink(evidence: dict, rule_sinks: list) -> tuple[bool, str]:
    patterns = _sink_patterns(rule_sinks)
    if not patterns:
        return True, "rule defines no fixed sink API; sink check skipped"
    sink_apis = [e.get("api", "") for e in evidence.get("sinks", [])]
    matched = [s for s in sink_apis if s in patterns]
    if matched:
        return True, "sink hit: " + ", ".join(matched)
    return False, "no rule-defined sink call found"


def judge(alert: dict, rule: dict, dep: dict, evidence: dict) -> dict:
    rule_id = rule["rule_id"]
    checks = {}
    evidence_items = []

    if dep:
        installed = dep.get("version", "")
        checks["version_match"] = version_in_range(installed, rule.get("affected_versions", ""))
        evidence_items.append(
            {
                "rule_id": rule_id,
                "check": "version_match",
                "detail": f"{dep['package']} {installed} in {rule.get('affected_versions', '*')}"
                if checks["version_match"]
                else f"{dep['package']} {installed} NOT in {rule.get('affected_versions', '*')}",
            }
        )
    else:
        checks["version_match"] = False
        evidence_items.append(
            {"rule_id": rule_id, "check": "version_match", "detail": "package not found in dependency inventory"}
        )

    if evidence:
        ok, detail = check_sink(evidence, rule.get("sinks", []))
        checks["sink_present"] = ok
        evidence_items.append({"rule_id": rule_id, "check": "sink_present", "detail": detail})
        if ok:
            patterns = _sink_patterns(rule.get("sinks"))
            if patterns:
                for e in evidence.get("sinks", []):
                    if e.get("api") in patterns:
                        evidence_items.append(
                            {
                                "rule_id": rule_id,
                                "check": "sink_call",
                                "detail": f"{e.get('file','')}:{e.get('line','')} {e.get('api','')} - {e.get('context','')}",
                            }
                        )
            else:
                for u in evidence.get("usage", []):
                    evidence_items.append(
                        {
                            "rule_id": rule_id,
                            "check": "usage",
                            "detail": f"{u.get('file','')}:{u.get('line','')} {u.get('api','')} - {u.get('context','')}",
                        }
                    )
    else:
        checks["sink_present"] = False
        evidence_items.append(
            {"rule_id": rule_id, "check": "sink_present", "detail": "no evidence in usage.json for this package"}
        )

    checks["preconditions"] = {}
    precond_met = True
    for pc in rule.get("preconditions", []):
        values = resolve_evidence_path(evidence or {}, pc["evidence_path"])
        if not values:
            checks["preconditions"][pc["id"]] = None
            precond_met = False
            evidence_items.append(
                {
                    "rule_id": rule_id,
                    "check": f"precondition:{pc['id']}",
                    "detail": f"{pc['description']} - evidence missing",
                }
            )
        else:
            ok = any(v == pc["expect"] for v in values)
            checks["preconditions"][pc["id"]] = ok
            precond_met = precond_met and ok
            evidence_items.append(
                {
                    "rule_id": rule_id,
                    "check": f"precondition:{pc['id']}",
                    "detail": f"{pc['description']} - {'met' if ok else 'NOT met'} (values: {values})",
                }
            )

    verdict = None
    reason = ""
    if not checks["version_match"]:
        verdict = "not_reachable"
        reason = "installed version outside affected range"
    elif not checks["sink_present"]:
        verdict = "not_reachable"
        reason = "no rule-defined sink call found"
    elif any(v is False for v in checks["preconditions"].values()):
        verdict = "not_reachable"
        failed = [pc for pc in rule.get("preconditions", []) if checks["preconditions"].get(pc["id"]) is False]
        reason = "precondition not met: " + "; ".join(pc["description"] for pc in failed)
    elif any(v is None for v in checks["preconditions"].values()):
        verdict = "unknown"
        reason = "precondition evidence missing"
    else:
        verdict = "reachable"
        reason = "version hit, sink present and all preconditions met"

    confidence = "medium"
    if verdict == "not_reachable" and not checks["version_match"]:
        confidence = "high"
    elif verdict == "reachable":
        has_loc = any(re.search(r"[A-Za-z0-9_./-]+\.java:\d+", e.get("detail", "")) for e in evidence_items)
        confidence = "high" if has_loc else "medium"
    elif verdict == "unknown":
        confidence = "low"

    return {
        "cve_id": alert["advisory"]["cve_id"],
        "ghsa_id": alert["advisory"]["ghsa_id"],
        "alert_number": alert["alert"]["number"],
        "state": alert["alert"]["state"],
        "severity": alert["advisory"]["severity"],
        "package": alert["vulnerability"]["package"],
        "installed_version": dep.get("version", "") if dep else "",
        "affected_versions": rule.get("affected_versions", ""),
        "fixed_version": rule.get("fixed_version", ""),
        "rule_id": rule_id,
        "checks": checks,
        "verdict": verdict,
        "confidence": confidence,
        "verdict_reason": reason,
        "evidence": evidence_items,
        "fix": rule.get("fix", []),
        "exploit_notes": rule.get("exploit_notes", ""),
    }


def build_markdown(verdicts: list, policy: dict, generated_at: str) -> str:
    icon = {"reachable": "[REACHABLE]", "not_reachable": "[NOT REACHABLE]", "unknown": "[UNKNOWN]"}
    lines = [
        "# Vulnerability Reachability Report",
        "",
        f"- generated_at: {generated_at}",
        f"- verdict policy: {policy['verdicts']['reachable']['definition']}",
        f"- alerts analyzed: {len(verdicts)}",
        "",
    ]
    for v in sorted(verdicts, key=lambda x: x["alert_number"]):
        lines.append(
            f"## #{v['alert_number']} {v['cve_id']} ({v['severity']}) - {icon.get(v['verdict'], '?')} ({v['confidence']})"
        )
        lines.append("")
        lines.append(
            f"- package: {v['package']} {v['installed_version'] or '(not found)'} | affected: {v['affected_versions']} | fixed: {v['fixed_version'] or 'n/a'}"
        )
        lines.append(f"- rule: `{v['rule_id']}`")
        lines.append(f"- verdict: {v['verdict_reason']}")
        lines.append("")
        lines.append("checks:")
        lines.append("")
        lines.append(f"- version_match: {'PASS' if v['checks']['version_match'] else 'FAIL'}")
        lines.append(f"- sink_present: {'PASS' if v['checks']['sink_present'] else 'FAIL'}")
        for pid, val in v["checks"].get("preconditions", {}).items():
            mark = {True: "PASS", False: "FAIL", None: "N/A"}.get(val, "N/A")
            lines.append(f"- precondition {pid}: {mark}")
        lines.append("")
        lines.append("evidence:")
        lines.append("")
        for e in v["evidence"]:
            lines.append(f"  - `{e['rule_id']}` [{e['check']}] {e['detail']}")
        lines.append("")
        lines.append("fix:")
        lines.append("")
        for f in v["fix"]:
            lines.append(f"  - {f}")
        lines.append("")
        if v.get("exploit_notes"):
            lines.append(f"note: {v['exploit_notes']}")
            lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="vulnerability reachability analysis")
    parser.add_argument("--alerts", default="alerts")
    parser.add_argument("--repo", default="repo")
    parser.add_argument("--rules", default="rules")
    parser.add_argument("--output", default="report")
    args = parser.parse_args()

    root = project_root()
    alerts_dir = ws(root, args.alerts)
    repo_dir = ws(root, args.repo)
    rules_dir = ws(root, args.rules)
    out_dir = ws(root, args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    deps = load_json(repo_dir / "dependencies.json").get("dependencies", [])
    usage = load_json(repo_dir / "usage.json").get("evidence", {})
    policy = load_yaml(rules_dir / "verdict.yaml")

    rules = {}
    for rf in sorted(rules_dir.glob("*.yaml")):
        if rf.name == "verdict.yaml":
            continue
        for r in load_yaml(rf).get("rules", []):
            rules[r["cve"]] = r

    dep_by_pkg = {d["package"]: d for d in deps}
    verdicts = []
    for af in sorted(alerts_dir.glob("*.json")):
        if af.name == "index.json":
            continue
        alert = load_json(af)
        pkg = alert["vulnerability"]["package"]
        cve = alert["advisory"]["cve_id"]
        rule = rules.get(cve)
        if not rule:
            verdicts.append(
                {
                    "cve_id": cve,
                    "ghsa_id": alert["advisory"]["ghsa_id"],
                    "alert_number": alert["alert"]["number"],
                    "state": alert["alert"]["state"],
                    "severity": alert["advisory"]["severity"],
                    "package": pkg,
                    "installed_version": dep_by_pkg.get(pkg, {}).get("version", ""),
                    "rule_id": None,
                    "checks": {},
                    "verdict": "unknown",
                    "confidence": "low",
                    "verdict_reason": "no rule for this CVE",
                    "evidence": [],
                    "fix": [],
                }
            )
            print(f"[WARN] {cve}: no rule, skipped")
            continue
        v = judge(alert, rule, dep_by_pkg.get(pkg), usage.get(pkg))
        verdicts.append(v)
        print(f"[OK] {v['cve_id']} -> {v['verdict']} ({v['confidence']})")

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = {
        "schema_version": "verdict/1.0",
        "generated_at": generated_at,
        "verdicts": verdicts,
    }
    (out_dir / "verdicts.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "reachability-report.md").write_text(
        build_markdown(verdicts, policy, generated_at), encoding="utf-8"
    )
    print(f"\n{len(verdicts)} alerts analyzed -> {out_dir.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
