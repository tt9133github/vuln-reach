#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
normalize.py — 把 workspace/raw/dependabot/*.json 归一化为统一输入契约 workspace/alerts/*.json。

用法:
    python3 scripts/normalize.py

产出:
    workspace/alerts/{CVE-ID}.json   每条告警一个文件(无 CVE 时用 GHSA ID)
    workspace/alerts/index.json      所有告警索引

契约字段与 GitHub Dependabot alert 一一对应，后续规则脚本/Agent 只消费本契约，
不直接读原始响应。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("缺少 PyYAML，请先安装: pip install pyyaml")

SCHEMA = "vuln-alert/1.0"


def _safe(obj, *keys, default=""):
    cur = obj
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur if cur is not None else default


def _first_patched_version(vuln: dict) -> str:
    """Dependabot API 中 first_patched_version 可能是 {"identifier": "x"} 或 null，
    统一提取为纯字符串。"""
    f = _safe(vuln, "first_patched_version", default=None)
    if isinstance(f, dict):
        return str(f.get("identifier", "") or "")
    return str(f) if f else ""


def normalize_alert(raw: dict, repo_cfg: dict, normalized_at: str) -> dict:
    adv = _safe(raw, "security_advisory", default={})
    vuln = _safe(raw, "security_vulnerability", default={})
    dep = _safe(raw, "dependency", default={})
    cvss = _safe(adv, "cvss", default={})
    cwes = [c.get("cwe_id", "") for c in _safe(adv, "cwes", default=[]) if isinstance(c, dict)]
    refs = [r.get("url", "") for r in _safe(adv, "references", default=[]) if isinstance(r, dict)]
    refs = [u for u in refs if u]

    return {
        "schema_version": SCHEMA,
        "alert": {
            "number": _safe(raw, "number"),
            "state": _safe(raw, "state"),
            "html_url": _safe(raw, "html_url"),
            "created_at": _safe(raw, "created_at"),
            "updated_at": _safe(raw, "updated_at"),
        },
        "repo": {
            "owner": repo_cfg.get("owner", ""),
            "name": repo_cfg.get("repo", ""),
            "branch": repo_cfg.get("branch", ""),
            "ecosystem": repo_cfg.get("ecosystem", "")
            or _safe(dep, "package", "ecosystem"),
        },
        "advisory": {
            "cve_id": _safe(adv, "cve_id"),
            "ghsa_id": _safe(adv, "ghsa_id"),
            "summary": _safe(adv, "summary"),
            "description": _safe(adv, "description"),
            "severity": _safe(adv, "severity"),
            "cvss_score": _safe(cvss, "score"),
            "cvss_vector": _safe(cvss, "vector_string"),
            "cwes": cwes,
            "published_at": _safe(adv, "published_at"),
            "references": refs,
        },
        "vulnerability": {
            "package": _safe(vuln, "package", "name"),
            "ecosystem": _safe(vuln, "package", "ecosystem"),
            "vulnerable_version_range": _safe(vuln, "vulnerable_version_range"),
            "first_patched_version": _first_patched_version(vuln),
            "vulnerable_manifest_path": _safe(vuln, "vulnerable_manifest_path")
            or _safe(raw, "vulnerable_manifest_path"),
        },
        "normalized_at": normalized_at,
    }


def alert_file_name(norm: dict) -> str:
    cve = norm["advisory"]["cve_id"]
    ghsa = norm["advisory"]["ghsa_id"]
    ident = cve or ghsa or f"alert-{norm['alert']['number']}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", ident) + ".json"


def main() -> int:
    parser = argparse.ArgumentParser(description="原始告警 -> 统一契约")
    parser.add_argument("--sources", default="sources.yaml")
    parser.add_argument("--raw", default="workspace/raw/dependabot")
    parser.add_argument("--output", default="workspace/alerts")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    sources = yaml.safe_load((root / args.sources).read_text(encoding="utf-8"))
    repo_cfgs = {f"{c['owner']}__{c['repo']}": c for c in sources.get("repos", [])}

    raw_dir = root / args.raw
    out_dir = root / args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    normalized_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    index: list[dict] = []

    for raw_file in sorted(raw_dir.glob("*.json")):
        key = raw_file.stem
        raw_list = json.loads(raw_file.read_text(encoding="utf-8"))
        if not isinstance(raw_list, list):
            print(f"[SKIP] {raw_file.name}: 不是告警列表")
            continue
        repo_cfg = repo_cfgs.get(key, {})
        for raw in raw_list:
            norm = normalize_alert(raw, repo_cfg, normalized_at)
            name = alert_file_name(norm)
            out_file = out_dir / name
            out_file.write_text(
                json.dumps(norm, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            index.append(
                {
                    "file": name,
                    "alert_number": norm["alert"]["number"],
                    "state": norm["alert"]["state"],
                    "cve_id": norm["advisory"]["cve_id"],
                    "ghsa_id": norm["advisory"]["ghsa_id"],
                    "package": norm["vulnerability"]["package"],
                    "severity": norm["advisory"]["severity"],
                    "repo": f"{norm['repo']['owner']}/{norm['repo']['name']}",
                }
            )
            print(f"[OK] {raw_file.name} -> {name}")

    index.sort(key=lambda x: (x["repo"], str(x["alert_number"])))
    (out_dir / "index.json").write_text(
        json.dumps({"schema_version": SCHEMA, "alerts": index}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"\n共 {len(index)} 条告警 -> {out_dir.relative_to(root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
