#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_alerts.py — 从 GitHub Dependabot Alerts API 拉取固定仓库列表的告警。

用法:
    export GITHUB_TOKEN='<只读 GitHub Token>'
    python3 scripts/fetch_alerts.py

流程:
    sources.yaml 中配置的每个仓库
        -> GET /repos/{owner}/{repo}/dependabot/alerts?state={open|fixed|dismissed}
        -> 原始响应原样缓存到 workspace/raw/dependabot/{owner}__{repo}.json

注意:
    GitHub Dependabot Alerts API 的 state 只接受 open/fixed/dismissed，
    没有 "all"；脚本默认拉全部三种状态并按告警编号去重，
    这样修复后重跑即可看到告警状态从 open 变为 fixed。

设计要点:
    - 告警源固定，由配置驱动；新增仓库只改 sources.yaml，不改代码
    - 缓存原始响应，normalize.py 之后再消费，演示时支持离线回放
    - 单个仓库失败不中断其他仓库
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("缺少 PyYAML，请先安装: pip install pyyaml")

API_LIST_ALERTS = "https://api.github.com/repos/{owner}/{repo}/dependabot/alerts"


def load_sources(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def build_headers(token: str, version: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": version,
        "User-Agent": "vuln-reach-agent",
    }


def api_get(url: str, headers: dict) -> tuple[list | dict, dict]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body, {"link": resp.headers.get("Link", "")}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"HTTP {e.code} {url}\n{detail}") from e


def next_url(link_header: str) -> str | None:
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) == 2 and 'rel="next"' in section[1]:
            return section[0].strip().strip("<>")
    return None


def fetch_repo_alerts(owner: str, repo: str, headers: dict, states: list[str]) -> list[dict]:
    by_number: dict = {}
    for state in states:
        url = f"{API_LIST_ALERTS.format(owner=owner, repo=repo)}?state={state}&per_page=100"
        while url:
            body, meta = api_get(url, headers)
            if not isinstance(body, list):
                raise RuntimeError(f"意外响应结构: {str(body)[:200]}")
            for alert in body:
                # 按告警编号去重，保留先出现的（states 顺序 open -> fixed -> dismissed）
                by_number.setdefault(alert.get("number"), alert)
            url = next_url(meta.get("link", ""))
            time.sleep(0.2)  # 温和限流，避免触发 API 限速
    return list(by_number.values())


def resolve_token(args_token: str, root: Path) -> str:
    token = args_token or os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token
    env_path = root / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("GITHUB_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description="拉取固定仓库的 Dependabot 告警")
    parser.add_argument("--sources", default="sources.yaml", help="仓库配置(相对项目根)")
    parser.add_argument("--output", default="workspace/raw/dependabot", help="原始缓存目录")
    parser.add_argument("--token", default="", help="GitHub PAT(默认读环境变量 GITHUB_TOKEN)")
    parser.add_argument(
        "--states",
        default="open,fixed,dismissed",
        help="拉取状态列表，逗号分隔（合法值: open/fixed/dismissed）",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    token = resolve_token(args.token, root)
    if not token:
        sys.exit("未找到 GITHUB_TOKEN：请 export GITHUB_TOKEN=... 或在项目根 .env 配置")

    sources = load_sources(root / args.sources)
    version = sources.get("github", {}).get("api_version", "2022-11-28")
    headers = build_headers(token, version)
    output_dir = root / args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    states = [s.strip() for s in args.states.split(",") if s.strip()]
    invalid = [s for s in states if s not in ("open", "fixed", "dismissed")]
    if invalid:
        sys.exit(f"非法的 state 值: {invalid}（Dependabot API 只支持 open/fixed/dismissed）")

    failed: list[tuple[str, str]] = []
    for cfg in sources.get("repos", []):
        owner, repo = cfg["owner"], cfg["repo"]
        key = f"{owner}__{repo}"
        try:
            alerts = fetch_repo_alerts(owner, repo, headers, states)
            out = output_dir / f"{key}.json"
            with open(out, "w", encoding="utf-8") as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
            print(f"[OK] {key}: {len(alerts)} 条告警 -> {out.relative_to(root)}")
        except Exception as e:  # noqa: BLE001
            failed.append((key, str(e)))
            print(f"[FAIL] {key}: {e}")

    if failed:
        print(f"\n{len(failed)} 个仓库拉取失败:")
        for key, err in failed:
            print(f"  - {key}: {err}")
        return 1
    print("\n全部完成。下一步运行: python3 scripts/normalize.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
