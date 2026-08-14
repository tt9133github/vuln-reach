#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${AGENT_COMPOSE_INSTALL_DIR:-/opt/agent-compose}"
PROJECT_FILE="/data/projects/vuln-reach/agent-compose.yml"

cd "$INSTALL_DIR"
docker compose up -d octobus agent-compose >/dev/null

wait_for() {
  local description="$1"
  shift
  for _ in $(seq 1 30); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "timeout waiting for $description" >&2
  return 1
}

wait_for "OctoBus" docker exec octobus octobus --addr 127.0.0.1:9000 status
wait_for "Agent-Compose" docker exec agent-compose agent-compose status

docker exec octobus octobus --addr 127.0.0.1:9000 \
  capset list-methods vulnreach | grep -q 'CheckReachability'

echo "=== validate and apply project ==="
docker exec agent-compose agent-compose -f "$PROJECT_FILE" config >/dev/null
docker exec agent-compose agent-compose -f "$PROJECT_FILE" up

PROMPT="运行漏洞可达性研判：读取工作区 /workspace 下的告警契约（alerts/）、规则（rules/）与代码证据（repo/），运行本地脚本 python3 /workspace/scripts/reachability.py，并调用 OctoBus 能力 vuln-reach__reach-01__check_reachability 交叉验证每条告警，输出带证据的研判报告（/workspace/report/agent-report.md）与修复建议。IMPORTANT: Do NOT reply with a plan or intent statement. In your first turn you MUST immediately call exec_command to inspect the workspace files and read /data/runtime/mpi/catalog.md for the capability gateway recipe (endpoint agent-compose:7411, token header from catalog using env CAP_TOKEN, plus x-octobus-capset=vulnreach and x-octobus-instance=reach-01). Then run reachability.py, then call vulnreach.v1.VulnReachService/CheckReachability via grpcurl for each CVE, then produce the final structured report."

echo "=== running agent (provider=opencode model=agent-compose/deepseek-v4-flash) ==="
docker exec agent-compose agent-compose -f "$PROJECT_FILE" run reach-analyzer --prompt "$PROMPT" 2>&1 | tail -120

echo "=== run logs ==="
docker exec agent-compose agent-compose -f "$PROJECT_FILE" logs 2>&1 | tail -40

echo "=== octobus audit (latest) ==="
docker exec octobus sh -c "grep 'CheckReachability' /var/lib/octobus/access.log | tail -8"
