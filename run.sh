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
if ! docker image inspect vuln-reach-guest:v1.0.0 >/dev/null 2>&1; then
  echo "=== building pinned guest image ==="
  docker exec agent-compose agent-compose -f "$PROJECT_FILE" image build reach-analyzer
fi
docker exec agent-compose agent-compose -f "$PROJECT_FILE" up

PROMPT="运行漏洞可达性研判：读取工作区 /workspace 下的告警契约（alerts/）、规则（rules/）与代码证据（repo/），运行本地脚本 python3 /workspace/scripts/reachability.py，并调用 OctoBus 能力 vuln-reach__reach-01__check_reachability 交叉验证每条告警，输出带证据的研判报告（/workspace/report/agent-report.md）与修复建议。IMPORTANT: Do NOT reply with a plan or intent statement. In your first turn you MUST immediately call exec_command to inspect the workspace files and read /data/runtime/mpi/catalog.md for the capability gateway recipe. Check CAP_TOKEN only with test -n \"\${CAP_TOKEN:-}\" and never print its value. Then run reachability.py, call vulnreach.v1.VulnReachService/CheckReachability via grpcurl for every alert, compare the structured outputs, downgrade any mismatch to unknown, and produce the final report."

echo "=== running agent (provider=opencode model=agent-compose/deepseek-v4-flash) ==="
docker exec agent-compose agent-compose -f "$PROJECT_FILE" run reach-analyzer --prompt "$PROMPT" 2>&1 | tail -120

for report in verdicts.json reachability-report.md agent-report.md; do
  test -s "$INSTALL_DIR/data/projects/vuln-reach/workspace/report/$report" || {
    echo "missing or empty report: workspace/report/$report" >&2
    exit 1
  }
done

echo "=== run logs ==="
docker exec agent-compose agent-compose -f "$PROJECT_FILE" logs 2>&1 | tail -40

echo "=== octobus audit (latest) ==="
docker exec octobus sh -c "grep 'CheckReachability' /var/lib/octobus/access.log | tail -8"

bash "$INSTALL_DIR/data/projects/vuln-reach/scripts/verify.sh"
