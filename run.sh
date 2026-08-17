#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${AGENT_COMPOSE_INSTALL_DIR:-/opt/agent-compose}"
PROJECT_DIR="${VULN_REACH_PROJECT_DIR:-${INSTALL_DIR}/data/projects/vuln-reach}"
PROJECT_FILE="/data/projects/vuln-reach/agent-compose.yml"

cd "${INSTALL_DIR}"
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
  echo "timeout waiting for ${description}" >&2
  return 1
}

wait_for "OctoBus" docker exec octobus octobus --addr 127.0.0.1:9000 status
wait_for "Agent-Compose" docker exec agent-compose agent-compose status

echo "=== configure gateway and deploy capability ==="
bash "${PROJECT_DIR}/scripts/configure_gateway.sh"
bash "${PROJECT_DIR}/scripts/deploy_octobus.sh" >/dev/null
docker exec octobus octobus --addr 127.0.0.1:9000 capset list-methods vulnreach \
  | grep -q 'BuildRepositoryEvidence'
docker exec octobus octobus --addr 127.0.0.1:9000 capset list-methods vulnreach \
  | grep -q 'CheckReachability'

echo "=== validate and apply project ==="
docker exec agent-compose agent-compose -f "${PROJECT_FILE}" config >/dev/null
if ! docker image inspect vuln-reach-guest:v1.0.0 >/dev/null 2>&1; then
  echo "=== building pinned guest image ==="
  docker exec agent-compose agent-compose -f "${PROJECT_FILE}" image build reach-analyzer
fi
docker exec agent-compose agent-compose -f "${PROJECT_FILE}" up

PROMPT="立即执行完整证据分析闭环：先阅读 /data/runtime/mpi/catalog.md，再运行 python3 /workspace/scripts/run_pipeline.py；然后仅依据 snapshot.json、verdicts.json、reachability-report.md 和当前快照 provenance.json，生成 /workspace/report/agent-report.md。不得只回复计划，不得自行改写 OctoBus 的确定性判定，必要时只读取证据引用的少量源码行。"

echo "=== running agent ==="
docker exec agent-compose agent-compose -f "${PROJECT_FILE}" run reach-analyzer --prompt "${PROMPT}" 2>&1 | tail -160

test -s "${PROJECT_DIR}/workspace/runtime/current.json" || {
  echo "missing runtime snapshot pointer" >&2
  exit 1
}
for report in snapshot.json verdicts.json reachability-report.md agent-report.md; do
  test -s "${PROJECT_DIR}/workspace/report/${report}" || {
    echo "missing or empty report: workspace/report/${report}" >&2
    exit 1
  }
done

echo "=== run logs ==="
docker exec agent-compose agent-compose -f "${PROJECT_FILE}" logs 2>&1 | tail -40

echo "=== OctoBus audit (latest) ==="
docker exec octobus sh -c \
  "grep -E 'BuildRepositoryEvidence|CheckReachability' /var/lib/octobus/access.log | tail -12"

bash "${PROJECT_DIR}/scripts/verify.sh"
