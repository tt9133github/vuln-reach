#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${AGENT_COMPOSE_INSTALL_DIR:-/opt/agent-compose}"
PROJECT_DIR="${VULN_REACH_PROJECT_DIR:-${INSTALL_DIR}/data/projects/vuln-reach}"
PROJECT_FILE="/data/projects/vuln-reach/agent-compose.yml"

docker exec octobus octobus --addr 127.0.0.1:9000 status >/dev/null
docker exec agent-compose agent-compose status >/dev/null
docker exec octobus octobus --addr 127.0.0.1:9000 \
  capset list-methods vulnreach | grep -q 'CheckReachability'
docker exec agent-compose agent-compose -f "${PROJECT_FILE}" \
  scheduler ls | grep -q 'daily-reachability'

for report in verdicts.json reachability-report.md agent-report.md; do
  test -s "${PROJECT_DIR}/workspace/report/${report}" || {
    echo "missing or empty report: workspace/report/${report}" >&2
    exit 1
  }
done

AUDIT_COUNT="$(docker exec octobus sh -c \
  "grep -c 'CheckReachability' /var/lib/octobus/access.log 2>/dev/null || true")"
if [[ "${AUDIT_COUNT}" -lt 3 ]]; then
  echo "expected at least 3 CheckReachability audit records, got ${AUDIT_COUNT}" >&2
  exit 1
fi

echo "verification passed: services, scheduler, reports and OctoBus audit records are present"
