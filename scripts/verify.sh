#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${AGENT_COMPOSE_INSTALL_DIR:-/opt/agent-compose}"
PROJECT_DIR="${VULN_REACH_PROJECT_DIR:-${INSTALL_DIR}/data/projects/vuln-reach}"
PROJECT_FILE="/data/projects/vuln-reach/agent-compose.yml"

docker exec octobus octobus --addr 127.0.0.1:9000 status >/dev/null
docker exec agent-compose agent-compose status >/dev/null
docker exec octobus octobus --addr 127.0.0.1:9000 \
  capset list-methods vulnreach | grep -q 'BuildRepositoryEvidence'
docker exec octobus octobus --addr 127.0.0.1:9000 \
  capset list-methods vulnreach | grep -q 'CheckReachability'
docker exec agent-compose agent-compose -f "${PROJECT_FILE}" \
  scheduler ls | grep -q 'daily-reachability'

test -s "${PROJECT_DIR}/workspace/runtime/current.json" || {
  echo "missing runtime snapshot pointer" >&2
  exit 1
}
for report in snapshot.json verdicts.json reachability-report.md verified-verdicts.json cross-check.json agent-report.md; do
  test -s "${PROJECT_DIR}/workspace/report/${report}" || {
    echo "missing or empty report: workspace/report/${report}" >&2
    exit 1
  }
done

ALERT_COUNT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["alertCount"])' \
  "${PROJECT_DIR}/workspace/report/snapshot.json")"
python3 -c 'import json,sys; assert json.load(open(sys.argv[1], encoding="utf-8"))["all_matched"] is True' \
  "${PROJECT_DIR}/workspace/report/cross-check.json"

BUILD_AUDIT_COUNT="$(docker exec octobus sh -c \
  "grep -c 'BuildRepositoryEvidence' /var/lib/octobus/access.log 2>/dev/null || true")"
CHECK_AUDIT_COUNT="$(docker exec octobus sh -c \
  "grep -c 'CheckReachability' /var/lib/octobus/access.log 2>/dev/null || true")"
if [[ "${BUILD_AUDIT_COUNT}" -lt 1 ]]; then
  echo "expected at least one BuildRepositoryEvidence audit record" >&2
  exit 1
fi
if [[ "${CHECK_AUDIT_COUNT}" -lt "${ALERT_COUNT}" ]]; then
  echo "expected at least ${ALERT_COUNT} CheckReachability audit records, got ${CHECK_AUDIT_COUNT}" >&2
  exit 1
fi

echo "verification passed: real snapshot, matching engines, scheduler, reports and OctoBus audit records are present"
