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
for report in snapshot.json verdicts.json reachability-report.md agent-report.md; do
  test -s "${PROJECT_DIR}/workspace/report/${report}" || {
    echo "missing or empty report: workspace/report/${report}" >&2
    exit 1
  }
done

python3 - "${PROJECT_DIR}/workspace/report/verdicts.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("schema_version") != "verdict/4.0":
    raise SystemExit(f"unexpected verdict schema: {report.get('schema_version')!r}")

expected = {
    "CVE-2025-70974": ("reachable", "L3"),
    "CVE-2022-25845": ("reachable", "L3"),
    "CVE-2020-13936": ("unknown", "L2"),
}
actual = {
    item.get("cve_id"): (item.get("verdict"), item.get("reachability_level"))
    for item in report.get("verdicts", [])
}
if actual != expected:
    raise SystemExit(f"unexpected verdict/level results: {actual!r}")

for item in report["verdicts"]:
    required = ("level_reason", "governance_action", "level_checks")
    missing = [name for name in required if not item.get(name)]
    if missing:
        raise SystemExit(f"{item.get('cve_id')} missing level fields: {missing}")
print("verdict/level assertions passed")
PY

ALERT_COUNT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["alertCount"])' \
  "${PROJECT_DIR}/workspace/report/snapshot.json")"
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

echo "verification passed: snapshot, expected verdict/levels, scheduler, reports and OctoBus audit records are present"
